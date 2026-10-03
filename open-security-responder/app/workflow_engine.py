"""
Workflow execution engine using Dramatiq

Handles asynchronous playbook execution with Redis state management.
"""

import json
import uuid
import logging
import asyncio
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Mapping, Optional, List, Tuple
from jinja2 import (
    DictLoader, TemplateRuntimeError, TemplateSyntaxError, UndefinedError, nodes
)
from jinja2.utils import missing
from jinja2.sandbox import SandboxedEnvironment, SecurityError
import redis
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.results import Results
from dramatiq.results.backends import RedisBackend

from .models import (
    Playbook, PlaybookStep, StepFailurePolicy, ExecutionStatus, step_context_key, 
    StepExecutionResult, PlaybookExecutionResult
)
from .config import settings
from .playbook_parser import playbook_parser
from .connectors import connector_registry
from .caller import CallerIdentityUnavailable, require_caller, run_as

# Configure logging
logger = logging.getLogger(__name__)

# Configure Redis connection
redis_client = redis.from_url(settings.redis_url)

# Configure Dramatiq broker
result_backend = RedisBackend(url=settings.redis_url)
broker = RedisBroker(url=settings.redis_url)
broker.add_middleware(Results(backend=result_backend))
dramatiq.set_broker(broker)

# Jinja2 sandboxed environment for template rendering
# SECURITY: SandboxedEnvironment prevents access to dangerous attributes
# like __class__, __subclasses__, __import__, etc. that could lead to RCE.
from jinja2 import StrictUndefined

# No autoescape. A step input is an argument to an action -- a URL to
# blacklist, a title for a finding -- not HTML, and escaping it changed the
# data: `{{ trigger.url }}` turned "?a=1&b=2" into "?a=1&amp;b=2", so
# triage_url would have blacklisted a URL nobody submitted (#605). The
# sandbox, not escaping, is what stands between a template and Python.
jinja_env = SandboxedEnvironment(
    loader=DictLoader({}),
    autoescape=False,
    undefined=StrictUndefined
)


class _UndefinedReferenceError(UndefinedError):
    """UndefinedError that carries the Undefined which raised it."""

    def __init__(self, message: str, undefined: "_ConditionUndefined"):
        super().__init__(message)
        self.undefined = undefined


class _ConditionUndefined(StrictUndefined):
    """StrictUndefined that says which reference was undefined.

    Used only for step conditions (#595). It fails exactly like
    StrictUndefined, but the error it raises carries the Undefined itself, so
    that evaluate_condition can name the missing reference in the run log.

    The sandbox builds its "unsafe attribute" placeholders from this same
    class with exc=SecurityError; those keep raising SecurityError, which is
    not an UndefinedError, so a sandbox violation never reads as an undefined
    name.
    """

    __slots__ = ()

    def __init__(self, hint=None, obj=missing, name=None, exc=UndefinedError):
        super().__init__(hint=hint, obj=obj, name=name, exc=exc)
        if exc is UndefinedError:
            self._undefined_exception = self._reference_error

    def _reference_error(self, message: str) -> _UndefinedReferenceError:
        return _UndefinedReferenceError(message, self)


# Conditions are rendered in their own environment so that the lenient
# handling of undefined names there cannot leak into action inputs, which are
# rendered by jinja_env above and stay strict.
condition_env = SandboxedEnvironment(
    loader=DictLoader({}),
    autoescape=True,
    undefined=_ConditionUndefined
)


def run_context(run_id: str, playbook_id: str, started_at: datetime) -> Dict[str, Any]:
    """The `run` entry of a step's template context.

    Gives a playbook the facts about its own run: `run.id`, `run.playbook_id`
    and `run.started_at`, the time the run was queued as an ISO 8601 string in
    UTC. all_star_e2e.yml read a `system.timestamp` that nothing ever
    provided, so its threat_assessment step could not render and the run
    stopped there (#605).
    """
    return {
        "id": run_id,
        "playbook_id": playbook_id,
        "started_at": started_at.replace(tzinfo=timezone.utc).isoformat(),
    }


# A run in one of these states has ended; nothing changes it any more.
TERMINAL_STATUSES = frozenset(
    {ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.CANCELLED}
)


def _decode(value) -> Optional[str]:
    """A Redis reply as text (redis-py returns bytes by default)."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode()
    return value


class RunCancelled(Exception):
    """Raised in the worker when it finds that the run's cancel was accepted.

    Carries the names of the steps that will not run (#653).
    """

    def __init__(self, not_run: List[str]):
        super().__init__("cancelled at the user's request")
        self.not_run = not_run


class ExecutionStateCorruptError(Exception):
    """Raised when a persisted execution record exists but cannot be parsed.

    Distinct from "no such run" on purpose: conflating the two let a corrupt or
    evicted record be silently replaced by a fresh one (WILDBO-DATA-02).
    """


class WorkflowExecutionError(Exception):
    """Raised when workflow execution fails"""
    pass


class TemplateRenderError(Exception):
    """Raised when template rendering fails"""
    pass


class WorkflowEngine:
    """Main workflow execution engine"""
    
    def __init__(self):
        self.redis_client = redis_client
        self.key_prefix = settings.redis_key_prefix
        
    def _get_execution_key(self, run_id: str) -> str:
        """Get Redis key for execution state"""
        return f"{self.key_prefix}run:{run_id}"
    
    def _get_logs_key(self, run_id: str) -> str:
        """Get Redis key for execution logs"""
        return f"{self.key_prefix}run:{run_id}:logs"
    
    def _get_cancel_key(self, run_id: str) -> str:
        """Get Redis key recording that a cancel of the run was accepted"""
        return f"{self.key_prefix}run:{run_id}:cancel"

    @staticmethod
    def _retention_seconds() -> int:
        return settings.execution_retention_days * 24 * 60 * 60

    @staticmethod
    def _state_mapping(execution_result: PlaybookExecutionResult) -> Dict[str, str]:
        """The hash fields a run's record is stored as."""
        data = execution_result.dict()

        # Convert datetime objects to ISO strings for JSON serialization
        for field in ['start_time', 'end_time']:
            if data.get(field):
                data[field] = data[field].isoformat()

        # Handle step results datetime fields
        for step_result in data.get('step_results', []):
            for field in ['start_time', 'end_time']:
                if step_result.get(field):
                    step_result[field] = step_result[field].isoformat()

        now = datetime.utcnow().isoformat()
        return {
            'data': json.dumps(data),
            'status': ExecutionStatus(execution_result.status).value,
            'playbook_id': execution_result.playbook_id,
            'updated_at': now,
            # Heartbeat: lets a reaper tell an abandoned run from a live one
            # (WILDBO-REL-02).
            'heartbeat_at': now,
        }

    @staticmethod
    def resolve_status(
        requested: ExecutionStatus,
        stored: Optional[str],
        cancel_requested: bool,
    ) -> ExecutionStatus:
        """The status a write may record, given what is stored (#653).

        - A run recorded as cancelled stays cancelled: no write turns it
          back into running, completed or failed.
        - Once a cancel has been accepted, a run that is still going is
          cancelling, and a run that ends -- completed or failed -- ends
          cancelled. Its step results say which steps ran and how.
        - Otherwise the requested status is recorded.
        """
        requested = ExecutionStatus(requested)
        if stored == ExecutionStatus.CANCELLED.value:
            return ExecutionStatus.CANCELLED
        if not cancel_requested:
            return requested
        if requested in TERMINAL_STATUSES:
            return ExecutionStatus.CANCELLED
        return ExecutionStatus.CANCELLING

    def save_execution_state(self, run_id: str, execution_result: PlaybookExecutionResult):
        """Save execution state to Redis.

        The write is a compare-and-set against the stored status and the
        run's cancel request (WATCH/MULTI), so it cannot undo a cancel that
        landed after the caller read the record: see resolve_status. When
        the status recorded differs from the one requested, it is also set
        on ``execution_result``, so the caller sees what was stored (#653).
        """
        key = self._get_execution_key(run_id)
        cancel_key = self._get_cancel_key(run_id)
        logs_key = self._get_logs_key(run_id)

        def write(pipe):
            stored = _decode(pipe.hget(key, 'status'))
            # The log list is the run's log. The worker holds a copy of the
            # record loaded when the run started, and saving that copy used
            # to replace every line add_log had written since -- including
            # the line saying the run was cancelled.
            logs = pipe.lrange(logs_key, 0, -1)
            if logs:
                execution_result.logs = [_decode(line) for line in logs]
            status = self.resolve_status(
                execution_result.status, stored, bool(pipe.exists(cancel_key))
            )
            if status != execution_result.status:
                execution_result.status = status
                if status in TERMINAL_STATUSES and execution_result.end_time is None:
                    execution_result.end_time = datetime.utcnow()
            # Write and expiry in one transaction: a crash between the hset
            # and the expire used to leave a record with no TTL, in a Redis
            # with a 512MB ceiling and an eviction policy that then discards
            # other records (WILDBO-DATA-07).
            pipe.multi()
            pipe.hset(key, mapping=self._state_mapping(execution_result))
            pipe.expire(key, self._retention_seconds())

        self.redis_client.transaction(write, key, cancel_key, logs_key)

    def cancel_requested(self, run_id: str) -> bool:
        """True once a cancel of the run has been accepted."""
        return bool(self.redis_client.exists(self._get_cancel_key(run_id)))

    def request_cancel(self, run_id: str) -> Optional[Tuple[ExecutionStatus, bool]]:
        """Ask for a run to stop; return its resulting status (#653).

        The request is durable: it is a key the worker reads before the run
        starts and before every step, kept as long as the run's record.

        - A queued run is cancelled at once: the worker that picks it up
          finds the request and runs no step.
        - A running run becomes cancelling. The step in progress runs to its
          end and is recorded as it ended -- its call may already have taken
          effect -- and no further step starts; the worker then records the
          run as cancelled.
        - A run that has ended is left as it is.

        Returns ``(status, accepted)``: the run's status after the call and
        whether this call recorded the request (False when the run had ended
        or a cancel was already requested). None when there is no such run.
        Check ownership before calling.
        """
        key = self._get_execution_key(run_id)
        cancel_key = self._get_cancel_key(run_id)
        logs_key = self._get_logs_key(run_id)

        def cancel(pipe):
            raw = pipe.hget(key, 'data')
            if not raw:
                return None
            state = self._parse_state(run_id, raw)
            status = ExecutionStatus(state.status)
            if status in TERMINAL_STATUSES or pipe.exists(cancel_key):
                return status, False

            now = datetime.utcnow()
            if status == ExecutionStatus.RUNNING:
                state.status = ExecutionStatus.CANCELLING
                line = (
                    "Cancel requested: the step in progress runs to its end; "
                    "no further step will start"
                )
            else:
                state.status = ExecutionStatus.CANCELLED
                state.end_time = now
                state.duration_seconds = (now - state.start_time).total_seconds()
                line = "Cancelled before it started: no step will run"
            entry = f"[{now.isoformat()}] WARNING: {line}"
            logs = pipe.lrange(logs_key, 0, -1)
            state.logs = [_decode(item) for item in logs] + [entry]

            pipe.multi()
            pipe.set(cancel_key, now.isoformat(), ex=self._retention_seconds())
            pipe.hset(key, mapping=self._state_mapping(state))
            pipe.expire(key, self._retention_seconds())
            pipe.rpush(logs_key, entry)
            return ExecutionStatus(state.status), True

        return self.redis_client.transaction(
            cancel, key, cancel_key, logs_key, value_from_callable=True
        )


    def reap_abandoned_runs(self, stale_after_seconds: int = 900) -> int:
        """
        Mark runs whose worker died as FAILED.

        Nothing used to reconcile interrupted work: a worker killed mid-run --
        an OOM, a deploy, a host restart -- left the record saying RUNNING
        forever, because no reaper, startup sweep or lease existed anywhere and
        the actor is declared max_retries=0 (WILDBO-REL-02). A user polling such
        a run saw "running" indefinitely and an operator had no list of work
        needing to be redone.

        A run is considered abandoned when it is in a non-terminal state and its
        heartbeat (refreshed by save_execution_state on every step) is older than
        stale_after_seconds. Returns the number of runs reconciled.

        Call at startup and periodically.
        """
        reaped = 0
        cutoff = datetime.utcnow() - timedelta(seconds=stale_after_seconds)
        pattern = f"{self.key_prefix}run:*"

        for key in self.redis_client.scan_iter(match=pattern, count=100):
            key_s = key.decode() if isinstance(key, (bytes, bytearray)) else str(key)
            if key_s.endswith((":team", ":logs", ":cancel")):
                continue

            raw_status = self.redis_client.hget(key_s, "status")
            if raw_status is None:
                continue
            status = raw_status.decode() if isinstance(raw_status, (bytes, bytearray)) else str(raw_status)
            if status not in (
                ExecutionStatus.RUNNING.value,
                ExecutionStatus.QUEUED.value,
                ExecutionStatus.CANCELLING.value,
            ):
                continue

            raw_hb = self.redis_client.hget(key_s, "heartbeat_at") or self.redis_client.hget(key_s, "updated_at")
            if raw_hb is None:
                continue
            hb = raw_hb.decode() if isinstance(raw_hb, (bytes, bytearray)) else str(raw_hb)
            try:
                last_seen = datetime.fromisoformat(hb)
            except ValueError:
                continue
            if last_seen > cutoff:
                continue  # still alive

            run_id = key_s.rsplit("run:", 1)[-1]
            try:
                execution_result = self.get_execution_state(run_id)
            except ExecutionStateCorruptError:
                execution_result = None
            if execution_result is None:
                continue

            execution_result.status = ExecutionStatus.FAILED
            execution_result.end_time = datetime.utcnow()
            execution_result.error = (
                f"Run abandoned: no heartbeat since {hb}. The worker executing it "
                "stopped without reporting a terminal status."
            )
            # A run whose cancel was accepted is recorded as cancelled
            # (resolve_status); its error still says the worker stopped.
            self.save_execution_state(run_id, execution_result)
            self.add_log(
                run_id,
                f"Run reconciled as {ExecutionStatus(execution_result.status).value.upper()}: "
                "worker heartbeat expired",
                level="ERROR",
            )
            logger.warning(f"Reaped abandoned run {run_id} (last heartbeat {hb})")
            reaped += 1

        if reaped:
            logger.warning(f"Reconciled {reaped} abandoned run(s)")
        return reaped

    def get_execution_state(self, run_id: str) -> Optional[PlaybookExecutionResult]:
        """Retrieve execution state from Redis"""
        key = self._get_execution_key(run_id)
        data = self.redis_client.hget(key, 'data')

        if not data:
            return None
        return self._parse_state(run_id, data)

    @staticmethod
    def _parse_state(run_id: str, data) -> PlaybookExecutionResult:
        """Parse a stored record; raise ExecutionStateCorruptError if it cannot be."""
        try:
            parsed_data = json.loads(data)
            
            # Convert ISO strings back to datetime objects
            for field in ['start_time', 'end_time']:
                if parsed_data.get(field):
                    parsed_data[field] = datetime.fromisoformat(parsed_data[field])
            
            # Handle step results datetime fields
            for step_result in parsed_data.get('step_results', []):
                for field in ['start_time', 'end_time']:
                    if step_result.get(field):
                        step_result[field] = datetime.fromisoformat(step_result[field])
            
            return PlaybookExecutionResult(**parsed_data)
        except (json.JSONDecodeError, ValueError) as e:
            # Do NOT return None here: the caller cannot distinguish that from
            # "no such run", and its documented response to a miss is to build a
            # fresh RUNNING record and save it over the top -- committing new
            # state over the evidence of the corruption (WILDBO-DATA-02).
            logger.error(f"Failed to parse execution state for {run_id}: {e}")
            raise ExecutionStateCorruptError(
                f"Execution state for {run_id} could not be parsed: {e}"
            ) from e
    
    def _get_owner_key(self, run_id: str) -> str:
        """Get Redis key recording which team owns an execution (tenancy)."""
        return f"{self.key_prefix}run:{run_id}:team"

    def set_run_owner(self, run_id: str, team_id) -> None:
        """Record which team owns a run so reads/cancels can be tenant-scoped.

        Stored as a separate key with the same retention as the run state, so
        it is independent of the worker rewriting the execution state.
        """
        key = self._get_owner_key(run_id)
        # SET with an expiry in one command (WILDBO-DATA-07).
        expire_seconds = settings.execution_retention_days * 24 * 60 * 60
        self.redis_client.set(key, str(team_id), ex=expire_seconds)

    def get_run_owner(self, run_id: str) -> Optional[str]:
        """Return the team_id that owns ``run_id``, or None if unknown."""
        value = self.redis_client.get(self._get_owner_key(run_id))
        if value is None:
            return None
        return value.decode() if isinstance(value, (bytes, bytearray)) else str(value)

    def is_run_owner(self, run_id: str, team_id) -> bool:
        """True only if ``team_id`` owns ``run_id`` (unknown owner -> False)."""
        owner = self.get_run_owner(run_id)
        return owner is not None and owner == str(team_id)

    def add_log(self, run_id: str, message: str, level: str = "INFO"):
        """Add a log entry for the execution"""
        logs_key = self._get_logs_key(run_id)
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {level}: {message}"
        
        self.redis_client.rpush(logs_key, log_entry)
        
        # Also update the logs in the main execution state
        execution_state = self.get_execution_state(run_id)
        if execution_state:
            execution_state.logs.append(log_entry)
            self.save_execution_state(run_id, execution_state)
    
    def render_template(self, template_str: str, context: Dict[str, Any]) -> Any:
        """
        Render a Jinja2 template string with the given context
        
        Args:
            template_str: The template string to render
            context: Dictionary containing template variables
            
        Returns:
            Rendered value (can be string, dict, list, etc.)
            
        Raises:
            TemplateRenderError: If rendering fails
        """
        if not isinstance(template_str, str):
            return template_str

        # SECURITY: Reject templates containing dangerous patterns
        template_lower = template_str.lower()
        for pattern in self._DANGEROUS_PATTERNS:
            if pattern.lower() in template_lower:
                raise TemplateRenderError(
                    f"Template contains blocked pattern: '{pattern}'"
                )

        try:
            template = jinja_env.from_string(template_str)
            rendered = template.render(**context)
            
            # Try to parse as JSON if it looks like structured data
            if rendered.startswith(('{', '[')) and rendered.endswith(('}', ']')):
                try:
                    return json.loads(rendered)
                except json.JSONDecodeError:
                    pass
            
            return rendered
            
        except SecurityError as e:
            raise TemplateRenderError(f"Template blocked by sandbox: {str(e)}")
        except (TemplateSyntaxError, UndefinedError) as e:
            raise TemplateRenderError(f"Template rendering failed: {str(e)}")
    
    def render_step_input(self, step_input: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively render all template strings in step input
        
        Args:
            step_input: Dictionary containing input parameters
            context: Template rendering context
            
        Returns:
            Dictionary with rendered values
        """
        if not step_input:
            return {}
        
        rendered_input = {}
        
        for key, value in step_input.items():
            if isinstance(value, str):
                rendered_input[key] = self.render_template(value, context)
            elif isinstance(value, dict):
                rendered_input[key] = self.render_step_input(value, context)
            elif isinstance(value, list):
                rendered_input[key] = [
                    self.render_template(item, context) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                rendered_input[key] = value
        
        return rendered_input
    
    # Patterns that must NEVER appear in playbook conditions or templates
    _DANGEROUS_PATTERNS = [
        '__class__', '__subclasses__', '__import__', '__globals__',
        '__builtins__', '__mro__', '__bases__', '__init__',
        'os.system', 'os.popen', 'subprocess', 'eval(', 'exec(',
        'compile(', 'open(', 'getattr(', 'setattr(',
    ]

    def evaluate_condition(
        self,
        condition: str,
        context: Dict[str, Any],
        run_id: Optional[str] = None,
    ) -> bool:
        """
        Evaluate a Jinja2 condition expression

        A condition that references an undefined name -- a trigger field
        that was not sent, an attribute an earlier step did not return --
        evaluates to false, and the reference is logged (to the run log too
        when run_id is given). The reference is reported as written in the
        condition; no value from the context is logged (#595).

        Every other template error still raises TemplateRenderError: a syntax
        error, a sandbox violation and a blocked pattern are faults in the
        playbook, not facts about the data, and must not pass for a condition
        that does not hold.

        Args:
            condition: Jinja2 condition expression
            context: Template rendering context
            run_id: Run whose log records an undefined reference, if any

        Returns:
            Boolean result of condition evaluation

        Raises:
            TemplateRenderError: If the condition is not a valid expression,
                contains a blocked pattern or is blocked by the sandbox
        """
        if not condition:
            return True

        template_str, template = self.compile_condition(condition)

        try:
            result = template.render(**context)
        except SecurityError as e:
            raise TemplateRenderError(f"Condition blocked by sandbox: {e}")
        except _UndefinedReferenceError as e:
            reference = self._undefined_reference(template_str, e.undefined, context)
            message = (
                f"Condition references an undefined name ({reference}); "
                "evaluating it as false"
            )
            logger.warning(message)
            if run_id:
                self.add_log(run_id, message, level="WARNING")
            return False
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False
        return result == "true"

    def compile_condition(self, condition: str):
        """Check and compile a step condition without evaluating it.

        Used by evaluate_condition, and by the tests that check every shipped
        playbook, so that both apply the same rules.

        Returns:
            (template source, compiled template)

        Raises:
            TemplateRenderError: If the condition contains a blocked pattern
                or is not a valid expression
        """
        # SECURITY: Reject conditions containing dangerous patterns
        condition_lower = condition.lower()
        for pattern in self._DANGEROUS_PATTERNS:
            if pattern.lower() in condition_lower:
                # Raise, as the sandbox does: an attempt to reach Python
                # internals must fail the step, not pass for a condition
                # that does not hold.
                logger.warning(
                    f"Blocked dangerous pattern '{pattern}' in playbook condition: {condition[:100]}"
                )
                raise TemplateRenderError(
                    f"Condition contains blocked pattern: '{pattern}'"
                )

        # Wrap condition in an if statement to get boolean result
        template_str = f"{{% if {condition} %}}true{{% else %}}false{{% endif %}}"
        try:
            template = condition_env.from_string(template_str)
        except TemplateSyntaxError as e:
            raise TemplateRenderError(f"Condition is not a valid expression: {e}")
        return template_str, template

    @staticmethod
    def _undefined_reference(
        template_str: str, undefined: StrictUndefined, context: Dict[str, Any]
    ) -> str:
        """Name the reference that produced ``undefined``, as written in the condition.

        The name is taken from the condition's source, never from the
        context: a subscript computed at run time could carry a value, so a
        reference that is not spelled out in the condition is described
        generically.
        """
        name = undefined._undefined_name
        if undefined._undefined_obj is missing:
            # A bare name: it can only come from the source.
            return f"'{name}'"

        def static_path(node):
            if isinstance(node, nodes.Name):
                return (node.name,)
            if isinstance(node, nodes.Getattr):
                base = static_path(node.node)
                return base + (node.attr,) if base else None
            if (
                isinstance(node, nodes.Getitem)
                and isinstance(node.arg, nodes.Const)
                and isinstance(node.arg.value, (str, int))
            ):
                base = static_path(node.node)
                return base + (node.arg.value,) if base else None
            return None

        def resolve(path):
            value = context.get(path[0], condition_env.globals.get(path[0], missing))
            for part in path[1:]:
                if isinstance(part, str):
                    value = condition_env.getattr(value, part)
                else:
                    value = condition_env.getitem(value, part)
            return value

        def spell(path):
            text = str(path[0])
            for part in path[1:]:
                text += f".{part}" if isinstance(part, str) else f"[{part}]"
            return text

        ast = condition_env.parse(template_str)
        for node in ast.find_all((nodes.Getattr, nodes.Getitem)):
            path = static_path(node)
            if not path or path[-1] != name:
                continue
            try:
                parent = resolve(path[:-1])
            except (TemplateRuntimeError, TypeError, ValueError, LookupError):
                continue  # a sibling path that cannot be resolved is not the one
            if parent is undefined._undefined_obj:
                return f"'{spell(path)}'"
        return "a key computed at run time"


# Global workflow engine instance
workflow_engine = WorkflowEngine()


@dramatiq.actor(store_results=True, max_retries=0)
def execute_playbook_actor(
    run_id: str,
    playbook_id: str,
    trigger_data: Dict[str, Any],
    caller: Optional[Dict[str, str]] = None,
):
    """
    Dramatiq actor for executing playbooks asynchronously
    
    Args:
        run_id: Unique identifier for this execution
        playbook_id: ID of the playbook to execute
        trigger_data: Data provided by the trigger
        caller: The user who started the run, as recorded by start_execution
            (user_id, team_id, role). Every call the run makes to another
            service is made as this user (#616). A run without one fails
            before its first step.
        
    Returns:
        Final execution result
    """
    start_time = datetime.utcnow()
    # Holds the run's caller identity; closed in `finally`, so the identity
    # is reset however the run ends and the next message this worker thread
    # runs does not inherit it (#594, #616).
    identity_scope = ExitStack()
    
    try:
        # Get the playbook - reload to ensure worker has fresh copy
        try:
            # Ensure playbook_parser has loaded playbooks in this worker process
            if not playbook_parser.playbooks:
                playbook_parser.load_playbooks()
            playbook = playbook_parser.get_playbook(playbook_id)
        except KeyError:
            raise WorkflowExecutionError(f"Playbook '{playbook_id}' not found")
        
        # Load existing state from Redis (created in start_execution).
        # A corrupt record now raises ExecutionStateCorruptError rather than
        # returning None, so it cannot be mistaken for a miss and overwritten
        # with a fresh RUNNING record (WILDBO-DATA-02).
        execution_result = workflow_engine.get_execution_state(run_id)
        
        if not execution_result:
            # Genuinely absent: the record expired, or was evicted. Create state
            # so the run is at least tracked, and say so.
            logger.warning(
                f"No persisted state for run {run_id}; creating a new record. "
                "This means the original was expired or evicted."
            )
            execution_result = PlaybookExecutionResult(
                run_id=run_id,
                playbook_id=playbook_id,
                playbook_name=playbook.name,
                status=ExecutionStatus.RUNNING,
                start_time=start_time,
                trigger_data=trigger_data,
                context={"trigger": trigger_data}
            )
        else:
            # A run cancelled while it was queued never starts (#653).
            if workflow_engine.cancel_requested(run_id):
                raise RunCancelled([step.name for step in playbook.steps])

            # Update status to RUNNING
            execution_result.status = ExecutionStatus.RUNNING
            execution_result.playbook_name = playbook.name

        # Every run's context carries `run`, built from the persisted start
        # time so it reads the same however often the record is reloaded.
        execution_result.context.setdefault(
            "run", run_context(run_id, playbook_id, execution_result.start_time)
        )

        # Save updated state (QUEUED -> RUNNING transition)
        workflow_engine.save_execution_state(run_id, execution_result)
        workflow_engine.add_log(run_id, f"Starting execution of playbook '{playbook.name}'")

        # Act for the user who started the run, or not at all. A run without
        # a complete caller fails here, before any step, so no connector call
        # is ever sent without an identity or under someone else's.
        try:
            identity = identity_scope.enter_context(run_as(caller))
        except CallerIdentityUnavailable as e:
            raise WorkflowExecutionError(f"Refusing to run: {e}") from e
        workflow_engine.add_log(
            run_id,
            f"Acting for user {identity['user_id']} in team {identity['team_id']} "
            f"(role {identity['role']})",
        )
        
        # Execute each step
        for index, step in enumerate(playbook.steps):
            # A cancel is honored between steps (#653). A step already
            # running is not interrupted: its connector call has been sent
            # and may have taken effect, so it runs to its end and is
            # recorded as it ended, completed or failed, never dropped.
            if workflow_engine.cancel_requested(run_id):
                raise RunCancelled([s.name for s in playbook.steps[index:]])

            step_start_time = datetime.utcnow()
            
            try:
                # Create step result
                step_result = StepExecutionResult(
                    step_name=step.name,
                    status=ExecutionStatus.RUNNING,
                    start_time=step_start_time
                )
                
                workflow_engine.add_log(run_id, f"Executing step '{step.name}'")
                
                # Evaluate condition if present
                if step.condition:
                    condition_result = workflow_engine.evaluate_condition(
                        step.condition,
                        execution_result.context,
                        run_id=run_id,
                    )
                    if not condition_result:
                        workflow_engine.add_log(
                            run_id, 
                            f"Step '{step.name}' skipped due to condition: {step.condition}"
                        )
                        step_result.status = ExecutionStatus.COMPLETED
                        step_result.end_time = datetime.utcnow()
                        step_result.output = {"skipped": True, "reason": "condition_failed"}
                        execution_result.step_results.append(step_result)
                        continue
                
                # Render step input
                try:
                    rendered_input = workflow_engine.render_step_input(
                        step.input or {}, 
                        execution_result.context
                    )
                except TemplateRenderError as e:
                    raise WorkflowExecutionError(f"Failed to render input for step '{step.name}': {e}")
                
                # Execute the action via the connector registry. A connector
                # failure must surface as a FAILED step (handled by the outer
                # except below) — never substitute fabricated "success" data.
                connector_name, action_name = step.action.split('.', 1)
                workflow_engine.add_log(
                    run_id,
                    f"Executing action '{action_name}' on connector '{connector_name}' with input: {json.dumps(rendered_input, indent=2)}"
                )

                action_result = connector_registry.execute_action(
                    connector_name,
                    action_name,
                    rendered_input
                )
                
                # Update step result
                step_result.status = ExecutionStatus.COMPLETED
                step_result.end_time = datetime.utcnow()
                step_result.duration_seconds = (step_result.end_time - step_result.start_time).total_seconds()
                step_result.output = action_result
                
                # Update context with step result.
                #
                # Keyed by id when the step has one. The key is what a later
                # step writes in `{{ steps.<key>.output }}`, and playbooks that
                # give their steps an id refer to them by it -- while this used
                # to key by `name`, the display label ("🤖 AI-Powered Threat
                # Analysis"). Every cross-step reference in all_star_e2e.yml
                # therefore resolved to nothing, silently: conditions read as
                # false and templates rendered empty. Playbooks without ids are
                # unaffected, since there `name` is the identifier.
                if "steps" not in execution_result.context:
                    execution_result.context["steps"] = {}
                execution_result.context["steps"][step_context_key(step)] = {
                    "output": action_result,
                    "status": step_result.status,
                    "duration": step_result.duration_seconds
                }
                
                execution_result.step_results.append(step_result)
                workflow_engine.add_log(
                    run_id, 
                    f"Step '{step.name}' completed successfully in {step_result.duration_seconds:.2f}s"
                )
                
            except Exception as e:
                # Catch Exception, not five builtins.
                #
                # The documented failure of a step is ConnectorError, raised by
                # connector_registry.execute_action -- and ConnectorError is a
                # plain Exception subclass, so it skipped this handler entirely
                # and the step was never marked FAILED (WILDBO-ERR-02).
                # Handle step failure
                step_result.status = ExecutionStatus.FAILED
                step_result.end_time = datetime.utcnow()
                step_result.duration_seconds = (step_result.end_time - step_result.start_time).total_seconds()
                step_result.error = str(e)
                
                execution_result.step_results.append(step_result)
                workflow_engine.add_log(
                    run_id, 
                    f"Step '{step.name}' failed: {str(e)}", 
                    level="ERROR"
                )
                
                # on_failure decides whether the run ends here.
                #
                # Four steps of playbooks/all_star_e2e.yml declare
                # `on_failure: "continue"`. Nothing read that key -- the engine
                # always raised -- so a playbook that asked to carry on stopped
                # at its first enrichment failure, and the steps after it never
                # ran. The failure is recorded either way; what changes is
                # whether the remaining steps get their turn.
                if step.on_failure == StepFailurePolicy.CONTINUE:
                    if "steps" not in execution_result.context:
                        execution_result.context["steps"] = {}
                    execution_result.context["steps"][step_context_key(step)] = {
                        "output": None,
                        "status": step_result.status,
                        "error": step_result.error,
                        "duration": step_result.duration_seconds,
                    }
                    workflow_engine.add_log(
                        run_id,
                        f"Step '{step.name}' declares on_failure=continue; carrying on",
                        level="WARNING",
                    )
                    continue

                # Fail the entire execution
                raise WorkflowExecutionError(f"Step '{step.name}' failed: {str(e)}")
        
        # Mark execution as completed
        execution_result.status = ExecutionStatus.COMPLETED
        execution_result.end_time = datetime.utcnow()
        execution_result.duration_seconds = (execution_result.end_time - execution_result.start_time).total_seconds()
        
        # FIX: Persist completed state to Redis. A cancel accepted after the
        # last step started makes this write record CANCELLED instead
        # (resolve_status), and save_execution_state says so.
        workflow_engine.save_execution_state(run_id, execution_result)
        if execution_result.status == ExecutionStatus.CANCELLED:
            workflow_engine.add_log(
                run_id,
                "Run cancelled at the user's request after its last step had "
                "started; every step ran",
                level="WARNING",
            )
        else:
            workflow_engine.add_log(
                run_id,
                f"Playbook execution completed successfully in {execution_result.duration_seconds:.2f}s"
            )

    except RunCancelled as cancelled:
        # The cancel was found before a step started: no further step runs.
        # The steps that did run are in step_results, as they ended (#653).
        # A run cancelled while queued keeps the time it was cancelled.
        if not (
            execution_result.status == ExecutionStatus.CANCELLED
            and execution_result.end_time
        ):
            execution_result.end_time = datetime.utcnow()
        execution_result.status = ExecutionStatus.CANCELLED
        execution_result.duration_seconds = (
            execution_result.end_time - execution_result.start_time
        ).total_seconds()
        workflow_engine.save_execution_state(run_id, execution_result)
        ran = [result.step_name for result in execution_result.step_results]
        workflow_engine.add_log(
            run_id,
            "Run cancelled at the user's request. "
            f"Steps that ran: {', '.join(ran) or 'none'}. "
            f"Steps not run: {', '.join(cancelled.not_run) or 'none'}.",
            level="WARNING",
        )
        logger.info(f"Playbook execution {run_id} cancelled")

    except Exception as e:
        # Catch Exception here too. WorkflowExecutionError -- which the step
        # handler above raises deliberately to fail the run -- is an Exception
        # subclass, so even the designed failure path did not reach this block
        # and the run was left persisted as RUNNING (WILDBO-ERR-02).
        # Handle execution failure
        # Ensure we have an execution_result even if error occurred early
        if 'execution_result' not in locals():
            execution_result = PlaybookExecutionResult(
                run_id=run_id,
                playbook_id=playbook_id,
                playbook_name="Unknown",
                status=ExecutionStatus.FAILED,
                start_time=start_time,
                trigger_data=trigger_data,
                context={"trigger": trigger_data}
            )
        
        execution_result.status = ExecutionStatus.FAILED
        execution_result.end_time = datetime.utcnow()
        execution_result.duration_seconds = (execution_result.end_time - execution_result.start_time).total_seconds()
        execution_result.error = str(e)
        
        # FIX: Persist failed state to Redis
        workflow_engine.save_execution_state(run_id, execution_result)
        workflow_engine.add_log(run_id, f"Playbook execution failed: {str(e)}", level="ERROR")
        logger.error(f"Playbook execution {run_id} failed: {e}")
    
    finally:
        identity_scope.close()
        # Final state save. A run that reaches this block has stopped, so it must
        # not be left saying RUNNING: if some future exception escapes both
        # handlers above, record it as FAILED rather than persisting a lie that
        # nothing will ever correct (WILDBO-ERR-02/WILDBO-REL-02).
        if 'execution_result' in locals():
            if execution_result.status in (
                ExecutionStatus.RUNNING,
                ExecutionStatus.QUEUED,
                ExecutionStatus.CANCELLING,
            ):
                execution_result.status = ExecutionStatus.FAILED
                execution_result.end_time = datetime.utcnow()
                if not getattr(execution_result, "error", None):
                    execution_result.error = (
                        "Execution ended without reporting a terminal status"
                    )
                workflow_engine.add_log(
                    run_id,
                    "Execution ended without a terminal status; recorded as FAILED",
                    level="ERROR",
                )
            workflow_engine.save_execution_state(run_id, execution_result)
    
    return execution_result.dict()


def start_execution(
    playbook_id: str,
    trigger_data: Dict[str, Any] = None,
    caller: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    Start a new playbook execution
    
    Args:
        playbook_id: ID of the playbook to execute
        trigger_data: Data provided by the trigger
        caller: The gateway-authenticated user starting the run (user_id,
            team_id, role). The run is owned by their team and acts as them
            in every call it makes (#616).
        
    Returns:
        Unique run ID for the execution
        
    Raises:
        WorkflowExecutionError: If playbook doesn't exist
        CallerIdentityUnavailable: If ``caller`` is missing or incomplete;
            nothing is persisted or queued then.
    """
    # Who the run acts for, checked before anything is written or queued.
    identity = require_caller(caller)

    # Validate playbook exists
    try:
        playbook = playbook_parser.get_playbook(playbook_id)
    except KeyError:
        raise WorkflowExecutionError(f"Playbook '{playbook_id}' not found")
    
    # Generate unique run ID
    run_id = str(uuid.uuid4())
    
    # FIX: Persist initial state to Redis BEFORE enqueueing
    initial_state = PlaybookExecutionResult(
        run_id=run_id,
        playbook_id=playbook_id,
        playbook_name=playbook.name,
        status=ExecutionStatus.QUEUED,
        start_time=datetime.utcnow(),
        trigger_data=trigger_data or {},
        context={"trigger": trigger_data or {}}
    )
    workflow_engine.save_execution_state(run_id, initial_state)

    # Record the owner BEFORE the work is dispatched. This used to happen in the
    # HTTP handler after start_execution returned, so a crash in that window left
    # a run executing with no owner key -- and because is_run_owner fails closed,
    # no team could read or cancel it while it performed its side effects
    # (WILDBO-DATA-06).
    workflow_engine.set_run_owner(run_id, identity["team_id"])

    workflow_engine.add_log(run_id, f"Playbook '{playbook.name}' queued for execution")
    
    # Start execution
    # The caller travels with the message: the worker sets it for the run's
    # duration and the connectors send it with every request (#616).
    execute_playbook_actor.send(run_id, playbook_id, trigger_data or {}, identity)
    
    logger.info(f"Started execution {run_id} for playbook '{playbook_id}'")
    return run_id
