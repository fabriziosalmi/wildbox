"""What the asynchronous runs did, where Prometheus can read it (#721).

``wildbox_tool_executions_total`` is a counter in the memory of the API
process, so it holds the synchronous runs only. An asynchronous run executes
in ``tools-worker``, a Celery prefork worker, and was counted nowhere:

* Prometheus cannot scrape the worker. In the production overlay it is on
  the ``data`` and ``egress`` networks and Prometheus on ``backend``, and it
  serves no HTTP at all.
* A counter in the worker's memory would be one per child process, and the
  pool replaces a child after fifty tasks and whenever it kills one.
* The child that runs a task is not the process that learns how the task
  ended when it is killed at the hard time limit or cancelled: the worker's
  main process is.

So the counts are kept in the service's Redis, which every process of the
service reaches, and the API process exports them from ``/metrics``, which
Prometheus already scrapes:

``wildbox:tools:async-outcomes``
    A hash, ``<tool>|<outcome>`` to a number. One is added for each task
    when Celery settles its state, by the process that settles it (see
    ``app.tasks``): the child for a task that returned or raised, the
    worker's main process for one killed at the hard time limit or
    cancelled.

``wildbox:tools:async-consumed``
    How many times a worker took a task off the queue: once for each start
    (a retried task starts more than once) and once for a task it dropped
    because it had been cancelled while it waited.

The third number is not kept here, because the broker already holds it: the
length of the Celery queue, a Redis list in the same database, is how many
tasks no worker has taken yet. A queue that stays non-empty while the
consumed count stands still is a worker that consumes nothing.

A write that fails (Redis did not answer the worker) is logged and the task
goes on: these are metrics, and a task must not fail for them. The count is
then short by one. A read that fails exports no number at all, only
``wildbox_tool_async_metrics_up 0``: a zero would read as a counter that
was reset, and the next good reading as a burst of runs.
"""

import os
import threading
from typing import Dict, Optional, Tuple

from app.logging_config import get_logger
from redis.exceptions import RedisError

logger = get_logger(__name__)

OUTCOMES_KEY = "wildbox:tools:async-outcomes"
CONSUMED_KEY = "wildbox:tools:async-consumed"

# How a task can end. The values are the ones the synchronous counter uses.
COMPLETED = "completed"
FAILED = "failed"
TIMEOUT = "timeout"
CANCELLED = "cancelled"
REFUSED = "refused"
OUTCOMES = (COMPLETED, FAILED, TIMEOUT, CANCELLED, REFUSED)

# The label of a task whose tool name is not a tool. The name is the path
# segment the caller wrote, so it cannot be a label as it is: every new
# spelling would be a new series, for ever.
UNKNOWN_TOOL = "unknown"

_FIELD_SEPARATOR = "|"


class Snapshot:
    """One reading of the counts."""

    def __init__(
        self, outcomes: Dict[Tuple[str, str], int], consumed: int, queued: int
    ):
        self.outcomes = outcomes
        self.consumed = consumed
        self.queued = queued


class AsyncRunCounts:
    """The counts above, on one Redis client.

    ``queue`` is the name of the Celery queue the tasks wait in. With the
    Redis transport a queue is a list under its own name, holding the
    messages no worker has reserved.
    """

    def __init__(self, client, queue: str):
        # A redis.Redis created with decode_responses=True, on the database
        # that is also the Celery broker.
        self._redis = client
        self._queue = queue

    # --- written by the worker ------------------------------------------------

    def task_taken(self) -> None:
        """A worker took a task off the queue and is starting it."""
        self._redis.incr(CONSUMED_KEY)

    def task_settled(self, tool: str, outcome: str, taken_now: bool = False) -> None:
        """Count how a task ended.

        ``taken_now``: the task never started, so nothing has counted it as
        consumed yet (a task cancelled while it waited).
        """
        if outcome not in OUTCOMES:
            raise ValueError(f"not an outcome: {outcome!r}")
        pipe = self._redis.pipeline()
        pipe.hincrby(OUTCOMES_KEY, f"{tool}{_FIELD_SEPARATOR}{outcome}", 1)
        if taken_now:
            pipe.incr(CONSUMED_KEY)
        pipe.execute()

    # --- read by the API --------------------------------------------------------

    def read(self) -> Snapshot:
        pipe = self._redis.pipeline()
        pipe.hgetall(OUTCOMES_KEY)
        pipe.get(CONSUMED_KEY)
        pipe.llen(self._queue)
        outcomes, consumed, queued = pipe.execute()

        counts: Dict[Tuple[str, str], int] = {}
        for field, value in (outcomes or {}).items():
            tool, separator, outcome = field.rpartition(_FIELD_SEPARATOR)
            if not separator or not tool or outcome not in OUTCOMES:
                continue
            counts[(tool, outcome)] = int(value)
        return Snapshot(
            outcomes=counts, consumed=int(consumed or 0), queued=int(queued)
        )


_known_tools: Optional[frozenset] = None


def tool_label(tool_name) -> str:
    """The ``tool`` label for a task: the tool's name, if it is one."""
    global _known_tools
    if _known_tools is None:
        from app.tool_loader import list_tool_names

        _known_tools = frozenset(list_tool_names())
    return tool_name if tool_name in _known_tools else UNKNOWN_TOOL


_counts: Optional[Tuple[int, AsyncRunCounts]] = None
_counts_lock = threading.Lock()


def get_counts() -> Optional[AsyncRunCounts]:
    """This process's client for the counts, or None without ``REDIS_URL``.

    One per process: a worker child is forked from a process that may already
    have one, and a connection must not be shared across a fork.
    """
    global _counts
    pid = os.getpid()
    if _counts is None or _counts[0] != pid:
        with _counts_lock:
            if _counts is None or _counts[0] != pid:
                from app.config import settings

                if not settings.redis_url:
                    return None
                import redis
                from app.celery_app import celery_app

                client = redis.Redis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    # A scrape, and a task that reports its end, wait this
                    # long for Redis and no longer.
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                _counts = (
                    pid,
                    AsyncRunCounts(client, queue=celery_app.conf.task_default_queue),
                )
    return _counts[1]


def _from_the_worker(what: str, write) -> None:
    """Run one of the worker's writes; a failure is logged, never raised."""
    try:
        counts = get_counts()
        if counts is not None:
            write(counts)
    except (RedisError, OSError, ValueError) as error:
        logger.warning(
            f"Asynchronous run metrics: could not record {what}: "
            f"{type(error).__name__}: {error}"
        )


def record_taken(task_id: Optional[str]) -> None:
    """From the worker: a task is starting."""
    _from_the_worker(
        f"that task {task_id} was taken", lambda counts: counts.task_taken()
    )


def record_outcome(
    task_id: Optional[str], tool_name, outcome: str, taken_now: bool = False
) -> None:
    """From the worker: a task has ended with ``outcome``."""
    _from_the_worker(
        f"the outcome {outcome} of task {task_id}",
        lambda counts: counts.task_settled(
            tool_label(tool_name), outcome, taken_now=taken_now
        ),
    )


class AsyncRunsCollector:
    """The counts, as Prometheus metrics, read from Redis on every scrape."""

    def __init__(self, counts_source=get_counts):
        self._counts = counts_source

    def collect(self):
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

        executions = CounterMetricFamily(
            "wildbox_tool_async_executions",
            "Asynchronous tool tasks by tool and final outcome.",
            labels=["tool", "outcome"],
        )
        consumed = CounterMetricFamily(
            "wildbox_tool_async_tasks_consumed",
            "Times a worker took an asynchronous tool task off the queue.",
        )
        queued = GaugeMetricFamily(
            "wildbox_tool_async_queue_length",
            "Asynchronous tool tasks in the queue, not yet taken by a worker.",
        )
        up = GaugeMetricFamily(
            "wildbox_tool_async_metrics_up",
            "1 when the asynchronous run counts could be read from Redis, else 0.",
        )

        snapshot = None
        try:
            counts = self._counts()
            if counts is not None:
                snapshot = counts.read()
        except (RedisError, OSError, ValueError) as error:
            logger.warning(
                "Asynchronous run metrics: could not read the counts: "
                f"{type(error).__name__}: {error}"
            )

        if snapshot is None:
            # No number is better than a wrong one. The families are still
            # named, so a rule that reads them is not a rule on nothing; they
            # carry no sample.
            up.add_metric([], 0)
        else:
            up.add_metric([], 1)
            for (tool, outcome), count in sorted(snapshot.outcomes.items()):
                executions.add_metric([tool, outcome], count)
            consumed.add_metric([], snapshot.consumed)
            queued.add_metric([], snapshot.queued)
        return [executions, consumed, queued, up]
