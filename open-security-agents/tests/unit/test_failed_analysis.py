"""An analysis that fails is a failed task, with no report (#717).

Three paths turned a failure into a completed analysis:

- the agent answered a report with the verdict "Informational" and
  confidence 0 when it raised one of five builtin exceptions;
- the worker did the same when the task body raised one, after setting the
  Celery state to FAILURE, which returning then replaced with SUCCESS;
- a structured report that could not be generated was replaced by a verdict
  taken from the first verdict word in the narrative ("not malicious" read
  as Malicious), a confidence of 0.3 and one evidence item per tool that no
  tool had reported.

A client got a well-formed report for an analysis that had not run. Now each
of them raises: the worker records why with the task, Celery records
FAILURE, the API answers ``status: failed`` with a reason fit for the user,
and nothing but the model's structured output produces a verdict.

No test calls a model API: the agent runs with a scripted model.
"""

import asyncio
import os
import sys

import pytest
from anthropic import AnthropicError
from celery.exceptions import SoftTimeLimitExceeded
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage
from open_security_shared.circuit_breaker import CircuitBreaker, CircuitBreakerError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import failures, main, stats, worker  # noqa: E402
from app.agents import threat_enrichment_agent as agent_module  # noqa: E402
from app.agents.threat_enrichment_agent import ThreatEnrichmentAgent  # noqa: E402
from app.config import settings  # noqa: E402
from app.failures import AnalysisFailed, reason_for  # noqa: E402
from app.tools.wildbox_client import (  # noqa: E402
    CallerIdentityUnavailable,
    _caller_identity,
)
from scripted_model import ScriptedModel  # noqa: E402

SECRET = "gateway-secret-for-tests"
CALLER = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "role": "member",
}
IOC = {"type": "domain", "value": "example.com"}
TASK_ID = "11111111-2222-4333-8444-555555555555"
REPORT_FIELDS = {
    "verdict",
    "confidence",
    "executive_summary",
    "evidence",
    "full_report",
}


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        value = self.store.get(key)
        if value is None:
            return None
        return value if isinstance(value, bytes) else str(value).encode()

    def setex(self, key, ttl, value):
        self.store[key] = value

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def expire(self, key, ttl):
        return True

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    """No caller identity left behind, and a circuit breaker of this test's
    own: the production one is a module global that failures here would open
    for the tests that follow."""
    _caller_identity.set(None)
    monkeypatch.setattr(
        agent_module,
        "LLM_BREAKER",
        CircuitBreaker(
            name="test", failure_threshold=3, timeout=120, recovery_timeout=60
        ),
    )
    yield
    _caller_identity.set(None)


@pytest.fixture
def redis(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(worker, "redis_client", redis)
    monkeypatch.setattr(main, "redis_client", redis)
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )
    return redis


def stand_in_agent(monkeypatch, outcome):
    """An agent whose analysis raises ``outcome``, or returns it."""
    built = []

    class Agent:
        async def analyze_ioc(self, ioc):
            if isinstance(outcome, BaseException):
                raise outcome
            return dict(outcome)

    def build():
        built.append(True)
        return Agent()

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", build)
    return built


def production_agent(monkeypatch, responses, report=None):
    """The production agent with a scripted model instead of Claude."""
    model = ScriptedModel(responses=responses, report=report)
    monkeypatch.setattr(ThreatEnrichmentAgent, "_initialize_llm", lambda self: model)
    agent = ThreatEnrichmentAgent()
    monkeypatch.setattr(worker, "get_threat_enrichment_agent", lambda: agent)
    return agent


def run_task(task_id=TASK_ID, caller=CALLER):
    return worker.run_threat_enrichment_task(
        task_id=task_id, ioc=dict(IOC), caller=caller
    )


def recorded(redis, task_id=TASK_ID):
    """The failure code the worker left for the API, or None.

    The worker also wrote a ``task:<id>:status`` key ("running", "completed",
    "failed") that nothing read: the API takes a task's status from Celery
    and its failure from the ``error`` key (#665). No test may see that key
    come back.
    """
    assert f"task:{task_id}:status" not in redis.store
    return redis.store.get(f"task:{task_id}:error")


# --- The worker: a failure raises, and is recorded ---------------------------


@pytest.mark.parametrize(
    "error",
    [
        ValueError("bad tool output"),
        KeyError("output"),
        TypeError("Could not resolve authentication method"),
        ConnectionError("connection reset"),
        RuntimeError("anything else"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_an_error_in_the_analysis_fails_the_task_and_returns_no_report(
    monkeypatch, redis, error
):
    """The first four are the types that used to be answered with a report."""
    stand_in_agent(monkeypatch, error)

    with pytest.raises(type(error)):
        run_task()

    assert recorded(redis) == failures.INTERNAL
    assert stats.read_today(redis, stats.FAILED) == 1
    assert stats.read_today(redis, stats.COMPLETED) == 0


@pytest.mark.parametrize(
    "code",
    [failures.MODEL_UNAVAILABLE, failures.TIMED_OUT, failures.REPORT_FAILED],
)
def test_the_agents_own_failure_is_recorded_with_its_code(monkeypatch, redis, code):
    stand_in_agent(monkeypatch, AnalysisFailed(code))

    with pytest.raises(AnalysisFailed) as failed:
        run_task()

    assert failed.value.code == code
    assert recorded(redis) == code
    assert stats.read_today(redis, stats.FAILED) == 1
    assert stats.read_today(redis, stats.COMPLETED) == 0


def test_the_soft_time_limit_is_recorded_as_a_timeout(monkeypatch, redis):
    stand_in_agent(monkeypatch, SoftTimeLimitExceeded())

    with pytest.raises(SoftTimeLimitExceeded):
        run_task()

    assert recorded(redis) == failures.TIMED_OUT


def test_a_task_without_a_caller_is_recorded_as_such(monkeypatch, redis):
    built = stand_in_agent(monkeypatch, {"verdict": "Benign"})

    with pytest.raises(CallerIdentityUnavailable):
        run_task(caller=None)

    assert recorded(redis) == failures.NO_CALLER
    assert built == []


@pytest.mark.parametrize("key", [None, "", "   ", "your_anthropic_api_key_here"])
def test_without_a_model_key_the_task_fails_before_anything_runs(
    monkeypatch, redis, key
):
    """It used to go on, fail on the model's authentication with a TypeError,
    and come back as a completed "Informational" report."""
    monkeypatch.setattr(settings, "anthropic_api_key", key)
    built = stand_in_agent(monkeypatch, {"verdict": "Benign"})

    with pytest.raises(AnalysisFailed) as failed:
        run_task()

    assert failed.value.code == failures.NOT_CONFIGURED
    assert recorded(redis) == failures.NOT_CONFIGURED
    assert built == [], "the agent was built without a model key"
    assert stats.read_today(redis, stats.COMPLETED) == 0


def test_an_analysis_that_runs_is_completed_as_before(monkeypatch, redis):
    report = {"verdict": "Benign", "confidence": 0.9, "tools_used": []}
    stand_in_agent(monkeypatch, report)

    result = run_task()

    assert result == {**report, "task_id": TASK_ID}
    assert recorded(redis) is None
    assert stats.read_today(redis, stats.COMPLETED) == 1
    assert stats.read_today(redis, stats.FAILED) == 0


def test_a_failure_that_cannot_be_recorded_still_fails_as_itself(monkeypatch, redis):
    """Redis down while recording: the task's own error is what is raised."""
    stand_in_agent(monkeypatch, AnalysisFailed(failures.MODEL_UNAVAILABLE))

    setex = redis.setex

    def down_when_recording(key, ttl, value):
        if value == "failed":
            raise ConnectionError("redis is down")
        setex(key, ttl, value)

    monkeypatch.setattr(redis, "setex", down_when_recording)

    with pytest.raises(AnalysisFailed):
        run_task()


# --- The agent: no report but the model's ------------------------------------


@pytest.mark.parametrize(
    "error, code",
    [
        (AnthropicError("401 invalid x-api-key"), failures.MODEL_UNAVAILABLE),
        (
            CircuitBreakerError("Circuit breaker 'anthropic_agent' is OPEN."),
            failures.MODEL_UNAVAILABLE,
        ),
        (TimeoutError(), failures.TIMED_OUT),
    ],
    ids=["model-refused", "breaker-open", "timeout"],
)
def test_a_model_that_cannot_be_used_fails_the_analysis(monkeypatch, error, code):
    agent = production_agent(monkeypatch, [AIMessage(content="unused")])

    async def unusable(func, *args, **kwargs):
        raise error

    monkeypatch.setattr(agent_module.LLM_BREAKER, "call", unusable)

    with pytest.raises(AnalysisFailed) as failed:
        asyncio.run(agent.analyze_ioc(dict(IOC)))

    assert failed.value.code == code
    assert failed.value.__cause__ is error


@pytest.mark.parametrize(
    "narrative",
    [
        "The indicator is not malicious. Benign.",
        "Malicious infrastructure, without a doubt.",
        "",
    ],
)
def test_a_report_that_cannot_be_generated_is_a_failure_not_a_guess(
    monkeypatch, narrative
):
    """The fallback read the first verdict word of the narrative: the first
    of these came back "Malicious", with confidence 0.3."""
    agent = production_agent(
        monkeypatch,
        [AIMessage(content=narrative)],
        report=ValueError("the model returned no structured output"),
    )

    with pytest.raises(AnalysisFailed) as failed:
        asyncio.run(agent.analyze_ioc(dict(IOC)))

    assert failed.value.code == failures.REPORT_FAILED
    assert isinstance(failed.value.__cause__, ValueError)


def test_the_verdict_and_the_evidence_are_the_models_own(monkeypatch):
    """With a report from the model, every field of the result is that
    report's: nothing is taken from the narrative or filled in."""
    report = {
        "verdict": "Suspicious",
        "confidence": 0.42,
        "executive_summary": "One source flags the domain.",
        "evidence": [
            {
                "source": "reputation_check_tool",
                "finding": "Listed once.",
                "severity": "medium",
            }
        ],
        "recommended_actions": ["Monitor"],
    }
    agent = production_agent(
        monkeypatch, [AIMessage(content="Clearly Malicious, block it.")], report=report
    )

    result = asyncio.run(agent.analyze_ioc(dict(IOC)))

    assert result["verdict"] == "Suspicious"
    assert result["confidence"] == 0.42
    assert result["evidence"] == report["evidence"]
    assert result["recommended_actions"] == ["Monitor"]


def test_the_agent_has_no_way_left_to_make_a_verdict_up():
    assert not hasattr(ThreatEnrichmentAgent, "_verdict_from_text")
    # Neither module builds a report with a fixed verdict any more.
    for module in (agent_module, worker):
        with open(module.__file__) as source:
            assert '"verdict": "Informational"' not in source.read(), module.__name__


def test_through_the_task_a_failed_report_leaves_a_failed_task(monkeypatch, redis):
    production_agent(
        monkeypatch,
        [AIMessage(content="Not malicious.")],
        report=RuntimeError("no structured output"),
    )

    with pytest.raises(AnalysisFailed):
        run_task()

    assert recorded(redis) == failures.REPORT_FAILED
    assert stats.read_today(redis, stats.FAILED) == 1
    assert stats.read_today(redis, stats.COMPLETED) == 0


# --- The exception Celery stores ---------------------------------------------


def test_the_failure_is_rebuilt_from_what_celery_stores():
    """The result backend keeps an exception's type and arguments, as JSON,
    and builds it again from them."""
    backend = worker.celery_app.backend
    stored = backend.prepare_exception(AnalysisFailed(failures.REPORT_FAILED), "json")

    rebuilt = backend.exception_to_python(stored)

    assert isinstance(rebuilt, AnalysisFailed)
    assert rebuilt.code == failures.REPORT_FAILED
    assert rebuilt.reason == failures.REASONS[failures.REPORT_FAILED]


def test_an_unknown_code_is_an_internal_failure_not_a_key_error():
    assert AnalysisFailed("something else").code == failures.INTERNAL
    assert (
        AnalysisFailed("something else").reason == failures.REASONS[failures.INTERNAL]
    )


# --- The API: status failed, with the reason ---------------------------------


class CeleryResult:
    state = "PENDING"
    result = None
    date_done = None

    def __init__(self, task_id, app=None):
        self.id = task_id
        self.info = (
            None if self.state != "FAILURE" else AnalysisFailed(failures.INTERNAL)
        )


@pytest.fixture
def api(monkeypatch, redis):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "AsyncResult", CeleryResult)
    monkeypatch.setattr(CeleryResult, "state", "FAILURE")
    monkeypatch.setattr(CeleryResult, "result", None)
    redis.setex(f"task:{TASK_ID}:celery_id", 3600, "celery-task-1")
    redis.setex(f"task:{TASK_ID}:user_id", 3600, CALLER["user_id"])
    redis.setex(
        f"task:{TASK_ID}:metadata", 3600, '{"created_at": "2026-10-05T10:00:00+00:00"}'
    )
    return TestClient(main.app)


def read(api, caller=CALLER):
    return api.get(
        f"/v1/analyze/{TASK_ID}",
        headers={
            "X-Wildbox-User-ID": caller["user_id"],
            "X-Wildbox-Team-ID": caller["team_id"],
            "X-Wildbox-Role": caller["role"],
            "X-Gateway-Secret": SECRET,
        },
    )


@pytest.mark.parametrize("code", sorted(failures.REASONS))
def test_a_failed_task_says_why(api, redis, code):
    redis.setex(f"task:{TASK_ID}:error", 3600, code)

    response = read(api)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[code]
    assert body["task_id"] == TASK_ID
    # A status, not a report.
    assert not REPORT_FIELDS & set(body)


@pytest.mark.parametrize("stored", ["", "no such code", "ValueError: /srv/app.py line 3"])
def test_a_failure_without_a_known_code_gets_the_generic_reason(api, redis, stored):
    """Never the raw value: it could be anything a future worker wrote.

    A failure with no code recorded at all was the fourth case here, and
    got the generic reason too. It is now given the code of the exception
    Celery holds for it (#727): tests/unit/test_time_limits.py.
    """
    redis.setex(f"task:{TASK_ID}:error", 3600, stored)

    body = read(api).json()

    assert body["status"] == "failed"
    assert body["error"] == failures.GENERIC_REASON


def test_no_reason_names_an_internal():
    for reason in list(failures.REASONS.values()) + [failures.GENERIC_REASON]:
        lowered = reason.lower()
        for word in (
            "traceback",
            "exception",
            "redis",
            "celery",
            "anthropic",
            "http://",
            ".py",
        ):
            assert word not in lowered, reason
    assert reason_for(b"timed_out") == failures.REASONS[failures.TIMED_OUT]
    assert reason_for(object()) == failures.GENERIC_REASON


def test_the_task_the_worker_failed_reads_as_failed_with_its_reason(
    monkeypatch, api, redis
):
    """The two halves together: what the worker records for a failure is
    what the API shows the task's owner."""
    monkeypatch.setattr(settings, "anthropic_api_key", None)
    stand_in_agent(monkeypatch, {"verdict": "Benign"})
    with pytest.raises(AnalysisFailed):
        run_task()

    body = read(api).json()

    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[failures.NOT_CONFIGURED]
    assert "verdict" not in body


def test_a_completed_task_still_reads_as_its_report(monkeypatch, api):
    report = {
        "task_id": TASK_ID,
        "ioc": IOC,
        "verdict": "Benign",
        "confidence": 0.9,
        "executive_summary": "Nothing found.",
        "evidence": [],
        "recommended_actions": [],
        "full_report": "# Report",
        "analysis_duration": 1.5,
        "tools_used": ["whois_lookup_tool"],
    }
    monkeypatch.setattr(CeleryResult, "state", "SUCCESS")
    monkeypatch.setattr(CeleryResult, "result", report)

    body = read(api).json()

    assert body["verdict"] == "Benign" and body["confidence"] == 0.9
    assert "error" not in body or body.get("error") is None
