"""Cancelling a run stops it (#653).

DELETE /v1/runs/{run_id} used to rewrite the stored status and nothing
else. The worker never read it again: a cancelled run executed every
remaining step, side effects included, and then overwrote "cancelled" with
"completed"; a run cancelled while queued was set back to running and
executed in full.

These tests run the real endpoint, engine and actor against an in-memory
Redis with WATCH/MULTI semantics (memory_redis.py), with the connector
registry replaced by a recorder, and check that:

- a run cancelled while queued runs no step;
- a run cancelled during a step finishes that step, recorded as it ended,
  and starts no other;
- whichever of completion and cancel commits first decides the outcome, and
  a run recorded as cancelled is never recorded as anything else;
- the cancel is checked against the run's team, as reading it is.
"""

import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import app.main as main_module  # noqa: E402
import app.workflow_engine as engine_module  # noqa: E402
from app.models import ExecutionStatus, Playbook  # noqa: E402
from memory_redis import MemoryRedis  # noqa: E402

CALLER = {"user_id": str(uuid.uuid4()), "team_id": str(uuid.uuid4()), "role": "member"}
OTHER_TEAM = str(uuid.uuid4())
STEPS = ["first", "second", "third", "fourth"]

PLAYBOOK = Playbook(
    playbook_id="four_steps",
    name="Four steps",
    trigger={"type": "api"},
    steps=[
        {"name": name, "action": "system.log", "input": {"message": name}}
        for name in STEPS
    ],
)


def headers(team_id=CALLER["team_id"]):
    return {
        "X-Wildbox-User-ID": CALLER["user_id"],
        "X-Wildbox-Team-ID": team_id,
        "X-Wildbox-Role": CALLER["role"],
        "X-Gateway-Secret": os.environ["GATEWAY_INTERNAL_SECRET"],
    }


class Harness:
    """A queued run, the worker that will execute it, and the API."""

    def __init__(self, monkeypatch):
        self.engine = engine_module.workflow_engine
        self.store = MemoryRedis()
        monkeypatch.setattr(self.engine, "redis_client", self.store)
        monkeypatch.setattr(
            engine_module.playbook_parser, "playbooks", {"four_steps": PLAYBOOK}
        )
        self.messages = []
        monkeypatch.setattr(
            engine_module.execute_playbook_actor,
            "send",
            lambda *args: self.messages.append(args),
        )
        # step name -> what to do while that step's action runs
        self.during = {}
        self.executed = []
        monkeypatch.setattr(
            engine_module.connector_registry, "execute_action", self._execute
        )
        self.api = TestClient(main_module.app)
        self.run_id = engine_module.start_execution(
            "four_steps", {"x": 1}, caller=CALLER
        )

    def _execute(self, connector, action, params):
        step = params["message"]
        self.executed.append(step)
        hook = self.during.get(step)
        if hook:
            hook()
        return {"status": "logged", "message": step}

    def work(self):
        """The worker picks the message up."""
        [message] = self.messages
        return engine_module.execute_playbook_actor.fn(*message)

    def cancel(self, team_id=CALLER["team_id"]):
        return self.api.delete(f"/v1/runs/{self.run_id}", headers=headers(team_id))

    def read(self):
        response = self.api.get(f"/v1/runs/{self.run_id}", headers=headers())
        assert response.status_code == 200, response.text
        return response.json()

    def record(self):
        return self.engine.get_execution_state(self.run_id)


@pytest.fixture
def harness(monkeypatch):
    return Harness(monkeypatch)


def ran(record):
    return [(s.step_name, s.status) for s in record.step_results]


def log_has(record, text):
    return any(text in line for line in record.logs)


# --- Cancelled while queued -------------------------------------------------


def test_a_run_cancelled_while_queued_runs_no_step(harness):
    response = harness.cancel()
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "cancelled"
    assert harness.read()["status"] == "cancelled"

    harness.work()

    record = harness.record()
    assert harness.executed == []
    assert record.status == ExecutionStatus.CANCELLED
    assert record.step_results == []
    # It never started: not set running, never acting for anyone.
    assert not log_has(record, "Starting execution")
    assert not log_has(record, "Acting for user")
    assert log_has(record, "Cancelled before it started")
    assert log_has(record, "Steps that ran: none. Steps not run: " + ", ".join(STEPS))


# --- Cancelled while running ------------------------------------------------


def test_a_run_cancelled_during_step_two_stops_after_it(harness):
    answers = []

    def cancel_now():
        response = harness.cancel()
        answers.append((response.status_code, response.json()))
        answers.append(harness.read()["status"])

    harness.during["second"] = cancel_now
    harness.work()

    [(code, body), seen] = answers
    assert code == 202
    assert body["status"] == "cancelling"
    assert "no further step will start" in body["message"]
    assert seen == "cancelling"

    record = harness.record()
    assert harness.executed == ["first", "second"]
    # The step in progress ran to its end and is recorded as it ended.
    assert ran(record) == [("first", "completed"), ("second", "completed")]
    assert record.status == ExecutionStatus.CANCELLED
    assert record.end_time is not None
    assert harness.read()["status"] == "cancelled"
    assert log_has(
        record, "Steps that ran: first, second. Steps not run: third, fourth."
    )


def test_a_step_that_fails_while_cancelling_is_recorded_as_failed(harness):
    def cancel_then_fail():
        harness.cancel()
        raise RuntimeError("service answered 503")

    harness.during["second"] = cancel_then_fail
    harness.work()

    record = harness.record()
    assert harness.executed == ["first", "second"]
    assert ran(record) == [("first", "completed"), ("second", "failed")]
    # Cancelled, not failed: the cancel was accepted first. The failure is
    # kept, not hidden.
    assert record.status == ExecutionStatus.CANCELLED
    assert "service answered 503" in record.error


def test_cancelling_twice_answers_the_same_and_records_once(harness):
    answers = []
    harness.during["first"] = lambda: answers.extend(
        [harness.cancel(), harness.cancel()]
    )
    harness.work()

    assert [a.status_code for a in answers] == [202, 202]
    assert [a.json()["status"] for a in answers] == ["cancelling", "cancelling"]
    record = harness.record()
    assert sum("Cancel requested" in line for line in record.logs) == 1
    assert harness.executed == ["first"]


# --- Completion and cancel race ----------------------------------------------


def test_a_cancel_that_commits_before_the_completion_wins(harness):
    """The cancel lands between the worker reading the record and writing
    'completed'. The write is a compare-and-set, so it is retried and records
    'cancelled'."""
    outcome = []
    save = harness.engine.save_execution_state

    def save_racing_a_cancel(run_id, result):
        if result.status == ExecutionStatus.COMPLETED and not outcome:
            harness.store.before_commit = lambda: outcome.append(
                harness.engine.request_cancel(run_id)
            )
        return save(run_id, result)

    harness.engine.save_execution_state = save_racing_a_cancel
    try:
        harness.work()
    finally:
        del harness.engine.save_execution_state

    assert outcome == [(ExecutionStatus.CANCELLING, True)]
    assert harness.store.retries >= 1
    record = harness.record()
    assert harness.executed == STEPS
    assert record.status == ExecutionStatus.CANCELLED
    assert log_has(record, "after its last step had started; every step ran")


def test_a_cancel_after_the_completion_changes_nothing(harness):
    harness.work()
    response = harness.cancel()

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert "already completed" in response.json()["message"]
    record = harness.record()
    assert record.status == ExecutionStatus.COMPLETED
    assert not harness.engine.cancel_requested(harness.run_id)


@pytest.mark.parametrize(
    "requested, stored, cancel_requested, recorded",
    [
        # No cancel: what is asked.
        ("running", "queued", False, "running"),
        ("completed", "running", False, "completed"),
        ("failed", "running", False, "failed"),
        # Cancel accepted: a live run is cancelling, an ending one cancelled.
        ("running", "queued", True, "cancelling"),
        ("running", "cancelling", True, "cancelling"),
        ("completed", "cancelling", True, "cancelled"),
        ("failed", "cancelling", True, "cancelled"),
        # Cancelled is final, whatever is asked.
        ("running", "cancelled", True, "cancelled"),
        ("completed", "cancelled", True, "cancelled"),
        ("completed", "cancelled", False, "cancelled"),
        ("failed", "cancelled", False, "cancelled"),
    ],
)
def test_resolve_status(requested, stored, cancel_requested, recorded):
    resolve = engine_module.WorkflowEngine.resolve_status
    assert resolve(ExecutionStatus(requested), stored, cancel_requested) == recorded


# --- Who may cancel ---------------------------------------------------------


def test_another_team_cannot_cancel_the_run(harness):
    response = harness.cancel(team_id=OTHER_TEAM)

    assert response.status_code == 404
    assert not harness.engine.cancel_requested(harness.run_id)
    harness.work()
    assert harness.record().status == ExecutionStatus.COMPLETED
    assert harness.executed == STEPS


def test_cancelling_an_unknown_run_answers_404(harness):
    response = harness.api.delete(f"/v1/runs/{uuid.uuid4()}", headers=headers())
    assert response.status_code == 404


# --- A worker that dies while cancelling ------------------------------------


def test_the_reaper_ends_an_abandoned_cancelling_run_as_cancelled(harness):
    """The worker died after the cancel was accepted, before it stopped."""
    engine = harness.engine
    record = harness.record()
    record.status = ExecutionStatus.RUNNING
    engine.save_execution_state(harness.run_id, record)
    assert harness.cancel().json()["status"] == "cancelling"
    key = engine._get_execution_key(harness.run_id)
    stale = (datetime.utcnow() - timedelta(hours=1)).isoformat().encode()
    harness.store.hashes[key]["heartbeat_at"] = stale

    # The scan also meets the run's cancel key, which is not a hash.
    assert engine.reap_abandoned_runs() == 1
    record = harness.record()
    assert record.status == ExecutionStatus.CANCELLED
    assert "Run abandoned" in record.error
