"""Unit tests for WorkflowEngine's run-owner (tenancy) key logic.

Pure-logic, no live Redis needed - the engine's redis_client is swapped for
an in-memory fake. Locks in the tenant-scoping behavior that gates whether a
team can read/cancel another team's playbook run (set_run_owner /
get_run_owner / is_run_owner in app/workflow_engine.py).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.workflow_engine import WorkflowEngine  # noqa: E402


class FakeRedis:
    """Minimal in-memory stand-in for the subset of redis-py used here."""

    def __init__(self):
        self.store = {}
        self.expirations = {}

    def set(self, key, value):
        self.store[key] = value

    def get(self, key):
        value = self.store.get(key)
        if value is None:
            return None
        # redis-py returns bytes by default; exercise that decode path.
        return value.encode() if isinstance(value, str) else value

    def expire(self, key, seconds):
        self.expirations[key] = seconds


@pytest.fixture
def engine():
    eng = WorkflowEngine()
    eng.redis_client = FakeRedis()
    return eng


def test_get_run_owner_unknown_run_returns_none(engine):
    assert engine.get_run_owner("missing-run") is None


def test_set_then_get_run_owner_roundtrips(engine):
    engine.set_run_owner("run-1", "team-42")
    assert engine.get_run_owner("run-1") == "team-42"


def test_set_run_owner_accepts_non_string_team_id(engine):
    engine.set_run_owner("run-1", 42)
    assert engine.get_run_owner("run-1") == "42"


def test_is_run_owner_true_for_matching_team(engine):
    engine.set_run_owner("run-1", "team-42")
    assert engine.is_run_owner("run-1", "team-42") is True


def test_is_run_owner_false_for_other_team(engine):
    engine.set_run_owner("run-1", "team-42")
    assert engine.is_run_owner("run-1", "team-99") is False


def test_is_run_owner_false_for_unknown_run(engine):
    # A run with no recorded owner must never be treated as owned - this is
    # the fail-closed default that protects cross-tenant reads/cancels.
    assert engine.is_run_owner("never-set", "team-42") is False


def test_is_run_owner_compares_as_strings(engine):
    engine.set_run_owner("run-1", 42)
    assert engine.is_run_owner("run-1", "42") is True
    assert engine.is_run_owner("run-1", 42) is True


def test_set_run_owner_sets_expiration(engine):
    engine.set_run_owner("run-1", "team-42")
    key = engine._get_owner_key("run-1")
    assert key in engine.redis_client.expirations
    assert engine.redis_client.expirations[key] > 0


def test_owner_key_is_distinct_from_execution_and_logs_keys(engine):
    run_id = "run-1"
    assert engine._get_owner_key(run_id) != engine._get_execution_key(run_id)
    assert engine._get_owner_key(run_id) != engine._get_logs_key(run_id)
