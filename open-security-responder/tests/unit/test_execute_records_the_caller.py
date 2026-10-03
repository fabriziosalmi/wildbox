"""The execute endpoint starts a run as the user the gateway authenticated (#616).

Every call a run makes to another service carries the identity recorded
here, so it must be the gateway-authenticated caller of the request, with
their role, and a request without one must not start anything.
"""

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import app.main as main_module  # noqa: E402


@pytest.fixture
def started(monkeypatch):
    runs = []

    def start_execution(playbook_id, trigger_data=None, caller=None):
        runs.append((playbook_id, trigger_data, caller))
        return "run-1"

    monkeypatch.setattr(main_module, "start_execution", start_execution)
    monkeypatch.setattr(
        main_module.playbook_parser,
        "get_playbook",
        lambda playbook_id: SimpleNamespace(name="Simple Notification Test"),
    )
    return runs


def headers(user_id, team_id, role="member"):
    return {
        "X-Wildbox-User-ID": user_id,
        "X-Wildbox-Team-ID": team_id,
        "X-Wildbox-Role": role,
        "X-Gateway-Secret": os.environ["GATEWAY_INTERNAL_SECRET"],
    }


@pytest.mark.parametrize("role", ["member", "admin", "viewer"])
def test_the_run_is_started_as_the_gateway_caller(started, role):
    """With the caller's own role: the services authorize the run by it."""
    user_id, team_id = str(uuid.uuid4()), str(uuid.uuid4())
    response = TestClient(main_module.app).post(
        "/v1/playbooks/simple_notification/execute",
        json={"trigger_data": {"message": "hi"}},
        headers=headers(user_id, team_id, role=role),
    )
    assert response.status_code == 202, response.text
    assert started == [
        (
            "simple_notification",
            {"message": "hi"},
            {"user_id": user_id, "team_id": team_id, "role": role},
        )
    ]


@pytest.mark.parametrize(
    "drop", ["X-Wildbox-User-ID", "X-Wildbox-Team-ID", "X-Gateway-Secret"]
)
def test_no_run_is_started_without_a_gateway_caller(started, drop):
    sent = headers(str(uuid.uuid4()), str(uuid.uuid4()))
    del sent[drop]
    response = TestClient(main_module.app).post(
        "/v1/playbooks/simple_notification/execute", json={}, headers=sent
    )
    assert response.status_code == 403, response.text
    assert started == []
