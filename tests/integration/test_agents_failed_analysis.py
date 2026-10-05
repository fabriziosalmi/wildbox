"""An analysis that cannot run is a failed task, on the running stack (#717).

The stack this suite runs against has no model key. An analysis submitted
there cannot run, and used to come back as a completed one: the agent
answered a report with the verdict "Informational" and confidence 0, the
task returned it, and ``completed_today`` counted it.

Through the gateway, a signed-in user submits an analysis and reads the task
until it ends. It must end ``failed``, with the reason that AI analysis is
not configured, and with no verdict; ``failed_today`` counts it and
``completed_today`` does not.

On a stack that does have a model key the analysis would really run, so the
test is skipped there: the agents service's own health check says whether a
key is configured.
"""

import os
import secrets
import time

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
AGENTS_URL = os.getenv("AGENTS_SERVICE_URL", "http://localhost:8006").rstrip("/")
ANALYZE = f"{GATEWAY_URL}/api/v1/agents/analyze"
STATS = f"{GATEWAY_URL}/api/v1/agents/stats"
TIMEOUT = 20
# The task fails as soon as the worker picks it up; this covers a worker
# that is busy with other tests' submissions.
FINISH_WITHIN = 90
NOT_CONFIGURED = (
    "AI analysis is not configured on this server: no model API key is set."
)


def session_headers():
    email = f"agents-failed-{secrets.token_hex(6)}@example.com"
    password = f"Agents-Failed-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def counters(headers):
    response = requests.get(STATS, headers=headers, timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    return body["completed_today"], body["failed_today"]


def test_without_a_model_key_an_analysis_fails_and_says_so():
    health = requests.get(f"{AGENTS_URL}/health", timeout=TIMEOUT)
    assert health.status_code == 200, health.text[:200]
    if health.json()["services"].get("anthropic") != "not_configured":
        pytest.skip("this stack has a model key: the analysis would run")

    headers = session_headers()
    completed_before, failed_before = counters(headers)

    submitted = requests.post(
        ANALYZE,
        json={"ioc": {"type": "domain", "value": "example.com"}, "priority": "normal"},
        headers=headers,
        timeout=TIMEOUT,
    )
    assert submitted.status_code == 202, submitted.text[:300]
    task_id = submitted.json()["task_id"]

    deadline = time.monotonic() + FINISH_WITHIN
    while True:
        read = requests.get(f"{ANALYZE}/{task_id}", headers=headers, timeout=TIMEOUT)
        assert read.status_code == 200, read.text[:300]
        task = read.json()
        # A report has a verdict and no status; a status has no verdict.
        if "verdict" in task or task.get("status") == "failed":
            break
        assert time.monotonic() < deadline, f"still unfinished: {task}"
        time.sleep(1)

    assert (
        "verdict" not in task
    ), f"a report was answered for an analysis that cannot run: {task}"
    assert task["status"] == "failed"
    assert task["error"] == NOT_CONFIGURED
    assert task["task_id"] == task_id

    # Other tests submit analyses on this stack too, and all of them fail
    # the same way: the counters only move in one direction here.
    completed_after, failed_after = counters(headers)
    assert failed_after >= failed_before + 1
    assert completed_after == completed_before
