"""A playbook run acts for the user who started it, on the running stack (#616).

The responder's connectors used to call routes the services do not serve,
with no identity, so no playbook step that reached another service could
succeed. Now each call carries the gateway identity of the user who started
the run. This test starts the shipped hash_evidence playbook through the
gateway, as a freshly registered user, and checks that:

- the run completes;
- the tools task its step queued belongs to that user: it is in their task
  list and they can read its result, the SHA-256 of the evidence;
- another user can neither see nor read that task.

hash_generator touches no network, so nothing here depends on the runner's
egress. Each request is sent once; only the run's status and the task's
status are polled until they finish.
"""

import hashlib
import os
import secrets
import time

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
RESPONDER = f"{GATEWAY_URL}/api/v1/responder"
TASKS = f"{GATEWAY_URL}/api/v1/tasks"
TIMEOUT = 15
# Long enough for a worker that is busy with other tests' work.
FINISH_WITHIN = 120
EVIDENCE = "powershell -nop -w hidden -enc SQBFAFgA"


def new_token():
    email = f"responder-identity-{secrets.token_hex(6)}@example.com"
    password = f"Responder-Identity-{secrets.token_hex(8)}!"
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
    return login.json()["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def wait_for(read, finished):
    deadline = time.monotonic() + FINISH_WITHIN
    while True:
        response = read()
        assert response.status_code == 200, response.text[:300]
        body = response.json()
        if finished(body):
            return body
        assert time.monotonic() < deadline, f"still unfinished: {body}"
        time.sleep(1)


def test_a_playbook_run_acts_for_the_user_who_started_it():
    owner = new_token()
    other = new_token()

    started = requests.post(
        f"{RESPONDER}/playbooks/hash_evidence/execute",
        json={"trigger_data": {"text": EVIDENCE}},
        headers=bearer(owner),
        timeout=TIMEOUT,
    )
    assert started.status_code == 202, started.text[:300]
    run_id = started.json()["run_id"]

    run = wait_for(
        lambda: requests.get(
            f"{RESPONDER}/runs/{run_id}", headers=bearer(owner), timeout=TIMEOUT
        ),
        lambda body: body["status"] in ("completed", "failed", "cancelled"),
    )
    assert run["status"] == "completed", (run.get("error"), run.get("logs"))
    [queued, report] = run["step_results"]
    assert queued["status"] == "completed", queued
    task_id = queued["output"]["task_id"]
    assert report["output"]["data"]["task_id"] == task_id

    # The task is the owner's: listed for them, readable by them.
    listed = requests.get(TASKS, headers=bearer(owner), timeout=TIMEOUT)
    assert listed.status_code == 200, listed.text[:300]
    assert task_id in [task["task_id"] for task in listed.json()["tasks"]]
    task = wait_for(
        lambda: requests.get(
            f"{TASKS}/{task_id}", headers=bearer(owner), timeout=TIMEOUT
        ),
        lambda body: body["status"] not in ("pending", "running", "retrying"),
    )
    assert task["status"] == "completed", task
    assert task["tool_name"] == "hash_generator"
    hashes = {h["algorithm"]: h["hash_value"] for h in task["result"]["hash_results"]}
    assert hashes["sha256"] == hashlib.sha256(EVIDENCE.encode()).hexdigest()

    # And nobody else's.
    assert (
        requests.get(
            f"{TASKS}/{task_id}", headers=bearer(other), timeout=TIMEOUT
        ).status_code
        == 404
    )
    others = requests.get(TASKS, headers=bearer(other), timeout=TIMEOUT)
    assert task_id not in [t["task_id"] for t in others.json()["tasks"]]
    # The other user cannot read the run either.
    assert (
        requests.get(
            f"{RESPONDER}/runs/{run_id}", headers=bearer(other), timeout=TIMEOUT
        ).status_code
        == 404
    )
