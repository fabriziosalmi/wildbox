"""Asynchronous tool tasks through the gateway, on the running stack (#567).

POST /api/v1/tools/<name>/async queued a task, but the gateway routed none of
the task endpoints, so its result could not be read, the task could not be
cancelled and the caller's tasks could not be listed. They are now served as
/api/v1/tasks, and each task belongs to the user who submitted it.

Each test registers its own accounts directly at identity, as
test_account_change_hardening.py does, and makes every other request through
the gateway. The tool is hash_generator: it touches no network, so its result
does not depend on the runner's egress.
"""

import hashlib
import os
import secrets
import time

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15
# Long enough for a worker that is busy with other tests' tasks.
FINISH_WITHIN = 120

TASKS = f"{GATEWAY_URL}/api/v1/tasks"
FAST_INPUT = {"input_text": "wildbox", "hash_types": ["sha256"]}
# Twenty PBKDF2-SHA512 hashes of a million iterations each: seconds of CPU in
# the worker and no network, so the task is still pending or running when it
# is cancelled right after submission.
SLOW_INPUT = {
    "input_text": "wildbox",
    "hash_types": ["sha512"] * 20,
    "include_salted": True,
    "iterations": 1000000,
}
UNFINISHED = {"pending", "running", "retrying"}


def new_token():
    email = f"async-tasks-{secrets.token_hex(6)}@example.com"
    password = f"Async-Tasks-{secrets.token_hex(8)}!"
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


def submit(token, payload=FAST_INPUT):
    response = requests.post(
        f"{GATEWAY_URL}/api/v1/tools/hash_generator/async",
        json=payload,
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert response.status_code == 202, response.text[:300]
    body = response.json()
    assert body["status_url"] == f"/api/v1/tasks/{body['task_id']}", body
    return body["task_id"]


def read(token, task_id):
    return requests.get(f"{TASKS}/{task_id}", headers=bearer(token), timeout=TIMEOUT)


def cancel(token, task_id):
    return requests.delete(f"{TASKS}/{task_id}", headers=bearer(token), timeout=TIMEOUT)


def listed(token):
    response = requests.get(TASKS, headers=bearer(token), timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:300]
    return [task["task_id"] for task in response.json()["tasks"]]


def without_request_id(body):
    """An error body without its per-request id."""
    error = dict(body.get("error", {}))
    error.pop("request_id", None)
    return {**body, "error": error}


def wait_until_finished(token, task_id):
    deadline = time.monotonic() + FINISH_WITHIN
    while True:
        response = read(token, task_id)
        assert response.status_code == 200, response.text[:300]
        body = response.json()
        if body["status"] not in UNFINISHED:
            return body
        assert time.monotonic() < deadline, f"task still {body['status']}: {body}"
        time.sleep(1)


def test_a_task_is_submitted_read_and_listed_through_the_gateway():
    token = new_token()
    task_id = submit(token)

    body = wait_until_finished(token, task_id)

    assert body["state"] == "SUCCESS", body
    assert body["status"] == "completed", body
    assert body["tool_name"] == "hash_generator"
    hashes = body["result"]["hash_results"]
    assert [h["algorithm"] for h in hashes] == ["sha256"]
    # The tool's own output, computed by the worker.
    assert hashes[0]["hash_value"] == hashlib.sha256(b"wildbox").hexdigest()
    assert task_id in listed(token)
    # A finished task cannot be cancelled.
    assert cancel(token, task_id).status_code == 400


def test_the_owner_cancels_a_task_that_has_not_finished():
    token = new_token()
    task_id = submit(token, SLOW_INPUT)

    response = cancel(token, task_id)

    assert response.status_code == 200, response.text[:300]
    # Cancelled from that moment, not from when a worker gets to it (#743):
    # the cancellation is a record the API reads, and the task reads it
    # first if it ever starts. A second cancellation has nothing to cancel.
    at_once = read(token, task_id)
    assert at_once.status_code == 200, at_once.text[:300]
    assert at_once.json()["status"] == "cancelled", at_once.json()
    assert cancel(token, task_id).status_code == 400
    body = wait_until_finished(token, task_id)
    assert body["status"] == "cancelled", body
    assert body["state"] == "REVOKED", body


def test_another_user_can_neither_read_cancel_nor_list_the_task():
    owner = new_token()
    other = new_token()
    task_id = submit(owner)
    wait_until_finished(owner, task_id)

    assert read(other, task_id).status_code == 404
    assert cancel(other, task_id).status_code == 404
    assert task_id not in listed(other)
    # The same answer as for a task that does not exist (but for the id of
    # the request, which differs on every request).
    unknown = read(other, "00000000-0000-4000-8000-000000000000")
    assert unknown.status_code == 404
    assert without_request_id(unknown.json()) == without_request_id(
        read(other, task_id).json()
    )
    # And the owner still has it.
    assert read(owner, task_id).json()["status"] == "completed"
    assert task_id in listed(owner)


def test_the_task_routes_require_authentication():
    for url in (TASKS, f"{TASKS}/00000000-0000-4000-8000-000000000000"):
        response = requests.get(url, timeout=TIMEOUT)
        assert response.status_code == 401, (url, response.text[:200])
