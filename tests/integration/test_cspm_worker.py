"""A submitted CSPM scan is run by cspm-worker, through the gateway (#601).

The worker was commented out of docker-compose.yml, so every scan stayed
"queued" forever and the compliance pages never had data. This test submits
a scan the way the dashboard does and waits for it to leave "queued".

No cloud credentials in CI: the scan is of a GCP project with a service
account key that is not one, so the worker takes it, cannot open a session
and the scan ends "failed". That needs no network and ends the same way on
every run, and only a worker can produce it: without one the scan stays
"queued" until the deadline and the test fails.

The account is registered directly at identity, as in
test_tools_async_tasks.py, so its team has no other scans; every other
request goes through the gateway.
"""

import os
import secrets
import time

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
CSPM = f"{GATEWAY_URL}/api/v1/cspm"
TIMEOUT = 15
# The scan itself fails in milliseconds; the margin is for a worker busy
# with the scans other tests submit.
FINISH_WITHIN = 180
UNFINISHED = {"queued", "running"}

SCAN = {
    "provider": "gcp",
    "account_id": "wildbox-ci-project",
    "account_name": "CI (no credentials)",
    "regions": ["europe-west1"],
    "credentials": {
        "auth_method": "service_account",
        "project_id": "wildbox-ci-project",
        "service_account_key": {"type": "service_account", "note": "not a key"},
    },
    "metadata": {"purpose": "integration test of cspm-worker"},
}


def new_token():
    email = f"cspm-worker-{secrets.token_hex(6)}@example.com"
    password = f"Cspm-Worker-{secrets.token_hex(8)}!"
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


def scan_status(token, scan_id):
    response = requests.get(
        f"{CSPM}/scans/{scan_id}", headers=bearer(token), timeout=TIMEOUT
    )
    assert response.status_code == 200, response.text[:300]
    return response.json()


def wait_until_finished(token, scan_id):
    """Every status the scan reported, oldest first, until it left the queue."""
    seen = []
    deadline = time.monotonic() + FINISH_WITHIN
    while True:
        status = scan_status(token, scan_id)
        if not seen or seen[-1] != status["status"]:
            seen.append(status["status"])
        if status["status"] not in UNFINISHED or time.monotonic() > deadline:
            return status, seen
        time.sleep(1)


def test_a_submitted_scan_is_taken_by_the_worker():
    token = new_token()

    submitted = requests.post(
        f"{CSPM}/scans", json=SCAN, headers=bearer(token), timeout=TIMEOUT
    )
    assert submitted.status_code == 202, submitted.text[:300]
    body = submitted.json()
    assert body["status"] == "started"
    assert (body["provider"], body["account_id"]) == ("gcp", SCAN["account_id"])
    scan_id = body["scan_id"]

    final, seen = wait_until_finished(token, scan_id)

    assert final["status"] == "failed", (
        f"scan {scan_id} went through {seen} in {FINISH_WITHIN}s: "
        "is cspm-worker running and consuming the queue?"
    )
    # Every state on the way is a real one ("unknown" was what a worker's
    # STARTED read as), and the scan never moved back.
    order = ["queued", "running", "failed"]
    assert all(state in order for state in seen), seen
    assert seen == sorted(seen, key=order.index), seen
    # The record is the scan that was submitted, and a failed scan has
    # no completion time and no report.
    assert final["scan_id"] == scan_id
    assert (final["provider"], final["account_id"]) == ("gcp", SCAN["account_id"])
    assert final["started_at"]
    assert final.get("completed_at") is None
    report = requests.get(
        f"{CSPM}/scans/{scan_id}/report", headers=bearer(token), timeout=TIMEOUT
    )
    assert report.status_code == 400, report.text[:300]

    # A final status stays final: it is read from the scan's metadata.
    assert scan_status(token, scan_id)["status"] == "failed"

    # The team's summary counts the scan and assesses no account: a failed
    # scan has no findings and no score.
    summary = requests.get(
        f"{CSPM}/dashboard/summary", headers=bearer(token), timeout=TIMEOUT
    )
    assert summary.status_code == 200, summary.text[:300]
    summary = summary.json()
    assert summary["total_scans"] == 1, summary
    assert summary["accounts_assessed"] == 0, summary
    assert summary["compliance_score"] is None, summary
