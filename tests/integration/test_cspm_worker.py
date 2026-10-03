"""A submitted CSPM scan is run by cspm-worker, through the gateway (#601).

The worker was commented out of docker-compose.yml, so every scan stayed
"queued" forever and the compliance pages never had data. This test submits
a scan the way the dashboard does and waits for it to leave "queued".

No cloud credentials in CI: the scan is of an AWS account with an access
key id AWS could never issue, so the worker takes it, its session factory
refuses the key before creating any boto3 session (app.providers, #612)
and the scan ends "failed". That makes no request to AWS and ends the same
way on every run, and only a worker can produce it: without one the scan
stays "queued" until the deadline and the test fails. This used a GCP
scan, which the API now refuses with a 400 (checked below).

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
    "provider": "aws",
    "account_id": "wildbox-ci-account",
    "account_name": "CI (no credentials)",
    "regions": ["eu-west-1"],
    "credentials": {
        "auth_method": "access_key",
        # Malformed on purpose (an AWS key id is 16 or more letters and
        # digits): refused before any call to AWS.
        "access_key_id": "not-an-aws-key",
        "secret_access_key": "not-a-secret",
    },
    "metadata": {"purpose": "integration test of cspm-worker"},
}
GCP_SCAN = {
    "provider": "gcp",
    "account_id": "wildbox-ci-project",
    "credentials": {
        "auth_method": "service_account",
        "project_id": "wildbox-ci-project",
        "service_account_key": {"type": "service_account", "note": "not a key"},
    },
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


def test_the_providers_cspm_scans_are_listed_through_the_gateway():
    """GET /api/v1/providers needs a token, like every cspm route."""
    assert requests.get(f"{CSPM}/providers", timeout=TIMEOUT).status_code == 401
    response = requests.get(
        f"{CSPM}/providers", headers=bearer(new_token()), timeout=TIMEOUT
    )
    assert response.status_code == 200, response.text[:300]
    listed = {p["provider"]: p for p in response.json()["providers"]}
    assert set(listed) == {"aws"}, listed
    assert listed["aws"]["checks"] > 0


def test_a_submitted_scan_is_taken_by_the_worker():
    token = new_token()

    # A provider cspm cannot scan is refused at submit time (#612), with
    # the supported ones named, and leaves no scan behind: the summary
    # below counts exactly one.
    refused = requests.post(
        f"{CSPM}/scans", json=GCP_SCAN, headers=bearer(token), timeout=TIMEOUT
    )
    assert refused.status_code == 400, refused.text[:300]
    assert "aws" in refused.text, refused.text[:300]

    submitted = requests.post(
        f"{CSPM}/scans", json=SCAN, headers=bearer(token), timeout=TIMEOUT
    )
    assert submitted.status_code == 202, submitted.text[:300]
    body = submitted.json()
    assert body["status"] == "started"
    assert (body["provider"], body["account_id"]) == ("aws", SCAN["account_id"])
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
    assert (final["provider"], final["account_id"]) == ("aws", SCAN["account_id"])
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
