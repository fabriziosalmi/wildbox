"""
Guardian (vulnerability management) integration tests.

Two paths, each the one a real client uses:

* Health is probed directly on guardian's published port, over plain HTTP,
  exactly as the container healthcheck and the conftest reachability guard
  do. /health/ is the one route exempt from guardian's HTTPS redirect.
* Everything else goes through the gateway, over HTTPS, with a JWT from the
  real login. Guardian refuses a direct API call by design (it only trusts the
  X-Wildbox-* headers the gateway injects alongside the shared secret), so a
  test that called /api/v1/... on port 8013 could only ever observe a redirect
  or a 401 -- which is all the previous version of this module asserted, and
  it accepted those as passes.

Every test asserts a concrete outcome; none of them accepts "any status".
"""

import os
import time
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
GUARDIAN_URL = os.getenv("GUARDIAN_SERVICE_URL", "http://localhost:8013").rstrip("/")

# /api/v1/guardian/<x> on the gateway is /api/v1/<x> on guardian.
GUARDIAN_API = f"{GATEWAY_URL}/api/v1/guardian"
ASSETS = f"{GUARDIAN_API}/assets/assets/"
VULNERABILITIES = f"{GUARDIAN_API}/vulnerabilities/"
DASHBOARDS = f"{GUARDIAN_API}/reports/dashboards/"
ALERT_CHECK_ALL = f"{GUARDIAN_API}/reports/alerts/check_all/"
TASKS = f"{GUARDIAN_API}/tasks/"

TIMEOUT = 15
# How long a queued task may take to be picked up and finished by the
# guardian worker. The tasks used here take well under a second.
TASK_DEADLINE = 90


@pytest.fixture(scope="module")
def admin_headers() -> dict:
    """Bearer header for the admin the stack provisions (a team owner)."""
    email = os.getenv("TEST_ADMIN_EMAIL")
    password = os.getenv("TEST_ADMIN_PASSWORD")
    assert (
        email and password
    ), "TEST_ADMIN_EMAIL/TEST_ADMIN_PASSWORD (or INITIAL_ADMIN_*) must be set"
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert (
        login.status_code == 200
    ), f"admin login failed: {login.status_code} {login.text[:200]}"
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _assert_page(response: requests.Response) -> dict:
    """A DRF PageNumberPagination body: count, next, previous, results."""
    assert response.status_code == 200, (
        f"{response.request.method} {response.url}: "
        f"{response.status_code} {response.text[:300]}"
    )
    body = response.json()
    assert isinstance(body.get("count"), int), body
    assert isinstance(body.get("results"), list), body
    return body


@pytest.fixture
def asset(admin_headers):
    """A throwaway asset, removed afterwards even if the test fails."""
    payload = {
        "name": f"it-guardian-{uuid.uuid4().hex[:12]}",
        "asset_type": "server",
        "hostname": "it-guardian.invalid",
        "tags": ["integration-test"],
    }
    created = requests.post(
        ASSETS, json=payload, headers=admin_headers, timeout=TIMEOUT
    )
    assert (
        created.status_code == 201
    ), f"asset creation failed: {created.status_code} {created.text[:300]}"
    body = created.json()
    yield body
    requests.delete(f"{ASSETS}{body['id']}/", headers=admin_headers, timeout=TIMEOUT)


def _wait_for_task(task_id: str, headers: dict) -> dict:
    """Poll guardian's task-status endpoint until the task is finished.

    Celery reports PENDING for a task no worker has taken, so with no
    guardian worker running this never leaves PENDING and the test fails at
    the deadline (#537).
    """
    uuid.UUID(task_id)  # Celery task ids are UUIDs; raises if not.
    deadline = time.monotonic() + TASK_DEADLINE
    body: dict = {}
    while time.monotonic() < deadline:
        response = requests.get(f"{TASKS}{task_id}/", headers=headers, timeout=TIMEOUT)
        assert (
            response.status_code == 200
        ), f"{response.status_code} {response.text[:300]}"
        body = response.json()
        if body["ready"]:
            return body
        time.sleep(1)
    pytest.fail(f"task {task_id} not finished after {TASK_DEADLINE}s: {body}")


class TestGuardianMonitoring:
    """Guardian through the paths operators and clients actually use."""

    def test_service_health(self) -> None:
        """/health/ answers 200 JSON over plain HTTP, with every dependency up.

        No redirect is allowed: a 301 here is what made the container
        healthcheck pass with the database down and the suite skip guardian
        as unreachable (#532).
        """
        response = requests.get(
            f"{GUARDIAN_URL}/health/", timeout=TIMEOUT, allow_redirects=False
        )
        assert response.status_code == 200, (
            f"{response.status_code} {response.headers.get('location', '')} "
            f"{response.text[:300]}"
        )
        assert "json" in response.headers.get("content-type", "")
        body = response.json()
        assert body["status"] == "healthy", body
        assert body["checks"]["database"]["status"] == "healthy", body
        assert body["checks"]["redis"]["status"] == "healthy", body

    def test_assets_database_access(self, admin_headers, asset) -> None:
        """Assets are read back from guardian's database through the gateway."""
        listing = _assert_page(
            requests.get(
                ASSETS,
                params={"search": asset["name"]},
                headers=admin_headers,
                timeout=TIMEOUT,
            )
        )
        assert [a["id"] for a in listing["results"]] == [asset["id"]], listing

        detail = requests.get(
            f"{ASSETS}{asset['id']}/", headers=admin_headers, timeout=TIMEOUT
        )
        assert detail.status_code == 200, detail.text[:300]
        assert detail.json()["name"] == asset["name"]
        assert detail.json()["asset_type"] == "server"

    def test_vulnerabilities_database_access(self, admin_headers, asset) -> None:
        """A vulnerability recorded against an asset is listed for that asset."""
        title = f"Integration test finding {uuid.uuid4().hex[:8]}"
        created = requests.post(
            VULNERABILITIES,
            json={
                "title": title,
                "description": "Created by the integration suite.",
                "asset": asset["id"],
                "severity": "high",
                "cvss_v3_score": 7.5,
                "cve_id": "CVE-2024-3094",
            },
            headers=admin_headers,
            timeout=TIMEOUT,
        )
        assert created.status_code == 201, (
            f"vulnerability creation failed: {created.status_code} "
            f"{created.text[:300]}"
        )

        listing = _assert_page(
            requests.get(
                VULNERABILITIES,
                params={"asset_id": asset["id"]},
                headers=admin_headers,
                timeout=TIMEOUT,
            )
        )
        assert listing["count"] == 1, listing
        found = listing["results"][0]
        assert found["title"] == title
        assert found["severity"] == "high"
        # The vulnerability is removed with its asset (on_delete=CASCADE)
        # when the asset fixture is torn down.

    def test_asset_creation_authorization(self, admin_headers) -> None:
        """Writing an asset needs a credential; an owner can create and delete."""
        payload = {
            "name": f"it-guardian-auth-{uuid.uuid4().hex[:12]}",
            "asset_type": "workstation",
        }

        anonymous = requests.post(ASSETS, json=payload, timeout=TIMEOUT)
        assert (
            anonymous.status_code == 401
        ), f"unauthenticated write was not refused: {anonymous.status_code}"

        invalid = requests.post(
            ASSETS,
            json={**payload, "asset_type": "not-a-type"},
            headers=admin_headers,
            timeout=TIMEOUT,
        )
        assert invalid.status_code == 400, invalid.text[:300]
        assert "asset_type" in invalid.json(), invalid.json()

        created = requests.post(
            ASSETS, json=payload, headers=admin_headers, timeout=TIMEOUT
        )
        assert created.status_code == 201, created.text[:300]
        asset_id = created.json()["id"]

        deleted = requests.delete(
            f"{ASSETS}{asset_id}/", headers=admin_headers, timeout=TIMEOUT
        )
        assert deleted.status_code == 204, deleted.text[:300]
        gone = requests.get(
            f"{ASSETS}{asset_id}/", headers=admin_headers, timeout=TIMEOUT
        )
        assert gone.status_code == 404, gone.status_code

    def test_celery_task_runs(self, admin_headers) -> None:
        """The alert-rule sweep is queued, and the guardian worker runs it.

        Until #537 nothing consumed guardian's queue, and this test could only
        assert that a task id came back. It now waits for the task to finish.
        """
        response = requests.post(
            ALERT_CHECK_ALL, headers=admin_headers, timeout=TIMEOUT
        )
        assert (
            response.status_code == 200
        ), f"{response.status_code} {response.text[:300]}"
        task_id = response.json().get("task_id")
        assert task_id, response.json()

        status = _wait_for_task(task_id, admin_headers)
        assert status["state"] == "SUCCESS", status
        assert status["successful"] is True, status

    def test_asset_scan_runs(self, admin_headers) -> None:
        """POST .../assets/{id}/scan/ queues a port scan that completes.

        The action imported a module that does not exist and answered 500 on
        every call (#537). The address is loopback, so the worker scans
        itself: every port is refused at once and nothing leaves the host.
        """
        payload = {
            "name": f"it-guardian-scan-{uuid.uuid4().hex[:12]}",
            "asset_type": "server",
            "ip_address": f"127.0.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}",
        }
        created = requests.post(
            ASSETS, json=payload, headers=admin_headers, timeout=TIMEOUT
        )
        assert created.status_code == 201, created.text[:300]
        asset_id = created.json()["id"]
        try:
            response = requests.post(
                f"{ASSETS}{asset_id}/scan/", headers=admin_headers, timeout=TIMEOUT
            )
            assert (
                response.status_code == 200
            ), f"{response.status_code} {response.text[:300]}"
            status = _wait_for_task(response.json()["task_id"], admin_headers)
            assert status["state"] == "SUCCESS", status
        finally:
            requests.delete(
                f"{ASSETS}{asset_id}/", headers=admin_headers, timeout=TIMEOUT
            )

    def test_monitoring_dashboard_access(self, admin_headers) -> None:
        """Reporting dashboards are served to an authenticated user, not to anyone."""
        anonymous = requests.get(DASHBOARDS, timeout=TIMEOUT)
        assert anonymous.status_code == 401, anonymous.status_code

        _assert_page(requests.get(DASHBOARDS, headers=admin_headers, timeout=TIMEOUT))


def run_tests() -> dict:
    """Entry point kept for tests/test_pulse_check_system.py; runs this module."""
    started = time.time()
    code = pytest.main([__file__, "-q"])
    return {
        "success": code == 0,
        "summary": f"pytest exit code {code} in {time.time() - started:.1f}s",
    }
