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
ALERTS = f"{GUARDIAN_API}/reports/alerts/"
ALERT_CHECK_ALL = f"{ALERTS}check_all/"
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


def _alert_rule_interval() -> int:
    """How often guardian-beat sends the alert-rule sweep in this stack.

    The default is 15 minutes, too long to wait for; CI starts the stack
    with GUARDIAN_SCHEDULE_ALERT_RULES=15 and gives the suite the same value.
    """
    interval = os.getenv("GUARDIAN_SCHEDULE_ALERT_RULES", "")
    if not interval.isdigit() or not 0 < int(interval) <= 60:
        message = (
            "start the stack with GUARDIAN_SCHEDULE_ALERT_RULES at 60 s or "
            "less, and set it for the suite too"
        )
        if os.getenv("REQUIRE_ALL_SERVICES", "") in ("1", "true", "yes"):
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    return int(interval)


def _wait_for_rule(rule_id, headers, condition, what, seconds) -> dict:
    """Poll an alert rule until ``condition(rule)`` holds; fail after ``seconds``."""
    deadline = time.monotonic() + seconds
    rule: dict = {}
    while time.monotonic() < deadline:
        response = requests.get(f"{ALERTS}{rule_id}/", headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200, response.text[:300]
        rule = response.json()
        if condition(rule):
            return rule
        time.sleep(2)
    pytest.fail(f"no sweep brought {what} within {seconds}s: {rule}")


def _notification_kinds(rule_id, headers) -> list:
    """The kinds of the notifications a rule recorded, newest first (#549)."""
    response = requests.get(
        f"{ALERTS}{rule_id}/notifications/", headers=headers, timeout=TIMEOUT
    )
    page = _assert_page(response)
    return [n["kind"] for n in page["results"]]


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


COMPLIANCE = f"{GUARDIAN_API}/compliance"
COMPLIANCE_FRAMEWORKS = f"{COMPLIANCE}/frameworks/"
COMPLIANCE_CONTROLS = f"{COMPLIANCE}/controls/"
COMPLIANCE_ASSESSMENTS = f"{COMPLIANCE}/assessments/"
COMPLIANCE_RESULTS = f"{COMPLIANCE}/results/"


def _wait_for_metrics(framework_id, headers, condition) -> dict:
    """Poll a framework's latest metrics until ``condition(metrics)`` holds.

    The metrics are recalculated by the guardian worker after a result
    changes; until it has run, the endpoint answers 404 or older counts.
    """
    deadline = time.monotonic() + TASK_DEADLINE
    metrics: dict = {}
    while time.monotonic() < deadline:
        response = requests.get(
            f"{COMPLIANCE_FRAMEWORKS}{framework_id}/metrics/",
            headers=headers,
            timeout=TIMEOUT,
        )
        assert response.status_code in (200, 404), response.text[:300]
        if response.status_code == 200:
            metrics = response.json()
            if condition(metrics):
                return metrics
        time.sleep(1)
    pytest.fail(f"metrics not recalculated after {TASK_DEADLINE}s: {metrics}")


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
        # Delivered on the queue guardian/celery.py routes it to. Until #545
        # the routes matched no task name and everything went to default.
        assert status["queue"] == "reporting", status

    def test_scheduled_task_runs_on_its_own(self, admin_headers, asset) -> None:
        """guardian-beat sends the alert-rule sweep without anyone asking.

        Nothing scheduled guardian's periodic tasks until #545. The rule
        created here counts the unresolved vulnerabilities of an asset that
        has none, so its value is 0 and "equal to 0" fires on the first
        evaluation; a sweep that is not in test mode records that in
        trigger_count. Nothing in this test starts a sweep, so the count can
        only move if beat sent one and the worker ran it. CI runs the sweep
        every GUARDIAN_SCHEDULE_ALERT_RULES seconds (15) instead of the
        default 15 minutes.
        """
        interval = _alert_rule_interval()

        payload = {
            "name": f"it-guardian-beat-{uuid.uuid4().hex[:12]}",
            # A real metric since #549, over data this test controls: the
            # rule used to name nothing and was evaluated against 0.
            "data_source": "vulnerabilities.unresolved",
            "condition_config": {"asset": asset["id"]},
            "condition_type": "threshold",
            "operator": "eq",
            "threshold_value": 0,
        }
        created = requests.post(
            ALERTS, json=payload, headers=admin_headers, timeout=TIMEOUT
        )
        assert created.status_code == 201, created.text[:300]
        rule = created.json()
        assert rule["trigger_count"] == 0, rule
        try:
            deadline = time.monotonic() + max(TASK_DEADLINE, 3 * interval)
            while time.monotonic() < deadline:
                current = requests.get(
                    f"{ALERTS}{rule['id']}/", headers=admin_headers, timeout=TIMEOUT
                )
                assert current.status_code == 200, current.text[:300]
                rule = current.json()
                if rule["trigger_count"] > 0:
                    break
                time.sleep(2)
            assert (
                rule["trigger_count"] > 0
            ), f"no scheduled sweep evaluated the rule within the deadline: {rule}"
            assert rule["last_triggered"], rule
            assert rule["last_value"] == 0, rule
        finally:
            requests.delete(
                f"{ALERTS}{rule['id']}/", headers=admin_headers, timeout=TIMEOUT
            )

    def test_alert_rule_notifies_on_state_changes(self, admin_headers, asset) -> None:
        """A rule notifies when it starts firing and when it recovers, once each.

        Until #549 every rule was evaluated against 0 and a firing rule
        notified on every sweep. The rule here counts the unresolved
        vulnerabilities of one asset, and the test moves it through every
        state with real data, the sweeps coming from guardian-beat alone:
        not firing (no vulnerability), firing (one is recorded), still firing
        over two more sweeps (no second notification: the re-notification
        interval is a day), recovered (it is resolved).
        """
        interval = _alert_rule_interval()
        deadline = max(TASK_DEADLINE, 3 * interval)
        created = requests.post(
            ALERTS,
            json={
                "name": f"it-guardian-states-{uuid.uuid4().hex[:12]}",
                "data_source": "vulnerabilities.unresolved",
                "condition_config": {"asset": asset["id"]},
                "condition_type": "threshold",
                "operator": "gt",
                "threshold_value": 0,
            },
            headers=admin_headers,
            timeout=TIMEOUT,
        )
        assert created.status_code == 201, created.text[:300]
        rule_id = created.json()["id"]
        try:
            rule = _wait_for_rule(
                rule_id,
                admin_headers,
                lambda r: r["last_evaluated_at"] is not None,
                "a first evaluation",
                deadline,
            )
            assert (rule["state"], rule["last_value"]) == ("ok", 0), rule
            assert _notification_kinds(rule_id, admin_headers) == []

            finding = requests.post(
                VULNERABILITIES,
                json={
                    "title": f"Alert rule finding {uuid.uuid4().hex[:8]}",
                    "description": "Created by the integration suite.",
                    "asset": asset["id"],
                    "severity": "high",
                    "cve_id": "CVE-2024-3094",
                },
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert finding.status_code == 201, finding.text[:300]
            # The create response carries no id; the asset has only this one.
            listing = _assert_page(
                requests.get(
                    VULNERABILITIES,
                    params={"asset_id": asset["id"]},
                    headers=admin_headers,
                    timeout=TIMEOUT,
                )
            )
            assert listing["count"] == 1, listing
            finding_id = listing["results"][0]["id"]

            rule = _wait_for_rule(
                rule_id,
                admin_headers,
                lambda r: r["state"] == "firing",
                "the rule to fire",
                deadline,
            )
            assert rule["last_value"] == 1, rule
            assert rule["trigger_count"] == 1, rule
            assert _notification_kinds(rule_id, admin_headers) == ["firing"]

            # Two more sweeps while it keeps firing: nothing new is sent.
            for _ in range(2):
                seen = rule["last_evaluated_at"]
                rule = _wait_for_rule(
                    rule_id,
                    admin_headers,
                    lambda r, seen=seen: r["last_evaluated_at"] != seen,
                    "another evaluation",
                    deadline,
                )
                assert rule["state"] == "firing", rule
            assert rule["trigger_count"] == 1, rule
            assert _notification_kinds(rule_id, admin_headers) == ["firing"]

            resolved = requests.patch(
                f"{VULNERABILITIES}{finding_id}/",
                json={"status": "resolved"},
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert resolved.status_code == 200, resolved.text[:300]

            rule = _wait_for_rule(
                rule_id,
                admin_headers,
                lambda r: r["state"] == "ok",
                "the rule to recover",
                deadline,
            )
            assert rule["last_value"] == 0, rule
            assert _notification_kinds(rule_id, admin_headers) == [
                "resolved",
                "firing",
            ]
        finally:
            requests.delete(
                f"{ALERTS}{rule_id}/", headers=admin_headers, timeout=TIMEOUT
            )

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
            # Port scans run on the scanning queue (#545).
            assert status["queue"] == "scanning", status
        finally:
            requests.delete(
                f"{ASSETS}{asset_id}/", headers=admin_headers, timeout=TIMEOUT
            )

    def test_monitoring_dashboard_access(self, admin_headers) -> None:
        """Reporting dashboards are served to an authenticated user, not to anyone."""
        anonymous = requests.get(DASHBOARDS, timeout=TIMEOUT)
        assert anonymous.status_code == 401, anonymous.status_code

        _assert_page(requests.get(DASHBOARDS, headers=admin_headers, timeout=TIMEOUT))

    def test_compliance_update_recalculates_metrics(self, admin_headers) -> None:
        """Updating a compliance result answers 200 and the worker recounts.

        The compliance signals read a FieldTracker the models never had, so
        updating a result or an assessment answered 500 and its metrics were
        never recalculated (#555).
        """
        framework = requests.post(
            COMPLIANCE_FRAMEWORKS,
            json={"name": f"it-guardian-{uuid.uuid4().hex[:12]}"},
            headers=admin_headers,
            timeout=TIMEOUT,
        )
        assert framework.status_code == 201, framework.text[:300]
        framework_id = framework.json()["id"]
        try:
            assessment = requests.post(
                COMPLIANCE_ASSESSMENTS,
                json={
                    "name": "Integration test assessment",
                    "framework": framework_id,
                    "assessment_type": "self_assessment",
                    "status": "in_progress",
                },
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert assessment.status_code == 201, assessment.text[:300]
            assessment_id = assessment.json()["id"]
            results = []
            for number in (1, 2):
                control = requests.post(
                    COMPLIANCE_CONTROLS,
                    json={
                        "framework": framework_id,
                        "control_id": f"IT-{number}",
                        "title": "Integration test control",
                        "description": "Created by the integration suite.",
                        "control_type": "technical",
                    },
                    headers=admin_headers,
                    timeout=TIMEOUT,
                )
                assert control.status_code == 201, control.text[:300]
                result = requests.post(
                    COMPLIANCE_RESULTS,
                    json={
                        "assessment": assessment_id,
                        "control": control.json()["id"],
                        "status": "compliant",
                        "risk_level": "low",
                    },
                    headers=admin_headers,
                    timeout=TIMEOUT,
                )
                assert result.status_code == 201, result.text[:300]
                results.append(result.json()["id"])

            updated = requests.patch(
                f"{COMPLIANCE_RESULTS}{results[0]}/",
                json={"status": "non_compliant", "risk_level": "critical"},
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert updated.status_code == 200, updated.text[:300]
            metrics = _wait_for_metrics(
                framework_id,
                admin_headers,
                lambda m: m["non_compliant_controls"] == 1,
            )
            assert metrics["total_controls"] == 2, metrics
            assert metrics["compliant_controls"] == 1, metrics
            assert metrics["high_risk_findings"] == 1, metrics
            assert float(metrics["compliance_percentage"]) == 50.0, metrics

            completed = requests.patch(
                f"{COMPLIANCE_ASSESSMENTS}{assessment_id}/",
                json={"status": "completed"},
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert completed.status_code == 200, completed.text[:300]
            assert completed.json()["status"] == "completed"
        finally:
            # Controls, the assessment, its results and metrics cascade.
            requests.delete(
                f"{COMPLIANCE_FRAMEWORKS}{framework_id}/",
                headers=admin_headers,
                timeout=TIMEOUT,
            )


def run_tests() -> dict:
    """Entry point kept for tests/test_pulse_check_system.py; runs this module."""
    started = time.time()
    code = pytest.main([__file__, "-q"])
    return {
        "success": code == 0,
        "summary": f"pytest exit code {code} in {time.time() - started:.1f}s",
    }
