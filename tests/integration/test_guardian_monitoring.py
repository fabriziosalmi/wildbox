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
from datetime import datetime, timezone

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
DISCOVERY_RULES = f"{GUARDIAN_API}/assets/discovery-rules/"
REPORT_TEMPLATES = f"{GUARDIAN_API}/reports/templates/"
REPORT_SCHEDULES = f"{GUARDIAN_API}/reports/schedules/"
REPORTS = f"{GUARDIAN_API}/reports/reports/"

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


def _beat_interval(variable: str, default: str = "") -> int:
    """How often guardian-beat sends a periodic task in this stack, in seconds.

    The suite waits for beat, so an interval over 60 s would make its
    deadlines minutes long: it is refused (a failure when every service is
    required, a skip otherwise). CI starts the stack with the variable set
    and gives the suite the same value.
    """
    interval = os.getenv(variable, "") or default
    if not interval.isdigit() or not 0 < int(interval) <= 60:
        message = (
            f"start the stack with {variable} at 60 s or "
            "less, and set it for the suite too"
        )
        if os.getenv("REQUIRE_ALL_SERVICES", "") in ("1", "true", "yes"):
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    return int(interval)


def _alert_rule_interval() -> int:
    """How often guardian-beat sends the alert-rule sweep in this stack.

    The default is 15 minutes, too long to wait for; CI starts the stack
    with GUARDIAN_SCHEDULE_ALERT_RULES=15.
    """
    return _beat_interval("GUARDIAN_SCHEDULE_ALERT_RULES")


def _user_schedule_interval() -> int:
    """How often guardian-beat sends the user-schedule dispatcher (#548).

    GUARDIAN_SCHEDULE_USER_SCHEDULES, 60 seconds when unset, as in
    guardian/schedule.py.
    """
    return _beat_interval("GUARDIAN_SCHEDULE_USER_SCHEDULES", "60")


def _timestamp(value: str) -> datetime:
    """A DRF datetime ("...Z") as an aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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

    def test_report_schedule_runs_on_its_own(self, admin_headers) -> None:
        """A report schedule that is due is generated without anyone asking.

        Report schedules were stored and never run (#548): nothing read
        next_run. guardian-beat now sends a dispatcher every
        GUARDIAN_SCHEDULE_USER_SCHEDULES seconds that queues each due
        schedule's report. Nothing in this test starts one: the report can
        only appear if beat sent the dispatcher, the dispatcher queued the
        report and the worker generated it -- and before #548 generation
        itself failed for every report, so it must also complete and be
        downloadable from guardian, which is not the container that wrote it.
        """
        interval = _user_schedule_interval()
        template = requests.post(
            REPORT_TEMPLATES,
            json={
                "name": f"it-guardian-template-{uuid.uuid4().hex[:12]}",
                "report_type": "vulnerability_summary",
                "template_content": "unused: reports are rendered by guardian",
                "default_format": "json",
            },
            headers=admin_headers,
            timeout=TIMEOUT,
        )
        assert template.status_code == 201, template.text[:300]
        template_id = template.json()["id"]
        try:
            created = requests.post(
                REPORT_SCHEDULES,
                json={
                    "name": f"it-guardian-schedule-{uuid.uuid4().hex[:12]}",
                    "template": template_id,
                    "frequency": "once",
                    "format": "json",
                    "next_run": datetime.now(timezone.utc).isoformat(),
                },
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert created.status_code == 201, created.text[:300]
            schedule = created.json()
            assert schedule["status"] == "active", schedule
            assert schedule["last_run"] is None, schedule

            report: dict = {}
            deadline = time.monotonic() + max(TASK_DEADLINE, 3 * interval)
            while time.monotonic() < deadline:
                listing = _assert_page(
                    requests.get(
                        REPORTS,
                        params={"schedule": schedule["id"]},
                        headers=admin_headers,
                        timeout=TIMEOUT,
                    )
                )
                if listing["results"] and listing["results"][0]["status"] in (
                    "completed",
                    "failed",
                ):
                    assert listing["count"] == 1, listing
                    report = listing["results"][0]
                    break
                time.sleep(2)
            assert report, "no scheduled run generated the report within the deadline"
            assert report["status"] == "completed", report

            # A one-off schedule runs once, then is switched off.
            current = requests.get(
                f"{REPORT_SCHEDULES}{schedule['id']}/",
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert current.status_code == 200, current.text[:300]
            assert current.json()["status"] == "disabled", current.json()
            assert current.json()["last_run"], current.json()

            download = requests.get(
                f"{REPORTS}{report['id']}/download/",
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert download.status_code == 200, download.text[:300]
            body = download.json()
            assert isinstance(body["vulnerabilities"], list), body
            assert isinstance(body["vulnerability_stats"]["total_count"], int), body
        finally:
            # The schedule and its reports go with the template (CASCADE).
            requests.delete(
                f"{REPORT_TEMPLATES}{template_id}/",
                headers=admin_headers,
                timeout=TIMEOUT,
            )

    def test_discovery_rule_runs_on_its_own(self, admin_headers) -> None:
        """A discovery rule runs on its cron schedule and finds its host.

        Discovery rules had a cron schedule nothing read (#548), and the
        host probe ran a ping binary the image does not contain, so even a
        manual run found nothing. The rule here runs every minute over one
        loopback address, which the worker's TCP probe finds up (every
        connection is refused at once, and nothing leaves the host); the
        asset can only appear if the rule ran on its own.
        """
        interval = _user_schedule_interval()
        address = f"127.0.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}"
        created = requests.post(
            DISCOVERY_RULES,
            json={
                "name": f"it-guardian-rule-{uuid.uuid4().hex[:12]}",
                "discovery_type": "network_scan",
                "target_specification": {"networks": [f"{address}/32"]},
                "schedule": "* * * * *",
            },
            headers=admin_headers,
            timeout=TIMEOUT,
        )
        assert created.status_code == 201, created.text[:300]
        rule = created.json()
        assert rule["next_run"], rule
        assert rule["last_run"] is None, rule
        found: list = []
        try:
            # The first run is at the next minute, then within one interval.
            deadline = time.monotonic() + 60 + max(TASK_DEADLINE, 3 * interval)
            while time.monotonic() < deadline:
                listing = _assert_page(
                    requests.get(
                        ASSETS,
                        params={"search": address},
                        headers=admin_headers,
                        timeout=TIMEOUT,
                    )
                )
                found = [a for a in listing["results"] if a["ip_address"] == address]
                if found:
                    break
                time.sleep(2)
            assert found, f"no scheduled run of the rule discovered {address}"

            current = requests.get(
                f"{DISCOVERY_RULES}{rule['id']}/",
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            assert current.status_code == 200, current.text[:300]
            ran = current.json()
            assert ran["last_run"], ran
            # Moved on past the run it claimed.
            assert _timestamp(ran["next_run"]) > _timestamp(ran["last_run"]), ran
        finally:
            requests.delete(
                f"{DISCOVERY_RULES}{rule['id']}/",
                headers=admin_headers,
                timeout=TIMEOUT,
            )
            for asset in found:
                requests.delete(
                    f"{ASSETS}{asset['id']}/", headers=admin_headers, timeout=TIMEOUT
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
