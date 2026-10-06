"""Every route answers, and its answer is the one its model describes (#766).

``GET /api/v1/checks`` answered 500 as soon as a check matched: the model
requires ``remediation`` of every check, and the catalog the runner returns
left it out. ``GET /api/v1/scans/{id}/compliance`` answered 500 for every
completed scan: the handler gave a datetime to a field declared a string.
Both failures were in the building of the route's own response model, and
nothing called either route.

The first test here is the one that would have: it takes the routes from
the application, sends each the request ``route_probes.REQUESTS`` holds for
it, on a stock of scans the API and the worker's task made, and validates
the answer against the model the route declares. A route without a request,
or without a model, fails until it has one.
"""

from datetime import datetime

import pytest
from app import main, scan_store, schemas
from app.checks.framework import CheckStatus, CloudProvider
from route_probes import (
    HEADERS,
    OTHER_TEAM_HEADERS,
    REQUESTS,
    route_keys,
    route_named,
    send,
)

# The routes that answer no model of the service: the Prometheus text
# exposition (open_security_shared.observability) and the liveness probe,
# whose body is one fixed word. Every other route declares its answer.
WITHOUT_A_MODEL = {("GET", "/metrics"), ("GET", "/health/live")}

ROUTES = route_keys()


def test_every_route_has_a_request_to_walk_it_with():
    assert set(REQUESTS) == set(ROUTES)


def test_every_route_but_the_two_probes_declares_its_answer():
    without = {
        (method, path)
        for method, path in ROUTES
        if route_named(method, path).response_model is None
    }
    assert without == WITHOUT_A_MODEL


@pytest.mark.parametrize("method, path", ROUTES, ids=[" ".join(key) for key in ROUTES])
def test_the_answer_of_every_route_validates_against_its_model(world, method, path):
    route = route_named(method, path)

    response = send(world.client, method, path, world.scans)

    assert response.status_code == (route.status_code or 200), response.text
    if route.response_model is None:
        assert (method, path) in WITHOUT_A_MODEL
        return
    body = response.json()
    route.response_model.model_validate(body)
    # Nothing the model declares is missing from what was sent, and nothing
    # is sent that the model does not declare.
    assert set(body) == set(route.response_model.model_fields)


# --- GET /api/v1/checks ----------------------------------------------------------


def _loaded_checks():
    return [
        check for checks in main.check_runner.loaded_checks.values() for check in checks
    ]


def test_the_catalog_lists_every_loaded_check_with_what_it_declares(world):
    response = world.client.get("/api/v1/checks", headers=HEADERS)

    assert response.status_code == 200, response.text
    body = schemas.ChecksListResponse.model_validate(response.json())
    loaded = {check.metadata.check_id: check.metadata for check in _loaded_checks()}
    assert len(loaded) >= 22
    assert body.total_checks == len(body.checks) == len(loaded)
    assert {check.check_id for check in body.checks} == set(loaded)
    for check in body.checks:
        declared = loaded[check.check_id]
        # The check's own words, not a placeholder and not an empty string.
        assert check.remediation == declared.remediation
        assert check.remediation.strip()
        assert check.references == declared.references
        assert check.title == declared.title
        assert check.severity == declared.severity
        assert check.compliance_frameworks == declared.compliance_frameworks
    assert body.providers == ["aws"]
    assert body.categories == sorted({check.category for check in loaded.values()})


def test_the_catalog_entry_of_a_check_is_what_its_results_carry(world):
    """The remediation the catalog shows is the one a result of the check has."""
    catalog = {
        check["check_id"]: check
        for check in world.client.get("/api/v1/checks", headers=HEADERS).json()[
            "checks"
        ]
    }
    report = world.client.get(
        f"/api/v1/scans/{world.scans.completed}/report", headers=HEADERS
    ).json()

    verdicts = [r for r in report["results"] if r["status"] in ("passed", "failed")]
    assert verdicts
    for result in verdicts:
        assert result["remediation"] == catalog[result["check_id"]]["remediation"]


@pytest.mark.parametrize(
    "query, expected",
    [
        ({"provider": "aws"}, "all"),
        ({"provider": "AWS"}, "all"),
        ({"provider": "gcp"}, "none"),
        # Answered 500: not one of the provider enum's values.
        ({"provider": "oracle"}, "none"),
        ({"severity": "no-such-severity"}, "none"),
        ({"category": "no-such-category"}, "none"),
    ],
    ids=lambda value: str(value),
)
def test_a_filter_that_matches_no_check_is_an_empty_list(world, query, expected):
    response = world.client.get("/api/v1/checks", params=query, headers=HEADERS)

    assert response.status_code == 200, response.text
    body = schemas.ChecksListResponse.model_validate(response.json())
    if expected == "all":
        assert body.total_checks == len(_loaded_checks())
    else:
        assert body.total_checks == 0
        assert (body.checks, body.providers, body.categories) == ([], [], [])


def test_the_severity_and_category_filters_keep_the_matching_checks(world):
    loaded = [check.metadata for check in _loaded_checks()]
    severity = loaded[0].severity.value
    category = loaded[0].category

    by_severity = world.client.get(
        "/api/v1/checks", params={"severity": severity.upper()}, headers=HEADERS
    ).json()
    by_category = world.client.get(
        "/api/v1/checks", params={"category": category.upper()}, headers=HEADERS
    ).json()

    assert {c["check_id"] for c in by_severity["checks"]} == {
        m.check_id for m in loaded if m.severity.value == severity
    }
    assert {c["check_id"] for c in by_category["checks"]} == {
        m.check_id for m in loaded if m.category == category
    }
    assert by_category["categories"] == [category]


# --- GET /api/v1/scans/{id}/compliance ---------------------------------------------


def test_the_compliance_report_of_a_completed_scan(world):
    before = datetime.utcnow()

    response = world.client.get(
        f"/api/v1/scans/{world.scans.completed}/compliance", headers=HEADERS
    )

    assert response.status_code == 200, response.text
    body = response.json()
    report = schemas.ComplianceReportResponse.model_validate(body)
    assert report.scan_id == world.scans.completed
    assert report.account_id == "123456789012"
    # UTC without an offset, as every other time in this service's answers.
    generated = datetime.fromisoformat(body["generated_at"])
    assert generated.tzinfo is None
    assert before <= generated <= datetime.utcnow()

    # The figures are those of the stored report, per framework.
    stored = scan_store.load_report(world.redis, world.scans.completed)
    expected = {}
    for result in stored["results"]:
        for framework in result["compliance_frameworks"]:
            row = expected.setdefault(framework, {"total": 0, "passed": 0, "failed": 0})
            row["total"] += 1
            if result["status"] in ("passed", "failed"):
                row[result["status"]] += 1
    assert expected, "the scan's checks map to no framework"
    assert {row.framework for row in report.frameworks} == set(expected)
    for row in report.frameworks:
        figures = expected[row.framework]
        assert (row.total_checks, row.passed_checks, row.failed_checks) == (
            figures["total"],
            figures["passed"],
            figures["failed"],
        )
        # Over the results with a verdict. This asserted the division by
        # the total, which counts the results without one (#778).
        assert row.compliance_percentage == pytest.approx(
            figures["passed"] / (figures["passed"] + figures["failed"]) * 100
        )
    assert report.recommendations == stored["summary"]["recommendations"]
    assert report.recommendations
    # A result without a verdict is in a framework's total and in neither of
    # its other counts, as in the report's own summary: the reference says so.
    assert any(
        row.total_checks > row.passed_checks + row.failed_checks
        for row in report.frameworks
    )
    assert {
        row.framework: (row.total_checks, row.passed_checks, row.failed_checks)
        for row in report.frameworks
    } == {
        name: (figures["total"], figures["passed"], figures["failed"])
        for name, figures in stored["summary"]["compliance_frameworks"].items()
    }
    assert report.overall_score == pytest.approx(
        sum(row.passed_checks for row in report.frameworks)
        / sum(row.passed_checks + row.failed_checks for row in report.frameworks)
        * 100
    )


def test_the_compliance_report_can_be_narrowed_to_one_framework(world):
    passing = world.checks[0]
    framework = passing.metadata.compliance_frameworks[0]

    response = world.client.get(
        f"/api/v1/scans/{world.scans.completed}/compliance",
        params={"framework": framework},
        headers=HEADERS,
    )

    assert response.status_code == 200, response.text
    report = schemas.ComplianceReportResponse.model_validate(response.json())
    assert [row.framework for row in report.frameworks] == [framework]
    assert report.overall_score == report.frameworks[0].compliance_percentage


def test_a_framework_no_result_carries_gives_an_empty_report(world):
    response = world.client.get(
        f"/api/v1/scans/{world.scans.completed}/compliance",
        params={"framework": "no such framework"},
        headers=HEADERS,
    )

    assert response.status_code == 200, response.text
    report = schemas.ComplianceReportResponse.model_validate(response.json())
    assert report.frameworks == []
    assert report.overall_score == 0


@pytest.mark.parametrize("state", ["queued", "running", "failed"])
def test_a_scan_that_did_not_complete_has_no_compliance_report(world, state):
    scan_id = getattr(world.scans, state)

    response = world.client.get(f"/api/v1/scans/{scan_id}/compliance", headers=HEADERS)

    assert response.status_code == 400, response.text
    assert response.json()["error"]["message"] == "Scan is not completed"


def test_another_teams_compliance_report_is_refused(world):
    response = world.client.get(
        f"/api/v1/scans/{world.scans.completed}/compliance", headers=OTHER_TEAM_HEADERS
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["message"] == "Access denied"


# --- A report is its scan's -------------------------------------------------------
# Found by the walk: the runner gave each report an id of its own making, so
# the report of scan A read ``"scan_id": B``, and every finding named B, an
# id no route knows. The tests that read reports wrote them by hand, with
# the scan's id.


def test_a_report_names_the_scan_it_was_asked_for(world):
    response = world.client.get(
        f"/api/v1/scans/{world.scans.completed}/report", headers=HEADERS
    )

    assert response.status_code == 200, response.text
    assert response.json()["scan_id"] == world.scans.completed
    # And it is stored so: the worker's task gives the runner the scan's id.
    stored = scan_store.decode_report(
        world.redis.get(scan_store.report_key(world.scans.completed))
    )
    assert stored["scan_id"] == world.scans.completed


def test_a_finding_names_a_scan_that_can_be_read(world):
    findings = world.client.get("/api/v1/compliance/findings", headers=HEADERS).json()

    assert findings["total_count"] == 3
    for finding in findings["findings"]:
        assert finding["scan_id"] == world.scans.completed
        assert finding["finding_id"].startswith(f"{world.scans.completed}:")
        read = world.client.get(f"/api/v1/scans/{finding['scan_id']}", headers=HEADERS)
        assert read.status_code == 200, read.text


def test_a_report_stored_under_another_id_is_read_as_its_scans(world):
    """Reports stored before the fix carry the runner's id; they are read
    with the id of the scan they are stored under."""
    scan_id = world.scans.completed
    report = scan_store.load_report(world.redis, scan_id)
    report["scan_id"] = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
    world.redis.setex(
        scan_store.report_key(scan_id),
        scan_store.retention_seconds(),
        scan_store.encode_report(report),
    )

    assert scan_store.load_report(world.redis, scan_id)["scan_id"] == scan_id
    read = world.client.get(f"/api/v1/scans/{scan_id}/report", headers=HEADERS).json()
    assert read["scan_id"] == scan_id
    findings = world.client.get("/api/v1/compliance/findings", headers=HEADERS).json()
    assert {finding["scan_id"] for finding in findings["findings"]} == {scan_id}


# --- The stock itself ------------------------------------------------------------


def test_the_stock_holds_a_scan_in_each_state_as_the_service_made_it(world):
    """What the walk reads is real: each state is read back through the API."""
    statuses = {
        state: world.client.get(
            f"/api/v1/scans/{getattr(world.scans, state)}", headers=HEADERS
        ).json()
        for state in ("queued", "running", "completed", "failed")
    }

    assert {state: body["status"] for state, body in statuses.items()} == {
        "queued": "queued",
        "running": "running",
        "completed": "completed",
        "failed": "failed",
    }
    assert statuses["running"]["progress"]["current_status"] == "initializing"
    assert statuses["completed"]["completed_at"]

    stored = scan_store.load_report(world.redis, world.scans.completed)
    assert {result["status"] for result in stored["results"]} == {
        CheckStatus.PASSED.value,
        CheckStatus.FAILED.value,
        CheckStatus.ERROR.value,
        CheckStatus.SKIPPED.value,
    }
    assert stored["provider"] == CloudProvider.AWS.value
