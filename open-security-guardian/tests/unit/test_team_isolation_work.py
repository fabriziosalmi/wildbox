"""Background work, task status, filters and users stay within a team (#642).

test_team_isolation.py covers the viewsets' rows. This covers what reaches
another team's data without a row id in the URL: the Celery tasks a team
starts or schedules (discovery, alert rules, reports, widgets, compliance
metrics), the status of a dispatched task, the foreign-key filters of the
list endpoints, and the users a team can name.
"""

import json
import os
import uuid
from unittest import mock

import pytest
from django.test import Client

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"


@pytest.fixture
def api(settings, monkeypatch):
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)

    def call(method, url, team, data=None, role="admin", user_id=None):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": user_id or str(uuid.uuid4()),
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": role,
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
        }
        if data is not None:
            kwargs.update(data=data, content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def teams():
    return uuid.uuid4(), uuid.uuid4()


def _models():
    from apps.assets.models import Asset, AssetGroup
    from apps.reporting.models import AlertRule

    return Asset, AssetGroup, AlertRule


# --- the status of a dispatched task -------------------------------------------


@pytest.mark.django_db
def test_a_task_is_visible_to_the_team_that_dispatched_it_only(api, teams):
    team_a, team_b = teams
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        asset = tf.asset(team_a, ip_address="192.0.2.10")
    task_id = str(uuid.uuid4())
    with mock.patch("apps.assets.views.scan_asset_ports") as task:
        task.delay.return_value = mock.Mock(id=task_id)
        dispatched = api("post", f"/api/v1/assets/assets/{asset.pk}/scan/", team_a)
    assert dispatched.status_code == 200, dispatched.content[:300]
    assert dispatched.json()["task_id"] == task_id

    backend = mock.Mock(state="SUCCESS", queue="scanning")
    with mock.patch("guardian.celery.app.AsyncResult", return_value=backend):
        mine = api("get", f"/api/v1/tasks/{task_id}/", team_a, role="member")
        theirs = api("get", f"/api/v1/tasks/{task_id}/", team_b, role="member")
        nobodys = api("get", f"/api/v1/tasks/{uuid.uuid4()}/", team_a, role="member")

    assert mine.status_code == 200, mine.content[:300]
    assert mine.json()["state"] == "SUCCESS"
    # Another team's task and a task nobody dispatched answer alike.
    assert theirs.status_code == 404
    assert nobodys.status_code == 404
    assert theirs.json() == nobodys.json()


@pytest.mark.django_db
def test_every_endpoint_that_answers_a_task_id_records_its_team(api, teams):
    from apps.core.models import TeamTask

    team_a, _ = teams
    with mock.patch("apps.assets.views.discover_assets") as discover, mock.patch(
        "apps.reporting.tasks.check_all_alert_rules"
    ) as check_all, mock.patch("apps.assets.tasks.execute_discovery_rule") as execute:
        discover.delay.return_value = mock.Mock(id="t-discover")
        check_all.delay.return_value = mock.Mock(id="t-alerts")
        execute.delay.return_value = mock.Mock(id="t-rule")
        rule = tf.discovery_rule(team_a)
        responses = [
            api(
                "post",
                "/api/v1/assets/assets/discover/",
                team_a,
                data={"network_range": "192.0.2.0/30"},
            ),
            api("post", "/api/v1/reports/alerts/check_all/", team_a, data={}),
            api(
                "post",
                f"/api/v1/assets/discovery-rules/{rule.pk}/execute/",
                team_a,
                data={},
            ),
        ]
    for response in responses:
        assert response.status_code == 200, response.content[:300]
    recorded = dict(TeamTask.objects.values_list("task_id", "team_id"))
    assert recorded == {
        "t-discover": team_a,
        "t-alerts": team_a,
        "t-rule": team_a,
    }
    # The discovery and the alert sweep run for the caller's team only.
    assert discover.delay.call_args.kwargs == {"team_id": str(team_a)}
    assert check_all.delay.call_args.kwargs == {"team_id": str(team_a)}


# --- Celery tasks operate on their team's rows ------------------------------------


@pytest.mark.django_db
def test_discovery_finds_hosts_for_its_team_and_leaves_others_alone(teams):
    from apps.assets.tasks import discover_assets

    Asset, _, _ = _models()
    team_a, team_b = teams
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        theirs = tf.asset(team_b, ip_address="192.0.2.1")
    seen_before = theirs.last_seen

    with mock.patch("apps.assets.tasks._host_is_up", return_value=True), mock.patch(
        "apps.assets.tasks._resolve_hostname", return_value=None
    ), mock.patch("apps.assets.signals.scan_asset_ports"):
        result = discover_assets.apply(
            args=("192.0.2.0/30", "basic"), kwargs={"team_id": str(team_a)}
        ).get()

    assert result["discovered_count"] == 2
    mine = Asset.objects.filter(team_id=team_a)
    assert sorted(mine.values_list("ip_address", flat=True)) == [
        "192.0.2.1",
        "192.0.2.2",
    ]
    theirs.refresh_from_db()
    assert theirs.team_id == team_b
    assert theirs.last_seen == seen_before
    assert Asset.objects.filter(team_id__isnull=True).count() == 0


@pytest.mark.django_db
def test_a_scheduled_discovery_rule_discovers_for_its_team(teams):
    from apps.assets.tasks import execute_discovery_rule

    team_a, _ = teams
    rule = tf.discovery_rule(team_a)
    with mock.patch("apps.assets.tasks.discover_assets") as discover:
        execute_discovery_rule.apply(args=(rule.pk,)).get()
    discover.delay.assert_called_once_with("192.0.2.0/30", "basic", team_id=str(team_a))


@pytest.mark.django_db
def test_alert_rules_measure_their_own_teams_data(teams):
    from apps.reporting.alert_metrics import current_value

    team_a, team_b = teams
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        rule_a = tf.alert_rule(team_a)
        rule_b = tf.alert_rule(team_b)
        rule_legacy = tf.alert_rule(None)
    tf.make(_vulnerability(), team_a)
    for _ in range(3):
        tf.make(_vulnerability(), team_b)

    assert current_value(rule_a) == 1
    assert current_value(rule_b) == 3
    # A rule written before guardian kept a team sees the rows without one.
    assert current_value(rule_legacy) == 0
    tf.make(_vulnerability(), None)
    assert current_value(rule_legacy) == 1


@pytest.mark.django_db
def test_an_alert_rule_cannot_filter_on_another_teams_asset(api, teams):
    team_a, team_b = teams
    theirs = tf.asset(team_b)
    mine = tf.asset(team_a)
    payload = {
        "name": "r",
        "data_source": "vulnerabilities.unresolved",
        "condition_type": "threshold",
        "operator": "gt",
        "threshold_value": 0,
        "notification_config": {},
    }
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        refused = api(
            "post",
            "/api/v1/reports/alerts/",
            team_a,
            data={**payload, "condition_config": {"asset": str(theirs.pk)}},
        )
        accepted = api(
            "post",
            "/api/v1/reports/alerts/",
            team_a,
            data={**payload, "condition_config": {"asset": str(mine.pk)}},
        )
    assert refused.status_code == 400, refused.content[:300]
    assert "condition_config" in refused.json()
    assert accepted.status_code == 201, accepted.content[:300]


@pytest.mark.django_db
def test_check_all_from_the_api_checks_the_callers_rules_only(teams, settings):
    from apps.reporting.tasks import check_all_alert_rules

    # The sweep's lock uses the default cache, Redis outside the tests; a
    # cache of its own, so no lock another test left behind skips the run.
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": f"check-all-{uuid.uuid4().hex}",
        }
    }
    team_a, team_b = teams
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        mine = tf.alert_rule(team_a)
        tf.alert_rule(team_b)
    with mock.patch("apps.reporting.tasks.deliver_alert_notification"):
        team_run = check_all_alert_rules.apply(kwargs={"team_id": str(team_a)}).get()
        sweep = check_all_alert_rules.apply().get()
    assert [r["rule_id"] for r in team_run] == [str(mine.pk)]
    assert len(sweep) == 2


@pytest.mark.django_db
def test_a_report_holds_its_teams_data_in_its_teams_directory(
    teams, settings, tmp_path
):
    from apps.reporting.tasks import generate_report

    settings.MEDIA_ROOT = str(tmp_path)
    team_a, team_b = teams
    mine = tf.make(_vulnerability(), team_a)
    theirs = tf.make(_vulnerability(), team_b)
    report = tf.report(team_a)

    with mock.patch("apps.reporting.tasks.update_report_metrics"):
        assert generate_report.apply(args=(report.pk,)).get() == report.pk

    report.refresh_from_db()
    assert report.status == "completed", report.error_message
    assert os.path.dirname(report.file_path) == os.path.join(
        str(tmp_path), "reports", str(team_a)
    )
    with open(report.file_path) as handle:
        data = json.load(handle)
    titles = {row["title"] for row in data["vulnerabilities"]}
    assert titles == {mine.title}
    assert theirs.title not in json.dumps(data)
    assert data["vulnerability_stats"]["total_count"] == 1


@pytest.mark.django_db
def test_report_download_serves_only_the_teams_report_files(
    api, teams, settings, tmp_path
):
    from apps.reporting.models import Report

    settings.MEDIA_ROOT = str(tmp_path / "media")
    team_a, team_b = teams
    files = {}
    for name, directory in (
        ("outside", tmp_path),
        ("theirs", tmp_path / "media" / "reports" / str(team_b)),
        ("mine", tmp_path / "media" / "reports" / str(team_a)),
        ("legacy", tmp_path / "media" / "reports"),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        files[name] = directory / f"{name}.json"
        files[name].write_text(f'{{"file": "{name}"}}')
    report = tf.report(team_a)
    url = f"/api/v1/reports/reports/{report.pk}/download/"

    def download(name, team=team_a):
        Report.objects.filter(pk=report.pk).update(
            status="completed", file_path=str(files[name])
        )
        return api("get", url, team)

    assert download("outside").status_code == 404
    assert download("theirs").status_code == 404
    mine = download("mine")
    assert mine.status_code == 200
    assert mine.content == b'{"file": "mine"}'
    # Written before reports were kept per team.
    assert download("legacy").status_code == 200
    assert download("mine", team=team_b).status_code == 404


@pytest.mark.django_db
def test_a_report_file_path_cannot_be_set_through_the_api(api, teams):
    team_a, _ = teams
    template = tf.report_template(team_a)
    created = api(
        "post",
        "/api/v1/reports/reports/",
        team_a,
        data={
            "name": "r",
            "template": str(template.pk),
            "format": "json",
            "status": "completed",
            "file_path": "/etc/passwd",
        },
    )
    assert created.status_code == 201, created.content[:300]
    assert created.json()["file_path"] == ""
    patched = api(
        "patch",
        f"/api/v1/reports/reports/{created.json()['id']}/",
        team_a,
        data={"file_path": "/etc/passwd"},
    )
    assert patched.status_code == 200, patched.content[:300]
    assert patched.json()["file_path"] == ""


@pytest.mark.django_db
def test_widgets_and_dashboards_show_their_teams_data(api, teams):
    from apps.reporting.tasks import process_widget_data

    team_a, team_b = teams
    tf.asset(team_a)
    for _ in range(4):
        tf.asset(team_b)
    widget = tf.widget(team_a)

    response = api("get", f"/api/v1/reports/widgets/{widget.pk}/data/", team_a)
    assert response.status_code == 200, response.content[:300]
    assert response.json()["value"] == 1
    assert process_widget_data(widget, {}, team_id=team_b)["value"] == 4

    board = tf.dashboard(team_a)
    board.widgets_config = [{"type": "metric", "data_source": "assets"}]
    board.save()
    response = api("get", f"/api/v1/reports/dashboards/{board.pk}/data/", team_a)
    assert response.status_code == 200, response.content[:300]
    assert response.json()["widgets"] == [{"value": 1, "label": "Total Assets"}]


@pytest.mark.django_db
def test_compliance_metrics_count_the_assessments_teams_exceptions(teams):
    from apps.compliance.models import ComplianceMetrics, ComplianceResult
    from apps.compliance.tasks import calculate_compliance_metrics
    from django.utils import timezone

    team_a, team_b = teams
    shared = tf.framework(None)
    control = tf.control(None, shared)
    mine = tf.assessment(team_a, shared)
    with mock.patch("apps.compliance.signals.calculate_compliance_metrics"), mock.patch(
        "apps.compliance.signals.send_compliance_notification"
    ):
        ComplianceResult.objects.create(
            assessment=mine, control=control, status="compliant"
        )
        for team in (team_b, team_b):
            exception = tf.exception(team)
            exception.control = control
            exception.status = "approved"
            exception.valid_until = timezone.now() + timezone.timedelta(days=5)
            exception.save()

    calculate_compliance_metrics.apply(args=(str(mine.pk),)).get()

    metrics = ComplianceMetrics.objects.get(assessment=mine)
    assert metrics.team_id == team_a
    assert metrics.open_exceptions == 0


@pytest.mark.django_db
def test_auto_assignment_collects_the_groups_teams_assets_only(teams):
    Asset, AssetGroup, _ = _models()
    team_a, team_b = teams
    group = AssetGroup.objects.create(
        team_id=team_a, name="servers", auto_assignment_rules={"asset_type": "server"}
    )
    tf.asset(team_b, asset_type="server")
    mine = tf.asset(team_a, asset_type="server")

    group.apply_auto_assignment_rules()

    assert list(group.assets.values_list("pk", flat=True)) == [mine.pk]


@pytest.mark.django_db
def test_a_scheduled_report_is_generated_from_its_teams_data(teams, settings, tmp_path):
    from apps.core.tasks import dispatch_report_schedules
    from apps.reporting.models import Report
    from django.utils import timezone

    settings.MEDIA_ROOT = str(tmp_path)
    team_a, team_b = teams
    schedule = tf.report_schedule(team_a)
    tf.make(_vulnerability(), team_b)

    with mock.patch("apps.reporting.tasks.generate_report") as generate:
        outcome = dispatch_report_schedules(timezone.now())
    assert outcome["dispatched"] == [str(schedule.pk)]
    report = Report.objects.get(pk=generate.delay.call_args.args[0])
    # The report is the schedule's team's: its template's.
    assert report.template.team_id == team_a


# --- list filters do not tell which ids exist elsewhere ----------------------------


@pytest.mark.django_db
def test_filtering_on_another_teams_row_is_answered_like_an_unknown_id(api, teams):
    team_a, team_b = teams
    theirs = tf.asset(team_b)
    tf.make(_vulnerability(), team_b)
    mine = tf.asset(team_a)

    foreign = api("get", f"/api/v1/assets/software/?asset={theirs.pk}", team_a)
    unknown = api("get", f"/api/v1/assets/software/?asset={uuid.uuid4()}", team_a)
    own = api("get", f"/api/v1/assets/software/?asset={mine.pk}", team_a)

    assert foreign.status_code == 400, foreign.content[:300]
    assert unknown.status_code == 400, unknown.content[:300]
    assert foreign.json().keys() == unknown.json().keys()
    assert own.status_code == 200, own.content[:300]


# --- users a team can name ----------------------------------------------------------


@pytest.mark.django_db
def test_a_vulnerability_is_assigned_to_a_member_of_the_team_only(api, teams):
    team_a, team_b = teams
    vulnerability = tf.make(_vulnerability(), team_a)
    stranger = tf.user(team_b)
    colleague = tf.user(team_a)

    with mock.patch("apps.vulnerabilities.views.notify_vulnerability_assignment"):
        refused = api(
            "post",
            f"/api/v1/vulnerabilities/{vulnerability.pk}/assign/",
            team_a,
            data={"assigned_to": stranger.pk},
        )
        bulk = api(
            "post",
            "/api/v1/vulnerabilities/bulk_action/",
            team_a,
            data={
                "vulnerability_ids": [str(vulnerability.pk)],
                "action": "assign",
                "assigned_to": stranger.pk,
            },
        )
        accepted = api(
            "post",
            f"/api/v1/vulnerabilities/{vulnerability.pk}/assign/",
            team_a,
            data={"assigned_to": colleague.pk},
        )

    assert refused.status_code == 400, refused.content[:300]
    assert bulk.status_code == 400, bulk.content[:300]
    assert accepted.status_code == 200, accepted.content[:300]
    vulnerability.refresh_from_db()
    assert vulnerability.assigned_to_id == colleague.pk


@pytest.mark.django_db
def test_a_gateway_request_records_the_users_team(api, teams):
    from apps.core.models import TeamMembership

    team_a, _ = teams
    user_id = str(uuid.uuid4())
    api("get", "/api/v1/assets/assets/", team_a, user_id=user_id)
    assert TeamMembership.objects.filter(
        team_id=team_a, user__username=user_id
    ).exists()


@pytest.mark.django_db
def test_a_dashboard_is_shared_with_members_of_the_team_only(api, teams):
    team_a, team_b = teams
    board = tf.dashboard(team_a)
    stranger = tf.user(team_b)
    colleague = tf.user(team_a)

    response = api(
        "post",
        f"/api/v1/reports/dashboards/{board.pk}/share/",
        team_a,
        data={"user_ids": [stranger.pk, colleague.pk]},
    )

    assert response.status_code == 200, response.content[:300]
    assert list(board.shared_with.values_list("pk", flat=True)) == [colleague.pk]


@pytest.mark.django_db
def test_bulk_actions_skip_another_teams_rows(api, teams):
    team_a, team_b = teams
    theirs = tf.make(_vulnerability(), team_b)

    response = api(
        "post",
        "/api/v1/vulnerabilities/bulk_action/",
        team_a,
        data={"vulnerability_ids": [str(theirs.pk)], "action": "close"},
    )

    assert response.status_code == 404, response.content[:300]
    theirs.refresh_from_db()
    assert theirs.status == "open"


@pytest.mark.django_db
def test_group_membership_takes_the_teams_own_assets_only(api, teams):
    Asset, AssetGroup, _ = _models()
    team_a, team_b = teams
    group = tf.asset_group(team_a)
    theirs = tf.asset(team_b)
    mine = tf.asset(team_a)

    response = api(
        "post",
        f"/api/v1/assets/groups/{group.pk}/add_assets/",
        team_a,
        data={"asset_ids": [str(theirs.pk), str(mine.pk)]},
    )

    assert response.status_code == 200, response.content[:300]
    assert list(group.assets.values_list("pk", flat=True)) == [mine.pk]


def _vulnerability():
    from apps.vulnerabilities.models import Vulnerability

    return Vulnerability
