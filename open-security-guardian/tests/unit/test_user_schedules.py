"""User-defined schedules are run (#548).

Asset discovery rules and report schedules were stored with a schedule and a
next_run that nothing read. apps.core.tasks.dispatch_due_schedules, sent by
guardian-beat every minute, now queues the work of each due schedule once per
due time. These tests cover when a schedule is due, the claim that makes a
run happen once even when two sweeps race, the work each kind queues, the
API validation that refuses schedules that could not run, and the scan
schedules guardian cannot run at all.
"""

import errno
import json
import socket
import uuid
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from unittest import mock

import pytest
from apps.core import tasks as dispatch
from apps.core.locks import LOCK_PREFIX
from apps.core.schedules import (
    InvalidSchedule,
    next_cron_run,
    next_frequency_run,
    schedule_timezone,
    validate_cron,
)
from celery.schedules import crontab
from django.test import Client
from django.utils import timezone
from guardian.celery import TASK_QUEUES, app
from guardian.schedule import build_beat_schedule

UTC = dt_timezone.utc
NOW = datetime(2026, 10, 2, 17, 33, 20, tzinfo=UTC)
_GW_SECRET = "test-gateway-secret"
# Every row these tests seed belongs to this team, and every request is
# made as a member of it: guardian answers 404 for another team's rows (#642).
TEAM_ID = str(uuid.uuid4())


@pytest.fixture
def locmem_cache(settings):
    # The lock and the throttles use the default cache, Redis outside tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


@pytest.fixture
def client(locmem_cache, monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    return Client(raise_request_exception=False)


def _headers(role="admin"):
    return {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": TEAM_ID,
        "HTTP_X_WILDBOX_ROLE": role,
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        "HTTP_X_WILDBOX_AUTH_TYPE": "session",
    }


# --- when a cron schedule is next due ----------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "* * * * *",
        "*/15 8-18 * * 1-5",
        "0 3 * * *",
        "0 8 * * 1",
        "30 4 1 * *",
        "0 0 29 2 *",
        "5 0 * 8 sun",
    ],
)
def test_next_cron_run_agrees_with_celery(expression):
    # Same syntax and meaning as GUARDIAN_SCHEDULE_*, which Celery runs.
    minute, hour, day_of_month, month_of_year, day_of_week = expression.split()
    reference = crontab(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month_of_year,
        day_of_week=day_of_week,
        app=app,
        nowfun=lambda: NOW,
    )
    start, delta, _ = reference.remaining_delta(NOW)
    assert next_cron_run(expression, NOW) == start + delta


def test_next_cron_run_is_strictly_after():
    on_the_minute = NOW.replace(minute=45, second=0)
    assert next_cron_run("*/15 * * * *", on_the_minute) == on_the_minute + timedelta(
        minutes=15
    )


def test_cron_is_read_in_the_celery_time_zone(settings):
    settings.CELERY_TIMEZONE = "Europe/Rome"
    # 03:00 in Rome is 01:00 UTC in October (CEST, UTC+2).
    assert next_cron_run("0 3 * * *", NOW).astimezone(UTC) == datetime(
        2026, 10, 3, 1, 0, tzinfo=UTC
    )


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "* * * *",
        "* * * * * *",
        "61 * * * *",
        "*/0 * * * *",
        "* * * * funday",
        "0 0 31 2 *",  # February 31st: never
        "0 0 30 2 *",
    ],
)
def test_invalid_cron_is_refused(expression):
    with pytest.raises(InvalidSchedule):
        validate_cron(expression)


@pytest.mark.parametrize("expression", ["61 * * * *", "* * * * funday", "0 0 31 2 *"])
def test_the_api_refuses_a_bad_schedule_without_the_parser_text(expression):
    from apps.assets.serializers import AssetDiscoveryRuleSerializer
    from rest_framework.exceptions import ValidationError

    with pytest.raises(ValidationError) as refused:
        AssetDiscoveryRuleSerializer().validate_schedule(expression)
    (message,) = refused.value.detail
    assert message == (
        "Schedule must be five crontab fields (minute hour day-of-month month "
        f"day-of-week, in {schedule_timezone()}) that match at least one time."
    )


def test_a_schedule_that_is_not_a_string_is_refused():
    with pytest.raises(InvalidSchedule):
        next_cron_run(None, NOW)


# --- when a report schedule is next due --------------------------------------


@pytest.mark.parametrize(
    "frequency,expected",
    [
        ("daily", NOW + timedelta(days=1)),
        ("weekly", NOW + timedelta(weeks=1)),
        ("monthly", NOW.replace(month=11)),
        ("quarterly", NOW.replace(year=2027, month=1)),
    ],
)
def test_next_frequency_run(frequency, expected):
    assert next_frequency_run(frequency, NOW, NOW) == expected


def test_a_one_off_schedule_has_no_next_run():
    assert next_frequency_run("once", NOW, NOW) is None


def test_missed_runs_are_skipped_not_replayed():
    # Due ten days ago, daily: one run now, the next tomorrow at the same time.
    due = NOW - timedelta(days=10, hours=1)
    assert next_frequency_run("daily", due, NOW) == due + timedelta(days=11)


def test_monthly_runs_keep_the_day_of_month():
    due = datetime(2026, 1, 31, 6, 0, tzinfo=UTC)
    assert next_frequency_run("monthly", due, due) == datetime(
        2026, 2, 28, 6, 0, tzinfo=UTC
    )
    later = datetime(2026, 3, 1, tzinfo=UTC)
    assert next_frequency_run("monthly", due, later) == datetime(
        2026, 3, 31, 6, 0, tzinfo=UTC
    )


def test_an_unknown_frequency_is_refused():
    with pytest.raises(InvalidSchedule):
        next_frequency_run("hourly", NOW, NOW)


# --- the dispatcher is scheduled and routed ----------------------------------


def test_the_dispatcher_runs_every_minute():
    entry = build_beat_schedule({})["core.dispatch_due_schedules"]
    assert entry["task"] == "apps.core.tasks.dispatch_due_schedules"
    assert entry["schedule"] == timedelta(seconds=60)
    assert entry["options"] == {"expire_seconds": 60}
    assert entry["enabled"] is True
    override = build_beat_schedule({"GUARDIAN_SCHEDULE_USER_SCHEDULES": "15"})
    assert override["core.dispatch_due_schedules"]["schedule"] == timedelta(seconds=15)


def test_the_dispatcher_and_its_work_have_queues():
    app.loader.import_default_modules()
    assert "apps.core.tasks.dispatch_due_schedules" in TASK_QUEUES["default"]
    assert "apps.assets.tasks.execute_discovery_rule" in TASK_QUEUES["scanning"]
    assert "apps.reporting.tasks.generate_report" in TASK_QUEUES["reporting"]


# --- discovery rules ---------------------------------------------------------


def _rule(schedule="*/5 * * * *", **fields):
    from apps.assets.models import AssetDiscoveryRule

    fields.setdefault("name", f"rule-{uuid.uuid4().hex[:8]}")
    fields.setdefault("discovery_type", "network_scan")
    fields.setdefault("target_specification", {"networks": ["192.0.2.0/30"]})
    fields.setdefault("team_id", TEAM_ID)
    return AssetDiscoveryRule.objects.create(schedule=schedule, **fields)


def _set(instance, **values):
    type(instance).objects.filter(pk=instance.pk).update(**values)
    instance.refresh_from_db()
    return instance


@pytest.fixture
def discovery_task():
    with mock.patch("apps.assets.tasks.execute_discovery_rule") as task:
        yield task


@pytest.mark.django_db
def test_a_new_rule_is_scheduled_not_run(discovery_task):
    before = timezone.now()
    rule = _rule("*/5 * * * *")
    assert rule.next_run == next_cron_run("*/5 * * * *", before)
    dispatch.dispatch_discovery_rules(timezone.now())
    discovery_task.delay.assert_not_called()


@pytest.mark.django_db
def test_a_due_rule_is_dispatched_once(discovery_task):
    rule = _set(_rule(), next_run=NOW - timedelta(minutes=1))

    outcome = dispatch.dispatch_discovery_rules(NOW)

    discovery_task.delay.assert_called_once_with(rule.pk)
    assert outcome["dispatched"] == [rule.pk]
    rule.refresh_from_db()
    assert rule.last_run == NOW
    assert rule.next_run == datetime(2026, 10, 2, 17, 35, tzinfo=UTC)

    # The next sweep in the same minute finds nothing due.
    dispatch.dispatch_discovery_rules(NOW + timedelta(seconds=30))
    discovery_task.delay.assert_called_once()


@pytest.mark.django_db
def test_a_rule_not_yet_due_is_left_alone(discovery_task):
    rule = _set(_rule(), next_run=NOW + timedelta(seconds=1))
    dispatch.dispatch_discovery_rules(NOW)
    discovery_task.delay.assert_not_called()
    rule.refresh_from_db()
    assert rule.last_run is None


@pytest.mark.django_db
def test_a_disabled_rule_is_not_run(discovery_task):
    rule = _rule()
    _set(rule, enabled=False, next_run=NOW - timedelta(hours=1))
    dispatch.dispatch_discovery_rules(NOW)
    discovery_task.delay.assert_not_called()


@pytest.mark.django_db
def test_a_rule_of_an_unimplemented_type_is_not_run(discovery_task):
    # Refused by the API; a row from before that check is left alone.
    rule = _rule()
    _set(rule, discovery_type="cloud_api", next_run=NOW - timedelta(hours=1))
    dispatch.dispatch_discovery_rules(NOW)
    discovery_task.delay.assert_not_called()


@pytest.mark.django_db
def test_a_rule_with_a_bad_schedule_is_reported_and_skipped(discovery_task):
    broken = _set(_rule(), schedule="61 * * * *", next_run=NOW - timedelta(hours=1))
    good = _set(_rule(), next_run=NOW - timedelta(hours=1))

    outcome = dispatch.dispatch_discovery_rules(NOW)

    assert outcome["invalid"] == [broken.pk]
    discovery_task.delay.assert_called_once_with(good.pk)
    broken.refresh_from_db()
    assert broken.last_run is None


@pytest.mark.django_db
def test_a_rule_without_next_run_gets_one(discovery_task):
    rule = _set(_rule("0 3 * * *"), next_run=None)
    outcome = dispatch.dispatch_discovery_rules(NOW)
    assert outcome["scheduled"] == 1
    discovery_task.delay.assert_not_called()
    rule.refresh_from_db()
    assert rule.next_run == datetime(2026, 10, 3, 3, 0, tzinfo=UTC)


@pytest.mark.django_db
def test_two_racing_sweeps_dispatch_a_rule_once(discovery_task):
    """The second sweep read the row before the first claimed it.

    The other sweep runs between this one's read and its claim, the widest
    window there is. A claim that is not conditional on the next_run that
    was read would queue the rule twice.
    """
    rule = _set(_rule(), next_run=NOW - timedelta(minutes=1))
    real_next_cron_run = dispatch.next_cron_run
    raced = []

    def other_sweep_first(expression, after):
        if not raced:
            raced.append(True)
            dispatch.dispatch_discovery_rules(after)
        return real_next_cron_run(expression, after)

    with mock.patch.object(dispatch, "next_cron_run", other_sweep_first):
        outcome = dispatch.dispatch_discovery_rules(NOW)

    assert raced
    assert outcome["dispatched"] == []
    discovery_task.delay.assert_called_once_with(rule.pk)


@pytest.mark.django_db
def test_a_failed_enqueue_gives_the_run_back(discovery_task):
    due = NOW - timedelta(minutes=1)
    rule = _set(_rule(), next_run=due)
    discovery_task.delay.side_effect = ConnectionError("broker down")

    with pytest.raises(ConnectionError):
        dispatch.dispatch_discovery_rules(NOW)

    rule.refresh_from_db()
    assert rule.next_run == due
    assert rule.last_run is None
    discovery_task.delay.side_effect = None
    dispatch.dispatch_discovery_rules(NOW + timedelta(seconds=60))
    assert discovery_task.delay.call_count == 2


@pytest.mark.django_db
def test_an_edit_does_not_write_back_a_stale_next_run():
    rule = _rule()
    stale = type(rule).objects.get(pk=rule.pk)
    moved_on = NOW + timedelta(days=1)
    _set(rule, next_run=moved_on, last_run=NOW)

    stale.description = "edited"
    stale.save()

    rule.refresh_from_db()
    assert rule.description == "edited"
    assert rule.next_run == moved_on
    assert rule.last_run == NOW


@pytest.mark.django_db
def test_changing_the_schedule_or_enabling_reschedules():
    rule = _set(_rule(), next_run=NOW - timedelta(days=7), enabled=False)
    rule.enabled = True
    rule.save()
    assert rule.next_run > timezone.now()

    rule.schedule = "0 3 * * *"
    rule.save()
    assert rule.next_run == next_cron_run("0 3 * * *", timezone.now())


@pytest.mark.django_db
def test_execute_records_its_own_last_run():
    from apps.assets.tasks import execute_discovery_rule

    rule = _rule()
    with mock.patch("apps.assets.tasks.discover_assets") as discover:
        result = execute_discovery_rule.apply(args=(rule.pk,)).get()
    assert result["status"] == "completed"
    # The hosts it finds are the rule's team's assets (#642).
    discover.delay.assert_called_once_with("192.0.2.0/30", "basic", team_id=TEAM_ID)
    next_run = rule.next_run
    rule.refresh_from_db()
    assert rule.last_run is not None
    assert rule.next_run == next_run


@pytest.mark.django_db
def test_execute_does_not_claim_an_unimplemented_type_ran():
    from apps.assets.tasks import execute_discovery_rule

    rule = _set(_rule(), discovery_type="dns_zone")
    result = execute_discovery_rule.apply(args=(rule.pk,)).get()
    assert result == {"status": "skipped", "reason": "not_implemented"}


# --- host discovery ----------------------------------------------------------


def _closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_a_host_that_refuses_the_connection_is_up(monkeypatch):
    # There was no ping binary in the image: every probe raised and a
    # network scan found nothing.
    from apps.assets import tasks

    monkeypatch.setattr(tasks, "HOST_PROBE_PORTS", (_closed_port(),))
    assert tasks._host_is_up("127.0.0.1") is True


def test_a_host_that_accepts_the_connection_is_up(monkeypatch):
    from apps.assets import tasks

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        monkeypatch.setattr(tasks, "HOST_PROBE_PORTS", (listener.getsockname()[1],))
        assert tasks._host_is_up("127.0.0.1") is True


@pytest.mark.parametrize("error", [errno.ETIMEDOUT, errno.EHOSTUNREACH])
def test_a_silent_host_is_down(monkeypatch, error):
    from apps.assets import tasks

    fake = mock.MagicMock()
    fake.__enter__.return_value.connect_ex.return_value = error
    monkeypatch.setattr(tasks.socket, "socket", mock.Mock(return_value=fake))
    assert tasks._host_is_up("192.0.2.1") is False
    assert fake.__enter__.return_value.connect_ex.call_count == len(
        tasks.HOST_PROBE_PORTS
    )


def test_an_invalid_address_is_down():
    from apps.assets import tasks

    assert tasks._host_is_up("not-an-ip") is False


@pytest.mark.django_db
def test_a_network_scan_records_a_host_that_is_up(monkeypatch):
    from apps.assets import tasks
    from apps.assets.models import Asset

    monkeypatch.setattr(tasks, "HOST_PROBE_PORTS", (_closed_port(),))
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        result = tasks.discover_assets.apply(args=("127.0.0.1/32",)).get()
    assert result["discovered_count"] == 1
    asset = Asset.objects.get(ip_address="127.0.0.1")
    assert asset.discovered_by == "guardian_network_discovery"


# --- report schedules --------------------------------------------------------


def _template(report_type="vulnerability_summary"):
    from apps.reporting.models import ReportTemplate

    return ReportTemplate.objects.create(
        team_id=TEAM_ID,
        name=f"template-{uuid.uuid4().hex[:8]}",
        report_type=report_type,
        template_content="unused",
    )


def _schedule(frequency="daily", next_run=None, **fields):
    from apps.reporting.models import ReportSchedule

    fields.setdefault("template", _template())
    fields.setdefault("format", "json")
    return ReportSchedule.objects.create(
        name=f"schedule-{uuid.uuid4().hex[:8]}",
        frequency=frequency,
        next_run=next_run or NOW - timedelta(minutes=1),
        **fields,
    )


@pytest.fixture
def report_task():
    with mock.patch("apps.reporting.tasks.generate_report") as task:
        yield task


@pytest.mark.django_db
def test_a_due_report_schedule_queues_a_report(report_task):
    from apps.reporting.models import Report

    schedule = _schedule("daily", parameters={"p": 1}, filters={"severity": ["high"]})
    due = schedule.next_run

    outcome = dispatch.dispatch_report_schedules(NOW)

    report = Report.objects.get(schedule=schedule)
    report_task.delay.assert_called_once_with(report.pk)
    assert outcome["dispatched"] == [str(schedule.pk)]
    assert report.template_id == schedule.template_id
    assert report.format == "json"
    assert report.parameters == {"p": 1}
    assert report.filters == {"severity": ["high"]}
    schedule.refresh_from_db()
    assert schedule.last_run == NOW
    assert schedule.next_run == due + timedelta(days=1)
    assert schedule.status == "active"

    dispatch.dispatch_report_schedules(NOW + timedelta(seconds=30))
    report_task.delay.assert_called_once()


@pytest.mark.django_db
def test_a_one_off_schedule_runs_once_and_is_disabled(report_task):
    schedule = _schedule("once")
    dispatch.dispatch_report_schedules(NOW)
    dispatch.dispatch_report_schedules(NOW + timedelta(days=1))
    report_task.delay.assert_called_once()
    schedule.refresh_from_db()
    assert schedule.status == "disabled"


@pytest.mark.django_db
@pytest.mark.parametrize("status", ["paused", "disabled"])
def test_an_inactive_report_schedule_is_not_run(report_task, status):
    _schedule(status=status)
    dispatch.dispatch_report_schedules(NOW)
    report_task.delay.assert_not_called()


@pytest.mark.django_db
def test_a_report_schedule_not_yet_due_is_left_alone(report_task):
    _schedule(next_run=NOW + timedelta(seconds=1))
    dispatch.dispatch_report_schedules(NOW)
    report_task.delay.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "report_type,report_format",
    [("risk_assessment", "json"), ("custom", "html"), ("asset_inventory", "pdf")],
)
def test_an_unsupported_report_schedule_is_reported_not_run(
    report_task, report_type, report_format
):
    schedule = _schedule(template=_template(report_type), format=report_format)
    outcome = dispatch.dispatch_report_schedules(NOW)
    assert outcome == {"dispatched": [], "invalid": [str(schedule.pk)]}
    report_task.delay.assert_not_called()


@pytest.mark.django_db
def test_two_racing_sweeps_dispatch_a_report_schedule_once(report_task):
    from apps.reporting.models import Report

    schedule = _schedule("weekly")
    real_next_frequency_run = dispatch.next_frequency_run
    raced = []

    def other_sweep_first(frequency, due, now):
        if not raced:
            raced.append(True)
            dispatch.dispatch_report_schedules(now)
        return real_next_frequency_run(frequency, due, now)

    with mock.patch.object(dispatch, "next_frequency_run", other_sweep_first):
        outcome = dispatch.dispatch_report_schedules(NOW)

    assert raced
    assert outcome["dispatched"] == []
    report_task.delay.assert_called_once()
    assert Report.objects.filter(schedule=schedule).count() == 1


@pytest.mark.django_db
def test_a_failed_report_enqueue_gives_the_run_back(report_task):
    from apps.reporting.models import Report

    schedule = _schedule("once")
    due = schedule.next_run
    report_task.delay.side_effect = ConnectionError("broker down")

    with pytest.raises(ConnectionError):
        dispatch.dispatch_report_schedules(NOW)

    schedule.refresh_from_db()
    assert (schedule.status, schedule.next_run, schedule.last_run) == (
        "active",
        due,
        None,
    )
    assert not Report.objects.filter(schedule=schedule).exists()


@pytest.mark.django_db
def test_reactivating_a_schedule_skips_the_runs_it_missed():
    schedule = _schedule("daily", next_run=timezone.now() - timedelta(days=3))
    _set(schedule, status="paused")
    schedule.status = "active"
    schedule.save()
    assert timezone.now() < schedule.next_run <= timezone.now() + timedelta(days=1)


# --- the sweep ---------------------------------------------------------------


@pytest.mark.django_db
def test_the_sweep_dispatches_both_kinds(locmem_cache, discovery_task, report_task):
    rule = _set(_rule(), next_run=timezone.now() - timedelta(minutes=1))
    schedule = _schedule("once", next_run=timezone.now() - timedelta(minutes=1))

    result = dispatch.dispatch_due_schedules.apply()

    assert result.successful(), result.traceback
    assert result.get()["discovery_rules"]["dispatched"] == [rule.pk]
    assert result.get()["report_schedules"]["dispatched"] == [str(schedule.pk)]


@pytest.mark.django_db
def test_one_kind_failing_does_not_stop_the_other(
    locmem_cache, discovery_task, report_task
):
    _set(_rule(), next_run=timezone.now() - timedelta(minutes=1))
    schedule = _schedule("once", next_run=timezone.now() - timedelta(minutes=1))
    discovery_task.delay.side_effect = ConnectionError("broker down")

    result = dispatch.dispatch_due_schedules.apply()

    assert result.failed()
    report_task.delay.assert_called_once()
    schedule.refresh_from_db()
    assert schedule.status == "disabled"


@pytest.mark.django_db
def test_a_sweep_already_running_skips_the_second(
    locmem_cache, discovery_task, report_task
):
    from django.core.cache import cache

    _set(_rule(), next_run=timezone.now() - timedelta(minutes=1))
    key = f"{LOCK_PREFIX}apps.core.tasks.dispatch_due_schedules"
    assert cache.add(key, "another-run", timeout=60)

    assert dispatch.dispatch_due_schedules.apply().get() == {
        "skipped": "already running"
    }
    discovery_task.delay.assert_not_called()


# --- the work behind a report schedule ---------------------------------------


@pytest.fixture
def media_root(settings, tmp_path, locmem_cache):
    settings.MEDIA_ROOT = str(tmp_path)
    return tmp_path


def _vulnerability(title="exposed service"):
    from apps.assets.models import Asset
    from apps.vulnerabilities.models import Vulnerability

    with mock.patch("apps.assets.signals.scan_asset_ports"):
        asset = Asset.objects.create(name="host", status="active", team_id=TEAM_ID)
        return Vulnerability.objects.create(
            title=title, description="d", asset=asset, severity="critical"
        )


def _generate(report_type, report_format, schedule=None):
    from apps.reporting.models import Report
    from apps.reporting.tasks import generate_report

    report = Report.objects.create(
        name="r",
        template=_template(report_type),
        schedule=schedule,
        format=report_format,
    )
    with mock.patch("apps.reporting.tasks.update_report_metrics"):
        result = generate_report.apply(args=(report.pk,))
    assert result.successful(), result.traceback
    report.refresh_from_db()
    return report


@pytest.mark.django_db
@pytest.mark.parametrize(
    "report_type",
    [
        "vulnerability_summary",
        "asset_inventory",
        "compliance_status",
        "executive_dashboard",
    ],
)
@pytest.mark.parametrize("report_format", ["json", "html"])
def test_every_schedulable_report_is_generated(media_root, report_type, report_format):
    # Every report failed before #548: no template existed for any type, a
    # completed report's post_save signal read a field Report does not have,
    # and the asset statistics filtered on one Asset does not have.
    _vulnerability()
    report = _generate(report_type, report_format)
    assert report.status == "completed", report.error_message
    assert report.file_size > 0
    assert report.file_path.endswith(f".{report_format}")


@pytest.mark.django_db
def test_a_json_report_holds_the_rows(media_root):
    vulnerability = _vulnerability("exposed service")
    report = _generate("vulnerability_summary", "json")
    with open(report.file_path) as handle:
        body = json.load(handle)
    assert [row["title"] for row in body["vulnerabilities"]] == ["exposed service"]
    assert body["vulnerabilities"][0]["id"] == str(vulnerability.id)
    assert body["vulnerability_stats"]["critical_count"] == 1


@pytest.mark.django_db
def test_an_html_report_is_a_table_and_escaped(media_root):
    _vulnerability("<script>alert(1)</script>")
    report = _generate("vulnerability_summary", "html")
    with open(report.file_path) as handle:
        body = handle.read()
    assert "<table>" in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "<script>" not in body


@pytest.mark.django_db
def test_a_scheduled_report_is_sent_to_its_recipients(media_root, mailoutbox):
    schedule = _schedule("weekly", recipients=["ciso@example.com"])
    report = _generate("vulnerability_summary", "json", schedule=schedule)
    assert report.status == "completed", report.error_message
    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == ["ciso@example.com"]
    assert str(report.pk) in mailoutbox[0].body


@pytest.mark.django_db
@pytest.mark.parametrize(
    "report_type,report_format,reason",
    [
        ("risk_assessment", "json", "no data behind them"),
        ("custom", "html", "no data behind them"),
        ("vulnerability_summary", "pdf", "pdf reports are not generated yet"),
        ("vulnerability_summary", "csv", "csv reports are not generated yet"),
    ],
)
def test_a_report_guardian_cannot_generate_fails_with_the_reason(
    media_root, report_type, report_format, reason
):
    # Not "completed" with a placeholder score, no data, or HTML in a .pdf.
    report = _generate(report_type, report_format)
    assert report.status == "failed"
    assert reason in report.error_message


# --- the API refuses what could not run --------------------------------------

RULES = "/api/v1/assets/discovery-rules/"
SCHEDULES = "/api/v1/reports/schedules/"
SCAN_SCHEDULES = "/api/v1/scanners/scan-schedules/"


def _post(client, url, payload):
    return client.post(
        url, data=payload, content_type="application/json", secure=True, **_headers()
    )


def _patch(client, url, payload):
    return client.patch(
        url, data=payload, content_type="application/json", secure=True, **_headers()
    )


def _rule_payload(**fields):
    payload = {
        "name": f"rule-{uuid.uuid4().hex[:8]}",
        "discovery_type": "network_scan",
        "target_specification": {"networks": ["192.0.2.0/30"]},
        "schedule": "*/10 * * * *",
    }
    payload.update(fields)
    return payload


@pytest.mark.django_db
def test_a_discovery_rule_is_created_with_its_next_run(client):
    before = timezone.now()
    response = _post(client, RULES, _rule_payload())
    assert response.status_code == 201, response.content[:500]
    body = response.json()
    assert body["last_run"] is None
    next_run = datetime.fromisoformat(body["next_run"].replace("Z", "+00:00"))
    assert next_run == next_cron_run("*/10 * * * *", before)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "fields,field",
    [
        ({"schedule": "every day"}, "schedule"),
        ({"schedule": "61 * * * *"}, "schedule"),
        ({"schedule": "0 0 31 2 *"}, "schedule"),
        (
            {
                "discovery_type": "cloud_api",
                "target_specification": {"provider": "aws"},
            },
            "discovery_type",
        ),
        ({"discovery_type": "dns_zone"}, "discovery_type"),
        (
            {"target_specification": {"networks": ["10.0.0.0/33"]}},
            "target_specification",
        ),
        ({"target_specification": {"networks": "10.0.0.0/8"}}, "target_specification"),
    ],
)
def test_a_discovery_rule_that_could_not_run_is_refused(client, fields, field):
    response = _post(client, RULES, _rule_payload(**fields))
    assert response.status_code == 400, response.content[:500]
    assert field in response.json(), response.json()


@pytest.mark.django_db
def test_changing_a_rule_schedule_through_the_api_reschedules_it(client):
    rule = _rule()
    response = _patch(client, f"{RULES}{rule.pk}/", {"schedule": "0 3 * * *"})
    assert response.status_code == 200, response.content[:500]
    rule.refresh_from_db()
    assert rule.next_run == next_cron_run("0 3 * * *", timezone.now())


def _schedule_payload(template, **fields):
    payload = {
        "name": f"schedule-{uuid.uuid4().hex[:8]}",
        "template": str(template.pk),
        "frequency": "daily",
        "format": "json",
        "next_run": (timezone.now() + timedelta(hours=1)).isoformat(),
        "recipients": ["ciso@example.com"],
    }
    payload.update(fields)
    return payload


@pytest.mark.django_db
def test_a_report_schedule_is_created(client):
    response = _post(client, SCHEDULES, _schedule_payload(_template()))
    assert response.status_code == 201, response.content[:500]
    assert response.json()["status"] == "active"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "report_type,fields,field",
    [
        ("risk_assessment", {}, "template"),
        ("trend_analysis", {}, "template"),
        ("vulnerability_summary", {"format": "pdf"}, "format"),
        ("vulnerability_summary", {"format": "xlsx"}, "format"),
        ("vulnerability_summary", {"format": "csv"}, "format"),
        ("vulnerability_summary", {"recipients": ["not an address"]}, "recipients"),
        ("vulnerability_summary", {"recipients": "ciso@example.com"}, "recipients"),
    ],
)
def test_a_report_schedule_that_could_not_run_is_refused(
    client, report_type, fields, field
):
    payload = _schedule_payload(_template(report_type), **fields)
    response = _post(client, SCHEDULES, payload)
    assert response.status_code == 400, response.content[:500]
    assert field in response.json(), response.json()


@pytest.mark.django_db
def test_a_report_schedule_can_be_paused_and_resumed(client):
    # Editing a schedule raised AttributeError ('tracker') in a post_save
    # signal: every PATCH answered 500.
    schedule = _schedule("daily", next_run=timezone.now() - timedelta(days=2))
    url = f"{SCHEDULES}{schedule.pk}/"
    assert _patch(client, url, {"status": "paused"}).status_code == 200
    response = _patch(client, url, {"status": "active"})
    assert response.status_code == 200, response.content[:500]
    schedule.refresh_from_db()
    assert schedule.next_run > timezone.now()


@pytest.fixture
def scan_schedule():
    from apps.scanners.models import Scanner, ScanProfile, ScanSchedule

    scanner = Scanner.objects.create(
        team_id=TEAM_ID,
        name="nessus",
        scanner_type="nessus",
        base_url="https://nessus.invalid",
    )
    profile = ScanProfile.objects.create(name="full", scanner=scanner)
    return ScanSchedule.objects.create(
        name="nightly", scanner=scanner, profile=profile, cron_expression="0 2 * * *"
    )


# The routes below answered 400 "Scheduled scans are not supported" (#548).
# They could answer nothing else, and were removed (#724): the method or the
# path is not there, which is what the answer says now.


@pytest.mark.django_db
def test_scan_schedules_cannot_be_created(client, scan_schedule):
    payload = {
        "name": "weekly",
        "scanner": str(scan_schedule.scanner_id),
        "profile": str(scan_schedule.profile_id),
        "cron_expression": "0 2 * * 0",
    }
    response = _post(client, SCAN_SCHEDULES, payload)
    assert response.status_code == 405, response.content[:500]
    assert response["Allow"] == "GET, HEAD, OPTIONS"
    assert type(scan_schedule).objects.count() == 1


@pytest.mark.django_db
@pytest.mark.parametrize("action", ["trigger", "enable"])
def test_scan_schedules_cannot_be_run_or_enabled(client, scan_schedule, action):
    _set(scan_schedule, is_active=False)
    url = f"{SCAN_SCHEDULES}{scan_schedule.pk}/{action}/"
    for method in (client.post, client.get):
        assert method(url, secure=True, **_headers()).status_code == 404
    scan_schedule.refresh_from_db()
    assert scan_schedule.is_active is False


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["patch", "put"])
def test_scan_schedules_cannot_be_changed(client, scan_schedule, method):
    url = f"{SCAN_SCHEDULES}{scan_schedule.pk}/"
    response = getattr(client, method)(
        url,
        data={"cron_expression": "* * * * *", "is_active": True},
        content_type="application/json",
        secure=True,
        **_headers(),
    )
    assert response.status_code == 405, response.content[:500]
    assert response["Allow"] == "GET, DELETE, HEAD, OPTIONS"
    scan_schedule.refresh_from_db()
    assert scan_schedule.cron_expression == "0 2 * * *"


def test_the_scan_schedule_routes_are_the_ones_that_do_something():
    from django.urls import get_resolver

    routes = {}

    def walk(patterns, prefix=""):
        for entry in patterns:
            path = prefix + str(entry.pattern).lstrip("^").rstrip("$")
            if hasattr(entry, "url_patterns"):
                walk(entry.url_patterns, path)
            elif "scan-schedules" in path and "format" not in path:
                routes[path.split("scan-schedules/", 1)[1]] = {
                    method: action
                    for method, action in entry.callback.actions.items()
                    if method != "head"
                }

    walk(get_resolver().url_patterns)

    assert routes == {
        "": {"get": "list"},
        "(?P<pk>[^/.]+)/": {"get": "retrieve", "delete": "destroy"},
        "(?P<pk>[^/.]+)/disable/": {"post": "disable"},
    }


@pytest.mark.django_db
def test_existing_scan_schedules_can_be_listed_disabled_and_deleted(
    client, scan_schedule
):
    listing = client.get(SCAN_SCHEDULES, secure=True, **_headers())
    assert listing.status_code == 200
    assert [row["name"] for row in listing.json()["results"]] == ["nightly"]
    url = f"{SCAN_SCHEDULES}{scan_schedule.pk}/"
    assert client.get(url, secure=True, **_headers()).json()["is_active"] is True
    assert client.post(f"{url}disable/", secure=True, **_headers()).status_code == 200
    scan_schedule.refresh_from_db()
    assert scan_schedule.is_active is False
    assert client.delete(url, secure=True, **_headers()).status_code == 204
    assert type(scan_schedule).objects.count() == 0
