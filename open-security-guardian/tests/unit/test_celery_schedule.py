"""guardian's periodic schedule (#545).

guardian configured django-celery-beat's DatabaseScheduler and wrote tasks
meant to run on a timer, but scheduled none of them. These tests cover the
schedule in guardian/schedule.py, its environment overrides, how
DatabaseScheduler turns it into PeriodicTask rows, the heartbeat that
guardian-beat's health check reads, the lock that keeps the sweeps from
overlapping, and that each scheduled task actually runs.
"""

import os
from datetime import timedelta
from unittest import mock

import pytest
from apps.core.locks import LOCK_PREFIX
from celery.schedules import crontab
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django_celery_beat.models import PeriodicTask
from django_celery_beat.schedulers import DatabaseScheduler
from guardian import beat
from guardian.celery import TASK_QUEUES, app
from guardian.schedule import (
    CRONTAB_EXPIRY_SECONDS,
    PERIODIC_TASKS,
    build_beat_schedule,
    parse_schedule,
)

ENTRY_NAMES = [entry[0] for entry in PERIODIC_TASKS]
TASK_NAMES = [entry[1] for entry in PERIODIC_TASKS]


@pytest.fixture
def locmem_cache(settings):
    # The lock and the throttles use the default cache, Redis outside tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


@pytest.fixture
def beat_schedule(monkeypatch):
    """Swap the schedule guardian-beat reads, for one test.

    The Django-namespaced key is the one app.conf.beat_schedule resolves to.
    """

    def use(schedule):
        monkeypatch.setitem(app.conf, "CELERY_BEAT_SCHEDULE", schedule)

    return use


_schedulers = []


@pytest.fixture(autouse=True)
def _no_sync_at_exit():
    # Each scheduler registers a sync() to run at interpreter exit, when the
    # test database is gone; drop it once the test is over.
    yield
    while _schedulers:
        _schedulers.pop()._finalize.cancel()


def _scheduler(lazy=False):
    # lazy=False: runs setup_schedule(), which is what guardian-beat does at
    # start-up, writing CELERY_BEAT_SCHEDULE into PeriodicTask rows.
    scheduler = beat.HeartbeatDatabaseScheduler(app=app, lazy=lazy)
    _schedulers.append(scheduler)
    return scheduler


# --- the schedule itself ------------------------------------------------------


def test_settings_load_the_schedule():
    assert django_settings.CELERY_BEAT_SCHEDULE == build_beat_schedule()
    assert app.conf.beat_scheduler == "guardian.beat:HeartbeatDatabaseScheduler"
    assert issubclass(beat.HeartbeatDatabaseScheduler, DatabaseScheduler)


def test_every_scheduled_task_exists_and_has_a_queue():
    app.loader.import_default_modules()
    routed = {name for names in TASK_QUEUES.values() for name in names}
    for task in TASK_NAMES:
        assert task in app.tasks, task
        assert task in routed, task
    assert len(set(ENTRY_NAMES)) == len(ENTRY_NAMES)
    assert len(set(TASK_NAMES)) == len(TASK_NAMES)


def test_every_periodic_task_has_its_own_variable():
    variables = [entry[2] for entry in PERIODIC_TASKS]
    assert len(set(variables)) == len(variables)
    assert all(v.startswith("GUARDIAN_SCHEDULE_") for v in variables)


def test_defaults():
    schedule = build_beat_schedule({})
    assert set(schedule) == set(ENTRY_NAMES)
    for name, task, variable, default in PERIODIC_TASKS:
        entry = schedule[name]
        assert entry["task"] == task
        assert entry["enabled"] is True
        assert variable in entry["description"]
        expected, expire = parse_schedule(default, variable)
        assert entry["schedule"] == expected
        assert entry["options"] == {"expire_seconds": expire}
    sla = schedule["vulnerabilities.check_sla_violations"]
    assert sla["schedule"] == timedelta(minutes=15)
    assert sla["options"]["expire_seconds"] == 900
    cleanup = schedule["reporting.cleanup_expired_reports"]
    assert cleanup["schedule"] == crontab(minute="0", hour="3")
    assert cleanup["options"]["expire_seconds"] == CRONTAB_EXPIRY_SECONDS


def test_an_interval_override():
    schedule = build_beat_schedule({"GUARDIAN_SCHEDULE_ALERT_RULES": "15"})
    entry = schedule["reporting.check_all_alert_rules"]
    assert entry["schedule"] == timedelta(seconds=15)
    # The run expires when the next one is due, so they cannot pile up.
    assert entry["options"] == {"expire_seconds": 15}
    assert entry["enabled"] is True


def test_a_crontab_override():
    schedule = build_beat_schedule({"GUARDIAN_SCHEDULE_SLA_CHECK": "*/5 8-18 * * 1-5"})
    entry = schedule["vulnerabilities.check_sla_violations"]
    assert entry["schedule"] == crontab(minute="*/5", hour="8-18", day_of_week="1-5")
    assert entry["options"] == {"expire_seconds": CRONTAB_EXPIRY_SECONDS}


def test_an_empty_variable_means_the_default():
    assert build_beat_schedule({"GUARDIAN_SCHEDULE_SLA_CHECK": ""}) == (
        build_beat_schedule({})
    )


@pytest.mark.parametrize("value", ["off", "OFF", " off "])
def test_off_disables_the_entry_but_keeps_it(value):
    schedule = build_beat_schedule({"GUARDIAN_SCHEDULE_RISK_SCORES": value})
    entry = schedule["vulnerabilities.update_vulnerability_risk_scores"]
    # Kept, so that DatabaseScheduler updates the existing row to disabled:
    # an entry dropped from the mapping would leave the old row running.
    assert entry["enabled"] is False
    assert entry["schedule"] == crontab(minute="0", hour="2")


@pytest.mark.parametrize(
    "value", ["0", "-5", "1.5", "every hour", "0 3 * *", "61 * * * *", "0 25 * * *"]
)
def test_an_invalid_value_stops_start_up(value):
    with pytest.raises(ImproperlyConfigured, match="GUARDIAN_SCHEDULE_SLA_CHECK"):
        build_beat_schedule({"GUARDIAN_SCHEDULE_SLA_CHECK": value})


# --- DatabaseScheduler ---------------------------------------------------------


@pytest.mark.django_db
def test_database_scheduler_writes_every_entry(beat_schedule):
    beat_schedule(build_beat_schedule({}))
    scheduler = _scheduler()

    for name, task, variable, default in PERIODIC_TASKS:
        row = PeriodicTask.objects.get(name=name)
        assert row.task == task
        assert row.enabled is True
        assert row.queue is None  # routed by name, see guardian/celery.py
        expected, expire = parse_schedule(default, variable)
        assert row.expire_seconds == expire
        if isinstance(expected, timedelta):
            assert row.interval.every == expected.total_seconds()
            assert row.interval.period == "seconds"
            assert row.crontab is None
        else:
            assert row.interval is None
            assert row.crontab.minute == default.split()[0]
            assert row.crontab.hour == default.split()[1]
            assert row.crontab.day_of_week == default.split()[4]
        # What beat will send: the task, with the expiry as an option.
        entry = scheduler.schedule[name]
        assert entry.task == task
        assert entry.options["expires"] == expire


@pytest.mark.django_db
def test_a_restart_applies_a_changed_interval(beat_schedule):
    beat_schedule(build_beat_schedule({}))
    _scheduler()
    beat_schedule(build_beat_schedule({"GUARDIAN_SCHEDULE_ALERT_RULES": "15"}))
    _scheduler()

    rows = PeriodicTask.objects.filter(name="reporting.check_all_alert_rules")
    assert rows.count() == 1
    assert rows.get().interval.every == 15
    assert rows.get().expire_seconds == 15


@pytest.mark.django_db
def test_a_restart_with_off_disables_the_existing_row(beat_schedule):
    beat_schedule(build_beat_schedule({}))
    _scheduler()
    beat_schedule(build_beat_schedule({"GUARDIAN_SCHEDULE_SLA_CHECK": "off"}))
    scheduler = _scheduler()

    row = PeriodicTask.objects.get(name="vulnerabilities.check_sla_violations")
    assert row.enabled is False
    assert "vulnerabilities.check_sla_violations" not in scheduler.schedule

    beat_schedule(build_beat_schedule({}))
    assert "vulnerabilities.check_sla_violations" in _scheduler().schedule


# --- heartbeat -----------------------------------------------------------------


def test_each_tick_refreshes_the_heartbeat(tmp_path, monkeypatch):
    heartbeat = tmp_path / "heartbeat"
    monkeypatch.setattr(beat, "HEARTBEAT_FILE", str(heartbeat))
    monkeypatch.setattr(DatabaseScheduler, "tick", lambda self, *a, **k: 4.5)
    scheduler = _scheduler(lazy=True)

    assert scheduler.tick() == 4.5
    assert heartbeat.exists()
    os.utime(heartbeat, (0, 0))
    scheduler.tick()
    assert heartbeat.stat().st_mtime > 0


def test_a_failed_tick_does_not_refresh_the_heartbeat(tmp_path, monkeypatch):
    heartbeat = tmp_path / "heartbeat"
    monkeypatch.setattr(beat, "HEARTBEAT_FILE", str(heartbeat))

    def broken(self, *args, **kwargs):
        raise RuntimeError("scheduler loop failed")

    monkeypatch.setattr(DatabaseScheduler, "tick", broken)
    scheduler = _scheduler(lazy=True)
    with pytest.raises(RuntimeError):
        scheduler.tick()
    assert not heartbeat.exists()


# --- the tasks run ---------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("task_name", TASK_NAMES)
def test_each_scheduled_task_runs(task_name, locmem_cache):
    # Run as the worker would, on an empty database: a task that raised here
    # would fail on every scheduled run.
    app.loader.import_default_modules()
    result = app.tasks[task_name].apply()
    assert result.successful(), result.traceback


def _alert_rule():
    from apps.reporting.models import AlertRule

    # Without the test-mode check its creation queues (signals.py).
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        return AlertRule.objects.create(
            name="always fires",
            data_source="vulnerabilities",
            condition_type="threshold",
            operator="eq",
            threshold_value=0,
        )


@pytest.mark.django_db
def test_the_alert_rule_sweep_records_a_triggered_rule(locmem_cache):
    # The integration test relies on this: a sweep that fires a rule bumps
    # its trigger_count, which the API exposes.
    from apps.reporting.tasks import check_all_alert_rules

    rule = _alert_rule()
    check_all_alert_rules.apply()
    rule.refresh_from_db()
    assert rule.trigger_count == 1
    assert rule.last_triggered is not None


def _overdue_vulnerability():
    from apps.assets.models import Asset
    from apps.vulnerabilities.models import Vulnerability
    from django.contrib.auth.models import User
    from django.utils import timezone

    owner = User.objects.create(username="owner", email="owner@example.com")
    with mock.patch("apps.assets.signals.scan_asset_ports"), mock.patch(
        "apps.vulnerabilities.signals.enrich_vulnerability_with_threat_intel"
    ), mock.patch("apps.vulnerabilities.signals.notify_vulnerability_assignment"):
        asset = Asset.objects.create(name="host")
        return Vulnerability.objects.create(
            title="overdue",
            description="d",
            asset=asset,
            assigned_to=owner,
            due_date=timezone.now() - timedelta(hours=5),
        )


@pytest.mark.django_db
def test_the_sla_check_notifies_once_a_day(locmem_cache, mailoutbox):
    # The check queried VulnerabilityHistory.changed_at, a field that does
    # not exist (it is timestamp), and formatted settings.BASE_URL, which was
    # never defined: with anything overdue, every run raised.
    from apps.vulnerabilities.tasks import check_sla_violations

    vulnerability = _overdue_vulnerability()
    first = check_sla_violations.apply()
    assert first.successful(), first.traceback
    assert first.get() == {"notifications_sent": 1}
    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == ["owner@example.com"]
    assert f"/vulnerabilities/{vulnerability.id}/" in mailoutbox[0].body

    # Running every 15 minutes does not mean an e-mail every 15 minutes.
    second = check_sla_violations.apply()
    assert second.get() == {"notifications_sent": 0}
    assert len(mailoutbox) == 1


@pytest.mark.django_db
def test_the_history_cleanup_keeps_a_year(locmem_cache):
    from apps.vulnerabilities.models import VulnerabilityHistory
    from apps.vulnerabilities.tasks import cleanup_old_vulnerability_history
    from django.utils import timezone

    vulnerability = _overdue_vulnerability()
    old = VulnerabilityHistory.objects.create(
        vulnerability=vulnerability, field_name="status", old_value="", new_value="x"
    )
    VulnerabilityHistory.objects.filter(pk=old.pk).update(
        timestamp=timezone.now() - timedelta(days=400)
    )
    recent = VulnerabilityHistory.objects.filter(vulnerability=vulnerability).exclude(
        pk=old.pk
    )
    kept = recent.count()

    result = cleanup_old_vulnerability_history.apply()
    assert result.successful(), result.traceback
    assert result.get() == {"deleted_count": 1}
    assert not VulnerabilityHistory.objects.filter(pk=old.pk).exists()
    assert recent.count() == kept


@pytest.mark.django_db
def test_the_compliance_sweeps_notify_what_is_due(locmem_cache):
    from apps.compliance import tasks
    from apps.compliance.models import (
        ComplianceAssessment,
        ComplianceControl,
        ComplianceException,
        ComplianceFramework,
    )
    from django.utils import timezone

    now = timezone.now()
    with mock.patch("apps.compliance.signals.send_compliance_notification"), mock.patch(
        "apps.compliance.signals.calculate_compliance_metrics"
    ):
        framework = ComplianceFramework.objects.create(name="ISO27001")
        control = ComplianceControl.objects.create(
            framework=framework,
            control_id="A.5.1",
            title="c",
            control_type="preventive",
        )
        ComplianceAssessment.objects.create(
            name="late",
            framework=framework,
            assessment_type="self_assessment",
            due_date=now - timedelta(days=2),
        )
        ComplianceException.objects.create(
            control=control,
            title="waiver",
            status="approved",
            valid_from=now - timedelta(days=300),
            valid_until=now + timedelta(days=10),
        )

    with mock.patch.object(tasks.send_compliance_notification, "delay") as delay:
        assert tasks.check_overdue_assessments.apply().get() == 1
        assert tasks.check_expiring_exceptions.apply().get() == 1
    kinds = [c.args[0] for c in delay.call_args_list]
    assert kinds == ["assessment_overdue", "exception_expiring"]


# --- one run at a time -----------------------------------------------------------


@pytest.mark.django_db
def test_a_sweep_already_running_skips_the_second_run(locmem_cache):
    from apps.reporting.tasks import check_all_alert_rules
    from django.core.cache import cache

    rule = _alert_rule()
    key = f"{LOCK_PREFIX}apps.reporting.tasks.check_all_alert_rules"
    assert cache.add(key, "another-run", timeout=60)

    result = check_all_alert_rules.apply()
    assert result.get() == {"skipped": "already running"}
    rule.refresh_from_db()
    assert rule.trigger_count == 0
    # The other run's lock is not released by the skipped one.
    assert cache.get(key) == "another-run"


@pytest.mark.django_db
def test_the_lock_is_released_after_a_run_even_if_it_fails(locmem_cache, monkeypatch):
    from apps.vulnerabilities import tasks
    from django.core.cache import cache

    key = f"{LOCK_PREFIX}apps.vulnerabilities.tasks.check_sla_violations"
    tasks.check_sla_violations.apply()
    assert cache.get(key) is None

    def boom(*args, **kwargs):
        raise RuntimeError("database gone")

    monkeypatch.setattr(tasks.Vulnerability.objects, "filter", boom)
    assert tasks.check_sla_violations.apply().failed()
    assert cache.get(key) is None


def test_the_locked_tasks_keep_their_names():
    # functools.wraps keeps __module__/__name__, from which Celery derives the
    # registered name; a wrapper without it would rename the task.
    from apps.compliance import tasks as compliance
    from apps.reporting import tasks as reporting
    from apps.vulnerabilities import tasks as vulnerabilities

    assert reporting.check_all_alert_rules.name == (
        "apps.reporting.tasks.check_all_alert_rules"
    )
    assert vulnerabilities.update_vulnerability_risk_scores.name == (
        "apps.vulnerabilities.tasks.update_vulnerability_risk_scores"
    )
    assert compliance.check_expiring_exceptions.name == (
        "apps.compliance.tasks.check_expiring_exceptions"
    )
