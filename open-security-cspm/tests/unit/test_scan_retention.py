"""Scan reports outlive the Celery result backend; batch scans are recorded (#591).

The compliance pages and the cloud security overview are built from the
reports of the team's completed scans. They were read from the Celery result
backend, which keeps results for a day by default, so every scan older than
that dropped out of them while its metadata and team index entry lived on
for 30 days. Batch scans wrote no metadata, so they never counted at all.

The worker now stores each report under its scan with the retention of the
scan's metadata and team index entry (CSPM_REPORT_RETENTION_DAYS), and batch
scans go through the function single scans use. The fake Redis in
conftest.py expires keys on a clock these tests move.
"""

import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

# conftest.py does the same; repeated so the file reads on its own.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import config, main, scan_store, schemas, worker  # noqa: E402
from app.checks.framework import (  # noqa: E402
    CheckResult,
    CheckStatus,
    CloudProvider,
    ScanReport,
)
from app.credential_crypto import decrypt_credentials  # noqa: E402

DAY = 86400
TEAM_A = "team-a"
TEAM_B = "team-b"


class EmptyBackend:
    """A Celery result backend whose results have all expired."""

    def AsyncResult(self, task_id):  # noqa: N802 - Celery's name
        return type("Result", (), {"status": "PENDING", "result": None, "info": None})()


class LegacyBackend:
    """A backend that still holds every scan's report, as before #591."""

    def __init__(self):
        self.reports = {}

    def AsyncResult(self, task_id):  # noqa: N802 - Celery's name
        report = self.reports.get(task_id)
        return type(
            "Result",
            (),
            {
                "status": "SUCCESS" if report else "PENDING",
                "result": {"report": report} if report else None,
                "info": None,
            },
        )()


class QueuedTasks:
    """Stands in for run_cspm_scan_task: records what would be queued."""

    def __init__(self):
        self.calls = []

    def apply_async(self, args, task_id):
        self.calls.append((task_id, args[0]))


def _user(team_id):
    return {"user_id": f"user-of-{team_id}", "team_id": team_id}


def _request(account_id, **extra):
    return schemas.ScanRequest(
        provider="aws",
        account_id=account_id,
        credentials={
            "auth_method": "access_key",
            "access_key_id": "AKIAFAKEFAKEFAKEFAKE",
            "secret_access_key": "fake-secret-for-tests-only",
        },
        **extra,
    )


def _report(scan_id, account_id, started, results):
    """A report as the worker stores it: ScanReport.model_dump(mode="json")."""
    report = ScanReport(
        scan_id=scan_id,
        provider=CloudProvider.AWS,
        account_id=account_id,
        regions=["eu-west-1"],
        started_at=started,
        completed_at=started + timedelta(minutes=5),
        status="completed",
    )
    for check_id, resource_id, status in results:
        report.add_result(
            CheckResult(
                check_id=check_id,
                resource_id=resource_id,
                resource_type="S3 Bucket",
                region="eu-west-1",
                status=CheckStatus(status),
                message="msg",
                compliance_frameworks=["CIS"],
                timestamp=started,
            )
        )
    return report.model_dump(mode="json")


@pytest.fixture
def env(monkeypatch, fake_redis, clock):
    """The API wired to the fake Redis, an empty result backend and a fake queue."""
    monkeypatch.setattr(main, "redis_client", fake_redis)
    monkeypatch.setattr(main, "celery_app", EmptyBackend())
    queue = QueuedTasks()
    monkeypatch.setattr(main, "run_cspm_scan_task", queue)
    monkeypatch.setattr(main.check_runner, "get_available_checks", lambda: [])
    monkeypatch.setattr(config.settings, "cspm_report_retention_days", 90)
    return queue


def _scan_at(clock, team_id, account_id, days_ago, results=(("S3", "b", "failed"),)):
    """Start a scan ``days_ago`` and complete it, as the API and worker would."""
    now = clock.now
    clock.now = now - days_ago * DAY
    started = datetime.utcnow() - timedelta(days=days_ago)
    scan_id = asyncio.run(
        main.start_scan(_request(account_id), None, _user(team_id))
    ).scan_id
    # start_scan stamps the real time; put the scan back where it belongs.
    metadata = scan_store.load_metadata(main.redis_client, scan_id)
    metadata["started_at"] = started.isoformat()
    scan_store.save_metadata(main.redis_client, metadata)
    clock.now += 300
    scan_store.complete_scan(
        main.redis_client,
        scan_id,
        _report(scan_id, account_id, started, list(results)),
        (started + timedelta(minutes=5)).isoformat(),
    )
    clock.now = now
    return scan_id


def _compliance(team_id, days=365):
    return asyncio.run(
        main.get_compliance_summary(
            days=days, provider=None, current_user=_user(team_id)
        )
    )


def _dashboard(team_id, days=365):
    return asyncio.run(
        main.get_dashboard_summary(days=days, current_user=_user(team_id))
    )


# --- retention ---------------------------------------------------------------


def test_a_report_older_than_a_day_is_still_aggregated(env, clock):
    scan_id = _scan_at(clock, TEAM_A, "acct-1", days_ago=3)

    # The Celery result is long gone (EmptyBackend); the stored report is not.
    summary = _compliance(TEAM_A, days=30)
    assert summary["scans_considered"] == 1
    assert summary["non_compliant_resources"] == 1

    findings = asyncio.run(
        main.get_compliance_findings(
            framework=None,
            severity=None,
            status_filter=None,
            days=30,
            provider=None,
            limit=100,
            offset=0,
            current_user=_user(TEAM_A),
        )
    )
    assert findings["total_count"] == 1

    report = asyncio.run(main.get_scan_report(scan_id, _user(TEAM_A)))
    assert report.scan_id == scan_id
    assert len(report.results) == 1

    dashboard = _dashboard(TEAM_A, days=30)
    assert dashboard.total_scans == 1
    assert dashboard.accounts_assessed == 1


def test_reports_are_read_from_the_store_not_from_the_celery_backend(
    env, clock, monkeypatch
):
    # A scan whose Celery result still holds a report but which has no stored
    # report (it completed before the upgrade) is not aggregated: the stored
    # report is the only source.
    scan_id = _scan_at(clock, TEAM_A, "acct-1", days_ago=0)
    backend = LegacyBackend()
    backend.reports[scan_id] = scan_store.load_report(main.redis_client, scan_id)
    main.redis_client.delete(scan_store.report_key(scan_id))
    monkeypatch.setattr(main, "celery_app", backend)

    assert _compliance(TEAM_A)["scans_considered"] == 0


def test_a_report_is_dropped_after_the_retention(env, clock):
    _scan_at(clock, TEAM_A, "kept", days_ago=89)
    _scan_at(clock, TEAM_A, "dropped", days_ago=91)

    summary = _compliance(TEAM_A, days=365)
    dashboard = _dashboard(TEAM_A, days=365)

    assert summary["scans_considered"] == 1
    assert dashboard.total_scans == 1
    assert dashboard.accounts_assessed == 1


def test_the_retention_is_the_configured_one(env, clock, monkeypatch):
    monkeypatch.setattr(config.settings, "cspm_report_retention_days", 7)
    _scan_at(clock, TEAM_A, "kept", days_ago=6)
    _scan_at(clock, TEAM_A, "dropped", days_ago=8)

    assert _compliance(TEAM_A)["scans_considered"] == 1
    assert _dashboard(TEAM_A).total_scans == 1


def test_report_metadata_and_index_entry_expire_together(env, clock, fake_redis):
    clock.now -= 2 * DAY
    scan_id = asyncio.run(
        main.start_scan(_request("acct"), None, _user(TEAM_A))
    ).scan_id
    clock.now += DAY
    # Completing a day later restarts the retention of all three records.
    scan_store.complete_scan(
        fake_redis, scan_id, _report(scan_id, "acct", datetime.utcnow(), []), "x"
    )

    expected = clock.now + 90 * DAY
    index = scan_store.team_index_key(TEAM_A)
    assert fake_redis.expiry[scan_store.metadata_key(scan_id)] == expected
    assert fake_redis.expiry[scan_store.report_key(scan_id)] == expected
    assert fake_redis.zscore(index, scan_id) == expected
    # The index key lives exactly as long as its longest-lived entry.
    assert fake_redis.expiry[index] == int(expected) + 1


# --- index pruning -----------------------------------------------------------


def test_expired_index_entries_are_pruned(env, clock, fake_redis):
    old = _scan_at(clock, TEAM_A, "old", days_ago=95)
    new = _scan_at(clock, TEAM_A, "new", days_ago=1)
    index = scan_store.team_index_key(TEAM_A)

    # Writing the newer scan already pruned the older entry ...
    assert fake_redis.zrangebyscore(index, "-inf", "+inf") == [new]

    # ... and so does a read, once the newer one expires too.
    clock.now += 90 * DAY
    assert list(scan_store.team_scan_metadata(fake_redis, TEAM_A)) == []
    assert fake_redis.zrangebyscore(index, "-inf", "+inf") == []
    assert old not in fake_redis.zsets.get(index, {})


def test_an_index_entry_is_dropped_on_read_when_its_metadata_expired(
    env, clock, fake_redis
):
    scan_id = _scan_at(clock, TEAM_A, "acct", days_ago=1)
    index = scan_store.team_index_key(TEAM_A)
    # Stale entry: in the index, past its expiry, never pruned by a write.
    fake_redis.zsets[index]["stale-scan"] = clock.now - 1

    ids = [m["scan_id"] for m in scan_store.team_scan_metadata(fake_redis, TEAM_A)]

    assert ids == [scan_id]
    assert "stale-scan" not in fake_redis.zsets[index]


def test_lowering_the_retention_keeps_older_entries_reachable(
    env, clock, fake_redis, monkeypatch
):
    long_lived = _scan_at(clock, TEAM_A, "a", days_ago=0)
    monkeypatch.setattr(config.settings, "cspm_report_retention_days", 7)
    _scan_at(clock, TEAM_A, "b", days_ago=0)

    # The key must not expire with the 7-day entry while the 90-day scan lives.
    clock.now += 30 * DAY
    ids = [m["scan_id"] for m in scan_store.team_scan_metadata(fake_redis, TEAM_A)]
    assert ids == [long_lived]


def test_pre_upgrade_index_entries_are_still_read(env, clock, fake_redis):
    # Releases before #591 indexed scans in a plain set.
    scan_store.save_metadata(
        fake_redis,
        {
            "scan_id": "legacy-scan",
            "team_id": TEAM_A,
            "provider": "aws",
            "account_id": "acct",
            "status": "started",
            "started_at": datetime.utcnow().isoformat(),
        },
    )
    fake_redis.delete(scan_store.team_index_key(TEAM_A))
    fake_redis.sadd(scan_store.legacy_team_index_key(TEAM_A), "legacy-scan")

    assert _dashboard(TEAM_A).total_scans == 1
    assert _dashboard(TEAM_B).total_scans == 0


# --- batch scans -------------------------------------------------------------


def _batch(team_id, *requests):
    return asyncio.run(
        main.start_batch_scans(
            schemas.BatchScanRequest(scans=list(requests)), current_user=_user(team_id)
        )
    )


def test_batch_scans_are_recorded_like_single_scans(env, fake_redis):
    single = asyncio.run(main.start_scan(_request("solo"), None, _user(TEAM_A))).scan_id
    batch = _batch(TEAM_A, _request("acct-1"), _request("acct-2"))

    single_meta = scan_store.load_metadata(fake_redis, single)
    for job in batch.scans:
        metadata = scan_store.load_metadata(fake_redis, job.scan_id)
        assert metadata is not None, "batch scan wrote no metadata"
        assert metadata["batch_id"] == batch.batch_id
        assert metadata["team_id"] == TEAM_A
        assert set(metadata) - {"batch_id"} == set(single_meta)
        assert fake_redis.zscore(scan_store.team_index_key(TEAM_A), job.scan_id)

    # Credentials are encrypted, as for a single scan: the worker can read
    # them, and the plaintext secret is not in Redis.
    for task_id, scan_config in env.calls:
        stored = fake_redis.get(scan_config["credential_ref"])
        assert "fake-secret-for-tests-only" not in stored
        assert decrypt_credentials(stored)["secret_access_key"] == (
            "fake-secret-for-tests-only"
        )
    assert [task_id for task_id, _ in env.calls][1:] == [
        job.scan_id for job in batch.scans
    ]


def test_batch_scans_appear_in_their_team_summary_only(env, clock, fake_redis):
    batch = _batch(TEAM_A, _request("acct-1"), _request("acct-2"))
    for job in batch.scans:
        scan_store.complete_scan(
            fake_redis,
            job.scan_id,
            _report(
                job.scan_id,
                job.account_id,
                datetime.utcnow(),
                [("S3", "bucket", "passed")],
            ),
            datetime.utcnow().isoformat(),
        )

    team_a = _dashboard(TEAM_A)
    assert team_a.total_scans == 2
    assert team_a.accounts_assessed == 2
    assert _compliance(TEAM_A)["scans_considered"] == 2

    team_b = _dashboard(TEAM_B)
    assert team_b.total_scans == 0
    assert team_b.accounts_assessed == 0
    assert _compliance(TEAM_B)["scans_considered"] == 0


def test_a_batch_request_cannot_choose_its_team(env, fake_redis):
    batch = _batch(TEAM_A, _request("acct", metadata={"team_id": TEAM_B}))
    scan_id = batch.scans[0].scan_id

    assert scan_store.load_metadata(fake_redis, scan_id)["team_id"] == TEAM_A
    _, scan_config = env.calls[0]
    assert scan_config["metadata"]["team_id"] == TEAM_A
    assert _dashboard(TEAM_A).total_scans == 1
    assert _dashboard(TEAM_B).total_scans == 0


# --- status after the Celery result expired ----------------------------------


def test_a_completed_scan_stays_completed_after_its_celery_result_expires(env, clock):
    scan_id = _scan_at(clock, TEAM_A, "acct", days_ago=2)

    status = asyncio.run(main.get_scan_status(scan_id, _user(TEAM_A)))

    assert status.status == "completed"
    assert status.completed_at is not None


def test_report_of_a_scan_in_progress_is_refused(env):
    scan_id = asyncio.run(
        main.start_scan(_request("acct"), None, _user(TEAM_A))
    ).scan_id

    with pytest.raises(main.HTTPException) as refused:
        asyncio.run(main.get_scan_report(scan_id, _user(TEAM_A)))
    assert refused.value.status_code == 400
    with pytest.raises(main.HTTPException) as denied:
        asyncio.run(main.get_scan_report(scan_id, _user(TEAM_B)))
    assert denied.value.status_code == 403


# --- worker ------------------------------------------------------------------


@pytest.fixture
def worker_env(monkeypatch, fake_redis):
    monkeypatch.setattr(worker, "redis_client", fake_redis)
    monkeypatch.setattr(worker.run_cspm_scan_task, "update_state", lambda **_: None)
    monkeypatch.setattr(worker, "_create_cloud_session", lambda provider, creds: None)
    monkeypatch.setattr(config.settings, "cspm_report_retention_days", 90)
    return fake_redis


def _queued_scan(monkeypatch, fake_redis):
    monkeypatch.setattr(main, "redis_client", fake_redis)
    queue = QueuedTasks()
    monkeypatch.setattr(main, "run_cspm_scan_task", queue)
    scan_id = asyncio.run(
        main.start_scan(_request("acct"), None, _user(TEAM_A))
    ).scan_id
    return scan_id, queue.calls[0][1]


def test_the_worker_stores_the_report_and_returns_none_of_it(worker_env, monkeypatch):
    scan_id, scan_config = _queued_scan(monkeypatch, worker_env)
    report = ScanReport(
        scan_id=scan_id,
        provider=CloudProvider.AWS,
        account_id="acct",
        regions=["eu-west-1"],
        results=[
            CheckResult(
                check_id="S3",
                resource_id="bucket",
                resource_type="S3 Bucket",
                status=CheckStatus.FAILED,
                message="public",
            )
        ],
    )

    async def run_scan(**_):
        return report

    monkeypatch.setattr(worker.check_runner, "run_scan", run_scan)

    result = worker.run_cspm_scan_task.apply(args=[scan_config], task_id=scan_id).get()

    assert "report" not in result
    stored = scan_store.load_report(worker_env, scan_id)
    assert stored["scan_id"] == scan_id
    assert stored["results"][0]["status"] == "failed"
    metadata = scan_store.load_metadata(worker_env, scan_id)
    assert metadata["status"] == "completed"
    assert metadata["completed_at"] == result["completed_at"]


def test_a_failed_scan_is_marked_failed_whatever_the_error(worker_env, monkeypatch):
    scan_id, scan_config = _queued_scan(monkeypatch, worker_env)

    async def run_scan(**_):
        raise RuntimeError("not caught by the task's own except clause")

    monkeypatch.setattr(worker.check_runner, "run_scan", run_scan)

    worker.run_cspm_scan_task.apply(args=[scan_config], task_id=scan_id)

    assert scan_store.load_metadata(worker_env, scan_id)["status"] == "failed"
    assert scan_store.load_report(worker_env, scan_id) is None


def test_celery_results_expire_within_hours():
    expires = worker.celery_app.conf.result_expires
    expires = expires.total_seconds() if isinstance(expires, timedelta) else expires
    assert config.settings.scan_timeout_seconds < expires < DAY


# --- configuration -----------------------------------------------------------


def _settings():
    return config.Settings(_env_file=None)


def test_the_retention_defaults_to_90_days(monkeypatch):
    monkeypatch.delenv("CSPM_REPORT_RETENTION_DAYS", raising=False)
    assert _settings().cspm_report_retention_days == 90


def test_the_retention_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("CSPM_REPORT_RETENTION_DAYS", "30")
    assert _settings().cspm_report_retention_days == 30


@pytest.mark.parametrize("value", ["0", "-1", "3651", "1.5", "ninety", ""])
def test_an_invalid_retention_refuses_to_start(monkeypatch, value):
    monkeypatch.setenv("CSPM_REPORT_RETENTION_DAYS", value)
    with pytest.raises(ValidationError):
        _settings()
