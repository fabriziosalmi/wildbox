"""cspm-worker runs the scans cspm queues, with cspm's settings (#601).

The worker was commented out of docker-compose.yml, so every scan stayed
queued forever. These tests hold the service and the code to each other:
the worker consumes exactly the queues the tasks are routed to, has the
settings the API encrypts, stores and times scans with, and is given as
long to stop as a scan may run. The last tests cover what a scan does once
a worker takes it: it reads "running", and a scan the worker cannot run
ends "failed", the path the integration suite drives through the gateway.
"""

import asyncio
import re
import shlex
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

# conftest.py does the same; repeated so the file reads on its own.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import config, main, scan_store, schemas, worker  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
needs_compose = pytest.mark.skipif(
    not COMPOSE_FILE.exists(), reason="needs the repository checkout"
)

# What the worker must share with the API: the key that decrypts the
# credentials the API encrypted, the Redis it reads them and the queue
# from, the retention it writes reports with and the scan time limit.
SHARED_SETTINGS = (
    "ENVIRONMENT",
    "SECRET_KEY",
    "REDIS_URL",
    "CELERY_BROKER_URL",
    "CELERY_RESULT_BACKEND",
    "CSPM_CREDENTIAL_KEY",
    "CSPM_REPORT_RETENTION_DAYS",
    "SCAN_TIMEOUT_SECONDS",
    "LOG_LEVEL",
)


# --- routing -----------------------------------------------------------------


def _registered():
    """cspm's own tasks, as the worker registers them."""
    worker.celery_app.loader.import_default_modules()
    return {name for name in worker.celery_app.tasks if not name.startswith("celery.")}


def _intended():
    intended = {}
    for queue, names in worker.TASK_QUEUES.items():
        for name in names:
            assert name not in intended, f"{name} is listed twice"
            intended[name] = queue
    return intended


def _routed_queue(name):
    return worker.celery_app.amqp.router.route({}, name)["queue"].name


def test_every_registered_task_has_an_intended_queue():
    missing = sorted(_registered() - set(_intended()))
    assert not missing, f"tasks with no queue in app/worker.py TASK_QUEUES: {missing}"


def test_every_listed_task_is_registered():
    stale = sorted(set(_intended()) - _registered())
    assert not stale, f"TASK_QUEUES names tasks that do not exist: {stale}"


def test_each_task_resolves_to_its_intended_queue():
    intended = _intended()
    wrong = {
        name: (_routed_queue(name), intended[name])
        for name in sorted(_registered())
        if _routed_queue(name) != intended.get(name)
    }
    assert not wrong, f"task: (routed to, intended): {wrong}"


def test_scans_go_to_the_queue_earlier_releases_used():
    # Scans queued before the upgrade sit in "celery", Celery's default.
    assert _routed_queue("run_cspm_scan") == "celery"


# --- the compose service -----------------------------------------------------


def _services():
    return yaml.safe_load(COMPOSE_FILE.read_text())["services"]


def _environment(service):
    return dict(item.split("=", 1) for item in service["environment"])


def _argv(command):
    return shlex.split(command) if isinstance(command, str) else list(command)


@needs_compose
def test_the_worker_consumes_exactly_the_routed_queues():
    argv = _argv(_services()["cspm-worker"]["command"])
    queues = argv[argv.index("-Q") + 1].split(",")
    assert len(queues) == len(set(queues)), queues
    assert set(queues) == set(worker.TASK_QUEUES), queues


@needs_compose
def test_the_worker_runs_the_app_the_api_queues_to():
    argv = _argv(_services()["cspm-worker"]["command"])
    assert argv[:4] == ["celery", "-A", "app.worker:celery_app", "worker"], argv


@needs_compose
def test_the_worker_is_built_like_the_api():
    services = _services()
    assert services["cspm-worker"]["build"] == services["cspm"]["build"]


@needs_compose
@pytest.mark.parametrize("name", SHARED_SETTINGS)
def test_the_worker_has_the_api_settings(name):
    services = _services()
    api, cspm_worker = _environment(services["cspm"]), _environment(
        services["cspm-worker"]
    )
    assert name in api, f"cspm has no {name}"
    assert cspm_worker.get(name) == api[name]


@needs_compose
def test_redis_is_reached_with_the_password():
    env = _environment(_services()["cspm-worker"])
    for name in ("REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND"):
        assert ":${REDIS_PASSWORD:?" in env[name], name


@needs_compose
def test_the_worker_has_as_long_to_stop_as_a_scan_may_run():
    service = _services()["cspm-worker"]
    timeout = _environment(service)["SCAN_TIMEOUT_SECONDS"]
    # The same variable, so the two cannot drift apart.
    assert service["stop_grace_period"] == f"{timeout}s"
    default = re.fullmatch(r"\$\{CSPM_SCAN_TIMEOUT_SECONDS:-(\d+)\}", timeout)
    assert default, timeout
    assert (
        int(default.group(1))
        == config.Settings.model_fields["scan_timeout_seconds"].default
    )


@needs_compose
def test_the_worker_is_hardened_and_bounded_like_the_other_workers():
    service = _services()["cspm-worker"]
    assert service["restart"] == "unless-stopped"
    assert "no-new-privileges:true" in service["security_opt"]
    assert "user" not in service, "the image's non-root user must not be overridden"
    assert "container_name" not in service, "a fixed name prevents --scale"
    assert "ports" not in service
    limits = service["deploy"]["resources"]["limits"]
    assert limits["cpus"] and limits["memory"]


@needs_compose
def test_the_health_check_pings_this_worker():
    test = _services()["cspm-worker"]["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    assert "inspect ping" in test[1]
    assert "-d celery@$$HOSTNAME" in test[1]


# --- time limits -------------------------------------------------------------


def test_a_running_scan_is_never_delivered_twice():
    # Tasks are acknowledged late: Redis redelivers an unacknowledged one
    # after the visibility timeout, so it must exceed the time limit.
    conf = worker.celery_app.conf
    assert conf.task_acks_late
    assert conf.broker_transport_options["visibility_timeout"] > conf.task_time_limit


def test_the_soft_limit_comes_before_the_hard_one():
    conf = worker.celery_app.conf
    assert 0 < conf.task_soft_time_limit < conf.task_time_limit


@pytest.mark.parametrize("value", ["119", "0", "-1", "86401", "ten"])
def test_an_invalid_scan_timeout_refuses_to_start(monkeypatch, value):
    monkeypatch.setenv("SCAN_TIMEOUT_SECONDS", value)
    with pytest.raises(ValidationError):
        config.Settings(_env_file=None)


def test_the_scan_timeout_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("SCAN_TIMEOUT_SECONDS", "7200")
    assert config.Settings(_env_file=None).scan_timeout_seconds == 7200


# --- a scan a worker took ----------------------------------------------------


class Backend:
    """A Celery result backend that reports one state for every task."""

    def __init__(self, state, info=None):
        self.state, self.info = state, info

    def AsyncResult(self, task_id):  # noqa: N802 - Celery's name
        return type(
            "Result", (), {"status": self.state, "info": self.info, "result": None}
        )()


class Queue:
    """Stands in for run_cspm_scan_task: records what would be queued."""

    def __init__(self):
        self.calls = []

    def apply_async(self, args, task_id):
        self.calls.append((task_id, args[0]))


USER = {"user_id": "user-a", "team_id": "team-a"}


def _malformed_aws_request():
    # The scan the integration suite submits: an access key id AWS could
    # never issue, refused by the session factory before any call to AWS
    # (#612). GCP, which this used, is now refused at submit time.
    return schemas.ScanRequest(
        provider="aws",
        account_id="ci-account",
        credentials={
            "auth_method": "access_key",
            "access_key_id": "not-an-aws-key",
            "secret_access_key": "not-a-secret",
        },
    )


@pytest.fixture
def queued(monkeypatch, fake_redis):
    """An AWS scan queued by the API, and the config the worker receives."""
    queue = Queue()
    monkeypatch.setattr(main, "redis_client", fake_redis)
    monkeypatch.setattr(main, "run_cspm_scan_task", queue)
    monkeypatch.setattr(worker, "redis_client", fake_redis)
    monkeypatch.setattr(config.settings, "cspm_report_retention_days", 90)
    scan_id = asyncio.run(main.start_scan(_malformed_aws_request(), None, USER)).scan_id
    return scan_id, queue.calls[0][1]


def _status(monkeypatch, scan_id, state, info=None):
    monkeypatch.setattr(main, "celery_app", Backend(state, info))
    return asyncio.run(main.get_scan_status(scan_id, USER))


def test_a_scan_no_worker_took_reads_queued(monkeypatch, queued):
    scan_id, _ = queued
    assert _status(monkeypatch, scan_id, "PENDING").status == "queued"


def test_a_scan_a_worker_took_reads_running(monkeypatch, queued):
    # task_track_started: STARTED comes before the scan's own PROGRESS.
    scan_id, _ = queued
    started = _status(
        monkeypatch, scan_id, "STARTED", {"pid": 7, "hostname": "celery@w"}
    )
    assert started.status == "running"
    assert started.progress["current_status"] == "running"
    assert (
        _status(monkeypatch, scan_id, "PROGRESS", {"status": "initializing"}).status
        == "running"
    )


def test_a_scan_the_worker_cannot_run_ends_failed(monkeypatch, queued, fake_redis):
    scan_id, scan_config = queued
    assert scan_config["credential_ref"] == f"scan:{scan_id}:creds"
    assert fake_redis.get(scan_config["credential_ref"])

    # No AWS session can be created with a malformed key, as with the
    # credentials the integration suite submits: the task raises.
    result = worker.run_cspm_scan_task.apply(args=[scan_config], task_id=scan_id)

    assert result.failed()
    metadata = scan_store.load_metadata(fake_redis, scan_id)
    assert metadata["status"] == "failed"
    assert metadata["failed_at"] >= metadata["started_at"]
    assert (metadata["provider"], metadata["account_id"]) == ("aws", "ci-account")
    assert scan_store.load_report(fake_redis, scan_id) is None
    # The worker deletes the credentials as soon as it has read them.
    assert fake_redis.get(scan_config["credential_ref"]) is None
    # The final status wins over whatever the result backend still says.
    assert _status(monkeypatch, scan_id, "PENDING").status == "failed"


def test_a_scan_queued_before_its_credentials_expired_ends_failed(
    monkeypatch, queued, clock, fake_redis
):
    # An upgrade drains scans an earlier release queued with no worker:
    # their credentials expired five minutes after they were queued.
    scan_id, scan_config = queued
    clock.now += timedelta(minutes=6).total_seconds()

    result = worker.run_cspm_scan_task.apply(args=[scan_config], task_id=scan_id)

    assert result.failed()
    assert scan_store.load_metadata(fake_redis, scan_id)["status"] == "failed"
