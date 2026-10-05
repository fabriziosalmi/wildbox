"""Scans of providers cspm cannot scan are refused at submit time (#612).

The API accepted GCP and Azure scans, single and batch, and answered with a
scan id; the worker then failed every one of them, because only the AWS
session was implemented. app.providers now derives the supported providers
from the code (a session factory and implemented checks), the scan
endpoints refuse the others with a 400 before storing or queueing
anything, and GET /api/v1/providers lists the same registry.
"""

import asyncio
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import main, providers, scan_store, worker  # noqa: E402
from app.checks.framework import CloudProvider  # noqa: E402
from app.checks.runner import check_runner  # noqa: E402

TEAM = "team-612"
USER = {"user_id": "user-612", "team_id": TEAM, "role": "member"}

AWS_CREDENTIALS = {
    "auth_method": "access_key",
    "access_key_id": "AKIAFAKEFAKEFAKEFAKE",
    "secret_access_key": "fake-secret-for-tests-only",
}
GCP_CREDENTIALS = {
    "auth_method": "service_account",
    "project_id": "wildbox-test-project",
    "service_account_key": {"type": "service_account", "note": "not a key"},
}
AZURE_CREDENTIALS = {
    "auth_method": "client_secret",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "00000000-0000-0000-0000-000000000001",
    "client_secret": "fake-secret-for-tests-only",
    "subscription_id": "00000000-0000-0000-0000-000000000002",
}
UNSUPPORTED = {"gcp": GCP_CREDENTIALS, "azure": AZURE_CREDENTIALS}


def _scan(provider, credentials, account_id="acct"):
    return {"provider": provider, "account_id": account_id, "credentials": credentials}


class QueuedTasks:
    """Stands in for run_cspm_scan_task: records what would be queued."""

    def __init__(self):
        self.calls = []

    def apply_async(self, args, task_id):
        self.calls.append((task_id, args[0]))


@pytest.fixture
def api(monkeypatch, fake_redis):
    """A client of the cspm API with a fake Redis, a fake queue and a signed-in user."""
    monkeypatch.setattr(main, "redis_client", fake_redis)
    queue = QueuedTasks()
    monkeypatch.setattr(main, "run_cspm_scan_task", queue)
    main.app.dependency_overrides[main.get_current_user] = lambda: USER
    client = TestClient(main.app)
    client.queue = queue
    client.redis = fake_redis
    yield client
    main.app.dependency_overrides.clear()


def _nothing_stored(client):
    """No credentials, metadata, index entry or task were written."""
    assert client.queue.calls == []
    assert client.redis.values == {}
    assert client.redis.sets == {}
    assert client.redis.zsets == {}


def _assert_refused(response, provider):
    assert response.status_code == 400, response.text
    message = response.json()["error"]["message"]
    assert provider in message
    # The 400 names the providers that can be scanned.
    for supported in providers.supported_provider_ids():
        assert supported in message


# --- the registry ------------------------------------------------------------


def test_aws_is_the_only_supported_provider():
    assert providers.supported_provider_ids() == ["aws"]


def test_the_check_count_is_the_enabled_checks_the_runner_loaded():
    (aws,) = providers.supported_providers()
    enabled = [
        c for c in check_runner.loaded_checks[CloudProvider.AWS] if c.metadata.enabled
    ]
    assert aws == {
        "provider": "aws",
        "name": "Amazon Web Services",
        "checks": len(enabled),
    }
    assert aws["checks"] > 0


def _runner_with(checks_by_provider):
    def check(enabled=True):
        return SimpleNamespace(metadata=SimpleNamespace(enabled=enabled))

    return SimpleNamespace(
        loaded_checks={
            provider: [check(enabled) for enabled in flags]
            for provider, flags in checks_by_provider.items()
        }
    )


def test_checks_without_a_session_factory_do_not_make_a_provider_supported():
    runner = _runner_with({CloudProvider.AWS: [True], CloudProvider.GCP: [True, True]})
    assert providers.supported_provider_ids(runner) == ["aws"]


def test_a_session_factory_without_enabled_checks_does_not_either():
    assert providers.supported_provider_ids(_runner_with({})) == []
    assert (
        providers.supported_provider_ids(_runner_with({CloudProvider.AWS: [False]}))
        == []
    )
    assert providers.supported_providers(
        _runner_with({CloudProvider.AWS: [True, False, True]})
    ) == [{"provider": "aws", "name": "Amazon Web Services", "checks": 2}]


def test_no_gcp_or_azure_check_is_loaded():
    """Their checks returned invented resources; they are gone, not hidden."""
    assert set(check_runner.loaded_checks) == {CloudProvider.AWS}
    assert check_runner.unimplemented_checks == []
    checks_dir = Path(__file__).resolve().parents[2] / "app" / "checks"
    assert not (checks_dir / "gcp").exists()
    assert not (checks_dir / "azure").exists()


# --- GET /api/v1/providers ---------------------------------------------------


def test_the_providers_endpoint_lists_the_registry(api):
    response = api.get("/api/v1/providers")
    assert response.status_code == 200, response.text
    assert response.json() == {"providers": providers.supported_providers()}


def test_the_providers_endpoint_requires_the_gateway(monkeypatch):
    """Authenticated like every other cspm route: no gateway headers, no list."""
    main.app.dependency_overrides.clear()
    response = TestClient(main.app).get("/api/v1/providers")
    assert response.status_code in (401, 403, 503), response.text


# --- single scans ------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(UNSUPPORTED))
def test_a_scan_of_an_unsupported_provider_is_refused(api, provider):
    response = api.post("/api/v1/scans", json=_scan(provider, UNSUPPORTED[provider]))
    _assert_refused(response, provider)
    _nothing_stored(api)


def test_an_aws_scan_is_accepted(api):
    response = api.post("/api/v1/scans", json=_scan("aws", AWS_CREDENTIALS))
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    assert [task_id for task_id, _ in api.queue.calls] == [scan_id]
    assert scan_store.load_metadata(api.redis, scan_id)["provider"] == "aws"


# --- batch scans -------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(UNSUPPORTED))
def test_a_batch_naming_an_unsupported_provider_is_refused_whole(api, provider):
    """The AWS scan listed first is not started either."""
    batch = {
        "scans": [
            _scan("aws", AWS_CREDENTIALS, "aws-acct"),
            _scan(provider, UNSUPPORTED[provider], f"{provider}-acct"),
        ]
    }
    response = api.post("/api/v1/batch/scans", json=batch)
    _assert_refused(response, provider)
    _nothing_stored(api)


def test_a_batch_names_every_unsupported_provider_it_holds(api):
    batch = {"scans": [_scan(p, c) for p, c in UNSUPPORTED.items()]}
    response = api.post("/api/v1/batch/scans", json=batch)
    assert response.status_code == 400, response.text
    message = response.json()["error"]["message"]
    assert "Unsupported provider: azure, gcp." in message
    _nothing_stored(api)


def test_an_aws_batch_is_accepted(api):
    batch = {"scans": [_scan("aws", AWS_CREDENTIALS, f"acct-{i}") for i in range(2)]}
    response = api.post("/api/v1/batch/scans", json=batch)
    assert response.status_code == 200, response.text
    assert response.json()["total_scans"] == 2
    assert len(api.queue.calls) == 2


# --- the AWS session factory -------------------------------------------------


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test on any boto3 session or socket connection."""

    def refuse(*args, **kwargs):
        raise AssertionError("a boto3 session or a connection was opened")

    monkeypatch.setattr(providers.boto3, "Session", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.mark.parametrize(
    "credentials",
    [
        {**AWS_CREDENTIALS, "access_key_id": "not-an-aws-key"},
        {**AWS_CREDENTIALS, "access_key_id": "SHORTKEY"},
        {**AWS_CREDENTIALS, "access_key_id": None},
        {**AWS_CREDENTIALS, "secret_access_key": ""},
        {**AWS_CREDENTIALS, "auth_method": "assume_role", "role_arn": None},
        {**AWS_CREDENTIALS, "auth_method": "assume_role", "role_arn": "not-a-role"},
        {**AWS_CREDENTIALS, "auth_method": "web_identity"},
    ],
)
def test_malformed_aws_credentials_are_refused_before_any_call(no_network, credentials):
    with pytest.raises(providers.MalformedCredentialsError) as refused:
        providers.create_session(CloudProvider.AWS, credentials)
    # The message never carries the secret.
    assert "fake-secret-for-tests-only" not in str(refused.value)


def test_well_formed_aws_keys_open_a_session(monkeypatch):
    opened = []
    monkeypatch.setattr(
        providers.boto3, "Session", lambda **kwargs: opened.append(kwargs) or "session"
    )
    assert providers.create_session(CloudProvider.AWS, AWS_CREDENTIALS) == "session"
    assert opened[0]["aws_access_key_id"] == AWS_CREDENTIALS["access_key_id"]
    assert opened[0]["region_name"] == "us-east-1"


@pytest.mark.parametrize("provider", [CloudProvider.GCP, CloudProvider.AZURE])
def test_no_session_factory_for_gcp_or_azure(provider):
    with pytest.raises(ValueError):
        providers.create_session(provider, {})


# --- the worker --------------------------------------------------------------


@pytest.fixture
def worker_env(monkeypatch, fake_redis):
    monkeypatch.setattr(worker, "redis_client", fake_redis)
    states = []
    monkeypatch.setattr(
        worker.run_cspm_scan_task,
        "update_state",
        lambda state=None, meta=None, **_: states.append(state),
    )
    fake_redis.states = states
    return fake_redis


def _queue(monkeypatch, fake_redis, scan):
    """Submit ``scan`` as the API does and return (scan id, task arguments)."""
    monkeypatch.setattr(main, "redis_client", fake_redis)
    queue = QueuedTasks()
    monkeypatch.setattr(main, "run_cspm_scan_task", queue)
    from app import schemas

    response = asyncio.run(main.start_scan(schemas.ScanRequest(**scan), None, USER))
    return response.scan_id, queue.calls[0][1]


def test_a_scan_with_malformed_aws_keys_fails_without_reaching_aws(
    worker_env, monkeypatch, no_network
):
    """The path tests/integration/test_cspm_worker.py takes to a failed scan."""
    credentials = {**AWS_CREDENTIALS, "access_key_id": "not-an-aws-key"}
    scan_id, scan_config = _queue(monkeypatch, worker_env, _scan("aws", credentials))

    async def run_scan(**_):
        raise AssertionError("the checks ran")

    monkeypatch.setattr(worker.check_runner, "run_scan", run_scan)

    result = worker.run_cspm_scan_task.apply(args=[scan_config], task_id=scan_id)

    assert scan_store.load_metadata(worker_env, scan_id)["status"] == "failed"
    assert scan_store.load_report(worker_env, scan_id) is None
    # The credentials were deleted when the worker read them.
    assert worker_env.get(scan_config["credential_ref"]) is None
    # The task fails with an exception the result backend can store and
    # read back, with no detail of the cause. A FAILURE state set by hand
    # with a dict as its meta made GET /api/v1/scans/{id} answer 500.
    assert result.failed()
    assert "FAILURE" not in worker_env.states
    assert isinstance(result.result, RuntimeError)
    assert "access key" not in str(result.result)


class UnreadableBackend:
    """A result backend holding a FAILURE meta Celery cannot decode."""

    def AsyncResult(self, task_id):  # noqa: N802 - Celery's name
        class Result:
            @property
            def status(self):
                raise ValueError(
                    "Exception information must include the exception type"
                )

            info = status

        return Result()


def test_a_failed_scan_reads_failed_whatever_the_result_backend_holds(
    monkeypatch, fake_redis
):
    scan_id, _ = _queue(monkeypatch, fake_redis, _scan("aws", AWS_CREDENTIALS))
    scan_store.fail_scan(fake_redis, scan_id, "2026-10-03T12:00:00")
    monkeypatch.setattr(main, "celery_app", UnreadableBackend())

    status = asyncio.run(main.get_scan_status(scan_id, USER))

    assert status.status == "failed"


def test_a_gcp_scan_queued_before_the_upgrade_fails(
    worker_env, monkeypatch, no_network
):
    """A scan accepted by an earlier release still ends, as failed."""
    scan_id, scan_config = _queue(
        monkeypatch, worker_env, _scan("aws", AWS_CREDENTIALS)
    )
    scan_config = {**scan_config, "provider": "gcp"}

    worker.run_cspm_scan_task.apply(args=[scan_config], task_id=scan_id)

    assert scan_store.load_metadata(worker_env, scan_id)["status"] == "failed"
