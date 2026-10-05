"""The endpoints that hand work to Celery (#537).

``POST /api/v1/assets/assets/{id}/scan/`` imported
``apps.scanners.tasks.scan_asset``, a module that does not exist, so every
call answered 500. It now queues ``apps.assets.tasks.scan_asset_ports``.

``GET /api/v1/tasks/{task_id}/`` reports what became of a dispatched task,
which is how the integration suite proves the guardian worker runs them.
"""

import uuid
from types import SimpleNamespace
from unittest import mock

import pytest
from django.test import Client

_GW_SECRET = "test-gateway-secret"
# Every row these tests seed belongs to this team, and every request is
# made as a member of it: guardian answers 404 for another team's rows (#642).
TEAM_ID = str(uuid.uuid4())


@pytest.fixture
def client(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
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


def _asset(**fields):
    """An asset, without the port scan its creation queues (signals.py)."""
    from apps.assets.models import Asset

    fields.setdefault("team_id", TEAM_ID)
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        return Asset.objects.create(**fields)


def _scan_url(asset):
    return f"/api/v1/assets/assets/{asset.id}/scan/"


@pytest.mark.django_db
def test_scan_queues_the_port_scan_task(client):
    asset = _asset(name="host", ip_address="192.0.2.10")
    task_id = str(uuid.uuid4())
    with mock.patch("apps.assets.views.scan_asset_ports") as task:
        task.delay.return_value = SimpleNamespace(id=task_id)
        response = client.post(_scan_url(asset), secure=True, **_headers())

    assert response.status_code == 200, response.content[:500]
    assert response.json()["task_id"] == task_id
    task.delay.assert_called_once_with(str(asset.id))


@pytest.mark.django_db
def test_scan_task_is_a_registered_celery_task():
    # The import that failed at request time, checked without a request.
    from apps.assets import views
    from guardian.celery import app

    assert views.scan_asset_ports.name in app.tasks


@pytest.mark.django_db
def test_scan_without_an_address_is_refused(client):
    asset = _asset(name="no-ip", hostname="no-ip.invalid")
    with mock.patch("apps.assets.views.scan_asset_ports") as task:
        response = client.post(_scan_url(asset), secure=True, **_headers())

    assert response.status_code == 400, response.content[:500]
    task.delay.assert_not_called()


@pytest.mark.django_db
def test_scan_needs_an_admin(client):
    asset = _asset(name="host", ip_address="192.0.2.11")
    with mock.patch("apps.assets.views.scan_asset_ports") as task:
        response = client.post(_scan_url(asset), secure=True, **_headers(role="member"))

    assert response.status_code == 403, response.content[:500]
    task.delay.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "state,ready,successful,queue",
    [
        # No worker has taken it, so no delivery queue is recorded yet.
        ("PENDING", False, None, None),
        ("STARTED", False, None, "scanning"),
        ("RETRY", False, None, "scanning"),
        ("SUCCESS", True, True, "reporting"),
        ("FAILURE", True, False, "default"),
    ],
)
def test_task_status_reports_the_backend_state(client, state, ready, successful, queue):
    from apps.core.models import TeamTask

    task_id = str(uuid.uuid4())
    # The caller's team dispatched it (#642).
    TeamTask.objects.create(task_id=task_id, team_id=TEAM_ID)
    with mock.patch(
        "guardian.celery.app.AsyncResult",
        return_value=SimpleNamespace(
            state=state, result="secret", queue=queue, args=["secret"]
        ),
    ) as async_result:
        response = client.get(
            f"/api/v1/tasks/{task_id}/", secure=True, **_headers(role="member")
        )

    assert response.status_code == 200, response.content[:500]
    assert response.json() == {
        "task_id": task_id,
        "state": state,
        "ready": ready,
        "successful": successful,
        "queue": queue,
    }
    async_result.assert_called_once_with(task_id)


@pytest.mark.django_db
def test_task_status_needs_a_credential(client):
    response = client.get(f"/api/v1/tasks/{uuid.uuid4()}/", secure=True)
    # 403 GATEWAY_AUTH_REQUIRED, as every service answers a direct call (#629).
    assert response.status_code == 403, response.status_code
    assert response.json()["code"] == "GATEWAY_AUTH_REQUIRED"


@pytest.mark.django_db
def test_task_status_rejects_a_malformed_id(client):
    response = client.get("/api/v1/tasks/not-a-uuid/", secure=True, **_headers())
    assert response.status_code == 404
