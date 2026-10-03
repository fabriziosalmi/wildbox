"""Write paths of the remediation and integrations APIs (#516).

``RemediationStep.complete_execution`` called
``workflow.update_workflow_progress()``, which did not exist, so completing a
step raised ``AttributeError``; the ``complete`` action of the steps API did
not call it at all, so the workflow progress never moved. And no create
endpoint of the two apps set ``created_by``, so it stayed null.

Requests go through the full middleware stack with gateway headers, as in
production: ``GatewayAuthMiddleware`` mirrors the identity user into an
``auth.User`` whose username is the gateway user id, and that is the user
``created_by`` must point at.
"""

import uuid

import pytest
from apps.assets.models import Asset
from apps.remediation.models import RemediationStep, RemediationWorkflow
from apps.vulnerabilities.models import Vulnerability
from django.contrib.auth.models import User
from django.test import Client

_GW_SECRET = "test-gateway-secret"
# Every row these tests seed belongs to this team, and every request is
# made as a member of it: guardian answers 404 for another team's rows (#642).
TEAM_ID = str(uuid.uuid4())


@pytest.fixture
def gateway_user_id():
    return str(uuid.uuid4())


@pytest.fixture
def api(settings, monkeypatch, gateway_user_id):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client()
    headers = {
        "HTTP_X_WILDBOX_USER_ID": gateway_user_id,
        "HTTP_X_WILDBOX_TEAM_ID": TEAM_ID,
        "HTTP_X_WILDBOX_ROLE": "admin",
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
    }

    def post(url, data):
        return client.post(
            url, data, content_type="application/json", secure=True, **headers
        )

    return post


def _vulnerability():
    asset = Asset.objects.create(name="host", team_id=TEAM_ID)
    # bulk_create skips the vulnerability post_save history signal, which is
    # fixed separately (#515) and not what these tests are about.
    (vulnerability,) = Vulnerability.objects.bulk_create(
        [Vulnerability(title="v", description="d", asset=asset)]
    )
    return vulnerability


def _workflow_with_steps(count):
    workflow = RemediationWorkflow.objects.create(
        vulnerability=_vulnerability(),
        title="w",
        remediation_type="patch",
        priority="high",
        status="in_progress",
    )
    steps = [
        RemediationStep.objects.create(
            workflow=workflow,
            title=f"step {n}",
            description="d",
            order=n,
            instructions="i",
        )
        for n in range(1, count + 1)
    ]
    return workflow, steps


@pytest.mark.django_db
def test_complete_execution_updates_workflow_progress():
    workflow, (first, second) = _workflow_with_steps(2)

    first.complete_execution(notes="patched")

    first.refresh_from_db()
    workflow.refresh_from_db()
    assert first.status == "completed"
    assert first.completed_at is not None
    assert first.execution_notes == "patched"
    assert workflow.progress_percentage == 50.0
    assert workflow.current_step == second.title


@pytest.mark.django_db
def test_completing_every_step_moves_workflow_to_testing():
    workflow, steps = _workflow_with_steps(2)

    for step in steps:
        step.complete_execution()

    workflow.refresh_from_db()
    assert workflow.progress_percentage == 100.0
    assert workflow.status == "testing"


@pytest.mark.django_db
def test_complete_action_records_execution(api):
    workflow, (first, _) = _workflow_with_steps(2)

    started = api(f"/api/v1/remediation/steps/{first.pk}/execute/", {})
    completed = api(
        f"/api/v1/remediation/steps/{first.pk}/complete/",
        {"notes": "patched", "validation_results": "rescan clean"},
    )

    assert started.status_code == 200, started.content[:500]
    assert completed.status_code == 200, completed.content[:500]
    first.refresh_from_db()
    workflow.refresh_from_db()
    assert first.started_at is not None
    assert first.completed_at is not None
    assert first.execution_notes == "patched"
    assert first.validation_results == "rescan clean"
    assert workflow.progress_percentage == 50.0


def _payloads():
    return {
        "/api/v1/remediation/tickets/": {
            "title": "t",
            "description": "d",
            "system": "jira",
            "external_ticket_id": "SEC-1",
            "priority": "high",
        },
        "/api/v1/remediation/workflows/": {
            "vulnerability": str(_vulnerability().pk),
            "title": "w",
            "remediation_type": "patch",
            "priority": "high",
        },
        "/api/v1/remediation/templates/": {
            "name": "n",
            "description": "d",
            "category": "c",
            "remediation_type": "patch",
        },
        "/api/v1/integrations/systems/": {
            "name": "jira",
            "system_type": "ticketing",
            "base_url": "https://jira.example.com",
        },
        "/api/v1/integrations/notifications/": {
            "name": "slack",
            "channel_type": "slack",
        },
    }


@pytest.mark.django_db
def test_create_sets_created_by_to_the_gateway_user(api, gateway_user_id):
    for url, payload in _payloads().items():
        response = api(url, payload)
        assert response.status_code == 201, (url, response.content[:500])
        created_by = response.json()["created_by"]
        assert created_by is not None, url
        assert User.objects.get(pk=created_by).username == gateway_user_id, url
