"""Regression tests for the vulnerabilities app (#514, #515).

#514: the router registered the ``''`` prefix before ``templates`` and
``assessments``. The vulnerability detail route ``^(?P<pk>[^/.]+)/$`` was
therefore tried first, ``/api/v1/vulnerabilities/templates/`` was served as
``VulnerabilityViewSet.retrieve(pk="templates")`` and answered 404, and the
template and assessment viewsets could not be reached at all.

#515: the post_save signal wrote the creation history entry with
``old_value=None`` into a NOT NULL ``TextField``, so creating any
vulnerability raised ``IntegrityError``. The same happened on update for a
tracked field moving from or to ``None`` (assigning or unassigning a user).
"""

import uuid

import pytest
from apps.assets.models import Asset
from apps.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAssessment,
    VulnerabilityHistory,
    VulnerabilityTemplate,
)
from apps.vulnerabilities.views import (
    VulnerabilityAssessmentViewSet,
    VulnerabilityTemplateViewSet,
    VulnerabilityViewSet,
)
from django.contrib.auth.models import User
from django.test import Client
from django.urls import resolve

_GW_SECRET = "test-gateway-secret"
_BASE = "/api/v1/vulnerabilities/"


def _resolved(url):
    match = resolve(url)
    return match.func.cls, (match.func.actions or {}).get("get")


@pytest.mark.parametrize(
    "url,view_cls,action",
    [
        (_BASE, VulnerabilityViewSet, "list"),
        (f"{_BASE}{uuid.uuid4()}/", VulnerabilityViewSet, "retrieve"),
        (f"{_BASE}stats/", VulnerabilityViewSet, "stats"),
        (f"{_BASE}templates/", VulnerabilityTemplateViewSet, "list"),
        (f"{_BASE}templates/{uuid.uuid4()}/", VulnerabilityTemplateViewSet, "retrieve"),
        (f"{_BASE}assessments/", VulnerabilityAssessmentViewSet, "list"),
        (
            f"{_BASE}assessments/{uuid.uuid4()}/",
            VulnerabilityAssessmentViewSet,
            "retrieve",
        ),
    ],
)
def test_vulnerability_urls_resolve_to_their_viewset(url, view_cls, action):
    assert _resolved(url) == (view_cls, action)


@pytest.fixture
def api(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client()
    headers = {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_ROLE": "admin",
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
    }

    def get(url):
        return client.get(url, secure=True, **headers)

    return get


def _vulnerability(**kwargs):
    asset = Asset.objects.create(name="host")
    return Vulnerability.objects.create(
        title="v", description="d", asset=asset, **kwargs
    )


@pytest.mark.django_db
def test_templates_and_assessments_are_served(api):
    template = VulnerabilityTemplate.objects.create(
        title="t", description_template="d", solution_template="s", severity="high"
    )
    vulnerability = _vulnerability()
    assessment = VulnerabilityAssessment.objects.create(vulnerability=vulnerability)

    for url, pk in (
        (f"{_BASE}templates/", template.pk),
        (f"{_BASE}assessments/", assessment.pk),
    ):
        listed = api(url)
        assert listed.status_code == 200, listed.content[:500]
        assert [str(row["id"]) for row in listed.json()["results"]] == [str(pk)]
        retrieved = api(f"{url}{pk}/")
        assert retrieved.status_code == 200, retrieved.content[:500]


@pytest.mark.django_db
def test_creating_a_vulnerability_records_its_initial_status():
    vulnerability = _vulnerability()

    (entry,) = VulnerabilityHistory.objects.filter(vulnerability=vulnerability)
    assert entry.field_name == "status"
    assert entry.old_value == ""
    assert entry.new_value == vulnerability.status
    assert entry.change_reason == "Vulnerability created"


@pytest.mark.django_db
def test_assigning_and_unassigning_records_history():
    user = User.objects.create(username="analyst")
    vulnerability = _vulnerability()

    vulnerability.assigned_to = user
    vulnerability.save()
    vulnerability.assigned_to = None
    vulnerability.save()

    changes = list(
        VulnerabilityHistory.objects.filter(
            vulnerability=vulnerability, field_name="assigned_to"
        )
        .order_by("timestamp", "id")
        .values_list("old_value", "new_value")
    )
    assert changes == [("", str(user.pk)), (str(user.pk), "")]
