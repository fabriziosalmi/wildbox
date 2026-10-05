"""The API offers no file it cannot serve (#724).

``GET vulnerabilities/{id}/attachments/`` listed ``VulnerabilityAttachment``
rows. guardian has never had an upload route, a task or a command that
creates one, so the answer was always an empty list; and had a row existed,
its ``file`` would have been ``/media/vulnerability_attachments/...``, a URL
nothing serves (media is outside ``/api/``, where neither the gateway's
authentication nor the team check applies, #642). The route and its
serializer were removed rather than given an upload and a download that
were never there.

What guardian does serve as a file is a generated report, through
``reports/reports/{id}/download/`` (test_report_paths.py).
"""

import importlib
import uuid

import pytest
from django.apps import apps
from django.db import models
from django.test import Client
from django.urls import Resolver404, resolve
from rest_framework import serializers

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
_GUARDIAN_APPS = (
    "assets",
    "vulnerabilities",
    "scanners",
    "remediation",
    "compliance",
    "integrations",
    "reporting",
)


@pytest.fixture
def get(settings, monkeypatch, tmp_path):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    settings.MEDIA_ROOT = str(tmp_path)
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(url, team):
        return client.get(
            url,
            secure=True,
            HTTP_X_WILDBOX_USER_ID=caller,
            HTTP_X_WILDBOX_TEAM_ID=str(team),
            HTTP_X_WILDBOX_ROLE="admin",
            HTTP_X_WILDBOX_AUTH_TYPE="session",
            HTTP_X_GATEWAY_SECRET=_GW_SECRET,
        )

    return call


def _attached(team):
    """A vulnerability with an attachment row, written as only the ORM can."""
    from apps.vulnerabilities.models import Vulnerability, VulnerabilityAttachment

    vulnerability = tf.make(Vulnerability, team)
    VulnerabilityAttachment.objects.create(
        vulnerability=vulnerability,
        uploaded_by=tf.user(team),
        file="vulnerability_attachments/evidence.txt",
        filename="evidence.txt",
        file_size=1,
        content_type="text/plain",
    )
    return vulnerability


@pytest.mark.django_db
def test_there_is_no_attachments_route(get):
    team = uuid.uuid4()
    vulnerability = _attached(team)
    url = f"/api/v1/vulnerabilities/{vulnerability.pk}/attachments/"

    with pytest.raises(Resolver404):
        resolve(url)
    assert get(url, team).status_code == 404


@pytest.mark.django_db
def test_a_vulnerability_names_no_media_url(get):
    team = uuid.uuid4()
    vulnerability = _attached(team)

    for url in (
        f"/api/v1/vulnerabilities/{vulnerability.pk}/",
        "/api/v1/vulnerabilities/",
    ):
        response = get(url, team)
        body = response.content.decode()
        assert response.status_code == 200, body[:300]
        assert str(vulnerability.pk) in body
        assert "/media/" not in body
        assert "evidence.txt" not in body


def test_media_is_not_served(get):
    assert (
        get("/media/vulnerability_attachments/evidence.txt", uuid.uuid4()).status_code
        == 404
    )


def _serializer_classes():
    found = set()
    for label in _GUARDIAN_APPS:
        module = importlib.import_module(f"apps.{label}.serializers")
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, serializers.BaseSerializer)
                and value.__module__ == module.__name__
            ):
                found.add(value)
    return found


def test_no_serializer_carries_a_file():
    """A file field is written as a URL under MEDIA_URL, which is not served."""
    classes = _serializer_classes()
    assert len(classes) > 50
    for serializer_class in classes:
        try:
            fields = serializer_class().fields
        except Exception:
            # A serializer that needs its request to list its fields.
            fields = serializer_class(context={"team_id": uuid.uuid4()}).fields
        for name, field in fields.items():
            assert not isinstance(
                field, serializers.FileField
            ), f"{serializer_class.__name__}.{name}"


def test_the_attachment_model_is_the_only_one_with_a_file_and_has_no_serializer():
    with_files = {
        model._meta.label
        for model in apps.get_models()
        if model._meta.app_label in _GUARDIAN_APPS
        and any(isinstance(field, models.FileField) for field in model._meta.fields)
    }
    assert with_files == {"vulnerabilities.VulnerabilityAttachment"}
    served = {
        getattr(getattr(cls, "Meta", None), "model", None)
        for cls in _serializer_classes()
    }
    assert apps.get_model("vulnerabilities.VulnerabilityAttachment") not in served
