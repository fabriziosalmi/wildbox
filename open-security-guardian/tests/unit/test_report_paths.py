"""No answer about a report names a path on the server (#724).

``ReportSerializer`` listed every field of the model, ``file_path`` among
them: read-only since #642, and still in every answer that carried a report,
``/app/media/reports/<team id>/<report id>.json``. A client has no use for
it: a completed report's file is ``reports/reports/{id}/download/``.

A failed report had the same leak by another door: ``error_message`` was the
text of whatever exception stopped it, and an error of the operating system
names the file it was about.
"""

import json
import uuid
from unittest import mock

import pytest
from apps.reporting.models import Report, ReportSchedule, ReportTemplate
from apps.reporting.serializers import ReportSerializer
from apps.reporting.tasks import generate_report
from django.test import Client

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
_REPORTS = "/api/v1/reports/reports/"
_TEMPLATES = "/api/v1/reports/templates/"
_SCHEDULES = "/api/v1/reports/schedules/"


@pytest.fixture
def media_root(settings, tmp_path):
    settings.MEDIA_ROOT = str(tmp_path / "media")
    return settings.MEDIA_ROOT


@pytest.fixture
def api(settings, monkeypatch, media_root):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(method, url, team, data=None):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": caller,
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": "admin",
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=json.dumps(data), content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


def _generated(team):
    """A report of ``team``, generated as the worker generates it."""
    report = tf.make(Report, team)
    with mock.patch("apps.reporting.tasks.update_report_metrics"):
        assert generate_report.apply(args=(report.pk,)).successful()
    report.refresh_from_db()
    assert report.status == "completed", report.error_message
    return report


def test_the_serializer_has_no_file_path():
    assert "file_path" not in ReportSerializer().fields
    # Still told: whether there is a file, and how to check it.
    assert {"status", "file_size", "file_hash", "file_size_mb"} <= set(
        ReportSerializer().fields
    )


@pytest.mark.django_db
def test_no_answer_about_a_report_names_where_its_file_is(api, media_root):
    team = uuid.uuid4()
    report = _generated(team)
    # The file is under MEDIA_ROOT, and the row knows where.
    assert report.file_path.startswith(media_root)
    schedule = tf.make(ReportSchedule, team)
    Report.objects.filter(pk=report.pk).update(schedule=schedule)

    answers = {
        "list": api("get", _REPORTS, team),
        "detail": api("get", f"{_REPORTS}{report.pk}/", team),
        "recent": api("get", f"{_REPORTS}recent/", team),
        "of the template": api(
            "get", f"{_TEMPLATES}{report.template_id}/reports/", team
        ),
        "rename": api("patch", f"{_REPORTS}{report.pk}/", team, {"name": "renamed"}),
    }

    for name, response in answers.items():
        body = response.content.decode()
        assert response.status_code == 200, (name, body[:300])
        assert str(report.pk) in body, name
        assert "file_path" not in body, name
        assert media_root not in body, name
        assert report.file_path not in body, name


@pytest.mark.django_db
def test_the_answers_that_queue_a_report_have_no_path_either(api, media_root):
    team = uuid.uuid4()
    template = tf.make(ReportTemplate, team)
    schedule = tf.make(ReportSchedule, team)

    with mock.patch("apps.reporting.views.generate_report"):
        answers = [
            api(
                "post", f"{_TEMPLATES}{template.pk}/generate/", team, {"format": "json"}
            ),
            api("post", f"{_SCHEDULES}{schedule.pk}/run_now/", team, {}),
        ]

    for response in answers:
        assert response.status_code == 202, response.content[:300]
        assert "file_path" not in response.json()
        assert response.json()["template"] is not None


@pytest.mark.django_db
def test_the_file_is_still_downloaded_through_the_api(api, media_root):
    team = uuid.uuid4()
    report = _generated(team)

    response = api("get", f"{_REPORTS}{report.pk}/download/", team)

    assert response.status_code == 200
    with open(report.file_path, "rb") as handle:
        assert response.content == handle.read()
    assert media_root not in response["Content-Disposition"]


@pytest.mark.django_db
def test_a_report_that_could_not_be_written_does_not_say_where(api, media_root):
    team = uuid.uuid4()
    report = tf.make(Report, team)
    path = f"{media_root}/reports/{team}/{report.pk}.json"
    denied = PermissionError(13, "Permission denied", path)
    assert path in str(denied)

    with mock.patch("apps.reporting.tasks.save_report_file", side_effect=denied):
        generate_report.apply(args=(report.pk,))

    report.refresh_from_db()
    assert report.status == "failed"
    assert report.error_message == "The report file could not be written."
    body = api("get", f"{_REPORTS}{report.pk}/", team).content.decode()
    assert media_root not in body
    failed = api("get", f"{_REPORTS}failed/", team)
    assert failed.status_code == 200
    assert media_root not in failed.content.decode()
    assert [row["id"] for row in failed.json()] == [str(report.pk)]


@pytest.mark.django_db
def test_a_reason_guardian_words_itself_is_kept(media_root):
    report = tf.make(Report, uuid.uuid4())
    Report.objects.filter(pk=report.pk).update(format="pdf")

    generate_report.apply(args=(report.pk,))

    report.refresh_from_db()
    assert report.status == "failed"
    assert report.error_message == "pdf reports are not generated yet"
