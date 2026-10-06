"""A serializer a view builds is given the view's context (#724).

``self.get_serializer(...)`` passes the request, the view and the format to
the serializer; a serializer built by its class name gets nothing unless the
call says so. Nineteen calls in guardian's views did not: the history of a
vulnerability, the results of a scan, a template's reports, and others.

Their answers were the same without it, because none of those serializers
reads its request on the way out. They do on the way in:
``TeamScopedModelSerializer`` takes the caller's team from the context, and
with no context it accepts no related row at all. A serializer that starts
reading the request for output (a link, a field shown to some roles only)
would have found none, in exactly the routes nobody thought to check. So the
rule is checked where it is cheap to: in the source.
"""

import ast
import uuid
from pathlib import Path

import pytest
from django.test import Client

from tests.unit import team_fixtures as tf

APPS_DIR = Path(__file__).resolve().parents[2] / "apps"
_GW_SECRET = "test-gateway-secret"


def _serializer_calls():
    """(file, line, class name, keyword names) of every serializer built by name."""
    calls = []
    for source in sorted(APPS_DIR.glob("*/views.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id.endswith("Serializer")
            ):
                keywords = {keyword.arg for keyword in node.keywords}
                calls.append((source.parent.name, node.lineno, node.func.id, keywords))
    return calls


def test_views_build_serializers_by_name():
    # Guards the check below against finding nothing to check.
    assert len(_serializer_calls()) >= 20


def test_every_serializer_a_view_builds_gets_the_views_context():
    without = [
        f"apps/{app}/views.py:{line} {name}"
        for app, line, name, keywords in _serializer_calls()
        if "context" not in keywords
    ]
    assert not without, (
        f"{without}: pass context=self.get_serializer_context(), or build the "
        "serializer with self.get_serializer(...)."
    )


@pytest.mark.django_db
def test_a_serializer_built_by_name_sees_the_request(settings, monkeypatch):
    """The history of a vulnerability: its serializer now knows who asks."""
    from apps.vulnerabilities import views
    from apps.vulnerabilities.models import Vulnerability, VulnerabilityHistory

    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    team = uuid.uuid4()
    vulnerability = tf.make(Vulnerability, team)
    VulnerabilityHistory.objects.create(
        vulnerability=vulnerability,
        field_name="severity",
        old_value="low",
        new_value="high",
    )
    seen = []

    class Recording(views.VulnerabilityHistorySerializer):
        def to_representation(self, instance):
            seen.append(self.context.get("request"))
            return super().to_representation(instance)

    monkeypatch.setattr(views, "VulnerabilityHistorySerializer", Recording)

    response = Client(raise_request_exception=False).get(
        f"/api/v1/vulnerabilities/{vulnerability.pk}/history/",
        secure=True,
        HTTP_X_WILDBOX_USER_ID=str(uuid.uuid4()),
        HTTP_X_WILDBOX_TEAM_ID=str(team),
        HTTP_X_WILDBOX_ROLE="admin",
        HTTP_X_WILDBOX_AUTH_TYPE="session",
        HTTP_X_GATEWAY_SECRET=_GW_SECRET,
    )

    assert response.status_code == 200, response.content[:300]
    assert len(response.json()) >= 1
    assert seen and all(request is not None for request in seen)
    assert seen[0].path.endswith("/history/")
