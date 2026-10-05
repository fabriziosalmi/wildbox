"""Every read route of the API must answer without a server error (#499).

The list endpoints of the remediation and integrations apps answered 500:
their ``filterset_fields``, ``search_fields`` or ``ordering`` named fields the
model does not have, and none of their viewsets declared a
``serializer_class``. ``GET /api/v1/scanners/scanners/stats/`` and
``GET /api/v1/reports/metrics/summary/`` failed as well. Nothing caught it
because ``manage.py check`` and the schema do not run a request.

This walks the URLconf and sends an authenticated GET, through the full
middleware stack, to every list route, every list-level GET action, every
list route with ``?search=`` and with each ``?ordering=`` the viewset
accepts, and every detail route with a primary key that does not exist. None
may answer 5xx. A second test stores one row per remediation and
integrations model and reads it back through list and retrieve, so that
the serializers run on real data, and checks that the payloads of an
integration log are not returned. A third reads the scanner statistics over
stored rows.
"""

import re
import uuid

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver

_GW_SECRET = "test-gateway-secret"
# Every row these tests seed belongs to this team, and every request is
# made as a member of it: guardian answers 404 for another team's rows (#642).
TEAM_ID = str(uuid.uuid4())
_PK = re.compile(r"\(\?P<pk>[^)]*\)")


def _walk(patterns, prefix=""):
    for entry in patterns:
        part = str(entry.pattern).lstrip("^").rstrip("$")
        if isinstance(entry, URLResolver):
            yield from _walk(entry.url_patterns, prefix + part)
        elif isinstance(entry, URLPattern):
            yield prefix + part, entry.callback


def _pk_for(view_cls):
    queryset = getattr(view_cls, "queryset", None)
    if queryset is not None:
        if queryset.model._meta.pk.get_internal_type() == "UUIDField":
            return str(uuid.UUID(int=0))
    return "0"


def _read_routes():
    routes = []
    for path, callback in _walk(get_resolver().url_patterns):
        view_cls = getattr(callback, "cls", None)
        actions = getattr(callback, "actions", None) or {}
        action = actions.get("get")
        if not path.startswith("api/v1/") or action is None or "format" in path:
            continue
        url = "/" + _PK.sub(_pk_for(view_cls), path).replace("\\.", ".")
        if "(?P" in url:
            continue
        routes.append(url)
        if action != "list":
            continue
        if getattr(view_cls, "search_fields", None):
            routes.append(url + "?search=x")
        ordering_fields = getattr(view_cls, "ordering_fields", None)
        if isinstance(ordering_fields, (list, tuple)):
            for field in ordering_fields:
                routes.append(f"{url}?ordering={field}")
                routes.append(f"{url}?ordering=-{field}")
    return routes


READ_ROUTES = _read_routes()


@pytest.fixture
def api(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    headers = {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": TEAM_ID,
        "HTTP_X_WILDBOX_ROLE": "admin",
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        "HTTP_X_WILDBOX_AUTH_TYPE": "session",
    }

    def get(url):
        return client.get(url, secure=True, **headers)

    return get


def test_there_are_read_routes():
    # Guards the parametrization below against silently collecting nothing.
    assert len(READ_ROUTES) > 100


@pytest.mark.django_db
@pytest.mark.parametrize("url", READ_ROUTES)
def test_read_route_does_not_answer_5xx(api, url):
    response = api(url)
    assert response.status_code < 500, response.content[:500]


def _seed():
    from apps.assets.models import Asset
    from apps.integrations.models import (
        ExternalSystem,
        IntegrationLog,
        IntegrationMapping,
        NotificationChannel,
        SyncRecord,
        WebhookEndpoint,
    )
    from apps.remediation.models import (
        RemediationComment,
        RemediationStep,
        RemediationTemplate,
        RemediationTicket,
        RemediationWorkflow,
    )
    from apps.vulnerabilities.models import Vulnerability

    user = User.objects.create(username="seed")
    system = ExternalSystem.objects.create(
        team_id=TEAM_ID,
        name="jira",
        system_type="ticketing",
        base_url="https://jira.example.com",
        auth_type="bearer",
    )
    mapping = IntegrationMapping.objects.create(
        system=system, guardian_entity="vulnerability", external_entity="issue"
    )
    asset = Asset.objects.create(name="host", team_id=TEAM_ID)
    # bulk_create skips post_save: the vulnerability history signal is out of
    # scope here (it writes old_value=None into a NOT NULL column).
    (vulnerability,) = Vulnerability.objects.bulk_create(
        [Vulnerability(title="v", description="d", asset=asset)]
    )
    ticket = RemediationTicket.objects.create(
        team_id=TEAM_ID,
        title="t",
        description="d",
        system="jira",
        external_ticket_id="SEC-1",
        priority="high",
    )
    workflow = RemediationWorkflow.objects.create(
        vulnerability=vulnerability,
        title="w",
        remediation_type="patch",
        priority="high",
        ticket=ticket,
    )
    return {
        "remediation/tickets": ticket,
        "remediation/workflows": workflow,
        "remediation/steps": RemediationStep.objects.create(
            workflow=workflow, title="s", description="d", order=1, instructions="i"
        ),
        "remediation/comments": RemediationComment.objects.create(
            workflow=workflow, author=user, content="c"
        ),
        "remediation/templates": RemediationTemplate.objects.create(
            team_id=TEAM_ID,
            name="n", description="d", category="c", remediation_type="patch"
        ),
        "integrations/systems": system,
        "integrations/mappings": mapping,
        "integrations/sync-records": SyncRecord.objects.create(
            system=system,
            mapping=mapping,
            guardian_record_id=vulnerability.pk,
            external_record_id="SEC-1",
            last_sync_direction="guardian_to_external",
        ),
        "integrations/webhooks": WebhookEndpoint.objects.create(
            system=system,
            name="hook",
            endpoint_url="/hooks/jira",
        ),
        "integrations/logs": IntegrationLog.objects.create(
            system=system,
            operation="api_call",
            message="m",
            request_data={"headers": {"Authorization": "Bearer s3cr3t-request"}},
        ),
        "integrations/notifications": NotificationChannel.objects.create(
            team_id=TEAM_ID,
            name="slack",
            channel_type="slack",
        ),
    }


@pytest.mark.django_db
def test_list_and_retrieve_serialize_stored_rows(api):
    for route, obj in _seed().items():
        listed = api(f"/api/v1/{route}/")
        assert listed.status_code == 200, (route, listed.content[:500])
        assert listed.json()["count"] == 1, route
        retrieved = api(f"/api/v1/{route}/{obj.pk}/")
        assert retrieved.status_code == 200, (route, retrieved.content[:500])
        assert retrieved.json()["id"] == str(obj.pk), route
        for response in (listed, retrieved):
            # The payloads of an integration log are not served. The other
            # rows hold no credential to serve: the columns that did are
            # gone (#728, tests/unit/test_no_stored_credentials.py).
            assert b"s3cr3t" not in response.content, route


@pytest.mark.django_db
def test_scanner_stats_counts_stored_rows(api):
    from apps.scanners.models import Scan, Scanner

    scanner = Scanner.objects.create(
        team_id=TEAM_ID,
        name="n",
        scanner_type="nessus", base_url="https://scanner.example.com"
    )
    Scan.objects.create(
        name="s",
        scanner=scanner,
        status="completed",
        duration_seconds=600,
        total_vulnerabilities_found=4,
    )
    response = api("/api/v1/scanners/scanners/stats/")
    assert response.status_code == 200, response.content[:500]
    stats = response.json()
    assert stats["total_scanners"] == 1
    assert stats["completed_scans"] == 1
    assert stats["total_vulnerabilities_found"] == 4
    assert stats["avg_scan_duration_minutes"] == 10.0
    assert stats["scanner_types"] == {"nessus": 1}
    assert stats["scan_frequency"]["last_24h"] == 1
