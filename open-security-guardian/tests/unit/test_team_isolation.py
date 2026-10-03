"""Every viewset keeps each team to its own rows (#642).

guardian kept no team on its data: every viewset served every row, so any
team read, changed and deleted every other team's assets, vulnerabilities,
scanners, integrations, remediation, compliance and reports. The viewsets
are listed from the URLconf, not by hand, so a viewset added later is
covered, and fails here if it is not scoped.

For each viewset, a row owned by team B is stored, and team A (an admin of
its own team) must not find it in any list, nor reach it through any detail
route or detail action: those answer 404, as for a row that does not exist.
Team B itself reaches the row (the positive control: the row is there, and
the 404 is about the team). A's list-level actions answer the same before
and after B's row exists. Requests go through the whole middleware stack
with gateway headers, as in production.
"""

import re
import uuid
from unittest import mock

import pytest
from apps.core.tenancy import (
    TEAM_FIELD,
    TeamScopedModelSerializer,
    TeamScopedViewSetMixin,
    has_global_rows,
    owner_field,
    team_lookup,
)
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework import serializers, viewsets
from rest_framework.relations import ManyRelatedField, RelatedField

from tests.unit import team_fixtures

_GW_SECRET = "test-gateway-secret"
_PK = re.compile(r"\(\?P<pk>[^)]*\)")


def _walk(patterns, prefix=""):
    for entry in patterns:
        part = str(entry.pattern).lstrip("^").rstrip("$")
        if isinstance(entry, URLResolver):
            yield from _walk(entry.url_patterns, prefix + part)
        elif isinstance(entry, URLPattern):
            yield prefix + part, entry.callback


def _viewsets():
    """(list URL, viewset class) for every viewset the URLconf routes."""
    found = {}
    for path, callback in _walk(get_resolver().url_patterns):
        view_cls = getattr(callback, "cls", None)
        actions = getattr(callback, "actions", None) or {}
        if view_cls is None or actions.get("get") != "list" or "format" in path:
            continue
        found.setdefault(view_cls, "/" + path)
    return [(url, cls) for cls, url in found.items()]


VIEWSETS = _viewsets()
IDS = [cls.__name__ for _, cls in VIEWSETS]


def _model(view_cls):
    return view_cls.queryset.model


@pytest.fixture
def api(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)

    def call(method, url, team, data=None, role="admin", user_id=None):
        headers = {
            "HTTP_X_WILDBOX_USER_ID": user_id or str(uuid.uuid4()),
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": role,
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        kwargs = {"secure": True, **headers}
        if data is not None:
            kwargs.update(data=data, content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def teams():
    return uuid.uuid4(), uuid.uuid4()


def _ids(response):
    body = response.json()
    rows = body["results"] if isinstance(body, dict) and "results" in body else body
    return {str(row.get("id")) for row in rows}


# --- static guards: nothing is left unscoped ---------------------------------


def test_the_urlconf_routes_the_viewsets():
    # Guards the parametrization below against silently covering nothing.
    assert len(VIEWSETS) == 40, sorted(IDS)


@pytest.mark.parametrize("url,view_cls", VIEWSETS, ids=IDS)
def test_every_viewset_is_team_scoped(url, view_cls):
    assert issubclass(
        view_cls, TeamScopedViewSetMixin
    ), f"{view_cls.__name__} ({url}) does not narrow its rows to the caller's team"
    # The mixin's get_queryset must be the one that runs: a viewset that
    # overrides it must call super().
    model = _model(view_cls)
    assert team_lookup(model), f"{model.__name__} declares no TEAM_LOOKUP"


@pytest.mark.parametrize("url,view_cls", VIEWSETS, ids=IDS)
def test_every_serializer_writes_for_the_callers_team(url, view_cls):
    """Every serializer a viewset uses scopes its keys and stamps the team."""
    view = view_cls()
    for action in ("list", "retrieve", "create", "update", "partial_update"):
        view.action = action
        view.request = None
        view.format_kwarg = None
        serializer_cls = view.get_serializer_class()
        assert issubclass(serializer_cls, TeamScopedModelSerializer), (
            view_cls.__name__,
            action,
            serializer_cls.__name__,
        )
        fields = serializer_cls(context={"team_id": uuid.uuid4()}).fields
        if team_lookup(serializer_cls.Meta.model) == TEAM_FIELD:
            assert isinstance(fields[TEAM_FIELD], serializers.HiddenField)


# --- the rows of another team are out of reach --------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("url,view_cls", VIEWSETS, ids=IDS)
def test_another_teams_rows_are_not_listed_or_reachable(api, teams, url, view_cls):
    team_a, team_b = teams
    model = _model(view_cls)
    row = team_fixtures.make(model, team_b)
    detail = f"{url}{row.pk}/"

    # Positive control: the owner lists and reads it.
    owner_list = api("get", url, team_b)
    assert owner_list.status_code == 200, owner_list.content[:300]
    assert str(row.pk) in _ids(owner_list)
    assert api("get", detail, team_b).status_code == 200

    listed = api("get", url, team_a)
    assert listed.status_code == 200, listed.content[:300]
    assert str(row.pk) not in _ids(listed)
    assert team_fixtures.MARKER not in listed.content.decode()

    assert api("get", detail, team_a).status_code == 404
    allowed = {m.lower() for m in view_cls.http_method_names}
    if hasattr(view_cls, "update"):
        assert api("put", detail, team_a, data={}).status_code == 404
        assert api("patch", detail, team_a, data={}).status_code == 404
    if hasattr(view_cls, "destroy") and "delete" in allowed:
        assert api("delete", detail, team_a).status_code == 404
    assert model._default_manager.filter(pk=row.pk).exists()


def _detail_actions():
    cases = []
    for url, view_cls in VIEWSETS:
        for action in view_cls.get_extra_actions():
            if not action.detail:
                continue
            for method in action.mapping:
                cases.append(
                    pytest.param(
                        url,
                        view_cls,
                        action.url_path,
                        method,
                        id=f"{view_cls.__name__}.{action.url_path}.{method}",
                    )
                )
    return cases


DETAIL_ACTIONS = _detail_actions()


def test_there_are_detail_actions():
    assert len(DETAIL_ACTIONS) > 50


@pytest.mark.django_db
@pytest.mark.parametrize("url,view_cls,url_path,method", DETAIL_ACTIONS)
def test_another_teams_rows_cannot_be_acted_on(
    api, teams, url, view_cls, url_path, method
):
    team_a, team_b = teams
    model = _model(view_cls)
    row = team_fixtures.make(model, team_b)
    before = model._default_manager.filter(pk=row.pk).values().get()

    response = api(method, f"{url}{row.pk}/{url_path}/", team_a, data={})

    assert response.status_code == 404, response.content[:300]
    assert model._default_manager.filter(pk=row.pk).values().get() == before


def _list_actions():
    cases = []
    for url, view_cls in VIEWSETS:
        for action in view_cls.get_extra_actions():
            if action.detail or "get" not in action.mapping:
                continue
            cases.append(
                pytest.param(
                    url,
                    view_cls,
                    action.url_path,
                    id=f"{view_cls.__name__}.{action.url_path}",
                )
            )
    return cases


LIST_ACTIONS = _list_actions()


def test_there_are_list_actions():
    assert len(LIST_ACTIONS) > 15


@pytest.mark.django_db
@pytest.mark.parametrize("url,view_cls,url_path", LIST_ACTIONS)
def test_list_actions_see_only_the_callers_team(api, teams, url, view_cls, url_path):
    """Statistics, summaries and filtered lists: B's rows change nothing for A."""
    team_a, team_b = teams
    action_url = f"{url}{url_path}/"
    # A has rows of its own, so an action that counts them has something to
    # count both times.
    team_fixtures.make(_model(view_cls), team_a)
    before = api("get", action_url, team_a)
    assert before.status_code == 200, before.content[:300]

    row = team_fixtures.make(_model(view_cls), team_b)
    after = api("get", action_url, team_a)

    assert after.status_code == 200, after.content[:300]
    if isinstance(row.pk, uuid.UUID):  # an integer id would match any digit
        assert str(row.pk) not in after.content.decode()
    assert _comparable(after.json()) == _comparable(before.json())


def _comparable(body):
    """A response body without the fields that change between two calls."""
    if isinstance(body, dict):
        return {k: _comparable(v) for k, v in body.items() if k not in {"last_updated"}}
    if isinstance(body, list):
        return [_comparable(v) for v in body]
    return body


# --- foreign keys: an id of another team is refused like an unknown one -------


def _related_fields(view_cls, action):
    view = view_cls()
    view.action = action
    view.request = None
    view.format_kwarg = None
    serializer_cls = view.get_serializer_class()
    fields = serializer_cls(context={"team_id": uuid.uuid4()}).fields
    model = serializer_cls.Meta.model
    found = []
    for name, field in fields.items():
        if field.read_only:
            continue
        relation = (
            field.child_relation if isinstance(field, ManyRelatedField) else field
        )
        if not isinstance(relation, RelatedField):
            continue
        target = relation.queryset.model
        if team_lookup(target) is None:
            continue
        found.append(
            (
                name,
                target,
                isinstance(field, ManyRelatedField),
                name == owner_field(model),
            )
        )
    return found


def _fk_cases():
    cases = []
    for url, view_cls in VIEWSETS:
        if not hasattr(view_cls, "create"):
            continue
        if view_cls.__name__ == "ScanScheduleViewSet":
            continue  # creating one is refused outright (#548)
        for name, target, many, _ in _related_fields(view_cls, "create"):
            cases.append(
                pytest.param(
                    url, view_cls, name, target, many, id=f"{view_cls.__name__}.{name}"
                )
            )
    return cases


FK_CASES = _fk_cases()


def test_there_are_foreign_keys_to_check():
    assert len(FK_CASES) > 25


@pytest.mark.django_db
@pytest.mark.parametrize("url,view_cls,name,target,many", FK_CASES)
def test_a_foreign_key_to_another_teams_row_is_refused(
    api, teams, url, view_cls, name, target, many
):
    team_a, team_b = teams
    foreign = _referenced(target, team_b)
    own = _referenced(target, team_a)

    def error_for(row):
        value = [str(row.pk)] if many else str(row.pk)
        response = api("post", url, team_a, data={name: value})
        return response, (
            response.json().get(name) if response.status_code == 400 else None
        )

    response, error = error_for(foreign)
    assert response.status_code == 400, (response.status_code, response.content[:300])
    assert error, response.json()
    assert "does not exist" in str(error), error
    # The message for an id that exists nowhere is the same: nothing tells
    # A that B's row exists.
    unknown = type(foreign)(pk=foreign.pk)
    unknown.pk = uuid.uuid4() if isinstance(foreign.pk, uuid.UUID) else 10**9
    _, unknown_error = error_for(unknown)
    assert str(unknown_error).replace(str(unknown.pk), "<id>") == str(error).replace(
        str(foreign.pk), "<id>"
    )
    # Positive control: A's own row is accepted for that field.
    _, own_error = error_for(own)
    assert own_error is None, own_error


def _referenced(model, team_id):
    if model.__name__ == "User":
        return team_fixtures.user(team_id)
    return team_fixtures.make(model, team_id)


@pytest.mark.django_db
def test_a_derived_row_cannot_be_filed_under_a_shared_parent(api, teams):
    """A control under a shared framework would make it every team's."""
    team_a, _ = teams
    shared = team_fixtures.make(_framework_model(), None)
    response = api(
        "post",
        "/api/v1/compliance/controls/",
        team_a,
        data={
            "framework": str(shared.pk),
            "control_id": "X-1",
            "title": "t",
            "description": "d",
            "control_type": "technical",
        },
    )
    assert response.status_code == 400, response.content[:300]
    assert "does not exist" in str(response.json()["framework"])


def _framework_model():
    from apps.compliance.models import ComplianceFramework

    return ComplianceFramework


@pytest.mark.django_db
def test_an_update_cannot_point_at_another_teams_row(api, teams):
    team_a, team_b = teams
    own = team_fixtures.make(_vulnerability_model(), team_a)
    stranger = team_fixtures.user(team_b)

    response = api(
        "patch",
        f"/api/v1/vulnerabilities/{own.pk}/",
        team_a,
        data={"assigned_to": stranger.pk},
    )

    assert response.status_code == 400, response.content[:300]
    assert "does not exist" in str(response.json()["assigned_to"])
    own.refresh_from_db()
    assert own.assigned_to_id is None


def _vulnerability_model():
    from apps.vulnerabilities.models import Vulnerability

    return Vulnerability


# --- team stamping -------------------------------------------------------------


def _create_payloads(team_a):
    framework = team_fixtures.make(_framework_model(), None)
    return {
        "/api/v1/assets/assets/": {"name": "host", "team_id": None},
        "/api/v1/assets/environments/": {"name": "production"},
        "/api/v1/integrations/systems/": {
            "name": "jira",
            "system_type": "ticketing",
            "base_url": "https://jira.example.com",
        },
        "/api/v1/integrations/notifications/": {
            "name": "slack",
            "channel_type": "slack",
        },
        "/api/v1/remediation/tickets/": {
            "title": "t",
            "description": "d",
            "system": "jira",
            "external_ticket_id": "SEC-1",
            "priority": "high",
        },
        "/api/v1/compliance/frameworks/": {"name": "ISO 27001"},
        "/api/v1/compliance/assessments/": {
            "name": "Q3",
            "framework": str(framework.pk),
            "assessment_type": "internal_audit",
        },
        "/api/v1/reports/templates/": {
            "name": "weekly",
            "report_type": "vulnerability_summary",
            "template_content": "x",
        },
        "/api/v1/scanners/scanners/": {
            "name": "nessus",
            "scanner_type": "nessus",
            "base_url": "https://scanner.example.com",
        },
    }


@pytest.mark.django_db
def test_created_rows_belong_to_the_callers_team_whatever_the_body_says(api, teams):
    team_a, team_b = teams
    for url, payload in _create_payloads(team_a).items():
        payload["team_id"] = str(team_b)
        response = api("post", url, team_a, data=payload)
        assert response.status_code == 201, (url, response.content[:300])
        assert TEAM_FIELD not in response.json(), url
        pk = response.json()["id"]
        view_cls = dict((u, c) for u, c in VIEWSETS)[url]
        row = _model(view_cls)._default_manager.get(pk=pk)
        assert str(row.team_id) == str(team_a), url
        assert api("get", f"{url}{pk}/", team_b).status_code == 404, url
        assert api("get", f"{url}{pk}/", team_a).status_code == 200, url


@pytest.mark.django_db
def test_names_are_unique_per_team_not_across_teams(api, teams):
    """A taken name is the team's business: B can reuse it, A is told."""
    team_a, team_b = teams
    for team in (team_a, team_b):
        response = api(
            "post", "/api/v1/assets/environments/", team, data={"name": "prod"}
        )
        assert response.status_code == 201, response.content[:300]
    again = api("post", "/api/v1/assets/environments/", team_a, data={"name": "prod"})
    assert again.status_code == 400, again.content[:300]

    ticket = {
        "title": "t",
        "description": "d",
        "system": "jira",
        "external_ticket_id": "SEC-9",
        "priority": "high",
    }
    for team in (team_a, team_b):
        response = api("post", "/api/v1/remediation/tickets/", team, data=ticket)
        assert response.status_code == 201, response.content[:300]


@pytest.mark.django_db
def test_an_ip_address_is_unique_per_team(api, teams):
    team_a, team_b = teams
    theirs = team_fixtures.make(_asset_model(), team_b)
    _asset_model().objects.filter(pk=theirs.pk).update(ip_address="192.0.2.7")

    with mock.patch("apps.assets.signals.scan_asset_ports"):
        mine = api(
            "post",
            "/api/v1/assets/assets/",
            team_a,
            data={"name": "mine", "ip_address": "192.0.2.7"},
        )
        again = api(
            "post",
            "/api/v1/assets/assets/",
            team_a,
            data={"name": "again", "ip_address": "192.0.2.7"},
        )

    # B's address is not A's business; A's own duplicate still is.
    assert mine.status_code == 201, mine.content[:300]
    assert again.status_code == 400, again.content[:300]


def _asset_model():
    from apps.assets.models import Asset

    return Asset


# --- shared reference data --------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "url,model_name",
    [
        ("/api/v1/compliance/frameworks/", "framework"),
        ("/api/v1/compliance/controls/", "control"),
        ("/api/v1/vulnerabilities/templates/", "vulnerability_template"),
    ],
)
def test_shared_reference_rows_are_read_by_all_and_changed_by_none(
    api, teams, url, model_name
):
    team_a, team_b = teams
    shared = getattr(team_fixtures, model_name)(None)
    assert has_global_rows(type(shared))

    for team in (team_a, team_b):
        assert str(shared.pk) in _ids(api("get", url, team))
        assert api("get", f"{url}{shared.pk}/", team).status_code == 200
        assert api("patch", f"{url}{shared.pk}/", team, data={}).status_code == 404
        assert api("delete", f"{url}{shared.pk}/", team).status_code == 404
    assert type(shared).objects.filter(pk=shared.pk).exists()


# --- rows written before guardian kept a team -------------------------------------


@pytest.mark.django_db
def test_rows_without_a_team_are_reached_by_no_team(api, teams):
    team_a, _ = teams
    legacy = team_fixtures.make(_asset_model(), None)
    legacy_vuln = team_fixtures.make(_vulnerability_model(), None)

    assert str(legacy.pk) not in _ids(api("get", "/api/v1/assets/assets/", team_a))
    assert api("get", f"/api/v1/assets/assets/{legacy.pk}/", team_a).status_code == 404
    assert (
        api("get", f"/api/v1/vulnerabilities/{legacy_vuln.pk}/", team_a).status_code
        == 404
    )


@pytest.mark.django_db
def test_assign_guardian_team_gives_the_legacy_rows_to_a_team(api, teams):
    from django.core.management import call_command

    team_a, team_b = teams
    legacy_asset = team_fixtures.make(_asset_model(), None)
    legacy_vuln = team_fixtures.make(_vulnerability_model(), None)
    shared = team_fixtures.framework(None)
    other = team_fixtures.make(_asset_model(), team_b)

    call_command("assign_guardian_team", "--team", str(team_a), "--dry-run")
    legacy_asset.refresh_from_db()
    assert legacy_asset.team_id is None

    call_command("assign_guardian_team", "--team", str(team_a))

    legacy_asset.refresh_from_db()
    assert str(legacy_asset.team_id) == str(team_a)
    # The vulnerability follows its asset, other teams' rows stay theirs,
    # and shared reference data stays shared.
    assert (
        api("get", f"/api/v1/vulnerabilities/{legacy_vuln.pk}/", team_a).status_code
        == 200
    )
    other.refresh_from_db()
    assert str(other.team_id) == str(team_b)
    shared.refresh_from_db()
    assert shared.team_id is None

    call_command("assign_guardian_team", "--team", str(team_a), "--include-shared")
    shared.refresh_from_db()
    assert str(shared.team_id) == str(team_a)


@pytest.mark.django_db
def test_assign_guardian_team_needs_a_team():
    from django.core.management import call_command
    from django.core.management.base import CommandError

    with pytest.raises(CommandError):
        call_command("assign_guardian_team")


# --- a request without a team is refused ----------------------------------------


@pytest.mark.django_db
def test_a_request_without_a_team_is_refused(settings, monkeypatch):
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    response = Client().get(
        "/api/v1/assets/assets/",
        secure=True,
        HTTP_X_WILDBOX_USER_ID=str(uuid.uuid4()),
        HTTP_X_WILDBOX_ROLE="admin",
        HTTP_X_GATEWAY_SECRET=_GW_SECRET,
    )
    assert response.status_code == 403


def test_viewsets_are_model_viewsets():
    # The detail tests above rely on get_object(); a plain APIView would need
    # its own checks.
    for _, view_cls in VIEWSETS:
        assert issubclass(view_cls, viewsets.GenericViewSet), view_cls
