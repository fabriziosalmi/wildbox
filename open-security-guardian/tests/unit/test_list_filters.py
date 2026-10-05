"""Every filter a list route declares selects the rows it says (#724).

``GET /api/v1/vulnerabilities/?severity=medium`` answered an empty page
whatever the team held, and so did ``?status=``, ``?priority=`` and
``?threat_level=``: the four were ``MultipleChoiceFilter(lookup_expr='in')``,
which compares the column with the *characters* of the value. The dashboard's
severity and status menus send exactly these. Nothing failed: a filter that
matches nothing answers ``200`` with ``"results": []``, and one that ignores
its value answers ``200`` with everything.

So every filter is tried, from the URLconf and not from a list kept by hand:
for each list route, for each filter of the filter set the route uses (its
``filterset_class``, or the one django-filter generates from
``filterset_fields``) and for each of its ``search_fields``, two rows of the
caller's team are stored that differ in what the filter reads, and a value
that describes one of them must answer exactly that row. A filter that cannot
match answers neither and fails; one that ignores its value answers both and
fails.

Most filters name a model field and a lookup, and the two rows and the value
are derived from those (``_derive``). A filter with a method of its own has
its case written out in ``METHOD_CASES``; one added without a case fails
``test_every_filter_has_a_case`` with the instructions.
"""

import uuid
from datetime import timedelta
from decimal import Decimal

import django_filters
import pytest
from django.contrib.auth import get_user_model
from django.db import connection, models
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"

# Lookups that need a JSON containment operator: PostgreSQL has one, the
# in-memory SQLite of the default run does not.
_JSON_CONTAINS = "supports_json_field_contains"


# --- what the URLconf routes -------------------------------------------------


def _walk(patterns, prefix=""):
    for entry in patterns:
        part = str(entry.pattern).lstrip("^").rstrip("$")
        if isinstance(entry, URLResolver):
            yield from _walk(entry.url_patterns, prefix + part)
        elif isinstance(entry, URLPattern):
            yield prefix + part, entry.callback


def _list_routes():
    """{viewset name: (path, viewset class)} for every list route."""
    routes = {}
    for path, callback in _walk(get_resolver().url_patterns):
        view_cls = getattr(callback, "cls", None)
        actions = getattr(callback, "actions", None) or {}
        if view_cls is None or actions.get("get") != "list" or "format" in path:
            continue
        routes.setdefault(view_cls.__name__, ("/" + path, view_cls))
    return routes


def _filterset_class(view_cls):
    if not any(issubclass(b, DjangoFilterBackend) for b in view_cls.filter_backends):
        return None
    view = view_cls()
    view.action = "list"
    return DjangoFilterBackend().get_filterset_class(view, view_cls.queryset.none())


def _declared_filters():
    """{"ViewSet.filter": (path, viewset class, filter)}."""
    found = {}
    for name, (path, view_cls) in LIST_ROUTES.items():
        filterset_class = _filterset_class(view_cls)
        if filterset_class is None:
            continue
        for filter_name, filter_ in filterset_class.base_filters.items():
            found[f"{name}.{filter_name}"] = (path, view_cls, filter_)
    return found


def _declared_searches():
    """{"ViewSet~field": (path, viewset class, field path)}."""
    found = {}
    for name, (path, view_cls) in LIST_ROUTES.items():
        if not any(issubclass(b, SearchFilter) for b in view_cls.filter_backends):
            continue
        for field in getattr(view_cls, "search_fields", None) or ():
            found[f"{name}~{field}"] = (path, view_cls, field)
    return found


LIST_ROUTES = _list_routes()
FILTERS = _declared_filters()
SEARCHES = _declared_searches()


# --- rows that differ in one field -------------------------------------------


def _set(row, **fields):
    """Set fields without save(): no signal, no auto_now, no validation."""
    type(row)._base_manager.filter(pk=row.pk).update(**fields)
    for name, value in fields.items():
        setattr(row, name, value)
    return row


def _new(model, team):
    """A row of ``model`` in ``team``, for a relation a filter follows."""
    if model is get_user_model():
        return tf.user(team)
    return tf.make(model, team)


def _follow(team, row, relation):
    """The row ``relation`` points at, created and attached if there is none."""
    field = type(row)._meta.get_field(relation)
    related = getattr(row, relation)
    if related is None:
        related = _new(field.related_model, team)
        _set(row, **{field.attname: related.pk})
        setattr(row, relation, related)
    return related


def _owner(team, row, path):
    """(the row that holds the last field of ``path``, that field's name)."""
    *relations, name = path.split("__")
    for relation in relations:
        row = _follow(team, row, relation)
    return row, name


def _field(model, path):
    """The model field at the end of ``path``."""
    field = None
    for name in path.split("__"):
        field = model._meta.get_field(name)
        if field.is_relation:
            model = field.related_model
    return field


def _put(team, row, path, value):
    owner, name = _owner(team, row, path)
    _set(owner, **{name: value})


def _relation_path(model, path):
    """``path`` if it ends at a related row, without a trailing primary key.

    ``asset`` and ``asset__id`` both select by the related row's key.
    """
    field = _field(model, path)
    if field.is_relation:
        return path
    if field.primary_key and "__" in path:
        return path.rsplit("__", 1)[0]
    return None


def _related_pk(team, row, path):
    *relations, last = path.split("__")
    for relation in relations:
        row = _follow(team, row, relation)
    return _follow(team, row, last).pk


def _token(field, letter):
    length = min(getattr(field, "max_length", None) or 12, 12)
    return (letter * 2 + uuid.uuid4().hex)[:length]


def _two_values(field, lookup="exact"):
    """Two values of ``field`` and a query: the first row's and not the second's.

    Returns ``(first, second, query)``.
    """
    now = timezone.now()
    if field.choices:
        values = [value for value, _ in field.flatchoices if value not in ("", None)]
        # Neither inside the other ("active" is inside "inactive"), so that a
        # text search for one cannot find the other.
        for first in values:
            for second in values:
                if first not in second and second not in first:
                    return first, second, first
        raise LookupError(f"{field} has no two distinct choices")
    if isinstance(field, models.BooleanField):
        return True, False, "true"
    if isinstance(field, models.GenericIPAddressField):
        return "192.0.2.77", "198.51.100.9", "192.0.2.77"
    if isinstance(field, models.UUIDField):
        first = uuid.uuid4()
        return first, uuid.uuid4(), str(first)
    if isinstance(field, (models.CharField, models.TextField)):
        first, second = _token(field, "q"), _token(field, "z")
        if lookup == "exact":
            return first, second, first
        if lookup == "iexact":
            return first, second, first.upper()
        if lookup == "icontains":
            return first, second, first[1:].upper()
    if isinstance(field, (models.IntegerField, models.FloatField, models.DecimalField)):
        number = Decimal if isinstance(field, models.DecimalField) else int
        if lookup == "exact":
            return number(5), number(6), "5"
        if lookup == "gte":
            return number(8), number(2), "5"
        if lookup == "lte":
            return number(2), number(8), "5"
    if isinstance(field, models.DateField):
        recent, old, between = now, now - timedelta(days=10), now - timedelta(days=5)
        if not isinstance(field, models.DateTimeField):
            recent, old = recent.date(), old.date()
        if lookup == "gte":
            return recent, old, between.isoformat()
        if lookup == "lte":
            return old, recent, between.isoformat()
    raise LookupError(f"no two values for {field} with the lookup {lookup!r}")


# --- the cases ---------------------------------------------------------------


class Probe:
    """A query and the rows, of the two, it must answer."""

    def __init__(self, query, *expected, setup=None):
        self.query = query
        self.expected = expected
        self.setup = setup


def _derive(filter_name, filter_, model):
    """The case of a filter that names a field and a lookup, or None.

    A case is a callable ``(ctx, first, second) -> [Probe, ...]`` that makes
    the two rows differ and says what each query must answer; ``ctx`` has
    the ``team`` of the rows and the ``caller()`` who lists them.
    """
    if filter_.method is not None:
        return None
    path, lookup = filter_.field_name, filter_.lookup_expr
    try:
        field = _field(model, path)
    except Exception:
        return None
    relation = _relation_path(model, path)

    if relation is not None:
        if lookup != "exact":
            return None

        def related(ctx, first, second):
            ours = _related_pk(ctx.team, first, relation)
            theirs = _related_pk(ctx.team, second, relation)
            assert ours != theirs
            return [Probe({filter_name: str(ours)}, first)]

        return related

    if isinstance(filter_, django_filters.DateFromToRangeFilter):

        def date_range(ctx, first, second):
            now = timezone.now()
            old, recent = now - timedelta(days=10), now
            if not isinstance(field, models.DateTimeField):
                old, recent = old.date(), recent.date()
            _put(ctx.team, first, path, old)
            _put(ctx.team, second, path, recent)
            day = (
                lambda days: (now - timedelta(days=days)).date().isoformat()
            )  # noqa: E731
            return [
                Probe({f"{filter_name}_before": day(5)}, first),
                Probe({f"{filter_name}_after": day(5)}, second),
                Probe(
                    {f"{filter_name}_after": day(15), f"{filter_name}_before": day(5)},
                    first,
                ),
            ]

        return date_range

    if isinstance(filter_, django_filters.BooleanFilter):
        if lookup != "exact" or not isinstance(field, models.BooleanField):
            return None

        def boolean(ctx, first, second):
            _put(ctx.team, first, path, True)
            _put(ctx.team, second, path, False)
            return [
                Probe({filter_name: "true"}, first),
                Probe({filter_name: "false"}, second),
            ]

        return boolean

    if isinstance(filter_, django_filters.MultipleChoiceFilter):
        if not field.choices:
            return None

        def any_of(ctx, first, second):
            ours, theirs, _ = _two_values(field)
            _put(ctx.team, first, path, ours)
            _put(ctx.team, second, path, theirs)
            return [
                Probe({filter_name: ours}, first),
                Probe({filter_name: theirs}, second),
                Probe({filter_name: [ours, theirs]}, first, second),
            ]

        return any_of

    try:
        _two_values(field, lookup)
    except LookupError:
        return None

    def by_value(ctx, first, second):
        ours, theirs, query = _two_values(field, lookup)
        _put(ctx.team, first, path, ours)
        _put(ctx.team, second, path, theirs)
        return [Probe({filter_name: query}, first)]

    return by_value


def _yes_no(name, prepare):
    """A true/false filter: ``prepare`` makes the first row a "yes"."""

    def case(ctx, first, second):
        prepare(ctx, first, second)
        return [Probe({name: "true"}, first), Probe({name: "false"}, second)]

    return case


def _asset_in_a_range(ctx, first, second):
    _set(first, ip_address="192.0.2.77")
    _set(second, ip_address="198.51.100.9")
    return [
        Probe({"ip_range": "192.0.2.0/24"}, first),
        # A range that is not a whole number of octets.
        Probe({"ip_range": "192.0.2.64/26"}, first),
        Probe({"ip_range": "192.0.2.77"}, first),
        Probe({"ip_range": "198.51.100.8/31"}, second),
        Probe({"ip_range": "192.0.0.0/8"}, first),
        Probe({"ip_range": "0.0.0.0/0"}, first, second),
        Probe({"ip_range": "192.0.2.128/25"}),
        # Not a network: the start of an address.
        Probe({"ip_range": "198.51."}, second),
    ]


def _asset_tags(ctx, first, second):
    _set(first, tags=["edge", "pci"])
    _set(second, tags=["edge"])
    return [
        Probe({"tags": "pci"}, first),
        Probe({"tags": "edge,pci"}, first),
        Probe({"tags": "edge"}, first, second),
    ]


def _asset_has_vulnerabilities(ctx, first, second):
    from apps.vulnerabilities.models import Vulnerability

    # Two, so that a join that repeats the asset shows.
    for title in ("one", "two"):
        Vulnerability.objects.bulk_create(
            [Vulnerability(asset=first, title=title, description="d")]
        )


def _asset_has_software(ctx, first, second):
    from apps.assets.models import AssetSoftware

    AssetSoftware.objects.create(asset=first, name="nginx", version="1")
    AssetSoftware.objects.create(asset=first, name="nginx", version="2")


def _asset_has_open_ports(ctx, first, second):
    from apps.assets.models import AssetPort

    for number in (22, 443):
        AssetPort.objects.create(
            asset=first, port_number=number, protocol="tcp", state="open"
        )
    AssetPort.objects.create(
        asset=second, port_number=22, protocol="tcp", state="closed"
    )


def _vulnerability_unassigned(ctx, first, second):
    # The first has neither an assignee nor a group. A group alone is an
    # assignment, and so is a user alone.
    _set(first, assigned_to=None, assignee_group="")
    _set(second, assigned_to=None, assignee_group="blue-team")

    def to_a_user():
        _set(second, assigned_to=tf.user(ctx.team), assignee_group="")

    return [
        Probe({"unassigned": "true"}, first),
        Probe({"unassigned": "false"}, second),
        Probe({"unassigned": "true"}, first, setup=to_a_user),
        Probe({"unassigned": "false"}, second),
    ]


def _due(first_due, second_due):
    def prepare(ctx, first, second):
        now = timezone.now()
        _set(first, due_date=now + first_due, status="open")
        _set(second, due_date=now + second_due, status="open")

    return prepare


def _vulnerability_has_tag(ctx, first, second):
    _set(first, tags=["kev", "internet"])
    _set(second, tags=["internet"])
    return [
        Probe({"has_tag": "kev"}, first),
        Probe({"has_tag": "internet"}, first, second),
    ]


def _assessment_overdue(ctx, first, second):
    now = timezone.now()
    _set(first, due_date=now - timedelta(days=1), status="in_progress")
    _set(second, due_date=now + timedelta(days=30), status="in_progress")


def _exception_expired(ctx, first, second):
    now = timezone.now()
    _set(first, valid_until=now - timedelta(days=1))
    _set(second, valid_until=now + timedelta(days=30))


def _exception_needs_review(ctx, first, second):
    now = timezone.now()
    _set(first, review_date=now - timedelta(days=1), status="approved")
    _set(second, review_date=now + timedelta(days=30), status="approved")


def _report_expired(ctx, first, second):
    _set(first, expires_at=timezone.now() - timedelta(days=1))
    _set(second, expires_at=None)


def _dashboard_public(ctx, first, second):
    # A dashboard that is not public is listed for the one who made it.
    _set(first, is_public=True)
    _set(second, is_public=False, created_by=ctx.caller())
    return [
        Probe({"is_public": "true"}, first),
        Probe({"is_public": "false"}, second),
    ]


# The filters with a method of their own, and the ones whose rows need more
# than a field set. NEEDS names a database feature a lookup requires; the
# case is skipped where the database lacks it.
METHOD_CASES = {
    "AssetViewSet.ip_range": _asset_in_a_range,
    "AssetViewSet.tags": _asset_tags,
    "AssetViewSet.has_vulnerabilities": _yes_no(
        "has_vulnerabilities", _asset_has_vulnerabilities
    ),
    "AssetViewSet.has_software": _yes_no("has_software", _asset_has_software),
    "AssetViewSet.has_open_ports": _yes_no("has_open_ports", _asset_has_open_ports),
    "VulnerabilityViewSet.unassigned": _vulnerability_unassigned,
    "VulnerabilityViewSet.overdue": _yes_no(
        "overdue", _due(-timedelta(days=1), timedelta(days=30))
    ),
    "VulnerabilityViewSet.due_today": _yes_no(
        "due_today", _due(timedelta(0), timedelta(days=30))
    ),
    "VulnerabilityViewSet.due_this_week": _yes_no(
        "due_this_week", _due(timedelta(days=2), timedelta(days=30))
    ),
    "VulnerabilityViewSet.has_tag": _vulnerability_has_tag,
    "ComplianceAssessmentViewSet.is_overdue": _yes_no(
        "is_overdue", _assessment_overdue
    ),
    "ComplianceExceptionViewSet.is_expired": _yes_no("is_expired", _exception_expired),
    "ComplianceExceptionViewSet.needs_review": _yes_no(
        "needs_review", _exception_needs_review
    ),
    "ReportViewSet.is_expired": _yes_no("is_expired", _report_expired),
    # Not a method: the list hides the dashboards of others that are not
    # public, so the row that is not must be the caller's.
    "DashboardViewSet.is_public": _dashboard_public,
}

NEEDS = {
    "AssetViewSet.tags": _JSON_CONTAINS,
    "VulnerabilityViewSet.has_tag": _JSON_CONTAINS,
}


def _case(key):
    if key in METHOD_CASES:
        return METHOD_CASES[key]
    _, view_cls, filter_ = FILTERS[key]
    return _derive(key.split(".", 1)[1], filter_, view_cls.queryset.model)


# --- nothing is left untried -------------------------------------------------


def test_the_urlconf_declares_filters():
    # Guards the parametrized tests below against silently covering nothing.
    assert len(LIST_ROUTES) > 35, sorted(LIST_ROUTES)
    assert len(FILTERS) > 140, sorted(FILTERS)
    assert len(SEARCHES) > 70, sorted(SEARCHES)


def test_every_filter_has_a_case():
    missing = sorted(key for key in FILTERS if _case(key) is None)
    assert not missing, (
        f"{missing} have no case. A filter that names a model field and a "
        "lookup gets one by itself; one with a method of its own, or with a "
        "lookup _derive does not know, needs an entry in METHOD_CASES "
        "(tests/unit/test_list_filters.py): two rows that differ in what the "
        "filter reads, and the rows each query must answer (#724)."
    )
    stale = sorted(set(METHOD_CASES) - set(FILTERS))
    assert not stale, f"{stale} are no longer declared: remove their cases."


def test_a_list_has_one_search():
    """``?search=`` is read once (#724).

    The vulnerability list had a ``search`` filter in its filter set and
    DRF's ``SearchFilter``: the two were applied one after the other, so a row
    had to match both, and the fields only the first one searched (the asset's
    address, the scanner, the service) never decided anything.
    """
    twice = sorted(
        key
        for key in FILTERS
        if key.endswith(".search")
        and key.split(".")[0] in {name.split("~")[0] for name in SEARCHES}
    )
    assert not twice, twice


# --- the harness -------------------------------------------------------------


@pytest.fixture
def listing(settings, monkeypatch):
    """``listing(path, team, query) -> [id, ...]``, as an admin of the team."""
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def get(path, team, query=None):
        response = client.get(
            path,
            query or {},
            secure=True,
            HTTP_X_WILDBOX_USER_ID=caller,
            HTTP_X_WILDBOX_TEAM_ID=str(team),
            HTTP_X_WILDBOX_ROLE="admin",
            HTTP_X_WILDBOX_AUTH_TYPE="session",
            HTTP_X_GATEWAY_SECRET=_GW_SECRET,
        )
        assert response.status_code == 200, (query, response.content[:400])
        return [str(row["id"]) for row in response.json()["results"]]

    get.caller = caller
    return get


class Ctx:
    """What a case is given: the team of the rows and who lists them."""

    def __init__(self, team, caller_id):
        self.team = team
        self._caller_id = caller_id

    def caller(self):
        """The caller's row, as the gateway middleware mirrors it."""
        return get_user_model().objects.get_or_create(username=self._caller_id)[0]


def _ids(rows):
    return sorted(str(row.pk) for row in rows)


def _skip_unless_supported(key):
    feature = NEEDS.get(key)
    if feature is not None and not getattr(connection.features, feature):
        pytest.skip(
            f"{connection.vendor} has no JSON containment; guardian runs on "
            "PostgreSQL, and the suite covers this there (DATABASE_URL)"
        )


@pytest.mark.django_db
@pytest.mark.parametrize("key", [pytest.param(key, id=key) for key in sorted(FILTERS)])
def test_a_filter_answers_the_rows_it_describes(listing, key):
    _skip_unless_supported(key)
    case = _case(key)
    if case is None:
        pytest.fail(f"{key} has no case: see test_every_filter_has_a_case")
    path, view_cls, _ = FILTERS[key]
    model = view_cls.queryset.model
    ctx = Ctx(uuid.uuid4(), listing.caller)
    first, second = tf.make(model, ctx.team), tf.make(model, ctx.team)

    probes = case(ctx, first, second)

    # Without the filter both are there: what it leaves out, it leaves out.
    assert sorted(listing(path, ctx.team)) == _ids([first, second])
    for probe in probes:
        if probe.setup is not None:
            probe.setup()
        answered = listing(path, ctx.team, probe.query)
        assert sorted(answered) == _ids(probe.expected), (
            f"{path}?{probe.query} answered {len(answered)} of the two rows; "
            f"it describes {len(probe.expected)}"
        )
        # Once each: a join on a to-many relation repeats a row.
        assert len(answered) == len(set(answered)), (probe.query, answered)


@pytest.mark.django_db
@pytest.mark.parametrize("key", [pytest.param(key, id=key) for key in sorted(SEARCHES)])
def test_a_search_finds_a_row_by_each_field_it_names(listing, key):
    path, view_cls, field_path = SEARCHES[key]
    model = view_cls.queryset.model
    team = uuid.uuid4()
    first, second = tf.make(model, team), tf.make(model, team)
    ours, theirs, query = _two_values(_field(model, field_path), "icontains")
    _put(team, first, field_path, ours)
    _put(team, second, field_path, theirs)

    assert listing(path, team, {"search": query}) == [str(first.pk)]
