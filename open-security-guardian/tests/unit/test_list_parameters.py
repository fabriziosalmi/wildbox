"""A list answers what its parameters ask for (#724).

Four things a client could ask a guardian list for and not get, each
answered ``200`` as if it had:

* ``?severity=``, ``?status=``, ``?priority=`` and ``?threat_level=`` on the
  vulnerability list matched nothing (and on ``stats/``, which takes the same
  filters, counted nothing);
* ``?search=`` on the vulnerability list was two searches applied one after
  the other, so the asset's address, the scanner and the service, which only
  one of them read, never found a row;
* ``?page_size=`` was ignored: fifty rows whatever the client asked for;
* ``?ip_range=`` on the asset list listed every address of the range before
  it asked the database, so a large range did not answer at all.

test_list_filters.py tries every filter of every list; this module states
these four as what a client sees, and checks every list request the dashboard
makes against what the list accepts.
"""

import re
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from apps.assets.models import Asset
from apps.core.pagination import GatewayPageNumberPagination
from apps.vulnerabilities.models import Vulnerability
from django.test import Client
from django.urls import Resolver404, resolve
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter, SearchFilter

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
_ASSETS = "/api/v1/assets/assets/"
_VULNERABILITIES = "/api/v1/vulnerabilities/"

REPO_ROOT = Path(__file__).resolve().parents[3]
DASHBOARD_SRC = REPO_ROOT / "open-security-dashboard" / "src"


@pytest.fixture
def get(settings, monkeypatch):
    """``get(url, team, query) -> response``, as an admin through the gateway."""
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(url, team, query=None):
        return client.get(
            url,
            query or {},
            secure=True,
            HTTP_X_FORWARDED_PREFIX="/api/v1/guardian",
            HTTP_X_WILDBOX_USER_ID=caller,
            HTTP_X_WILDBOX_TEAM_ID=str(team),
            HTTP_X_WILDBOX_ROLE="admin",
            HTTP_X_WILDBOX_AUTH_TYPE="session",
            HTTP_X_GATEWAY_SECRET=_GW_SECRET,
        )

    return call


def _page(response):
    assert response.status_code == 200, response.content[:400]
    return response.json()


def _set(row, **fields):
    type(row)._base_manager.filter(pk=row.pk).update(**fields)
    return row


@pytest.fixture
def findings(db):
    """A team with one vulnerability of each severity, and their statuses."""
    team = uuid.uuid4()
    rows = {}
    for severity, status, priority, threat in (
        ("critical", "open", "p1", "imminent"),
        ("high", "in_progress", "p2", "active"),
        ("medium", "open", "p3", "emerging"),
        ("low", "resolved", "p4", "possible"),
        ("info", "false_positive", "p4", "unknown"),
    ):
        rows[severity] = _set(
            tf.make(Vulnerability, team),
            severity=severity,
            status=status,
            priority=priority,
            threat_level=threat,
        )
    return team, rows


# --- the choice filters of the vulnerability list ----------------------------


@pytest.mark.parametrize(
    "query, expected",
    [
        ({"severity": "medium"}, {"medium"}),
        ({"severity": "critical"}, {"critical"}),
        ({"status": "open"}, {"critical", "medium"}),
        ({"status": "in_progress"}, {"high"}),
        ({"priority": "p4"}, {"low", "info"}),
        ({"threat_level": "active"}, {"high"}),
        # Several values of one filter: any of them.
        ({"severity": ["critical", "high"]}, {"critical", "high"}),
        # Two filters: both.
        ({"severity": "critical", "status": "open"}, {"critical"}),
        ({"severity": "low", "status": "open"}, set()),
    ],
)
def test_the_vulnerability_list_filters_by_choice(get, findings, query, expected):
    team, rows = findings

    page = _page(get(_VULNERABILITIES, team, query))

    assert {row["severity"] for row in page["results"]} == expected
    assert page["count"] == len(expected)


def test_a_value_that_is_not_a_choice_is_refused(get, findings):
    team, _ = findings

    response = get(_VULNERABILITIES, team, {"severity": "urgent"})

    assert response.status_code == 400
    assert "severity" in response.json()


def test_stats_counts_what_the_filters_select(get, findings):
    team, _ = findings

    everything = _page(get(_VULNERABILITIES + "stats/", team))
    medium = _page(get(_VULNERABILITIES + "stats/", team, {"severity": "medium"}))
    open_ = _page(get(_VULNERABILITIES + "stats/", team, {"status": "open"}))

    assert everything["total_vulnerabilities"] == 5
    assert (medium["total_vulnerabilities"], medium["medium_count"]) == (1, 1)
    assert (open_["total_vulnerabilities"], open_["open_count"]) == (2, 2)
    assert open_["resolved_count"] == 0


# --- one search ---------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "where, fields",
    [
        ("asset", {"ip_address": "203.0.113.77"}),
        ("vulnerability", {"scanner": "openvas-probe"}),
        ("vulnerability", {"service": "postgresql-probe"}),
    ],
)
def test_the_vulnerability_search_reads_every_field_it_names(get, where, fields):
    team = uuid.uuid4()
    found, other = tf.make(Vulnerability, team), tf.make(Vulnerability, team)
    _set(found.asset if where == "asset" else found, **fields)
    (value,) = fields.values()

    page = _page(get(_VULNERABILITIES, team, {"search": value}))

    assert [row["id"] for row in page["results"]] == [str(found.pk)]
    assert str(other.pk) not in str(page)


@pytest.mark.django_db
def test_every_word_of_a_search_must_be_found(get):
    """DRF's search: each word somewhere in the row, in any of the fields."""
    team = uuid.uuid4()
    both, one = tf.make(Vulnerability, team), tf.make(Vulnerability, team)
    _set(both, title="OpenSSH regreSSHion", scanner="nessus")
    _set(one, title="OpenSSH agent forwarding", scanner="openvas")

    page = _page(get(_VULNERABILITIES, team, {"search": "openssh nessus"}))

    assert [row["id"] for row in page["results"]] == [str(both.pk)]


# --- page_size ------------------------------------------------------------------


@pytest.fixture
def assets(db):
    """A team with 60 assets, 7 of them not active."""
    team = uuid.uuid4()
    Asset.objects.bulk_create(
        Asset(
            team_id=team,
            name=f"asset-{number:02d}",
            status="inactive" if number < 7 else "active",
        )
        for number in range(60)
    )
    return team


def test_page_size_sets_the_size_of_the_page(get, assets):
    page = _page(get(_ASSETS, assets, {"page_size": 7, "ordering": "name"}))

    assert page["count"] == 60
    assert [row["name"] for row in page["results"]] == [
        f"asset-{number:02d}" for number in range(7)
    ]


def test_without_page_size_a_page_is_fifty(get, assets):
    assert len(_page(get(_ASSETS, assets))["results"]) == 50


def test_the_links_keep_the_page_size(get, assets):
    first = _page(get(_ASSETS, assets, {"page_size": 25, "ordering": "name"}))

    assert first["next"] == (
        "/api/v1/guardian/assets/assets/?ordering=name&page=2&page_size=25"
    )
    second = _page(
        get(_ASSETS, assets, {"page_size": 25, "ordering": "name", "page": 2})
    )
    assert second["results"][0]["name"] == "asset-25"
    assert second["previous"] == (
        "/api/v1/guardian/assets/assets/?ordering=name&page_size=25"
    )
    assert second["next"].endswith("page=3&page_size=25")


def test_page_size_has_a_maximum(get, db):
    maximum = GatewayPageNumberPagination.max_page_size
    assert 50 < maximum <= 500, "a maximum a request can afford to serialize"
    team = uuid.uuid4()
    Asset.objects.bulk_create(
        Asset(team_id=team, name=f"asset-{number:04d}") for number in range(maximum + 5)
    )

    page = _page(get(_ASSETS, team, {"page_size": 100000}))

    assert page["count"] == maximum + 5
    assert len(page["results"]) == maximum
    assert _page(get(_ASSETS, team, {"page_size": maximum}))["next"] is not None


@pytest.mark.parametrize("value", ["0", "-1", "abc", "", "1.5"])
def test_a_page_size_that_is_not_a_positive_number_is_the_default(get, assets, value):
    assert len(_page(get(_ASSETS, assets, {"page_size": value}))["results"]) == 50


def test_the_schema_documents_page_size():
    parameters = GatewayPageNumberPagination().get_schema_operation_parameters(None)

    assert "page_size" in {parameter["name"] for parameter in parameters}


# --- ?format= is a filter, not a renderer --------------------------------------


@pytest.mark.django_db
def test_reports_are_filtered_by_format(get):
    from apps.reporting.models import Report

    team = uuid.uuid4()
    pdf, csv = tf.make(Report, team), tf.make(Report, team)
    _set(pdf, format="pdf")
    _set(csv, format="csv")

    page = _page(get("/api/v1/reports/reports/", team, {"format": "pdf"}))

    assert [row["id"] for row in page["results"]] == [str(pdf.pk)]


@pytest.mark.django_db
def test_format_chooses_no_renderer(get):
    """``?format=api`` asked DRF for its HTML renderer; now it is a parameter
    like another, which this list does not have."""
    team = uuid.uuid4()
    tf.make(Asset, team)

    response = get(_ASSETS, team, {"format": "api"})

    assert response.status_code == 200
    assert response["Content-Type"] == "application/json"


# --- ip_range --------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "ip_range", ["10.0.0.0/8", "0.0.0.0/0", "10.128.0.0/9", "10.20.0.0/15"]
)
def test_a_large_range_is_answered_without_listing_it(get, ip_range):
    """``10.0.0.0/8`` built sixteen million strings; ``0.0.0.0/0`` never ended."""
    team = uuid.uuid4()
    inside = _set(tf.make(Asset, team), ip_address="10.200.3.4")
    outside = _set(tf.make(Asset, team), ip_address="192.0.2.1")
    # Never in an IPv4 range, not even in all of IPv4.
    _set(tf.make(Asset, team), ip_address="2001:db8::10")
    tf.make(Asset, team)  # and one without an address
    wanted = {
        "10.20.0.0/15": set(),
        "0.0.0.0/0": {str(inside.pk), str(outside.pk)},
    }.get(ip_range, {str(inside.pk)})

    started = time.monotonic()
    page = _page(get(_ASSETS, team, {"ip_range": ip_range}))

    assert {row["id"] for row in page["results"]} == wanted
    assert time.monotonic() - started < 5


def test_a_range_is_a_bounded_condition():
    """Whatever the prefix length: never more than 128 terms or addresses."""
    import ipaddress

    from apps.assets.filters import network_q

    def size(q):
        return sum(
            size(child) if hasattr(child, "children") else len(_listed(child))
            for child in q.children
        )

    def _listed(child):
        return child[1] if isinstance(child[1], list) else [child[1]]

    for prefix in range(0, 33):
        network = ipaddress.ip_network(f"10.20.30.40/{prefix}", strict=False)
        assert size(network_q(network)) <= 128, prefix


@pytest.mark.django_db
def test_an_ipv6_range_is_listed_or_refused(get):
    team = uuid.uuid4()
    inside = _set(tf.make(Asset, team), ip_address="2001:db8::10")
    _set(tf.make(Asset, team), ip_address="2001:db8::1:10")

    page = _page(get(_ASSETS, team, {"ip_range": "2001:db8::/120"}))
    assert [row["id"] for row in page["results"]] == [str(inside.pk)]

    refused = get(_ASSETS, team, {"ip_range": "2001:db8::/64"})
    assert refused.status_code == 400
    assert "/120" in str(refused.json()["ip_range"])


# --- what the dashboard asks for -------------------------------------------------


def test_the_dashboard_reads_a_count_from_one_row(get, assets):
    """dashboard/page.tsx: ``?page_size=1`` and ``?status=active&page_size=1``."""
    everything = _page(get(_ASSETS, assets, {"page_size": 1}))
    active = _page(get(_ASSETS, assets, {"status": "active", "page_size": 1}))

    assert (everything["count"], len(everything["results"])) == (60, 1)
    assert (active["count"], len(active["results"])) == (53, 1)


@pytest.mark.django_db
def test_the_dashboard_gets_the_three_newest_vulnerabilities(get):
    """dashboard/page.tsx: ``?ordering=-created_at&page_size=3``."""
    from datetime import timedelta

    from django.utils import timezone

    team = uuid.uuid4()
    now = timezone.now()
    rows = [
        _set(tf.make(Vulnerability, team), created_at=now - timedelta(hours=age))
        for age in (5, 1, 4, 2, 3)
    ]

    page = _page(
        get(_VULNERABILITIES, team, {"ordering": "-created_at", "page_size": 3})
    )

    assert [row["id"] for row in page["results"]] == [
        str(rows[1].pk),
        str(rows[3].pk),
        str(rows[4].pk),
    ]
    assert page["count"] == 5


def test_the_vulnerabilities_page_gets_its_search_and_its_menus(get, findings):
    """vulnerabilities/page.tsx: page, search, severity and status together."""
    team, rows = findings
    _set(rows["medium"], title="Weak TLS configuration")
    _set(rows["critical"], title="Weak TLS and more")

    page = _page(
        get(
            _VULNERABILITIES,
            team,
            {"page": 1, "search": "weak tls", "severity": "medium", "status": "open"},
        )
    )

    assert [row["id"] for row in page["results"]] == [str(rows["medium"].pk)]


_CALL = re.compile(r"getGuardianPath\(\s*([`'\"])(.+?)\1\s*\)", re.S)
_APPENDED = re.compile(r"params\.append\(\s*'(\w+)'")
_INITIAL = re.compile(r"new URLSearchParams\(\{([^}]*)\}\)")


def _dashboard_calls():
    """[(file, path, {parameter: value or None})] for every guardian call.

    A query the page builds at run time (``?${params.toString()}``) is read
    from the ``URLSearchParams`` of that file: the names, without values.
    """
    calls = []
    for source in sorted(DASHBOARD_SRC.rglob("*.ts*")):
        text = source.read_text(encoding="utf-8")
        for match in _CALL.finditer(text):
            url = urlsplit(match.group(2))
            parameters = dict(parse_qsl(url.query, keep_blank_values=True))
            if "${" in url.query:
                parameters = {name: None for name in _APPENDED.findall(text)}
                for initial in _INITIAL.findall(text):
                    parameters.update(
                        {name: None for name in re.findall(r"(\w+)\s*:", initial)}
                    )
            calls.append((source.relative_to(REPO_ROOT), url.path, parameters))
    return calls


def _accepted(view_cls):
    """({parameter names a list accepts}, {its ordering fields})."""
    paginator = view_cls.pagination_class
    names = {paginator.page_query_param}
    if paginator.page_size_query_param:
        names.add(paginator.page_size_query_param)
    backends = view_cls.filter_backends
    if any(issubclass(backend, SearchFilter) for backend in backends):
        names.add("search")
    if any(issubclass(backend, OrderingFilter) for backend in backends):
        names.add("ordering")
    if any(issubclass(backend, DjangoFilterBackend) for backend in backends):
        view = view_cls()
        view.action = "list"
        filterset = DjangoFilterBackend().get_filterset_class(
            view, view_cls.queryset.none()
        )
        if filterset is not None:
            names.update(filterset.base_filters)
    return names, set(getattr(view_cls, "ordering_fields", None) or ())


@pytest.mark.skipif(not DASHBOARD_SRC.exists(), reason="needs the repository checkout")
def test_every_dashboard_request_is_one_guardian_understands():
    """Each route exists, and each parameter is one its list reads.

    A parameter a list does not have is ignored without a word, and the page
    shows whatever came back: ``page_size`` was, and before it the path
    itself (#572).
    """
    calls = _dashboard_calls()
    assert len(calls) >= 5, calls
    with_parameters = 0
    for source, path, parameters in calls:
        try:
            match = resolve(path)
        except Resolver404:
            pytest.fail(f"{source} calls {path}, which guardian does not route")
        if not parameters:
            continue
        with_parameters += 1
        accepted, ordering_fields = _accepted(match.func.cls)
        unknown = sorted(set(parameters) - accepted)
        assert not unknown, (
            f"{source} sends {unknown} to {path}, which reads only "
            f"{sorted(accepted)}: the value would be ignored"
        )
        ordering = parameters.get("ordering")
        if ordering:
            assert ordering.lstrip("-") in ordering_fields, (source, path, ordering)
    assert with_parameters >= 4, calls
