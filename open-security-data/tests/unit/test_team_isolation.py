"""Every route keeps a team to its own rows, and every count to its own too (#755).

``GET /api/v1/stats`` counted every team's collection runs in
``recent_collections``: a number about other teams' sources, on a route any
member of any team can call. Every other figure of that answer, and every
other route, was already scoped (#570, #628, #641).

So that the next count is not forgotten the same way, the routes are listed
from the application, not by hand: each route under ``/api/`` must have a
probe below, and a route added later fails here until it has one. A probe
calls its route as team A against a database that holds rows of team A, of
team B and of nobody (``team_id`` NULL), and checks

- that nothing of team B is in the answer, by value and by count;
- that team A's own rows are (the positive control: the rows are there, and
  what is missing is missing because of the team);
- the documented rule for rows without a team: a source or an indicator
  without one is global, and every team reads and counts it; telemetry
  without one is from before telemetry had a team and belongs to no team.

Team B has more of everything than team A, so a count that takes in team
B's rows is larger than the one expected. The endpoints run against an
in-memory SQLite database.
"""

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import CIDR, INET, UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api import main  # noqa: E402
from app.auth import GatewayUser  # noqa: E402
from app.models import (  # noqa: E402
    CollectionRun,
    Domain,
    FileHash,
    Indicator,
    IPAddress,
    SensorMetadata,
    Source,
    TelemetryEvent,
)


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


@compiles(INET, "sqlite")
@compiles(CIDR, "sqlite")
def _address_on_sqlite(_type, _compiler, **_kw):
    # PostgreSQL's address types, of the enrichment tables the lookups read.
    return "VARCHAR(64)"


TEAM_A = uuid.uuid4()
TEAM_B = uuid.uuid4()
NOW = datetime.now(timezone.utc)
OWNERS = {"a": TEAM_A, "b": TEAM_B, "global": None}
# How many collection runs each owner's source had in the last 24 hours.
RUNS = {"a": 1, "b": 5, "global": 2}
# How many telemetry events each owner's sensor sent.
EVENTS = {"a": 2, "b": 3, "global": 1}
IPS = {"a": "198.51.100.1", "b": "203.0.113.2", "global": "192.0.2.3"}
# An address both teams have an indicator for, each from its own source.
SHARED_IP = "198.51.100.77"
HASHES = {owner: (owner[0] * 64) for owner in OWNERS}

ROUTES = sorted(
    (method, route.path)
    for route in main.app.routes
    if isinstance(route, APIRoute) and route.path.startswith("/api/")
    for method in route.methods - {"HEAD", "OPTIONS"}
)


class World:
    """The database, and what was put in it, by owner."""

    def __init__(self, db):
        self.db = db
        self.sources = {}
        self.indicators = {}

    def client(self, team_id):
        user = GatewayUser(user_id=uuid.uuid4(), team_id=team_id, role="member")
        main.app.dependency_overrides[main.get_current_user] = lambda: user
        main.app.dependency_overrides[main.get_ingest_user] = lambda: user
        main.app.dependency_overrides[main.get_db] = lambda: self.db
        return TestClient(main.app)

    def get(self, path, team_id=TEAM_A, **params):
        response = self.client(team_id).get(path, params=params)
        return response

    def ok(self, path, team_id=TEAM_A, **params):
        response = self.get(path, team_id, **params)
        assert response.status_code == 200, f"{path}: {response.text}"
        return response


def _indicator(db, source, owner, kind, value):
    row = Indicator(
        source_id=source.id,
        team_id=OWNERS[owner],
        indicator_type=kind,
        value=value,
        normalized_value=value.lower(),
        description=f"marker-{owner}",
        threat_types=["malware"],
        tags=[f"tag-{owner}"],
        severity=7,
        active=True,
        first_seen=NOW - timedelta(minutes=30),
        last_seen=NOW - timedelta(minutes=5),
        created_at=NOW - timedelta(hours=1),
    )
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def ids_as_text(monkeypatch):
    """Let SQLite take an id given as text, as PostgreSQL does.

    The routes compare an id column with the string from the URL. PostgreSQL
    reads the string as a UUID; SQLAlchemy's stand-in for the type on SQLite
    wants a UUID object. Nothing about tenancy: without this the two routes
    that take an id could not run here at all.
    """
    real = UUID.bind_processor

    def lenient(self, dialect):
        process = real(self, dialect)
        if process is None:
            return None
        return lambda value: process(
            uuid.UUID(value) if isinstance(value, str) else value
        )

    monkeypatch.setattr(UUID, "bind_processor", lenient)


@pytest.fixture
def world(ids_as_text):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [
        model.__table__
        for model in (
            Source,
            Indicator,
            IPAddress,
            Domain,
            FileHash,
            CollectionRun,
            TelemetryEvent,
            SensorMetadata,
        )
    ]
    Source.metadata.create_all(engine, tables=tables)
    db = sessionmaker(bind=engine, autoflush=False)()
    made = World(db)
    for owner, team_id in OWNERS.items():
        source = Source(
            name=f"{owner}-feed",
            source_type="feodo_tracker",
            team_id=team_id,
            enabled=True,
            status="active",
            description=f"marker-{owner}",
        )
        db.add(source)
        db.flush()
        made.sources[owner] = source
        for number in range(RUNS[owner]):
            db.add(
                CollectionRun(
                    source_id=source.id,
                    status="completed",
                    started_at=NOW - timedelta(hours=1, minutes=number),
                    completed_at=NOW - timedelta(minutes=50 - number),
                )
            )
        # An older run of each, outside the 24 hours the statistics count.
        db.add(
            CollectionRun(
                source_id=source.id,
                status="completed",
                started_at=NOW - timedelta(hours=30),
                completed_at=NOW - timedelta(hours=29),
            )
        )
        made.indicators[owner] = {
            "ip_address": _indicator(db, source, owner, "ip_address", IPS[owner]),
            "domain": _indicator(db, source, owner, "domain", f"{owner}.example"),
            "file_hash": _indicator(db, source, owner, "file_hash", HASHES[owner]),
        }
        if team_id is not None:
            made.indicators[owner]["shared"] = _indicator(
                db, source, owner, "ip_address", SHARED_IP
            )
        sensor_id = f"sensor-{owner}"
        db.add(
            SensorMetadata(
                team_id=team_id,
                sensor_id=sensor_id,
                hostname=f"host-{owner}",
                first_seen=NOW - timedelta(hours=2),
                last_seen=NOW - timedelta(minutes=1),
                active=True,
                total_events=EVENTS[owner],
            )
        )
        for number in range(EVENTS[owner]):
            db.add(
                TelemetryEvent(
                    team_id=team_id,
                    sensor_id=sensor_id,
                    event_type="security_event",
                    timestamp=NOW - timedelta(minutes=10 + number),
                    source_host=f"host-{owner}",
                    event_data={"marker": f"marker-{owner}"},
                    ingested_at=NOW,
                    severity=1,
                    tags=[],
                )
            )
    db.commit()
    try:
        yield made
    finally:
        main.app.dependency_overrides.clear()
        db.close()
        engine.dispose()


def nothing_of_team_b(response):
    """No value of team B's rows is anywhere in the answer."""
    text = response.text
    for value in (
        "marker-b",
        "b-feed",
        "tag-b",
        "sensor-b",
        "host-b",
        "b.example",
        IPS["b"],
        HASHES["b"],
    ):
        assert value not in text, value


# --- one probe per route ----------------------------------------------------------


def stats(world):
    body = world.ok("/api/v1/stats").json()
    # Team A's and the global rows: 3 + 1 shared address, and 3.
    assert body["total_indicators"] == 7
    assert body["indicator_types"] == {"ip_address": 3, "domain": 2, "file_hash": 2}
    assert body["total_sources"] == 2
    assert body["active_sources"] == 2
    # The runs of team A's source and of the global one: not team B's five.
    assert body["recent_collections"] == RUNS["a"] + RUNS["global"]
    # And team B, asked the same, counts its own.
    theirs = world.ok("/api/v1/stats", TEAM_B).json()
    assert theirs["recent_collections"] == RUNS["b"] + RUNS["global"]


def search(world):
    response = world.ok("/api/v1/indicators/search")
    nothing_of_team_b(response)
    assert response.json()["total"] == 7
    assert {item["description"] for item in response.json()["indicators"]} == {
        "marker-a",
        "marker-global",
    }
    assert world.ok("/api/v1/indicators/search", q="marker-b").json()["total"] == 0
    theirs = str(world.sources["b"].id)
    assert world.ok("/api/v1/indicators/search", source_id=theirs).json()["total"] == 0
    assert world.ok("/api/v1/indicators/search", q=SHARED_IP).json()["total"] == 1


def indicator(world):
    for kind, row in world.indicators["b"].items():
        assert world.get(f"/api/v1/indicators/{row.id}").status_code == 404, kind
    for owner in ("a", "global"):
        for row in world.indicators[owner].values():
            world.ok(f"/api/v1/indicators/{row.id}")


def lookup(world):
    wanted = [
        {"indicator_type": "ip_address", "value": IPS["b"]},
        {"indicator_type": "domain", "value": "b.example"},
        {"indicator_type": "file_hash", "value": HASHES["b"]},
        {"indicator_type": "ip_address", "value": IPS["a"]},
        {"indicator_type": "ip_address", "value": IPS["global"]},
        {"indicator_type": "ip_address", "value": SHARED_IP},
    ]
    response = world.client(TEAM_A).post(
        "/api/v1/indicators/lookup", json={"indicators": wanted}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert [result["found"] for result in body["results"]] == [
        False,
        False,
        False,
        True,
        True,
        True,
    ]
    assert body["total_found"] == 3
    # The address both teams know: team A's indicator, and not team B's too.
    assert len(body["results"][5]["matches"]) == 1
    assert "marker-b" not in response.text


def ip(world):
    assert world.get(f"/api/v1/ips/{IPS['b']}").status_code == 404
    assert world.ok(f"/api/v1/ips/{IPS['a']}").json()["threat_count"] == 1
    assert world.ok(f"/api/v1/ips/{IPS['global']}").json()["threat_count"] == 1
    shared = world.ok(f"/api/v1/ips/{SHARED_IP}")
    assert shared.json()["threat_count"] == 1
    nothing_of_team_b(shared)


def domain(world):
    assert world.get("/api/v1/domains/b.example").status_code == 404
    assert world.ok("/api/v1/domains/a.example").json()["threat_count"] == 1
    assert world.ok("/api/v1/domains/global.example").json()["threat_count"] == 1


def file_hash(world):
    assert world.get(f"/api/v1/hashes/{HASHES['b']}").status_code == 404
    assert world.ok(f"/api/v1/hashes/{HASHES['a']}").json()["threat_count"] == 1
    assert world.ok(f"/api/v1/hashes/{HASHES['global']}").json()["threat_count"] == 1


def sources(world):
    for enabled_only in (True, False):
        response = world.ok("/api/v1/sources", enabled_only=enabled_only)
        nothing_of_team_b(response)
        assert {item["name"] for item in response.json()} == {"a-feed", "global-feed"}


def realtime_feed(world):
    response = world.ok("/api/v1/feeds/realtime")
    nothing_of_team_b(response)
    lines = [json.loads(line) for line in response.text.splitlines() if line]
    assert len(lines) == 7
    assert {line["description"] for line in lines} == {"marker-a", "marker-global"}


def dashboard(world):
    body = world.ok("/api/v1/dashboard/threat-intel").json()
    assert body["total_feeds"] == 2
    assert body["active_feeds"] == 2
    assert body["new_indicators"] == 7


def ingest(world):
    """Team A names its sensor as team B does: team B's record is not touched."""
    before = world.db.query(TelemetryEvent).filter_by(team_id=TEAM_B).count()
    response = world.client(TEAM_A).post(
        "/api/v1/ingest",
        json={
            "events": [
                {
                    "sensor_id": "sensor-b",
                    "event_type": "security_event",
                    "timestamp": NOW.isoformat(),
                    "event_data": {"marker": "marker-a"},
                }
            ]
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["events_ingested"] == 1
    world.db.expire_all()
    theirs = (
        world.db.query(SensorMetadata)
        .filter_by(team_id=TEAM_B, sensor_id="sensor-b")
        .one()
    )
    assert theirs.total_events == EVENTS["b"]
    assert world.db.query(TelemetryEvent).filter_by(team_id=TEAM_B).count() == before
    mine = (
        world.db.query(SensorMetadata)
        .filter_by(team_id=TEAM_A, sensor_id="sensor-b")
        .one()
    )
    assert mine.total_events == 1


def telemetry_events(world):
    response = world.ok("/api/v1/telemetry/events")
    nothing_of_team_b(response)
    assert len(response.json()) == EVENTS["a"]
    assert {event["sensor_id"] for event in response.json()} == {"sensor-a"}
    assert world.ok("/api/v1/telemetry/events", sensor_id="sensor-b").json() == []
    # From before telemetry had a team: no team's.
    assert world.ok("/api/v1/telemetry/events", sensor_id="sensor-global").json() == []


def sensors(world):
    for active_only in (True, False):
        response = world.ok("/api/v1/sensors", active_only=active_only)
        nothing_of_team_b(response)
        assert [sensor["sensor_id"] for sensor in response.json()] == ["sensor-a"]


def sensor(world):
    assert world.ok("/api/v1/sensors/sensor-a").json()["total_events"] == EVENTS["a"]
    assert world.get("/api/v1/sensors/sensor-b").status_code == 404
    assert world.get("/api/v1/sensors/sensor-global").status_code == 404


def telemetry_stats(world):
    body = world.ok("/api/v1/telemetry/stats").json()
    assert body["total_events"] == EVENTS["a"]
    assert body["active_sensors"] == 1
    assert body["events_by_type"] == {"security_event": EVENTS["a"]}
    theirs = world.ok("/api/v1/telemetry/stats", sensor_id="sensor-b").json()
    assert theirs["total_events"] == 0
    assert theirs["events_by_type"] == {}


PROBES = {
    ("GET", "/api/v1/stats"): stats,
    ("GET", "/api/v1/indicators/search"): search,
    ("GET", "/api/v1/indicators/{indicator_id}"): indicator,
    ("POST", "/api/v1/indicators/lookup"): lookup,
    ("GET", "/api/v1/ips/{ip_address}"): ip,
    ("GET", "/api/v1/domains/{domain}"): domain,
    ("GET", "/api/v1/hashes/{file_hash}"): file_hash,
    ("GET", "/api/v1/sources"): sources,
    ("GET", "/api/v1/feeds/realtime"): realtime_feed,
    ("GET", "/api/v1/dashboard/threat-intel"): dashboard,
    ("POST", "/api/v1/ingest"): ingest,
    ("GET", "/api/v1/telemetry/events"): telemetry_events,
    ("GET", "/api/v1/sensors"): sensors,
    ("GET", "/api/v1/sensors/{sensor_id}"): sensor,
    ("GET", "/api/v1/telemetry/stats"): telemetry_stats,
}


def test_the_application_has_routes_for_this_to_read():
    assert len(ROUTES) >= 15, ROUTES


def test_every_route_has_a_probe_and_every_probe_a_route():
    """A route added later is listed here until someone writes its probe."""
    assert sorted(PROBES) == ROUTES


@pytest.mark.parametrize(
    "route", ROUTES, ids=[f"{method} {path}" for method, path in ROUTES]
)
def test_a_team_reads_and_counts_its_own_rows_and_the_global_ones(world, route):
    assert route in PROBES, f"{route} has no probe: write one before the route ships"
    PROBES[route](world)


def test_the_last_update_of_the_dashboard_is_not_another_teams(world):
    """Team B's source ran last of all; team A is told of its own."""
    late = CollectionRun(
        source_id=world.sources["b"].id,
        status="completed",
        started_at=NOW - timedelta(minutes=2),
        completed_at=NOW - timedelta(minutes=1),
    )
    world.db.add(late)
    world.db.commit()

    body = world.ok("/api/v1/dashboard/threat-intel").json()

    told = datetime.fromisoformat(body["last_updated"])
    if told.tzinfo is None:
        told = told.replace(tzinfo=timezone.utc)
    assert told < NOW - timedelta(minutes=30)


def test_a_run_of_a_source_without_a_team_counts_for_every_team(world):
    """The documented rule: a source with no team is global."""
    for team_id in (TEAM_A, TEAM_B, uuid.uuid4()):
        body = world.ok("/api/v1/stats", team_id).json()
        own = {TEAM_A: RUNS["a"], TEAM_B: RUNS["b"]}.get(team_id, 0)
        assert body["recent_collections"] == own + RUNS["global"]


def test_a_run_older_than_a_day_is_not_recent(world):
    body = world.ok("/api/v1/stats").json()

    # Each source also has a run of 30 hours ago.
    assert body["recent_collections"] == 3
    assert world.db.query(CollectionRun).count() == sum(RUNS.values()) + 3
