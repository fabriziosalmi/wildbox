"""A source that is offered is one that can be collected (#665, #755).

``manage.py sources add-defaults`` created five sources whose
``source_type`` (``txt``, ``json``) was registered to ``HTTPCollector``, and
``scripts/init_feeds.py`` six whose type (``api``, ``feed``) was registered
to nothing. ``HTTPCollector`` has no ``parse_item`` and cannot be
instantiated, so each of the eleven failed every time the scheduler tried
it, and counted as an active feed all the while.

Now there is one list of defaults, and a default is a source a fresh
deployment can collect from as it is; the registry holds only collectors
that can be instantiated; a source of a type nothing collects cannot be
enabled, and the scheduler disables the ones an earlier release left.

The default source is collected here from a local HTTP server that answers
what its feed answers (a copy of the feed's own format, taken on 6 October
2026), into an in-memory SQLite database: the collector, the validation and
the storage are the service's own.
"""

import asyncio
import inspect
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import CIDR, INET, UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

SERVICE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE))

import manage  # noqa: E402
from app import collectors  # noqa: E402
from app.collectors import (  # noqa: E402
    BaseCollector,
    CollectorRegistry,
    HTTPCollector,
    NoCollector,
    RSSCollector,
)
from app.collectors import sources as source_collectors  # noqa: E402,F401
from app.collectors.defaults import DEFAULT_SOURCES  # noqa: E402
from app.models import (  # noqa: E402
    CollectionRun,
    Domain,
    FileHash,
    Indicator,
    IPAddress,
    Source,
)
from app.scheduler.main import CollectionScheduler  # noqa: E402


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


@compiles(INET, "sqlite")
@compiles(CIDR, "sqlite")
def _address_on_sqlite(_type, _compiler, **_kw):
    return "VARCHAR(64)"


# The format of https://feodotracker.abuse.ch/downloads/ipblocklist.json, with
# documentation addresses in place of the listed ones.
FEODO_FEED = [
    {
        "ip_address": "198.51.100.24",
        "port": 8080,
        "status": "offline",
        "hostname": None,
        "as_number": 64500,
        "as_name": "EXAMPLE-AS",
        "country": "US",
        "first_seen": "2022-06-04 21:24:53",
        "last_online": "2026-03-07",
        "malware": "Emotet",
    },
    {
        "ip_address": "203.0.113.211",
        "port": 443,
        "status": "online",
        "hostname": "host.example.net",
        "as_number": 64501,
        "as_name": "EXAMPLE-NET",
        "country": "US",
        "first_seen": "2026-09-30 10:11:12",
        "last_online": "2026-10-06",
        "malware": "QakBot",
    },
    {
        "ip_address": "192.0.2.77",
        "port": 995,
        "status": "online",
        "hostname": None,
        "as_number": 64502,
        "as_name": "EXAMPLE-ORG",
        "country": "DE",
        "first_seen": "2026-10-01 01:02:03",
        "last_online": "2026-10-06",
        "malware": "Dridex",
    },
]


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [
        model.__table__
        for model in (Source, Indicator, IPAddress, Domain, FileHash, CollectionRun)
    ]
    Source.metadata.create_all(engine, tables=tables)
    factory = sessionmaker(bind=engine, autoflush=False)
    session = factory()
    session.factory = factory
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def sessions(db, monkeypatch):
    """Every session the service opens is on the test's database."""
    monkeypatch.setattr(manage, "get_db_session", db.factory)
    monkeypatch.setattr(collectors, "get_db_session", db.factory)
    monkeypatch.setattr("app.scheduler.main.get_db_session", db.factory)
    return db


class _Feed(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server naming
        body = json.dumps(FEODO_FEED).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture(scope="module")
def feed():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Feed)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/downloads/ipblocklist.json"
    finally:
        server.shutdown()
        server.server_close()


def a_source(source_type, name="a source", enabled=True, status="active"):
    return Source(
        id=uuid.uuid4(),
        name=name,
        source_type=source_type,
        config={},
        headers={},
        rate_limit=100,
        rate_limit_window=60,
        timeout=30,
        collection_interval=3600,
        enabled=enabled,
        status=status,
    )


# --- the registry ----------------------------------------------------------------


def test_every_registered_collector_can_be_instantiated():
    types = CollectorRegistry.list_supported_types()

    assert types == [
        "abuseipdb",
        "feodo_tracker",
        "malware_domain_list",
        "malwarebazaar",
        "phishtank",
        "threatfox",
        "urlvoid",
    ]
    for source_type in types:
        collector = CollectorRegistry.get_collector(a_source(source_type))
        assert isinstance(collector, BaseCollector), source_type
        assert not inspect.isabstract(type(collector)), source_type


@pytest.mark.parametrize(
    "source_type", ["http", "https", "json", "csv", "txt", "rss", "atom", "api", "feed"]
)
def test_a_type_nothing_can_collect_is_not_on_offer(source_type):
    """The first seven were registered to a class that cannot be instantiated."""
    assert not CollectorRegistry.can_collect(source_type)
    assert source_type not in CollectorRegistry.list_supported_types()
    with pytest.raises(NoCollector) as refused:
        CollectorRegistry.get_collector(a_source(source_type))
    assert str(refused.value) == f"No collector for source type '{source_type}'"


@pytest.mark.parametrize("base", [HTTPCollector, RSSCollector, BaseCollector])
def test_a_collector_that_cannot_run_cannot_be_registered(base):
    before = CollectorRegistry.list_supported_types()

    with pytest.raises(TypeError, match="cannot collect: it does not define"):
        CollectorRegistry.register_collector("generic", base)

    assert CollectorRegistry.list_supported_types() == before
    assert not CollectorRegistry.can_collect("generic")


def test_the_type_of_a_source_is_read_without_regard_to_case():
    assert CollectorRegistry.can_collect("Feodo_Tracker")
    assert not CollectorRegistry.can_collect(None)
    assert not CollectorRegistry.can_collect("")


# --- the defaults -----------------------------------------------------------------


def test_there_is_one_list_of_defaults_and_each_can_be_collected():
    assert manage.DEFAULT_SOURCES is DEFAULT_SOURCES
    assert DEFAULT_SOURCES, "a fresh deployment is offered at least one source"
    names = [config["name"] for config in DEFAULT_SOURCES]
    assert len(names) == len(set(names))
    for config in DEFAULT_SOURCES:
        assert CollectorRegistry.can_collect(config["source_type"]), config["name"]
        # Collectable as it is: enabled, and with nothing left to fill in.
        assert config["enabled"] is True, config["name"]
        assert "CONFIGURE" not in json.dumps(config), config["name"]
        assert "YOUR_API_KEY" not in json.dumps(config), config["name"]
        assert config["url"].startswith("https://"), config["name"]


def test_the_second_list_is_gone():
    """scripts/init_feeds.py created sources of types ``api`` and ``feed``."""
    assert not (SERVICE / "scripts" / "init_feeds.py").exists()
    for path in SERVICE.rglob("*.py"):
        if "tests" in path.parts or ".venv" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert '"source_type": "api"' not in text, path
        assert '"source_type": "feed"' not in text, path


def test_add_defaults_creates_sources_that_can_be_collected(sessions):
    assert manage.add_default_sources() is True

    created = sessions.query(Source).all()
    assert [source.name for source in created] == [c["name"] for c in DEFAULT_SOURCES]
    for source in created:
        assert source.enabled is True
        assert isinstance(CollectorRegistry.get_collector(source), BaseCollector)

    # Run again: nothing is added twice.
    assert manage.add_default_sources() is True
    assert sessions.query(Source).count() == len(DEFAULT_SOURCES)


def test_add_defaults_repairs_the_default_an_earlier_release_created(sessions):
    """It made "Feodo Tracker" with source_type "json", which never ran.

    Skipping it because it exists would leave an upgraded deployment with no
    default that works. The row is kept, so its id and its history are, and
    becomes the default it was meant to be.
    """
    old = a_source("json", name="Feodo Tracker", enabled=False, status="error")
    old.url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    old.last_error = "Can't instantiate abstract class HTTPCollector"
    old.error_count = 10
    sessions.add(old)
    sessions.commit()
    kept = old.id

    assert manage.add_default_sources() is True

    sessions.expire_all()
    (source,) = sessions.query(Source).all()
    assert source.id == kept
    assert source.source_type == "feodo_tracker"
    assert (source.enabled, source.status) == (True, "active")
    assert (source.last_error, source.error_count) == (None, 0)
    assert isinstance(CollectorRegistry.get_collector(source), BaseCollector)


def test_add_defaults_leaves_a_default_that_works_as_the_operator_set_it(sessions):
    mine = a_source("feodo_tracker", name="Feodo Tracker", enabled=False)
    mine.url = "https://mirror.example/ipblocklist.json"
    mine.collection_interval = 7200
    sessions.add(mine)
    sessions.commit()

    assert manage.add_default_sources() is True

    sessions.expire_all()
    (source,) = sessions.query(Source).all()
    assert source.url == "https://mirror.example/ipblocklist.json"
    assert source.collection_interval == 7200
    assert source.enabled is False


def test_add_defaults_refuses_a_default_nothing_can_collect(sessions, monkeypatch):
    """What the five defaults were: a type whose collector cannot run."""
    offered = [
        dict(DEFAULT_SOURCES[0]),
        dict(DEFAULT_SOURCES[0], name="PhishTank", source_type="json"),
    ]
    monkeypatch.setattr(manage, "DEFAULT_SOURCES", offered)

    assert manage.add_default_sources() is False

    # Not the collectable one either: the list is wrong, and says so.
    assert sessions.query(Source).count() == 0


def test_a_source_nothing_can_collect_cannot_be_enabled(sessions):
    sessions.add(a_source("json", name="PhishTank", enabled=False, status="inactive"))
    sessions.add(a_source("feodo_tracker", name="Feodo", enabled=False))
    sessions.commit()

    assert manage.enable_source("PhishTank") is False
    assert manage.enable_source("Feodo") is True

    sessions.expire_all()
    enabled = {source.name: source.enabled for source in sessions.query(Source)}
    assert enabled == {"PhishTank": False, "Feodo": True}


# --- the scheduler, on a database an earlier release seeded -------------------------


@pytest.mark.parametrize("status", ["active", "error"])
def test_the_scheduler_disables_what_it_cannot_collect_and_says_why(sessions, status):
    for name, source_type in (
        ("Malware Domain List", "txt"),
        ("PhishTank", "json"),
        ("ThreatFox", "api"),
    ):
        sessions.add(a_source(source_type, name=name, status=status))
    sessions.add(a_source("feodo_tracker", name="Feodo Tracker"))
    sessions.commit()
    scheduler = CollectionScheduler()

    asyncio.run(scheduler._load_sources())

    assert [task.source.name for task in scheduler.tasks.values()] == ["Feodo Tracker"]
    sessions.expire_all()
    rows = {source.name: source for source in sessions.query(Source)}
    assert rows["Feodo Tracker"].enabled is True
    for name, source_type in (
        ("Malware Domain List", "txt"),
        ("PhishTank", "json"),
        ("ThreatFox", "api"),
    ):
        assert rows[name].enabled is False, name
        assert rows[name].status == "inactive", name
        assert rows[name].last_error == f"No collector for source type '{source_type}'"


def test_the_periodic_reload_does_not_schedule_one_either(sessions):
    sessions.add(a_source("json", name="PhishTank"))
    sessions.add(a_source("feodo_tracker", name="Feodo Tracker"))
    sessions.commit()
    scheduler = CollectionScheduler()

    asyncio.run(scheduler._reload_sources())

    assert [task.source.name for task in scheduler.tasks.values()] == ["Feodo Tracker"]
    sessions.expire_all()
    assert sessions.query(Source).filter_by(name="PhishTank").one().enabled is False


# --- the default source, collected ---------------------------------------------------


def test_the_default_source_is_collected_from_its_feed(sessions, feed, monkeypatch):
    (config,) = [c for c in DEFAULT_SOURCES if c["source_type"] == "feodo_tracker"]
    monkeypatch.setattr(manage, "DEFAULT_SOURCES", [dict(config, url=feed)])
    assert manage.add_default_sources() is True
    source = sessions.query(Source).one()

    result = asyncio.run(CollectorRegistry.get_collector(source).run_collection())

    assert result.status is collectors.CollectionStatus.COMPLETED, result
    assert result.error_message is None
    # The two servers that are online; the offline one is not an indicator.
    assert result.items_new == 2, result
    assert result.items_failed == 0, result
    sessions.expire_all()
    stored = {row.value: row for row in sessions.query(Indicator)}
    assert set(stored) == {"203.0.113.211", "192.0.2.77"}
    for row in stored.values():
        assert row.indicator_type == "ip_address"
        assert row.source_id == source.id
        assert row.confidence == "verified"
    assert "qakbot" in stored["203.0.113.211"].tags
    (run,) = sessions.query(CollectionRun).all()
    assert run.status == "completed"
    assert run.items_new == 2
