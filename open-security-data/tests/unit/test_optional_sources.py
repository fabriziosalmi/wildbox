"""An optional source is one that can be collected but is not a default.

``manage.py sources add-optional`` creates one of ``OPTIONAL_SOURCES`` by
name. NetAPI Honeypot is the first: a CSV of the addresses that attacked
NetAPI's honeypot sensors within the last 48 hours. It is collected here from
a local HTTP server that answers in the feed's format (with documentation
addresses), into an in-memory SQLite database, like the default source in
``test_default_sources_can_run.py``.
"""

import asyncio
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
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
from app.collectors import BaseCollector, CollectorRegistry  # noqa: E402
from app.collectors import sources as source_collectors  # noqa: E402
from app.collectors.defaults import DEFAULT_SOURCES, OPTIONAL_SOURCES  # noqa: E402
from app.models import (  # noqa: E402
    CollectionRun,
    Domain,
    FileHash,
    Indicator,
    IPAddress,
    Source,
)


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


@compiles(INET, "sqlite")
@compiles(CIDR, "sqlite")
def _address_on_sqlite(_type, _compiler, **_kw):
    return "VARCHAR(64)"


# The format of the NetAPI feed, with documentation addresses and networks.
NETAPI_FEED = (
    "ip,first_seen,last_seen,category,top_threat,threats,country,asn,as_name,sensors\r\n"
    "192.0.2.10,2026-11-20T05:51:56Z,2026-11-24T05:54:26Z,C,ms17-010-exploit,"
    "ms17-010-exploit,TH,64500,\"EXAMPLE-NET - Example, Ltd\",6\r\n"
    "198.51.100.20,2026-11-24T04:50:55Z,2026-11-24T07:27:23Z,B,ssh-bruteforce,"
    "ssh-bruteforce|telnet-bruteforce,US,64501,EXAMPLE-AS,2\r\n"
    "203.0.113.30,2026-11-23T01:02:03Z,2026-11-24T09:00:00Z,A,malware-download,"
    "malware-download|bad tag,DE,64502,EXAMPLE-ORG,1\r\n"
    "203.0.113.40,2026-11-24T01:00:00Z,2026-11-24T02:00:00Z,D,form-spam,form-spam,NL,,,1\r\n"
    "203.0.113.50,2026-11-24T01:00:00Z,2026-11-24T02:00:00Z,Z,unknown,unknown,NL,,,1\r\n"
)

HEADER = NETAPI_FEED.split("\r\n")[0] + "\r\n"

BODIES = {
    "/feed.csv": ("text/csv;charset=UTF-8", NETAPI_FEED),
    "/bom.csv": ("text/csv;charset=UTF-8", "﻿" + NETAPI_FEED),
    "/error.html": ("text/html", "<html><body>Service unavailable</body></html>"),
    "/header-only.csv": ("text/csv;charset=UTF-8", HEADER),
    "/unknown-categories.csv": (
        "text/csv;charset=UTF-8",
        HEADER + "192.0.2.10,,2026-11-24T05:54:26Z,exploit,x,x,TH,,,1\r\n",
    ),
}


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
    return db


class _Feed(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server naming
        if self.path not in BODIES:
            self.send_error(503)
            return
        content_type, text = BODIES[self.path]
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Feed)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def netapi_config():
    (config,) = [c for c in OPTIONAL_SOURCES if c["source_type"] == "netapi_honeypot"]
    return config


# --- the list ------------------------------------------------------------------------


def test_optional_sources_can_be_collected_and_are_not_defaults():
    defaults = {c["name"] for c in DEFAULT_SOURCES}
    names = [c["name"] for c in OPTIONAL_SOURCES]
    assert len(names) == len(set(names))
    for config in OPTIONAL_SOURCES:
        assert config["name"] not in defaults, config["name"]
        assert config["source_type"] not in {c["source_type"] for c in DEFAULT_SOURCES}
        assert CollectorRegistry.can_collect(config["source_type"]), config["name"]
        assert config["url"].startswith("https://"), config["name"]


# --- add-optional ----------------------------------------------------------------------


def test_add_optional_creates_the_source_once(sessions):
    assert manage.add_optional_source("netapi honeypot") is True

    (source,) = sessions.query(Source).all()
    assert source.name == "NetAPI Honeypot"
    assert source.source_type == "netapi_honeypot"
    assert source.enabled is True
    # The limiter counts items: the feed's rows must fit in an hour.
    assert (source.rate_limit, source.rate_limit_window) == (100000, 3600)
    assert isinstance(CollectorRegistry.get_collector(source), BaseCollector)

    assert manage.add_optional_source("NetAPI Honeypot") is True
    assert sessions.query(Source).count() == 1


def test_add_optional_leaves_the_operators_source_alone(sessions):
    mine = Source(
        id=uuid.uuid4(),
        name="NetAPI Honeypot",
        source_type="netapi_honeypot",
        url="https://netapi.com/api2/?method=compromised&dataset_type=ip&format=csv&category=A",
        enabled=False,
        config={},
        headers={},
    )
    sessions.add(mine)
    sessions.commit()

    assert manage.add_optional_source("NetAPI Honeypot") is True

    sessions.expire_all()
    (source,) = sessions.query(Source).all()
    assert source.url.endswith("&category=A")
    assert source.enabled is False


def test_add_optional_refuses_a_name_it_does_not_know(sessions):
    assert manage.add_optional_source("Feodo Tracker") is False
    assert sessions.query(Source).count() == 0


def test_add_defaults_does_not_create_an_optional_source(sessions):
    assert manage.add_default_sources() is True
    names = {source.name for source in sessions.query(Source)}
    assert "NetAPI Honeypot" not in names


# --- the collector ------------------------------------------------------------------------


def test_the_netapi_source_is_collected_from_its_feed(sessions, server, monkeypatch):
    monkeypatch.setattr(
        manage, "OPTIONAL_SOURCES", [dict(netapi_config(), url=server + "/feed.csv")]
    )
    assert manage.add_optional_source("NetAPI Honeypot") is True
    source = sessions.query(Source).one()

    result = asyncio.run(CollectorRegistry.get_collector(source).run_collection())

    assert result.status is collectors.CollectionStatus.COMPLETED, result
    # Four categories it knows; the row of category Z is skipped.
    assert result.items_new == 4, result
    assert result.items_failed == 0, result
    assert result.items_skipped == 1, result
    sessions.expire_all()
    stored = {row.value: row for row in sessions.query(Indicator)}
    assert set(stored) == {"192.0.2.10", "198.51.100.20", "203.0.113.30", "203.0.113.40"}

    exploit = stored["192.0.2.10"]
    assert exploit.indicator_type == "ip_address"
    # 48 hours after its last attack (SQLite hands the time back naive).
    assert exploit.expires_at.replace(tzinfo=None) == datetime(2026, 11, 26, 5, 54, 26)
    assert exploit.threat_types == ["exploit"]
    assert exploit.severity == 7
    assert exploit.confidence == "high"
    assert exploit.tags == ["honeypot", "netapi", "exploit", "ms17-010-exploit"]
    # Quoted, with a comma: read whole by the csv module.
    assert exploit.indicator_metadata["as_name"] == "EXAMPLE-NET - Example, Ltd"
    assert exploit.indicator_metadata["asn"] == 64500
    assert exploit.indicator_metadata["sensors"] == 6

    guessing = stored["198.51.100.20"]
    assert guessing.threat_types == ["suspicious"]
    assert guessing.tags == [
        "honeypot", "netapi", "password-guessing", "ssh-bruteforce", "telnet-bruteforce"
    ]
    assert guessing.indicator_metadata["threats"] == ["ssh-bruteforce", "telnet-bruteforce"]

    # A threat name the tag validator refuses is left out of the tags only.
    malware = stored["203.0.113.30"]
    assert malware.threat_types == ["malware"]
    assert malware.severity == 8
    assert "bad tag" not in malware.tags
    assert malware.indicator_metadata["threats"] == ["malware-download", "bad tag"]

    spam = stored["203.0.113.40"]
    assert spam.threat_types == ["spam"]
    assert spam.indicator_metadata["asn"] is None
    assert spam.indicator_metadata["as_name"] is None


def test_an_item_expires_48_hours_after_its_last_attack():
    collector = source_collectors.NetAPIHoneypotCollector(
        Source(id=uuid.uuid4(), name="n", source_type="netapi_honeypot", config={}, headers={})
    )
    item = collector.parse_item({
        "ip": "192.0.2.10", "category": "C", "top_threat": "ms17-010-exploit",
        "threats": "ms17-010-exploit", "last_seen": "2026-11-24T05:54:26Z",
    })
    assert item["expires_at"] == datetime(2026, 11, 26, 5, 54, 26, tzinfo=timezone.utc)

    # A time without an offset is UTC: it compares with an aware clock.
    item = collector.parse_item({
        "ip": "192.0.2.10", "category": "C", "last_seen": "2026-11-24T05:54:26",
    })
    assert item["expires_at"] == datetime(2026, 11, 26, 5, 54, 26, tzinfo=timezone.utc)

    # No readable last attack time: 48 hours from now.
    for unreadable in ("", "yesterday"):
        item = collector.parse_item(
            {"ip": "192.0.2.10", "category": "B", "last_seen": unreadable}
        )
        left = item["expires_at"] - datetime.now(timezone.utc)
        assert timedelta(hours=47) < left <= timedelta(hours=48)


def collect(sessions, server, monkeypatch, path):
    monkeypatch.setattr(
        manage, "OPTIONAL_SOURCES", [dict(netapi_config(), url=server + path)]
    )
    assert manage.add_optional_source("NetAPI Honeypot") is True
    source = sessions.query(Source).one()
    return asyncio.run(CollectorRegistry.get_collector(source).run_collection())


def test_a_leading_byte_order_mark_is_not_part_of_the_first_column(
    sessions, server, monkeypatch
):
    result = collect(sessions, server, monkeypatch, "/bom.csv")

    assert result.status is collectors.CollectionStatus.COMPLETED, result
    assert result.items_new == 4, result


@pytest.mark.parametrize(
    "path",
    [
        # An error page answered with 200.
        "/error.html",
        # A header and no rows: a feed of the last 48 hours is never empty.
        "/header-only.csv",
        # Rows, none of a category the collector knows: a changed feed.
        "/unknown-categories.csv",
        # An HTTP error.
        "/missing.csv",
    ],
)
def test_a_feed_it_cannot_read_fails_the_run(sessions, server, monkeypatch, path):
    """A failure is not an empty collection that completed."""
    result = collect(sessions, server, monkeypatch, path)

    assert result.status is collectors.CollectionStatus.FAILED, result
    assert sessions.query(Indicator).count() == 0
