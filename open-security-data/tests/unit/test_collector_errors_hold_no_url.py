"""A failed collection is logged and stored without the URL it fetched (#755).

A feed's URL can hold its key, in the query string or in the path. The text
of an HTTP client's error ends with the URL, and a failed run logged that
text, with a traceback that repeats it, and stored it as the run's error,
from where the scheduler copies it to ``sources.last_error``.

The collector runs here against a real HTTP server that answers 404, so the
error is the one aiohttp raises, with the one text it has.
"""

import asyncio
import logging
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import aiohttp
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import collectors  # noqa: E402
from app.models import Source  # noqa: E402
from app.utils import database, log_safety  # noqa: E402

KEY = "feedkey" + uuid.uuid4().hex


class _NotFound(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server naming
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture(scope="module")
def feed():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _NotFound)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


class Feed(collectors.HTTPCollector):
    def parse_item(self, raw_item):
        return None


def source(url):
    return Source(
        id=uuid.uuid4(),
        name="feed-under-test",
        source_type="test",
        url=url,
        config={},
        headers={},
        rate_limit=100,
        rate_limit_window=60,
        timeout=10,
    )


def run(url, monkeypatch):
    session = MagicMock()
    monkeypatch.setattr(collectors, "get_db_session", lambda: session)
    result = asyncio.run(Feed(source(url)).run_collection())
    (stored,) = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], collectors.CollectionRun)
    ]
    return result, stored


def test_the_text_of_the_error_does_hold_the_url(feed):
    """Why the text cannot be used: this is what aiohttp says."""

    async def fetch():
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{feed}/1000/{KEY}/host/x?auth={KEY}") as response:
                response.raise_for_status()

    with pytest.raises(aiohttp.ClientResponseError) as raised:
        asyncio.run(fetch())

    assert KEY in str(raised.value)
    assert KEY not in log_safety.describe_error(raised.value)
    assert log_safety.describe_error(raised.value) == "ClientResponseError (HTTP 404)"


def test_a_failed_run_keeps_the_key_out_of_the_log_and_the_record(
    feed, monkeypatch, caplog
):
    url = f"{feed}/1000/{KEY}/host/x?auth={KEY}"

    with caplog.at_level(logging.DEBUG):
        result, stored = run(url, monkeypatch)

    assert result.status is collectors.CollectionStatus.FAILED
    # What is stored with the run, and copied to the source's last_error.
    assert result.error_message == "ClientResponseError (HTTP 404)"
    assert stored.error_message == "ClientResponseError (HTTP 404)"
    assert stored.error_details == {"exception_type": "ClientResponseError"}
    # What is logged: the host that was asked and what it answered.
    assert KEY not in caplog.text
    for record in caplog.records:
        assert KEY not in str(record.__dict__)
        assert not record.exc_info, record.getMessage()
    host = url.split("/")[2]
    assert f"HTTP error collecting from {host}: ClientResponseError (HTTP 404)" in (
        caplog.text
    )
    assert "Collection failed for source feed-under-test" in caplog.text


def test_a_failure_that_is_not_the_feeds_keeps_its_traceback(monkeypatch, caplog):
    """A fault of the service is still the operator's to trace."""
    with caplog.at_level(logging.ERROR):
        result, stored = run("", monkeypatch)  # no URL configured: a ValueError

    assert result.status is collectors.CollectionStatus.FAILED
    assert stored.error_message == "ValueError"
    failed = [r for r in caplog.records if "Collection failed" in r.getMessage()]
    assert failed and all(record.exc_info for record in failed)


@pytest.mark.parametrize(
    "url, host",
    [
        (
            f"https://user:{KEY}@feeds.example.com:8443/{KEY}?k={KEY}",
            "feeds.example.com:8443",
        ),
        (f"https://feeds.example.com/{KEY}", "feeds.example.com"),
        ("http://[2001:db8::1]/feed", "[2001:db8::1]"),
        ("not a url", log_safety.NO_HOST),
        ("", log_safety.NO_HOST),
        (None, log_safety.NO_HOST),
    ],
)
def test_a_url_is_named_by_its_host(url, host):
    assert log_safety.host_of(url) == host


def test_the_engine_hides_the_parameters_of_its_statements(monkeypatch):
    """Neither DB_ECHO nor the text of a database error has the values."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import SQLAlchemyError

    asked = {}

    def on_sqlite(url, **options):
        # The service's options, on a database a unit test has: the pool
        # options are PostgreSQL's and are left out.
        asked.update(options)
        kept = {k: v for k, v in options.items() if k in ("echo", "hide_parameters")}
        return create_engine("sqlite://", **kept)

    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database, "_SessionLocal", None)
    monkeypatch.setattr(database, "create_engine", on_sqlite)
    monkeypatch.setattr(
        database.config.database, "url", "postgresql://user@db.invalid/data"
    )
    engine = database.get_engine()
    try:
        assert asked["hide_parameters"] is True
        assert engine.hide_parameters is True
        with pytest.raises(SQLAlchemyError) as raised:
            with engine.connect() as connection:
                connection.execute(
                    text("SELECT * FROM no_such_table WHERE value = :value"),
                    {"value": KEY},
                )
        assert KEY not in str(raised.value)
        assert "no_such_table" in str(raised.value)
    finally:
        engine.dispose()
