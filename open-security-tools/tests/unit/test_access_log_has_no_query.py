"""The service's access log has the path of a request, not its query (#755).

uvicorn writes the request line of every request: ``"GET /api/tools?x=y
HTTP/1.1" 200``. The shared package filters the query string out
(``open_security_shared.log_safety``), from the moment the application
installs its error handlers. Its own tests feed the filter a record shaped
like uvicorn's; this one runs the uvicorn the service pins, so that a
release that words its access record another way fails here and not in
production.

Both orders in which the two can meet are run: ``uvicorn app.main:app``
configures logging and then imports the application; ``uvicorn.run(app)``
has the application first and configures logging after.
"""

import asyncio
import logging
import threading
import time
import urllib.request
import uuid

import pytest
import uvicorn
from fastapi import FastAPI
from open_security_shared import log_safety
from open_security_shared.errors import install_error_handlers

SECRET = "do-not-log-" + uuid.uuid4().hex
SERVER = {"host": "127.0.0.1", "port": 0, "lifespan": "off"}


class Keep(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


@pytest.fixture(autouse=True)
def leave_the_process_as_it_was():
    """A server started here must not change what later tests run under.

    uvicorn configures its three loggers when a Config is made, and a
    server's ``run`` sets the process's event loop policy (to uvloop when it
    is installed). Both are put back, with the access logger's filters.
    """
    policy = asyncio.get_event_loop_policy()
    loggers = {
        name: (
            list(logging.getLogger(name).handlers),
            list(logging.getLogger(name).filters),
            logging.getLogger(name).level,
            logging.getLogger(name).propagate,
            logging.getLogger(name).disabled,
        )
        for name in UVICORN_LOGGERS
    }
    yield
    asyncio.set_event_loop_policy(policy)
    for name, (handlers, filters, level, propagate, disabled) in loggers.items():
        logger = logging.getLogger(name)
        logger.handlers[:] = handlers
        logger.filters[:] = filters
        logger.setLevel(level)
        logger.propagate = propagate
        logger.disabled = disabled


def application():
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/probe")
    def probe():
        return {}

    return app


def serve(app_first: bool):
    """Run a request through uvicorn; return what its access logger wrote."""
    access = logging.getLogger(log_safety.ACCESS_LOGGER)
    access.filters[:] = []
    if app_first:
        app = application()
        config = uvicorn.Config(app, loop="asyncio", **SERVER)
    else:
        # The loader's order: logging is configured when the Config is made,
        # and the application is imported afterwards.
        placeholder = FastAPI()
        config = uvicorn.Config(placeholder, loop="asyncio", **SERVER)
        app = application()
        config.app = app
    keep = Keep()
    access.addHandler(keep)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started, "uvicorn did not start"
        port = server.servers[0].sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/probe?token={SECRET}&q={SECRET}"
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310
            assert response.status == 200
        deadline = time.monotonic() + 5
        while not keep.lines and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        server.should_exit = True
        thread.join(timeout=20)
        access.removeHandler(keep)
    return keep.lines


@pytest.mark.parametrize(
    "app_first", [True, False], ids=["uvicorn.run(app)", "uvicorn app:app"]
)
def test_the_access_log_of_a_running_server_has_no_query_string(app_first):
    lines = serve(app_first)

    assert len(lines) == 1, lines
    assert '"GET /probe HTTP/1.1" 200' in lines[0]
    assert SECRET not in lines[0]
    assert "?" not in lines[0]


def test_without_the_filter_the_same_server_logs_the_query(monkeypatch):
    """The control: this is what uvicorn writes when nothing filters it."""
    monkeypatch.setattr(
        log_safety, "keep_query_strings_out_of_the_access_log", lambda: None
    )

    lines = serve(app_first=True)

    assert len(lines) == 1, lines
    assert f"/probe?token={SECRET}" in lines[0]
