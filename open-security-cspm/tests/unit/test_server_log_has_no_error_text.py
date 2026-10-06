"""The log of a running server has no text of an error no route handled (#788).

An error a route does not handle is answered 500 by the shared handler, and
Starlette raises it again for the server, which logs it with its traceback
(``Exception in ASGI application``). A traceback ends with the error's text,
and the text is made from what the route was given. The shared package puts
its own description of the error (class, place, frames) in the place of both
records' tracebacks (``open_security_shared.log_safety``).

The package's tests make uvicorn's record by hand. This one runs the uvicorn
the service pins, in the two orders in which it and the application can
meet, as test_access_log_has_no_query.py does: a release of uvicorn that
logs the error another way fails here and not in production.
"""

import asyncio
import logging
import threading
import time
import urllib.error
import urllib.request
import uuid

import pytest
import uvicorn
from fastapi import FastAPI
from open_security_shared import errors, log_safety
from open_security_shared.errors import install_error_handlers

SECRET = "do-not-log-" + uuid.uuid4().hex
SERVER = {"host": "127.0.0.1", "port": 0, "lifespan": "off"}
UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


class Written(logging.Handler):
    """What a handler with an ordinary formatter writes: the message, and
    the traceback when the record has one."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


@pytest.fixture(autouse=True)
def leave_the_process_as_it_was():
    """As in test_access_log_has_no_query.py: a server started here must not
    change what later tests run under."""
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

    @app.get("/lookup")
    def lookup(value: str):
        try:
            return {"record": int(value)}
        except ValueError as error:
            raise RuntimeError(f"no record for {value!r}") from error

    return app


def serve(app_first: bool):
    """Run one request that raises through uvicorn; what the server's logger
    and the shared handler's wrote for it."""
    server_logger = logging.getLogger(log_safety.SERVER_LOGGER)
    server_logger.filters[:] = []
    if app_first:
        app = application()
        config = uvicorn.Config(app, loop="asyncio", **SERVER)
    else:
        placeholder = FastAPI()
        config = uvicorn.Config(placeholder, loop="asyncio", **SERVER)
        app = application()
        config.app = app
    written = Written()
    handler_logger = logging.getLogger(errors.__name__)
    server_logger.addHandler(written)
    handler_logger.addHandler(written)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started, "uvicorn did not start"
        port = server.servers[0].sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/lookup?value={SECRET}"
        with pytest.raises(urllib.error.HTTPError) as answered:
            urllib.request.urlopen(url, timeout=10)  # noqa: S310
        assert answered.value.code == 500
        assert SECRET not in answered.value.read().decode()

        def both():
            return [line for line in written.lines if line.startswith("ERROR")]

        deadline = time.monotonic() + 5
        while len(both()) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        server.should_exit = True
        thread.join(timeout=20)
        server_logger.removeHandler(written)
        handler_logger.removeHandler(written)
    return both()


@pytest.mark.parametrize(
    "app_first", [True, False], ids=["uvicorn.run(app)", "uvicorn app:app"]
)
def test_the_log_of_a_running_server_has_the_frames_of_the_error_and_not_its_text(
    app_first,
):
    lines = serve(app_first)

    by_logger = {line.split()[1]: line for line in lines}
    assert set(by_logger) == {errors.__name__, log_safety.SERVER_LOGGER}, lines
    for line in lines:
        # main: the text of both errors, in each of the two records.
        assert SECRET not in line
        assert "RuntimeError raised at " in line
        assert "caused by ValueError raised at " in line
        assert "in lookup" in line and 'return {"record": int(value)}' in line
        assert "Traceback (most recent call last)" not in line
    assert by_logger[errors.__name__].startswith(
        f"ERROR {errors.__name__} Unhandled exception: RuntimeError raised at "
    )
    assert "Exception in ASGI application" in by_logger[log_safety.SERVER_LOGGER]


def test_without_the_filter_the_same_server_logs_the_text(monkeypatch):
    """The control: this is what uvicorn writes when nothing rewrites it."""
    monkeypatch.setattr(
        log_safety, "keep_exception_texts_out_of_the_server_log", lambda: None
    )

    lines = serve(app_first=True)

    (server_line,) = [line for line in lines if log_safety.SERVER_LOGGER in line]
    assert f"RuntimeError: no record for '{SECRET}'" in server_line
    assert f"invalid literal for int() with base 10: '{SECRET}'" in server_line
