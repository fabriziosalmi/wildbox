"""What the shared package keeps out of every service's log (#755).

* the query string of a request, which uvicorn's access log wrote with the
  request line;
* the URL of each request an HTTP client library sends, which httpx logs at
  INFO;
* the detail of an HTTP error, which the shared handler put in its record:
  a detail is the answer to the caller and often names what they sent;
* the values of a request's headers, which the request-logging middleware
  recorded for every header but three, X-Gateway-Secret among the rest.

The access-log filter is also tested against a running uvicorn, in the unit
suites of the services, with the uvicorn each of them pins: this suite does
not install one.
"""

import logging
import uuid

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from open_security_shared import log_safety
from open_security_shared.errors import install_error_handlers
from open_security_shared.security_middleware import RequestLoggingMiddleware

SECRET = "do-not-log-" + uuid.uuid4().hex
# uvicorn's own format and argument order (uvicorn/protocols/http/*_impl.py).
ACCESS_FORMAT = '%s - "%s %s HTTP/%s" %d'


def access_record(path, logger_name=log_safety.ACCESS_LOGGER):
    return logging.LogRecord(
        logger_name,
        logging.INFO,
        __file__,
        1,
        ACCESS_FORMAT,
        ("203.0.113.9:51000", "GET", path, "1.1", 200),
        None,
    )


@pytest.fixture
def clean_loggers():
    """The loggers this module touches, as a fresh process has them."""
    access = logging.getLogger(log_safety.ACCESS_LOGGER)
    filters = list(access.filters)
    levels = {
        name: logging.getLogger(name).level for name in log_safety.QUIETED_LOGGERS
    }
    access.filters[:] = [
        item for item in filters if not isinstance(item, log_safety.WithoutQueryString)
    ]
    for name in levels:
        logging.getLogger(name).setLevel(logging.NOTSET)
    yield access
    access.filters[:] = filters
    for name, level in levels.items():
        logging.getLogger(name).setLevel(level)


# --- the access log -----------------------------------------------------------


@pytest.mark.parametrize(
    "path, logged",
    [
        (f"/api/v1/indicators/search?q={SECRET}", "/api/v1/indicators/search"),
        (f"/api/v1/x?token={SECRET}&page=2", "/api/v1/x"),
        (f"/api/v1/x?{SECRET}", "/api/v1/x"),
        ("/api/v1/x?", "/api/v1/x"),
        ("/api/v1/x", "/api/v1/x"),
        ("/", "/"),
    ],
)
def test_the_access_line_has_the_path_and_not_the_query(path, logged):
    record = access_record(path)

    assert log_safety.WithoutQueryString().filter(record) is True

    assert record.getMessage() == f'203.0.113.9:51000 - "GET {logged} HTTP/1.1" 200'
    assert SECRET not in record.getMessage()
    assert SECRET not in str(record.args)


def test_a_record_of_another_shape_is_left_alone():
    """The filter knows uvicorn's record; it does not guess at any other."""
    for arguments in (None, (), ("a", "b"), {"path": f"/x?{SECRET}"}, (1, 2, 3, 4, 5)):
        record = logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 1, "message", None, None
        )
        record.args = arguments
        before = record.args
        assert log_safety.WithoutQueryString().filter(record) is True
        assert record.args == before


def test_every_service_gets_the_filter_with_its_error_handlers(clean_loggers):
    assert not clean_loggers.filters

    install_error_handlers(FastAPI())

    assert [type(item) for item in clean_loggers.filters] == [
        log_safety.WithoutQueryString
    ]
    record = access_record(f"/search?q={SECRET}")
    assert clean_loggers.filter(record)
    assert SECRET not in record.getMessage()


def test_installing_twice_filters_once(clean_loggers):
    install_error_handlers(FastAPI())
    install_error_handlers(FastAPI())
    log_safety.keep_requests_out_of_the_logs()

    assert len(clean_loggers.filters) == 1


# --- the HTTP client libraries ------------------------------------------------


def test_the_http_client_libraries_log_warnings_only(clean_loggers, monkeypatch):
    """httpx: 'HTTP Request: GET https://target/path?query "HTTP/1.1 200 OK"'."""
    # As in a process that has not configured logging yet: the root logger
    # is at WARNING, and every library inherits that.
    monkeypatch.setattr(logging.getLogger(), "level", logging.WARNING)
    install_error_handlers(FastAPI())
    # The service sets its own level afterwards, to anything.
    monkeypatch.setattr(logging.getLogger(), "level", logging.DEBUG)

    for name in ("httpx", "httpcore", "urllib3", "aiohttp.client", "botocore", "boto3"):
        assert logging.getLogger(name).getEffectiveLevel() == logging.WARNING, name


def test_a_level_a_service_raised_is_kept(clean_loggers):
    logging.getLogger("httpx").setLevel(logging.ERROR)

    log_safety.quiet_http_client_loggers()

    assert logging.getLogger("httpx").level == logging.ERROR


def test_a_request_sent_with_httpx_is_not_logged(clean_loggers, caplog, monkeypatch):
    import httpx

    install_error_handlers(FastAPI())
    monkeypatch.setattr(logging.getLogger(), "level", logging.DEBUG)

    def answer(request):
        return httpx.Response(200, json={})

    with caplog.at_level(logging.DEBUG):
        logging.getLogger("httpx").setLevel(logging.WARNING)  # caplog reset it
        with httpx.Client(transport=httpx.MockTransport(answer)) as client:
            client.get(f"https://target.example/path?token={SECRET}")

    assert SECRET not in caplog.text


# --- the detail of an HTTP error ---------------------------------------------------


def test_the_detail_of_an_http_error_is_answered_and_not_logged(caplog):
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/refused")
    def refused():
        raise HTTPException(
            status_code=400, detail=f"Target 'https://admin:{SECRET}@host/' is internal"
        )

    @app.get("/structured")
    def structured():
        raise HTTPException(status_code=422, detail={"reason": "bad", "value": SECRET})

    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG, logger="open_security_shared.errors"):
        first = client.get("/refused", headers={"X-Request-ID": "req-1"})
        second = client.get("/structured")

    # The caller reads it.
    assert SECRET in first.json()["error"]["message"]
    assert second.json()["error"]["details"]["value"] == SECRET
    # The log has the status, the path and the request id.
    records = [r for r in caplog.records if r.name == "open_security_shared.errors"]
    assert [r.getMessage() for r in records] == [
        "HTTP exception: 400",
        "HTTP exception: 422",
    ]
    for record in records:
        assert SECRET not in str(record.__dict__)
        assert not hasattr(record, "detail")
    assert records[0].request_id == "req-1"
    assert records[0].status_code == 400
    assert records[0].path == "/refused"


# --- the headers of a request ----------------------------------------------------


def test_the_request_log_names_the_headers_and_holds_no_value(caplog):
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/ok")
    def ok():
        return {}

    with caplog.at_level(
        logging.DEBUG, logger="open_security_shared.security_middleware"
    ):
        TestClient(app).get(
            f"/ok?q={SECRET}",
            headers={
                "X-Gateway-Secret": SECRET,
                "X-Wildbox-User-ID": SECRET,
                "Authorization": f"Bearer {SECRET}",
                "X-Custom": SECRET,
            },
        )

    records = [
        r
        for r in caplog.records
        if r.name == "open_security_shared.security_middleware"
    ]
    assert records
    for record in records:
        assert SECRET not in str(record.__dict__)
        assert not hasattr(record, "headers")
    assert {
        "x-gateway-secret",
        "x-wildbox-user-id",
        "authorization",
        "x-custom",
    } <= set(records[0].header_names)
    assert records[0].path == "/ok"
