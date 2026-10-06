"""An error no route handles is logged without its text (#788).

The shared handler logged ``Unhandled exception: <text>`` with the traceback,
which ends with the text again, and once more for each error it came from.
The text of an error is made from the values at hand when it is raised: in a
route, the request's. ``int("what the caller sent")`` says what the caller
sent.

The handler logs the class of the error, where it was raised and the frames
it went through, for the error and for each one behind it. Starlette then
hands the error on to the server, and uvicorn logs it with its traceback
(``Exception in ASGI application``): the same description takes the place of
that traceback. The answer is as it was, and never had the text (#735).

The server's record is made here as uvicorn makes it; the unit suite of the
cspm service runs the same through the uvicorn it pins.
"""

import logging
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from open_security_shared import errors, log_safety
from open_security_shared.errors import install_error_handlers
from open_security_shared.log_safety import describe_exception

SECRET = "do-not-log-" + uuid.uuid4().hex
OTHER_SECRET = "nor-this-" + uuid.uuid4().hex


class NoRecord(Exception):
    """An error of an application's own, as a service defines them."""


def _parse(value):
    return int(value)


def _look_up(value):
    try:
        return _parse(value)
    except ValueError as error:
        raise NoRecord(f"no record for {value!r}") from error


def _clean_up_after(value):
    try:
        return _parse(value)
    except ValueError:
        raise KeyError(f"{OTHER_SECRET} while handling {value}")


def _quietly(value):
    try:
        return _parse(value)
    except ValueError:
        raise NoRecord(f"not found: {value}") from None


@pytest.fixture
def service():
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/lookup")
    def lookup(value: str):
        return {"record": _look_up(value)}

    @app.get("/handling")
    def handling(value: str):
        return {"record": _clean_up_after(value)}

    return app


@pytest.fixture
def formatted(caplog):
    """What a handler with a formatter writes for each record: the message,
    and the traceback when the record has one."""
    formatter = logging.Formatter("%(levelname)s %(name)s %(message)s")

    def lines():
        return "\n".join(formatter.format(record) for record in caplog.records)

    with caplog.at_level(logging.DEBUG):
        yield lines


def _raised(call, *arguments):
    try:
        call(*arguments)
    except Exception as error:  # noqa: BLE001 - whatever it raises
        return error
    raise AssertionError("it did not raise")


# --- What is said of an error -------------------------------------------------------


def test_an_error_is_described_by_its_class_its_place_and_its_frames():
    error = _raised(_parse, SECRET)

    described = describe_exception(error)

    first, *frames = described.splitlines()
    assert first.startswith("ValueError raised at ")
    assert first.endswith(" in _parse")
    assert __file__ in first
    # The frames, innermost last, with the source of each call.
    assert "in _raised" in described and "in _parse" in described
    assert "return int(value)" in described
    assert SECRET not in described
    assert len(frames) >= 4


def test_the_errors_behind_it_are_described_the_same_way():
    error = _raised(_look_up, SECRET)

    described = describe_exception(error)

    lines = described.splitlines()
    assert lines[0].startswith(f"{__name__}.NoRecord raised at ")
    assert lines[0].endswith(" in _look_up")
    (cause,) = [line for line in lines if line.startswith("caused by ")]
    assert cause.startswith("caused by ValueError raised at ")
    assert cause.endswith(" in _parse")
    assert SECRET not in described


def test_an_error_raised_while_another_was_handled_names_that_one_too():
    error = _raised(_clean_up_after, SECRET)

    described = describe_exception(error)

    assert described.startswith("KeyError raised at ")
    assert "raised while handling ValueError raised at " in described
    assert SECRET not in described and OTHER_SECRET not in described


def test_an_error_that_hid_the_one_before_it_does_not_name_it():
    """``raise ... from None``: Python's own traceback does not show it."""
    error = _raised(_quietly, SECRET)

    described = describe_exception(error)

    assert "ValueError" not in described
    assert SECRET not in described


def test_the_errors_of_a_group_are_each_described():
    group = ExceptionGroup(
        f"errors of {SECRET}", [_raised(_parse, SECRET), _raised(_look_up, SECRET)]
    )

    described = describe_exception(_raised(_raise, group))

    assert described.startswith("ExceptionGroup raised at ")
    assert "in that group, ValueError raised at " in described
    assert f"in that group, {__name__}.NoRecord raised at " in described
    assert SECRET not in described


def _raise(error):
    raise error


@pytest.mark.parametrize("link", ["__context__", "__cause__"])
def test_errors_that_refer_to_each_other_are_described_once(link):
    first, second = _raised(_parse, SECRET), _raised(_parse, OTHER_SECRET)
    setattr(first, link, second)
    setattr(second, link, first)

    described = describe_exception(first)

    assert described.count("ValueError raised at ") == 2
    assert SECRET not in described and OTHER_SECRET not in described


def test_an_error_that_was_never_raised_is_still_described():
    assert describe_exception(ValueError(SECRET)) == (
        "ValueError raised at an unknown place (it has no traceback)"
    )


# --- The handler ----------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/lookup", "/handling"])
def test_the_handler_logs_the_class_and_the_frames_and_not_the_text(
    service, formatted, path
):
    client = TestClient(service, raise_server_exceptions=False)

    response = client.get(path, params={"value": SECRET})

    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": 500,
        "message": "An internal error occurred",
        "type": "InternalServerError",
        "request_id": response.json()["error"]["request_id"],
    }
    written = formatted()
    # main: the text of both errors, twice each.
    assert SECRET not in written and OTHER_SECRET not in written
    assert "ERROR open_security_shared.errors Unhandled exception: " in written
    assert "ValueError raised at " in written
    assert "in _parse" in written and "return int(value)" in written
    if path == "/lookup":
        assert f"{__name__}.NoRecord raised at " in written
        assert "caused by ValueError raised at " in written
    else:
        assert "raised while handling ValueError raised at " in written


def test_the_handlers_record_has_no_traceback_for_a_formatter_to_write(service, caplog):
    """The text is not in the record at all: no formatter, of any handler a
    service adds, can write it."""
    client = TestClient(service, raise_server_exceptions=False)

    with caplog.at_level(logging.ERROR, logger=errors.__name__):
        client.get("/lookup", params={"value": SECRET})

    (record,) = [r for r in caplog.records if r.name == errors.__name__]
    assert record.exc_info is None and record.exc_text is None
    assert SECRET not in record.getMessage()
    assert SECRET not in repr(record.args)
    assert record.path == "/lookup"


# --- The server's own record --------------------------------------------------------


@pytest.fixture
def server_logger():
    """uvicorn's error logger, with the filters it has put back afterwards."""
    server = logging.getLogger(log_safety.SERVER_LOGGER)
    filters = list(server.filters)
    yield server
    server.filters[:] = filters


def _as_the_server_logs_it(server, error):
    """uvicorn's own call (uvicorn/protocols/http/*_impl.py)."""
    server.error("Exception in ASGI application\n", exc_info=error)


def test_the_application_hands_the_error_on_to_the_server(service):
    """Why the handler is not the only place: Starlette answers with it,
    and raises the error again for the server to log."""
    client = TestClient(service, raise_server_exceptions=True)

    with pytest.raises(NoRecord):
        client.get("/lookup", params={"value": SECRET})


def test_the_servers_record_of_it_has_the_frames_and_not_the_text(
    service, server_logger, formatted
):
    error = _raised(_look_up, SECRET)

    _as_the_server_logs_it(server_logger, error)

    written = formatted()
    assert "ERROR uvicorn.error Exception in ASGI application" in written
    assert f"{__name__}.NoRecord raised at " in written
    assert "caused by ValueError raised at " in written
    assert "in _parse" in written
    # main: the traceback, with the text of both errors.
    assert SECRET not in written
    assert "Traceback (most recent call last)" not in written


def test_the_servers_record_keeps_no_error_for_another_formatter_to_write(
    service, server_logger, caplog
):
    """A formatter of a service's own (JSON, for instance) formats the
    record's exc_info itself: the record has none left."""
    with caplog.at_level(logging.ERROR, logger=log_safety.SERVER_LOGGER):
        _as_the_server_logs_it(server_logger, _raised(_look_up, SECRET))

    (record,) = caplog.records
    assert record.exc_info is None
    assert record.exc_text.startswith(f"{__name__}.NoRecord raised at ")
    assert SECRET not in record.exc_text


def test_without_the_filter_the_same_record_has_the_text(server_logger, formatted):
    """The control: what uvicorn's record holds when nothing rewrites it."""
    server_logger.filters[:] = []

    _as_the_server_logs_it(server_logger, _raised(_look_up, SECRET))

    written = formatted()
    assert f"NoRecord: no record for '{SECRET}'" in written
    assert f"invalid literal for int() with base 10: '{SECRET}'" in written


def test_the_filter_is_installed_once_by_every_application(server_logger):
    server_logger.filters[:] = []

    for _ in range(3):
        install_error_handlers(FastAPI())

    assert [type(item) for item in server_logger.filters] == [
        log_safety.WithoutExceptionText
    ]


def test_a_record_without_an_error_is_left_as_it_is(server_logger, formatted):
    install_error_handlers(FastAPI())

    server_logger.info("Application startup complete.")
    server_logger.error("connection closed", exc_info=None)

    assert formatted().splitlines() == [
        "INFO uvicorn.error Application startup complete.",
        "ERROR uvicorn.error connection closed",
    ]


def test_the_filter_takes_every_form_of_exc_info(server_logger, formatted):
    install_error_handlers(FastAPI())
    error = _raised(_parse, SECRET)

    server_logger.error("as an instance", exc_info=error)
    server_logger.error(
        "as a tuple", exc_info=(type(error), error, error.__traceback__)
    )
    try:
        _parse(SECRET)
    except ValueError:
        server_logger.exception("as the error being handled")

    written = formatted()
    assert written.count("ValueError raised at ") == 3
    assert SECRET not in written
