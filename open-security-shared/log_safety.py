"""What a service's log may say about a request: not what it held (#755).

A log is read by more people, kept for longer and copied to more places than
the request it describes. Two things put a request's content there without
any service writing a log line for it:

* uvicorn's access log has the request line as the client sent it:
  ``"GET /api/v1/indicators/search?q=198.51.100.7 HTTP/1.1"``. The query
  string is the caller's input: an indicator, a search term, a filter, a
  token a client put there. ``WithoutQueryString`` cuts it; the line keeps
  the method, the path and the status, which is what an access log is read
  for. The gateway does the same in its own access log (``nginx.conf``).
* the HTTP client libraries log the address they call: httpx at INFO
  (``HTTP Request: GET https://target/path?query``), urllib3 at DEBUG. For a
  tool that address is the caller's target, credentials in the URL included;
  for the agents it is a search with the indicator in its query. botocore,
  at DEBUG, logs the request it signs with the cloud account's session
  token. Their loggers say warnings and errors only, whatever the service's
  level is.

* an error no route handles is logged with its traceback, and a traceback
  ends with the error's text: ``ValueError: invalid literal for int() with
  base 10: '<what the caller sent>'``, and once more for each error it came
  from. The text of an error is made from the values at hand when it is
  raised, which in a route are the request's. It was logged twice: by the
  shared handler (``errors.unhandled_exception_handler``) and by uvicorn,
  which is handed every error the application does not swallow
  (``Exception in ASGI application``). ``describe_exception`` says what an
  operator looks for, the class of the error, where it was raised and the
  frames it went through, for the error and for each one behind it, without
  the text of any; the handler logs that, and ``WithoutExceptionText`` puts
  it in the place of the traceback in uvicorn's record (#788).

``keep_requests_out_of_the_logs()`` does all three.
``open_security_shared.errors.install_error_handlers`` calls it, so every
FastAPI service has it from the moment its application is made; a worker
process, which makes no application, calls it itself.

Standard library only: the module is imported by services that install no
extra of this package.
"""

import logging
import traceback
from typing import List, Set

ACCESS_LOGGER = "uvicorn.access"
# The logger uvicorn reports an application's own errors on.
SERVER_LOGGER = "uvicorn.error"

# Loggers of libraries that log the requests they send: the URL (httpx at
# INFO, urllib3 at DEBUG), or, for botocore at DEBUG, the canonical request
# it signs, which has the session token of the cloud account among its
# headers.
QUIETED_LOGGERS = (
    "httpx",
    "httpcore",
    "urllib3",
    "aiohttp.client",
    "botocore",
    "boto3",
)

# uvicorn's access record: ('%s - "%s %s HTTP/%s" %d', client, method,
# path-with-query, HTTP version, status). Both of its HTTP implementations
# log through this one format.
_ARGUMENTS = 5
_PATH = 2


class WithoutQueryString(logging.Filter):
    """Cut the query string from the path of an access record."""

    def filter(self, record: logging.LogRecord) -> bool:
        arguments = record.args
        if (
            isinstance(arguments, tuple)
            and len(arguments) == _ARGUMENTS
            and isinstance(arguments[_PATH], str)
        ):
            path, mark, _query = arguments[_PATH].partition("?")
            if mark:
                before, after = arguments[:_PATH], arguments[_PATH + 1 :]  # noqa: E203
                record.args = before + (path,) + after
        return True


def keep_query_strings_out_of_the_access_log() -> None:
    """Install the filter on uvicorn's access logger, once."""
    access = logging.getLogger(ACCESS_LOGGER)
    if not any(isinstance(item, WithoutQueryString) for item in access.filters):
        access.addFilter(WithoutQueryString())


def quiet_http_client_loggers() -> None:
    """Warnings and errors only from the libraries that log each URL they call."""
    for name in QUIETED_LOGGERS:
        library = logging.getLogger(name)
        # Its own level, not the effective one: the root logger's level is
        # usually set after this runs, and would be inherited then.
        if library.level < logging.WARNING:
            library.setLevel(logging.WARNING)


def _class_name(error: BaseException) -> str:
    """``ValueError``, ``sqlalchemy.exc.OperationalError``: as a traceback
    names a class."""
    kind = type(error)
    if kind.__module__ in ("builtins", "__main__"):
        return kind.__qualname__
    return f"{kind.__module__}.{kind.__qualname__}"


def _raised_at(error: BaseException) -> str:
    """``app/main.py:57 in lookup``: the last frame of the error's traceback."""
    frames = traceback.extract_tb(error.__traceback__)
    if not frames:
        return "an unknown place (it has no traceback)"
    last = frames[-1]
    return f"{last.filename}:{last.lineno} in {last.name}"


def _described(error: BaseException, link: str, seen: Set[int]) -> List[str]:
    seen.add(id(error))
    frames = "".join(traceback.format_tb(error.__traceback__)).rstrip("\n")
    lines = [f"{link}{_class_name(error)} raised at {_raised_at(error)}"]
    if frames:
        lines.append(frames)
    # The errors of a group (a task group of several requests' work): each
    # has a text of its own, and the group's says only how many they are.
    for member in getattr(error, "exceptions", None) or ():
        if isinstance(member, BaseException) and id(member) not in seen:
            lines.extend(_described(member, "in that group, ", seen))
    cause, context = error.__cause__, error.__context__
    if cause is not None and id(cause) not in seen:
        lines.extend(_described(cause, "caused by ", seen))
    elif (
        context is not None
        and not error.__suppress_context__
        and id(context) not in seen
    ):
        lines.extend(_described(context, "raised while handling ", seen))
    return lines


def describe_exception(error: BaseException) -> str:
    """The class of an error, where it was raised and the frames it went
    through, then the same for each error behind it: the text of none.

    What a traceback says, without the line each of its parts ends with.
    The frames name files, lines, functions and the source line of each
    call: code, not what the code was given.
    """
    return "\n".join(_described(error, "", set()))


class WithoutExceptionText(logging.Filter):
    """Put ``describe_exception`` in the place of a record's traceback.

    A formatter writes ``exc_text`` when the record has it and formats
    ``exc_info`` only when it has not: with the one set and the other gone,
    no handler of the record writes the error's text.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        info = record.exc_info
        if isinstance(info, tuple) and isinstance(info[1], BaseException):
            record.exc_text = describe_exception(info[1])
            record.exc_info = None
        return True


def keep_exception_texts_out_of_the_server_log() -> None:
    """Install the filter on the logger uvicorn reports errors on, once."""
    server = logging.getLogger(SERVER_LOGGER)
    if not any(isinstance(item, WithoutExceptionText) for item in server.filters):
        server.addFilter(WithoutExceptionText())


def keep_requests_out_of_the_logs() -> None:
    """All of the above. Safe to call more than once."""
    keep_query_strings_out_of_the_access_log()
    quiet_http_client_loggers()
    keep_exception_texts_out_of_the_server_log()
