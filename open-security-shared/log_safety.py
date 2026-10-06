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

``keep_requests_out_of_the_logs()`` does both.
``open_security_shared.errors.install_error_handlers`` calls it, so every
FastAPI service has it from the moment its application is made; a worker
process, which makes no application, calls it itself.

Standard library only: the module is imported by services that install no
extra of this package.
"""

import logging

ACCESS_LOGGER = "uvicorn.access"

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


def keep_requests_out_of_the_logs() -> None:
    """Both of the above. Safe to call more than once."""
    keep_query_strings_out_of_the_access_log()
    quiet_http_client_loggers()
