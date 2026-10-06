"""What a collector may log, and store, about a request that failed (#755).

A feed is fetched with a URL and, often, a key: in a header, in the query
string, or in the path itself (URLVoid's is ``/1000/<key>/host/<domain>``).
The text of an HTTP client's error ends with the URL it could not fetch, so
logging it, or storing it as the run's error, wrote the key into the log and
into ``collection_runs.error_message`` and ``sources.last_error``.

``host_of`` names a URL by its host; ``describe_error`` says what failed
without the text: the status an HTTP error came with, the class otherwise.
"""

import re
import traceback
from typing import Any, Iterator, Optional
from urllib.parse import urlsplit

NO_HOST = "(no host)"


def host_of(url: Any) -> str:
    """The host of a URL, and its port if it names one; nothing else."""
    try:
        parts = urlsplit(str(url or ""))
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return NO_HOST
    if not host:
        return NO_HOST
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def describe_error(error: BaseException) -> str:
    """``ClientResponseError (HTTP 404)`` or ``ClientConnectorError``.

    The class, and the HTTP status when the error has one: enough to tell a
    feed that is gone from one that refuses the key, and nothing that was
    part of the request.
    """
    name = type(error).__name__
    status = getattr(error, "status", None)
    if isinstance(status, int) and not isinstance(status, bool) and status > 0:
        return f"{name} (HTTP {status})"
    return name


# --- Database errors (#778) -------------------------------------------------------
# The engine hides the parameters of a statement (hide_parameters, #755), so
# the text of a SQLAlchemy error no longer ends with the values bound to it.
# The message the database wrote is still in that text, and PostgreSQL puts
# values there too:
#
#     duplicate key value violates unique constraint "uq_source_indicator"
#     DETAIL:  Key (source_id, indicator_type, value)=(..., domain,
#     evil.example.com) already exists.
#
#     invalid input syntax for type inet: "what the caller searched for"
#
# describe_database_error says what failed without the database's words: the
# class of the error, the driver's own class, the SQLSTATE, and the names of
# the constraint, table and column when the driver gives them. code_path is
# the traceback's frames without the exception at its end.

# What a diagnostic field must look like to be written: an identifier of the
# schema, or a five-character SQLSTATE.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_$.\-]{1,128}\Z")
_NAMED = ("constraint_name", "table_name", "column_name")


def _sources(error: BaseException) -> Iterator[Any]:
    """Where a driver keeps its diagnostics.

    ``orig`` is the driver's error. With asyncpg it is SQLAlchemy's adapter,
    and asyncpg's own exception, which has the fields, is its cause; psycopg2
    keeps them in ``orig.diag``.
    """
    orig = getattr(error, "orig", None)
    if orig is None:
        return
    cause = getattr(orig, "__cause__", None)
    if cause is not None:
        yield cause
    yield orig
    diag = getattr(orig, "diag", None)
    if diag is not None:
        yield diag


def _field(error: BaseException, *names: str) -> Optional[str]:
    for source in _sources(error):
        for name in names:
            value = getattr(source, name, None)
            if isinstance(value, str) and _IDENTIFIER.match(value):
                return value
    return None


def describe_database_error(error: BaseException) -> str:
    """``IntegrityError (UniqueViolationError, SQLSTATE 23505, constraint
    ix_users_email, table users)``: nothing the database wrote in prose."""
    details = []
    for source in _sources(error):
        details.append(type(source).__name__)
        break
    sqlstate = _field(error, "sqlstate", "pgcode")
    if sqlstate:
        details.append(f"SQLSTATE {sqlstate}")
    for name in _NAMED:
        value = _field(error, name)
        if value:
            details.append(f"{name.split('_')[0]} {value}")
    described = type(error).__name__
    return f"{described} ({', '.join(details)})" if details else described


def code_path(error: BaseException) -> str:
    """The frames the error went through, without the error's own text."""
    return "".join(traceback.format_tb(error.__traceback__)).rstrip()
