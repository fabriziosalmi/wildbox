"""What may be written about a database error (#778).

The engine hides the parameters of a statement (``hide_parameters``, #755),
so the text of a SQLAlchemy error no longer ends with the values that were
bound. The message the database itself wrote is still in it, and PostgreSQL
puts values there too::

    duplicate key value violates unique constraint "ix_users_email"
    DETAIL:  Key (email)=(alice@example.com) already exists.

    invalid input syntax for type uuid: "hunter2-pasted-in-the-wrong-field"

An error no route caught went to the shared handler, which logs the
exception's text and its traceback, whose last line is that text again.

``describe_database_error`` says what failed without the database's words:
the class of the error, the driver's own class, the SQLSTATE, and the names
of the constraint, table and column when the driver gives them. Those are
names from the schema. ``code_path`` is the traceback's frames without the
exception at its end: where it happened, in the service's code.
"""

import re
import traceback
from typing import Any, Iterator, Optional

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
