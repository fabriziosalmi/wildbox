"""
Tests for open_security_shared.scopes: reading what the gateway says about a
credential, and deciding whether it may do what needs a scope (#637).

The gateway enforces API-key scopes and the services check them again. The
second check is worth something only if it reads the gateway's headers
strictly and decides exactly as the gateway does, so these pin both: the
parsers refuse everything that is not what the gateway writes, and the
hierarchy is checked against open-security-gateway/test/scope_vectors.txt,
the table the gateway's own harness checks its Lua against.

Pure-function tests; they need no stack.
"""

from pathlib import Path

import pytest
from open_security_shared import scopes
from open_security_shared.scopes import (
    GatewayCredentialError,
    credential_allows,
    parse_auth_type,
    parse_scopes,
    scope_for_method,
    scope_satisfied,
)

VECTORS = (
    Path(__file__).resolve().parents[2]
    / "open-security-gateway"
    / "test"
    / "scope_vectors.txt"
)


def _vectors():
    rows = []
    for number, line in enumerate(VECTORS.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(" ")
        assert len(fields) == 3 and fields[2] in (
            "allow",
            "deny",
        ), f"{VECTORS.name}:{number}: {line!r}"
        granted, required, verdict = fields
        rows.append((granted, required, verdict == "allow"))
    return rows


# --- The hierarchy, against the gateway's table -----------------------------


def test_the_table_covers_every_scope_identity_grants_against_every_required_one():
    rows = _vectors()
    granted = {row[0] for row in rows}
    required = {row[1] for row in rows}

    assert {
        "-",
        "*",
        "admin",
        "read",
        "write",
        "data:ingest",
        "data:delete",
        "tools:admin",
    } <= granted
    assert required == {
        "read",
        "write",
        "admin",
        "tools:read",
        "tools:execute",
        "tools:admin",
        "data:read",
        "data:write",
        "data:delete",
        "data:ingest",
    }
    # Every granted set against every required scope, once.
    assert (
        len(rows)
        == len(granted) * len(required)
        == len(set((g, r) for g, r, _ in rows))
    )


@pytest.mark.parametrize("granted,required,allowed", _vectors())
def test_scope_satisfied_agrees_with_the_gateway(granted, required, allowed):
    held = [] if granted == "-" else granted.split(",")

    assert scope_satisfied(held, required) is allowed


@pytest.mark.parametrize("granted,required,allowed", _vectors())
def test_an_api_key_is_allowed_what_its_scopes_satisfy(granted, required, allowed):
    """Through the headers, as a service sees the key."""
    header = None if granted == "-" else granted.replace(",", " ")

    assert credential_allows("api_key", parse_scopes(header), required) is allowed


def test_the_sensor_key_does_nothing_but_ingest():
    """The case #637 was opened for: data:ingest satisfies nothing else."""
    for required in (
        "read",
        "write",
        "data:read",
        "data:write",
        "data:delete",
        "tools:read",
        "admin",
    ):
        assert not scope_satisfied(["data:ingest"], required), required
    assert scope_satisfied(["data:ingest"], "data:ingest")


def test_delete_needs_an_explicit_grant():
    assert not scope_satisfied(["write", "data:write", "read"], "data:delete")
    assert scope_satisfied(["data:delete"], "data:delete")
    assert scope_satisfied(["data:admin"], "data:delete")


def test_an_unknown_action_is_satisfied_only_by_itself_or_an_admin_scope():
    assert not scope_satisfied(["write", "data:write", "data:read"], "data:export")
    assert scope_satisfied(["data:export"], "data:export")
    assert scope_satisfied(["data:admin"], "data:export")
    assert scope_satisfied(["*"], "data:export")


# --- The scopes header -------------------------------------------------------


def test_no_scopes_header_is_none_not_an_empty_list():
    assert parse_scopes(None) is None


@pytest.mark.parametrize(
    "header,expected",
    [
        ("data:ingest", ("data:ingest",)),
        (
            "tools:read data:ingest data:read",
            ("tools:read", "data:ingest", "data:read"),
        ),
        ("*", ("*",)),
        ("read write admin", ("read", "write", "admin")),
        ("team:manage reports:read", ("team:manage", "reports:read")),
    ],
)
def test_a_scopes_header_as_the_gateway_writes_it_is_read(header, expected):
    assert parse_scopes(header) == expected


@pytest.mark.parametrize(
    "header",
    [
        "",  # nginx sends no empty header: one that arrives was not the gateway's
        " ",
        "read ",  # trailing space
        " read",
        "read  write",  # doubled space
        "read,write",  # another separator
        "read\twrite",
        "read\nwrite",
        '["read"]',  # another encoding
        "Read",  # no scope has an upper-case letter
        "data:",
        ":read",
        "data:read:all",
        "data:*",
        "**",
        "read; admin",
        "x" * 2049,
        " ".join(["read"] * 65),
    ],
)
def test_a_malformed_scopes_header_is_refused(header):
    with pytest.raises(GatewayCredentialError):
        parse_scopes(header)


def test_the_error_does_not_repeat_the_header():
    """A header is attacker-controlled on a direct request; keep it out of logs."""
    with pytest.raises(GatewayCredentialError) as exc:
        parse_scopes("read\r\nX-Injected: 1")

    assert "Injected" not in str(exc.value)


# --- The auth type -----------------------------------------------------------


def test_the_auth_types_the_gateway_and_the_services_state():
    assert scopes.AUTH_TYPES == ("session", "api_key", "service")
    for value in scopes.AUTH_TYPES:
        assert parse_auth_type(value) == value


def test_no_auth_type_header_is_none():
    assert parse_auth_type(None) is None


@pytest.mark.parametrize(
    "value",
    ["", "Session", "API_KEY", "apikey", "jwt", "bearer", "session ", "admin", "*"],
)
def test_an_unknown_auth_type_is_refused(value):
    with pytest.raises(GatewayCredentialError):
        parse_auth_type(value)


# --- What a credential may do ------------------------------------------------

REQUIRED = ("read", "write", "admin", "tools:execute", "data:ingest", "data:delete")


@pytest.mark.parametrize("auth_type", ["session", "service"])
def test_a_session_and_a_service_are_not_limited_by_scopes(auth_type):
    for required in REQUIRED:
        assert credential_allows(auth_type, None, required), required


def test_an_api_key_without_scopes_may_do_nothing():
    """An empty list reaches the service as no header at all."""
    for required in REQUIRED:
        assert not credential_allows("api_key", None, required), required


def test_an_unlimited_api_key_says_so():
    for required in REQUIRED:
        assert credential_allows("api_key", ("*",), required), required


@pytest.mark.parametrize("auth_type", [None, "", "jwt", "API_KEY", "admin"])
def test_a_missing_or_unknown_auth_type_satisfies_nothing(auth_type):
    """Not even with scopes that would: nothing says what holds them."""
    for required in REQUIRED:
        assert not credential_allows(auth_type, None, required), required
        assert not credential_allows(auth_type, ("*",), required), required
        assert not credential_allows(auth_type, ("admin",), required), required


def test_scopes_limit_whatever_carries_them():
    """Scopes on a session would be a restriction, and are applied as one."""
    assert credential_allows("session", ("data:read",), "data:read")
    assert not credential_allows("session", ("data:read",), "data:write")
    assert not credential_allows("service", ("data:ingest",), "read")


# --- The scope a method needs ------------------------------------------------


@pytest.mark.parametrize(
    "method,expected",
    [
        ("GET", "data:read"),
        ("HEAD", "data:read"),
        ("OPTIONS", "data:read"),
        ("POST", "data:write"),
        ("PUT", "data:write"),
        ("PATCH", "data:write"),
        ("DELETE", "data:delete"),
        ("TRACE", "data:write"),  # anything that is not a read is a write
    ],
)
def test_scope_for_method_follows_the_gateway(method, expected):
    assert (
        scope_for_method(method, "data:read", "data:write", "data:delete") == expected
    )


def test_delete_is_a_write_where_no_delete_scope_is_named():
    assert scope_for_method("DELETE", "read", "write") == "write"


def test_the_module_imports_nothing_but_the_standard_library():
    """guardian (Django) imports it; it must not drag FastAPI in."""
    source = Path(scopes.__file__).read_text(encoding="utf-8")
    imports = [
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    ]

    assert imports == ["import re", "from typing import Iterable, Optional, Tuple"]
