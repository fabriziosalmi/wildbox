#!/usr/bin/env python3
"""Check the gateway's env declarations and where it authenticates (#627, #630).

nginx gives its worker processes only the environment variables nginx.conf
declares with ``env NAME;``, so ``os.getenv("NAME")`` in the gateway's Lua
returns nil for any other variable, and the code goes on with its default.
RATE_LIMIT_PER_HOUR was read that way without a declaration: the setting
reached the gateway only because the module happens to be loaded by the
master process, which is not something to rely on.

The check reads every ``os.getenv`` in the gateway's Lua files and in the
Lua blocks of its nginx configuration (nginx.conf, conf.d, includes and the
test configuration) and fails when

* a variable is read that nginx.conf does not declare, or
* the name is not a string literal, so it cannot be checked.

It also fails when an nginx configuration file asks identity's
``/internal/authorize`` itself. Authentication goes through
``auth_handler.authenticate()``, which carries the cache, the revocation
markers, the must-change-password refusal, the rate limit and the retry of
a closed connection; the agents route had its own copy that carried none of
them (#630).

And it fails when a configuration file authenticates without declaring the
nginx variables ``authenticate()`` assigns. Assigning an undeclared variable
from Lua is an error at request time, a 500 for every authenticated request,
and ``$wildbox_auth_type`` and ``$wildbox_scopes`` are what
``proxy_params.conf`` sends the services as the credential's type and scopes
(#637).

And it fails when a configuration file authenticates without declaring
``set $wildbox_route_uri $uri;``. auth_handler maps a request to the
API-key scope it requires by that variable, the path as it was before any
location rewrote it; without the declaration the map knows no path and
requires ``admin`` of every scope-limited key (#647).

Usage:
  scripts/check_gateway_config.py [--gateway-dir DIR]
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GATEWAY_DIR = ROOT / "open-security-gateway" / "nginx"

_ENV_DIRECTIVE = re.compile(r"^\s*env\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;")
_GETENV = re.compile(r"os\.getenv\s*\(\s*(?:([\"'])([^\"']*)\1\s*\))?")
_AUTHORIZE = "/internal/authorize"
_AUTHENTICATE = re.compile(r"\bauthenticate\s*\(")
# The variables auth_handler.set_auth_headers() assigns.
ASSIGNED_VARIABLES = (
    "wildbox_user_id",
    "wildbox_team_id",
    "wildbox_role",
    "wildbox_gateway_secret",
    "wildbox_auth_type",
    "wildbox_scopes",
)
_ROUTE_URI = re.compile(r"^\s*set\s+\$wildbox_route_uri\s+\$uri\s*;")
_SET_EMPTY = re.compile(r'^\s*set\s+\$([a-z_]+)\s+""\s*;')


def strip_comment(line: str, suffix: str) -> str:
    """Drop the comment on one line: Lua ``--`` everywhere, nginx ``#`` in .conf.

    Line based and approximate: a ``--`` inside a Lua string is taken for a
    comment. The gateway's Lua has none in a line that reads a variable.
    """
    if suffix == ".conf" and line.lstrip().startswith("#"):
        return ""
    index = line.find("--")
    return line if index < 0 else line[:index]


def declared_variables(nginx_conf: Path) -> set:
    names = set()
    for line in nginx_conf.read_text(encoding="utf-8").splitlines():
        match = _ENV_DIRECTIVE.match(strip_comment(line, ".conf"))
        if match:
            names.add(match.group(1))
    return names


def getenv_reads(path: Path):
    """Yield (line number, variable name or None) for each os.getenv call."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for match in _GETENV.finditer(strip_comment(line, path.suffix)):
            yield number, match.group(2)


def gateway_files(gateway_dir: Path):
    return sorted(
        p
        for p in gateway_dir.rglob("*")
        if p.is_file() and p.suffix in (".lua", ".conf")
    )


def check(gateway_dir: Path) -> list:
    nginx_conf = gateway_dir / "nginx.conf"
    declared = declared_variables(nginx_conf)
    failures = []
    for path in gateway_files(gateway_dir):
        for number, name in getenv_reads(path):
            where = f"{path.relative_to(gateway_dir.parent)}:{number}"
            if name is None:
                failures.append(
                    f"{where}: os.getenv with a name that is not a string literal "
                    "cannot be checked against the env declarations"
                )
            elif name not in declared:
                failures.append(
                    f"{where}: reads {name}, which nginx.conf does not declare; "
                    f"add `env {name};` to {nginx_conf.relative_to(gateway_dir.parent)} "
                    "or the worker processes never see it"
                )
        if path.suffix == ".conf":
            failures.extend(inline_authorizations(path, gateway_dir))
            failures.extend(undeclared_assigned_variables(path, gateway_dir))
            failures.extend(missing_route_uri(path, gateway_dir))
    return failures


def missing_route_uri(path: Path, gateway_dir: Path) -> list:
    """A configuration that authenticates without the path the scope map reads."""
    lines = [
        strip_comment(line, path.suffix)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    if not any(_AUTHENTICATE.search(line) for line in lines):
        return []
    if any(_ROUTE_URI.match(line) for line in lines):
        return []
    return [
        f"{path.relative_to(gateway_dir.parent)}: calls authenticate() but does not "
        "declare `set $wildbox_route_uri $uri;` in its server block; the scope map "
        "reads the request path from it"
    ]


def undeclared_assigned_variables(path: Path, gateway_dir: Path) -> list:
    """A configuration that authenticates without a variable authenticate() assigns.

    Each must be declared empty (``set $name "";``): empty is what a location
    that authenticates nobody forwards, which is nothing.
    """
    lines = [
        strip_comment(line, path.suffix)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    if not any(_AUTHENTICATE.search(line) for line in lines):
        return []
    declared = {
        match.group(1) for match in (_SET_EMPTY.match(line) for line in lines) if match
    }
    return [
        f"{path.relative_to(gateway_dir.parent)}: calls authenticate() but does not "
        f'declare `set ${name} "";` in its server block; authenticate() assigns it'
        for name in ASSIGNED_VARIABLES
        if name not in declared
    ]


def inline_authorizations(path: Path, gateway_dir: Path) -> list:
    """An nginx configuration that calls identity's authorization itself."""
    failures = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _AUTHORIZE in strip_comment(line, path.suffix):
            failures.append(
                f"{path.relative_to(gateway_dir.parent)}:{number}: calls {_AUTHORIZE} "
                "itself; authenticate with auth_handler.authenticate() instead"
            )
    return failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--gateway-dir", type=Path, default=DEFAULT_GATEWAY_DIR)
    args = ap.parse_args(argv)
    failures = check(args.gateway_dir)
    if failures:
        print("FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        "Every variable the gateway reads is declared in nginx.conf, every "
        "authorization goes through auth_handler, and every configuration that "
        "authenticates declares the variables it assigns and the path the scope "
        "map reads."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
