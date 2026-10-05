"""List the locations of an nginx configuration that authenticate, or proxy.

Prints one line for each ``location`` block whose body calls
``auth_handler.authenticate()`` (#647), as the location is written in the
file: ``= /api/v1/tools``, ``~ ^/api/v1/tools/(.*)$``, ``/api/v1/data/``.
With ``--proxying`` it lists the blocks that pass the request to an
upstream (``proxy_pass``) instead (#711).

The harness compares each list with what it pins, so a location added to
``wildbox_gateway.conf`` fails it until someone says what the location is:
``route_scope_tests.sh`` pins the API-key scope of every location that
authenticates, ``upstream_header_tests.sh`` pins which of Wildbox's own
headers every proxying location sends its upstream.

Usage:
  authenticated_locations.py [--proxying] <nginx configuration file>
"""

import re
import sys
from pathlib import Path

_LOCATION = re.compile(r"^\s*location\s+(.+?)\s*\{\s*$")
_AUTHENTICATE = re.compile(r"\bauthenticate\s*\(")
_PROXY_PASS = re.compile(r"^\s*proxy_pass\s")


def strip_comment(line: str) -> str:
    """Drop an nginx ``#`` comment line and a Lua ``--`` comment."""
    if line.lstrip().startswith("#"):
        return ""
    index = line.find("--")
    return line if index < 0 else line[:index]


def _locations_with(text: str, pattern) -> list:
    """The ``location`` blocks with a line matching ``pattern``, in file order.

    Braces are counted line by line on the text without comments. A quoted
    JSON body (``return 404 '{...}'``) opens and closes on its own line, so
    it leaves the depth where it was.
    """
    found = []
    current = None  # [location, depth at which its block closes, matched]
    depth = 0
    for raw in text.splitlines():
        line = strip_comment(raw)
        match = _LOCATION.match(line)
        if match and current is None:
            current = [match.group(1), depth, False]
        elif current is not None and pattern.search(line):
            current[2] = True
        depth += line.count("{") - line.count("}")
        if current is not None and depth <= current[1]:
            if current[2]:
                found.append(current[0])
            current = None
    if depth != 0 or current is not None:
        raise ValueError("unbalanced braces: the configuration was not read to its end")
    return found


def authenticated_locations(text: str) -> list:
    """The ``location`` blocks that call authenticate(), in file order."""
    return _locations_with(text, _AUTHENTICATE)


def proxying_locations(text: str) -> list:
    """The ``location`` blocks that pass the request to an upstream."""
    return _locations_with(text, _PROXY_PASS)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    select = authenticated_locations
    if args and args[0] == "--proxying":
        select = proxying_locations
        args = args[1:]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    for location in select(Path(args[0]).read_text(encoding="utf-8")):
        print(location)
    return 0


if __name__ == "__main__":
    sys.exit(main())
