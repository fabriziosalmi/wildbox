"""List the locations of an nginx configuration that authenticate (#647).

Prints one line for each ``location`` block whose body calls
``auth_handler.authenticate()``, as the location is written in the file:
``= /api/v1/tools``, ``~ ^/api/v1/tools/(.*)$``, ``/api/v1/data/``.

``route_scope_tests.sh`` compares the list with the scopes it pins, so a
location added to ``wildbox_gateway.conf`` without a pin fails the harness
instead of going out with whatever scope the gateway's map happens to give
it.

Usage:
  authenticated_locations.py <nginx configuration file>
"""

import re
import sys
from pathlib import Path

_LOCATION = re.compile(r"^\s*location\s+(.+?)\s*\{\s*$")
_AUTHENTICATE = re.compile(r"\bauthenticate\s*\(")


def strip_comment(line: str) -> str:
    """Drop an nginx ``#`` comment line and a Lua ``--`` comment."""
    if line.lstrip().startswith("#"):
        return ""
    index = line.find("--")
    return line if index < 0 else line[:index]


def authenticated_locations(text: str) -> list:
    """The ``location`` blocks that call authenticate(), in file order.

    Braces are counted line by line on the text without comments. A quoted
    JSON body (``return 404 '{...}'``) opens and closes on its own line, so
    it leaves the depth where it was.
    """
    found = []
    current = None  # [location, depth at which its block closes, authenticates]
    depth = 0
    for raw in text.splitlines():
        line = strip_comment(raw)
        match = _LOCATION.match(line)
        if match and current is None:
            current = [match.group(1), depth, False]
        elif current is not None and _AUTHENTICATE.search(line):
            current[2] = True
        depth += line.count("{") - line.count("}")
        if current is not None and depth <= current[1]:
            if current[2]:
                found.append(current[0])
            current = None
    if depth != 0 or current is not None:
        raise ValueError("unbalanced braces: the configuration was not read to its end")
    return found


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    locations = authenticated_locations(Path(args[0]).read_text(encoding="utf-8"))
    for location in locations:
        print(location)
    return 0


if __name__ == "__main__":
    sys.exit(main())
