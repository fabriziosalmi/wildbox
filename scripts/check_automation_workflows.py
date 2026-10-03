#!/usr/bin/env python3
"""Check that every HTTP call in the n8n workflows reaches an API route that exists.

The workflows in open-security-automations/workflows are JSON documents that
n8n runs; nothing executes them in CI, so an endpoint that is renamed or
removed broke them silently. The executive dashboard workflow called
/api/v1/dashboard/executive-summary, which #578 removed, and an endpoint
that never existed (#592).

For every n8n HTTP Request node this script:

1. resolves the URL. A Wildbox call must start with the gateway base
   ``{{ $env.WILDBOX_API_GATEWAY_URL }}``; a literal URL to an internal
   host (``open-security-cspm:8019`` and the like) is refused, because the
   services accept calls only through the gateway. Calls to an external
   address held in an allowed environment variable (a Slack webhook) and
   literal URLs to public hosts are not checked further.
2. matches the path against the locations of the gateway's HTTPS server
   (open-security-gateway/nginx/conf.d/wildbox_gateway.conf) with nginx's own
   precedence: exact, then the longest prefix (``^~`` stops there), then the
   first matching regex, then the longest prefix. A path that lands on a
   location that answers by itself (the catch-all 404) fails.
3. maps the path to the upstream the location proxies to, as proxy_pass
   rewrites it, and looks the method and path up in that service's own
   route table, read from its FastAPI source. An upstream with no route
   table here fails: the call cannot be verified.
4. checks that a gateway call authenticates the way the gateway accepts
   from an automation: an ``X-API-Key`` header (a personal API key) or an
   ``Authorization: Bearer`` header.

Exit status 0 when every call checks out, 1 with one line per problem.
Standard library only, so it runs in any CI job with a Python 3.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = Path("open-security-automations/workflows")
GATEWAY_CONF = Path("open-security-gateway/nginx/conf.d/wildbox_gateway.conf")

# Route tables: the upstream host named in the gateway's `upstream` blocks ->
# the modules that declare that service's routes (``@app.<method>("...")``).
# A gateway location that proxies to a host missing here cannot be verified,
# and a workflow that calls it fails the check until its routes are listed.
SERVICE_SOURCES: Dict[str, Tuple[str, ...]] = {
    "open-security-cspm": ("open-security-cspm/app/main.py",),
    "open-security-data": ("open-security-data/app/api/main.py",),
    "open-security-agents": ("open-security-agents/app/main.py",),
    "open-security-responder": ("open-security-responder/app/main.py",),
}

# How a workflow names the gateway: n8n expression for the environment
# variable docker-compose passes to the automations container.
GATEWAY_BASE = re.compile(
    r"^\{\{\s*\$env(?:\.WILDBOX_API_GATEWAY_URL|\[\s*['\"]WILDBOX_API_GATEWAY_URL['\"]\s*\])\s*\}\}"
)

# Environment variables that hold a complete external URL (an incoming
# webhook of a chat service). A node may post to one of them as is.
EXTERNAL_URL_VARIABLES = frozenset({"SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"})
EXTERNAL_URL = re.compile(r"^\{\{\s*\$env\.([A-Z0-9_]+)\s*\}\}$")
# A URL whose scheme and host are written out (expressions may follow in the path).
LITERAL_URL = re.compile(r"^https?://[^/{}?#\s]+")

HTTP_NODE_TYPE = "n8n-nodes-base.httpRequest"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
EXPRESSION = re.compile(r"\{\{.*?\}\}")
# Stands for one n8n expression inside a path segment.
PLACEHOLDER = "\x00"


@dataclass(frozen=True)
class Location:
    modifier: str  # "", "=", "^~", "~" or "~*"
    pattern: str
    proxy_pass: Optional[str]
    answers: Optional[str]  # the `return` directive, when the location answers itself

    def describe(self) -> str:
        return f"location {self.modifier + ' ' if self.modifier else ''}{self.pattern}"


@dataclass(frozen=True)
class Route:
    method: str
    template: str


# --------------------------------------------------------------------------
# Gateway configuration
# --------------------------------------------------------------------------

_LOCATION = re.compile(r"^\s*location\s+(?:(=|\^~|~\*|~)\s+)?(\S+)\s*\{")
_SERVER = re.compile(r"^server\s*\{")
_LISTEN = re.compile(r"^\s*listen\s+(\d+)")
_PROXY_PASS = re.compile(r"^\s*proxy_pass\s+([^;\s]+)\s*;")
_RETURN = re.compile(r"^\s*return\s+(\d+)")
_UPSTREAM = re.compile(r"^upstream\s+(\w+)\s*\{")
_UPSTREAM_SERVER = re.compile(r"^\s*server\s+([\w.-]+)(?::\d+)?")


def parse_gateway(text: str) -> Tuple[List[Location], Dict[str, str]]:
    """Return the HTTPS server's locations and the upstream name -> host map.

    Line based: a ``location`` line opens a location that collects the
    proxy_pass and return directives that follow it, until the next location
    or server. Commented lines are skipped, so a commented-out route is no
    route. The Lua blocks inside locations hold neither directive.
    """
    upstreams: Dict[str, str] = {}
    servers: List[Tuple[Set[int], List[Location]]] = []
    current_upstream: Optional[str] = None
    pending: Optional[dict] = None

    def close_location() -> None:
        nonlocal pending
        if pending is not None and servers:
            servers[-1][1].append(Location(**pending))
        pending = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0] if raw.lstrip().startswith("#") else raw
        if not line.strip():
            continue
        match = _UPSTREAM.match(line)
        if match:
            current_upstream = match.group(1)
            continue
        if current_upstream is not None:
            match = _UPSTREAM_SERVER.match(line)
            if match and current_upstream not in upstreams:
                upstreams[current_upstream] = match.group(1)
            if line.strip() == "}":
                current_upstream = None
            continue
        if _SERVER.match(line):
            close_location()
            servers.append((set(), []))
            continue
        if not servers:
            continue
        match = _LISTEN.match(line)
        if match and pending is None:
            servers[-1][0].add(int(match.group(1)))
            continue
        match = _LOCATION.match(line)
        if match:
            close_location()
            pending = {
                "modifier": match.group(1) or "",
                "pattern": match.group(2),
                "proxy_pass": None,
                "answers": None,
            }
            continue
        if pending is None:
            continue
        match = _PROXY_PASS.match(line)
        if match:
            pending["proxy_pass"] = match.group(1)
            continue
        match = _RETURN.match(line)
        if match and pending["proxy_pass"] is None:
            pending["answers"] = match.group(1)
    close_location()

    https = [locations for ports, locations in servers if 443 in ports]
    if not https:
        raise ValueError(
            "no server block listening on 443 in the gateway configuration"
        )
    return https[0], upstreams


def match_location(
    locations: Sequence[Location], path: str
) -> Tuple[Optional[Location], Optional[re.Match]]:
    """Pick the location nginx would use for ``path``."""
    for loc in locations:
        if loc.modifier == "=" and loc.pattern == path:
            return loc, None
    prefixes = [
        loc
        for loc in locations
        if loc.modifier in ("", "^~") and path.startswith(loc.pattern)
    ]
    longest = max(prefixes, key=lambda loc: len(loc.pattern), default=None)
    if longest is not None and longest.modifier == "^~":
        return longest, None
    for loc in locations:
        if loc.modifier in ("~", "~*"):
            flags = re.IGNORECASE if loc.modifier == "~*" else 0
            found = re.search(loc.pattern, path, flags)
            if found:
                return loc, found
    return longest, None


def upstream_target(
    loc: Location, path: str, found: Optional[re.Match]
) -> Tuple[str, str]:
    """Return (upstream name, path the upstream receives) for a proxied location."""
    assert loc.proxy_pass is not None
    target = loc.proxy_pass.replace("$is_args$args", "")
    parts = urlsplit(target)
    name = parts.netloc
    uri = parts.path
    if found is not None:
        # Regex location: proxy_pass carries the captures ($1, $2, ...).
        uri = re.sub(r"\$(\d)", lambda m: found.group(int(m.group(1))) or "", uri)
        return name, uri or path
    if not uri:
        return name, path  # no URI part: nginx passes the request path unchanged
    if loc.modifier == "=":
        return name, uri
    return name, uri + path[len(loc.pattern) :]


# --------------------------------------------------------------------------
# Service route tables
# --------------------------------------------------------------------------


def service_routes(sources: Iterable[Path]) -> List[Route]:
    """Collect ``@app.<method>("<path>")`` routes from FastAPI modules."""
    routes: List[Route] = []
    for source in sources:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "app"
                    and decorator.func.attr in HTTP_METHODS
                    and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                    and isinstance(decorator.args[0].value, str)
                ):
                    continue
                routes.append(
                    Route(decorator.func.attr.upper(), decorator.args[0].value)
                )
    return routes


def template_matches(template: str, path: str) -> bool:
    """Match a concrete path (with expression placeholders) against a route template."""
    want = template.strip("/").split("/")
    have = path.strip("/").split("/")
    for index, segment in enumerate(want):
        if segment.startswith("{") and segment.endswith(":path}"):
            return len(have) > index
        if index >= len(have):
            return False
        if segment.startswith("{") and segment.endswith("}"):
            if not have[index]:
                return False
            continue
        if PLACEHOLDER in have[index] or segment != have[index]:
            return False
    return len(want) == len(have)


# --------------------------------------------------------------------------
# Workflows
# --------------------------------------------------------------------------


def _is_internal_host(host: str) -> bool:
    host = host.lower()
    return (
        "." not in host
        or host.endswith(".local")
        or host.startswith(("open-security-", "wildbox-"))
        or host in ("localhost", "127.0.0.1", "::1")
    )


def node_method(params: dict) -> str:
    method = params.get("method") or params.get("requestMethod") or "GET"
    return str(method).upper()


def node_headers(params: dict) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for key in ("headerParameters", "headerParametersUi"):
        block = params.get(key) or {}
        for entry in block.get("parameters", []) + block.get("parameter", []):
            name = str(entry.get("name", "")).strip()
            if name:
                headers[name.lower()] = str(entry.get("value", ""))
    return headers


def check_auth(params: dict, type_version: float) -> Optional[str]:
    headers = node_headers(params)
    if type_version >= 3 and headers and not params.get("sendHeaders"):
        return "declares headers but sendHeaders is off, so n8n sends none of them"
    if "cookie" in headers:
        return "sends a Cookie header; the gateway does not accept a cookie as API authentication"
    if headers.get("x-api-key", "").strip():
        return None
    auth = headers.get("authorization", "").lstrip("=").strip()
    if auth.startswith("Bearer ") and auth[len("Bearer ") :].strip():
        return None
    return "sends neither an X-API-Key header nor an Authorization: Bearer header"


class Checker:
    def __init__(self, root: Path, gateway_conf: Path):
        self.root = root
        self.locations, self.upstreams = parse_gateway(
            gateway_conf.read_text(encoding="utf-8")
        )
        self._routes: Dict[str, List[Route]] = {}

    def routes_for(self, host: str) -> Optional[List[Route]]:
        if host not in SERVICE_SOURCES:
            return None
        if host not in self._routes:
            self._routes[host] = service_routes(
                self.root / rel for rel in SERVICE_SOURCES[host]
            )
        return self._routes[host]

    def check_gateway_call(self, method: str, path: str) -> Optional[str]:
        loc, found = match_location(self.locations, path)
        if loc is None:
            return "no gateway location matches this path"
        if loc.proxy_pass is None:
            answer = (
                f"answers {loc.answers} itself" if loc.answers else "proxies nowhere"
            )
            return (
                f"the gateway's {loc.describe()} {answer}: there is no such API route"
            )
        name, upstream_path = upstream_target(loc, path, found)
        host = self.upstreams.get(name)
        if host is None:
            return f"the gateway's {loc.describe()} proxies to {name}, which this check has no route table for"
        routes = self.routes_for(host)
        if routes is None:
            return (
                f"the gateway's {loc.describe()} proxies to {host}, which this check has no route "
                "table for; add its source to SERVICE_SOURCES in scripts/check_automation_workflows.py"
            )
        same_path = [
            route for route in routes if template_matches(route.template, upstream_path)
        ]
        if not same_path:
            shown = upstream_path.replace(PLACEHOLDER, "{{...}}")
            return f"{host} has no route {shown} (the gateway's {loc.describe()} sends the call there)"
        if not any(route.method == method for route in same_path):
            allowed = ", ".join(sorted({route.method for route in same_path}))
            return f"{host} serves {same_path[0].template} for {allowed}, not {method}"
        return None

    def check_node(self, node: dict) -> Optional[str]:
        params = node.get("parameters") or {}
        url = str(params.get("url", "")).strip()
        method = node_method(params)
        if method.startswith("=") or "{{" in method:
            return "the method is an expression; it cannot be checked"
        expression = url[1:] if url.startswith("=") else url

        base = GATEWAY_BASE.match(expression)
        if base:
            rest = expression[base.end() :]
            path = EXPRESSION.sub(PLACEHOLDER, rest.split("?", 1)[0].split("#", 1)[0])
            if not path.startswith("/"):
                return "the path after the gateway base must start with /"
            problem = self.check_gateway_call(method, path)
            if problem:
                return problem
            return check_auth(params, float(node.get("typeVersion", 1)))

        external = EXTERNAL_URL.match(expression)
        if external:
            if external.group(1) in EXTERNAL_URL_VARIABLES:
                return None
            return f"the URL comes from ${external.group(1)}, which is not a known gateway or webhook variable"

        literal = LITERAL_URL.match(expression)
        if literal:
            host = urlsplit(literal.group(0)).hostname or ""
            if _is_internal_host(host):
                return (
                    f"calls the internal host {host} directly; Wildbox services take calls only "
                    "through the gateway, as {{ $env.WILDBOX_API_GATEWAY_URL }}/api/v1/..."
                )
            return None
        return "cannot resolve the URL to the gateway or to a known external address"

    def check_workflow(self, path: Path) -> Tuple[int, List[str]]:
        try:
            shown = path.resolve().relative_to(self.root.resolve())
        except ValueError:
            shown = path
        try:
            workflow = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return 0, [f"{shown}: cannot read the workflow: {exc}"]
        problems: List[str] = []
        count = 0
        for node in workflow.get("nodes", []):
            if node.get("type") != HTTP_NODE_TYPE:
                continue
            count += 1
            problem = self.check_node(node)
            if problem:
                params = node.get("parameters") or {}
                problems.append(
                    f'{shown}: node "{node.get("name")}": {node_method(params)} {params.get("url", "")}: {problem}'
                )
        return count, problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    parser.add_argument(
        "--workflows", type=Path, help="workflow directory (default: the repository's)"
    )
    parser.add_argument(
        "--gateway-conf",
        type=Path,
        help="gateway configuration (default: the repository's)",
    )
    args = parser.parse_args(argv)

    root = args.root
    workflows_dir = args.workflows or root / WORKFLOWS_DIR
    checker = Checker(root, args.gateway_conf or root / GATEWAY_CONF)

    files = sorted(workflows_dir.rglob("*.json"))
    if not files:
        print(f"ERROR: no workflow JSON under {workflows_dir}", file=sys.stderr)
        return 1

    total = 0
    problems: List[str] = []
    for file in files:
        count, found = checker.check_workflow(file)
        total += count
        problems.extend(found)

    if problems:
        print(
            f"ERROR: {len(problems)} workflow HTTP call(s) do not reach an existing API route:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} HTTP call(s) in {len(files)} workflow(s) reach existing routes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
