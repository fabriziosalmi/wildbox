"""Stand-ins for the services the agent's tools call (#652).

The tools are tested against these, never against the network. A stand-in
answers the way the real service would, and what "the real service" serves
is read from its source in this repository, so a test cannot pass against a
route, a query parameter or a body field the service does not have:

- the routes come from the services' own files, through the responder's
  ``tests/unit/service_contracts.py`` (#616), loaded here by path. A request
  to anything else is answered 404, and a request without the gateway
  identity and secret 403, as the services answer them;
- a tool's body is checked against the input model the tools service
  validates it with, read with ``ast`` from the tool's ``schemas.py``;
- the data service and Guardian answer for the caller's team only, from the
  rows a test seeds, the way their tenancy filters do.
"""

import ast
import importlib.util
import json
import re
from pathlib import Path

import httpx
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
CONTRACTS_PATH = (
    REPO_ROOT / "open-security-responder" / "tests" / "unit" / "service_contracts.py"
)
TOOLS_DIR = REPO_ROOT / "open-security-tools" / "app" / "tools"
TOOLS_BASE = REPO_ROOT / "open-security-tools" / "app" / "standardized_schemas.py"
COMPOSE = REPO_ROOT / "docker-compose.yml"

SECRET = "gateway-secret-for-tests"


def sources_available():
    return CONTRACTS_PATH.is_file() and TOOLS_BASE.is_file() and COMPOSE.is_file()


def load_contracts():
    """The responder's reader of what each service serves."""
    spec = importlib.util.spec_from_file_location(
        "wildbox_service_contracts", CONTRACTS_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contracts = load_contracts() if sources_available() else None


# --- The tools service's input models ---------------------------------------


def _classes(path):
    return {
        node.name: node
        for node in ast.parse(path.read_text()).body
        if isinstance(node, ast.ClassDef)
    }


def tool_input_class(tool):
    """The name of the model the tools service validates ``tool``'s body with.

    The rule of open-security-tools/app/tool_loader.py find_schema_classes:
    a model whose name contains "input" or "request", the shared base
    excluded; the last in name order when there are several.
    """
    names = sorted(
        name
        for name in _classes(TOOLS_DIR / tool / "schemas.py")
        if ("input" in name.lower() or "request" in name.lower())
        and name != "BaseToolInput"
    )
    assert names, f"the tools service has no input model for {tool}"
    return names[-1]


def tool_input_fields(tool):
    """{field: required} of ``tool``'s input model, BaseToolInput included."""
    schemas = TOOLS_DIR / tool / "schemas.py"
    fields = dict(contracts.model_fields(TOOLS_BASE, "BaseToolInput"))
    fields.update(contracts.model_fields(schemas, tool_input_class(tool)))
    return fields


def _literal_values(annotation, classes):
    """The values an annotation allows, or None when it allows any."""
    if isinstance(annotation, ast.Subscript):
        outer = getattr(annotation.value, "id", "")
        inner = annotation.slice
        if outer == "Literal":
            items = inner.elts if isinstance(inner, ast.Tuple) else [inner]
            return {item.value for item in items}
        if outer in ("List", "Optional"):
            return _literal_values(inner, classes)
        return None
    name = getattr(annotation, "id", None)
    if name in classes and any(
        getattr(base, "id", "") == "Enum" for base in classes[name].bases
    ):
        return {
            item.value.value
            for item in classes[name].body
            if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant)
        }
    return None


def tool_input_values(tool):
    """{field: allowed values} for the fields of ``tool`` that take a choice."""
    classes = _classes(TOOLS_DIR / tool / "schemas.py")
    allowed = {}
    for item in classes[tool_input_class(tool)].body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            values = _literal_values(item.annotation, classes)
            if values is not None:
                allowed[item.target.id] = values
    return allowed


def tool_input_problems(tool, payload):
    """Why the tools service would refuse (or ignore part of) ``payload``."""
    fields = tool_input_fields(tool)
    problems = []
    unknown = sorted(set(payload) - set(fields))
    missing = sorted(
        n for n, required in fields.items() if required and n not in payload
    )
    if unknown:
        problems.append(f"{tool} has no input field {unknown}")
    if missing:
        problems.append(f"{tool} requires {missing}")
    for name, allowed in tool_input_values(tool).items():
        if name not in payload:
            continue
        given = payload[name] if isinstance(payload[name], list) else [payload[name]]
        bad = [value for value in given if value not in allowed]
        if bad:
            problems.append(f"{tool}.{name} does not take {bad}")
    return problems


# --- What the compose file says about Guardian ------------------------------


def guardian_allowed_hosts():
    """The ALLOWED_HOSTS docker-compose.yml gives Guardian."""
    guardian = yaml.safe_load(COMPOSE.read_text())["services"]["guardian"]
    for entry in guardian["environment"]:
        name, _, value = entry.partition("=")
        if name == "ALLOWED_HOSTS":
            return {host.strip() for host in value.split(",")}
    raise AssertionError("docker-compose.yml sets no ALLOWED_HOSTS for guardian")


# --- The stand-in ------------------------------------------------------------


class Services:
    """An httpx transport handler that answers as tools, data and Guardian.

    ``indicators`` and ``vulnerabilities`` are the rows the data service and
    Guardian hold: each has a ``team_id`` (None for a data-service indicator
    of a shared feed) and a vulnerability also a ``created_by``. ``down``
    names services whose connection fails, ``answers`` maps a service to a
    fixed ``(status, body)`` or ``httpx.Response``.
    """

    def __init__(self, settings, indicators=(), vulnerabilities=()):
        self.urls = {
            "tools": settings.wildbox_api_url,
            "data": settings.wildbox_data_url,
            "guardian": settings.wildbox_guardian_url,
        }
        self.indicators = list(indicators)
        self.vulnerabilities = list(vulnerabilities)
        self.requests = []
        self.down = set()
        self.answers = {}

    def service(self, request):
        for name, url in self.urls.items():
            if str(request.url).startswith(url.rstrip("/") + "/"):
                return name
        raise AssertionError(f"request to an unknown service: {request.url}")

    def sent_to(self, service):
        return [r for r in self.requests if self.service(r) == service]

    def __call__(self, request):
        service = self.service(request)
        if service in self.down:
            raise httpx.ConnectError("All connection attempts failed", request=request)
        self.requests.append(request)
        refused = contracts.refusal(service, request, SECRET)
        if refused:
            return httpx.Response(
                refused[0],
                json={"error": {"code": refused[0], "message": refused[1]}},
            )
        if service in self.answers:
            if isinstance(self.answers[service], httpx.Response):
                return self.answers[service]
            status, body = self.answers[service]
            if isinstance(body, (dict, list)):
                return httpx.Response(status, json=body)
            return httpx.Response(status, text=body)
        return getattr(self, f"_{service}")(request)

    # tools: POST /api/tools/{tool}, body validated by the tool's input model.
    def _tools(self, request):
        tool = request.url.path.rsplit("/", 1)[-1]
        problems = tool_input_problems(tool, json.loads(request.content))
        if problems:
            return httpx.Response(
                422,
                json={
                    "error": {
                        "code": 422,
                        "message": "Input validation failed",
                        "details": {"errors": problems},
                    }
                },
            )
        return httpx.Response(200, json={"success": True, "tool_name": tool})

    # data: GET /api/v1/indicators/search, the caller's team and the shared
    # feeds (open_security_shared.tenancy team_or_global_filter).
    def _data(self, request):
        params = request.url.params
        team = request.headers["X-Wildbox-Team-ID"]
        q = (params.get("q") or "").lower()
        wanted_type = params.get("indicator_type")
        rows = [
            row
            for row in self.indicators
            if row["team_id"] in (None, team)
            and (not q or q in row["value"].lower())
            and (not wanted_type or row["indicator_type"] == wanted_type)
        ]
        limit = int(params.get("limit", 100))
        return httpx.Response(
            200,
            json={
                "indicators": [self._indicator(row) for row in rows[:limit]],
                "total": len(rows),
                "limit": limit,
                "offset": 0,
                "query_time": "2026-10-05T10:00:00Z",
            },
        )

    @staticmethod
    def _indicator(row):
        return {
            "id": row.get("id", "0b6f1c1e-8a0d-4a53-9a59-6f0c3b1e2a77"),
            "indicator_type": row["indicator_type"],
            "value": row["value"],
            "normalized_value": row["value"].lower(),
            "threat_types": row.get("threat_types", ["malware"]),
            "confidence": "high",
            "severity": 8,
            "description": row.get("description"),
            "tags": [],
            "first_seen": "2026-09-01T00:00:00Z",
            "last_seen": "2026-10-01T00:00:00Z",
            "expires_at": None,
            "active": True,
            "source_id": "5e2d1c0b-9a8f-4e7d-8c6b-5a4f3e2d1c0b",
            "indicator_metadata": {"internal": "note"},
            "created_at": "2026-09-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        }

    # guardian: GET /api/v1/vulnerabilities/?search=, the caller's team; a
    # member sees what they created (VulnerabilityViewSet.get_queryset).
    def _guardian(self, request):
        host = request.headers["Host"].rsplit(":", 1)[0]
        if host not in guardian_allowed_hosts():
            return httpx.Response(400, text="<h1>Bad Request (400)</h1>")
        # guardian/settings.py, with DEBUG off as docker-compose.yml runs it:
        # SECURE_SSL_REDIRECT, and SECURE_PROXY_SSL_HEADER trusting the
        # gateway's X-Forwarded-Proto. A plain-HTTP request that does not
        # carry it is redirected to https:// on the same host and port.
        if request.headers.get("X-Forwarded-Proto") != "https":
            return httpx.Response(
                301,
                headers={"Location": str(request.url.copy_with(scheme="https"))},
            )
        team = request.headers["X-Wildbox-Team-ID"]
        user = request.headers["X-Wildbox-User-ID"]
        privileged = request.headers.get("X-Wildbox-Role") in ("owner", "admin")
        search = (request.url.params.get("search") or "").lower()
        rows = [
            row
            for row in self.vulnerabilities
            if row["team_id"] == team
            and (privileged or row.get("created_by") == user)
            and any(
                search in str(row.get(field) or "").lower()
                for field in ("title", "description", "cve_id", "asset_name")
            )
        ]
        return httpx.Response(
            200,
            json={
                "count": len(rows),
                "next": None,
                "previous": None,
                "results": [
                    {
                        "id": row.get("id", "7a3e9c1b-5d2f-4b8a-9e6c-1f0d2b4a6c83"),
                        "title": row["title"],
                        "cve_id": row.get("cve_id"),
                        "severity": row.get("severity", "high"),
                        "status": "open",
                        "priority": "p1",
                        "risk_score": 8.1,
                        "cvss_v3_score": 9.8,
                        "asset_name": row.get("asset_name"),
                        "asset_type": "server",
                        "due_date": None,
                        "days_to_due": None,
                        "is_overdue": False,
                        "created_at": "2026-10-01T00:00:00Z",
                        "updated_at": "2026-10-01T00:00:00Z",
                    }
                    for row in rows[:50]
                ],
            },
        )


def install(monkeypatch, client_module, services):
    """Route the Wildbox client's requests to ``services``.

    The client builds an ``httpx.AsyncClient`` per call; each one gets the
    stand-in as its transport, and the client's gateway secret is the one
    the stand-in checks.
    """
    real_client = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(services)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(client_module.httpx, "AsyncClient", client)
    monkeypatch.setattr(client_module.wildbox_client, "gateway_secret", SECRET)
    return services


def no_address(text, settings):
    """``text`` names none of the services' addresses."""
    for url in (
        settings.wildbox_api_url,
        settings.wildbox_data_url,
        settings.wildbox_guardian_url,
    ):
        host = re.sub(r"^https?://", "", url)
        name = host.rsplit(":", 1)[0]
        # A bare name such as "api" is also an ordinary word; a qualified
        # one such as "open-security-data" is not.
        if url in text or host in text or ("-" in name and name in text):
            return False
    return "http://" not in text and "https://" not in text
