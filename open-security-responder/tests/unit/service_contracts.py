"""What the other Wildbox services serve, read from their source (#616).

The responder's connector tests check every request against these: the
route must be one the target service declares, and the body or query the
fields that service validates. They are read with ``ast`` from the
services' own files in this repository, the way test_shipped_playbooks_run
reads the tools' schemas (#617), so a test cannot pass against a route or a
field the real service does not have.
"""

import ast
import re
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent

TOOLS_ROUTERS = [
    REPO_ROOT / "open-security-tools" / "app" / "api" / "router.py",
    REPO_ROOT / "open-security-tools" / "app" / "api" / "async_router.py",
]
AGENTS_MAIN = REPO_ROOT / "open-security-agents" / "app" / "main.py"
AGENTS_SCHEMAS = REPO_ROOT / "open-security-agents" / "app" / "schemas.py"
DATA_MAIN = REPO_ROOT / "open-security-data" / "app" / "api" / "main.py"
DATA_SCHEMAS = REPO_ROOT / "open-security-data" / "app" / "schemas" / "api.py"
GUARDIAN = REPO_ROOT / "open-security-guardian"
GUARDIAN_URLS = GUARDIAN / "guardian" / "urls.py"
GUARDIAN_SETTINGS = GUARDIAN / "guardian" / "settings.py"
GUARDIAN_VULN_SERIALIZERS = GUARDIAN / "apps" / "vulnerabilities" / "serializers.py"
GUARDIAN_VULN_MODELS = GUARDIAN / "apps" / "vulnerabilities" / "models.py"
GUARDIAN_VULN_FILTERS = GUARDIAN / "apps" / "vulnerabilities" / "filters.py"
DATA_MODELS = REPO_ROOT / "open-security-data" / "app" / "models.py"

HTTP_METHODS = ("get", "post", "put", "delete", "patch")


def sources_available():
    return all(
        p.is_file()
        for p in TOOLS_ROUTERS
        + [AGENTS_MAIN, AGENTS_SCHEMAS, DATA_MAIN, DATA_SCHEMAS, GUARDIAN_URLS]
    )


def _path_text(node):
    """The text of a route path: a string, or an f-string with {names}."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        text = ""
        for part in node.values:
            if isinstance(part, ast.Constant):
                text += str(part.value)
            elif isinstance(part, ast.FormattedValue) and isinstance(
                part.value, ast.Name
            ):
                text += "{" + part.value.id + "}"
            else:
                return None
        return text
    return None


def fastapi_routes(*paths):
    """{(METHOD, path template): function name or None} declared in ``paths``.

    Reads ``APIRouter(prefix=...)`` assignments and every
    ``<router or app>.<method>(path)`` call, decorator or not (the tools
    service registers each tool with ``router.post(f"/tools/{tool_name}")``).
    """
    routes = {}
    for path in paths:
        tree = ast.parse(path.read_text())
        prefixes = {"app": ""}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "id", None) == "APIRouter"
            ):
                prefix = next(
                    (k.value.value for k in node.value.keywords if k.arg == "prefix"),
                    "",
                )
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        prefixes[target.id] = prefix
        decorated = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    decorated[id(decorator)] = node.name
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in HTTP_METHODS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in prefixes
                and node.args
            ):
                continue
            text = _path_text(node.args[0])
            if text is None:
                continue
            key = (node.func.attr.upper(), prefixes[node.func.value.id] + text)
            routes[key] = decorated.get(id(node))
    return routes


def tools_routes():
    return fastapi_routes(*TOOLS_ROUTERS)


def agents_routes():
    return fastapi_routes(AGENTS_MAIN)


def data_routes():
    return fastapi_routes(DATA_MAIN)


def guardian_routes():
    """{(METHOD, path template)} of the Guardian viewsets the responder uses.

    guardian/urls.py includes each app's urls under ``api/v1/<prefix>/``;
    each app registers its viewsets on a DRF DefaultRouter, which serves a
    list route (GET, POST) and a detail route (GET, PUT, PATCH, DELETE),
    both with a trailing slash.
    """
    includes = {}
    tree = ast.parse(GUARDIAN_URLS.read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "path"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Call)
            and getattr(node.args[1].func, "id", None) == "include"
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[1].args[0], ast.Constant)
        ):
            prefix = node.args[0].value
            module = node.args[1].args[0].value
            includes[prefix] = module
    routes = set()
    for prefix, module in includes.items():
        urls = GUARDIAN / Path(*module.split(".")).with_suffix(".py")
        app_tree = ast.parse(urls.read_text())
        for node in ast.walk(app_tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "register"
                and node.args
            ):
                name = node.args[0].value
                base = "/" + prefix + (name + "/" if name else "")
                routes |= {("GET", base), ("POST", base)}
                routes |= {
                    (m, base + "{pk}/") for m in ("GET", "PUT", "PATCH", "DELETE")
                }
    return routes


def route_for(routes, method, path):
    """The route template in ``routes`` that serves ``method path``, or None."""
    for route_method, template in routes:
        if route_method != method:
            continue
        pattern = "^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template)) + "$"
        if re.match(pattern, path):
            return template
    return None


def function_parameters(path, function_name):
    """The parameter names of a function in ``path``."""
    for node in ast.walk(ast.parse(path.read_text())):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ):
            return {a.arg for a in node.args.args + node.args.kwonlyargs}
    raise LookupError(f"{function_name} is not defined in {path}")


def model_fields(path, class_name):
    """{field: required} of a pydantic model defined in ``path``."""
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            fields = {}
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    fields[item.target.id] = _is_required(item.value)
            return fields
    raise LookupError(f"{class_name} is not defined in {path}")


def _is_required(value):
    if value is None:
        return True
    if not (isinstance(value, ast.Call) and getattr(value.func, "id", "") == "Field"):
        return False
    if value.args:
        first = value.args[0]
        return isinstance(first, ast.Constant) and first.value is Ellipsis
    return not any(k.arg in ("default", "default_factory") for k in value.keywords)


def model_problems(payload, path, class_name):
    """Problems with ``payload`` as an instance of a pydantic model."""
    fields = model_fields(path, class_name)
    problems = []
    unknown = sorted(set(payload) - set(fields))
    missing = sorted(n for n, req in fields.items() if req and n not in payload)
    if unknown:
        problems.append(f"{class_name} has no {unknown}")
    if missing:
        problems.append(f"{class_name} requires {missing}")
    return problems


def serializer_fields(path, class_name):
    """The ``Meta.fields`` of a DRF serializer defined in ``path``."""
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.ClassDef) and item.name == "Meta":
                    for assign in item.body:
                        if (
                            isinstance(assign, ast.Assign)
                            and assign.targets[0].id == "fields"
                        ):
                            return set(ast.literal_eval(assign.value))
    raise LookupError(f"{class_name}.Meta.fields is not defined in {path}")


def django_required_fields(path, class_name):
    """Fields of a Django model with neither a default nor null/blank."""
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            required = set()
            for item in node.body:
                if not (
                    isinstance(item, ast.Assign)
                    and isinstance(item.value, ast.Call)
                    and isinstance(item.value.func, ast.Attribute)
                    and isinstance(item.targets[0], ast.Name)
                ):
                    continue
                kind = item.value.func.attr
                if not kind.endswith(("Field", "ForeignKey")) or kind in (
                    "ManyToManyField",
                    "AutoField",
                    "UUIDField",
                ):
                    continue
                keywords = {k.arg: k.value for k in item.value.keywords}
                if "default" in keywords or any(
                    isinstance(keywords.get(k), ast.Constant) and keywords[k].value
                    for k in ("null", "blank", "auto_now", "auto_now_add")
                ):
                    continue
                required.add(item.targets[0].id)
            return required
    raise LookupError(f"{class_name} is not defined in {path}")


def filterset_names(path, class_name):
    """The query parameters a django-filter FilterSet in ``path`` declares."""
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                item.targets[0].id
                for item in node.body
                if isinstance(item, ast.Assign)
                and isinstance(item.value, ast.Call)
                and isinstance(item.value.func, ast.Attribute)
                and getattr(item.value.func.value, "id", None) == "django_filters"
            }
    raise LookupError(f"{class_name} is not defined in {path}")


def enum_values(path, class_name):
    """The string values of an Enum defined in ``path``."""
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                item.value.value
                for item in node.body
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant)
            }
    raise LookupError(f"{class_name} is not defined in {path}")


# --- A service's answer to a request it would refuse -----------------------

IDENTITY_HEADERS = ("X-Wildbox-User-ID", "X-Wildbox-Team-ID", "X-Wildbox-Role")
# The services that check an API-key scope themselves (#637), and what a
# request may say its credential is. The responder says "service".
SCOPE_CHECKING_SERVICES = ("tools", "data", "guardian")
AUTH_TYPES = ("session", "api_key", "service")


def routes_of(service):
    return {
        "tools": lambda: set(tools_routes()),
        "agents": lambda: set(agents_routes()),
        "data": lambda: set(data_routes()),
        "guardian": guardian_routes,
    }[service]()


def guardian_https_redirect():
    """Guardian's HTTPS redirect, read from guardian/settings.py.

    ``(enabled, (header, value), exempt patterns)``: Django's
    SECURE_SSL_REDIRECT, the request header SECURE_PROXY_SSL_HEADER trusts
    as proof the client used HTTPS (as an HTTP header name, not a META key),
    and the SECURE_REDIRECT_EXEMPT patterns. They are set when DEBUG is off,
    which is how docker-compose.yml runs Guardian.
    """
    found = {}
    for node in ast.walk(ast.parse(GUARDIAN_SETTINGS.read_text())):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in (
                "SECURE_SSL_REDIRECT",
                "SECURE_PROXY_SSL_HEADER",
                "SECURE_REDIRECT_EXEMPT",
            ):
                found[name] = ast.literal_eval(node.value)
    meta_key, value = found.get("SECURE_PROXY_SSL_HEADER", ("", ""))
    header = meta_key.removeprefix("HTTP_").replace("_", "-")
    return (
        bool(found.get("SECURE_SSL_REDIRECT")),
        (header, value),
        tuple(found.get("SECURE_REDIRECT_EXEMPT", ())),
    )


def https_redirect(service, request):
    """The redirect ``service`` answers a plain-HTTP ``request`` with, or None.

    Only Guardian redirects. Django's SecurityMiddleware answers 301 to
    https:// on the same host, port and path for a request that is not
    secure, and a request is secure only when it carries the header
    SECURE_PROXY_SSL_HEADER names: TLS ends at the gateway, which sends it.
    An internal caller that does not send it gets the redirect, to a port
    where nothing speaks TLS (#707). The middleware runs before the route is
    resolved and before authentication, so this comes first.
    """
    if service != "guardian" or request.url.scheme == "https":
        return None
    enabled, (header, value), exempt = guardian_https_redirect()
    if not enabled or (header and request.headers.get(header) == value):
        return None
    path = request.url.path.lstrip("/")
    if any(re.search(pattern, path) for pattern in exempt):
        return None
    return str(request.url.copy_with(scheme="https"))


def refusal(service, request, secret):
    """(status, reason) the real service answers ``request`` with, or None.

    301 for a plain-HTTP request Guardian redirects to HTTPS (see
    https_redirect); 404 for a route the service does not declare; 403 for a
    request without the gateway identity headers or with the wrong
    X-Gateway-Secret, as open_security_shared.gateway_auth (tools, agents,
    data) and Guardian's GatewayAuthMiddleware answer it; and 403 for one
    that does not say what its credential is (X-Wildbox-Auth-Type), as
    tools, data and guardian answer it wherever they check an API-key scope
    (#637).
    """
    location = https_redirect(service, request)
    if location:
        return 301, f"Moved Permanently to {location}"
    if route_for(routes_of(service), request.method, request.url.path) is None:
        return 404, f"{service} serves no {request.method} {request.url.path}"
    headers = request.headers
    if not all(headers.get(h) for h in IDENTITY_HEADERS[:2]):
        return 403, "GATEWAY_AUTH_REQUIRED"
    if headers.get("X-Gateway-Secret") != secret:
        return 403, "GATEWAY_SECRET_REQUIRED"
    if service in SCOPE_CHECKING_SERVICES and headers.get("X-Wildbox-Auth-Type") not in AUTH_TYPES:
        return 403, "GATEWAY_AUTH_TYPE_REQUIRED"
    return None
