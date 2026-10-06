"""No service writes what a request held into its log (#755).

The tools service put the whole validated input of every run in the record
"Executing tool": a password to grade, a token to decode, a key to test.
Around it, in every service, the same thing had other shapes: the URL of a
request with its query, a connector's parameters with six key names masked
and the rest as they came, an indicator, the address typed into a login
form, the body of another service's answer, the broker URL with its
password, every header but three.

A log is read by more people, kept for longer and copied to more places than
the request it describes. So a line may say what a request was (the route,
the caller, the names of the fields) and never what it held. This reads
every tracked Python file of the services and the shared package and
refuses, in the arguments of a logging call (``logger.info(...)``,
``logging.warning(...)``, ``print(...)`` outside a ``__main__`` block), a
value whose name says it is a request, a part of one, or a credential:

- a name from ``PAYLOAD``, or one that ends like one (``safe_params``,
  ``raw_body``, ``event_data``);
- a name that says credential (``SECRET``): ``token``, ``api_key``,
  ``redis_url``;
- a dump of a model or a request: ``.model_dump()``, ``.dict()``,
  ``.json()``, ``.body()``;
- a key read by name: ``headers.get("authorization")``, ``data["password"]``.

A name is a finding only where it is used as a value. ``request.method``
reads one field of the request and is judged by that field's name;
``str(request)`` logs the request. What is passed to one of ``REDUCERS`` is
not a finding either: each of them returns a shape of its argument (its
length, its field names, its host, the class of an error) and is tested for
it in the service that defines it.

What is left is listed in ``ALLOWED``, each with the reason it was read and
accepted. The list must be exact: a finding that is not there fails, and so
does an entry that no longer matches anything.

The gateway is nginx and Lua and is read by text: its access-log formats may
not name a variable that holds a query string or a credential, and no Lua
log call may be handed a body, a token or a header's value.
"""

import ast
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
_SKIPPED_PARTS = frozenset({"tests", "test", "node_modules", "migrations"})

LOG_METHODS = frozenset(
    {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "exception",
        "critical",
        "fatal",
        "log",
    }
)
# What a logger is called: logger, log, logging, self.logger, audit_logger,
# getLogger(...). Not everything with "log" in it: a catalog is not one.
_LOGGER_NAME = re.compile(
    r"(?i)^(_?log(ger|ging)?|\w*_log(ger)?|\w*logger|get_?logger)$"
)
# Arguments of a logging call that are not what it logs.
_NOT_LOGGED = frozenset({"exc_info", "stack_info", "stacklevel"})

# Functions whose result is a shape of their argument, never its content.
REDUCERS = frozenset(
    {
        "len",
        "type",
        "bool",
        "isinstance",
        "id",
        # open-security-tools/app/log_safety.py
        "field_names",
        "error_site",
        "host_of",
        # open-security-tools/app/prerun.py
        "refusal_log",
        # open-security-data/app/utils/log_safety.py
        "describe_error",
        # open-security-identity/app/token_blacklist.py
        "account_digest",
        # open-security-agents/app/tools/wildbox_client.py
        "_logged",
        # open-security-guardian/apps/core/middleware.py: the client's address
        "get_client_ip",
    }
)

# A request, or a part of one a caller fills in; a whole settings object.
PAYLOAD = frozenset(
    {
        "input_data",
        "validated_input",
        "tool_input",
        "request_data",
        "body",
        "payload",
        "payloads",
        "params",
        "parameters",
        "query_params",
        "query_string",
        "kwargs",
        "headers",
        "cookies",
        "request",
        "req",
        "environ",
        "META",
        "settings",
        "config",
        "url",
        "detail",
        "email",
        "ioc_value",
        "env_value",
    }
)
_PAYLOAD_ENDING = re.compile(
    r"_(params|parameters|headers|cookies|body|payload|payloads|input|inputs|data|url)$"
)
# A name that says the value is a credential.
SECRET = re.compile(
    r"(?i)(passw(or)?d|passwd|secret|token|api_?key|authorization|cookie|"
    r"credential|private_?key|session_?id|dsn|database_url|redis_url|"
    r"broker_url|connection_string|bearer|signature)"
)
# Methods that return the whole of a model, a request or a response.
DUMPS = frozenset({"model_dump", "model_dump_json", "dict", "json", "body", "form"})


def names_a_payload(name: str) -> bool:
    # A header is named with hyphens: "X-API-Key" is api_key.
    plain = name.replace("-", "_")
    return (
        plain in PAYLOAD
        or bool(_PAYLOAD_ENDING.search(plain))
        or bool(SECRET.search(plain))
    )


def _receiver(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _receiver(node.func)
    return ""


def is_logging_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "print"
    return (
        isinstance(func, ast.Attribute)
        and func.attr in LOG_METHODS
        and bool(_LOGGER_NAME.match(_receiver(func.value)))
    )


def _string(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def logged_values(argument: ast.AST) -> set:
    """The names, among those an argument reads as values, that name a payload."""
    found = set()

    def visit(node, parent):
        if isinstance(node, ast.Call):
            callee = node.func
            called = (
                callee.attr if isinstance(callee, ast.Attribute) else _receiver(callee)
            )
            if called in REDUCERS:
                return
            if called in DUMPS and isinstance(callee, ast.Attribute):
                found.add(f"{called}()")
            # x.get("key"), x.pop("key"): the key says what is read.
            if called in ("get", "pop") and node.args and _string(node.args[0]):
                if names_a_payload(_string(node.args[0])):
                    found.add(_string(node.args[0]))
            if called == "getattr" and len(node.args) > 1 and _string(node.args[1]):
                # getattr(x, "name"): one field of x, judged by its name.
                if names_a_payload(_string(node.args[1])):
                    found.add(_string(node.args[1]))
                for extra in node.args[2:]:
                    visit(extra, node)
                return
        if isinstance(node, ast.Subscript) and _string(node.slice):
            if names_a_payload(_string(node.slice)):
                found.add(_string(node.slice))
        # x.field and x["field"] read one field of x, which is judged by
        # its own name. x[0] and x[:8] are still x: a piece of a token is
        # the token.
        read_further = (isinstance(parent, ast.Attribute) and parent.value is node) or (
            isinstance(parent, ast.Subscript)
            and parent.value is node
            and _string(parent.slice) is not None
        )
        is_callee = isinstance(parent, ast.Call) and parent.func is node
        if not read_further and not is_callee:
            name = (
                node.id
                if isinstance(node, ast.Name)
                else node.attr if isinstance(node, ast.Attribute) else None
            )
            if name and names_a_payload(name):
                found.add(name)
        for child in ast.iter_child_nodes(node):
            visit(child, node)

    visit(argument, None)
    return found


def problems(source: str) -> list:
    """(line, names) for each logging call that is handed a payload."""
    tree = ast.parse(source)
    in_main = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
        ):
            in_main.update(id(inner) for inner in ast.walk(node))
    found = []
    for node in ast.walk(tree):
        if not is_logging_call(node):
            continue
        if isinstance(node.func, ast.Name) and id(node) in in_main:
            continue  # a module run by hand prints to the terminal of whoever runs it
        names = set()
        for argument in node.args:
            names |= logged_values(argument)
        for keyword in node.keywords:
            if keyword.arg not in _NOT_LOGGED:
                names |= logged_values(keyword.value)
        if names:
            found.append((node.lineno, sorted(names)))
    return sorted(found)


def service_files() -> list:
    listed = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--",
            "open-security-*/**/*.py",
            "open-security-*/*.py",
        ],
        cwd=REPO,
        capture_output=True,
        check=True,
    )
    paths = {path for path in listed.stdout.decode().split("\0") if path}
    return sorted(
        path
        for path in paths
        if not _SKIPPED_PARTS & set(path.split("/")[:-1])
        and not Path(path).name.startswith("test_")
    )


# --- the rule ----------------------------------------------------------------


def check(body: str) -> list:
    return [names for _, names in problems(textwrap.dedent(body))]


def test_the_record_the_tools_service_had_is_refused():
    assert check("""
        logger.info(f"Executing tool: {tool_name}", extra={
            "tool": tool_name,
            "input": validated_input.model_dump(),
            "request_id": getattr(request.state, "request_id", "unknown"),
        })
        """) == [["model_dump()"]]


def test_the_record_it_has_now_is_accepted():
    assert check("""
        logger.info(f"Executing tool: {tool_name}", extra={
            "tool": tool_name,
            "user_id": str(caller.user_id),
            "team_id": str(caller.team_id),
            "input_fields": field_names(validated_input),
            "request_id": getattr(request.state, "request_id", "unknown"),
        })
        """) == []


@pytest.mark.parametrize(
    "call, names",
    [
        ('logger.info(f"submitted: {input_data}")', ["input_data"]),
        ('logger.info("submitted: %s", input_data)', ["input_data"]),
        ('logger.info("submitted", extra={"input": input_data})', ["input_data"]),
        ('logger.debug("got %r", request)', ["request"]),
        ('logger.debug(f"{request.url}")', ["url"]),
        ("logger.debug(str(request.headers))", ["headers"]),
        ('logger.debug("h", extra={"headers": dict(request.headers)})', ["headers"]),
        ('logger.debug("h", extra={"headers": safe_headers})', ["safe_headers"]),
        ('logger.info(f"with params: {safe_params}")', ["safe_params"]),
        ('logger.info(request.headers.get("Authorization"))', ["Authorization"]),
        ('logger.info(request.headers["x-api-key"])', ["x-api-key"]),
        ('logger.info(f"key {api_key}")', ["api_key"]),
        ('logger.info(f"bearer {access_token[:8]}")', ["access_token"]),
        (
            'logger.info("configured", extra={"broker": settings.redis_url})',
            ["redis_url"],
        ),
        ('logger.info(f"settings: {settings}")', ["settings"]),
        ("logger.info(await request.json())", ["json()"]),
        ("logger.info(payload.dict())", ["dict()"]),
        ('logger.warning("event", extra={"kind": kind, **kwargs})', ["kwargs"]),
        ('self.logger.error(f"refused: {exc.detail}")', ["detail"]),
        ("logging.getLogger(__name__).info(body)", ["body"]),
        ('log.info(f"IOC {ioc_value}")', ["ioc_value"]),
        ('logger.warning(f"locked: {email}")', ["email"]),
        ('print(f"got {payload}")', ["payload"]),
    ],
)
def test_a_payload_handed_to_a_log_call_is_refused(call, names):
    assert check(call) == [names]


@pytest.mark.parametrize(
    "call",
    [
        'logger.info(f"{request.method} {request.url.path}")',
        'logger.info("request", extra={"path": request.url.path, "method": request.method})',
        'logger.info(request.headers.get("user-agent", "unknown"))',
        'logger.info(f"{len(input_data)} fields")',
        'logger.info(f"fields: {field_names(validated_input)}")',
        'logger.error(f"failed: {error_site(e)}")',
        'logger.error(f"fetching {host_of(url)}: {type(e).__name__}")',
        'logger.info(f"port {settings.port}, debug {settings.debug}")',
        'logger.info(f"user {user.user_id} team {user.team_id}")',
        'logger.exception("Workflow step: tool %s failed", tool_name)',
        'logger.info(f"Token blacklisted (TTL={ttl}s)")',
        'logger.info("done", exc_info=request)',
        "math.log(payload)",
        "catalog.info(payload)",
    ],
)
def test_the_shape_of_a_request_is_accepted(call):
    assert check(call) == []


def test_a_module_run_by_hand_may_print_what_it_made():
    assert check("""
        def helper(payload):
            print(payload)

        if __name__ == "__main__":
            result = run()
            print(f"Token: {result.token}")
        """) == [["payload"]]


# --- the repository ----------------------------------------------------------

# (file, name) -> why it was read and accepted. Nothing here is a request's
# content or a credential.
ALLOWED = {
    ("open-security-agents/app/main.py", "team_data"): (
        "the names of the tools AGENT_TEAM_DATA_TOOLS enables, from the "
        "service's own settings, logged once at start-up"
    ),
    ("open-security-data/app/api/main.py", "url"): (
        "what follows the '@' of DATABASE_URL (host, port, database), logged "
        "once at start-up; the user and the password before it are cut"
    ),
    ("open-security-data/manage.py", "url"): (
        "`manage.py sources list`: an operator's command prints the sources "
        "it was asked to list, to that operator's terminal"
    ),
    ("open-security-identity/demo.py", "api_key"): (
        "a demonstration script run by hand: it prints the ORM object of the "
        "key it has just made, whose repr holds the prefix and no secret"
    ),
    ("open-security-sensor/sensor/pipeline/data_forwarder.py", "ingest_url"): (
        "data_lake.ingest_url, the gateway address the operator configured "
        "the sensor to send to, logged once when its session is made; the "
        "sensor's key travels in a header and is not logged"
    ),
    ("open-security-responder/app/connectors/base.py", "params"): (
        "sorted(params): the names of the parameters a playbook step passes "
        "to an action, which the playbook's author wrote; no value"
    ),
}


def repository_findings() -> dict:
    found = {}
    for path in service_files():
        source = (REPO / path).read_text(encoding="utf-8")
        for line, names in problems(source):
            for name in names:
                found.setdefault((path, name), []).append(line)
    return found


def test_the_services_have_log_calls_for_this_to_read():
    # More than 800 when this was written, in ten packages.
    calls = 0
    packages = set()
    for path in service_files():
        tree = ast.parse((REPO / path).read_text(encoding="utf-8"))
        here = sum(1 for node in ast.walk(tree) if is_logging_call(node))
        if here:
            packages.add(path.split("/")[0])
        calls += here
    assert calls >= 800, calls
    assert len(packages) >= 9, sorted(packages)


def test_no_log_call_is_handed_a_request_or_a_credential():
    found = repository_findings()
    unexpected = {
        f"{path}:{lines[0]}: {name}"
        for (path, name), lines in found.items()
        if (path, name) not in ALLOWED
    }
    assert not unexpected, (
        "a logging call is handed a value whose name says it is a request, a "
        "part of one or a credential. Log its shape (a count, the field names, "
        "a host, an id), or, if the value is none of those, list it in ALLOWED "
        "with the reason:\n  " + "\n  ".join(sorted(unexpected))
    )


def test_every_exception_listed_still_exists():
    found = repository_findings()
    stale = sorted(
        f"{path}: {name}" for path, name in ALLOWED if (path, name) not in found
    )
    assert not stale, f"ALLOWED lists what is no longer in the code: {stale}"


def test_every_exception_has_a_reason():
    for key, reason in ALLOWED.items():
        assert len(reason.split()) >= 8, key


# --- the gateway ---------------------------------------------------------------

GATEWAY = REPO / "open-security-gateway"
# nginx variables that hold what a client sent: the request line and the URI
# with their query string, the query itself, the body, and the headers that
# carry a credential or a URL.
_REQUEST_VARIABLES = re.compile(
    r"\$(request|request_uri|args|query_string|request_body|arg_\w+|"
    r"http_referer|http_authorization|http_cookie|http_x_api_key|"
    r"http_x_gateway_secret|cookie_\w+)\b"
)
_LOG_FORMAT = re.compile(r"\blog_format\s+(\w+)\s+((?:'[^']*'\s*)+);")
# What a Lua log call may not be handed: a body, a credential, the request's
# own headers or arguments.
_LUA_VALUES = re.compile(
    r"\b(res\.body|body\s*=\s*\w+\.body|token\s*=\s*token|api_key\s*=|"
    r"password\s*=|secret\s*=|get_headers\s*\(|get_uri_args\s*\(|"
    r"get_body_data\s*\(|ngx\.var\.http_\w+|ngx\.var\.args|ngx\.var\.request_uri|"
    r"ngx\.var\.query_string|ngx\.var\.cookie_\w+)"
)


def gateway_files(*suffixes) -> list:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "open-security-gateway"],
        cwd=REPO,
        capture_output=True,
        check=True,
    )
    return sorted(
        path for path in listed.stdout.decode().split("\0") if path.endswith(suffixes)
    )


def log_formats(text: str) -> dict:
    return {
        name: " ".join(re.findall(r"'([^']*)'", body))
        for name, body in _LOG_FORMAT.findall(text)
    }


def _without_lengths(call: str) -> str:
    """A Lua call without its length expressions: ``#token``, ``#(x or "")``."""
    return re.sub(r"#\([^()]*\)|#[\w.]+", "0", call)


def lua_log_calls(text: str) -> list:
    """(line, the text of the call) for each utils.log / ngx.log call."""
    calls = []
    for match in re.finditer(r"\b(?:utils|_M|ngx)\.log\s*\(", text):
        depth, index = 0, match.end() - 1
        while index < len(text):
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        calls.append(
            (text.count("\n", 0, match.start()) + 1, text[match.start() : index + 1])
        )
    return calls


def test_an_access_log_format_that_names_the_request_line_is_refused():
    formats = log_formats("""
        log_format old '$remote_addr "$request" $status "$http_referer"';
        log_format new '$remote_addr "$request_method $request_path $server_protocol" '
                       '$status rid=$request_id';
        """)

    assert sorted(m.group(0) for m in _REQUEST_VARIABLES.finditer(formats["old"])) == [
        "$http_referer",
        "$request",
    ]
    assert not _REQUEST_VARIABLES.search(formats["new"])


def test_the_gateways_access_logs_name_no_query_string_and_no_credential():
    read = 0
    for path in gateway_files(".conf", ".sh", ".template"):
        formats = log_formats((REPO / path).read_text(encoding="utf-8"))
        for name, body in formats.items():
            read += 1
            named = sorted({m.group(0) for m in _REQUEST_VARIABLES.finditer(body)})
            assert not named, f"{path}: log_format {name} names {named}"
    # nginx.conf has two. Every tracked file that could hold one is read:
    # the configurations, and the scripts and templates that write them.
    assert read >= 2, read


def test_the_path_the_access_log_names_is_cut_at_the_query():
    text = (GATEWAY / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    block = re.search(r"map\s+\$request_uri\s+\$request_path\s*\{([^}]*)\}", text)
    assert block, "nginx.conf no longer derives $request_path from $request_uri"
    (pattern,) = re.findall(r'"~([^"]+)"\s+\$p;', block.group(1))
    for uri, path in (
        ("/api/v1/data/search?q=198.51.100.7&token=abc", "/api/v1/data/search"),
        ("/api/v1/tools/?", "/api/v1/tools/"),
        ("/a?b?c", "/a"),
    ):
        match = re.match(pattern.replace("(?<p>", "(?P<p>"), uri)
        assert match and match.group("p") == path, uri
    # Without a query nothing matches, and the default is the URI itself.
    assert not re.match(pattern.replace("(?<p>", "(?P<p>"), "/api/v1/tools/whois")
    assert re.search(r"default\s+\$request_uri;", block.group(1))
    assert "$request_path" in log_formats(text)["gateway"]


def test_a_lua_log_call_that_is_handed_a_body_is_refused():
    calls = lua_log_calls("""
        utils.log("error", "Identity service returned unexpected status", {
            status = res.status,
            body = res.body,
        })
        utils.log("debug", "Token validation successful", {user_id = auth_data.user_id})
        utils.log("error", "Failed to decode identity response", {
            body_bytes = #(res.body or ""),
            length = #token,
        })
        """)

    assert [bool(_LUA_VALUES.search(_without_lengths(text))) for _, text in calls] == [
        True,
        False,
        False,
    ]


def test_no_lua_log_call_is_handed_a_body_a_credential_or_a_header():
    read = 0
    for path in gateway_files(".lua", ".conf"):
        for line, text in lua_log_calls((REPO / path).read_text(encoding="utf-8")):
            read += 1
            found = _LUA_VALUES.search(_without_lengths(text))
            assert not found, f"{path}:{line}: a log call is handed {found.group(0)!r}"
    assert read >= 30, read
