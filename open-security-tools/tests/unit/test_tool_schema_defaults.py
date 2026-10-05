"""Every tool's input schema describes what the tool accepts (#611).

hash_generator's schema defaulted to algorithms the tool no longer
implemented, so a run with the defaults, and the form the dashboard builds
from the published schema, failed. These tests hold every registered tool to
the same contract:

* the model the endpoint validates with is the model ``/info`` publishes;
* the model validates with its defaults plus the minimal inputs below;
* every default is a valid value of its own field (pydantic does not check
  defaults, so a default outside a Literal goes unnoticed until a run), and
  every published default is one of its field's published enum values;
* every tool builds its output with ``success``, which BaseToolOutput
  requires: several did not, so every one of their runs failed validation;
* with the network and subprocesses refused, every tool's ``execute_tool``
  answers with a valid instance of its output model instead of raising, and
  the tools that need neither succeed.
"""

import ast
import asyncio
import inspect
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.standardized_schemas import BaseToolInput  # noqa: E402
from app.tool_loader import (  # noqa: E402
    find_schema_classes,
    list_tool_names,
    load_tool_module,
)
from pydantic import BaseModel, ValidationError  # noqa: E402

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# What each tool needs beyond its defaults: its required fields, and the
# field one of several alternatives a model validator asks for. Every tool
# has an entry, so a new tool has to be added here, and its schema checked.
MINIMAL_INPUTS = {
    "api_security_analyzer": {"target_url": "https://example.com"},
    # An IP literal: api_base_url resolves its host when it is validated.
    "api_security_tester": {"api_base_url": "https://93.184.215.14"},
    "base64_tool": {"operation": "encode", "data": "wildbox"},
    "blockchain_security_analyzer": {
        "contract_code": "pragma solidity ^0.8.0; contract A {}"
    },
    "ca_analyzer": {"target": "example.com"},
    "cloud_security_analyzer": {"cloud_provider": "aws"},
    "container_security_scanner": {"dockerfile_content": "FROM alpine:3.19\n"},
    "cookie_scanner": {"target_url": "https://example.com"},
    "crypto_strength_analyzer": {
        "analysis_type": "algorithm",
        "algorithm_name": "AES",
        "key_size": 256,
    },
    "ct_log_scanner": {"domain": "example.com"},
    "database_security_analyzer": {
        "database_type": "postgresql",
        "host": "db.example.com",
        "port": 5432,
        "username": "reader",
    },
    "digital_footprint_analyzer": {"target_identifier": "user@example.com"},
    "directory_bruteforcer": {"target_url": "https://example.com"},
    "dns_enumerator": {"target_domain": "example.com"},
    "dns_security_checker": {"domain": "example.com"},
    "email_harvester": {"domain": "example.com"},
    "email_security_analyzer": {"email_headers": "From: a@example.com\nSubject: hi"},
    "entra_id_security_analyzer": {},
    "file_upload_scanner": {"target_url": "https://example.com/upload"},
    "hash_cracker": {"hash_value": "5d41402abc4b2a76b9719d911017c592"},
    "hash_generator": {"input_text": "wildbox"},
    "header_analyzer": {"url": "https://example.com"},
    "http_security_scanner": {"url": "https://example.com"},
    "iot_security_scanner": {"target_ip": "192.0.2.10"},
    "ip_geolocation": {"ip_address": "8.8.8.8"},
    "jwt_analyzer": {"jwt_token": JWT},
    "jwt_decoder": {"jwt_token": JWT},
    "malware_hash_checker": {"hash_value": "d41d8cd98f00b204e9800998ecf8427e"},
    "metadata_extractor": {"file_data": "SGVsbG8="},
    "mobile_security_analyzer": {"app_package": "com.example.app"},
    "network_port_scanner": {"target": "192.0.2.10"},
    "network_scanner": {"network": "192.0.2.0/30"},
    "network_vulnerability_scanner": {"target": "192.0.2.10"},
    "password_generator": {},
    "password_strength_analyzer": {"password": "Example123!"},
    "pki_certificate_manager": {"domain": "example.com"},
    "port_scanner": {"target": "192.0.2.10"},
    "saml_analyzer": {"saml_response": "PFJlc3BvbnNlLz4="},
    "security_automation_orchestrator": {
        "workflow_name": "wildbox",
        "trigger_type": "manual",
        "workflow_steps": [],
    },
    "social_engineering_toolkit": {"target": "user@example.com"},
    "sql_injection_scanner": {"target_url": "https://example.com/login.php"},
    "ssl_analyzer": {"target": "example.com"},
    "static_malware_analyzer": {"file_content": "TVo="},
    "subdomain_scanner": {"domain": "example.com"},
    "threat_intelligence_aggregator": {"indicator": "8.8.8.8", "indicator_type": "ip"},
    "url_analyzer": {"shortened_url": "https://example.com/abc"},
    "url_security_scanner": {"url": "https://example.com"},
    "vulnerability_db_scanner": {"target": "CVE-2021-44228"},
    "web_application_firewall_bypass": {"target_url": "https://example.com"},
    "web_vuln_scanner": {"target_url": "https://example.com"},
    "whois_lookup": {"domain": "example.com"},
    "xss_scanner": {"target_url": "https://example.com/search"},
}

# Tools whose run needs no network, a subprocess or credentials.
OFFLINE_TOOLS = [
    "base64_tool",
    "crypto_strength_analyzer",
    "email_security_analyzer",
    "hash_cracker",
    "hash_generator",
    "jwt_analyzer",
    "jwt_decoder",
    "metadata_extractor",
    "password_generator",
    "password_strength_analyzer",
    "saml_analyzer",
    "security_automation_orchestrator",
    "static_malware_analyzer",
]

TOOLS = list_tool_names()


def _input_model(tool):
    module = load_tool_module(tool)
    assert module is not None, f"{tool} does not load"
    input_cls, _ = find_schema_classes(module.schemas)
    assert input_cls is not None, f"{tool} has no input model"
    return module, input_cls


def _input_candidates(schemas_module):
    """Every distinct input-looking model in a schemas module."""
    found = set()
    for name in dir(schemas_module):
        attr = getattr(schemas_module, name)
        if (
            isinstance(attr, type)
            and issubclass(attr, BaseModel)
            and attr not in (BaseModel, BaseToolInput)
            and ("input" in attr.__name__.lower() or "request" in attr.__name__.lower())
        ):
            found.add(attr)
    return found


def _resolve(node, schema):
    while isinstance(node, dict) and "$ref" in node:
        node = schema["$defs"][node["$ref"].rsplit("/", 1)[-1]]
    if isinstance(node, dict) and len(node.get("allOf", [])) == 1:
        node = _resolve(node["allOf"][0], schema)
    return node


def _enum_of(node, schema):
    """The enum values a published property admits, or None if unrestricted."""
    node = _resolve(node, schema)
    if "enum" in node:
        return node["enum"]
    if "const" in node:
        return [node["const"]]
    alternatives = node.get("anyOf") or node.get("oneOf")
    if alternatives:
        values = []
        for alternative in alternatives:
            alternative = _resolve(alternative, schema)
            if alternative.get("type") == "null":
                values.append(None)
                continue
            enum = _enum_of(alternative, schema)
            if enum is None:
                return None
            values.extend(enum)
        return values
    return None


def test_every_tool_has_minimal_inputs():
    assert sorted(MINIMAL_INPUTS) == TOOLS


@pytest.mark.parametrize("tool", TOOLS)
def test_the_published_model_is_the_validated_model(tool):
    module, input_cls = _input_model(tool)

    assert input_cls is not BaseToolInput
    # One model only: with two, which one validates depends on name order.
    assert _input_candidates(module.schemas) == {input_cls}


@pytest.fixture(scope="module")
def info_client():
    import uuid

    from app.api import router as router_module
    from app.auth import verify_api_key
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    for tool in TOOLS:
        router_module.DISCOVERED_TOOLS.setdefault(tool, load_tool_module(tool))
    app = FastAPI()
    app.include_router(router_module.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=str(uuid.uuid4()), team_id=str(uuid.uuid4()), role="member", auth_type="session"
    )
    return TestClient(app)


@pytest.mark.parametrize("tool", TOOLS)
def test_info_publishes_the_validated_model(tool, info_client):
    _, input_cls = _input_model(tool)

    response = info_client.get(f"/api/tools/{tool}/info")

    assert response.status_code == 200, response.text
    # It published BaseToolInput for the tools whose model sorts before it.
    assert response.json()["input_schema"] == input_cls.model_json_schema()


@pytest.mark.parametrize("tool", TOOLS)
def test_required_fields_are_covered(tool):
    _, input_cls = _input_model(tool)
    required = {name for name, f in input_cls.model_fields.items() if f.is_required()}
    assert required <= set(MINIMAL_INPUTS[tool])


@pytest.mark.parametrize("tool", TOOLS)
def test_the_defaults_validate(tool):
    _, input_cls = _input_model(tool)
    built = input_cls(**MINIMAL_INPUTS[tool])

    # Pydantic does not validate defaults; a round trip through JSON does,
    # as the endpoint would for a client that sends them back explicitly.
    input_cls.model_validate(json.loads(built.model_dump_json()))


@pytest.mark.parametrize("tool", TOOLS)
def test_published_defaults_are_published_enum_values(tool):
    _, input_cls = _input_model(tool)
    schema = input_cls.model_json_schema()

    for name, prop in schema["properties"].items():
        if "default" not in prop:
            continue
        default = prop["default"]
        node = _resolve(prop, schema)
        if isinstance(default, list) and node.get("type") == "array":
            allowed = _enum_of(node.get("items", {}), schema)
            values = default
        else:
            allowed = _enum_of(prop, schema)
            values = [default]
        if allowed is None:
            continue
        stray = [v for v in values if v not in allowed]
        assert not stray, f"{tool}.{name}: default {stray} not in {allowed}"


@pytest.fixture
def no_network(monkeypatch):
    """Make every target unreachable, and every binary missing.

    Names resolve, to a public address, so the SSRF guards that resolve a
    target before a tool contacts it let it through; every connection is
    then refused, as for a host that is down, and every subprocess fails as
    for a binary that is not installed. send() is left alone, since the
    event loop wakes itself through a socket pair.
    """
    import aiohttp.connector
    import aiohttp.resolver
    import app.safe_http
    from app.utils.tool_utils import RateLimiter

    def refuse(*args, **kwargs):
        raise ConnectionRefusedError("network access in a unit test")

    public = "93.184.215.14"

    def resolve(host, port=None, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (public, port or 0))]

    def no_binary(*args, **kwargs):
        raise FileNotFoundError("subprocess in a unit test")

    async def no_binary_async(*args, **kwargs):
        no_binary()

    async def no_wait(self):
        return None

    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "gethostbyname", lambda host: public)
    monkeypatch.setattr(socket, "gethostbyname_ex", lambda host: (host, [], [public]))
    # aiohttp's default resolver, aiodns, resolves in C, past the patches.
    threaded = aiohttp.resolver.ThreadedResolver
    monkeypatch.setattr(aiohttp.connector, "DefaultResolver", threaded)
    monkeypatch.setattr(app.safe_http, "DefaultResolver", threaded)
    monkeypatch.setattr(subprocess, "run", no_binary)
    monkeypatch.setattr(subprocess, "Popen", no_binary)
    monkeypatch.setattr(subprocess, "check_output", no_binary)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_binary_async)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", no_binary_async)
    # Rate limiting is not under test; directory_bruteforcer's would sleep
    # for minutes, xss_scanner's for seconds.
    monkeypatch.setattr(RateLimiter, "acquire", no_wait)
    monkeypatch.setattr(time, "sleep", lambda seconds: None)


def _run(module, params):
    kwargs = {}
    if "user_id" in inspect.signature(module.execute_tool).parameters:
        kwargs["user_id"] = "unit-test"
    result = module.execute_tool(params, **kwargs)
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return result


def _run_with_deadline(module, params, seconds=60):
    """_run in a thread, so a tool that hangs fails the test instead."""
    outcome = {}

    def work():
        try:
            outcome["result"] = _run(module, params)
        except BaseException as exc:  # noqa: B902 - reported below
            outcome["error"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"no answer within {seconds}s"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["result"]


@pytest.mark.parametrize("tool", OFFLINE_TOOLS)
def test_an_offline_tool_runs_with_its_defaults(tool, no_network):
    module, input_cls = _input_model(tool)
    result = _run(module, input_cls(**MINIMAL_INPUTS[tool]))

    error = getattr(result, "error", None) or getattr(result, "error_message", None)
    assert result.success is True, error


@pytest.mark.parametrize("tool", TOOLS)
def test_every_output_is_built_with_success(tool):
    module = load_tool_module(tool)
    _, output_cls = find_schema_classes(module.schemas)
    names = {k for k, v in vars(module).items() if v is output_cls}
    names.add(output_cls.__name__)

    missing = []
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        keywords = {k.arg for k in node.keywords}
        # None is a **mapping, which may carry it.
        if called in names and "success" not in keywords and None not in keywords:
            missing.append(node.lineno)

    assert (
        not missing
    ), f"{output_cls.__name__}(...) without success= at lines {missing}"


@pytest.mark.parametrize("tool", TOOLS)
def test_a_run_without_network_answers_with_a_valid_output(tool, no_network):
    module, input_cls = _input_model(tool)
    _, output_cls = find_schema_classes(module.schemas)

    result = _run_with_deadline(module, input_cls(**MINIMAL_INPUTS[tool]))

    assert isinstance(result, output_cls)
    # Built from its own fields again, so a field set after construction
    # cannot hide an invalid output.
    output_cls.model_validate(result.model_dump())
    assert isinstance(result.success, bool)


# Values each tool's main.py refused, ignored or crashed on at run time, now
# refused by its input model (so the endpoint answers 422 before running).
REFUSED = [
    ("api_security_analyzer", {"api_type": "gRPC"}),
    ("api_security_tester", {"authentication_type": "oauth"}),
    ("api_security_tester", {"authentication_value": "two words"}),
    ("api_security_tester", {"test_categories": ["broken_auth"]}),
    ("api_security_tester", {"wordlist": "../../etc/passwd"}),
    ("base64_tool", {"data": ""}),
    ("blockchain_security_analyzer", {"contract_code": None}),
    ("blockchain_security_analyzer", {"blockchain": "solana"}),
    ("cloud_security_analyzer", {"cloud_provider": "multi"}),
    ("cloud_security_analyzer", {"compliance_frameworks": ["nist"]}),
    ("cloud_security_analyzer", {"services_to_check": ["rds"]}),
    ("container_security_scanner", {"dockerfile_content": None}),
    ("container_security_scanner", {"image_name": "--output=/tmp/x"}),
    ("crypto_strength_analyzer", {"analysis_type": "certificate"}),
    ("crypto_strength_analyzer", {"algorithm_name": None}),
    ("crypto_strength_analyzer", {"algorithm_name": "SHA-256"}),
    ("crypto_strength_analyzer", {"compliance_standards": ["PCI-DSS"]}),
    ("ct_log_scanner", {"domain": "https://example.com"}),
    ("ct_log_scanner", {"max_results": 0}),
    ("ct_log_scanner", {"days_back": -1}),
    ("database_security_analyzer", {"database_type": "mongodb"}),
    ("database_security_analyzer", {"username": None}),
    ("database_security_analyzer", {"port": 0}),
    ("digital_footprint_analyzer", {"identifier_type": "bogus"}),
    (
        "digital_footprint_analyzer",
        {"identifier_type": "email", "target_identifier": "alice"},
    ),
    ("directory_bruteforcer", {"target_url": "example.com"}),
    ("directory_bruteforcer", {"wordlist_size": "huge"}),
    ("directory_bruteforcer", {"extensions": [".php"]}),
    ("email_harvester", {"search_engines": ["yahoo"]}),
    ("email_harvester", {"search_engines": None}),
    ("file_upload_scanner", {"test_types": ["polyglot"]}),
    ("hash_cracker", {"hash_type": "sha3_256"}),
    ("hash_cracker", {"wordlist_type": "custom"}),
    ("hash_cracker", {"wordlist_type": "huge"}),
    ("iot_security_scanner", {"target_ip": None}),
    ("metadata_extractor", {"file_data": None}),
    ("mobile_security_analyzer", {"app_package": None}),
    ("mobile_security_analyzer", {"platform": "windows"}),
    ("network_port_scanner", {"ports": None}),
    ("network_port_scanner", {"scan_type": "syn"}),
    ("network_port_scanner", {"timeout": 0}),
    ("network_scanner", {"scan_type": "comprehensive"}),
    ("network_vulnerability_scanner", {"scan_type": "ultra"}),
    ("network_vulnerability_scanner", {"port_range": "22,80-90"}),
    ("password_strength_analyzer", {"password": ""}),
    ("password_strength_analyzer", {"password": "Aa1!" * 33}),
    ("pki_certificate_manager", {"domain": None}),
    ("port_scanner", {"target": None}),
    ("port_scanner", {"ports": [0]}),
    ("port_scanner", {"scan_type": "udp"}),
    ("security_automation_orchestrator", {"execution_mode": "random"}),
    ("security_automation_orchestrator", {"trigger_type": "cron"}),
    ("social_engineering_toolkit", {"analysis_type": "sms"}),
    ("sql_injection_scanner", {"method": "PUT"}),
    ("subdomain_scanner", {"wordlist_size": "huge"}),
    ("threat_intelligence_aggregator", {"indicator_type": "asn"}),
    ("threat_intelligence_aggregator", {"sources": ["malwarebazaar"]}),
    ("threat_intelligence_aggregator", {"sources": None}),
    ("vulnerability_db_scanner", {"scan_type": "telepathy"}),
    ("vulnerability_db_scanner", {"severity_filter": ["urgent"]}),
    ("web_application_firewall_bypass", {"payload_types": ["ldap"]}),
    ("web_application_firewall_bypass", {"encoding_techniques": ["rot13"]}),
    ("web_application_firewall_bypass", {"obfuscation_methods": ["zalgo"]}),
    ("xss_scanner", {"method": "PUT"}),
    ("xss_scanner", {"payload_type": "blind"}),
]


@pytest.mark.parametrize(
    "tool,override", REFUSED, ids=[f"{t}-{'-'.join(o)}" for t, o in REFUSED]
)
def test_values_the_tool_cannot_run_are_refused(tool, override):
    _, input_cls = _input_model(tool)
    with pytest.raises(ValidationError):
        input_cls(**{**MINIMAL_INPUTS[tool], **override})


# Fields the tool compares regardless of case: the old spellings still work.
CASE_INSENSITIVE = [
    ("api_security_analyzer", "api_type", "graphql", "GraphQL"),
    ("cloud_security_analyzer", "cloud_provider", "AWS", "aws"),
    ("crypto_strength_analyzer", "algorithm_name", "aes", "AES"),
    ("database_security_analyzer", "database_type", "MySQL", "mysql"),
    ("network_scanner", "scan_type", "TCP", "tcp"),
    ("sql_injection_scanner", "method", "post", "POST"),
    ("xss_scanner", "method", "post", "POST"),
]


@pytest.mark.parametrize("tool,field,sent,stored", CASE_INSENSITIVE)
def test_a_case_insensitive_choice_is_normalised(tool, field, sent, stored):
    _, input_cls = _input_model(tool)
    built = input_cls(**{**MINIMAL_INPUTS[tool], field: sent})
    assert getattr(built, field) == stored


def test_list_items_are_normalised_too():
    _, harvester = _input_model("email_harvester")
    _, vulndb = _input_model("vulnerability_db_scanner")

    built = harvester(domain="example.com", search_engines=["Google", "BING"])
    assert built.search_engines == ["google", "bing"]
    built = vulndb(target="nginx", severity_filter=["Critical"])
    assert built.severity_filter == ["critical"]


def test_the_wordlist_enum_is_the_shipped_wordlists():
    from app.tools.wordlists import list_available_wordlists

    _, input_cls = _input_model("api_security_tester")
    schema = input_cls.model_json_schema()
    assert _enum_of(schema["properties"]["wordlist"], schema) == list(
        list_available_wordlists()
    )


def test_the_longest_accepted_password_is_analysed(no_network):
    # The bound exists because 2 ** entropy overflowed for long passwords.
    module, input_cls = _input_model("password_strength_analyzer")
    longest = input_cls.model_fields["password"].metadata
    max_length = next(m.max_length for m in longest if hasattr(m, "max_length"))
    password = ("Aa1!" * max_length)[:max_length]

    result = _run(module, input_cls(password=password))

    assert result.success is True


def test_a_workflow_step_gets_the_tools_own_input_model():
    from app.tools.email_security_analyzer.schemas import EmailSecurityInput
    from app.tools.security_automation_orchestrator.main import (
        SecurityAutomationOrchestrator,
    )

    built = SecurityAutomationOrchestrator()._create_tool_input(
        "email_security_analyzer", MINIMAL_INPUTS["email_security_analyzer"]
    )

    # It was the imported BaseToolInput, the first name ending in "Input".
    assert type(built) is EmailSecurityInput
    assert (
        built.email_headers
        == MINIMAL_INPUTS["email_security_analyzer"]["email_headers"]
    )


def test_port_scanner_reports_the_open_ports(no_network, monkeypatch):
    # The output was built with a "results" field it does not have, so an
    # open port was dropped even once success was passed.
    module, input_cls = _input_model("port_scanner")

    class _Writer:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(host, port, **kwargs):
        if port == 22:
            return object(), _Writer()
        raise ConnectionRefusedError(port)

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = _run(module, input_cls(target="192.0.2.10", ports=[22, 80]))

    assert result.success is True
    assert [(p.port, p.state) for p in result.open_ports] == [(22, "open")]
    assert result.closed_ports == 1


def test_base64_garbage_is_a_failed_result():
    # The decoder re-raised a bare Exception that nothing caught.
    module, input_cls = _input_model("base64_tool")

    result = _run(module, input_cls(operation="decode", data="@@not base64@@"))

    assert result.success is False
    assert "Decoding failed" in result.error


@pytest.mark.parametrize(
    "tool", ["ca_analyzer", "pki_certificate_manager", "whois_lookup"]
)
def test_a_name_that_does_not_resolve_is_a_failed_result(tool, no_network, monkeypatch):
    # socket.gaierror is an OSError, not the ConnectionError these caught.
    def no_name(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "name lookup in a unit test")

    for name in (
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "create_connection",
    ):
        monkeypatch.setattr(socket, name, no_name)
    module, input_cls = _input_model(tool)

    result = _run_with_deadline(module, input_cls(**MINIMAL_INPUTS[tool]))

    assert result.success is False


def test_a_malformed_indicator_is_a_failed_result(no_network):
    module, input_cls = _input_model("threat_intelligence_aggregator")

    result = _run(module, input_cls(indicator="not-an-ip", indicator_type="ip"))

    assert result.success is False
    assert "Invalid ip format" in result.error_message
