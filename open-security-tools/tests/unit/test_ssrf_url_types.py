"""The generic SSRF guard checks URL-typed inputs and nested fields (#610).

``InputSanitizer.validate_request_urls`` runs on every validated tool input,
on the synchronous endpoint and in the Celery task, before the tool is
entered. It used to check only top-level ``str`` fields, so a field declared
as ``HttpUrl`` (whose value is a pydantic ``Url`` object, not a ``str``) or a
URL inside a nested model or a list reached the tool unchecked.

No test touches the network: name resolution is replaced with a fake, and
the tool behind the endpoint and the task is a stub that records its calls.
"""

import os
import socket
import sys
import types
import uuid
from typing import Dict, List, Optional, Tuple

import pytest
from pydantic import AnyHttpUrl, AnyUrl, BaseModel, HttpUrl

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.input_validation import InputSanitizer  # noqa: E402

PUBLIC_IP = "93.184.215.14"

# Targets refused whatever the resolver answers. pydantic normalizes the
# numeric spellings (0x7f000001, 2130706433, 127.1, 017700000001) to
# 127.0.0.1 when it validates an HttpUrl, so they are refused as loopback.
REFUSED_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://[::1]/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://127.1/",
    "http://017700000001/",
    "http://[::ffff:127.0.0.1]/",
    "http://100.64.0.1/",
    "http://localhost/",
    "http://metadata.google.internal/",
    "http://user@example.com/",
]


@pytest.fixture
def resolver(monkeypatch):
    """Resolve every name to PUBLIC_IP unless mapped otherwise; record lookups."""
    answers = {}
    lookups = []

    def fake_getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        ip = answers.get(host, PUBLIC_IP)
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return answers, lookups


# --- pydantic URL types -----------------------------------------------------


class HttpUrlInput(BaseModel):
    # Deliberately not named like a URL: the type alone must trigger the check.
    destination: HttpUrl


class AnyHttpUrlInput(BaseModel):
    destination: AnyHttpUrl


class AnyUrlInput(BaseModel):
    destination: AnyUrl


@pytest.mark.parametrize("url", REFUSED_URLS)
def test_http_url_field_pointing_inside_is_refused(resolver, url):
    with pytest.raises(ValueError):
        InputSanitizer.validate_request_urls(HttpUrlInput(destination=url))


@pytest.mark.parametrize("model", [AnyHttpUrlInput, AnyUrlInput])
def test_other_url_types_are_refused_too(resolver, model):
    with pytest.raises(ValueError):
        InputSanitizer.validate_request_urls(
            model(destination="http://169.254.169.254/")
        )


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://example.com/", "ftp://example.com/"]
)
def test_any_url_with_another_scheme_is_refused(resolver, url):
    with pytest.raises(ValueError, match="scheme"):
        InputSanitizer.validate_request_urls(AnyUrlInput(destination=url))


def test_public_http_url_passes_and_is_resolved(resolver):
    _, lookups = resolver
    InputSanitizer.validate_request_urls(
        HttpUrlInput(destination="https://example.com/a?b=1")
    )
    assert lookups == ["example.com"]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
def test_http_url_whose_name_resolves_inside_is_refused(resolver, address):
    answers, _ = resolver
    answers["internal.example.com"] = address
    with pytest.raises(ValueError, match="blocked"):
        InputSanitizer.validate_request_urls(
            HttpUrlInput(destination="https://internal.example.com/")
        )


# --- nested models, lists, tuples and dicts ---------------------------------


class Inner(BaseModel):
    link: HttpUrl


class StringInner(BaseModel):
    target_url: str


class NestedInput(BaseModel):
    inner: Optional[Inner] = None
    inners: List[Inner] = []
    links: List[HttpUrl] = []
    pair: Optional[Tuple[str, HttpUrl]] = None
    by_name: Dict[str, HttpUrl] = {}
    string_inner: Optional[StringInner] = None
    callback_urls: List[str] = []
    steps: List[Dict[str, str]] = []
    note: str = ""


BAD = "http://169.254.169.254/"
GOOD = "https://example.com/"


@pytest.mark.parametrize(
    "fields",
    [
        {"inner": {"link": BAD}},
        {"inners": [{"link": GOOD}, {"link": BAD}]},
        {"links": [GOOD, BAD]},
        {"pair": ("label", BAD)},
        {"by_name": {"primary": GOOD, "fallback": BAD}},
        {"string_inner": {"target_url": BAD}},
        {"callback_urls": [GOOD, BAD]},
        {"steps": [{"name": "fetch", "url": BAD}]},
    ],
    ids=lambda f: next(iter(f)),
)
def test_nested_url_is_refused(resolver, fields):
    with pytest.raises(ValueError):
        InputSanitizer.validate_request_urls(NestedInput(**fields))


def test_nested_public_urls_pass(resolver):
    InputSanitizer.validate_request_urls(
        NestedInput(
            inner={"link": GOOD},
            inners=[{"link": GOOD}],
            links=[GOOD],
            pair=("label", GOOD),
            by_name={"primary": GOOD},
            string_inner={"target_url": GOOD},
            callback_urls=[GOOD],
            steps=[{"url": GOOD}],
        )
    )


def test_free_text_is_not_treated_as_a_target(resolver):
    # A string under a field not named like a URL carrier is left to the tool:
    # an indicator or a note may mention an internal URL without fetching it.
    InputSanitizer.validate_request_urls(NestedInput(note=BAD))


def test_top_level_string_url_is_still_checked(resolver):
    with pytest.raises(ValueError):
        InputSanitizer.validate_request_urls(StringInner(target_url=BAD))


def test_overly_deep_input_is_refused(resolver):
    nested = {"url": GOOD}
    for _ in range(InputSanitizer.URL_WALK_MAX_DEPTH + 1):
        nested = {"next": nested}

    class Deep(BaseModel):
        data: dict

    with pytest.raises(ValueError, match="nested too deeply"):
        InputSanitizer.validate_request_urls(Deep(data=nested))


# --- the shipped tools that declare HttpUrl fields --------------------------


def test_header_analyzer_input_is_guarded(resolver):
    from app.tools.header_analyzer.schemas import HeaderAnalyzerInput

    with pytest.raises(ValueError):
        InputSanitizer.validate_request_urls(HeaderAnalyzerInput(url=BAD))


def test_url_analyzer_input_is_guarded(resolver):
    from app.tools.url_analyzer.schemas import URLShortenerInput

    with pytest.raises(ValueError):
        InputSanitizer.validate_request_urls(URLShortenerInput(shortened_url=BAD))


# --- both execution paths run the guard before the tool ---------------------

PROBE_TOOL = "ssrf_url_type_probe"


class ProbeInput(BaseModel):
    destination: HttpUrl
    mirrors: List[Inner] = []


class ProbeOutput(BaseModel):
    ok: bool = True
    tool_name: Optional[str] = None
    execution_time: Optional[float] = None


@pytest.fixture
def probe_tool():
    """A stand-in tool module that records the inputs it is called with."""
    calls = []

    def execute_tool(input_data):
        calls.append(input_data)
        return ProbeOutput()

    schemas = types.ModuleType(f"{PROBE_TOOL}.schemas")
    schemas.ProbeInput = ProbeInput
    schemas.ProbeOutput = ProbeOutput
    module = types.ModuleType(PROBE_TOOL)
    module.schemas = schemas
    module.execute_tool = execute_tool
    return module, calls


@pytest.fixture
def client(monkeypatch, probe_tool):
    from app.api import router as router_module
    from app.auth import verify_api_key
    from app.execution_manager import ToolExecutionManager
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    module, _ = probe_tool
    monkeypatch.setattr(router_module, "execution_manager", ToolExecutionManager())
    routes = list(router_module.router.routes)
    router_module.register_tool_endpoint(None, PROBE_TOOL, module)
    path = router_module.router.routes[-1].path
    app = FastAPI()
    app.include_router(router_module.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=str(uuid.uuid4()), team_id=str(uuid.uuid4()), role="member"
    )
    yield TestClient(app), path
    router_module.router.routes[:] = routes


@pytest.mark.parametrize(
    "body",
    [
        {"destination": BAD},
        {"destination": GOOD, "mirrors": [{"link": "http://[::1]/"}]},
    ],
)
def test_sync_endpoint_refuses_before_the_tool_runs(resolver, client, probe_tool, body):
    http, path = client
    _, calls = probe_tool

    response = http.post(path, json=body)

    assert response.status_code == 400, response.text
    assert "SSRF" in response.json()["detail"] or "blocked" in response.json()["detail"]
    assert calls == []


def test_sync_endpoint_runs_the_tool_for_a_public_target(resolver, client, probe_tool):
    http, path = client
    _, calls = probe_tool

    response = http.post(path, json={"destination": GOOD})

    assert response.status_code == 200, response.text
    assert len(calls) == 1


@pytest.fixture
def celery_task(monkeypatch, probe_tool):
    pytest.importorskip("celery")
    from app import tasks

    module, _ = probe_tool
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kwargs: None)
    monkeypatch.setattr(tasks, "_load_tool_module", lambda name: module)
    return tasks.execute_tool_async


@pytest.mark.parametrize(
    "input_data",
    [
        {"destination": BAD},
        {"destination": GOOD, "mirrors": [{"link": "http://10.0.0.1/"}]},
    ],
)
def test_async_task_refuses_before_the_tool_runs(
    resolver, celery_task, probe_tool, input_data
):
    _, calls = probe_tool

    outcome = celery_task.run(
        tool_name=PROBE_TOOL, input_data=input_data, user_id="u-1"
    )

    assert outcome["status"] == "failed", outcome
    assert "SSRF" in outcome["error"] or "blocked" in outcome["error"]
    assert calls == []


def test_async_task_runs_the_tool_for_a_public_target(
    resolver, celery_task, probe_tool
):
    _, calls = probe_tool

    outcome = celery_task.run(
        tool_name=PROBE_TOOL, input_data={"destination": GOOD}, user_id="u-1"
    )

    assert outcome["status"] == "completed", outcome
    assert len(calls) == 1
