"""The agents service logs what it analyses by type, not by value (#755).

An indicator is the caller's data: a URL with a token in it, a hash, an
internal address. The service logged it twice per analysis, and a third
time, with whatever the model had asked the data service for, each time a
call to another service failed: the text of an httpx error ends with the URL
that was called, query string included. httpx itself logs that URL for
every request, at INFO, which is the level the worker runs at.

What is logged: the task id, the indicator's type, the caller's ids, the
verdict, the class and status of a failed call. Not the indicator, not a
prompt, not what a tool returned.
"""

import asyncio
import logging
import os
import subprocess
import sys
import uuid

import httpx
import pytest
from langchain_core.messages import AIMessage

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.agents.threat_enrichment_agent import ThreatEnrichmentAgent  # noqa: E402
from app.tools import wildbox_client  # noqa: E402
from app.tools.langchain_tools import port_scan_tool  # noqa: E402
from scripted_model import ScriptedModel  # noqa: E402

MARK = "indicator" + uuid.uuid4().hex
IOC = {"type": "url", "value": f"https://{MARK}.example.com/reset?token={MARK}"}


@pytest.fixture
def caller():
    wildbox_client._caller_identity.set(None)
    wildbox_client.set_caller_identity(str(uuid.uuid4()), str(uuid.uuid4()), "member")
    yield
    wildbox_client._caller_identity.set(None)


@pytest.fixture
def client(caller):
    api = wildbox_client.WildboxAPIClient()
    api.gateway_secret = "unit-test-proof-of-origin"
    return api


def answering(monkeypatch, status):
    """Every request the client sends is answered with ``status``."""
    real = httpx.AsyncClient

    def answer(request):
        return httpx.Response(status, json={"error": {"message": "no"}})

    def with_transport(*args, **kwargs):
        return real(*args, transport=httpx.MockTransport(answer), **kwargs)

    monkeypatch.setattr(wildbox_client.httpx, "AsyncClient", with_transport)


def test_an_analysis_is_logged_by_the_type_of_its_indicator(monkeypatch, caplog):
    model = ScriptedModel(responses=[AIMessage(content="Benign.")])
    monkeypatch.setattr(ThreatEnrichmentAgent, "_initialize_llm", lambda self: model)
    agent = ThreatEnrichmentAgent()

    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(agent.analyze_ioc(dict(IOC)))

    assert result["verdict"]
    ours = [r for r in caplog.records if r.name.startswith("app.")]
    lines = [r.getMessage() for r in ours]
    assert any("Starting analysis of an IOC of type url" in line for line in lines)
    assert any("Completed analysis of an IOC of type url" in line for line in lines)
    for record in ours:
        assert MARK not in record.getMessage()
        assert MARK not in str(record.__dict__)


@pytest.mark.parametrize("status", [404, 500])
def test_a_failed_search_is_logged_without_what_was_searched_for(
    client, monkeypatch, caplog, status
):
    answering(monkeypatch, status)

    with caplog.at_level(logging.DEBUG, logger="app.tools.wildbox_client"):
        result = asyncio.run(
            client._get_json(
                "data service",
                "http://data.invalid/api/v1/indicators/search",
                {"q": MARK},
            )
        )

    assert result["success"] is False
    assert MARK not in str(result)
    assert MARK not in caplog.text
    assert f"Call to the data service failed: HTTPStatusError ({status})" in caplog.text


def test_the_text_of_the_error_does_hold_the_query():
    """Why the text cannot be logged: this is what httpx says."""
    transport = httpx.MockTransport(lambda request: httpx.Response(404))
    with httpx.Client(transport=transport) as client:
        response = client.get("http://data.invalid/search", params={"q": MARK})
    with pytest.raises(httpx.HTTPStatusError) as raised:
        response.raise_for_status()

    assert MARK in str(raised.value)
    assert wildbox_client._logged(raised.value) == "HTTPStatusError (404)"
    assert wildbox_client._logged(httpx.ConnectError("refused")) == "ConnectError"


def test_a_failed_tool_call_is_logged_by_class(client, monkeypatch, caplog):
    answering(monkeypatch, 500)

    with caplog.at_level(logging.DEBUG, logger="app.tools.wildbox_client"):
        result = asyncio.run(client.run_tool("whois_lookup", {"target": MARK}))

    assert result["success"] is False
    assert MARK not in caplog.text
    assert "failed: HTTPStatusError (500)" in caplog.text


def test_a_tool_name_the_model_made_up_is_not_logged(client, caplog):
    with caplog.at_level(logging.DEBUG, logger="app.tools.wildbox_client"):
        result = asyncio.run(client.run_tool(f"../{MARK}", {}))

    assert result["success"] is False
    assert MARK not in caplog.text
    assert "Rejected a tool name that is not in the allowlist" in caplog.text


def test_a_langchain_tool_logs_the_class_of_its_error(caller, monkeypatch, caplog):
    async def fails(*args, **kwargs):
        raise ValueError(f"cannot scan {MARK}")

    monkeypatch.setattr(wildbox_client.wildbox_client, "port_scan", fails)

    with caplog.at_level(logging.DEBUG, logger="app.tools.langchain_tools"):
        asyncio.run(port_scan_tool.ainvoke({"ip_address": MARK}))

    assert MARK not in caplog.text
    assert "Port scan tool error: ValueError" in caplog.text


PROCESS = """
import logging
import {module}
logging.getLogger().setLevel(logging.DEBUG)
print(*(logging.getLogger(n).getEffectiveLevel() for n in ("httpx", "httpcore")))
"""


@pytest.mark.parametrize("module", ["app.main", "app.worker"])
def test_neither_process_lets_httpx_log_the_urls_it_calls(module, tmp_path):
    """httpx: 'HTTP Request: GET http://data/...search?q=<indicator>' at INFO."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "ANTHROPIC_API_KEY", "ANALYZE_RATE_LIMIT_STORAGE_URI")
    }
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..", "..")
    env["ENVIRONMENT"] = "development"
    result = subprocess.run(
        [sys.executable, "-c", PROCESS.format(module=module)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=env,
        timeout=180,
    )

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.split()[-2:] == [str(logging.WARNING)] * 2
