"""The model is sent no unfilled placeholder (#718).

The system prompt ended with ``CURRENT INVESTIGATION TARGET: {input}`` and
was given to LangChain as a ``SystemMessage``. A message instance is not a
template, so the placeholder was never filled: every analysis told the model
its target was the literal text ``{input}``.

These tests build the production prompt, fill it the way the executor does,
and read the messages the model receives.
"""

import os
import re
import sys

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.agents.threat_enrichment_agent import ThreatEnrichmentAgent  # noqa: E402
from app.config import TEAM_DATA_TOOLS, settings  # noqa: E402
from scripted_model import ScriptedModel  # noqa: E402

TARGET = "Please investigate this domain IOC: example.com"
# A template placeholder, as LangChain writes one: {name}.
PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


def messages(monkeypatch, team_data):
    """The messages of the first model call of an analysis of TARGET."""
    monkeypatch.setattr(settings, "agent_team_data_tools", team_data)
    monkeypatch.setattr(
        ThreatEnrichmentAgent,
        "_initialize_llm",
        lambda self: ScriptedModel(responses=[AIMessage(content="Benign.")]),
    )
    agent = ThreatEnrichmentAgent()
    prompt = agent.agent_executor.agent.runnable.get_prompts()[0]
    return prompt.format_messages(input=TARGET, agent_scratchpad=[])


@pytest.mark.parametrize(
    "team_data", ["", ",".join(TEAM_DATA_TOOLS)], ids=["off", "on"]
)
def test_no_message_carries_an_unfilled_placeholder(monkeypatch, team_data):
    sent = messages(monkeypatch, team_data)

    assert sent, "the prompt produced no message"
    for message in sent:
        assert not PLACEHOLDER.search(message.content), message.content[-200:]
        assert "__" not in message.content


@pytest.mark.parametrize(
    "team_data", ["", ",".join(TEAM_DATA_TOOLS)], ids=["off", "on"]
)
def test_the_target_is_in_the_human_turn_and_only_there(monkeypatch, team_data):
    system, *rest = messages(monkeypatch, team_data)

    assert isinstance(system, SystemMessage)
    assert [type(m) for m in rest] == [HumanMessage]
    assert rest[0].content == TARGET
    # What a user submits is not written into the system prompt.
    assert "example.com" not in system.content
    assert "INVESTIGATION TARGET" not in system.content


def test_the_system_prompt_is_not_a_template(monkeypatch):
    """Which is why a placeholder in it is never filled: the test above
    would pass for the wrong reason if this changed."""
    monkeypatch.setattr(settings, "agent_team_data_tools", "")
    monkeypatch.setattr(
        ThreatEnrichmentAgent,
        "_initialize_llm",
        lambda self: ScriptedModel(responses=[AIMessage(content="Benign.")]),
    )
    prompt = ThreatEnrichmentAgent().agent_executor.agent.runnable.get_prompts()[0]

    assert isinstance(prompt.messages[0], SystemMessage)
    assert set(prompt.input_variables) == {"input", "agent_scratchpad"}
