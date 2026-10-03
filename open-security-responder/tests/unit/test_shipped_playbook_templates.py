"""Every template in a shipped playbook must compile (#595).

The shipped playbooks wrote their conditions as "{{ ... }}". A condition is
the body of an {% if %}, so that was a syntax error, and every conditional
step in them failed at run time. Loading a playbook does not compile its
templates, so nothing noticed. These tests compile each condition the way
the engine does, in condition_env, and each action input template in
jinja_env, so a broken shipped playbook fails CI instead.
"""

import os
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import TemplateSyntaxError

SERVICE_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = SERVICE_ROOT / "playbooks"
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.playbook_parser import PlaybookParser  # noqa: E402
from app.workflow_engine import (  # noqa: E402
    TemplateRenderError,
    WorkflowEngine,
    jinja_env,
)

PLAYBOOK_FILES = sorted(PLAYBOOKS_DIR.glob("*.yml")) + sorted(
    PLAYBOOKS_DIR.glob("*.yaml")
)


@pytest.fixture(scope="module")
def playbooks():
    return PlaybookParser(playbooks_directory=str(PLAYBOOKS_DIR)).load_playbooks()


@pytest.fixture
def engine():
    return WorkflowEngine.__new__(WorkflowEngine)


def _playbook(path, playbooks):
    return playbooks[yaml.safe_load(path.read_text())["playbook_id"]]


def _strings(value, where):
    """Every string in a step input, with where it sits."""
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{where}[{index}]")


def test_there_are_playbooks_to_check():
    assert PLAYBOOK_FILES, f"no playbooks found in {PLAYBOOKS_DIR}"


@pytest.mark.parametrize("path", PLAYBOOK_FILES, ids=lambda p: p.name)
def test_every_condition_compiles(path, playbooks, engine):
    failures = []
    for step in _playbook(path, playbooks).steps:
        if not step.condition:
            continue
        try:
            engine.compile_condition(step.condition)
        except TemplateRenderError as e:
            failures.append(f"{step.id or step.name}: {e}")
    assert not failures, f"{path.name}: " + "; ".join(failures)


@pytest.mark.parametrize("path", PLAYBOOK_FILES, ids=lambda p: p.name)
def test_every_input_template_compiles(path, playbooks, engine):
    failures = []
    for step in _playbook(path, playbooks).steps:
        for where, text in _strings(step.input or {}, step.id or step.name):
            lowered = text.lower()
            blocked = [p for p in engine._DANGEROUS_PATTERNS if p.lower() in lowered]
            if blocked:
                failures.append(f"{where}: blocked pattern {blocked[0]!r}")
                continue
            try:
                jinja_env.from_string(text)
            except TemplateSyntaxError as e:
                failures.append(f"{where}: {e}")
    assert not failures, f"{path.name}: " + "; ".join(failures)


def test_a_braced_condition_is_caught(engine):
    """The check above would catch the original defect."""
    with pytest.raises(TemplateRenderError, match="not a valid expression"):
        engine.compile_condition("{{ steps.validate_ip.output.valid == true }}")


def test_a_guarded_condition_on_a_skipped_step_is_false_without_warning(
    playbooks, engine, caplog
):
    """triage_ip's whois_lookup, when scan_ports was skipped for a bad IP."""
    step = next(s for s in playbooks["triage_ip"].steps if s.name == "whois_lookup")
    context = {
        "trigger": {"ip": "not-an-ip"},
        "steps": {"validate_ip": {"output": {"valid": False}}},
    }
    assert engine.evaluate_condition(step.condition, context) is False
    assert "undefined name" not in caplog.text


def test_a_guarded_condition_holds_when_its_data_is_there(playbooks, engine):
    step = next(s for s in playbooks["triage_ip"].steps if s.name == "whois_lookup")
    context = {"steps": {"scan_ports": {"output": {"open_ports": [22, 443]}}}}
    assert engine.evaluate_condition(step.condition, context) is True
