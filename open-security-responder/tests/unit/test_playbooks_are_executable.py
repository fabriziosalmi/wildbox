"""Every shipped playbook must be one the engine can actually execute.

These tests exist because all_star_e2e.yml was none of those things and said so
to nobody. It wrote each step's arguments under `params:` while PlaybookStep
declares `input`; pydantic dropped the unknown key, the playbook loaded clean,
and every step ran with an empty input until the connector raised

    SystemConnector.validate() missing 2 required positional arguments

It also referred to its steps by `id` while the engine keyed the execution
context by `name`, so every condition and template that mentioned an earlier
step resolved to nothing -- quietly, as a false condition rather than an error.

A playbook is a configuration file that looks correct by construction. Nothing
type-checks it, so these tests do: the keys it uses, the actions it names, the
arguments those actions take, and the steps it points at.
"""

import inspect
import os
import re
import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = SERVICE_ROOT / "playbooks"
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.connectors import connector_registry  # noqa: E402
from app.models import PlaybookStep, step_context_key  # noqa: E402
from app.playbook_parser import PlaybookParseError, PlaybookParser  # noqa: E402

PLAYBOOK_FILES = sorted(PLAYBOOKS_DIR.glob("*.yml")) + sorted(
    PLAYBOOKS_DIR.glob("*.yaml")
)


def _connectors():
    return getattr(connector_registry, "connectors", None) or getattr(
        connector_registry, "_connectors", {}
    )


@pytest.fixture(scope="module")
def playbooks():
    return PlaybookParser(playbooks_directory=str(PLAYBOOKS_DIR)).load_playbooks()


def test_there_are_playbooks_to_check():
    assert PLAYBOOK_FILES, f"no playbooks found in {PLAYBOOKS_DIR}"


def test_every_playbook_loads(playbooks):
    """A playbook that fails to load takes the whole service down at startup."""
    assert len(playbooks) == len(PLAYBOOK_FILES)


def test_unknown_step_keys_are_rejected():
    """The exact shape of the original defect: `params` where `input` is meant."""
    with pytest.raises(Exception) as exc:
        PlaybookStep(name="s", action="system.validate", params={"type": "ip_address"})
    assert "params" in str(exc.value)


def test_unknown_playbook_keys_are_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "playbook_id: bad\n"
        "name: bad\n"
        "trigger:\n  type: api\n"
        "steps:\n"
        "  - name: s\n    action: system.validate\n    input: {type: ip_address, value: '1.1.1.1'}\n"
        "output:\n  format: json\n"
    )
    with pytest.raises(PlaybookParseError) as exc:
        PlaybookParser(playbooks_directory=str(tmp_path)).load_playbooks()
    assert "output" in str(exc.value)


@pytest.mark.parametrize("path", PLAYBOOK_FILES, ids=lambda p: p.name)
def test_actions_exist_on_their_connector(path, playbooks):
    playbook = playbooks[yaml.safe_load(path.read_text())["playbook_id"]]
    connectors = _connectors()
    for step in playbook.steps:
        connector_name, action = step.action.split(".", 1)
        connector = connectors.get(connector_name)
        assert (
            connector is not None
        ), f"{step.action}: no connector named {connector_name!r}"
        assert callable(
            getattr(connector, action, None)
        ), f"{step.action}: {connector_name} has no action {action!r}"


@pytest.mark.parametrize("path", PLAYBOOK_FILES, ids=lambda p: p.name)
def test_step_inputs_match_the_action_signature(path, playbooks):
    """Now that inputs actually reach the connector, a wrong key is a TypeError."""
    playbook = playbooks[yaml.safe_load(path.read_text())["playbook_id"]]
    connectors = _connectors()
    for step in playbook.steps:
        connector_name, action = step.action.split(".", 1)
        signature = inspect.signature(getattr(connectors[connector_name], action))
        accepts_kwargs = any(
            p.kind is p.VAR_KEYWORD for p in signature.parameters.values()
        )
        names = {n for n in signature.parameters if n != "self"}
        required = {
            n
            for n, p in signature.parameters.items()
            if n != "self"
            and p.default is inspect.Parameter.empty
            and p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL)
        }
        given = set((step.input or {}).keys())
        assert not (required - given), (
            f"{path.name}/{step.id or step.name}: {step.action} needs "
            f"{sorted(required - given)}"
        )
        if not accepts_kwargs:
            assert not (given - names), (
                f"{path.name}/{step.id or step.name}: {step.action} does not take "
                f"{sorted(given - names)}"
            )


@pytest.mark.parametrize("path", PLAYBOOK_FILES, ids=lambda p: p.name)
def test_cross_step_references_resolve(path, playbooks):
    """`{{ steps.X }}` must name a step of this playbook, by whatever key it gets."""
    playbook = playbooks[yaml.safe_load(path.read_text())["playbook_id"]]
    keys = {step.id or step.name for step in playbook.steps}
    referenced = set(
        re.findall(r"steps\.([A-Za-z0-9_]+)", yaml.dump(playbook.model_dump()))
    )
    assert not (
        referenced - keys
    ), f"{path.name} refers to steps that do not exist: {sorted(referenced - keys)}"


def test_validation_types_are_ones_the_connector_knows(playbooks):
    """system.validate answers "unknown type" without raising, so a typo is silent."""
    system = _connectors()["system"]
    supported = set(system.validate("__probe__", "")["supported_types"])
    for playbook in playbooks.values():
        for step in playbook.steps:
            if step.action == "system.validate":
                requested = (step.input or {}).get("type")
                assert requested in supported, (
                    f"{playbook.playbook_id}/{step.id or step.name}: validation type "
                    f"{requested!r} is not one of {sorted(supported)}"
                )


def test_context_key_is_the_id_when_there_is_one():
    """The key the engine files a result under, and the key playbooks write."""
    step = PlaybookStep(
        id="validate_ip", name="Validate IP Address", action="system.validate"
    )
    assert step_context_key(step) == "validate_ip"


def test_context_key_falls_back_to_the_name():
    """Playbooks without ids -- triage_ip.yml and friends -- are unaffected."""
    step = PlaybookStep(name="validate_ip", action="system.validate")
    assert step_context_key(step) == "validate_ip"


@pytest.mark.parametrize("path", PLAYBOOK_FILES, ids=lambda p: p.name)
def test_references_resolve_against_the_key_the_engine_uses(path, playbooks):
    """The same check as above, but against the engine's own keying function.

    Written separately and deliberately: the test above computes the key itself,
    so it stays green if the engine changes how it keys the context -- which is
    exactly the regression that has to be caught.
    """
    playbook = playbooks[yaml.safe_load(path.read_text())["playbook_id"]]
    keys = {step_context_key(step) for step in playbook.steps}
    referenced = set(
        re.findall(r"steps\.([A-Za-z0-9_]+)", yaml.dump(playbook.model_dump()))
    )
    assert not (
        referenced - keys
    ), f"{path.name}: {sorted(referenced - keys)} is not how the engine keys any of its steps"
