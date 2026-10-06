"""Compose gives guardian its scan allowlist, where it is needed (#748).

guardian scans no internal address unless the operator lists its range in
``GUARDIAN_ALLOWED_INTERNAL_TARGETS``. The code that reads the variable is
half of that; the other half is here:

* a variable Compose does not pass is one an operator sets in ``.env`` to no
  effect, and for this one "no effect" means a lab that is silently never
  scanned;
* ``guardian`` refuses the request and ``guardian-worker`` connects, so both
  need the list, and the same one;
* in the production overlay too, where the worker is on ``data`` (next to
  PostgreSQL, Redis and identity) and ``egress``;
* it is guardian's own variable: neither service is handed the tools
  service's list, and no other service is handed guardian's.
"""

import ast
import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
VARIABLE = "GUARDIAN_ALLOWED_INTERNAL_TARGETS"
TOOLS_VARIABLE = "TOOLS_ALLOWED_INTERNAL_TARGETS"
SCANNING = ("guardian", "guardian-worker")
BASE = "docker-compose.yml"
OVERLAY = "docker-compose.prod.yml"


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def _source(path):
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _services(compose_file):
    # A SafeLoader subclass: it builds plain mappings, lists and strings only.
    text = _source(compose_file)
    return yaml.load(text, Loader=_ComposeLoader)["services"]  # nosec B506


def _environment(service):
    env = service.get("environment") or []
    if isinstance(env, dict):
        return {key: str(value) for key, value in env.items()}
    return dict(item.split("=", 1) for item in env)


def _service_block(compose_file, name):
    """The text of one service of a Compose file, tags and comments included."""
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)",
        _source(compose_file),
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"{name} not found in {compose_file}"
    return match.group(1)


def _code_strings(path):
    """Every string a module's code holds, its docstrings left out."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return " ".join(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    )


@pytest.mark.parametrize("service", SCANNING)
def test_the_base_file_passes_the_list_to_both_services(service):
    environment = _environment(_services(BASE)[service])

    # Empty when unset: guardian/scan_targets.py reads that as "nothing
    # internal", and Compose does not warn about an unset variable.
    assert environment.get(VARIABLE) == f"${{{VARIABLE}:-}}"


@pytest.mark.parametrize("service", SCANNING)
def test_the_production_overlay_keeps_it(service):
    """The overlay merges a service's environment with the base file's.

    It would drop the variable only by replacing the list (``!override``,
    ``!reset``) or by setting the variable itself; it does neither.
    """
    overlay = _services(OVERLAY)[service]

    assert VARIABLE not in _environment(overlay)
    block = _service_block(OVERLAY, service)
    assert not re.search(r"^\s*environment:\s*!", block, flags=re.MULTILINE), block


def test_the_worker_is_inside_the_networks_the_policy_protects():
    """Why the policy exists: where the worker connects from."""
    base = _services(BASE)
    overlay = _services(OVERLAY)

    # One flat network in the base file: the worker is next to every service.
    assert base["guardian-worker"]["networks"] == ["wildbox"]
    assert base["postgres"]["networks"] == ["wildbox"]
    # In the overlay: with the databases and identity, and with a route out.
    worker = set(overlay["guardian-worker"]["networks"])
    assert worker == {"data", "egress"}
    for neighbor in ("postgres", "wildbox-redis", "identity"):
        assert "data" in set(overlay[neighbor]["networks"]), neighbor


def test_only_guardian_and_its_worker_get_guardians_list():
    for compose_file in (BASE, OVERLAY, "docker-compose.dev.yml"):
        holders = {
            name
            for name, service in _services(compose_file).items()
            if any(
                VARIABLE in key or VARIABLE in value
                for key, value in _environment(service).items()
            )
        }
        assert holders <= set(SCANNING), compose_file
    assert {
        name
        for name, service in _services(BASE).items()
        if VARIABLE in _environment(service)
    } == set(SCANNING)


def test_guardian_is_not_handed_the_tools_services_list():
    """Opening a range to one service must not open it to the other."""
    for compose_file in (BASE, OVERLAY):
        for name in (*SCANNING, "guardian-beat"):
            environment = _environment(_services(compose_file)[name])
            assert TOOLS_VARIABLE not in environment, (compose_file, name)
            assert not any(TOOLS_VARIABLE in value for value in environment.values()), (
                compose_file,
                name,
            )
    # And guardian's code has no use for the name, beyond saying so in prose.
    for path in sorted((REPO_ROOT / "open-security-guardian").rglob("*.py")):
        if "tests" in path.parts:
            continue
        assert TOOLS_VARIABLE not in _code_strings(path), path


def test_the_variable_compose_passes_is_the_one_guardian_reads():
    scan_targets = _source("open-security-guardian/guardian/scan_targets.py")
    settings = _source("open-security-guardian/guardian/settings.py")

    assert f'ALLOWLIST_VARIABLE = "{VARIABLE}"' in scan_targets
    assert "environ.get(ALLOWLIST_VARIABLE)" in scan_targets
    # Read when the settings load, so a malformed list stops the container.
    assert "SCAN_ALLOWED_INTERNAL_TARGETS = allowed_internal_targets()" in settings


def test_the_template_offers_it_empty_and_says_what_empty_means():
    template = _source(".env.example")

    # Present and empty: the default, written out, so an operator finds it.
    assert re.search(rf"^{VARIABLE}=$", template, flags=re.MULTILINE)
    comment = template[: template.index(f"\n{VARIABLE}=")].rsplit("\n\n", 1)[-1]
    assert "nothing" in comment and "internal is scanned" in comment
    assert TOOLS_VARIABLE in comment, "it must say the two lists are separate"
    assert re.search(
        rf"^{VARIABLE}=$",
        _source("open-security-guardian/.env.example"),
        flags=re.MULTILINE,
    )


@pytest.mark.parametrize("workflow", ["integration-tests.yml", "production-stack.yml"])
def test_the_ci_stacks_allow_loopback_only_and_tell_the_suite(workflow):
    """The integration suite scans the worker's own loopback, and nothing else
    internal: a wider list in CI would hide a refusal that stopped working."""
    text = _source(f".github/workflows/{workflow}")
    values = re.findall(rf'^\s*{VARIABLE}: "([^"]*)"$', text, flags=re.MULTILINE)

    assert values, f"{workflow} does not start its stack with {VARIABLE}"
    assert set(values) == {"127.0.0.0/8"}
    # integration-tests.yml: once for the stack, once for the suite. The
    # production stack sets it for the whole job.
    assert len(values) == (2 if workflow == "integration-tests.yml" else 1)
