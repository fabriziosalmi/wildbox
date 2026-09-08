"""Generated secrets must survive the validators that read them back.

open-security-tools/app/config.py refuses an API key containing any of a list of
weak patterns, and two of them -- "abc" and "123" -- are formable from the hex
alphabet. So a perfectly random key hit one by chance, and the service died at
start-up with

    ValidationError: API key contains weak pattern "abc"

which reads like a bad key rather than a coincidence. Measured before the fix:
2.89% of generated API keys were rejected, roughly one fresh install in
thirty-five. It is how the integration job went red on a pull request whose
diff was a lockfile.

These tests hold the two halves together: the generator must not emit a value
the validators refuse, and the pattern list it checks against must not drift
away from the ones that actually do the refusing.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts" / "generate_secrets.py"
VALIDATOR = REPO_ROOT / "scripts" / "validate_secrets.py"
TOOLS_CONFIG = REPO_ROOT / "open-security-tools" / "app" / "config.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator():
    return _load(GENERATOR, "wildbox_generate_secrets")


# Enough draws to catch a 3% failure rate with room to spare: the probability of
# seeing none of a 3%-frequent event in 2000 draws is about 1e-27.
DRAWS = 2000


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(lambda g: g.generate_api_key("prod"), id="api_key"),
        pytest.param(lambda g: g.generate_hex(32), id="hex"),
        pytest.param(lambda g: g.generate_base64(32), id="base64"),
        pytest.param(lambda g: g.generate_password(24), id="password"),
    ],
)
def test_generated_values_contain_no_weak_pattern(generator, factory):
    offenders = []
    for _ in range(DRAWS):
        value = factory(generator)
        lowered = value.lower()
        hit = next((p for p in generator.WEAK_PATTERNS if p in lowered), None)
        if hit:
            offenders.append((hit, value))
    assert not offenders, (
        f"{len(offenders)} of {DRAWS} generated values contain a weak pattern, "
        f"first: {offenders[0][0]!r} in {offenders[0][1][:24]}..."
    )


def test_the_generator_knows_every_pattern_the_tools_service_rejects():
    """The list that raises at start-up is the one that matters most."""
    source = TOOLS_CONFIG.read_text()
    block = re.search(r"weak_patterns\s*=\s*\[(.*?)\]", source, re.S)
    assert block, "could not find weak_patterns in the tools service config"
    enforced = set(re.findall(r"'([^']+)'", block.group(1)))
    known = set(_load(GENERATOR, "wildbox_generate_secrets_2").WEAK_PATTERNS)
    assert enforced <= known, (
        "the tools service rejects patterns the generator does not avoid: "
        f"{sorted(enforced - known)}"
    )


def test_the_generator_knows_every_pattern_validate_secrets_rejects():
    source = VALIDATOR.read_text()
    block = re.search(r"INSECURE_PATTERNS\s*=\s*\[(.*?)\]", source, re.S)
    assert block, "could not find INSECURE_PATTERNS in validate_secrets.py"
    enforced = {p.lower() for p in re.findall(r'"([^"]+)"', block.group(1))}
    known = set(_load(GENERATOR, "wildbox_generate_secrets_3").WEAK_PATTERNS)
    # "test-" is a stricter spelling of "test", which the generator does avoid.
    unmatched = {p for p in enforced if not any(k in p or p in k for k in known)}
    assert not unmatched, (
        f"validate_secrets.py rejects patterns the generator does not avoid: {sorted(unmatched)}"
    )


def test_a_value_carrying_a_weak_pattern_is_recognised(generator):
    """The guard is not vacuous: it says no to something."""
    assert not generator._acceptable("wsk_prod.deadbeefabc0123")
    assert generator._acceptable("wsk_prod.deadbeef0f5e9d7c")


def test_the_retry_actually_redraws(generator):
    """Feed it two rejects, then a good one, and check it kept going."""
    draws = iter(["contains-abc", "contains-123", "0f5e9d7c"])
    assert generator._retry_until_acceptable(lambda: next(draws)) == "0f5e9d7c"
