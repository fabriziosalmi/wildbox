"""Only an environment that says "development" is a development one (#736).

``open_security_shared.environment`` is where that is decided, for the two
things a service does with the name: conveniences (the API schema, a
reloader) are for development and nothing else; the start-up checks for
secrets are for everything else, an environment that was not declared
included. The checks used to ask whether the name was exactly ``production``.
"""

import ast
from pathlib import Path

import pytest
from open_security_shared.api_docs import api_docs_enabled
from open_security_shared.environment import is_development, production_checks_apply

REPO = Path(__file__).resolve().parents[2]

DEVELOPMENT = ["development", "Development", "DEVELOPMENT", " development\n"]
NOT_DEVELOPMENT = [
    "production",
    "Production",
    "staging",
    "test",
    "dev",
    "prod",
    "development-eu",
    "not development",
    "",
    "   ",
    None,
    True,
    1,
]


@pytest.mark.parametrize("environment", DEVELOPMENT)
def test_development_skips_the_checks_and_gets_the_conveniences(environment):
    assert is_development(environment) is True
    assert production_checks_apply(environment) is False
    assert api_docs_enabled(environment) is True


@pytest.mark.parametrize("environment", NOT_DEVELOPMENT)
def test_everything_else_is_held_to_the_checks(environment):
    assert is_development(environment) is False
    assert production_checks_apply(environment) is True
    assert api_docs_enabled(environment) is False


@pytest.mark.parametrize("environment", DEVELOPMENT + NOT_DEVELOPMENT)
def test_the_two_answers_never_agree(environment):
    # No environment has both the conveniences and the exemption withheld,
    # and none has both granted.
    assert production_checks_apply(environment) is not api_docs_enabled(environment)


def test_the_module_needs_the_standard_library_only():
    # Guardian and the sensor install the package without an extra.
    tree = ast.parse(
        (REPO / "open-security-shared" / "environment.py").read_text(encoding="utf-8")
    )
    imported = {
        (node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported == {"typing"}


# --- no service asks whether the environment is exactly "production" --------

SERVICE_CODE = [
    "open-security-identity/app",
    "open-security-tools/app",
    "open-security-data/app",
    "open-security-responder/app",
    "open-security-agents/app",
    "open-security-cspm/app",
    "open-security-sensor/sensor",
    "open-security-shared",
]


def exact_production_tests() -> list:
    """Comparisons of something with the literal "production", in service code."""
    found = []
    for root in SERVICE_CODE:
        for path in sorted((REPO / root).rglob("*.py")):
            relative = path.relative_to(REPO).as_posix()
            if "/tests/" in relative or "/build/" in relative:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                operands = [node.left, *node.comparators]
                literals = [
                    operand.value
                    for operand in operands
                    if isinstance(operand, ast.Constant)
                    and isinstance(operand.value, str)
                ]
                if (
                    "production" in literals
                    and "environment" in ast.unparse(node).lower()
                ):
                    found.append(f"{relative}:{node.lineno}: {ast.unparse(node)}")
    return found


def test_no_service_compares_the_environment_with_the_word_production():
    # A check for == "production" lets "staging" and an undeclared
    # environment through; one for != "production" hands them a convenience.
    assert exact_production_tests() == []
