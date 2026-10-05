"""A service states its version once (#721, #743).

Three services told a caller two versions. tools answered ``1.0.0`` on
``/health`` and ``0.1.6`` in its schema and its ``X-API-Version`` header;
agents and data passed the same literal to ``FastAPI(version=...)`` and to
``install_observability(service_version=...)``, two places to change at a
release and one of them forgotten sooner or later.

The rule, for every Python service: the application and the observability
middleware take the version from one name, never from a literal, and from
the same name. This reads the source, so it needs none of the services
installed.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The services built on FastAPI, and where their application is created.
APPLICATIONS = {
    "identity": "open-security-identity/app/main.py",
    "tools": "open-security-tools/app/main.py",
    "data": "open-security-data/app/api/main.py",
    "responder": "open-security-responder/app/main.py",
    "agents": "open-security-agents/app/main.py",
    "cspm": "open-security-cspm/app/main.py",
}

# Found by this test and left for the cross-service cleanup (#665): the
# literal each of these still passes. An entry that no longer applies fails
# the test, so the list cannot outlive the defect.
KNOWN_LITERALS = {
    ("responder", "install_observability"): "0.1.6",
}


def version_arguments(path):
    """{callee: the ``version`` / ``service_version`` argument} in one module."""
    found = {}
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = getattr(node.func, "id", getattr(node.func, "attr", ""))
        callee = callee.lstrip("_")
        if callee not in ("FastAPI", "install_observability"):
            continue
        for keyword in node.keywords:
            if keyword.arg in ("version", "service_version"):
                found[callee] = keyword.value
    return found


def test_every_fastapi_service_is_listed():
    mains = set()
    for path in ROOT.glob("open-security-*/app/**/main.py"):
        relative = path.relative_to(ROOT).as_posix()
        if "/tools/" in relative or "/tests/" in relative:
            continue  # a tool's main.py is a tool, not an application
        if "FastAPI(" in path.read_text(encoding="utf-8"):
            mains.add(relative)

    assert mains == set(APPLICATIONS.values())


@pytest.mark.parametrize("service", sorted(APPLICATIONS))
def test_the_application_and_the_middleware_are_given_a_version(service):
    arguments = version_arguments(APPLICATIONS[service])

    assert set(arguments) == {"FastAPI", "install_observability"}, service


def test_no_service_passes_a_version_literal():
    literals = {}
    for service, path in APPLICATIONS.items():
        for callee, value in version_arguments(path).items():
            if isinstance(value, ast.Constant):
                literals[(service, callee)] = value.value

    assert literals == KNOWN_LITERALS


@pytest.mark.parametrize("service", sorted(APPLICATIONS))
def test_both_are_given_the_same_name(service):
    arguments = version_arguments(APPLICATIONS[service])
    if (service, "install_observability") in KNOWN_LITERALS:
        pytest.skip(f"{service} still passes a literal; see KNOWN_LITERALS")

    assert ast.dump(arguments["FastAPI"]) == ast.dump(
        arguments["install_observability"]
    ), service


@pytest.mark.parametrize("service", ["agents", "data", "tools"])
def test_the_name_is_assigned_one_literal(service):
    """The services this was fixed in: the name leads to a single literal."""
    path = ROOT / APPLICATIONS[service]
    name = version_arguments(APPLICATIONS[service])["FastAPI"]
    assert isinstance(name, ast.Name), ast.dump(name)

    package = path.parents[0] if service != "data" else path.parents[1]
    sources = [path, package / "__init__.py"]
    assigned = []
    for source in sources:
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value.count(".") == 2
                and node.value.value.replace(".", "").isdigit()
            ):
                assigned.append((source.name, node.targets[0].id, node.value.value))

    assert len(assigned) == 1, assigned
