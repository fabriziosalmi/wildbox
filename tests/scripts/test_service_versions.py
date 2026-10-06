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
import re
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

# The literal a service still passes where the others pass a name. Empty:
# the responder's was the last (#743). An entry that no longer applies fails
# the test, so the list cannot outlive a defect.
KNOWN_LITERALS = {}


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


# --- one literal per service, wherever it is written (#665) ---------------------
#
# The tests above follow the two arguments of the FastAPI services. They did
# not see a version written a second time under another form:
#
# * cspm: ``__version__`` in ``app/__init__.py`` and ``app_version: str =
#   "0.1.6"``, an annotated field of its settings;
# * responder: ``__version__`` in ``app/__init__.py`` and ``SERVICE_VERSION``
#   in ``app/main.py``;
# * guardian, which is Django and in no list above: ``__version__ = "1.0.0"``
#   in ``guardian/__init__.py`` and ``'VERSION': '0.1.6'`` in the dictionary
#   its API schema is built from.
#
# So, for every service: one version literal in its code, under any name that
# says version, as an assignment, an annotated assignment or a dictionary
# entry.

# Where each service's own code is. A tool or a cloud check has a version of
# its own, and a migration records a column named version.
PACKAGES = {
    "identity": ["open-security-identity/app"],
    "tools": ["open-security-tools/app"],
    "data": ["open-security-data/app"],
    "responder": ["open-security-responder/app"],
    "agents": ["open-security-agents/app"],
    "cspm": ["open-security-cspm/app"],
    "guardian": ["open-security-guardian/guardian", "open-security-guardian/apps"],
    "sensor": ["open-security-sensor/sensor"],
}
NOT_THE_SERVICE = {"tools", "checks", "migrations", "tests", "__pycache__"}
VERSION_NAME = re.compile(r"(__version__|(^|_)version)$", re.I)
VERSION_VALUE = re.compile(r"\d+\.\d+\.\d+$")


def _is_version(node):
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(VERSION_VALUE.match(node.value))
    )


def version_literals_in(tree):
    """[(name, value)] for each version literal one parsed module states."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_version(node.value):
            targets = [getattr(target, "id", "") for target in node.targets]
        elif isinstance(node, ast.AnnAssign) and _is_version(node.value):
            targets = [getattr(node.target, "id", "")]
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                name = getattr(key, "value", None)
                if isinstance(name, str) and VERSION_NAME.search(name):
                    if _is_version(value):
                        found.append((name, value.value))
            continue
        else:
            continue
        for name in targets:
            if VERSION_NAME.search(name):
                found.append((name, node.value.value))
    return found


def version_literals(service):
    found = []
    for package in PACKAGES[service]:
        base = ROOT / package
        for path in sorted(base.rglob("*.py")):
            relative = path.relative_to(base)
            if NOT_THE_SERVICE & set(relative.parts[:-1]):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for name, value in version_literals_in(tree):
                found.append((path.relative_to(ROOT).as_posix(), name, value))
    return found


def test_every_python_service_is_listed():
    services = {
        path.name.removeprefix("open-security-")
        for path in ROOT.glob("open-security-*")
        if (path / "requirements.txt").exists()
    }

    assert services == set(PACKAGES)
    for packages in PACKAGES.values():
        for package in packages:
            assert (ROOT / package).is_dir(), package


@pytest.mark.parametrize(
    "source, expected",
    [
        ('__version__ = "0.1.6"\n', [("__version__", "0.1.6")]),
        ('SERVICE_VERSION = "0.1.6"\n', [("SERVICE_VERSION", "0.1.6")]),
        # An annotated field of a settings class.
        (
            'class Settings:\n    app_version: str = "0.1.6"\n',
            [("app_version", "0.1.6")],
        ),
        # An entry of a settings dictionary.
        ("SPECTACULAR = {'TITLE': 'x', 'VERSION': '0.1.6'}\n", [("VERSION", "0.1.6")]),
        # Not a version of the service: another name, or not a version.
        ('MIN_TLS = "1.2.0"\n', []),
        ("STATE_VERSION = 2\n", []),
        ('app_version: str = __version__\n', []),
        ("SPECTACULAR = {'VERSION': GUARDIAN_VERSION}\n", []),
    ],
)
def test_a_version_literal_is_seen_under_each_form(source, expected):
    assert version_literals_in(ast.parse(source)) == expected


@pytest.mark.parametrize("service", sorted(PACKAGES))
def test_a_service_states_its_version_once(service):
    literals = version_literals(service)

    assert len(literals) == 1, literals
