#!/usr/bin/env python3
"""Fail when an image would not hold what the shared modules it imports need (#722).

open-security-shared declared fastapi, pydantic, passlib, PyJWT and
prometheus-client as dependencies of the whole package, and every image
installed it with ``pip install --no-deps`` under a comment saying the
service's lock provided them. It did in one image of eight: ``pip check``
failed in the other seven, and nothing ran it. The services worked because
no module that needed a missing package was imported there, which nothing
checked either.

The package now has no core dependency and one extra per group of modules
(``[project.optional-dependencies]`` in open-security-shared/pyproject.toml,
with ``[tool.wildbox.module-extras]`` saying which module needs which). A
service's Dockerfile names the extras of the modules the service imports,

    RUN pip install --no-cache-dir --no-index --no-build-isolation \\
            "/tmp/open-security-shared[fastapi,metrics]" \\
        && pip check

Without ``--no-deps`` pip resolves those requirements, and with ``--no-index``
it can only resolve them against what the hash-checked lock installed: the
build fails when the lock does not provide one, and ``pip check`` fails it
for any other requirement the environment does not meet. Docker Build
Validation builds every image, so that is the check on the real environment.
This script keeps the pieces it rests on true, without building anything:

module     every module of the package is listed in the module table, names
           extras that exist, and imports nothing its extras do not provide
           (a sibling module's extras included).
extra      an extra of the package that no module needs.
import     a service imports a name the package does not define.
extras     a Dockerfile installs the package with other extras than the
           modules its service imports need: fewer, and pip verifies less
           than the service uses; more, and the service locks what it never
           imports.
install    a Dockerfile installs the package with ``--no-deps`` (pip then
           checks nothing), does not run ``pip check`` after installing it,
           or belongs to a service that imports the package and does not
           install it.
lock       a requirement of those extras is not pinned in the service's
           lock, or is pinned at a version below the floor the package
           declares. The build would fail on it; this says so sooner and
           says which line to change.

What a service imports is read from its tracked Python files outside its
tests, statically: ``import open_security_shared.errors``,
``from open_security_shared.errors import ...`` and
``from open_security_shared import install_error_handlers`` (resolved through
the package's ``_EXPORTS``).

Usage: python scripts/check_shared_dependencies.py [--root DIR]
Needs Python 3.11 (tomllib), packaging and PyYAML.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_container_hygiene as hygiene  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SHARED_DIR = "open-security-shared"
PACKAGE = "open_security_shared"

# The distribution that provides an imported module, by longest prefix.
# Starlette is FastAPI's own dependency, pinned by FastAPI to the range it
# supports, so a module that imports both asks for FastAPI only.
PROVIDERS = {
    "fastapi": "fastapi",
    "starlette": "fastapi",
    "pydantic": "pydantic",
    "jwt": "pyjwt",
    "passlib": "passlib",
    "prometheus_client": "prometheus-client",
    "redis": "redis",
    "sqlalchemy": "sqlalchemy",
}

# The environment the images run, for a requirement that carries a marker.
_TARGET = {
    "python_version": "3.11",
    "python_full_version": "3.11.0",
    "sys_platform": "linux",
    "platform_system": "Linux",
    "os_name": "posix",
    "implementation_name": "cpython",
    "platform_python_implementation": "CPython",
}

_SHARED_PATH = re.compile(rf"(?:^|/){re.escape(SHARED_DIR)}/?(?:\[([^\]]*)\])?$")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")
_SKIPPED_PARTS = frozenset({"tests", "test", "node_modules", "venv", ".venv"})


@dataclass(frozen=True)
class Shared:
    """What open-security-shared/pyproject.toml and its modules declare."""

    core: tuple[Requirement, ...]
    extras: dict[str, tuple[Requirement, ...]]
    module_extras: dict[str, tuple[str, ...]]
    modules: dict[str, str]  # module name -> source
    exports: dict[str, str]  # exported name -> module that defines it

    def requirements(self, extras: Iterable[str]) -> list[Requirement]:
        """Core requirements and those of ``extras`` that apply to the images."""
        found: dict[str, Requirement] = {}
        for requirement in self.core:
            found.setdefault(str(requirement), requirement)
        for extra in sorted(extras):
            for requirement in self.extras.get(extra, ()):
                found.setdefault(str(requirement), requirement)
        return [
            requirement
            for requirement in found.values()
            if requirement.marker is None or requirement.marker.evaluate(_TARGET)
        ]

    def extras_of(self, modules: Iterable[str]) -> set[str]:
        needed: set[str] = set()
        for module in modules:
            needed.update(self.module_extras.get(module, ()))
        return needed


@dataclass
class Service:
    """One service directory: what it imports and the Dockerfiles that build it."""

    name: str
    modules: set[str] = field(default_factory=set)
    dockerfiles: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# The shared package
# --------------------------------------------------------------------------


def read_exports(source: str) -> dict[str, str]:
    """The ``_EXPORTS`` mapping of the package's ``__init__.py``."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_EXPORTS"
            for target in node.targets
        ):
            return dict(ast.literal_eval(node.value))
    return {}


def load_shared(root: Path) -> Shared:
    directory = root / SHARED_DIR
    document = tomllib.loads((directory / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project", {})
    table = document.get("tool", {}).get("wildbox", {}).get("module-extras", {})
    modules = {
        path.stem: path.read_text(encoding="utf-8")
        for path in sorted(directory.glob("*.py"))
        if path.stem != "__init__"
    }
    init = directory / "__init__.py"
    return Shared(
        core=tuple(Requirement(text) for text in project.get("dependencies", [])),
        extras={
            name: tuple(Requirement(text) for text in requirements)
            for name, requirements in project.get("optional-dependencies", {}).items()
        },
        module_extras={name: tuple(extras) for name, extras in table.items()},
        modules=modules,
        exports=read_exports(init.read_text(encoding="utf-8")) if init.exists() else {},
    )


def module_imports(source: str) -> tuple[set[str], set[str]]:
    """Return (third-party modules, sibling modules) a module imports when loaded.

    Imports inside a function run only when it is called and are the caller's
    to guard; those under ``if TYPE_CHECKING:`` never run. Everything else at
    module level counts, a ``try``/``except ImportError`` included: the extra
    is what makes the guarded feature real.
    """
    third_party: set[str] = set()
    siblings: set[str] = set()

    def visit(body: Iterable[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    record(alias.name, 0)
            elif isinstance(node, ast.ImportFrom):
                record(node.module or "", node.level)
            elif isinstance(node, ast.If):
                if "TYPE_CHECKING" not in ast.dump(node.test):
                    visit(node.body)
                visit(node.orelse)
            elif isinstance(node, ast.Try):
                visit(node.body)
                for handler in node.handlers:
                    visit(handler.body)
                visit(node.orelse)
                visit(node.finalbody)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                visit(node.body)

    def record(name: str, level: int) -> None:
        if level:
            if name:
                siblings.add(name.split(".")[0])
            return
        top = name.split(".")[0]
        if top == PACKAGE:
            rest = name.split(".")[1:]
            if rest:
                siblings.add(rest[0])
        elif top not in sys.stdlib_module_names and top != "__future__":
            third_party.add(name)

    visit(ast.parse(source).body)
    return third_party, siblings


def provider(module: str) -> str | None:
    """The distribution that provides ``module``, or None when unknown."""
    parts = module.split(".")
    for length in range(len(parts), 0, -1):
        found = PROVIDERS.get(".".join(parts[:length]))
        if found:
            return found
    return None


def check_modules(shared: Shared) -> list[str]:
    """Problems in the module table and the extras, against the modules' imports."""
    problems: list[str] = []
    where = f"{SHARED_DIR}/pyproject.toml"

    for module in sorted(set(shared.modules) - set(shared.module_extras)):
        problems.append(
            f"{where}: module [{module}]: not listed in [tool.wildbox.module-extras]; "
            "say which extras it needs ([] for none)"
        )
    for module in sorted(set(shared.module_extras) - set(shared.modules)):
        problems.append(
            f"{where}: module [{module}]: listed in [tool.wildbox.module-extras] "
            "but the package has no such module"
        )
    used: set[str] = set()
    for module, extras in sorted(shared.module_extras.items()):
        used.update(extras)
        for extra in extras:
            if extra not in shared.extras:
                problems.append(
                    f"{where}: module [{module}]: needs the extra '{extra}', which "
                    "[project.optional-dependencies] does not define"
                )
    for extra in sorted(set(shared.extras) - used):
        problems.append(
            f"{where}: extra [{extra}]: needed by no module in "
            "[tool.wildbox.module-extras]; remove it or list the module that uses it"
        )

    for module, source in sorted(shared.modules.items()):
        if module not in shared.module_extras:
            continue
        extras = set(shared.module_extras[module])
        provided = {
            canonicalize_name(requirement.name)
            for requirement in shared.requirements(extras)
        }
        third_party, siblings = module_imports(source)
        for imported in sorted(third_party):
            distribution = provider(imported)
            if distribution is None:
                problems.append(
                    f"{SHARED_DIR}/{module}.py: module [{module}]: imports "
                    f"{imported}, which PROVIDERS in {Path(__file__).name} maps to "
                    "no distribution"
                )
            elif distribution not in provided:
                listed = ", ".join(sorted(extras)) or "none"
                problems.append(
                    f"{SHARED_DIR}/{module}.py: module [{module}]: imports "
                    f"{imported} ({distribution}), which its extras ({listed}) do "
                    "not require"
                )
        for sibling in sorted(siblings & set(shared.module_extras)):
            missing = set(shared.module_extras[sibling]) - extras
            if missing:
                problems.append(
                    f"{SHARED_DIR}/{module}.py: module [{module}]: imports "
                    f"{sibling}, which needs {', '.join(sorted(missing))}; list "
                    f"that for {module} too"
                )
    return problems


# --------------------------------------------------------------------------
# What a service imports
# --------------------------------------------------------------------------


def service_imports(source: str, shared: Shared) -> tuple[set[str], list[str]]:
    """Return (shared modules a file imports, names it imports that do not exist)."""
    modules: set[str] = set()
    unknown: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == PACKAGE and len(parts) > 1:
                    modules.add(parts[1])
        elif isinstance(node, ast.ImportFrom) and not node.level:
            parts = (node.module or "").split(".")
            if parts[0] != PACKAGE:
                continue
            if len(parts) > 1:
                modules.add(parts[1])
                continue
            for alias in node.names:
                if alias.name in shared.modules:
                    modules.add(alias.name)
                elif alias.name in shared.exports:
                    modules.add(shared.exports[alias.name])
                elif not alias.name.startswith("__"):
                    unknown.append(alias.name)
    unknown.extend(sorted(modules - set(shared.modules)))
    return modules & set(shared.modules), unknown


def is_service_code(path: str) -> bool:
    """A Python file that runs in the image: not a test, not a vendored tree."""
    parts = path.split("/")
    name = parts[-1]
    return (
        name.endswith(".py")
        and not _SKIPPED_PARTS & set(parts[:-1])
        and not name.startswith("test_")
        and not name.endswith("_test.py")
        and name != "conftest.py"
    )


def collect_services(
    root: Path, files: Iterable[str], shared: Shared
) -> tuple[dict[str, Service], list[str]]:
    """Group the tracked files by service directory (the first path component)."""
    services: dict[str, Service] = {}
    problems: list[str] = []
    for path in sorted(files):
        directory, _, rest = path.partition("/")
        if not rest or directory == SHARED_DIR:
            continue
        service = services.setdefault(directory, Service(directory))
        if "/" not in rest and hygiene.is_dockerfile(rest):
            service.dockerfiles.append(path)
        elif is_service_code(path):
            try:
                text = (root / path).read_text(encoding="utf-8")
                if PACKAGE not in text:
                    continue
                modules, unknown = service_imports(text, shared)
            except (OSError, UnicodeDecodeError, SyntaxError) as exc:
                problems.append(f"{path}: cannot be read: {exc}")
                continue
            service.modules.update(modules)
            for name in unknown:
                problems.append(
                    f"{path}: import [{name}]: {PACKAGE} defines no module or "
                    f"export named {name}"
                )
    return services, problems


# --------------------------------------------------------------------------
# Dockerfiles and locks
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Install:
    """How a Dockerfile installs the shared package."""

    line: int
    extras: frozenset[str]
    no_deps: bool
    checked: bool  # `pip check` runs after it
    locks: tuple[str, ...]  # the files `pip install -r` reads in this Dockerfile


def _is_pip_check(command: Sequence[str]) -> bool:
    words = [Path(command[0]).name, *command[1:]]
    if len(words) >= 3 and words[1:3] == ["-m", "pip"]:
        words = words[2:]
    return len(words) >= 2 and words[0].startswith("pip") and words[1] == "check"


def find_install(text: str) -> Install | None:
    """The install of the shared package in a Dockerfile, or None.

    The locks are every file a ``pip install -r`` of the Dockerfile reads,
    whatever the stage: cspm installs its lock in a builder stage and copies
    the result into the image that then installs the shared package.
    """
    found: tuple[int, frozenset[str], bool] | None = None
    checked = False
    locks: list[str] = []
    for instruction in hygiene.parse_dockerfile(text):
        if instruction.keyword != "RUN":
            continue
        for command in hygiene.shell_commands(hygiene.run_script(instruction.value)):
            if found and _is_pip_check(command):
                checked = True
                continue
            arguments = hygiene.pip_arguments(command)
            if arguments is None:
                continue
            words = list(arguments)
            for position, word in enumerate(words):
                if word in ("-r", "--requirement") and position + 1 < len(words):
                    locks.append(words[position + 1])
                match = _SHARED_PATH.search(word)
                if match and not word.startswith("-"):
                    extras = frozenset(
                        extra.strip()
                        for extra in (match.group(1) or "").split(",")
                        if extra.strip()
                    )
                    found = (instruction.line, extras, "--no-deps" in words)
                    checked = False
    if found is None:
        return None
    return Install(found[0], found[1], found[2], checked, tuple(locks))


def read_lock(text: str) -> dict[str, str]:
    """``{canonical name: version}`` of the ``name==version`` lines of a lock."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        match = _PIN.match(line.strip())
        if match:
            pins[canonicalize_name(match.group(1))] = match.group(2)
    return pins


def lock_problems(
    requirements: Iterable[Requirement], pins: dict[str, str], lock: str
) -> list[tuple[str, str]]:
    """(requirement name, what is wrong) for each requirement ``lock`` misses."""
    problems: list[tuple[str, str]] = []
    for requirement in requirements:
        name = canonicalize_name(requirement.name)
        pinned = pins.get(name)
        if pinned is None:
            problems.append((name, f"{requirement} is not pinned in {lock}; add it"))
            continue
        try:
            satisfied = requirement.specifier.contains(
                Version(pinned), prereleases=True
            )
        except InvalidVersion:
            satisfied = False
        if not satisfied:
            problems.append(
                (
                    name,
                    f"{lock} pins {name}=={pinned}, outside {requirement}; change it",
                )
            )
    return problems


def check_service(root: Path, service: Service, shared: Shared) -> list[str]:
    """Problems of one service's Dockerfiles and locks."""
    problems: list[str] = []
    needed = shared.extras_of(service.modules)
    imported = ", ".join(sorted(service.modules))
    for path in service.dockerfiles:
        text = (root / path).read_text(encoding="utf-8")
        install = find_install(text)
        if install is None:
            if service.modules and "pip" in text:
                problems.append(
                    f"{path}: install [{service.name}]: the service imports "
                    f"{PACKAGE} ({imported}) and this image does not install it"
                )
            continue
        where = f"{path}:{install.line}"
        if install.no_deps:
            problems.append(
                f"{where}: install [--no-deps]: with --no-deps pip checks none of "
                "the package's requirements; drop it and keep --no-index, so pip "
                "resolves them against what the lock installed"
            )
        if not install.checked:
            problems.append(
                f"{where}: install [pip check]: nothing runs `pip check` after the "
                "install; add `&& pip check` to the same RUN"
            )
        if set(install.extras) != needed:
            wanted = f"[{','.join(sorted(needed))}]" if needed else "no extra"
            given = (
                f"[{','.join(sorted(install.extras))}]"
                if install.extras
                else "no extra"
            )
            reason = (
                f"it imports {imported}"
                if service.modules
                else "it imports nothing from it"
            )
            problems.append(
                f"{where}: extras [{service.name}]: installs the shared package "
                f"with {given}; the service needs {wanted} ({reason})"
            )
        directory = Path(path).parent
        locks = [directory / Path(lock).name for lock in install.locks]
        pins: dict[str, str] = {}
        for lock in locks:
            if (root / lock).exists():
                pins.update(read_lock((root / lock).read_text(encoding="utf-8")))
        shown = ", ".join(str(lock) for lock in locks) or "a lock this does not install"
        for name, message in lock_problems(shared.requirements(needed), pins, shown):
            problems.append(
                f"{where}: lock [{name}]: {message} in "
                "requirements.in and run `make lock`"
            )
    return problems


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def check_tree(root: Path, files: Iterable[str]) -> tuple[list[str], int, int]:
    """Return (problems, images that install the package, modules checked)."""
    shared = load_shared(root)
    problems = check_modules(shared)
    services, unreadable = collect_services(root, files, shared)
    problems += unreadable
    images = 0
    for service in services.values():
        problems += check_service(root, service, shared)
        for path in service.dockerfiles:
            if find_install((root / path).read_text(encoding="utf-8")) is not None:
                images += 1
    return problems, images, len(shared.modules)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    args = parser.parse_args(argv)

    problems, images, modules = check_tree(args.root, hygiene.tracked_files(args.root))
    if images == 0:
        problems.append(
            "no Dockerfile installs the shared package: the check would pass on anything"
        )
    if problems:
        print(
            f"ERROR: {len(problems)} shared-package dependency problem(s):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(
        f"OK: {modules} shared module(s) match their extras; {images} image(s) "
        "install the package with the extras their service imports, locked."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
