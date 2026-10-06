#!/usr/bin/env python3
"""Fail on a tracked Compose file that cannot start what it describes (#726).

Only the root docker-compose.yml was ever rendered by CI. Three of the
per-service files could not start and nothing said so: the gateway's
development file mounted ``./test/mock-identity.conf`` and
``./test/mock-responses``, which were never in the repository; the data
service's mounted an nginx, a Prometheus and a Grafana configuration that
were not there either; the sensor's development file built a ``development``
stage its Dockerfile does not have. ``docker compose config`` accepts all
three: it does not look at what a path points to.

This renders every tracked Compose file with ``docker compose config``, alone
or with the files it is an overlay of (``STACKS``), every profile included,
and then reads the rendered configuration:

config     the file, or the stack it belongs to, does not render.
build      a ``build:`` whose context or Dockerfile does not exist, whose
           ``target`` is not a stage of that Dockerfile, whose
           ``additional_contexts`` name a missing directory, or whose
           Dockerfile copies ``--from`` a name that is neither a stage nor a
           context the Compose file provides.
mount      a bind mount of a path inside the repository that is not there.
           Docker creates an empty directory in its place, which fails the
           container at once when a file was meant and hides whatever the
           image had there otherwise. A path Git ignores is created at run
           time (``logs/``, the n8n data directory) and passes; so does one
           listed in ``CREATED_AT_RUN_TIME`` with the reason.
env-file   an ``env_file`` that is required and missing.

A variable the files require (``${NAME:?...}``) is given a placeholder, so no
``.env`` is needed and none is read.

Usage: python scripts/check_compose_files.py [--root DIR]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

# The Compose and Dockerfile reading is the hygiene checker's.
_spec = importlib.util.spec_from_file_location(
    "check_container_hygiene", Path(__file__).with_name("check_container_hygiene.py")
)
hygiene = importlib.util.module_from_spec(_spec)
sys.modules.setdefault(_spec.name, hygiene)
_spec.loader.exec_module(hygiene)

# The combinations the Makefile and the workflows run. A file that is the
# last of a stack is an overlay: it is rendered there and not on its own.
# Every other tracked Compose file is rendered alone.
STACKS: tuple[tuple[str, ...], ...] = (
    ("docker-compose.yml", "docker-compose.dev.yml"),
    ("docker-compose.yml", "docker-compose.prod.yml"),
    ("docker-compose.yml", ".github/compose.ci-ports.yml"),
    (
        "docker-compose.yml",
        ".github/compose.ci-ports.yml",
        ".github/compose.ci-cache.yml",
    ),
    (
        "docker-compose.yml",
        "docker-compose.prod.yml",
        ".github/compose.ci-ports.yml",
        ".github/compose.ci-prod.yml",
    ),
)

# Bind-mount sources that are not in the repository and that Git does not
# ignore as a whole, with what creates them.
CREATED_AT_RUN_TIME = {
    # Its files are ignored one by one (ssl/*.crt, ssl/*.key), not the
    # directory. The gateway's entrypoint writes the certificate there.
    "open-security-gateway/ssl": "the gateway's entrypoint writes its certificate there",
    # nginx.conf there serves HTTP only; its HTTPS server block is commented
    # out and reads its certificate from this directory once enabled.
    "open-security-tools/ssl": "certificates of the optional HTTPS block of nginx.conf",
}

_REQUIRED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?\?")
_STAGE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*\S+\s+AS\s+(\S+)", re.I | re.M)
# COPY --from=name, and RUN --mount=type=bind,from=name,...
_COPY_FROM = re.compile(r"(?:--from=|[,=]from=)([^\s,]+)")
PLACEHOLDER = "placeholder-for-config-validation"


def stacks_for(files: Iterable[str]) -> list[tuple[str, ...]]:
    """The stacks to render so that every Compose file in ``files`` is covered."""
    names = sorted(files)
    overlays = {stack[-1] for stack in STACKS}
    stacks = [stack for stack in STACKS if all(name in names for name in stack)]
    stacks += [(name,) for name in names if name not in overlays]
    return sorted(set(stacks))


def unknown_stack_files(files: Iterable[str]) -> list[str]:
    """Files ``STACKS`` names that are not tracked Compose files.

    Nothing when the tree has no root docker-compose.yml: every stack starts
    with it, so there is no stack to complete.
    """
    known = set(files)
    if STACKS[0][0] not in known:
        return []
    return sorted({name for stack in STACKS for name in stack if name not in known})


def required_variables(texts: Iterable[str]) -> set[str]:
    """Names of the variables the files refuse to start without."""
    names: set[str] = set()
    for text in texts:
        names.update(_REQUIRED.findall(text))
    return names


def dockerfile_stages(text: str) -> set[str]:
    return {name.lower() for name in _STAGE.findall(text)}


def dockerfile_contexts(text: str) -> set[str]:
    """Names a Dockerfile copies from that are neither a stage nor an image."""
    stages = dockerfile_stages(text)
    names = set()
    for instruction in hygiene.parse_dockerfile(text):
        if instruction.keyword not in ("COPY", "RUN"):
            continue
        for source in _COPY_FROM.findall(instruction.value):
            if source.lower() in stages or source.isdigit():
                continue
            if re.search(r"[/:@$]", source):
                continue  # an image, or a build argument
            names.add(source)
    return names


def _inside(path: str, root: Path) -> str | None:
    """``path`` relative to ``root``, or None when it is not under it."""
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def service_problems(
    name: str, service: dict[str, Any], root: Path, ignored: Callable[[str], bool]
) -> list[tuple[str, str]]:
    """(rule, message) for one service of a rendered configuration."""
    problems: list[tuple[str, str]] = []

    build = service.get("build")
    if isinstance(build, dict):
        context = Path(build.get("context", ""))
        dockerfile = context / build.get("dockerfile", "Dockerfile")
        shown = _inside(str(dockerfile), root) or str(dockerfile)
        contexts = build.get("additional_contexts") or {}
        for label, path in contexts.items():
            if "://" not in path and not Path(path).is_dir():
                where = _inside(path, root) or path
                problems.append(
                    (
                        "build",
                        f"additional context '{label}' is {where}, which does not exist",
                    )
                )
        if not context.is_dir():
            where = _inside(str(context), root) or str(context)
            problems.append(("build", f"build context {where} does not exist"))
        elif not build.get("dockerfile_inline") and not dockerfile.is_file():
            problems.append(("build", f"Dockerfile {shown} does not exist"))
        elif dockerfile.is_file():
            text = dockerfile.read_text(encoding="utf-8")
            target = build.get("target")
            if target and target.lower() not in dockerfile_stages(text):
                stages = sorted(dockerfile_stages(text)) or ["none"]
                problems.append(
                    (
                        "build",
                        f"builds the stage '{target}', which {shown} does not have "
                        f"(stages: {', '.join(stages)})",
                    )
                )
            for missing in sorted(dockerfile_contexts(text) - set(contexts)):
                problems.append(
                    (
                        "build",
                        f"{shown} copies --from={missing}, a build context this "
                        "service does not provide (additional_contexts)",
                    )
                )

    for volume in service.get("volumes") or []:
        if not isinstance(volume, dict) or volume.get("type") != "bind":
            continue
        source = str(volume.get("source", ""))
        relative = _inside(source, root)
        if relative is None or Path(source).exists():
            continue  # a path of the host, or one that is there
        if relative in CREATED_AT_RUN_TIME or ignored(relative):
            continue
        problems.append(
            (
                "mount",
                f"mounts {relative} at {volume.get('target')}, and nothing is "
                "there: Docker would create an empty directory in its place",
            )
        )

    for entry in service.get("env_file") or []:
        path = entry.get("path") if isinstance(entry, dict) else str(entry)
        required = entry.get("required", True) if isinstance(entry, dict) else True
        if required and path and not Path(path).is_file():
            where = _inside(path, root) or path
            problems.append(
                ("env-file", f"reads env_file {where}, which does not exist")
            )
    return problems


def config_problems(
    config: dict[str, Any], root: Path, ignored: Callable[[str], bool]
) -> list[tuple[str, str, str]]:
    """(service, rule, message) for every service of a rendered configuration."""
    found = []
    for name, service in sorted((config.get("services") or {}).items()):
        if isinstance(service, dict):
            for rule, message in service_problems(name, service, root, ignored):
                found.append((name, rule, message))
    return found


def git_ignored(root: Path) -> Callable[[str], bool]:
    """A function that says whether Git ignores a path that does not exist yet."""

    def ignored(relative: str) -> bool:
        # A pattern such as `logs/` matches a directory only, and a path that
        # is not there has no type: ask for both spellings.
        for candidate in (relative, relative.rstrip("/") + "/"):
            result = subprocess.run(
                ["git", "check-ignore", "-q", "--", candidate],
                cwd=root,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                return True
        return False

    return ignored


def render(root: Path, stack: Sequence[str]) -> tuple[dict[str, Any] | None, str]:
    """The rendered configuration of a stack, or None and what Compose said."""
    texts = [(root / name).read_text(encoding="utf-8") for name in stack]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("COMPOSE_")
    }
    for name in required_variables(texts):
        environment.setdefault(name, PLACEHOLDER)
    command = [
        "docker",
        "compose",
        "--project-directory",
        str(root / Path(stack[0]).parent),
    ]
    for name in stack:
        command += ["-f", str(root / name)]
    # /dev/null: no .env of the project directory takes part.
    command += [
        "--env-file",
        os.devnull,
        "--profile",
        "*",
        "config",
        "--format",
        "json",
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, env=environment, check=False
    )
    if result.returncode != 0:
        lines = [
            line
            for line in result.stderr.splitlines()
            if line.strip() and "level=warning" not in line
        ]
        return None, "; ".join(lines[-3:]) or f"exit status {result.returncode}"
    return json.loads(result.stdout), ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    compose_files = []
    for name in hygiene.tracked_files(root):
        if hygiene.is_yaml(name) and (root / name).is_file():
            try:
                text = (root / name).read_text(encoding="utf-8")
                if hygiene.load_compose(text) is not None:
                    compose_files.append(name)
            except (OSError, UnicodeDecodeError, hygiene.yaml.YAMLError):
                if hygiene.looks_like_compose(name):
                    compose_files.append(name)  # reported when it is rendered

    problems = [
        f"{name}: named in STACKS of {Path(__file__).name} and not a tracked Compose file"
        for name in unknown_stack_files(compose_files)
    ]
    if not compose_files:
        problems.append("no Compose file found: the check would pass on anything")
    ignored = git_ignored(root)
    stacks = stacks_for(compose_files)
    for stack in stacks:
        label = " + ".join(stack)
        config, error = render(root, stack)
        if config is None:
            problems.append(f"{label}: config: does not render: {error}")
            continue
        for service, rule, message in config_problems(config, root, ignored):
            problems.append(
                f"{label}: {rule} [{service}]: service '{service}' {message}"
            )

    if problems:
        print(f"ERROR: {len(problems)} Compose file problem(s):", file=sys.stderr)
        for problem in dict.fromkeys(problems):
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(compose_files)} Compose file(s) rendered in {len(stacks)} "
        "stack(s); every build and bind mount points at something that exists."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
