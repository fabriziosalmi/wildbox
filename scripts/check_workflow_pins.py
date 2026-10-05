#!/usr/bin/env python3
"""Fail on a workflow that runs a tool or an action at whatever version is current (#726).

test.yml and pr-validation.yml installed pytest, black, flake8, isort and mypy
with ``pip install <name>``, documentation-quality.yml its four npm tools with
``npm install -g <name>``, and secret-scan.yml unpacked and ran a downloaded
archive that nothing verified. A job then ran, with its token, whatever the
registry served that day, and a new release of a linter could turn main red
with no change in the repository. This reads every workflow under
.github/workflows and refuses, per step:

pip            a ``pip install`` that names a package without an exact
               version. Three forms pass: ``-r <file>`` of a tracked
               requirements file (a file with hashes is installed with
               ``--require-hashes``), ``name==1.2.3`` for every package named,
               and a local path (``./open-security-shared``). A package that
               tests/ci-tools/requirements.in also pins must be named at the
               same version, so the tools lock stays the one place that says
               which version CI runs.
npm            ``npm install -g`` (or ``yarn global add``) without an exact
               ``name@1.2.3``, or an install that is not ``npm ci``.
pipe-to-shell  a download fed to an interpreter (``curl ... | sh``).
download       ``curl`` or ``wget`` of a URL on another host with nothing in
               the same step that checks the result (``sha256sum -c``).
               Requests to localhost, and to a URL held in a variable, are
               how the workflows probe the stack they start, not downloads.
action         ``uses:`` of an action that is not pinned to a version tag
               (``@v4``, ``@v0.36.0``) or a full commit SHA. The repository
               pins actions by tag and Dependabot's ``github-actions``
               ecosystem moves them; ``@main`` or no reference at all floats.

Usage: python scripts/check_workflow_pins.py [--root DIR]
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import Any, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = Path(".github/workflows")
CI_TOOLS = Path("tests/ci-tools/requirements.in")

# The shell and pip parsing is the Dockerfile checker's: one reading of a
# `pip install` line for both.
_spec = importlib.util.spec_from_file_location(
    "check_container_hygiene", Path(__file__).with_name("check_container_hygiene.py")
)
hygiene = importlib.util.module_from_spec(_spec)
sys.modules.setdefault(_spec.name, hygiene)
_spec.loader.exec_module(hygiene)

_EXACT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([0-9][^\s;,<>=!~*]*)$"
)
_PIN_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==(\S+)")
_ACTION_REF = re.compile(r"^(v\d+(\.\d+){0,2}|[0-9a-f]{40})$")
_EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.S)
_PLACEHOLDER = "EXPR"  # what a ${{ }} expression is replaced with
# The stack a job starts is probed on the runner's loopback.
_LOCAL = re.compile(r"^https?://(localhost|127\.\d+\.\d+\.\d+|\[::1\])(?![\w.-])")
_INTERPRETERS = r"(?:(?:ba|z|da|a|k)?sh|python[\d.]*|perl|ruby|node)"
_PIPED = re.compile(rf"\b((?:curl|wget)\b[^|;&\n]*)\|\s*(?:sudo\s+)?{_INTERPRETERS}\b")
# What a command substitution or a process substitution downloads.
_SUBSTITUTED = re.compile(r"(?:\$\(|<\(|`)\s*((?:curl|wget)\b[^)`]*)")


def _remote_urls(text: str) -> list[str]:
    """The URLs in ``text`` that name another host."""
    return [url for url in hygiene._URL.findall(text) if not _LOCAL.match(url)]


def _feeds_a_shell(script: str) -> bool:
    """Whether the script hands a download to an interpreter.

    A request to the stack on the runner's loopback, piped to a JSON
    formatter or captured for its status code, is not one. A URL held in a
    variable is, when it is piped: nothing says where it points.
    """
    for request in _PIPED.findall(script):
        if not hygiene._URL.findall(request) or _remote_urls(request):
            return True
    return any(_remote_urls(inner) for inner in _SUBSTITUTED.findall(script))


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(text: str) -> dict[str, str]:
    """{package: version} for the ``name==version`` lines of a requirements file."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        match = _PIN_LINE.match(line.strip())
        if match:
            pins[normalise(match.group(1))] = match.group(3)
    return pins


def pip_problem(
    arguments: Sequence[str], pins: dict[str, str], files: set[str]
) -> str | None:
    """Say why a workflow's ``pip install`` takes an unpinned package, or None."""
    words = list(arguments)
    flags: set[str] = set()
    named: list[str] = []
    lockfiles: list[str] = []
    while words:
        word = words.pop(0)
        if not word.startswith("-"):
            named.append(word)
            continue
        option, equals, value = word.partition("=")
        if option in hygiene._PIP_VALUE_OPTIONS:
            if not equals:
                value = words.pop(0) if words else ""
            if option in ("-r", "--requirement"):
                lockfiles.append(value)
            elif option in ("-e", "--editable"):
                named.append(value)
        else:
            flags.add(option)

    if flags & {"--upgrade", "-U"} and not lockfiles:
        return "upgrades to whatever the index serves; name an exact version"
    for lockfile in lockfiles:
        if "$" in lockfile:
            continue  # a path in a shell variable: not known here
        # The placeholder stands for an expression, such as the matrix's service.
        pattern = lockfile.replace(_PLACEHOLDER, "*")
        known = [
            name
            for name in files
            if fnmatch.fnmatchcase(name, pattern)
            or fnmatch.fnmatchcase(name, "*/" + pattern)
        ]
        if not known:
            return f"-r {lockfile}: no tracked file of that name"
    for requirement in named:
        if requirement.startswith((".", "/")):
            continue  # a local path: the tree being tested
        match = _EXACT.match(requirement)
        if not match:
            return (
                f"installs {requirement} without an exact version (name==1.2.3), so "
                "the job runs whatever the index serves that day"
            )
        name, version = normalise(match.group(1)), match.group(3)
        if name in pins and pins[name] != version:
            return (
                f"installs {requirement}, but {CI_TOOLS} pins {name}=={pins[name]}; "
                "one version for all of CI"
            )
    if not named and not lockfiles:
        return "installs nothing"
    return None


def action_problem(uses: str) -> str | None:
    """Say why a ``uses:`` reference floats, or None."""
    reference = uses.strip()
    if reference.startswith("./"):
        return None  # an action of this repository, at this commit
    if reference.startswith("docker://"):
        return hygiene.image_problem(reference[len("docker://") :])
    _, at, ref = reference.rpartition("@")
    if not at:
        return "names no version; pin it to a version tag (@v4) or a commit SHA"
    if not _ACTION_REF.match(ref):
        return (
            f"is pinned to '{ref}', which is not a version tag or a full commit "
            "SHA; a branch moves under the workflow"
        )
    return None


def step_findings(
    step: dict[str, Any], pins: dict[str, str], files: set[str]
) -> list[tuple[str, str, str]]:
    """(rule, subject, message) for one step."""
    found: list[tuple[str, str, str]] = []
    uses = step.get("uses")
    if isinstance(uses, str):
        problem = action_problem(uses)
        if problem:
            found.append(("action", uses, f"uses {uses}: {problem}"))
    script = step.get("run")
    if not isinstance(script, str):
        return found
    # ${{ ... }} is replaced before the shell sees the script.
    script = _EXPRESSION.sub(_PLACEHOLDER, script)
    # Join continuation lines, drop comment lines.
    script = re.sub(r"\\\n", " ", script)
    script = "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )
    if _feeds_a_shell(script):
        found.append(
            (
                "pipe-to-shell",
                "run",
                "feeds a download straight to an interpreter; download a named "
                "version to a file and check its SHA-256 first",
            )
        )
    verified = bool(hygiene._VERIFIED.search(script))
    for command in hygiene.shell_commands(script):
        shown = " ".join(command)
        arguments = hygiene.pip_arguments(command)
        if arguments is not None:
            problem = pip_problem(arguments, pins, files)
            if problem:
                found.append(("pip", shown, problem))
            continue
        problem = hygiene.npm_problem(command)
        if problem:
            found.append(("npm", shown, problem))
            continue
        if os.path.basename(command[0]) in ("curl", "wget") and not verified:
            for url in _remote_urls(shown):
                if url:
                    found.append(
                        (
                            "download",
                            url,
                            f"downloads {url} and nothing in the same step checks it "
                            "(sha256sum -c)",
                        )
                    )
    return found


def check_workflow(
    path: str, text: str, pins: dict[str, str], files: set[str]
) -> list[str]:
    """Problems in one workflow file, each a printable line."""
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        return [f"{path}: not a workflow: no `jobs` mapping"]
    problems: list[str] = []
    for job_name, job in document["jobs"].items():
        if not isinstance(job, dict):
            continue
        uses = job.get("uses")
        if isinstance(uses, str):  # a reusable workflow
            problem = action_problem(uses)
            if problem:
                problems.append(
                    f"{path}: job '{job_name}': action [{uses}]: uses {uses}: {problem}"
                )
        for index, step in enumerate(job.get("steps") or [], 1):
            if not isinstance(step, dict):
                continue
            label = step.get("name") or step.get("uses") or f"step {index}"
            for rule, subject, message in step_findings(step, pins, files):
                problems.append(
                    f"{path}: job '{job_name}', step '{label}': {rule} [{subject}]: {message}"
                )
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    args = parser.parse_args(argv)
    root = args.root

    files = set(hygiene.tracked_files(root))
    workflows = sorted(
        name
        for name in files
        if Path(name).parent == WORKFLOWS and name.endswith((".yml", ".yaml"))
    )
    problems: list[str] = []
    pins: dict[str, str] = {}
    if (root / CI_TOOLS).exists():
        pins = read_pins((root / CI_TOOLS).read_text(encoding="utf-8"))
    else:
        problems.append(
            f"{CI_TOOLS}: missing; it says which version of each tool CI runs"
        )
    if not workflows:
        problems.append(
            f"no workflow found under {WORKFLOWS}: the check would pass on anything"
        )
    for name in workflows:
        try:
            text = (root / name).read_text(encoding="utf-8")
            problems += check_workflow(name, text, pins, files)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            problems.append(f"{name}: cannot be read: {exc}")

    if problems:
        print(
            f"ERROR: {len(problems)} unpinned tool(s) or action(s) in the workflows:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(workflows)} workflow(s) checked; {len(pins)} tool version(s) from {CI_TOOLS}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
