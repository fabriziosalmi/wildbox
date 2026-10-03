#!/usr/bin/env python3
"""Fail when a test file sits where no CI workflow collects it (#582).

A ``test_*.py`` that no job runs cannot catch a regression, and it drifts
from the code without anyone noticing: open-security-agents/tests/test_basic.py
asserted an attribute the client had lost, and nothing ran it to find out.
This check reads every workflow, works out which paths its pytest commands
collect, and lists every test file outside them.

The collected paths are derived, not declared: each ``pytest`` (or
``python -m pytest``) command in a step's ``run`` script contributes its path
arguments, resolved against the step's working directory and any ``cd`` before
it, with ``${{ matrix.<key> }}`` expanded over the job's matrix. Removing a
suite from a workflow therefore makes its files fail this check, too.

A file that is meant to stay out of CI goes in the allow-list, one path per
line followed by ``#`` and the reason. An entry without a reason, for a file
that does not exist, or for a file CI already collects is an error, so the
list cannot go stale.

Usage: python scripts/check_test_collection.py [--list-roots]
"""

from __future__ import annotations

import argparse
import itertools
import os
import posixpath
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
ALLOWLIST = REPO_ROOT / "scripts" / "test_collection_allowlist.txt"

# pytest's default python_files.
TEST_FILE = re.compile(r"^(test_.*|.*_test)\.py$")
MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEPARATORS = {";", "&&", "||", "|", "&", ">", ">>", "<", "(", ")"}
# Options that take their value as the next argument rather than after "=".
OPTIONS_WITH_VALUE = {
    "-c",
    "-k",
    "-m",
    "-n",
    "-o",
    "-p",
    "-W",
    "--basetemp",
    "--confcutdir",
    "--cov",
    "--cov-report",
    "--deselect",
    "--durations",
    "--ignore",
    "--junit-xml",
    "--junitxml",
    "--log-level",
    "--maxfail",
    "--override-ini",
    "--rootdir",
    "--tb",
    "--timeout",
}


def _tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes: not a line this check can read
        return []


def _commands(line: str) -> Iterable[list[str]]:
    """Split one shell line into its simple commands."""
    command: list[str] = []
    for token in _tokens(line):
        if token in SEPARATORS:
            if command:
                yield command
            command = []
        else:
            command.append(token)
    if command:
        yield command


def _pytest_args(command: list[str]) -> list[str] | None:
    """The arguments of a pytest invocation, or None if it is not one.

    Only the command word counts, after any VAR=value assignments: "pip install
    pytest" installs pytest, it does not run it.
    """
    words = list(itertools.dropwhile(lambda w: ENV_ASSIGNMENT.match(w), command))
    if not words:
        return None
    name = posixpath.basename(words[0])
    if name == "pytest":
        return words[1:]
    if re.fullmatch(r"python[0-9.]*", name) and words[1:3] == ["-m", "pytest"]:
        return words[3:]
    return None


def _positional(args: list[str]) -> list[str]:
    paths, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in OPTIONS_WITH_VALUE
        elif "$" not in arg:
            paths.append(arg.split("::", 1)[0])
    return paths


def _join(cwd: str, path: str) -> str:
    joined = posixpath.normpath(posixpath.join(cwd, path))
    return "." if joined in ("", ".") else joined


def pytest_targets(script: str, cwd: str = ".") -> list[str]:
    """Repository-relative paths that the pytest commands in ``script`` collect.

    A pytest command with no path argument collects its working directory.
    """
    script = script.replace("\\\n", " ")
    targets: list[str] = []
    for line in script.splitlines():
        for command in _commands(line):
            if command[0] == "cd" and len(command) > 1 and "$" not in command[1]:
                cwd = _join(cwd, command[1])
                continue
            args = _pytest_args(command)
            if args is None:
                continue
            paths = _positional(args) or ["."]
            targets.extend(_join(cwd, path) for path in paths)
    return targets


def _expansions(text: str, matrix: dict) -> list[dict[str, str]]:
    """Every assignment of the matrix keys ``text`` refers to."""
    keys = sorted(set(MATRIX_REF.findall(text)))
    values = []
    for key in keys:
        value = matrix.get(key)
        if not isinstance(value, list):
            return []  # a key the matrix does not list: nothing to resolve
        values.append([str(v) for v in value])
    return [dict(zip(keys, combo)) for combo in itertools.product(*values)]


def _expand(text: str, assignment: dict[str, str]) -> str:
    return MATRIX_REF.sub(lambda m: assignment[m.group(1)], text)


def workflow_targets(workflow: dict) -> set[str]:
    """Paths the pytest commands in one parsed workflow collect."""
    targets: set[str] = set()
    default_dir = ((workflow.get("defaults") or {}).get("run") or {}).get(
        "working-directory"
    ) or "."
    for job in (workflow.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        job_dir = ((job.get("defaults") or {}).get("run") or {}).get(
            "working-directory"
        ) or default_dir
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if not isinstance(matrix, dict):
            matrix = {}
        for step in job.get("steps") or []:
            script = step.get("run") if isinstance(step, dict) else None
            if not isinstance(script, str):
                continue
            cwd = step.get("working-directory") or job_dir
            text = f"{cwd}\n{script}"
            if MATRIX_REF.search(text):
                assignments = _expansions(text, matrix)  # [] if unresolvable
            else:
                assignments = [{}]
            for assignment in assignments:
                targets.update(
                    pytest_targets(
                        _expand(script, assignment),
                        _join(".", _expand(cwd, assignment)),
                    )
                )
    return targets


def collected_targets(workflow_dir: Path) -> set[str]:
    targets: set[str] = set()
    for path in sorted(workflow_dir.glob("*.y*ml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(workflow, dict):
            targets |= workflow_targets(workflow)
    return targets


def is_collected(path: str, targets: Iterable[str]) -> bool:
    return any(
        target == "." or path == target or path.startswith(target.rstrip("/") + "/")
        for target in targets
    )


def find_test_files(paths: Iterable[str]) -> list[str]:
    return sorted(p for p in paths if TEST_FILE.match(posixpath.basename(p)))


def tracked_files(root: Path) -> list[str]:
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
    ).stdout
    return [p for p in output.decode().split("\0") if p]


def read_allowlist(text: str) -> tuple[dict[str, str], list[str]]:
    """Parse the allow-list into {path: reason}, with any malformed lines."""
    entries: dict[str, str] = {}
    errors: list[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path, _, reason = line.partition("#")
        path, reason = path.strip(), reason.strip()
        if not reason:
            errors.append(f"line {number}: {path} has no reason after '#'")
        entries[path] = reason
    return entries, errors


def check(
    files: list[str], targets: set[str], allowlist: dict[str, str]
) -> tuple[list[str], list[str]]:
    """Return (uncollected test files, stale allow-list entries)."""
    uncollected = [
        f
        for f in find_test_files(files)
        if not is_collected(f, targets) and f not in allowlist
    ]
    existing = set(files)
    stale = []
    for path in sorted(allowlist):
        if path not in existing:
            stale.append(f"{path}: no such tracked file")
        elif is_collected(path, targets):
            stale.append(f"{path}: CI already collects it")
    return uncollected, stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--workflows", type=Path)
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument(
        "--list-roots", action="store_true", help="print what CI collects and exit"
    )
    args = parser.parse_args(argv)
    root = args.root
    workflows = args.workflows or root / ".github" / "workflows"
    allowlist_path = (
        args.allowlist or root / "scripts" / "test_collection_allowlist.txt"
    )

    targets = collected_targets(workflows)
    if args.list_roots:
        print("\n".join(sorted(targets)))
        return 0

    allowlist, errors = read_allowlist(
        allowlist_path.read_text(encoding="utf-8") if allowlist_path.exists() else ""
    )
    uncollected, stale = check(tracked_files(root), targets, allowlist)

    for path in uncollected:
        print(f"::error file={path}::{path} is not collected by any CI workflow")
    for message in errors + stale:
        print(f"::error file={os.path.relpath(allowlist_path, root)}::{message}")
    if uncollected:
        print(
            "\nNo workflow runs the files above, so they never run in CI. Move "
            "each under a directory a workflow collects (a service's tests/unit/, "
            "tests/integration/, ...), delete it, or list it in "
            f"{os.path.relpath(allowlist_path, root)} with the reason.\n"
            "Collected: " + ", ".join(sorted(targets))
        )
    if uncollected or errors or stale:
        return 1
    print(
        f"All {len(find_test_files(tracked_files(root)))} test files are collected by "
        f"CI or allow-listed ({len(allowlist)} allow-listed)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
