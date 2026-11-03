#!/usr/bin/env python3
"""Compare two hash-pinned requirements locks by what they install.

`compile_requirements.sh --check` used to compare the lock it compiled with
the committed one as text. Dependabot rewrites the locks of its pip-group PRs
with pip-compile, which writes the same pins differently: extras on the
requirement (`uvicorn[standard]==0.24.0`), environment markers, `# via` lines
that name `requirements.in` instead of the service's path, another order. The
text never matched, so the check failed on every one of those PRs whatever
they changed.

What a lock decides is which distribution of which version gets installed and
which artefacts pip accepts for it. This compares exactly that, per package:
the PEP 503 normalised name, the `==` version and the set of `--hash` values.
Extras, markers, comments and order are ignored. A package present in one
lock and not in the other, a different version or a different hash set is a
difference, and every difference is printed.

Usage: compare_locks.py EXPECTED ACTUAL
  EXPECTED  the lock compiled from requirements.in
  ACTUAL    the committed lock
Exit status: 0 same pins and hashes, 1 different, 2 a lock could not be read.
Standard library only: CI runs it before anything is installed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# name, optional [extras], ==version, optional ; marker
_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"==\s*(?P<version>[^\s;]+)\s*"
    r"(?:;.*)?$"
)
_HASH = re.compile(r"--hash[=\s]+(\S+)")


class LockError(ValueError):
    """A line of a lock that this comparison cannot interpret."""


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: case-insensitive, runs of -_. are one dash."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lines(text: str):
    """Join backslash continuations and drop comments and blank lines."""
    buf = ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        line = line.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            yield buf.strip()
        buf = ""
    if buf.strip():
        yield buf.strip()


def parse_lock(text: str) -> dict[str, dict[str, frozenset[str]]]:
    """Map each normalised package name to {version: hashes}."""
    packages: dict[str, dict[str, frozenset[str]]] = {}
    for line in _logical_lines(text):
        hashes = frozenset(_HASH.findall(line))
        spec = _HASH.sub("", line).strip()
        if spec.startswith("-"):
            # Options such as --index-url or -c carry no pin. A lock that
            # includes another file (-r) is not something these locks do.
            if spec.startswith(
                ("-r", "--requirement", "-c", "--constraint", "-e", "--editable")
            ):
                raise LockError(f"unsupported line in a lock: {line}")
            continue
        m = _REQUIREMENT.match(spec)
        if not m:
            raise LockError(f"not a '==' pin: {line}")
        name = normalize_name(m.group("name"))
        version = m.group("version")
        versions = packages.setdefault(name, {})
        versions[version] = versions.get(version, frozenset()) | hashes
    return packages


def compare(expected: dict, actual: dict) -> list[str]:
    """Every difference between two parsed locks, as readable lines."""
    problems: list[str] = []
    for name in sorted(expected.keys() - actual.keys()):
        problems.append(f"missing from the lock: {name}=={_versions(expected[name])}")
    for name in sorted(actual.keys() - expected.keys()):
        problems.append(
            f"in the lock but not resolved from requirements.in: {name}=={_versions(actual[name])}"
        )
    for name in sorted(expected.keys() & actual.keys()):
        exp, act = expected[name], actual[name]
        if set(exp) != set(act):
            problems.append(
                f"version differs: {name} resolves to {_versions(exp)}, lock has {_versions(act)}"
            )
            continue
        for version in sorted(exp):
            only_exp = exp[version] - act[version]
            only_act = act[version] - exp[version]
            if only_exp or only_act:
                problems.append(
                    f"hashes differ: {name}=={version}: "
                    f"{len(only_exp)} expected not in the lock, {len(only_act)} in the lock not expected"
                )
                problems.extend(f"    - {h}" for h in sorted(only_exp))
                problems.extend(f"    + {h}" for h in sorted(only_act))
    return problems


def _versions(versions: dict) -> str:
    return ",".join(sorted(versions))


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: compare_locks.py EXPECTED ACTUAL", file=sys.stderr)
        return 2
    try:
        expected = parse_lock(Path(argv[1]).read_text(encoding="utf-8"))
        actual = parse_lock(Path(argv[2]).read_text(encoding="utf-8"))
    except (OSError, LockError) as exc:
        print(f"compare_locks: {exc}", file=sys.stderr)
        return 2
    problems = compare(expected, actual)
    for p in problems:
        print(f"       {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
