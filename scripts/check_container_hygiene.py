#!/usr/bin/env python3
"""Fail on container settings that hand out the host or float with upstream (#680).

The gateway's development Compose file ran ``gliderlabs/logspout:latest``
with ``/var/run/docker.sock`` mounted: an unmaintained image, at whatever
version the registry served that day, holding the Docker API, which is root
on the host. Nothing looked at Compose files other than the root one, so
nothing noticed. This check reads every tracked Compose file (any YAML file
with a top-level ``services:`` mapping: the root files, the overlays, the
per-service ones, those under .github/) and refuses, per service:

socket     a bind mount of a container runtime socket (docker.sock and the
           like) or of a directory that holds one. ``:ro`` does not help: it
           restricts the socket file, not the API behind it.
image      an ``image:`` that does not name a version: no tag, ``latest``, or
           a tag with no digit in it (``nginx:alpine``). A digest
           (``@sha256:``) is accepted. A service that also has ``build:`` is
           skipped: there ``image:`` names what the build produces.
privilege  ``privileged``, ``cap_add``, ``devices``, the host's network, PID,
           IPC, user or cgroup namespace, or an unconfined seccomp or
           AppArmor profile.
port       a port published on every interface of the host. A port mapping
           must name a loopback address (``127.0.0.1:8000:8000``) unless the
           service is meant to be reached from other machines.

A deliberate exception goes in scripts/container_hygiene_allowlist.txt as
``rule  file  subject  # reason``, where the subject is what the finding
prints in brackets. An entry without a reason, or one that no longer matches
a finding, is an error, so the list cannot go stale.

Usage: python scripts/check_container_hygiene.py [--root DIR] [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = Path("scripts/container_hygiene_allowlist.txt")

# Rules a finding of which may be allow-listed, with a reason.
ALLOWABLE = frozenset({"socket", "image", "privilege", "port"})


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    subject: str  # what an allow-list entry names
    message: str
    line: int = 0

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.rule, self.path, self.subject)

    def render(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{where}: {self.rule} [{self.subject}]: {self.message}"


# --------------------------------------------------------------------------
# Compose files
# --------------------------------------------------------------------------


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose's own tags (``!override``, ``!reset``)."""


def _plain(loader: yaml.Loader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _plain)

# ${VAR:-default} and ${VAR-default}: Compose uses the default when the
# variable is unset, which is what a fresh checkout runs.
_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^${}]*)\}")

# A container runtime's control socket, wherever it is mounted from.
_SOCKET = re.compile(
    r"(^|/)(docker|podman|containerd|cri-dockerd|crio)\.sock$", re.IGNORECASE
)
# Directories whose bind mount carries the socket with it.
_SOCKET_DIRS = frozenset({"/", "/var", "/var/run", "/run", "/run/docker"})

_HOST_NAMESPACES = ("network_mode", "pid", "ipc", "userns_mode", "cgroup")
_LOOPBACK = re.compile(r"^(127(\.\d{1,3}){3}|::1|localhost)$")


def expand_defaults(value: str) -> str:
    """Replace ``${VAR:-default}`` with the default, innermost first."""
    previous = None
    while previous != value:
        previous = value
        value = _DEFAULT.sub(lambda m: m.group(1), value)
    return value


def load_compose(text: str) -> dict[str, Any] | None:
    """Return the document when it is a Compose file, else None."""
    document = yaml.load(
        text, Loader=_ComposeLoader
    )  # noqa: S506 - SafeLoader subclass
    if isinstance(document, dict) and isinstance(document.get("services"), dict):
        return document
    return None


def image_problem(reference: str) -> str | None:
    """Say why an image reference does not name a version, or None when it does."""
    resolved = expand_defaults(str(reference).strip())
    if "$" in resolved:
        return "the tag comes from a variable with no default, so it cannot be verified"
    if re.search(r"@sha256:[0-9a-f]{64}$", resolved):
        return None
    name = resolved.rsplit("/", 1)[-1]
    if ":" not in name:
        return "has no tag, which is :latest; name a version"
    tag = name.rsplit(":", 1)[1]
    if tag == "latest":
        return "floats with upstream; name a version"
    if not re.search(r"\d", tag):
        return f"the tag '{tag}' names no version and floats with upstream"
    return None


def _volume_sources(volumes: Any) -> Iterable[str]:
    for volume in volumes or []:
        if isinstance(volume, dict):
            if volume.get("type", "bind") == "bind" and volume.get("source"):
                yield expand_defaults(str(volume["source"]))
        elif isinstance(volume, str):
            parts = expand_defaults(volume).split(":")
            if len(parts) > 1:  # one part is an anonymous volume
                yield parts[0]


def is_runtime_socket(source: str) -> bool:
    normalized = source.rstrip("/") or "/"
    return bool(_SOCKET.search(normalized)) or normalized in _SOCKET_DIRS


def parse_port(entry: Any) -> tuple[str, str]:
    """Return (host address or '', published port or container port) of a mapping."""
    if isinstance(entry, dict):
        published = entry.get("published", entry.get("target", ""))
        return str(entry.get("host_ip", "")), str(published)
    text = expand_defaults(str(entry)).split("/", 1)[0]  # drop /tcp, /udp
    if text.startswith("["):  # [::1]:8000:8000
        address, _, rest = text[1:].partition("]")
        return address, rest.lstrip(":").split(":")[0]
    parts = text.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:-2]), parts[-2]
    return "", parts[0]


def _line_of(lines: Sequence[str], service: str, needle: str) -> int:
    """Line of ``needle`` inside ``service``, the service's own line, or 0."""
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(rf"\s+{re.escape(service)}\s*:", line)
        ),
        None,
    )
    if start is None:
        return 0
    for index in range(start + 1, len(lines)):
        if needle and needle in lines[index]:
            return index + 1
        if re.match(r"\S", lines[index]):  # left the services block
            break
    return start + 1


def check_compose(path: str, text: str) -> list[Finding]:
    """Findings for one Compose file; empty when the file is not Compose."""
    document = load_compose(text)
    if document is None:
        return []
    lines = text.splitlines()
    findings: list[Finding] = []

    def add(rule: str, service: str, detail: str, message: str, needle: str) -> None:
        findings.append(
            Finding(
                rule,
                path,
                f"{service}:{detail}",
                f"service '{service}' {message}",
                _line_of(lines, service, needle),
            )
        )

    for name, service in document["services"].items():
        if not isinstance(service, dict):
            continue

        for source in _volume_sources(service.get("volumes")):
            if is_runtime_socket(source):
                add(
                    "socket",
                    name,
                    source,
                    f"mounts {source}: the container runtime's API is root on the "
                    "host, read-only mount or not",
                    source,
                )

        if "image" in service and "build" not in service:
            problem = image_problem(service["image"])
            if problem:
                reference = str(service["image"])
                add("image", name, reference, f"runs {reference}: {problem}", reference)

        if service.get("privileged") is True:
            add("privilege", name, "privileged", "is privileged", "privileged")
        for key in ("cap_add", "devices"):
            if service.get(key):
                add("privilege", name, key, f"sets {key}: {service[key]}", key)
        for key in _HOST_NAMESPACES:
            if str(service.get(key, "")).strip() == "host":
                add("privilege", name, f"{key}=host", f"sets {key}: host", key)
        for option in service.get("security_opt") or []:
            if re.search(r"unconfined|label[:=]disable", str(option)):
                add(
                    "privilege",
                    name,
                    str(option),
                    f"sets security_opt {option}",
                    str(option),
                )

        for entry in service.get("ports") or []:
            address, port = parse_port(entry)
            if not _LOOPBACK.match(address):
                shown = entry if not isinstance(entry, dict) else dict(entry)
                add(
                    "port",
                    name,
                    port,
                    f"publishes {shown} on every interface; bind it to 127.0.0.1 "
                    "unless other machines must reach it",
                    str(entry) if not isinstance(entry, dict) else str(port),
                )
    return findings


# --------------------------------------------------------------------------
# Allow-list
# --------------------------------------------------------------------------


def read_allowlist(text: str) -> tuple[dict[tuple[str, str, str], str], list[str]]:
    """Parse the allow-list into {(rule, path, subject): reason} and its errors."""
    entries: dict[tuple[str, str, str], str] = {}
    errors: list[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry, _, reason = line.partition(" #")
        fields = entry.split()
        if len(fields) != 3:
            errors.append(f"line {number}: expected 'rule  file  subject  # reason'")
            continue
        rule = fields[0]
        if rule not in ALLOWABLE:
            errors.append(
                f"line {number}: '{rule}' is not a rule that can be allow-listed"
            )
            continue
        if not reason.strip():
            errors.append(f"line {number}: {' '.join(fields)} has no reason after '#'")
        entries[(fields[0], fields[1], fields[2])] = reason.strip()
    return entries, errors


def apply_allowlist(
    findings: Sequence[Finding], allowlist: dict[tuple[str, str, str], str]
) -> tuple[list[Finding], list[str]]:
    """Return (findings not allow-listed, allow-list entries that match nothing)."""
    keys = {finding.key for finding in findings}
    remaining = [finding for finding in findings if finding.key not in allowlist]
    stale = [
        f"{' '.join(key)}: matches no finding; remove the entry"
        for key in sorted(allowlist)
        if key not in keys
    ]
    return remaining, stale


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


_SKIPPED_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})


def tracked_files(root: Path) -> list[str]:
    """Files git tracks under ``root``; every file there when it is no checkout."""
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False
    )
    inside = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if (
        listed.returncode == 0
        and inside.returncode == 0
        and Path(inside.stdout.decode().strip()).resolve() == root.resolve()
    ):
        return [p for p in listed.stdout.decode().split("\0") if p]
    found = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in _SKIPPED_DIRS]
        for name in names:
            found.append(os.path.relpath(os.path.join(directory, name), root))
    return found


def is_yaml(path: str) -> bool:
    return path.endswith((".yml", ".yaml"))


def looks_like_compose(path: str) -> bool:
    return "compose" in os.path.basename(path).lower()


def check_tree(
    root: Path, files: Iterable[str]
) -> tuple[list[Finding], list[str], int]:
    """Check every Compose file among ``files``.

    Returns (findings, files that could not be read, number of Compose files).
    """
    findings: list[Finding] = []
    unreadable: list[str] = []
    compose_files = 0
    for path in sorted(files):
        if not is_yaml(path):
            continue
        try:
            text = (root / path).read_text(encoding="utf-8")
            found = load_compose(text) is not None
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            # A YAML file this cannot parse is somebody else's problem, unless
            # it is a Compose file: then skipping it would skip the check.
            if looks_like_compose(path):
                unreadable.append(f"{path}: cannot be read as YAML: {exc}")
            continue
        if not found:
            continue
        compose_files += 1
        findings.extend(check_compose(path, text))
    return findings, unreadable, compose_files


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    parser.add_argument("--allowlist", type=Path, help="allow-list file")
    args = parser.parse_args(argv)

    root = args.root
    allowlist_path = args.allowlist or root / ALLOWLIST
    allowlist, errors = read_allowlist(
        allowlist_path.read_text(encoding="utf-8") if allowlist_path.exists() else ""
    )
    findings, unreadable, compose_files = check_tree(root, tracked_files(root))
    remaining, stale = apply_allowlist(findings, allowlist)

    try:
        shown_allowlist = str(allowlist_path.resolve().relative_to(root.resolve()))
    except ValueError:
        shown_allowlist = str(allowlist_path)
    problems = [finding.render() for finding in remaining]
    problems += unreadable
    problems += [f"{shown_allowlist}: {message}" for message in errors + stale]
    if compose_files == 0:
        problems.append("no Compose file found: the check would pass on anything")

    if problems:
        print(f"ERROR: {len(problems)} container hygiene problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nFix the file, or, for a deliberate exception, add "
            f"'rule  file  subject  # reason' to {shown_allowlist}.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {compose_files} Compose file(s) checked, "
        f"{len(findings) - len(remaining)} finding(s) allow-listed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
