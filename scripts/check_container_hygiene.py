#!/usr/bin/env python3
"""Fail on container settings that hand out the host or float with upstream (#680, #657).

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

Four images ran ``pip install --upgrade pip`` before their hash-checked
install, so the installer itself was whatever PyPI served that day, and all
eight built the shared package in an isolated environment for which pip
downloaded the latest setuptools, unhashed (#657). The check therefore also
reads every tracked Dockerfile and refuses:

base-image     a ``FROM``, or the image of a ``COPY --from=``, that is not
               pinned by digest. A stage of the same file and ``scratch`` pass.
pip            a ``pip install`` (or ``download``, ``wheel``) that can fetch
               something no hash vouches for. Two forms pass:
               ``--require-hashes --no-build-isolation -r <lockfile>``, with no
               requirement on the command line, and ``--no-index <local path>``.
               Without ``--no-build-isolation`` a source distribution in the
               lockfile is built with build dependencies downloaded unhashed;
               without ``--no-index`` a local path still makes pip download
               its build backend.
npm            ``npm install``, ``yarn`` or ``pnpm`` resolving versions at
               build time: a global install without an exact ``name@1.2.3``,
               or an install that is not ``npm ci`` (``--frozen-lockfile``).
pipe-to-shell  a download fed to an interpreter (``curl ... | sh``) or
               substituted into the command line (``$(curl ...)``).
download       ``curl``, ``wget`` or ``ADD <url>`` with nothing in the same
               instruction that checks the result (``sha256sum -c``,
               ``gpg --verify``, ``cosign verify``, ``ADD --checksum=``).

os-packages    ``apt-get install`` without ``--no-install-recommends``, which
               also installs every package the named ones recommend; an
               ``apt-get update`` whose package lists are not removed in the
               same ``RUN`` (``rm -rf /var/lib/apt/lists/*``), since a later
               instruction cannot take them out of the layer; ``apk add``
               without ``--no-cache``, for the same reason (#726).

Not checked: ``apt-get install`` and ``apk add`` without versions. A pinned
OS package stops receiving security fixes and breaks the build when the
distribution drops it; the digest-pinned base image fixes the snapshot they
install on top of.

A deliberate exception goes in scripts/container_hygiene_allowlist.txt as
``rule  file  subject  # reason``, where the subject is what the finding
prints in brackets. An entry without a reason, or one that no longer matches
a finding, is an error, so the list cannot go stale. The Compose rules and
``download`` can be allow-listed; ``base-image``, ``pip``, ``npm``,
``pipe-to-shell`` and ``os-packages`` cannot.

Usage: python scripts/check_container_hygiene.py [--root DIR] [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = Path("scripts/container_hygiene_allowlist.txt")

# Rules a finding of which may be allow-listed, with a reason.
ALLOWABLE = frozenset({"socket", "image", "privilege", "port", "download"})


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
# Dockerfiles
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Instruction:
    keyword: str  # upper case: FROM, RUN, ...
    value: str  # the rest, continuation lines joined, comments dropped
    line: int


_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def parse_dockerfile(text: str) -> list[Instruction]:
    """Split a Dockerfile into instructions, as the builder joins them."""
    instructions: list[Instruction] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        start = index + 1
        parts: list[str] = []
        while index < len(lines):
            piece = lines[index].strip()
            index += 1
            if parts and (not piece or piece.startswith("#")):
                continue  # a comment or blank line inside a continued instruction
            if piece.endswith("\\"):
                parts.append(piece[:-1])
                continue
            parts.append(piece)
            break
        joined = " ".join(parts)
        keyword, _, value = joined.partition(" ")
        if keyword.upper() == "ONBUILD":
            keyword, _, value = value.strip().partition(" ")
        # A here-document carries the script on the lines that follow.
        for _quote, marker in _HEREDOC.findall(value):
            closing = next(
                (i for i in range(index, len(lines)) if lines[i].strip() == marker),
                None,
            )
            if closing is None:
                continue  # not a here-document after all: swallow nothing
            value += "\n" + "\n".join(lines[index:closing])
            index = closing + 1
        instructions.append(Instruction(keyword.upper(), value.strip(), start))
    return instructions


def is_dockerfile(path: str) -> bool:
    name = os.path.basename(path)
    return (
        name == "Dockerfile"
        or name.startswith("Dockerfile.")
        or name.lower().endswith(".dockerfile")
    )


_SHELL_PREFIXES = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "{", "!", "time", "exec"}
)
_SHELL_PREFIXES_WITH_ARGS = frozenset({"sudo", "env", "command", "nice", "xargs"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_OPERATOR = re.compile(r"^[;&|()]+$")


def shell_commands(script: str) -> list[list[str]]:
    """Split a RUN script into simple commands, each a list of words.

    Operators (``&&``, ``||``, ``;``, ``|``, subshells and ``$(...)``) end a
    command; leading shell keywords and ``VAR=value`` assignments are dropped,
    so the first word of each command is the program it runs.
    """
    script = script.replace("\n", " ; ")
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        words = list(lexer)
    except ValueError:  # unbalanced quotes: fall back to a plain split
        words = re.sub(r"([;&|()]+)", r" \1 ", script).split()
    commands: list[list[str]] = []
    current: list[str] = []
    for word in words + [";"]:
        if not _OPERATOR.match(word):
            current.append(word)
            continue
        while current and (
            current[0] in _SHELL_PREFIXES
            or current[0] in _SHELL_PREFIXES_WITH_ARGS
            or _ASSIGNMENT.match(current[0])
        ):
            current.pop(0)
        if current:
            commands.append(current)
            nested = _nested_script(current)
            if nested:
                commands.extend(shell_commands(nested))
        current = []
    return commands


_SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh", "ksh"})


def _nested_script(command: Sequence[str]) -> str:
    """The script a command hands to a shell: ``sh -c '...'`` or ``eval ...``."""
    program = os.path.basename(command[0])
    if program == "eval":
        return " ".join(command[1:])
    if program in _SHELLS:
        for position, word in enumerate(command[1:], 1):
            if re.match(r"^-[A-Za-z]*c$", word) and position + 1 < len(command):
                return command[position + 1]
    return ""


def run_script(value: str) -> str:
    """The shell script of a RUN instruction, in shell or in exec form."""
    script = re.sub(r"^(--\S+\s+)+", "", value)  # --mount=..., --network=...
    if script.startswith("["):
        try:
            words = json.loads(script)
        except ValueError:
            return script
        if isinstance(words, list) and all(isinstance(word, str) for word in words):
            return " ".join(shlex.quote(word) for word in words)
    return script


# pip options that take a value, so the value is not a requirement.
_PIP_VALUE_OPTIONS = frozenset(
    {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-t",
        "--target",
        "--prefix",
        "--root",
        "--src",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--only-binary",
        "--no-binary",
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--progress-bar",
        "--cache-dir",
        "--upgrade-strategy",
        "--trusted-host",
        "-C",
        "--config-settings",
        "--global-option",
        "--use-feature",
        "--python",
        "--log",
        "--proxy",
        "--retries",
        "--timeout",
        "--cert",
        "--client-cert",
        "--report",
        "-d",
        "--dest",
        "-w",
        "--wheel-dir",
    }
)
_PIP_SUBCOMMANDS = frozenset({"install", "download", "wheel"})
_PIP = re.compile(r"^pip(3(\.\d+)?)?$")
_PYTHON = re.compile(r"^python(3(\.\d+)?)?$")
_INSTALLERS = frozenset({"pip", "setuptools", "wheel"})


def pip_arguments(command: Sequence[str]) -> list[str] | None:
    """Arguments of ``pip install`` (or download, wheel) in a command, else None."""
    program = os.path.basename(command[0])
    if _PIP.match(program):
        rest = list(command[1:])
    elif _PYTHON.match(program) and list(command[1:3]) == ["-m", "pip"]:
        rest = list(command[3:])
    elif program == "uv" and list(command[1:2]) == ["pip"]:
        rest = list(command[2:])
    else:
        return None
    while rest:
        word = rest.pop(0)
        if not word.startswith("-"):
            return rest if word in _PIP_SUBCOMMANDS else None
        if word in _PIP_VALUE_OPTIONS and rest:
            rest.pop(0)  # pip --cache-dir /x install ...
    return None


def _is_local_path(word: str) -> bool:
    return word.startswith(("/", ".")) and "://" not in word


def pip_problem(arguments: Sequence[str]) -> str | None:
    """Say why a pip install can fetch something unverified, or None."""
    flags: set[str] = set()
    values: dict[str, list[str]] = {}
    requirements: list[str] = []
    words = list(arguments)
    while words:
        word = words.pop(0)
        if not word.startswith("-"):
            requirements.append(word)
            continue
        option, equals, value = word.partition("=")
        if option in _PIP_VALUE_OPTIONS:
            if not equals:
                value = words.pop(0) if words else ""
            values.setdefault(option, []).append(value)
        else:
            flags.add(option)

    lockfiles = values.get("-r", []) + values.get("--requirement", [])
    editables = values.get("-e", []) + values.get("--editable", [])
    named = requirements + editables
    remote_links = [
        link
        for link in values.get("-f", []) + values.get("--find-links", [])
        if not _is_local_path(link)
    ]

    if "--require-hashes" in flags:
        if named:
            return (
                f"names {', '.join(named)} next to --require-hashes; every "
                "requirement must come from the hash-pinned file"
            )
        if not lockfiles:
            return "--require-hashes without -r <lockfile>"
        if (
            "--no-build-isolation" not in flags
            and ":all:" not in values.get("--only-binary", [])
            and "--no-index" not in flags
        ):
            return (
                "a source distribution in the lockfile would be built with build "
                "dependencies downloaded unhashed; add --no-build-isolation"
            )
        return None

    if "--no-index" in flags:
        remote = [word for word in named if not _is_local_path(word)]
        if lockfiles:
            return "-r without --require-hashes; nothing checks what the file names"
        if remote or remote_links:
            return (
                f"fetches {', '.join(remote + remote_links)} although --no-index is "
                "set; install from a local path"
            )
        if not named:
            return "installs nothing"
        return None

    installers = sorted(
        {re.split(r"[<>=!~\[ ]", word)[0] for word in named} & _INSTALLERS
    )
    if installers:
        return (
            f"installs {', '.join(installers)} from PyPI unpinned and unhashed, and "
            "every later step runs it; use the one in the digest-pinned base image"
        )
    if named and all(_is_local_path(word) for word in named) and not lockfiles:
        return (
            "installs a local path without --no-index: pip still downloads the "
            "build backend (setuptools) and any missing dependency, unhashed; add "
            "--no-index --no-build-isolation"
        )
    return (
        "is not hash-checked; use --require-hashes --no-build-isolation -r "
        "<lockfile>, or --no-index for a local path"
    )


_EXACT_NPM = re.compile(r".@\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
_NPM_VALUE_OPTIONS = frozenset({"--prefix", "--registry", "--cache", "-C", "--dir"})


def npm_problem(command: Sequence[str]) -> str | None:
    """Say why an npm, yarn or pnpm command installs outside a lockfile, or None."""
    program = os.path.basename(command[0])
    if program not in ("npm", "yarn", "pnpm"):
        return None
    words: list[str] = []
    flags: set[str] = set()
    rest = list(command[1:])
    while rest:
        word = rest.pop(0)
        if word.startswith("-"):
            option = word.partition("=")[0]
            flags.add(option)
            if option in _NPM_VALUE_OPTIONS and "=" not in word and rest:
                rest.pop(0)
        else:
            words.append(word)
    if not words:
        return None
    globally = bool(flags & {"-g", "--global"})
    action, packages = words[0], words[1:]
    if program == "yarn" and action == "global":
        globally, action, packages = True, (words[1:2] or [""])[0], words[2:]
    if action not in ("install", "i", "add"):
        return None
    if globally or packages:
        loose = [package for package in packages if not _EXACT_NPM.search(package)]
        if loose:
            return (
                f"installs {', '.join(loose)} without an exact version "
                "(name@1.2.3), so the build takes whatever the registry serves"
            )
        if globally:
            return None
        return "adds packages outside the lockfile; put them in package-lock.json and run npm ci"
    if flags & {"--frozen-lockfile", "--immutable"}:
        return None
    return "resolves versions at build time; use `npm ci` (or --frozen-lockfile)"


_APT = frozenset({"apt-get", "apt", "aptitude"})
# apt options that take a value, so the value is not the subcommand.
_APT_VALUE_OPTIONS = frozenset({"-o", "--option", "-c", "--config-file", "-t"})
_APT_INSTALLS = frozenset({"install", "build-dep", "dist-upgrade", "full-upgrade"})
_NO_RECOMMENDS = re.compile(r"APT::Install-Recommends=[\"']?(0|false|no)\b", re.I)
_APT_LISTS = "/var/lib/apt/lists"
_APK_CACHE = "/var/cache/apk"
_CACHE_MOUNT = re.compile(r"--mount=(\S*type=cache\S*)")


def _subcommand(words: Sequence[str], value_options: frozenset[str]) -> str:
    """The first word of a command's arguments that is not an option."""
    rest = list(words)
    while rest:
        word = rest.pop(0)
        if not word.startswith("-"):
            return word
        if word in value_options and rest:
            rest.pop(0)
    return ""


def _removes(command: Sequence[str], directory: str) -> bool:
    """Whether the command is an ``rm -r`` of ``directory`` or its contents."""
    if os.path.basename(command[0]) != "rm":
        return False
    recursive = any(
        word in ("--recursive", "-R") or re.match(r"^-[A-Za-z]*[rR]", word)
        for word in command[1:]
        if word.startswith("-")
    )
    targets = [word.rstrip("/*") for word in command[1:] if not word.startswith("-")]
    return recursive and any(
        directory == target or directory.startswith(target + "/") for target in targets
    )


def _cache_mounted(value: str, directory: str) -> bool:
    """Whether a ``RUN --mount=type=cache`` keeps ``directory`` out of the layer."""
    for mount in _CACHE_MOUNT.findall(value):
        for field in mount.split(","):
            key, _, target = field.partition("=")
            if key in ("target", "dst", "destination"):
                target = target.rstrip("/")
                if directory == target or directory.startswith(target + "/"):
                    return True
    return False


def package_problems(
    commands: Sequence[Sequence[str]], value: str
) -> list[tuple[str, str]]:
    """(command, problem) for the apt and apk commands of one RUN script.

    ``apt-get install`` pulls in every package its targets recommend unless
    it is told not to, so an image ships compilers' documentation, mail
    agents and X libraries nobody asked for, each with its own advisories.
    ``apt-get update`` writes the package lists, some tens of megabytes that
    are stale the day after: removed in a later instruction they are still
    in the layer that made them.
    """
    problems: list[tuple[str, str]] = []
    last = {"apt": -1, "apk": -1}  # the last command that wrote an index
    shown = {"apt": "", "apk": ""}
    cleaned = {"apt": -1, "apk": -1}
    for position, command in enumerate(commands):
        program = os.path.basename(command[0])
        text = " ".join(command)
        if program in _APT:
            action = _subcommand(command[1:], _APT_VALUE_OPTIONS)
            if (
                action in _APT_INSTALLS
                and "--no-install-recommends" not in command
                and not _NO_RECOMMENDS.search(text)
            ):
                problems.append(
                    (
                        text,
                        f"{program} {action} without --no-install-recommends "
                        "also installs every package the named ones recommend",
                    )
                )
            if action == "update":
                last["apt"], shown["apt"] = position, text
        elif program == "apk":
            action = _subcommand(command[1:], frozenset({"-X", "--repository"}))
            if action in ("add", "update", "upgrade") and "--no-cache" not in command:
                last["apk"], shown["apk"] = position, text
        if _removes(command, _APT_LISTS):
            cleaned["apt"] = position
        if _removes(command, _APK_CACHE):
            cleaned["apk"] = position
    if last["apt"] > cleaned["apt"] and not _cache_mounted(value, _APT_LISTS):
        problems.append(
            (
                shown["apt"],
                f"leaves the package lists in the layer; end the same RUN with "
                f"`rm -rf {_APT_LISTS}/*`",
            )
        )
    if last["apk"] > cleaned["apk"] and not _cache_mounted(value, _APK_CACHE):
        problems.append(
            (
                shown["apk"],
                "leaves the package index in the layer; use `apk add --no-cache`",
            )
        )
    return problems


_URL = re.compile(r"https?://[^\s\"'\\)<>|;&]+")
_LOCAL_URL = re.compile(r"https?://(localhost|127\.\d+\.\d+\.\d+|\[::1\])([:/]|$)")
_INTERPRETERS = r"(?:(?:ba|z|da|a|k)?sh|python[\d.]*|perl|ruby|node)"
_PIPE_TO_SHELL = re.compile(
    rf"\b(curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?{_INTERPRETERS}\b"
    r"|(?:\$\(|<\(|`)\s*(?:curl|wget)\b"
)
_VERIFIED = re.compile(
    r"\bsha(?:256|384|512)sum\b[^|;&\n]*\s(?:-c|--check)\b"
    r"|\bshasum\b[^|;&\n]*\s(?:-c|--check)\b"
    r"|\bgpgv?\b[^|;&\n]*--verify\b|\bgpgv\s"
    r"|\bcosign\s+verify"
)
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_ARG_REFERENCE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def check_dockerfile(path: str, text: str) -> list[Finding]:
    """Findings for one Dockerfile."""
    findings: list[Finding] = []
    stages: set[str] = set()
    arguments: dict[str, str] = {}

    def add(rule: str, instruction: Instruction, subject: str, message: str) -> None:
        findings.append(Finding(rule, path, subject, message, instruction.line))

    def expand(value: str) -> str:
        return _ARG_REFERENCE.sub(
            lambda m: arguments.get(m.group(1), m.group(0)), expand_defaults(value)
        )

    for instruction in parse_dockerfile(text):
        keyword, value = instruction.keyword, instruction.value

        if keyword == "ARG":
            name, equals, default = value.partition("=")
            if equals:
                arguments[name.strip()] = default.strip().strip("\"'")

        elif keyword == "FROM":
            words = [word for word in value.split() if not word.startswith("--")]
            reference = expand(words[0]) if words else ""
            if len(words) >= 3 and words[1].upper() == "AS":
                alias = words[2].lower()
            else:
                alias = ""
            if reference.lower() not in stages | {"scratch"}:
                if "$" in reference:
                    add(
                        "base-image",
                        instruction,
                        words[0],
                        f"FROM {words[0]} comes from a build argument with no "
                        "default, so it cannot be verified",
                    )
                elif not _DIGEST.search(reference):
                    add(
                        "base-image",
                        instruction,
                        reference,
                        f"FROM {reference} is not pinned by digest (@sha256:...), so "
                        "the same commit builds on whatever the tag points to",
                    )
            if alias:
                stages.add(alias)

        elif keyword in ("COPY", "ADD"):
            for word in value.split():
                source = word.partition("=")[2] if word.startswith("--from=") else ""
                if (
                    source
                    and re.search(r"[/:@]", source)
                    and not _DIGEST.search(expand(source))
                ):
                    add(
                        "base-image",
                        instruction,
                        source,
                        f"{keyword} --from={source} copies from an image that is "
                        "not pinned by digest",
                    )
            if keyword == "ADD" and "--checksum=" not in value:
                for url in _URL.findall(value):
                    add(
                        "download",
                        instruction,
                        url,
                        f"ADD {url} has no --checksum=sha256:..., so the build "
                        "takes whatever the URL serves",
                    )

        elif keyword == "RUN":
            script = run_script(value)
            if _PIPE_TO_SHELL.search(script):
                add(
                    "pipe-to-shell",
                    instruction,
                    "RUN",
                    "feeds a download straight to an interpreter or to the "
                    "command line; download a named version to a file and check "
                    "its SHA-256 first",
                )
            verified = bool(_VERIFIED.search(script))
            commands = shell_commands(script)
            for shown, problem in package_problems(commands, value):
                add("os-packages", instruction, shown, problem)
            for command in commands:
                shown = " ".join(command)
                pip = pip_arguments(command)
                if pip is not None:
                    problem = pip_problem(pip)
                    if problem:
                        add("pip", instruction, shown, problem)
                    continue
                problem = npm_problem(command)
                if problem:
                    add("npm", instruction, shown, problem)
                    continue
                if os.path.basename(command[0]) in ("curl", "wget") and not verified:
                    for url in _URL.findall(shown):
                        if not _LOCAL_URL.match(url):
                            add(
                                "download",
                                instruction,
                                url,
                                f"downloads {url} and nothing in the same RUN "
                                "checks it (sha256sum -c); a URL that names a "
                                "version can still serve other bytes",
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
) -> tuple[list[Finding], list[str], int, int]:
    """Check every Compose file and Dockerfile among ``files``.

    Returns (findings, files that could not be read, number of Compose files,
    number of Dockerfiles).
    """
    findings: list[Finding] = []
    unreadable: list[str] = []
    compose_files = 0
    dockerfiles = 0
    for path in sorted(files):
        if is_dockerfile(path):
            try:
                text = (root / path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                unreadable.append(f"{path}: cannot be read: {exc}")
                continue
            dockerfiles += 1
            findings.extend(check_dockerfile(path, text))
            continue
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
    return findings, unreadable, compose_files, dockerfiles


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
    findings, unreadable, compose_files, dockerfiles = check_tree(
        root, tracked_files(root)
    )
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
    if dockerfiles == 0:
        problems.append("no Dockerfile found: the check would pass on anything")

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
        f"OK: {compose_files} Compose file(s) and {dockerfiles} Dockerfile(s) "
        f"checked, {len(findings) - len(remaining)} finding(s) allow-listed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
