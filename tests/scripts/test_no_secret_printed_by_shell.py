"""No shell that runs in a container prints a secret (#755, #758).

``open-security-responder/scripts/entrypoint.sh`` ran ``echo "Redis URL:
${REDIS_URL}"`` at every start. In the stack that URL is
``redis://:<REDIS_PASSWORD>@wildbox-redis:6379/2``, so the responder wrote the
Redis password to its container log each time it started. #758 took the
values a caller submits out of every log line and guards the Python sources;
a shell script is not Python, and its guard did not read this one.

This reads every piece of shell the repository runs:

* the tracked shell scripts (by extension or by their first line): the
  services' entrypoints and init scripts, the gateway's, and the operator's
  scripts, some of which the ``backup`` container runs;
* the ``RUN``, ``CMD``, ``ENTRYPOINT`` and ``HEALTHCHECK`` instructions of the
  tracked Dockerfiles;
* the ``command``, ``entrypoint`` and health check ``test`` of every service
  in the tracked Compose files.

and refuses, in each:

* a command that writes to standard output or standard error (``echo``,
  ``printf``, a here-document given to ``cat``) the value of a variable whose
  name says it holds a secret, or a URL that can carry one;
* ``set -x``, which writes every command with its expanded arguments.

Writing such a value to a file or a pipe is not printing it: ``echo
"$PGPASSWORD" > "$PGPASSFILE"`` is how a password file is made. Neither is
``${#NAME}`` (a length) nor ``${NAME:+set}`` (whether it is set).
"""

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]

# A variable whose value is a secret, or a URL that can hold a password.
SENSITIVE = re.compile(
    r"""
      (^|_)REDIS_URL$
    | (^|_)DATABASE_URL$
    | ^CELERY_BROKER_URL$
    | ^CELERY_RESULT_BACKEND$
    | (^|_)DSN$
    | SECRET
    | PASSWORD
    | PASSWD
    | (^|_)KEY$
    | TOKEN
    | _AUTH$
    | CREDENTIAL
    """,
    re.X,
)
# ${NAME...}, $NAME and, in a Compose file, $$NAME and $${NAME...}.
EXPANSION = re.compile(
    r"\$\$?(?:\{(#?)([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
WRITER = re.compile(r"(?<![\w./-])(echo|printf)(?![\w./-])")
XTRACE = re.compile(
    r"(?:^|[;&|]\s*|\s)set\s+(?:-[a-wyzA-Z]*x[a-zA-Z]*|-o\s+xtrace)\b|^#!.*\s-[a-wyz]*x"
)
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# What the rule finds and is not a secret reaching a log: (file, what) -> why.
ALLOWED = {
    ("open-security-gateway/scripts/docker-entrypoint.sh", "echo prints $KEY"): (
        "KEY is the path of the TLS key file, named in the warning that no "
        "certificate could be written; the script never reads the key"
    ),
    ("scripts/lib/db_access.sh", "printf prints $REDIS_PASSWORD"): (
        "wb_redis_password hands the password to its caller on standard "
        "output, and every caller captures it: password=$(wb_redis_password); "
        "test_the_redis_password_helper_is_always_captured holds them to it"
    ),
    ("scripts/rotate_secrets.sh", "echo prints $SECRET"): (
        "SECRET is the name of the secret given with --secret "
        "(JWT_SECRET_KEY, REDIS_PASSWORD...), never a value"
    ),
    ("scripts/rotate_secrets.sh", "here-document prints $SECRET"): (
        "SECRET is the name of the secret given with --secret, in the "
        "message that refuses a rotation; never a value"
    ),
}


def is_sensitive(name):
    return bool(SENSITIVE.search(name.upper()))


def strip_comment(line):
    """``line`` without a trailing shell comment (a # outside quotes)."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote and line[index - 1] != "\\":
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t;"):
            return line[:index]
    return line


def logical_lines(text):
    """(first line number, text) with backslash continuations joined."""
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        yield start, pending + line
        pending = ""
    if pending:
        yield start, pending


def command_at(line, start):
    """What one ``echo``/``printf`` at ``start`` expands, and where it writes.

    Returns (names expanded outside single quotes, to_stdout).
    """
    names, quote, depth, index = [], None, 0, start
    redirected = piped = False
    while index < len(line):
        char = line[index]
        if quote == "'":
            if char == "'":
                quote = None
        elif char == "\\":
            index += 1
        elif quote == '"' and char == '"':
            quote = None
        elif quote is None and char in "'\"":
            quote = char
        elif char == "$":
            match = EXPANSION.match(line, index)
            if match:
                length, name, rest = match.group(1), match.group(2), match.group(3)
                name = name or match.group(4)
                tests_only = bool(length) or (rest or "").startswith((":+", "+"))
                if not tests_only:
                    names.append(name)
                index = match.end() - 1
            elif line.startswith("$(", index):
                depth += 1
                index += 1
        elif quote is None:
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and char == ">":
                if not re.match(r">\s*&\s*[12]\b", line[index:]):
                    redirected = True
            elif depth == 0 and char == "|":
                piped = not line.startswith("||", index)
                break
            elif depth == 0 and (char == ";" or line.startswith("&&", index)):
                break
        index += 1
    return names, not (redirected or piped)


def inside_substitution(line, position):
    """Whether ``position`` is inside ``$( ... )`` or backticks: not standard output."""
    before = line[:position]
    return before.count("$(") > before.count(")") or before.count("`") % 2 == 1


def findings_in_shell(text):
    """[(line, what)] for each secret printed, or xtrace, in one piece of shell."""
    found = []
    heredoc = None  # (delimiter, expands, to_stdout)
    for number, raw in logical_lines(text):
        if heredoc:
            delimiter, expands, to_stdout = heredoc
            if raw.strip() == delimiter:
                heredoc = None
            elif expands and to_stdout:
                for match in EXPANSION.finditer(raw):
                    name = match.group(2) or match.group(4)
                    tests_only = bool(match.group(1)) or (
                        match.group(3) or ""
                    ).startswith((":+", "+"))
                    if is_sensitive(name) and not tests_only:
                        found.append((number, f"here-document prints ${name}"))
            continue
        line = strip_comment(raw)
        if XTRACE.search(raw if raw.startswith("#!") else line):
            found.append((number, "set -x"))
        for match in WRITER.finditer(line):
            if inside_substitution(line, match.start()):
                continue
            names, to_stdout = command_at(line, match.end())
            if to_stdout:
                for name in names:
                    if is_sensitive(name):
                        found.append((number, f"{match.group(1)} prints ${name}"))
        opened = HEREDOC.search(line)
        if opened and re.search(r"(?<![\w./-])cat(?![\w./-])", line[: opened.start()]):
            after = line[opened.end() :]
            to_stdout = not re.search(
                r"(?<![&\d])>(?!\s*&)|\|", after + line[: opened.start()]
            )
            heredoc = (opened.group(2), not opened.group(1), to_stdout)
        elif opened:
            heredoc = (opened.group(2), False, False)
    return found


def tracked(*patterns):
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", *patterns],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return sorted(name for name in listed.stdout.decode().split("\0") if name)


def shell_scripts():
    """Tracked files that are shell: by extension, or by their first line."""
    scripts = set(tracked("*.sh"))
    for name in tracked():
        path = ROOT / name
        if name in scripts or path.suffix or not path.is_file():
            continue
        try:
            first = path.open("rb").readline(80)
        except OSError:
            continue
        if re.match(rb"#!\s*/(usr/)?bin/(env\s+)?(ba|da|a)?sh\b", first):
            scripts.add(name)
    return sorted(scripts)


def dockerfile_shell(text):
    """(line, shell text) of each RUN, CMD, ENTRYPOINT and HEALTHCHECK."""
    for number, line in logical_lines(text):
        match = re.match(r"\s*(RUN|CMD|ENTRYPOINT|HEALTHCHECK)\s+(.*)", line, re.S)
        if not match:
            continue
        body = match.group(2).strip()
        body = re.sub(r"^(?:--[a-z-]+=\S+\s+)*(?:CMD\s+)?", "", body)
        if body.startswith("["):
            try:
                body = " ".join(str(part) for part in json.loads(body))
            except ValueError:
                pass
        yield number, body


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def compose_shell(text):
    """(service, key, shell text) of each command, entrypoint and health check."""
    document = yaml.load(text, Loader=_ComposeLoader) or {}  # noqa: S506
    for service, spec in (document.get("services") or {}).items():
        spec = spec or {}
        pieces = {
            "command": spec.get("command"),
            "entrypoint": spec.get("entrypoint"),
            "healthcheck": (spec.get("healthcheck") or {}).get("test"),
        }
        for key, value in pieces.items():
            if isinstance(value, list):
                value = " ".join(str(part) for part in value)
            if isinstance(value, str) and value.strip():
                yield service, key, value


def findings():
    """Every finding in the tree: {(file, where, what)}."""
    found = set()
    for name in shell_scripts():
        text = (ROOT / name).read_text(encoding="utf-8", errors="replace")
        for line, what in findings_in_shell(text):
            found.add((name, f"line {line}", what))
    for name in tracked("*Dockerfile*"):
        text = (ROOT / name).read_text(encoding="utf-8", errors="replace")
        for line, body in dockerfile_shell(text):
            for _, what in findings_in_shell(body):
                found.add((name, f"line {line}", what))
    for name in tracked("*docker-compose*.yml", "*docker-compose*.yaml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for service, key, body in compose_shell(text):
            for _, what in findings_in_shell(body):
                found.add((name, f"{service}.{key}", what))
    return found


# --- the check works -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "REDIS_URL",
        "IDENTITY_REDIS_URL",
        "DATABASE_URL",
        "GUARDIAN_DATABASE_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "SENTRY_DSN",
        "GATEWAY_INTERNAL_SECRET",
        "JWT_SECRET_KEY",
        "REDIS_PASSWORD",
        "PGPASSWORD",
        "API_KEY",
        "ANTHROPIC_API_KEY",
        "ACCESS_TOKEN",
        "REDISCLI_AUTH",
        "AWS_CREDENTIALS",
        "new_password",
    ],
)
def test_a_name_that_holds_a_secret_is_known(name):
    assert is_sensitive(name)


@pytest.mark.parametrize(
    "name",
    [
        "DEBUG",
        "ENVIRONMENT",
        "ANTHROPIC_MODEL",
        "WILDBOX_API_URL",
        "PORT",
        "KEYSPACE",
        "MONKEY",
        # The gateway's rate for its auth zone, a number.
        "AUTH",
    ],
)
def test_a_name_that_holds_none_is_not(name):
    assert not is_sensitive(name)


@pytest.mark.parametrize(
    "shell, what",
    [
        # The line this is about.
        ('echo "Redis URL: ${REDIS_URL}"', "echo prints $REDIS_URL"),
        ("printf '%s\\n' \"$REDIS_URL\"", "printf prints $REDIS_URL"),
        ("echo $DATABASE_URL", "echo prints $DATABASE_URL"),
        ('echo "key: ${API_KEY:-none}" >&2', "echo prints $API_KEY"),
        (
            'if true; then echo "secret=$GATEWAY_INTERNAL_SECRET"; fi',
            "echo prints $GATEWAY_INTERNAL_SECRET",
        ),
        (
            'ready && printf "%s" "${POSTGRES_PASSWORD:?required}"',
            "printf prints $POSTGRES_PASSWORD",
        ),
        # Compose escapes the dollar for the container's shell.
        ('sh -c "echo $$REDIS_PASSWORD"', "echo prints $REDIS_PASSWORD"),
        ("set -x", "set -x"),
        ("set -eux", "set -x"),
        ("set -o xtrace", "set -x"),
        ("#!/bin/sh -x", "set -x"),
    ],
)
def test_a_secret_printed_is_found(shell, what):
    assert [found for _, found in findings_in_shell(shell)] == [what]


def test_a_here_document_given_to_cat_is_found():
    shell = 'cat <<EOF\nconnecting to ${DATABASE_URL}\nEOF\necho "done"\n'

    assert findings_in_shell(shell) == [(2, "here-document prints $DATABASE_URL")]


@pytest.mark.parametrize(
    "shell",
    [
        # Other variables.
        'echo "Environment: ${ENVIRONMENT:-not set}"',
        'echo "Anthropic model: ${ANTHROPIC_MODEL:-claude}"',
        # Written to a file or a pipe, not printed.
        'echo "*:*:*:*:${PGPASSWORD}" > "$PGPASSFILE"',
        'printf "%s" "$REDIS_PASSWORD" >> /run/secret',
        'printf "%s" "$API_KEY" | sha256sum',
        # A length, or whether it is set.
        'echo "the key has ${#API_KEY} characters"',
        'echo "REDIS_PASSWORD is ${REDIS_PASSWORD:+set}"',
        # Its name, not its value.
        'echo "set REDIS_PASSWORD in .env"',
        "echo 'the value of $REDIS_PASSWORD is not expanded in single quotes'",
        'echo "REDIS_PASSWORD=\\$(openssl rand -hex 32)"',
        # Captured, not printed.
        'HASH=$(echo "$API_KEY" | sha256sum)',
        'HOST="$(printf "%s" "$DATABASE_URL" | cut -d@ -f2)"',
        # A comment.
        '# echo "$REDIS_URL"',
        "true  # set -x would print $REDIS_URL",
        # A here-document that does not expand, or goes to a file.
        "cat <<'EOF'\nexport REDIS_URL=${REDIS_URL}\nEOF",
        "cat > /tmp/pgpass <<EOF\n${PGPASSWORD}\nEOF",
        # set with other options.
        "set -e",
        "set -euo pipefail",
        "set +x",
    ],
)
def test_what_prints_no_secret_is_not_found(shell):
    assert findings_in_shell(shell) == []


def test_a_continued_line_is_one_command():
    shell = 'echo "starting" \\\n     "$REDIS_URL"\n'

    assert findings_in_shell(shell) == [(1, "echo prints $REDIS_URL")]


def test_the_instructions_of_a_dockerfile_are_read():
    text = (
        "FROM scratch\n"
        "RUN echo building\n"
        'HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || echo "$API_KEY"\n'
        'CMD ["sh", "-c", "echo $REDIS_URL && exec app"]\n'
        'ENTRYPOINT ["/app/scripts/entrypoint.sh"]\n'
    )

    found = [
        (line, what)
        for line, body in dockerfile_shell(text)
        for _, what in findings_in_shell(body)
    ]
    assert found == [(3, "echo prints $API_KEY"), (4, "echo prints $REDIS_URL")]


def test_the_commands_of_a_compose_file_are_read():
    text = (
        "services:\n"
        "  quiet:\n"
        "    command: redis-server --appendonly yes\n"
        "  loud:\n"
        '    command: sh -c "echo redis is at $$REDIS_URL && exec app"\n'
        '    entrypoint: ["sh", "-c", "printf \'%s\' ${POSTGRES_PASSWORD}"]\n'
        "    healthcheck:\n"
        '      test: ["CMD-SHELL", "redis-cli ping || echo $$REDISCLI_AUTH_TOKEN"]\n'
    )

    found = sorted(
        (service, key, what)
        for service, key, body in compose_shell(text)
        for _, what in findings_in_shell(body)
    )
    assert found == [
        ("loud", "command", "echo prints $REDIS_URL"),
        ("loud", "entrypoint", "printf prints $POSTGRES_PASSWORD"),
        ("loud", "healthcheck", "echo prints $REDISCLI_AUTH_TOKEN"),
    ]


def test_the_tree_is_read():
    scripts = shell_scripts()

    for name in (
        "open-security-responder/scripts/entrypoint.sh",
        "open-security-agents/scripts/entrypoint.sh",
        "open-security-gateway/scripts/docker-entrypoint.sh",
        "scripts/backup_postgres.sh",
        "scripts/rotate_secrets.sh",
    ):
        assert name in scripts, name
    assert "open-security-responder/Dockerfile" in tracked("*Dockerfile*")
    composes = tracked("*docker-compose*.yml", "*docker-compose*.yaml")
    assert {"docker-compose.yml", "docker-compose.prod.yml"} <= set(composes)
    commands = list(compose_shell((ROOT / "docker-compose.yml").read_text("utf-8")))
    assert any(key == "healthcheck" for _, key, _ in commands)
    assert any(key == "command" for _, key, _ in commands)


# --- the tree -------------------------------------------------------------------


def test_no_shell_prints_a_secret():
    found = {(name, what): where for name, where, what in findings()}
    unexpected = sorted(
        f"{name}: {where}: {what}"
        for (name, what), where in found.items()
        if (name, what) not in ALLOWED
    )

    assert unexpected == []


def test_the_redis_password_helper_is_always_captured():
    """``wb_redis_password`` prints the password: a call that is not inside
    ``$( ... )`` would put it on the caller's standard output."""
    calls = []
    for name in shell_scripts():
        text = (ROOT / name).read_text(encoding="utf-8", errors="replace")
        for number, line in logical_lines(text):
            line = strip_comment(line)
            for match in re.finditer(r"(?<![\w-])wb_redis_password(?![\w-])", line):
                if re.match(r"\s*wb_redis_password\s*\(\)", line):
                    continue  # its definition
                calls.append((name, number, inside_substitution(line, match.start())))

    assert len(calls) >= 2, calls
    assert [call for call in calls if not call[2]] == []


def test_the_responder_entrypoint_prints_no_url():
    """The line this guard was written for, and the one beside it."""
    text = (ROOT / "open-security-responder/scripts/entrypoint.sh").read_text("utf-8")
    code = "\n".join(strip_comment(line) for line in text.splitlines())

    assert "REDIS_URL" not in code
    assert "${DEBUG:-production}" not in code
    assert findings_in_shell(text) == []


def test_every_exception_listed_still_exists():
    present = {(name, what) for name, _, what in findings()}

    assert sorted(key for key in ALLOWED if key not in present) == []
    for reason in ALLOWED.values():
        assert (
            len(reason) > 40
        ), "an exception says why the value is not a secret in a log"


if __name__ == "__main__":
    for name, where, what in sorted(findings()):
        print(f"{name}: {where}: {what}")
