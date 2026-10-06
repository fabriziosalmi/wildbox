"""The gateway's plain-HTTP listeners redirect to a name of its own (#788).

Ports 80 and 8080 answer ``/health`` and send everything else to HTTPS. They
sent it to ``$server_name``, the first name of their ``server_name`` line,
whatever name the client had called: ``http://wildbox.local/`` led to
``https://api.wildbox.local/``.

The redirect now keeps the client's name when it is one of the gateway's,
through a ``map`` of ``$host`` that lists them, and falls back to the first
name for every other Host. The fallback matters as much as the fix: each of
those servers is the only one on its port, so it answers for any Host, and
a redirect to ``$host`` as it came would send a client wherever the header
says.

What the running gateway answers is asked by
``open-security-gateway/test/redirect_tests.sh``. This is the part that can
drift without a request failing: the names are written twice, in the map
and in each ``server_name``, and a name added to one only would fall back
to the first name without a word. The files are read; nothing is started.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = ROOT / "open-security-gateway" / "nginx" / "conf.d" / "wildbox_gateway.conf"
VARIABLE = "$https_redirect_host"


def code(text):
    """An nginx file without its comment lines."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def blocks(text, opening):
    """The body of every top-level block of ``text`` that ``opening`` starts."""
    found = []
    for match in re.finditer(opening, text, re.M):
        depth, start = 1, match.end()
        position = start
        while depth:
            position = min(
                index
                for index in (text.find("{", position), text.find("}", position))
                if index != -1
            )
            depth += 1 if text[position] == "{" else -1
            position += 1
        found.append(text[start : position - 1])
    return found


def redirect_map(text):
    """{name: value} of the map the redirects read, and its other lines."""
    (body,) = blocks(text, rf"^map \$host {re.escape(VARIABLE)} \{{")
    entries, others = {}, []
    for line in filter(None, (line.strip() for line in body.splitlines())):
        words = line.rstrip(";").split()
        if len(words) == 2:
            entries[words[0]] = words[1]
        else:
            others.append(line)
    return entries, others


def plain_http_servers(text):
    """(ports, names, redirect targets) of each server that listens without TLS
    and redirects."""
    servers = []
    for body in blocks(text, r"^server \{"):
        listens = re.findall(r"^\s*listen\s+([^;]+);", body, re.M)
        targets = re.findall(r"^\s*return 30\d\s+(\S+);", body, re.M)
        if not targets or any("ssl" in listen for listen in listens):
            continue
        names = re.search(r"^\s*server_name\s+([^;]+);", body, re.M).group(1).split()
        servers.append((listens, names, targets))
    return servers


def test_the_blocks_are_read():
    sample = (
        "map $host $https_redirect_host {\n"
        "    hostnames;\n"
        "    default  $server_name;\n"
        "    a.test   $host;\n"
        "}\n"
        "server {\n"
        "    listen 80;\n"
        "    server_name a.test b.test;\n"
        "    location /health {\n"
        "        return 200 '{}';\n"
        "    }\n"
        "    location / {\n"
        "        return 301 https://$https_redirect_host$request_uri;\n"
        "    }\n"
        "}\n"
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name a.test;\n"
        "    location / {\n"
        "        return 301 /elsewhere;\n"
        "    }\n"
        "}\n"
    )
    servers = plain_http_servers(sample)

    assert redirect_map(sample) == (
        {"default": "$server_name", "a.test": "$host"},
        ["hostnames;"],
    )
    assert servers == [
        (
            ["80"],
            ["a.test", "b.test"],
            ["https://$https_redirect_host$request_uri"],
        )
    ]


def test_the_two_plain_http_listeners_redirect_through_the_map():
    servers = plain_http_servers(code(CONF.read_text()))

    assert [listens for listens, _, _ in servers] == [["80"], ["8080"]]
    for listens, _, targets in servers:
        assert targets == [f"https://{VARIABLE}$request_uri"], listens


def test_no_redirect_is_built_from_the_host_header_as_it_came():
    """``https://$host...`` on a server that answers for every Host is a
    redirect to wherever the request says."""
    text = code(CONF.read_text())

    for target in re.findall(r"^\s*return 30\d\s+(\S+);", text, re.M):
        assert "$host" not in target and "$http_host" not in target, target


def test_the_map_keeps_the_gateways_names_and_no_other():
    text = code(CONF.read_text())
    entries, others = redirect_map(text)

    # Wildcards are matched as server_name matches them.
    assert others == ["hostnames;"]
    # Any other Host: the first name of the server that answers.
    assert entries.pop("default") == "$server_name"
    # A name of the gateway: the name the client called.
    assert set(entries.values()) == {"$host"}
    for listens, names, _ in plain_http_servers(text):
        assert set(entries) == set(names), listens


def test_the_map_lists_no_name_that_matches_every_host():
    """A catch-all entry would undo the fallback."""
    entries, _ = redirect_map(code(CONF.read_text()))

    for name in set(entries) - {"default"}:
        assert not name.startswith("~"), name
        assert name.strip("*.") and "." in name.strip("*."), name
