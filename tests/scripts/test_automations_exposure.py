"""How n8n, the optional automations service, can be reached (#714).

The gateway proxied /api/v1/automations/ to n8n's whole surface. n8n is a
single-tenant tool with accounts of its own behind a gateway that serves many
teams: every registered session passed, and on an instance whose owner
account did not exist yet the first caller could create it. The route is
gone. What is left is the port Compose publishes, which must stay on the
loopback interface, and n8n's own accounts.

N8N_BASIC_AUTH_ACTIVE, _USER and _PASSWORD were set everywhere and protected
nothing: n8n 1.x has no basic auth and ignores them. A setting that reads
like a lock and is not one is worse than none, so nothing may set them, ask
for them or generate them again.

These read the files; the gateway harness (open-security-gateway/test)
checks the route on the wire.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ROOT_COMPOSE = REPO / "docker-compose.yml"
PROD_COMPOSE = REPO / "docker-compose.prod.yml"
STANDALONE_COMPOSE = REPO / "open-security-automations" / "docker-compose.yml"

HYGIENE = REPO / "scripts" / "check_container_hygiene.py"
spec = importlib.util.spec_from_file_location("hygiene_for_automations", HYGIENE)
cch = importlib.util.module_from_spec(spec)
# dataclasses resolves string annotations through sys.modules.
sys.modules[spec.name] = cch
spec.loader.exec_module(cch)

# Every file that configures n8n, or produces or checks what configures it.
SETTINGS = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    ".env.example",
    "open-security-automations/docker-compose.yml",
    "open-security-automations/.env.example",
    "open-security-gateway/nginx/nginx.conf",
    "scripts/generate_secrets.py",
    "scripts/validate_secrets.py",
    "scripts/rotate_secrets.sh",
    "scripts/shell-scripts/security_validation_v2.sh",
)


def without_comments(text):
    """The text with whole-line comments and trailing ' # ...' removed."""
    lines = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(re.sub(r"\s+#.*$", "", line))
    return "\n".join(lines)


def service_block(text, name):
    """The lines of one service of a Compose file, comments removed."""
    block = []
    inside = False
    for line in without_comments(text).splitlines():
        if re.match(rf"^  {re.escape(name)}:\s*$", line):
            inside = True
            continue
        if inside and re.match(r"^  \S", line):
            break
        if inside and re.match(r"^\S", line):
            break
        if inside:
            block.append(line)
    assert block, f"service {name} not found"
    return "\n".join(block)


def published_ports(block):
    """The entries of a service's `ports:` list."""
    match = re.search(r"^    ports:\s*\n((?:      - .*\n?)+)", block, re.MULTILINE)
    if not match:
        return []
    return [
        entry.strip()[2:].strip().strip("\"'") for entry in match.group(1).splitlines()
    ]


@pytest.mark.parametrize(
    "path, service",
    [(ROOT_COMPOSE, "automations"), (STANDALONE_COMPOSE, "n8n")],
)
def test_n8n_is_published_on_the_loopback_interface_only(path, service):
    ports = published_ports(service_block(path.read_text(), service))

    assert ports == ["127.0.0.1:5678:5678"]


def test_the_production_overlay_publishes_nothing_more_for_n8n():
    block = service_block(PROD_COMPOSE.read_text(), "automations")

    assert "ports:" not in block


def test_the_hygiene_guard_refuses_n8n_on_every_interface():
    """The guard that runs in CI is what keeps the port where it is."""
    text = ROOT_COMPOSE.read_text()
    assert text.count('- "127.0.0.1:5678:5678"') == 1

    def about_n8n(compose):
        return [
            finding
            for finding in cch.check_compose("docker-compose.yml", compose)
            if "5678" in finding.render()
        ]

    assert about_n8n(text) == []
    exposed = about_n8n(text.replace('- "127.0.0.1:5678:5678"', '- "5678:5678"'))
    assert exposed, "publishing n8n on every interface is not a finding"
    assert "automations" in exposed[0].render()
    # And it is not excused in advance.
    allowlist = (REPO / "scripts" / "container_hygiene_allowlist.txt").read_text()
    assert "5678" not in allowlist and "automations" not in allowlist


@pytest.mark.parametrize("relative", SETTINGS)
def test_nothing_sets_or_asks_for_the_basic_auth_n8n_ignores(relative):
    path = REPO / relative
    assert path.exists(), relative

    assert "N8N_BASIC_AUTH" not in without_comments(path.read_text())


def test_no_traefik_route_is_declared_for_n8n():
    """A label is all a Traefik on the same Docker host needs to publish it."""
    for path in (ROOT_COMPOSE, PROD_COMPOSE, STANDALONE_COMPOSE):
        assert "traefik" not in without_comments(path.read_text()).lower(), path.name


def test_the_readme_says_to_create_the_owner_account():
    readme = (REPO / "open-security-automations" / "README.md").read_text()

    assert "/setup" in readme
    assert "showSetupOnFirstLoad" in readme
    assert "127.0.0.1:5678" in readme
