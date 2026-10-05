"""The tools service has no rate-limit setting (#646).

``RATE_LIMIT_REQUESTS`` and ``RATE_LIMIT_WINDOW`` were declared in
``app/config.py`` and set by ``docker-compose.yml``, and nothing enforced
them. The gateway limits requests per team, and every request reaches the
service through it, so the settings were removed instead of being enforced a
second time. These tests keep them from coming back as settings that do
nothing: in the service, in the compose file and in the example ``.env``
files an operator copies.
"""

import os
import re
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.config import Settings  # noqa: E402

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent

REMOVED = ("RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW", "ENABLE_RATE_LIMITING")

# The containers built from open-security-tools in docker-compose.yml.
TOOLS_SERVICES = ("api", "tools-worker", "tools-flower")


def test_the_service_declares_no_rate_limit_setting():
    assert [name for name in Settings.model_fields if "rate_limit" in name] == []


def test_a_rate_limit_variable_in_the_environment_changes_nothing(monkeypatch):
    # An operator's root .env may still carry the old lines. Compose no
    # longer passes them, and the service ignores them if something does.
    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW", "60")

    settings = Settings(_env_file=None)

    assert not hasattr(settings, "rate_limit_requests")
    assert not hasattr(settings, "rate_limit_window")


def test_a_dotenv_file_that_still_sets_one_stops_the_service(tmp_path):
    # The service refuses any key it does not declare in a .env file of its
    # working directory, so a stale line is reported, not silently dropped.
    dotenv = tmp_path / ".env"
    dotenv.write_text("RATE_LIMIT_REQUESTS=500\n", encoding="utf-8")

    with pytest.raises(ValueError) as refused:
        Settings(_env_file=str(dotenv))

    assert "rate_limit_requests" in str(refused.value)
    assert "Extra inputs are not permitted" in str(refused.value)


def _compose_environment(service):
    import yaml

    class Loader(yaml.SafeLoader):
        """Reads the compose merge tags (!override, !reset) as plain values."""

    def plain(loader, suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_scalar(node)

    Loader.add_multi_constructor("!", plain)

    names = set()
    for path in sorted(REPO_ROOT.glob("docker-compose*.yml")):
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader) or {}
        spec = (document.get("services") or {}).get(service) or {}
        environment = spec.get("environment") or []
        if isinstance(environment, dict):
            names.update(environment)
        else:
            names.update(str(entry).split("=", 1)[0] for entry in environment)
    return names


@pytest.mark.parametrize("service", TOOLS_SERVICES)
def test_compose_passes_no_rate_limit_variable_to_the_tools_containers(service):
    environment = _compose_environment(service)
    if not environment:
        pytest.skip("the compose files are not in this checkout")

    assert "API_KEY" in environment  # the block was found and parsed
    assert sorted(set(REMOVED) & environment) == []


@pytest.mark.parametrize(
    "example",
    [REPO_ROOT / ".env.example", SERVICE_ROOT / ".env.example"],
    ids=["root", "open-security-tools"],
)
def test_the_example_env_files_do_not_set_one(example):
    if not example.is_file():
        pytest.skip(f"{example} is not in this checkout")
    assigned = re.findall(r"^\s*#?\s*([A-Z0-9_]+)=", example.read_text("utf-8"), re.M)

    assert sorted(set(REMOVED) & set(assigned)) == []
