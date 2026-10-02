"""Unit tests for the opt-in security layer (app.security_integration).

SECURITY_CONTROLS_ENABLED=true used to load a SecureCredentialManager that
imported ``keyring`` (not in the lock) and wanted an ENCRYPTION_KEY nothing
supplied. The ImportError was caught and the whole layer was switched off, so
the SSRF validator and the authorization manager never ran (#540). These
tests pin that enabling the layer loads both, with no ENCRYPTION_KEY, and that
API keys still come from the environment.
"""

import os
import sys

import pytest

# Importing app.security pulls in app.config (Settings), whose API_KEY must be
# >=32 chars with no weak words ("test"/"key"/...). Provide a valid stand-in.
STAND_IN_API_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # pragma: allowlist secret
os.environ.setdefault("API_KEY", STAND_IN_API_KEY)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.security_integration import SecurityIntegration  # noqa: E402


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("SECURITY_CONTROLS_ENABLED", "true")
    monkeypatch.setenv("SECURITY_STRICT_MODE", "false")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    return SecurityIntegration()


def test_enabling_loads_validator_and_authorization_without_encryption_key(enabled):
    assert enabled.security_enabled is True
    assert enabled.validator is not None
    assert enabled.authorization_manager is not None


def test_strict_mode_initialises_without_encryption_key(monkeypatch):
    monkeypatch.setenv("SECURITY_CONTROLS_ENABLED", "true")
    monkeypatch.setenv("SECURITY_STRICT_MODE", "true")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    integration = SecurityIntegration()
    assert integration.security_enabled is True
    assert integration.strict_mode is True


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SECURITY_CONTROLS_ENABLED", raising=False)
    integration = SecurityIntegration()
    assert integration.security_enabled is False
    assert integration.validator is None


@pytest.mark.parametrize("flag", ["true", "false"])
def test_api_key_comes_from_environment(monkeypatch, flag):
    monkeypatch.setenv("SECURITY_CONTROLS_ENABLED", flag)
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-value-from-env")
    integration = SecurityIntegration()
    assert integration.get_api_key("shodan") == "shodan-value-from-env"
    assert integration.get_api_key("SHODAN") == "shodan-value-from-env"


def test_api_key_unset_or_unknown_service_is_none(enabled, monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    assert enabled.get_api_key("virustotal") is None
    assert enabled.get_api_key("no-such-service") is None
