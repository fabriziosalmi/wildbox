"""Unit tests for the central SSRF guard (SecurityValidator.validate_url).

Pure-logic, no service/DB needed. Locks in that the tools service rejects
private/loopback hosts and non-http(s) schemes so a crafted target can't make
a tool reach internal infrastructure.
"""
import os
import sys

import pytest

# Importing the validator pulls in app.config (Settings), whose API_KEY must be
# >=32 chars with no weak words ("test"/"key"/...). Provide a valid stand-in.
os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.security.validator import SecurityValidator  # noqa: E402


@pytest.mark.parametrize("url", [
    "https://example.com",
    "https://sub.domain.example.org:8443/x",
])
def test_public_urls_pass(url):
    assert SecurityValidator.validate_url(url) == url


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin",       # loopback
    "http://192.168.1.10",          # private
    "http://10.0.0.5",              # private
    "http://169.254.169.254/",      # link-local (cloud metadata)
    "http://localhost:8000",        # local hostname
])
def test_private_and_local_hosts_blocked(url):
    with pytest.raises(ValueError):
        SecurityValidator.validate_url(url)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com",
    "gopher://example.com",
    "",
])
def test_bad_schemes_and_empty_blocked(url):
    with pytest.raises(ValueError):
        SecurityValidator.validate_url(url)
