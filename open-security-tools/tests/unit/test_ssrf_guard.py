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


# The cases above use http://, which the dangerous-pattern check refuses on its
# own, so they never reach the host check. Over https:// the host check is the
# only guard: a private address used to pass because the "private" error was
# raised inside the try whose except branch treated it as "not an IP literal".
@pytest.mark.parametrize("url", [
    "https://10.0.0.5/",
    "https://192.168.1.10:8443/x",
    "https://127.0.0.1/admin",
    "https://169.254.169.254/latest/meta-data/",
    "https://0.0.0.0:8000/",
    "https://[::]/",
    "https://[::1]/",
    "https://localhost/",
    "https://100.64.0.1/",  # shared address space (carrier-grade NAT)
    "https://224.0.0.1/",  # multicast
    "https://[::ffff:10.0.0.1]/",  # IPv4-mapped private address
    "https://[fd00::1]/",  # unique local IPv6
])
def test_private_and_local_hosts_blocked_over_https(url):
    with pytest.raises(ValueError, match="(Private/local IP|Local hostnames)"):
        SecurityValidator.validate_url(url)


def test_private_hosts_pass_when_explicitly_allowed():
    url = "https://10.0.0.5/"
    assert SecurityValidator.validate_url(url, allow_private=True) == url


@pytest.mark.parametrize("url", [
    "https://8.8.8.8/",
    "https://[2606:4700:4700::1111]/",
    "https://example.com/",
])
def test_public_hosts_pass_over_https(url):
    assert SecurityValidator.validate_url(url) == url
