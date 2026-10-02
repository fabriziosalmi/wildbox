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


# The host check is the only guard for these: a private address used to pass
# because the "private" error was raised inside the try whose except branch
# treated it as "not an IP literal". (Before #561 the http:// cases above were
# refused by a pattern match on the scheme and never reached the host check.)
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


# --- #561: URLs are validated by parsing, not by pattern matching ----------
#
# The generic injection patterns used to run over the whole URL and refused
# ordinary targets. Most URLs below were refused before the fix.
@pytest.mark.parametrize("url", [
    "http://example.com/",                      # matched "http://"
    "https://shop.example.com/",                # matched "sh"
    "https://example.com/item?id=1",            # matched "=" (LDAP pattern)
    "https://example.com/a&b",                  # matched "&"
    "https://example.com/",
    "http://example.com/page?id=1&name=x",      # http with a query string
    "http://testphp.vulnweb.com/artists.php?artist=1",
    "https://example.com/search?q=(a|b)*!",     # LDAP metacharacters in a query
    "https://bash.example.com/curl/nc",         # command names as labels/paths
    "https://example.com:8443/path#frag",
    "https://Example.COM./",                    # trailing dot, mixed case
    "https://my_service.example.com/",          # underscore in a label
    "https://bücher.example/",             # internationalized name
    "https://xn--bcher-kva.example/",           # its punycode form
    "https://8.8.8.8:443/?x=1",
    "https://[2606:4700:4700::1111]:8443/",
])
def test_ordinary_urls_are_accepted(url):
    assert SecurityValidator.validate_url(url) == url


@pytest.mark.parametrize("url", [
    "https://user:pass@example.com/",
    "https://user@example.com/",
    "https://example.com@127.0.0.1/",
    "https://@example.com/",
])
def test_user_info_is_refused(url):
    with pytest.raises(ValueError, match="user info"):
        SecurityValidator.validate_url(url)


@pytest.mark.parametrize("url", [
    "https://example.com/\r\nX-Injected: 1",
    "https://example.com/\n",
    "https://example.com/\ta",
    "https://example.com/\x00",
    "https://example.com/a b",
    " https://example.com/",
    "https://example.com/\x7f",
    "https://example.com/​",               # zero-width space (format char)
    "https://example.com/ ",               # line separator
    "https://exa mple.com/",               # no-break space
])
def test_control_characters_and_whitespace_are_refused(url):
    with pytest.raises(ValueError, match="whitespace or control"):
        SecurityValidator.validate_url(url)


@pytest.mark.parametrize("url", [
    "https://example.com:0/",
    "https://example.com:65536/",
    "https://example.com:99999/",
    "https://example.com:abc/",
    "https://example.com:+80/",
    "https://example.com:-1/",
    "https://example.com:١٢/",        # non-ASCII digits
])
def test_bad_ports_are_refused(url):
    with pytest.raises(ValueError, match="port"):
        SecurityValidator.validate_url(url)


@pytest.mark.parametrize("url", ["https://example.com:1/", "https://example.com:65535/"])
def test_port_range_bounds_are_accepted(url):
    assert SecurityValidator.validate_url(url) == url


# Spellings that ipaddress refuses to parse but URL parsers, inet_aton and
# HTTP clients read as an IPv4 address. All of these mean 127.0.0.1 (or
# another non-public address); they are refused even with allow_private,
# because no component should have to guess which address they mean.
@pytest.mark.parametrize("url", [
    "http://2130706433/",          # decimal
    "http://0x7f000001/",          # hex
    "http://0X7F000001/",
    "http://017700000001/",        # octal
    "http://127.1/",               # short form
    "http://127.0.1/",
    "http://0x7f.0.0.1/",          # mixed hex part
    "http://0177.0.0.1/",          # octal part
    "http://127.000.000.001/",     # leading zeros
    "http://0/",                   # 0.0.0.0
    "http://0x/",
    "http://10.1/",                # private, short form
    "http://3232235777/",          # 192.168.1.1 in decimal
    "http://256.0.0.1/",           # out of range
    "http://1.2.3.4.5/",           # too many parts
    "http://example.123/",         # numeric last label
    "http://１２７．０．０．１/",  # fullwidth 127.0.0.1
])
@pytest.mark.parametrize("allow_private", [False, True])
def test_non_canonical_ipv4_spellings_are_refused(url, allow_private):
    with pytest.raises(ValueError):
        SecurityValidator.validate_url(url, allow_private=allow_private)


@pytest.mark.parametrize("url", [
    "http://localhost./",
    "http://LOCALHOST/",
    "http://LocalHost.:8080/",
    "http://foo.localhost/",       # RFC 6761: *.localhost is loopback too
    "http://127.0.0.1./",          # trailing dot on an IP literal
    "http://127.0.0.1/",
    "http://10.0.0.5/?id=1",
    "http://172.16.0.1/",
    "http://192.168.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[fe80::1]/",
])
def test_local_and_private_hosts_are_refused(url):
    with pytest.raises(ValueError, match="(Private/local IP|Local hostnames)"):
        SecurityValidator.validate_url(url)


@pytest.mark.parametrize("url", [
    "http://exa\\mple.com/",       # backslash in the host
    "http://-example.com/",        # label starting with a hyphen
    "http://example..com/",        # empty label
    "http://localhost../",
    "http://" + "a" * 64 + ".com/",  # label longer than 63
    "http://⒈.example/",      # IDNA-disallowed code point
    "http://[127.0.0.1]/",         # brackets around a non-IPv6 host
    "http://[fe80::1%25eth0]/",    # IPv6 zone id
    "http://[2606:4700:4700::1111%25eth0]/",  # zone id on a public address
    "http://[::1/",                # unbalanced bracket
    "http:///path",                # no host
    "http://:80/",
    "https:example.com",
    "//example.com/",
    "example.com",
    "javascript:alert(1)",
    "HTTP://",
])
def test_malformed_hosts_are_refused(url):
    with pytest.raises(ValueError):
        SecurityValidator.validate_url(url)


@pytest.mark.parametrize("value", [None, 123, b"https://example.com/", ""])
def test_non_string_or_empty_is_refused(value):
    with pytest.raises(ValueError):
        SecurityValidator.validate_url(value)


def test_over_length_is_refused():
    url = "https://example.com/" + "a" * 2048
    with pytest.raises(ValueError, match="too long"):
        SecurityValidator.validate_url(url)


def test_upper_case_scheme_is_accepted():
    url = "HTTPS://example.com/"
    assert SecurityValidator.validate_url(url) == url


def test_allow_private_accepts_private_url_with_query():
    # security_integration calls the validator this way.
    url = "http://10.0.0.5:8080/item?id=1&x=(y)"
    assert SecurityValidator.validate_url(url, allow_private=True) == url


def test_allow_private_still_checks_structure():
    with pytest.raises(ValueError, match="user info"):
        SecurityValidator.validate_url("http://a:b@10.0.0.5/", allow_private=True)


def test_free_text_pattern_check_is_unchanged():
    # The generic patterns still apply to free-text fields.
    with pytest.raises(ValueError, match="dangerous"):
        SecurityValidator.validate_string("1 UNION SELECT password FROM users")
    with pytest.raises(ValueError, match="dangerous"):
        SecurityValidator.validate_string("see http://example.com/")
