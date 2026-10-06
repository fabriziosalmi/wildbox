"""The dashboard guards the pages it has and configures what it uses (#665).

Three things in ``open-security-dashboard`` described an application that is
not there:

- ``src/proxy.ts`` listed ``/endpoints`` among the routes that need a
  session, and in its matcher; no page exists for it.
- ``next.config.js`` rewrote ``/api/proxy/*`` to ``API_BASE_URL``, which
  nothing sets, and answered every ``/api/*`` route with
  ``Access-Control-Allow-Origin`` for ``CORS_ORIGIN`` (nothing sets it:
  ``http://localhost:3000``) and ``Access-Control-Allow-Credentials``.
- It exposed ``CUSTOM_KEY``, which no code read.

These tests read the two files. A route the guard names has a page; the
configuration has no rewrite, sends no CORS header and reads no variable but
the ones the application documents.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DASHBOARD = REPO / "open-security-dashboard"
PROXY = DASHBOARD / "src" / "proxy.ts"
APP = DASHBOARD / "src" / "app"
NEXT_CONFIG = DASHBOARD / "next.config.js"


def without_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def array(name: str, text: str) -> list:
    """The string literals of ``const <name> = [...]`` or ``<name>: [...]``."""
    match = re.search(rf"\b{name}\b\s*[:=]\s*\[(.*?)\]", text, re.S)
    assert match, f"{name} not found in src/proxy.ts"
    return re.findall(r"'([^']+)'", match.group(1))


def has_page(route: str) -> bool:
    return (APP / route.strip("/")).is_dir()


def test_the_arrays_of_the_guard_are_read():
    text = without_comments(PROXY.read_text(encoding="utf-8"))
    protected = array("protectedRoutes", text)
    assert "/dashboard" in protected and "/settings" in protected
    assert "/admin" in array("adminRoutes", text)
    assert "/dashboard/:path*" in array("matcher", text)


def test_every_guarded_route_has_a_page():
    text = without_comments(PROXY.read_text(encoding="utf-8"))
    guarded = array("protectedRoutes", text) + array("adminRoutes", text)
    missing = [route for route in guarded if not has_page(route)]
    assert missing == [], f"src/proxy.ts guards {missing}, which have no page"


def test_every_matched_path_has_a_page_and_is_guarded():
    text = without_comments(PROXY.read_text(encoding="utf-8"))
    guarded = set(array("protectedRoutes", text) + array("adminRoutes", text))
    matched = {entry.split("/:", 1)[0] for entry in array("matcher", text)}
    assert [route for route in sorted(matched) if not has_page(route)] == []
    # The guard runs only on what the matcher selects, and decides only for
    # what the two lists name: the two have to agree.
    assert matched == guarded


def test_the_configuration_rewrites_nothing_and_sends_no_cors_header():
    config = without_comments(NEXT_CONFIG.read_text(encoding="utf-8"))
    assert "rewrites" not in config
    assert "/api/proxy" not in config
    assert "access-control" not in config.lower()


def test_the_configuration_reads_only_the_variables_the_application_documents():
    config = without_comments(NEXT_CONFIG.read_text(encoding="utf-8"))
    read = set(re.findall(r"process\.env\.([A-Z0-9_]+)", config))
    assert read == {"NODE_ENV", "NEXT_PUBLIC_GATEWAY_URL"}
    documented = (DASHBOARD / ".env.example").read_text(encoding="utf-8")
    assert "NEXT_PUBLIC_GATEWAY_URL=" in documented
