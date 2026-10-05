"""A client can follow guardian's pagination links through the gateway (#643).

Lists of more than one page answered ``next`` and ``previous`` links such as
``https://open-security-guardian/api/v1/assets/assets/?page=2``: the Host the
gateway presents guardian, without the gateway's ``/api/v1/guardian`` path.
No client could follow them, and they named an internal container.

An account is registered here, the owner of its own team, and stores 51
assets: one more than a page. The test then walks the list the way a client
does -- request, resolve ``next`` against the URL it requested, request
again -- and back with ``previous``. It also sends the headers a client
might try to steer the links with; the gateway replaces or ignores each, so
the links do not change.

The account is registered directly at identity, as test_guardian_tenancy.py
does; every other request goes through the gateway.
"""

import os
import secrets
import time
import uuid
from urllib.parse import urljoin, urlsplit

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 15

# /api/v1/guardian/<x> on the gateway is /api/v1/<x> on guardian.
PREFIX = "/api/v1/guardian"
ASSETS_PATH = f"{PREFIX}/assets/assets/"
ASSETS = f"{GATEWAY_URL}{ASSETS_PATH}"

PAGE_SIZE = 50
ROWS = PAGE_SIZE + 1

# The gateway allows one address 100 requests a second with a burst of 10
# (limit_req zone=global, nginx.conf) and answers 429 beyond it. Storing and
# removing the rows is a hundred requests in a row, and against a fast stack
# they come closer than 10 ms apart, so the fixture spaces them out.
SPACING_SECONDS = 0.025

# What a client could send to move the links elsewhere. The gateway sets
# X-Forwarded-Host, X-Forwarded-Proto and X-Forwarded-Prefix itself, nginx
# drops a header name with an underscore, and guardian reads none of the
# others.
FORGED = {
    "X-Forwarded-Prefix": "/forged-prefix",
    "X-Forwarded-Host": "forged-host.example",
    "X-Forwarded-Proto": "gopher",
    "X-Forwarded-Port": "4443",
    "Forwarded": "host=forged-host.example;proto=gopher",
    "X-Script-Name": "/forged-prefix",
    "SCRIPT_NAME": "/forged-prefix",
    "X-Original-URL": "/forged-prefix/assets/",
    "X-Rewrite-URL": "/forged-prefix/assets/",
}


def _new_owner():
    """Bearer headers of a newly registered account: the owner of its team."""
    email = f"guardian-links-{secrets.token_hex(6)}@example.com"
    password = f"Guardian-Links-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.fixture(scope="module")
def owner():
    return _new_owner()


@pytest.fixture(scope="module")
def asset_ids(owner):
    """51 assets of the owner's team; removed afterwards.

    No ``ip_address``, so creating them queues no port scan.
    """
    tag = uuid.uuid4().hex[:10]
    ids = []
    try:
        for number in range(ROWS):
            time.sleep(SPACING_SECONDS)
            created = requests.post(
                ASSETS,
                json={
                    "name": f"it-links-{tag}-{number:02d}",
                    "asset_type": "server",
                    "hostname": "it-links.invalid",
                },
                headers=owner,
                timeout=TIMEOUT,
            )
            assert created.status_code == 201, created.text[:300]
            ids.append(created.json()["id"])
        yield set(ids)
    finally:
        for asset_id in ids:
            time.sleep(SPACING_SECONDS)
            requests.delete(f"{ASSETS}{asset_id}/", headers=owner, timeout=TIMEOUT)


def _get(url, headers):
    response = requests.get(url, headers=headers, timeout=TIMEOUT)
    assert response.status_code == 200, (url, response.text[:300])
    return response


def _assert_link(link, query):
    """A relative reference to the list under the gateway's path."""
    parts = urlsplit(link)
    assert (parts.scheme, parts.netloc) == ("", ""), link
    assert parts.path == ASSETS_PATH, link
    assert parts.query == query, link


def _assert_nothing_internal(response):
    assert "open-security-guardian" not in response.text, response.text[:300]
    assert "forged" not in response.text, response.text[:300]


@pytest.mark.parametrize("extra", [{}, FORGED], ids=["plain", "forged-headers"])
def test_next_and_previous_can_be_followed(owner, asset_ids, extra):
    headers = {**owner, **extra}
    first = _get(f"{ASSETS}?ordering=name", headers)
    page = first.json()

    assert page["count"] == ROWS
    assert len(page["results"]) == PAGE_SIZE
    assert page["previous"] is None
    _assert_link(page["next"], "ordering=name&page=2")
    _assert_nothing_internal(first)

    # Followed as a client follows any relative reference.
    second = _get(urljoin(first.url, page["next"]), headers)
    last = second.json()

    assert last["next"] is None
    assert len(last["results"]) == ROWS - PAGE_SIZE
    _assert_link(last["previous"], "ordering=name")
    _assert_nothing_internal(second)

    seen = {row["id"] for row in page["results"]} | {
        row["id"] for row in last["results"]
    }
    assert seen == asset_ids

    back = _get(urljoin(second.url, last["previous"]), headers)
    assert [row["id"] for row in back.json()["results"]] == [
        row["id"] for row in page["results"]
    ]


def test_the_host_a_client_names_is_not_written_into_the_links(owner, asset_ids):
    """The gateway answers for any Host; guardian's links carry none."""
    response = _get(ASSETS, {**owner, "Host": "forged-host.example"})

    _assert_link(response.json()["next"], "page=2")
    _assert_nothing_internal(response)
