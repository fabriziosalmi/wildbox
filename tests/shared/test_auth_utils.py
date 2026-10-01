"""JWT helpers in open_security_shared.auth_utils.

auth_utils moved from python-jose to PyJWT: python-jose pulls in ecdsa, whose
timing advisory (CVE-2024-23342) upstream will not fix, and it was pinned in
three services only to satisfy this module. These tests hold the behaviour
that has to survive the switch: a token round-trips, and every way of
presenting a bad one ends in the same 401.
"""

import base64
import json
from datetime import timedelta

import pytest
from fastapi import HTTPException

from open_security_shared.auth_utils import create_access_token, verify_access_token

SECRET = "s" * 40
OTHER = "o" * 40


def _expect_401(token, secret=SECRET, algorithm="HS256"):
    with pytest.raises(HTTPException) as exc:
        verify_access_token(token, secret, algorithm)
    assert exc.value.status_code == 401
    assert exc.value.headers == {"WWW-Authenticate": "Bearer"}


def _b64(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_a_token_round_trips():
    token = create_access_token({"sub": "user-1", "team": "t1"}, SECRET)
    assert isinstance(token, str)
    payload = verify_access_token(token, SECRET)
    assert payload["sub"] == "user-1"
    assert payload["team"] == "t1"
    assert payload["exp"] > payload["iat"]


def test_the_caller_payload_is_not_mutated():
    data = {"sub": "user-1"}
    create_access_token(data, SECRET)
    assert data == {"sub": "user-1"}


def test_an_expired_token_is_refused():
    token = create_access_token({"sub": "u"}, SECRET, expires_delta=timedelta(seconds=-5))
    _expect_401(token)


def test_a_token_signed_with_another_key_is_refused():
    _expect_401(create_access_token({"sub": "u"}, OTHER))


def test_a_token_for_another_algorithm_is_refused():
    token = create_access_token({"sub": "u"}, SECRET, algorithm="HS512")
    _expect_401(token, algorithm="HS256")


def test_an_unsigned_token_is_refused():
    token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'admin'})}."
    _expect_401(token)


def test_a_tampered_payload_is_refused():
    header, _, signature = create_access_token({"sub": "u"}, SECRET).split(".")
    forged = f"{header}.{_b64({'sub': 'admin', 'exp': 4102444800})}.{signature}"
    _expect_401(forged)


def test_garbage_is_refused():
    _expect_401("not-a-jwt")
