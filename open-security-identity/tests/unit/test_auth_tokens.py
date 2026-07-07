"""Unit tests for token/credential helpers in app/auth.py.

Pure-logic, no DB needed - the existing tests/test_basic.py exercises full
HTTP+Postgres flows and can't run in the unit-test matrix job (no DB
service there), so this file covers the underlying JWT/API-key/password
logic directly instead, per the migration guidance in #245.
"""
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import HTTPException  # noqa: E402

from app.auth import (  # noqa: E402
    create_access_token,
    generate_api_key,
    get_password_hash,
    hash_api_key,
    verify_access_token,
    verify_password,
)


def test_password_hash_roundtrip():
    hashed = get_password_hash("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed) is True


def test_password_hash_rejects_wrong_password():
    hashed = get_password_hash("correct horse battery staple")
    assert verify_password("wrong password", hashed) is False


def test_password_hash_is_not_plaintext():
    password = "correct horse battery staple"
    assert get_password_hash(password) != password


def test_hash_api_key_is_deterministic():
    assert hash_api_key("wsk_abcd.deadbeef") == hash_api_key("wsk_abcd.deadbeef")


def test_hash_api_key_differs_per_key():
    assert hash_api_key("wsk_abcd.aaa") != hash_api_key("wsk_abcd.bbb")


def test_generate_api_key_has_expected_shape():
    full_key, prefix, hashed_key = generate_api_key()

    assert full_key.startswith("wsk_")
    assert prefix.startswith("wsk_")
    assert full_key.startswith(prefix + ".")
    assert hashed_key == hash_api_key(full_key)


def test_generate_api_key_is_unique_per_call():
    first_key, _, _ = generate_api_key()
    second_key, _, _ = generate_api_key()
    assert first_key != second_key


def test_create_and_verify_access_token_roundtrip():
    token = create_access_token({"sub": "user-123", "aud": "fastapi-users:auth"})
    payload = verify_access_token(token)

    assert payload["sub"] == "user-123"
    assert "jti" in payload
    assert "exp" in payload


def test_create_access_token_includes_unique_jti_each_call():
    token_a = create_access_token({"sub": "user-123", "aud": "fastapi-users:auth"})
    token_b = create_access_token({"sub": "user-123", "aud": "fastapi-users:auth"})

    payload_a = verify_access_token(token_a)
    payload_b = verify_access_token(token_b)
    assert payload_a["jti"] != payload_b["jti"]


def test_verify_access_token_rejects_garbage_token():
    with pytest.raises(HTTPException) as exc_info:
        verify_access_token("not-a-real-jwt")
    assert exc_info.value.status_code == 401


def test_verify_access_token_rejects_wrong_audience():
    # The identity service's verifier pins audience="fastapi-users:auth";
    # a token without that audience must be rejected, not silently accepted.
    token = create_access_token({"sub": "user-123"})
    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(token)
    assert exc_info.value.status_code == 401


def test_verify_access_token_rejects_tampered_signature():
    token = create_access_token({"sub": "user-123", "aud": "fastapi-users:auth"})
    tampered = token[:-4] + ("0" * 4 if token[-4:] != "0000" else "1111")
    with pytest.raises(HTTPException):
        verify_access_token(tampered)
