"""
Unit tests for authentication, password hashing, and JWT bearer token authorization.
"""

import pytest
from backend.auth import create_access_token, decode_access_token, get_password_hash, verify_password


def test_password_hashing():
    password = "secret_password_123"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False


def test_jwt_token_generation_and_decoding():
    data = {"sub": "test_admin"}
    token = create_access_token(data)
    assert isinstance(token, str)

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded.username == "test_admin"


def test_invalid_jwt_token():
    decoded = decode_access_token("invalid.jwt.token.value")
    assert decoded is None
