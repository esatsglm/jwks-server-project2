import os
import sys

# Add project root to PYTHONPATH so "import app" works on Windows/pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import base64
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

# Import the Flask app and keystore from app.py
from app import app as flask_app, keystore


def b64url_to_int(val: str) -> int:
    """
    Convert base64url string to integer.
    Used to reconstruct RSA public key from JWKS.
    """
    padding = "=" * ((4 - len(val) % 4) % 4)
    raw = base64.urlsafe_b64decode((val + padding).encode("utf-8"))
    return int.from_bytes(raw, "big")


def jwk_to_public_key(jwk: dict) -> rsa.RSAPublicKey:
    """
    Convert a JWK dictionary to an RSA public key object.
    """
    n = b64url_to_int(jwk["n"])
    e = b64url_to_int(jwk["e"])
    return rsa.RSAPublicNumbers(e, n).public_key()


def test_jwks_returns_only_unexpired_key():
    """
    Ensure JWKS endpoint returns only the active (unexpired) key.
    """
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200

    data = resp.get_json()
    assert "keys" in data
    assert len(data["keys"]) == 1  # Only active key should be served

    jwk = data["keys"][0]
    assert jwk["kid"] == keystore.active.kid
    assert jwk["kid"] != keystore.expired.kid


def test_auth_returns_valid_jwt_signed_by_active_key():
    """
    Ensure /auth returns a valid JWT signed by the active key.
    """
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    # Fetch JWKS and reconstruct public key
    jwks = client.get("/.well-known/jwks.json").get_json()
    jwk = jwks["keys"][0]
    public_key = jwk_to_public_key(jwk)

    # Request token
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    # Token should have 3 parts (header.payload.signature)
    assert token.count(".") == 2

    # Check header contains correct kid
    header = jwt.get_unverified_header(token)
    assert header["kid"] == keystore.active.kid

    # Verify signature and expiration
    payload = jwt.decode(token, public_key, algorithms=["RS256"])
    assert payload["sub"] == "fake-user"
    assert payload["exp"] > int(time.time())


def test_auth_expired_true_returns_expired_token():
    """
    Ensure /auth?expired=true returns a token signed by expired key
    and that the expiration time is in the past.
    """
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    # Header should contain expired key kid
    header = jwt.get_unverified_header(token)
    assert header["kid"] == keystore.expired.kid

    # Expired key should NOT appear in JWKS
    jwks = client.get("/.well-known/jwks.json").get_json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert keystore.expired.kid not in kids

    # Check expiration is in the past
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] < int(time.time())