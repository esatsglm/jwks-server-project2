import jwt
from app import app as flask_app, keystore


def jwk_to_public_key(jwk):
    return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)


def test_jwks_returns_only_unexpired_key():
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200

    data = resp.get_json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    valid_key = keystore.get_valid_key()
    assert valid_key is not None

    jwk = data["keys"][0]
    assert jwk["kid"] == str(valid_key.kid)


def test_auth_returns_valid_jwt_signed_by_active_key():
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    jwks = client.get("/.well-known/jwks.json").get_json()
    jwk = jwks["keys"][0]
    public_key = jwk_to_public_key(jwk)

    resp = client.post("/auth")
    assert resp.status_code == 200

    token = resp.get_json()["token"]
    assert token.count(".") == 2

    valid_key = keystore.get_valid_key()
    assert valid_key is not None

    header = jwt.get_unverified_header(token)
    assert header["kid"] == str(valid_key.kid)

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"


def test_auth_expired_true_returns_expired_token():
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()

    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200

    token = resp.get_json()["token"]

    expired_key = keystore.get_expired_key()
    assert expired_key is not None

    header = jwt.get_unverified_header(token)
    assert header["kid"] == str(expired_key.kid)

    decoded = jwt.decode(
        token,
        expired_key.private_key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )

    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] <= decoded["iat"]