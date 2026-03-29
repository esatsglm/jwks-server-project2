from flask import Flask, jsonify, request
import base64
import time
import jwt

from keys import KeyStore

app = Flask(__name__)
keystore = KeyStore()


def int_to_base64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("utf-8")


@app.get("/.well-known/jwks.json")
def jwks():
    keys = []

    for key_entry in keystore.get_unexpired_keys():
        public_key = key_entry.private_key.public_key()
        numbers = public_key.public_numbers()

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(key_entry.kid),
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
        }
        keys.append(jwk)

    return jsonify({"keys": keys}), 200


@app.post("/auth")
def auth():
    now = int(time.time())
    expired_flag = "expired" in request.args

    if expired_flag:
        key_entry = keystore.get_expired_key()
        if key_entry is None:
            return {"error": "No expired key found"}, 500
        exp_time = key_entry.expires_at
    else:
        key_entry = keystore.get_valid_key()
        if key_entry is None:
            return {"error": "No valid key found"}, 500
        exp_time = now + 300

    payload = {
        "sub": "fake-user",
        "iat": now,
        "exp": exp_time,
    }

    token = jwt.encode(
        payload,
        key_entry.private_key,
        algorithm="RS256",
        headers={"kid": str(key_entry.kid)},
    )

    return {"token": token}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)