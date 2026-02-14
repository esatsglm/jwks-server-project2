from flask import Flask, jsonify, request
from keys import KeyStore
import base64
import time
import jwt

app = Flask(__name__)
keystore = KeyStore()


def int_to_base64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("utf-8")


@app.get("/.well-known/jwks.json")
def jwks():
    keys = []

    for key in keystore.unexpired_public():
        pub = key.private_key.public_key()
        numbers = pub.public_numbers()

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": key.kid,
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
        key = keystore.expired
        exp_time = key.expires_at  # geçmişte
    else:
        key = keystore.active
        exp_time = now + 300  # 5 dakika

    payload = {
        "sub": "fake-user",
        "iat": now,
        "exp": exp_time
    }

    token = jwt.encode(
        payload,
        key.private_key,
        algorithm="RS256",
        headers={"kid": key.kid}
    )

    return {"token": token}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)