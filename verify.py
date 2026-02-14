import base64
import json
import urllib.request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


JWKS_URL = "http://localhost:8080/.well-known/jwks.json"


def b64url_to_int(val: str) -> int:
    # base64url string -> int
    padding = "=" * ((4 - len(val) % 4) % 4)
    raw = base64.urlsafe_b64decode((val + padding).encode("utf-8"))
    return int.from_bytes(raw, "big")


def jwk_to_public_key(jwk: dict) -> rsa.RSAPublicKey:
    n = b64url_to_int(jwk["n"])
    e = b64url_to_int(jwk["e"])
    return rsa.RSAPublicNumbers(e, n).public_key()


def fetch_jwks() -> dict:
    with urllib.request.urlopen(JWKS_URL) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    token = input("Paste JWT token here:\n").strip()

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    print("Token kid:", kid)

    jwks = fetch_jwks()
    keys = jwks.get("keys", [])

    jwk = next((k for k in keys if k.get("kid") == kid), None)
    if not jwk:
        print("❌ kid not found in JWKS. Token cannot be verified with current JWKS.")
        return

    public_key = jwk_to_public_key(jwk)

    try:
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        print("✅ VERIFIED. Payload:")
        print(payload)
    except jwt.ExpiredSignatureError:
        print("❌ Token expired (exp in the past).")
    except jwt.InvalidTokenError as e:
        print("❌ Invalid token:", str(e))


if __name__ == "__main__":
    main()