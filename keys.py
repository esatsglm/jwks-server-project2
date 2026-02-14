import time
import uuid
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class KeyEntry:
    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: int  # unix timestamp (seconds)


class KeyStore:
    def __init__(self):
        now = int(time.time())

        # Active key: expires 1 hour in the future
        active_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.active = KeyEntry(
            kid=str(uuid.uuid4()),
            private_key=active_priv,
            expires_at=now + 3600,
        )

        # Expired key: expired 1 hour ago
        expired_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.expired = KeyEntry(
            kid=str(uuid.uuid4()),
            private_key=expired_priv,
            expires_at=now - 3600,
        )

    def unexpired_public(self):
        """Return only keys that have not expired."""
        now = int(time.time())
        keys = []
        if self.active.expires_at > now:
            keys.append(self.active)
        return keys