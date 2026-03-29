import sqlite3
import time
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


DB_FILE = "totally_not_my_privateKeys.db"


@dataclass
class KeyEntry:
    kid: int
    private_key: rsa.RSAPrivateKey
    expires_at: int


class KeyStore:
    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self._initialize_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_file)

    def _initialize_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
                """
            )
            conn.commit()

        self._ensure_startup_keys()

    def _ensure_startup_keys(self):
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM keys")
            count = cursor.fetchone()[0]

            if count == 0:
                expired_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                valid_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )

                self._insert_key(conn, expired_key, now - 3600)
                self._insert_key(conn, valid_key, now + 3600)
                conn.commit()

    def _insert_key(self, conn, private_key: rsa.RSAPrivateKey, exp: int):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem, exp),
        )

    def _row_to_key_entry(self, row) -> KeyEntry:
        kid, pem_bytes, exp = row
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None,
        )
        return KeyEntry(kid=kid, private_key=private_key, expires_at=exp)

    def get_valid_key(self) -> KeyEntry | None:
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp ASC
                LIMIT 1
                """,
                (now,),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_key_entry(row)

    def get_expired_key(self) -> KeyEntry | None:
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (now,),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_key_entry(row)

    def get_unexpired_keys(self) -> list[KeyEntry]:
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY kid ASC
                """,
                (now,),
            )
            rows = cursor.fetchall()

        return [self._row_to_key_entry(row) for row in rows]