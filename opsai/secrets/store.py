"""Secret store: OS keyring on desktop, encrypted local vault on server."""

from __future__ import annotations

import base64
import logging
import os
import re
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SERVICE_NAME = "OpsAI"

_VAULT_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault (
    name TEXT PRIMARY KEY,
    dek_enc TEXT NOT NULL,
    dek_nonce TEXT NOT NULL,
    data_enc TEXT NOT NULL,
    data_nonce TEXT NOT NULL
);
"""


class SecretStore(ABC):
    """Secret storage interface (FR-150)."""

    @abstractmethod
    def put(self, name: str, value: bytes) -> None:
        """Store a secret (overwrites)."""

    @abstractmethod
    def get(self, name: str) -> bytes:
        """Load a secret; raises KeyError when missing."""

    @abstractmethod
    def delete(self, name: str) -> None:
        """Delete a secret (missing names are ignored)."""


class KeyringStore(SecretStore):
    """Desktop backend: Windows Credential Manager / Secret Service / KWallet."""

    def put(self, name: str, value: bytes) -> None:
        import keyring

        keyring.set_password(SERVICE_NAME, name, base64.b64encode(value).decode())

    def get(self, name: str) -> bytes:
        import keyring

        raw = keyring.get_password(SERVICE_NAME, name)
        if raw is None:
            msg = f"Secret {name!r} not found in keyring"
            raise KeyError(msg)
        return base64.b64decode(raw)

    def delete(self, name: str) -> None:
        import keyring

        try:
            keyring.delete_password(SERVICE_NAME, name)
        except Exception:  # noqa: BLE001 - missing secrets are ignored
            return


def _derive_kek(master_key: bytes, context: bytes = b"opsai-vault-kek-v1") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(master_key)


class LocalVaultStore(SecretStore):
    """Server backend: envelope encryption, AES-256-GCM (FR-151)."""

    def __init__(self, db_path: Path, master_key: bytes) -> None:
        if len(master_key) != 32:
            msg = "Master key must be 32 bytes"
            raise ValueError(msg)
        self.db_path = db_path
        self._kek = _derive_kek(master_key)
        with sqlite3.connect(db_path) as conn:
            conn.executescript(_VAULT_SCHEMA)
            conn.commit()

    def put(self, name: str, value: bytes) -> None:
        dek = AESGCM.generate_key(bit_length=256)
        data_nonce = os.urandom(12)
        data_enc = AESGCM(dek).encrypt(data_nonce, value, None)
        dek_nonce = os.urandom(12)
        dek_enc = AESGCM(self._kek).encrypt(dek_nonce, dek, name.encode("utf-8"))
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vault (name, dek_enc, dek_nonce, data_enc, data_nonce)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    name,
                    base64.b64encode(dek_enc).decode(),
                    base64.b64encode(dek_nonce).decode(),
                    base64.b64encode(data_enc).decode(),
                    base64.b64encode(data_nonce).decode(),
                ),
            )
            conn.commit()

    def get(self, name: str) -> bytes:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT dek_enc, dek_nonce, data_enc, data_nonce FROM vault WHERE name = ?", (name,)
            ).fetchone()
        if row is None:
            msg = f"Secret {name!r} not found in vault"
            raise KeyError(msg)
        dek = AESGCM(self._kek).decrypt(
            base64.b64decode(row[1]), base64.b64decode(row[0]), name.encode("utf-8")
        )
        return AESGCM(dek).decrypt(base64.b64decode(row[3]), base64.b64decode(row[2]), None)

    def delete(self, name: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM vault WHERE name = ?", (name,))
            conn.commit()

    def rotate_master_key(self, new_master_key: bytes) -> None:
        """Re-encrypt DEKs with a new KEK without touching data keys' payloads."""
        if len(new_master_key) != 32:
            msg = "Master key must be 32 bytes"
            raise ValueError(msg)
        new_kek = _derive_kek(new_master_key)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT name, dek_enc, dek_nonce FROM vault").fetchall()
            for name, dek_enc, dek_nonce in rows:
                dek = AESGCM(self._kek).decrypt(
                    base64.b64decode(dek_nonce), base64.b64decode(dek_enc), name.encode()
                )
                fresh_nonce = os.urandom(12)
                fresh_enc = AESGCM(new_kek).encrypt(fresh_nonce, dek, name.encode())
                conn.execute(
                    "UPDATE vault SET dek_enc = ?, dek_nonce = ? WHERE name = ?",
                    (
                        base64.b64encode(fresh_enc).decode(),
                        base64.b64encode(fresh_nonce).decode(),
                        name,
                    ),
                )
            conn.commit()
        self._kek = new_kek


def load_master_key() -> bytes:
    """Load the 32B master key from env or file (FR-151, FR-801)."""
    raw = os.environ.get("OPSAI_MASTER_KEY", "").strip()
    if not raw:
        key_file = os.environ.get("OPSAI_MASTER_KEY_FILE", "").strip()
        if key_file:
            raw = Path(key_file).read_text(encoding="utf-8").strip()
    if not raw:
        msg = "Set OPSAI_MASTER_KEY or OPSAI_MASTER_KEY_FILE for the local vault"
        raise RuntimeError(msg)
    try:
        key = base64.b64decode(raw)
    except ValueError as exc:
        msg = "OPSAI_MASTER_KEY is not valid base64"
        raise RuntimeError(msg) from exc
    if len(key) != 32:
        msg = "OPSAI_MASTER_KEY must decode to 32 bytes"
        raise RuntimeError(msg)
    return key


class SecretRedactor(logging.Filter):
    """Logging filter redacting known secrets and password patterns (FR-157)."""

    _PATTERNS = [
        re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;\"']+)"),
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@]+)@"),
    ]

    def __init__(self, known_values: list[str] | None = None) -> None:
        super().__init__()
        self.known_values = [v for v in (known_values or []) if v]

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = message
        for value in self.known_values:
            if len(value) >= 4:
                redacted = redacted.replace(value, "***")
        for pattern in self._PATTERNS:
            redacted = pattern.sub(r"\1=***", redacted)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True
