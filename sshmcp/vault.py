"""Encrypted storage for server configurations and SSH keys.

Security model:
- Master key stored in OS keyring (Windows Credential Manager / macOS Keychain / Linux SecretService)
- Fallback: Argon2id-derived key from user master password
- All sensitive data (SSH keys, TOTP secrets) encrypted with Fernet before writing to disk
- Single global TOTP secret shared across all servers
"""

import json
import logging
import os
import stat
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

import keyring
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from platformdirs import user_data_dir

SERVICE_NAME = "sshmcp"
KEYRING_USERNAME = "master_key"


def _set_restrictive_permissions(path: Path) -> None:
    """Set file permissions to owner-only read/write (600). No-op on Windows."""
    if os.name != "nt":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


@dataclass
class ServerConfig:
    alias: str
    host: str
    username: str
    port: int = 22
    encrypted_key: bytes = b""
    encrypted_password: bytes = b""


@dataclass
class VaultData:
    totp_secret: str = ""
    totp_timeout_minutes: int = 5
    servers: dict[str, ServerConfig] = field(default_factory=dict)


class Vault:
    def __init__(self, data_dir: Optional[Path] = None):
        self._data_dir = data_dir or Path(user_data_dir(SERVICE_NAME))
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._enc_file = self._data_dir / "servers.enc"
        self._fernet: Optional[Fernet] = None
        self._data = VaultData()
        self._last_verified: dict[str, float] = {}  # alias -> timestamp, in-memory only

    def initialize(self, master_password: Optional[str] = None) -> bool:
        """Initialize the vault with a master key.

        Tries OS keyring first. Falls back to Argon2id-derived key from password.
        Returns True if initialization succeeded.
        """
        key = self._load_key_from_keyring()
        if key is None and master_password:
            key = self._derive_key_from_password(master_password)
            self._save_key_to_keyring(key)
        elif key is None:
            key = self._generate_and_store_key()

        self._fernet = Fernet(key)
        self._load_data()
        return True

    def _generate_and_store_key(self) -> bytes:
        """Generate a new Fernet key and store it in the OS keyring."""
        key = Fernet.generate_key()
        self._save_key_to_keyring(key)
        return key

    def _load_key_from_keyring(self) -> Optional[bytes]:
        """Try to load the master key from the OS keyring."""
        try:
            stored = keyring.get_password(SERVICE_NAME, KEYRING_USERNAME)
            if stored:
                return stored.encode()
        except Exception as e:
            logger.warning("Failed to load key from keyring: %s", e)
        return None

    def _save_key_to_keyring(self, key: bytes) -> None:
        """Save the master key to the OS keyring."""
        try:
            keyring.set_password(SERVICE_NAME, KEYRING_USERNAME, key.decode())
        except Exception as e:
            logger.warning("Failed to save key to keyring: %s", e)

    def _derive_key_from_password(self, password: str) -> bytes:
        """Derive a Fernet key from a master password using Argon2id."""
        salt_file = self._data_dir / ".salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = os.urandom(16)
            salt_file.write_bytes(salt)
            _set_restrictive_permissions(salt_file)

        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=2**24,  # 16 MiB (OWASP minimum)
        )
        derived = kdf.derive(password.encode())
        return urlsafe_b64encode(derived)

    def _load_data(self) -> None:
        """Load and decrypt server configurations from disk."""
        if not self._enc_file.exists():
            self._data = VaultData()
            return

        try:
            encrypted = self._enc_file.read_bytes()
            decrypted = self._fernet.decrypt(encrypted)
            raw = json.loads(decrypted)

            servers = {}
            for alias, cfg in raw.get("servers", {}).items():
                ek = cfg.get("encrypted_key", "")
                ep = cfg.get("encrypted_password", "")
                servers[alias] = ServerConfig(
                    alias=alias,
                    host=cfg["host"],
                    username=cfg["username"],
                    port=cfg.get("port", 22),
                    encrypted_key=ek.encode() if isinstance(ek, str) else ek,
                    encrypted_password=ep.encode() if isinstance(ep, str) else ep,
                )

            self._data = VaultData(
                totp_secret=raw.get("totp_secret", ""),
                totp_timeout_minutes=raw.get("totp_timeout_minutes", 5),
                servers=servers,
            )
        except (InvalidToken, json.JSONDecodeError, KeyError):
            self._data = VaultData()

    def _save_data(self) -> None:
        """Encrypt and save server configurations to disk."""
        raw = {
            "totp_secret": self._data.totp_secret,
            "totp_timeout_minutes": self._data.totp_timeout_minutes,
            "servers": {},
        }
        for alias, cfg in self._data.servers.items():
            raw["servers"][alias] = {
                "host": cfg.host,
                "username": cfg.username,
                "port": cfg.port,
                "encrypted_key": cfg.encrypted_key.decode()
                if isinstance(cfg.encrypted_key, bytes)
                else cfg.encrypted_key,
                "encrypted_password": cfg.encrypted_password.decode()
                if isinstance(cfg.encrypted_password, bytes)
                else cfg.encrypted_password,
            }

        plaintext = json.dumps(raw).encode()
        encrypted = self._fernet.encrypt(plaintext)
        self._enc_file.write_bytes(encrypted)
        _set_restrictive_permissions(self._enc_file)

    @property
    def totp_secret(self) -> str:
        return self._data.totp_secret

    @totp_secret.setter
    def totp_secret(self, value: str) -> None:
        self._data.totp_secret = value
        self._save_data()

    @property
    def totp_timeout_minutes(self) -> int:
        return self._data.totp_timeout_minutes

    @totp_timeout_minutes.setter
    def totp_timeout_minutes(self, value: int) -> None:
        self._data.totp_timeout_minutes = value
        self._save_data()

    def is_totp_valid(self, alias: str) -> bool:
        """Check if the TOTP session for a server is still valid."""
        last = self._last_verified.get(alias)
        if last is None:
            return False
        elapsed = time.time() - last
        return elapsed < self._data.totp_timeout_minutes * 60

    def mark_totp_verified(self, alias: str) -> None:
        """Record a successful TOTP verification for a server."""
        self._last_verified[alias] = time.time()

    def add_server(
        self,
        alias: str,
        host: str,
        username: str,
        port: int,
        key_content: bytes = b"",
        password: str = "",
    ) -> None:
        """Add a server configuration with encrypted SSH key or password."""
        encrypted_key = self._fernet.encrypt(key_content) if key_content else b""
        encrypted_password = self._fernet.encrypt(password.encode()) if password else b""
        self._data.servers[alias] = ServerConfig(
            alias=alias,
            host=host,
            username=username,
            port=port,
            encrypted_key=encrypted_key,
            encrypted_password=encrypted_password,
        )
        self._save_data()

    def get_server(self, alias: str) -> Optional[ServerConfig]:
        """Get a server configuration by alias."""
        return self._data.servers.get(alias)

    def list_servers(self) -> list[dict]:
        """List all servers (without sensitive data)."""
        return [
            {
                "alias": cfg.alias,
                "host": cfg.host,
                "username": cfg.username,
                "port": cfg.port,
            }
            for cfg in self._data.servers.values()
        ]

    def remove_server(self, alias: str) -> bool:
        """Remove a server configuration. Returns True if found and removed."""
        if alias in self._data.servers:
            del self._data.servers[alias]
            self._save_data()
            return True
        return False

    def decrypt_ssh_key(self, alias: str) -> Optional[bytes]:
        """Decrypt and return the SSH key for a server. Returns None if not found."""
        cfg = self._data.servers.get(alias)
        if cfg is None:
            return None
        try:
            return self._fernet.decrypt(cfg.encrypted_key) if cfg.encrypted_key else None
        except InvalidToken:
            return None

    def decrypt_password(self, alias: str) -> Optional[str]:
        """Decrypt and return the SSH password for a server. Returns None if not set."""
        cfg = self._data.servers.get(alias)
        if cfg is None:
            return None
        try:
            return self._fernet.decrypt(cfg.encrypted_password).decode() if cfg.encrypted_password else None
        except InvalidToken:
            return None
