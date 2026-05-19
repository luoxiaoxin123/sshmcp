"""TOTP generation and verification for server access control.

Uses standard TOTP (RFC 6238) with SHA-1, 6 digits, 30-second period.
Compatible with all TOTP apps (Bitwarden, Google Authenticator, Authy, 1Password, etc.)
"""

import pyotp


def generate_secret() -> str:
    """Generate a new random TOTP secret (Base32-encoded)."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, alias: str, username: str) -> str:
    """Generate an otpauth:// URI for importing into authenticator apps.

    Args:
        secret: Base32-encoded TOTP secret
        alias: Server alias (used as account label)
        username: SSH username (included in label)

    Returns:
        otpauth:// URI string
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=f"{username}@{alias}",
        issuer_name="sshmcp",
    )


def verify_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a TOTP code against the secret.

    Args:
        secret: Base32-encoded TOTP secret
        code: 6-digit code to verify
        valid_window: Number of time steps to allow (default 1 = ±30 seconds)

    Returns:
        True if the code is valid
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=valid_window)
