"""SSH connection management using paramiko.

Key features:
- Loads SSH keys from memory (never writes to temp files)
- Supports RSA, Ed25519, and ECDSA key types
- Supports password-based authentication
- Executes commands and returns stdout/stderr
"""

from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

import paramiko


@dataclass
class SSHResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int


def _load_key_from_memory(key_content: bytes, passphrase: Optional[str] = None) -> paramiko.PKey:
    """Load an SSH private key from bytes in memory.

    Tries multiple key types in order: Ed25519, RSA, ECDSA.
    """
    key_str = key_content.decode("utf-8")
    key_file = StringIO(key_str)

    errors = []
    for key_class in [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]:
        try:
            key_file.seek(0)
            return key_class.from_private_key(key_file, password=passphrase)
        except paramiko.SSHException as e:
            errors.append(f"{key_class.__name__}: {e}")

    raise paramiko.SSHException(
        f"Failed to load SSH key. Tried: {', '.join(errors)}"
    )


def execute_command(
    host: str,
    username: str,
    port: int,
    command: str,
    key_content: Optional[bytes] = None,
    password: Optional[str] = None,
    passphrase: Optional[str] = None,
    timeout: int = 30,
) -> SSHResult:
    """Execute a single command on a remote server via SSH.

    Supports key-based or password-based authentication.
    If key_content is provided, key auth is preferred; password is used as fallback.
    """
    client = paramiko.SSHClient()
    # Load system known_hosts; reject unknown hosts for security
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    if known_hosts.exists():
        client.load_system_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }

    if key_content:
        connect_kwargs["pkey"] = _load_key_from_memory(key_content, passphrase)
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("Either key_content or password must be provided")

    try:
        client.connect(**connect_kwargs)
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(60)

        stdin, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        return SSHResult(
            command=command,
            stdout=out,
            stderr=err,
            exit_code=exit_code,
        )
    finally:
        client.close()


def execute_commands(
    host: str,
    username: str,
    port: int,
    commands: list[str],
    key_content: Optional[bytes] = None,
    password: Optional[str] = None,
    passphrase: Optional[str] = None,
    timeout: int = 30,
) -> list[SSHResult]:
    """Execute multiple commands on a remote server via SSH."""
    results = []
    for cmd in commands:
        result = execute_command(
            host=host,
            username=username,
            port=port,
            command=cmd,
            key_content=key_content,
            password=password,
            passphrase=passphrase,
            timeout=timeout,
        )
        results.append(result)
    return results
