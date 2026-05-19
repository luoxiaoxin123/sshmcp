"""MCP Server for secure SSH proxy with TOTP verification.

Exposes 3 read/execute tools for AI coding assistants (Claude Code, Codex, OpenCode):
- vault_list_servers: List registered servers (no sensitive data)
- vault_exec: Execute a command (requires TOTP)
- vault_exec_batch: Execute multiple commands (single TOTP)

Server management (add/remove) is done ONLY via CLI (`sshmcp add/remove`),
keeping credentials completely isolated from AI.
"""

import time
from typing import Optional

from mcp.server.fastmcp import FastMCP, Context
from pydantic import BaseModel

from sshmcp.vault import Vault
from sshmcp.totp import verify_code
from sshmcp.ssh_manager import execute_command, execute_commands

mcp = FastMCP("sshmcp")

_vault: Optional[Vault] = None
_totp_failures: dict[str, list[float]] = {}  # alias -> [timestamps of failed attempts]
_MAX_FAILURES = 5
_FAILURE_WINDOW = 300  # 5 minutes


def _get_vault() -> Vault:
    """Get or initialize the vault singleton."""
    global _vault
    if _vault is None:
        _vault = Vault()
        _vault.initialize()
    return _vault


class TOTPInput(BaseModel):
    code: str


async def _verify_totp(ctx: Context, vault: Vault, alias: str) -> str | None:
    """Verify TOTP for a server. Returns None if OK, error message string if denied.

    Skips prompt if the server's TOTP session is still valid.
    Rate-limited to 5 failures per 5-minute window.
    """
    if vault.is_totp_valid(alias):
        return None

    # Rate limit check
    now = time.time()
    failures = _totp_failures.get(alias, [])
    failures = [t for t in failures if now - t < _FAILURE_WINDOW]
    _totp_failures[alias] = failures

    if len(failures) >= _MAX_FAILURES:
        return f"Error: Too many failed attempts. Try again in {_FAILURE_WINDOW // 60} minutes."

    result = await ctx.elicit(
        message=f"Enter the 6-digit TOTP code from your authenticator app to execute on '{alias}':",
        schema=TOTPInput,
    )

    if result.action != "accept":
        return "Command cancelled by user."

    code = result.data.code.strip()
    if not verify_code(vault.totp_secret, code):
        _totp_failures.setdefault(alias, []).append(now)
        return "Error: Invalid TOTP code. Command denied."

    # Clear failures on success
    _totp_failures.pop(alias, None)
    vault.mark_totp_verified(alias)
    return None


@mcp.tool()
def vault_list_servers() -> str:
    """List all registered SSH servers (without sensitive data).

    Returns alias, host, username, port for each server.
    To add/remove servers, use the CLI: `sshmcp add` / `sshmcp remove`.
    """
    vault = _get_vault()
    servers = vault.list_servers()

    if not servers:
        return "No servers registered. Ask the user to run `sshmcp add` in their terminal."

    lines = ["Registered servers:\n"]
    for s in servers:
        lines.append(f"  - {s['alias']}: {s['username']}@{s['host']}:{s['port']}")
    return "\n".join(lines)


@mcp.tool()
async def vault_exec(ctx: Context, alias: str, command: str) -> str:
    """Execute a command on a remote SSH server. Requires TOTP verification.

    The user will be prompted to enter a 6-digit TOTP code from their authenticator app
    (e.g., Bitwarden, Google Authenticator). The command only executes if the code is valid.
    After successful verification, commands on the same server are allowed
    for a configurable time window without re-verification.

    To add servers, the user runs `sshmcp add` in their terminal (not through AI).

    Args:
        alias: Server alias (as registered via `sshmcp add`)
        command: The shell command to execute on the remote server

    Returns:
        Command output (stdout + stderr) or error message
    """
    vault = _get_vault()
    server = vault.get_server(alias)

    if server is None:
        return f"Error: Server '{alias}' not found. Use vault_list_servers to see available servers."

    # TOTP verification (skipped if session is still valid)
    error = await _verify_totp(ctx, vault, alias)
    if error:
        return error

    # Decrypt credentials and execute
    key_content = vault.decrypt_ssh_key(alias)
    password = vault.decrypt_password(alias)
    if key_content is None and password is None:
        return "Error: No SSH key or password configured for this server."

    try:
        ssh_result = execute_command(
            host=server.host,
            username=server.username,
            port=server.port,
            command=command,
            key_content=key_content,
            password=password,
        )

        output_parts = []
        if ssh_result.stdout:
            output_parts.append(f"stdout:\n{ssh_result.stdout}")
        if ssh_result.stderr:
            output_parts.append(f"stderr:\n{ssh_result.stderr}")
        output_parts.append(f"exit_code: {ssh_result.exit_code}")

        return "\n\n".join(output_parts)
    except Exception as e:
        err_msg = str(e)[:200]
        if "not found in known_hosts" in err_msg:
            return (
                f"SSH error: Host key not in known_hosts. "
                f"Connect once manually first: ssh {server.username}@{server.host} -p {server.port}"
            )
        return f"SSH error: {type(e).__name__}: {err_msg}"


@mcp.tool()
async def vault_exec_batch(ctx: Context, alias: str, commands: list[str]) -> str:
    """Execute multiple commands on a remote SSH server. Single TOTP verification.

    All commands run in sequence. One TOTP code covers the entire batch.

    Args:
        alias: Server alias (as registered via `sshmcp add`)
        commands: List of shell commands to execute in order

    Returns:
        Combined output of all commands
    """
    vault = _get_vault()
    server = vault.get_server(alias)

    if server is None:
        return f"Error: Server '{alias}' not found. Use vault_list_servers to see available servers."

    # TOTP verification (skipped if session is still valid)
    error = await _verify_totp(ctx, vault, alias)
    if error:
        return error

    key_content = vault.decrypt_ssh_key(alias)
    password = vault.decrypt_password(alias)
    if key_content is None and password is None:
        return "Error: No SSH key or password configured for this server."

    try:
        results = execute_commands(
            host=server.host,
            username=server.username,
            port=server.port,
            commands=commands,
            key_content=key_content,
            password=password,
        )

        output_parts = []
        for i, res in enumerate(results):
            part = f"--- Command {i + 1}: {res.command} ---"
            if res.stdout:
                part += f"\nstdout:\n{res.stdout}"
            if res.stderr:
                part += f"\nstderr:\n{res.stderr}"
            part += f"\nexit_code: {res.exit_code}"
            output_parts.append(part)

        return "\n\n".join(output_parts)
    except Exception as e:
        err_msg = str(e)[:200]
        if "not found in known_hosts" in err_msg:
            return (
                f"SSH error: Host key not in known_hosts. "
                f"Connect once manually first: ssh {server.username}@{server.host} -p {server.port}"
            )
        return f"SSH error: {type(e).__name__}: {err_msg}"


def run():
    """Start the MCP server (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    run()
