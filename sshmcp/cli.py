"""CLI entry point for sshmcp.

Commands:
    setup   - Auto-detect and configure AI coding tools
    add     - Add a server interactively
    list    - List registered servers
    remove  - Remove a server
    run     - Start the MCP server
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None


def _get_server_module_path() -> str:
    """Get the absolute path to the server module for MCP config."""
    return str(Path(__file__).parent.parent)


def _get_python_executable() -> str:
    """Get the correct Python executable (venv if available)."""
    # Check if we're in a venv by looking for the venv marker
    venv_python = Path(__file__).parent.parent / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return str(venv_python)
    venv_python = Path(__file__).parent.parent / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


# ─── AI Tool Detection and Configuration ───────────────────────────────

TOOLS = {
    "claude": {
        "name": "Claude Code",
        "config_path": Path.home() / ".claude" / "settings.json",
        "detect": lambda p: p.exists(),
        "configure": None,  # set below
    },
    "codex": {
        "name": "OpenAI Codex CLI",
        "config_path": Path.home() / ".codex" / "config.toml",
        "detect": lambda p: p.exists(),
        "configure": None,  # set below
    },
    "opencode": {
        "name": "OpenCode",
        "config_path": Path.home() / ".config" / "opencode" / "opencode.json",
        "detect": lambda p: p.exists(),
        "configure": None,  # set below
    },
}


def _configure_claude(cwd: str) -> None:
    """Configure Claude Code to use sshmcp MCP server."""
    config_path = TOOLS["claude"]["config_path"]
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        config = {}

    if "mcpServers" not in config:
        config["mcpServers"] = {}

    if "sshmcp" in config["mcpServers"]:
        print(f"  Claude Code: already configured, skipping.")
        return

    config["mcpServers"]["sshmcp"] = {
        "command": _get_python_executable(),
        "args": ["-m", "sshmcp.server"],
        "cwd": cwd,
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"  Claude Code: configured at {config_path}")


def _configure_codex(cwd: str) -> None:
    """Configure Codex CLI to use sshmcp MCP server."""
    config_path = TOOLS["codex"]["config_path"]
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Read existing config
    existing = ""
    if config_path.exists():
        existing = config_path.read_text(encoding="utf-8")

    if "sshmcp" in existing:
        print(f"  Codex CLI: already configured, skipping.")
        return

    # Append TOML config (escape backslashes for Windows paths)
    exe = _get_python_executable().replace("\\", "\\\\")
    cwd_escaped = cwd.replace("\\", "\\\\")
    section = f"""
[mcp_servers.sshmcp]
command = "{exe}"
args = ["-m", "sshmcp.server"]
cwd = "{cwd_escaped}"
enabled = true
"""
    with open(config_path, "a", encoding="utf-8") as f:
        f.write(section)

    print(f"  Codex CLI: configured at {config_path}")


def _configure_opencode(cwd: str) -> None:
    """Configure OpenCode to use sshmcp MCP server."""
    config_path = TOOLS["opencode"]["config_path"]
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        config = {}

    if "mcp" not in config:
        config["mcp"] = {}

    if "sshmcp" in config["mcp"]:
        print(f"  OpenCode: already configured, skipping.")
        return

    config["mcp"]["sshmcp"] = {
        "type": "local",
        "command": [_get_python_executable(), "-m", "sshmcp.server"],
        "cwd": cwd,
        "enabled": True,
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"  OpenCode: configured at {config_path}")


TOOLS["claude"]["configure"] = _configure_claude
TOOLS["codex"]["configure"] = _configure_codex
TOOLS["opencode"]["configure"] = _configure_opencode


def cmd_setup(args: argparse.Namespace) -> None:
    """Auto-detect and configure AI coding tools."""
    cwd = _get_server_module_path()
    tools_to_configure = args.tool if args.tool != "all" else list(TOOLS.keys())

    print("sshmcp setup\n")

    for tool_id in tools_to_configure:
        if tool_id not in TOOLS:
            print(f"  Unknown tool: {tool_id}")
            continue

        tool = TOOLS[tool_id]
        if tool["detect"](tool["config_path"]):
            print(f"  Detected {tool['name']}")
            tool["configure"](cwd)
        else:
            print(f"  {tool['name']}: not found at {tool['config_path']}, skipping")

    print("\nDone. Restart your AI coding tool to load the sshmcp MCP server.")


def cmd_add(args: argparse.Namespace) -> None:
    """Add a server interactively."""
    import getpass
    from sshmcp.vault import Vault

    vault = Vault()
    vault.initialize()

    # Auto-generate TOTP on first use
    if not vault.totp_secret:
        from sshmcp.totp import generate_secret
        vault.totp_secret = generate_secret()
        print("First server added. A TOTP secret has been generated.")
        print("Run `sshmcp totp` to get the TOTP URI for your authenticator app.\n")

    alias = args.alias or input("Server alias (e.g., 'web', 'db'): ").strip()
    host = args.host or input("Server IP/hostname: ").strip()
    username = args.username or input("SSH username: ").strip()
    if args.port is not None:
        port = args.port
    else:
        port_input = input("SSH port [22]: ").strip()
        try:
            port = int(port_input) if port_input else 22
        except ValueError:
            print(f"Error: Invalid port number: {port_input}")
            return

    # Auth: key or password
    key_content = b""
    password = ""

    if args.key_path:
        key_file = Path(args.key_path).expanduser()
        if not key_file.exists():
            print(f"Error: Key file not found: {args.key_path}")
            return
        key_content = key_file.read_bytes()
    else:
        auth = input("Authentication method - (k)ey file or (p)assword? [k]: ").strip().lower()
        if auth == "p":
            password = getpass.getpass("SSH password: ")
        else:
            key_path = input("SSH key path (e.g., ~/.ssh/id_rsa): ").strip()
            key_file = Path(key_path).expanduser()
            if not key_file.exists():
                print(f"Error: Key file not found: {key_path}")
                return
            key_content = key_file.read_bytes()

    vault.add_server(
        alias=alias,
        host=host,
        username=username,
        port=port,
        key_content=key_content,
        password=password,
    )

    print(f"\nServer '{alias}' added successfully.")
    print(f"Auth method: {'password' if password else 'SSH key'}")
    if vault.totp_secret:
        print("Run `sshmcp totp` to get the TOTP URI (if you haven't already).")


def cmd_list(args: argparse.Namespace) -> None:
    """List registered servers."""
    from sshmcp.vault import Vault

    vault = Vault()
    vault.initialize()

    servers = vault.list_servers()
    if not servers:
        print("No servers registered.")
        return

    print("Registered servers:\n")
    for s in servers:
        print(f"  {s['alias']}: {s['username']}@{s['host']}:{s['port']}")


def cmd_remove(args: argparse.Namespace) -> None:
    """Remove a server."""
    from sshmcp.vault import Vault

    vault = Vault()
    vault.initialize()

    if vault.remove_server(args.alias):
        print(f"Server '{args.alias}' removed.")
    else:
        print(f"Server '{args.alias}' not found.")


def cmd_run(args: argparse.Namespace) -> None:
    """Start the MCP server."""
    from sshmcp.server import run
    run()


def cmd_totp(args: argparse.Namespace) -> None:
    """Show the TOTP URI for importing into authenticator app."""
    from sshmcp.vault import Vault
    from sshmcp.totp import get_provisioning_uri

    vault = Vault()
    vault.initialize()

    if not vault.totp_secret:
        print("No TOTP secret generated yet. Add a server first with `sshmcp add`.")
        return

    uri = get_provisioning_uri(vault.totp_secret, "sshmcp", "access")
    print("Import this URI into your authenticator app (Bitwarden, Google Authenticator, etc.):\n")
    print(f"  {uri}")
    print("\nIn Bitwarden: edit login item -> 'Authenticator Key (TOTP)' -> paste URI.")
    print("In other apps: scan or manually add using the secret above.")
    print("This single TOTP works for ALL your servers.")


def cmd_config(args: argparse.Namespace) -> None:
    """View or update configuration."""
    from sshmcp.vault import Vault

    vault = Vault()
    vault.initialize()

    if args.totp_timeout is not None:
        vault.totp_timeout_minutes = args.totp_timeout
        print(f"TOTP timeout set to {args.totp_timeout} minutes.")
    else:
        print(f"Current TOTP timeout: {vault.totp_timeout_minutes} minutes")
        print(f"\nTo change: sshmcp config --totp-timeout <minutes>")
        print(f"  Example: sshmcp config --totp-timeout 10")


def main():
    parser = argparse.ArgumentParser(
        prog="sshmcp",
        description="Secure SSH proxy MCP server with TOTP verification",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # setup
    p_setup = subparsers.add_parser("setup", help="Configure AI coding tools")
    p_setup.add_argument(
        "--tool",
        choices=["claude", "codex", "opencode", "all"],
        default="all",
        help="Which tool to configure (default: all)",
    )
    p_setup.set_defaults(func=cmd_setup)

    # add
    p_add = subparsers.add_parser("add", help="Add a server")
    p_add.add_argument("alias", nargs="?", help="Server alias")
    p_add.add_argument("--host", help="Server IP/hostname")
    p_add.add_argument("--username", help="SSH username")
    p_add.add_argument("--port", type=int, default=None, help="SSH port (default: 22)")
    p_add.add_argument("--key-path", help="Path to SSH private key")
    p_add.set_defaults(func=cmd_add)

    # list
    p_list = subparsers.add_parser("list", help="List registered servers")
    p_list.set_defaults(func=cmd_list)

    # remove
    p_remove = subparsers.add_parser("remove", help="Remove a server")
    p_remove.add_argument("alias", help="Server alias to remove")
    p_remove.set_defaults(func=cmd_remove)

    # run
    p_run = subparsers.add_parser("run", help="Start the MCP server")
    p_run.set_defaults(func=cmd_run)

    # totp
    p_totp = subparsers.add_parser("totp", help="Show TOTP URI for authenticator app")
    p_totp.set_defaults(func=cmd_totp)

    # config
    p_config = subparsers.add_parser("config", help="View or update configuration")
    p_config.add_argument("--totp-timeout", type=int, help="TOTP session timeout in minutes")
    p_config.set_defaults(func=cmd_config)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
