"""CLI commands for local MCP server and Claude Desktop integration.

  exa mcp serve    — start stdio MCP server (Claude Desktop spawns this)
  exa mcp config   — print MCP client config JSON
  exa mcp install  — write config into Claude Desktop's config file
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

mcp_app = typer.Typer(
    name="mcp",
    help=(
        "Local MCP server for Claude Desktop integration. "
        "Run 'exa mcp install' to connect Claude Desktop to a tenant, "
        "then restart Claude Desktop."
    ),
    no_args_is_help=True,
)
console = Console()

_TENANT_HELP = "Tenant nickname or FQDN (default: saved default)"
_DOCS_MCP_URL = "https://developers.exabeam.com/mcp"


def _project_root() -> Path:
    """Return the exa-tools project root directory."""
    return Path(__file__).resolve().parents[2]


def _exa_executable() -> Path:
    """Return the path to the exa executable in the project venv."""
    root = _project_root()
    if sys.platform == "win32":
        return root / ".venv" / "Scripts" / "exa.exe"
    return root / ".venv" / "bin" / "exa"


def _generate_config(tenant: str | None, server_name: str) -> dict:
    """Generate the MCP client config dict for the local stdio server."""
    exe = _exa_executable()
    if exe.exists():
        command = str(exe)
        args = ["mcp", "serve"]
    else:
        command = "uv"
        args = ["run", "--project", str(_project_root()), "exa", "mcp", "serve"]

    if tenant:
        args += ["--tenant", tenant]
    if server_name != "exabeam":
        args += ["--name", server_name]

    return {
        "mcpServers": {
            server_name: {
                "command": command,
                "args": args,
            }
        }
    }


def _generate_docs_config(server_name: str = "exabeam-docs") -> dict:
    """Generate config for the Exabeam API documentation MCP server (SSE, no auth)."""
    return {
        "mcpServers": {
            server_name: {
                "url": _DOCS_MCP_URL,
                "transport": "sse",
            }
        }
    }


def _claude_config_path() -> Path:
    """Return the Claude Desktop config file path for the current OS."""
    import os

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    return (
        Path.home()
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json"
    )


def _install_config(server_name: str, server_config: dict, config_path: Path) -> None:
    """Merge a server entry into an MCP client config file (creates if absent)."""
    existing: dict = {}
    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    existing.setdefault("mcpServers", {})[server_name] = server_config
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


# -- serve -------------------------------------------------------------------


@mcp_app.command("serve")
def serve(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    name: Annotated[
        str,
        typer.Option("--name", help="Server name reported to MCP client [default: exabeam]"),
    ] = "exabeam",
) -> None:
    """Start a stdio MCP server. Claude Desktop spawns this as a subprocess.

    Exposes 9 tools: search_alerts, get_alert, search_cases, get_case,
    search_events, create_case, update_case, update_alert, add_case_note.
    Token refresh is handled automatically — the server runs indefinitely.
    """
    import asyncio

    from exa.client import ExaClient
    from exa.mcp.server import run_server

    client = ExaClient(tenant=tenant)
    client.authenticate()
    try:
        asyncio.run(run_server(client, server_name=name))
    finally:
        client.close()


# -- config ------------------------------------------------------------------


@mcp_app.command("config")
def config_cmd(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    name: Annotated[
        str,
        typer.Option("--name", help="Server name in the config block [default: exabeam]"),
    ] = "exabeam",
    docs: Annotated[
        bool,
        typer.Option(
            "--docs/--no-docs",
            help="Output Exabeam API docs MCP config instead [default: no-docs]",
        ),
    ] = False,
) -> None:
    """Print the MCP client config JSON to stdout (paste into Claude Desktop settings)."""
    if docs:
        docs_name = name if name != "exabeam" else "exabeam-docs"
        cfg = _generate_docs_config(server_name=docs_name)
    else:
        cfg = _generate_config(tenant=tenant, server_name=name)

    sys.stdout.write(json.dumps(cfg, indent=2) + "\n")


# -- install -----------------------------------------------------------------


@mcp_app.command("install")
def install(
    tenant: Annotated[
        str | None,
        typer.Option("--tenant", "-t", help=_TENANT_HELP),
    ] = None,
    name: Annotated[
        str,
        typer.Option("--name", help="Server name in the config [default: exabeam]"),
    ] = "exabeam",
    docs: Annotated[
        bool,
        typer.Option(
            "--docs/--no-docs",
            help="Install Exabeam API docs MCP server instead [default: no-docs]",
        ),
    ] = False,
) -> None:
    """Install the MCP server config into Claude Desktop (merges with existing config)."""
    if docs:
        server_name = name if name != "exabeam" else "exabeam-docs"
        cfg_block = _generate_docs_config(server_name=server_name)
    else:
        server_name = name
        cfg_block = _generate_config(tenant=tenant, server_name=server_name)

    server_config = cfg_block["mcpServers"][server_name]
    config_path = _claude_config_path()

    _install_config(server_name, server_config, config_path)

    console.print(
        f"  Installed '[bold]{server_name}[/bold]' → {config_path}",
        style="green",
    )
    if not docs:
        console.print(
            "  Prerequisite: run [bold]exa auth[/bold] first to cache credentials in keyring.",
            style="yellow",
        )
    console.print("  Restart Claude Desktop for changes to take effect.", style="dim")
