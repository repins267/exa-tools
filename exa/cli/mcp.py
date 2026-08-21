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
# stdio mode uses stdout as the MCP protocol channel; status must go to stderr.
err_console = Console(stderr=True)

_TENANT_HELP = "Tenant nickname or FQDN [default: saved default]"
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


def _generate_config(
    tenant: str | None, server_name: str, allow_writes: bool = False
) -> dict:
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
    if allow_writes:
        args += ["--allow-writes"]

    return {
        "mcpServers": {
            server_name: {
                "command": command,
                "args": args,
            }
        }
    }


def _generate_docs_config(
    server_name: str = "exabeam-docs", *, proxy: bool | None = None
) -> dict:
    """Generate config for the Exabeam API docs MCP server.

    The enterprise "3p" (Bedrock/Cowork) Desktop build rejects a native remote
    entry ({url, transport} or {type: sse}) and requires the server to be proxied
    through stdio via `mcp-remote` (needs Node/npx). Older builds accept the SSE
    URL directly. When proxy is None it is inferred from the resolved config path.
    """
    if proxy is None:
        proxy = _is_3p_config()
    if proxy:
        server: dict = {"command": "npx", "args": ["-y", "mcp-remote", _DOCS_MCP_URL]}
    else:
        server = {"url": _DOCS_MCP_URL, "transport": "sse"}
    return {"mcpServers": {server_name: server}}


def _claude_config_path() -> Path:
    """Return the Claude Desktop config path, preferring the "3p" build if present.

    The enterprise Bedrock/Cowork build ("Claude-3p") reads a different location
    than the classic app. Prefer it when its directory exists.
    """
    import os

    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        if local and (Path(local) / "Claude-3p").exists():
            return Path(local) / "Claude-3p" / "claude_desktop_config.json"
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    base = Path.home() / "Library" / "Application Support"
    if (base / "Claude-3p").exists():
        return base / "Claude-3p" / "claude_desktop_config.json"
    return base / "Claude" / "claude_desktop_config.json"


def _is_3p_config() -> bool:
    """True when the resolved Claude Desktop config path is the 3p build's."""
    return "Claude-3p" in _claude_config_path().parts


def _store_desktop_dir() -> Path | None:
    """Return the Microsoft Store (sandboxed, MSIX) Claude config dir if present.

    The Store build lives under ...\\Packages\\Claude_<id>\\LocalCache\\Roaming\\Claude
    and CANNOT run local MCP servers (no Developer Mode, sandboxed). Detecting it lets
    us warn instead of writing a config the app will never read.
    """
    if sys.platform != "win32":
        return None
    import glob
    import os

    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return None
    for pkg in glob.glob(str(Path(local) / "Packages" / "Claude_*")):
        cand = Path(pkg) / "LocalCache" / "Roaming" / "Claude"
        if cand.exists():
            return cand
    return None


def _desktop_targets() -> list[dict]:
    """All known Claude Desktop config locations for this OS, with detection state.

    Each entry: {label, path, exists, supports_mcp}. Ordered by install preference.
    The Store build is listed with supports_mcp=False so the caller can warn.
    """
    import os

    targets: list[dict] = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        local = os.environ.get("LOCALAPPDATA", "")
        std = Path(appdata) / "Claude" / "claude_desktop_config.json"
        tp = Path(local) / "Claude-3p" / "claude_desktop_config.json"
        targets.append({"label": "Claude Desktop (standard, from claude.ai)",
                        "path": std, "exists": std.parent.exists(), "supports_mcp": True})
        targets.append({"label": "Claude Desktop (work-licensed AWS Bedrock build \"Claude-3p\")",
                        "path": tp, "exists": tp.parent.exists(), "supports_mcp": True})
        store = _store_desktop_dir()
        if store is not None:
            targets.append({"label": "Claude Desktop (Microsoft Store - NO local MCP)",
                            "path": store / "claude_desktop_config.json",
                            "exists": True, "supports_mcp": False})
    else:
        base = Path.home() / "Library" / "Application Support"
        std = base / "Claude" / "claude_desktop_config.json"
        tp = base / "Claude-3p" / "claude_desktop_config.json"
        targets.append({"label": "Claude Desktop (standard, from claude.ai)",
                        "path": std, "exists": std.parent.exists(), "supports_mcp": True})
        targets.append({"label": "Claude Desktop (work-licensed AWS Bedrock build \"Claude-3p\")",
                        "path": tp, "exists": tp.parent.exists(), "supports_mcp": True})
    return targets


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


def _print_setup_guidance(server_name: str, server_config: dict, *, docs: bool) -> None:
    """Show the exact config block and where every Claude client expects it.

    No assumptions: the user picks their client/OS and pastes the block. Covers
    Claude Desktop (standard, work-licensed AWS Bedrock, and the Store build that
    can't do MCP) plus Claude Code, on Windows and macOS.
    """
    block = json.dumps({"mcpServers": {server_name: server_config}}, indent=2)

    console.print("\n[bold]Config block[/bold] - merge this into your client's MCP config:")
    console.print(block, style="cyan")

    console.print("\n[bold]Where it goes (pick the one that matches your client):[/bold]")
    for t in _desktop_targets():
        mark = "[green]detected[/green]" if t["exists"] else "[dim]not present[/dim]"
        if not t["supports_mcp"]:
            console.print(
                f"  - {t['label']}\n      {t['path']}  ({mark})\n"
                "      [yellow]This build is sandboxed and cannot run local MCP - use the "
                "standalone app from claude.ai/download or Claude Code instead.[/yellow]"
            )
        else:
            console.print(f"  - {t['label']}\n      {t['path']}  ({mark})")

    console.print(
        "\n  - Claude Code (any OS): don't hand-edit - run\n"
        f"      [bold]claude mcp add {server_name} -- {server_config.get('command', 'exa')} "
        f"{' '.join(server_config.get('args', []))}[/bold]\n"
        "      or drop the block above into a project-level [bold].mcp.json[/bold]."
    )

    if not docs:
        console.print(
            "\n  Prerequisite: run [bold]exa auth[/bold] first to cache credentials in keyring.",
            style="yellow",
        )
        console.print(
            "  For read-only docs only (no tenant, no local repo): "
            "[bold]exa mcp install --docs --print[/bold].",
            style="dim",
        )
    console.print(
        "\n  After pasting: fully quit and reopen the client. You do NOT run "
        "'exa mcp serve' yourself - the client spawns it.",
        style="dim",
    )


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
    port: Annotated[
        int | None,
        typer.Option(
            "--port",
            help="Run as HTTP/SSE server on this port instead of stdio [default: stdio]",
        ),
    ] = None,
    host: Annotated[
        str,
        typer.Option("--host", help="Host to bind when using --port [default: 127.0.0.1]"),
    ] = "127.0.0.1",
    allow_writes: Annotated[
        bool,
        typer.Option(
            "--allow-writes/--read-only",
            help=(
                "Enable the four write tools (create_case, update_case, update_alert, "
                "add_case_note). Default: read-only -- write tools are hidden and refused."
            ),
        ),
    ] = False,
) -> None:
    """Start the Exabeam MCP server.

    
    Examples:
      uv run exa mcp serve --tenant sademodev22      # stdio, for Claude Desktop
      uv run exa mcp serve --tenant sademodev22 --port 8080
      uv run exa mcp install --tenant sademodev22    # usually what you want instead

    Default (no --port): stdio mode — Claude Desktop spawns this as a subprocess.
    With --port: HTTP/SSE mode — add http://HOST:PORT/sse as a custom connector
    in Claude Desktop settings.

    Exposes 33 tools (29 read + 4 write). Read-only is the DEFAULT: the four
    write tools (create_case, update_case, update_alert, add_case_note) are
    hidden and refused unless --allow-writes is passed -- a hard gate, not just
    the in-prompt ask. Token refresh is automatic; the server runs indefinitely.
    """
    import asyncio

    from exa.client import ExaClient

    client = ExaClient(tenant=tenant)
    client.authenticate()

    read_only = not allow_writes
    if read_only:
        err_console.print(
            "  Mode: READ-ONLY -- write tools hidden and refused. "
            "Restart with --allow-writes to enable them.",
            style="green",
        )
    else:
        err_console.print(
            "  Mode: WRITES ENABLED -- create/update/close cases and alerts are live. "
            "This is a soft posture; confirm the tenant before every write.",
            style="yellow",
        )

    try:
        if port is not None:
            from exa.mcp.server import run_sse_server

            console.print(
                f"  Exabeam MCP server listening on [bold]http://{host}:{port}/sse[/bold]",
                style="green",
            )
            console.print(
                f"  Add [bold]http://{host}:{port}/sse[/bold] as a custom connector "
                "in Claude Desktop settings.",
                style="dim",
            )
            asyncio.run(
                run_sse_server(
                    client,
                    server_name=name,
                    host=host,
                    port=port,
                    read_only=read_only,
                )
            )
        else:
            from exa.mcp.server import run_server

            # Make it obvious this is a healthy stdio server waiting for a client,
            # not a hung command — the window will otherwise just sit silently.
            err_console.print(
                "  Server ready on stdio, waiting for a Claude client to connect.\n"
                "  This is NORMAL - the window will look idle. You do not run this by hand;\n"
                "  Claude spawns it via 'exa mcp install'. Press Ctrl+C to stop.",
                style="dim",
            )
            asyncio.run(run_server(client, server_name=name, read_only=read_only))
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
    allow_writes: Annotated[
        bool,
        typer.Option(
            "--allow-writes/--read-only",
            help="Add --allow-writes to the server args [default: read-only]",
        ),
    ] = False,
) -> None:
    """Print the MCP client config JSON to stdout.

    Outputs the JSON block to paste into Claude Desktop settings under
    'Developer > Model Context Protocol'. Use --docs to get the config for
    the Exabeam API documentation MCP server instead of the live tenant server.

    \b
    Examples:
      uv run exa mcp config
      uv run exa mcp config --tenant csnafusion
      uv run exa mcp config --docs
    """
    if docs:
        docs_name = name if name != "exabeam" else "exabeam-docs"
        cfg = _generate_docs_config(server_name=docs_name)
    else:
        cfg = _generate_config(tenant=tenant, server_name=name, allow_writes=allow_writes)

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
    allow_writes: Annotated[
        bool,
        typer.Option(
            "--allow-writes/--read-only",
            help="Configure the server to allow write tools [default: read-only]",
        ),
    ] = False,
    print_only: Annotated[
        bool,
        typer.Option(
            "--print/--write",
            help="Print the config + where each client expects it, instead of writing it.",
        ),
    ] = False,
) -> None:
    """Install (or print) the MCP server config for a Claude client.

    By default, merges the server entry into the detected Claude Desktop config
    file. Use --print to instead show the exact config block and the config path
    for every client/OS (Desktop on Windows/macOS, and Claude Code) so you can set
    it up by hand — no assumptions about which client you run.

    Run 'exa auth' first to cache credentials; restart the client after installing.
    Use --docs for the documentation-only Exabeam Developer Portal server (no tenant,
    no local repo needed).

    \b
    Examples:
      uv run exa mcp install --tenant csnafusion          # write to the detected Desktop
      uv run exa mcp install --tenant csnafusion --print   # show config + all client paths
      uv run exa mcp install --docs                        # docs-only (developers.exabeam.com)
    """
    if docs:
        server_name = name if name != "exabeam" else "exabeam-docs"
        cfg_block = _generate_docs_config(server_name=server_name)
    else:
        server_name = name
        cfg_block = _generate_config(
            tenant=tenant, server_name=server_name, allow_writes=allow_writes
        )

    server_config = cfg_block["mcpServers"][server_name]

    if print_only:
        _print_setup_guidance(server_name, server_config, docs=docs)
        return

    config_path = _claude_config_path()
    _install_config(server_name, server_config, config_path)

    console.print(
        f"  Installed '[bold]{server_name}[/bold]' -> {config_path}",
        style="green",
    )

    # If a Store (sandboxed) Desktop is present, it will NOT read this config.
    store = _store_desktop_dir()
    if store is not None:
        err_console.print(
            "\n  [yellow]Heads up:[/yellow] a Microsoft Store install of Claude Desktop was detected.\n"
            "  The Store build is sandboxed and [bold]cannot run local MCP servers[/bold] - it will\n"
            "  ignore the config just written. If your Claude Desktop shows no MCP servers,\n"
            "  install the standalone app from [bold]claude.ai/download[/bold] (or use Claude Code).",
            style="dim",
        )

    if not docs:
        console.print(
            "  Prerequisite: run [bold]exa auth[/bold] first to cache credentials in keyring.",
            style="yellow",
        )
    console.print(
        "\n  Next: fully quit and reopen Claude Desktop (not just close the window).\n"
        f"  Then check Settings -> Developer for the '[bold]{server_name}[/bold]' server.\n"
        "  You do NOT run 'exa mcp serve' yourself - Claude spawns it on demand.\n"
        "  Not sure which client/OS you're on? Re-run with [bold]--print[/bold] to see every path.",
        style="dim",
    )
