"""MCP stdio server entry point.

Manages a single ExaClient for the process lifetime; token refresh is handled
automatically by ExaClient on every request (60s before expiry).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient


async def run_server(client: ExaClient, server_name: str = "exabeam") -> None:
    """Run the Exabeam MCP server over stdio.

    This is a blocking async coroutine — call via asyncio.run().
    Claude Desktop spawns this process and communicates over stdin/stdout.
    """
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    from exa.mcp.tools import TOOL_DEFS, dispatch_tool

    server = Server(server_name)

    @server.list_tools()
    async def handle_list_tools():
        return TOOL_DEFS

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        return await dispatch_tool(client, name, arguments or {})

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
