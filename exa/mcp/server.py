"""MCP server entry points — stdio and HTTP/SSE transports.

Manages a single ExaClient for the process lifetime; token refresh is handled
automatically by ExaClient on every request (60s before expiry).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exa.client import ExaClient


class TenantSession:
    """Mutable holder for the active ExaClient.

    The MCP server is long-lived and can be re-pointed at a different tenant at
    runtime via the set_active_tenant tool. Handlers read `session.client` on
    every call, so a switch takes effect for all subsequent tool calls. The
    read_only posture is fixed for the process (set at serve time) and does not
    change on a tenant switch.
    """

    def __init__(self, client: "ExaClient", *, read_only: bool = False) -> None:
        self._client = client
        self.read_only = read_only

    @property
    def client(self) -> "ExaClient":
        return self._client

    def switch(self, tenant: str) -> "ExaClient":
        """Point at a different configured tenant and refresh its token.

        Creates a fresh ExaClient (credentials loaded from the OS credential
        store by nickname), authenticates it, then swaps it in and closes the
        old one. Raises on unknown tenant or auth failure -- the caller keeps
        the previous client if this raises before the swap.
        """
        from exa.client import ExaClient

        new = ExaClient(tenant=tenant)
        new.authenticate()
        old, self._client = self._client, new
        try:
            old.close()
        except Exception:
            pass
        return new


def _build_mcp_server(client: ExaClient, server_name: str, *, read_only: bool = False):
    """Construct and return a configured mcp.server.Server instance.

    When read_only is True the four write tools are neither advertised nor
    dispatched -- a hard gate enforced regardless of what the client requests.
    """
    from mcp.server import Server

    from exa.mcp.tools import dispatch_tool, visible_tools

    session = TenantSession(client, read_only=read_only)
    server = Server(server_name)
    tools = visible_tools(read_only=read_only)

    @server.list_tools()
    async def handle_list_tools():
        return tools

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        return await dispatch_tool(
            session.client,
            name,
            arguments or {},
            read_only=session.read_only,
            session=session,
        )

    return server


async def run_server(
    client: ExaClient, server_name: str = "exabeam", *, read_only: bool = False
) -> None:
    """Run the Exabeam MCP server over stdio (Claude Desktop subprocess mode)."""
    from mcp.server.stdio import stdio_server

    server = _build_mcp_server(client, server_name, read_only=read_only)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


async def run_sse_server(
    client: ExaClient,
    server_name: str = "exabeam",
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    read_only: bool = False,
) -> None:
    """Run the Exabeam MCP server over HTTP/SSE (remote connector mode).

    Exposes:
      GET  /sse        — SSE connection endpoint (add this URL to Claude Desktop)
      POST /messages/  — message ingestion endpoint
    """
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    server = _build_mcp_server(client, server_name, read_only=read_only)
    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await server.run(*streams, server.create_initialization_options())

    starlette_app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )

    config = uvicorn.Config(starlette_app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()
