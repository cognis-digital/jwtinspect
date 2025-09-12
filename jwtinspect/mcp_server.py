"""JWTINSPECT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from jwtinspect.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-jwtinspect[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-jwtinspect[mcp]'")
        return 1
    app = FastMCP("jwtinspect")

    @app.tool()
    def jwtinspect_scan(target: str) -> str:
        """Decode JWTs and lint for alg=none, weak secrets, and missing claims. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
