"""JWTINSPECT MCP server — exposes inspect_token() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from jwtinspect.core import JWTFormatError, inspect_token


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-jwtinspect[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-jwtinspect[mcp]'")
        return 1
    app = FastMCP("jwtinspect")

    @app.tool()
    def jwtinspect_scan(target: str) -> str:
        """Decode JWTs and lint for alg=none, weak secrets, and missing claims. Returns JSON findings."""
        if not target or not target.strip():
            return json.dumps({"error": "empty token"})
        try:
            result = inspect_token(target.strip())
        except JWTFormatError as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result.to_dict(), indent=2)

    app.run()
    return 0
