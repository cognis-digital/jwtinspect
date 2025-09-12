"""JWTINSPECT — Decode JWTs and lint for alg=none, weak secrets, and missing claims."""
from jwtinspect.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
