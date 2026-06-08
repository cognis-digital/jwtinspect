"""JWTINSPECT - Decode JWTs and lint for common security weaknesses.

Defensive / authorized-testing tool. Analysis, triage and detection only:
it decodes tokens and lints headers/claims for misconfigurations such as
``alg=none``, weak HMAC secrets (dictionary check against a supplied or
built-in list), and missing/insecure standard claims. It performs NO
attack, forging, or unauthorized signing of tokens.
"""
from .core import (
    Finding,
    InspectionResult,
    Severity,
    decode_segment,
    inspect_token,
    lint_token,
)

TOOL_NAME = "jwtinspect"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "InspectionResult",
    "Severity",
    "decode_segment",
    "inspect_token",
    "lint_token",
]
