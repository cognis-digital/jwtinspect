"""Core JWT decode + lint engine for JWTINSPECT.

Standard library only. No network access.

The engine never forges or signs tokens. It only decodes the base64url
segments and inspects header + claims for known-weak configurations.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Severity ranking (higher = worse). Used for exit-code / sorting decisions.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A small built-in list of notoriously weak HMAC secrets. This mirrors the
# spirit of jwt_tool's quick dictionary check. It is intentionally tiny;
# real audits should pass --wordlist with a larger corpus.
BUILTIN_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "changeme",
    "admin",
    "jwt",
    "jwtsecret",
    "your-256-bit-secret",
    "your_jwt_secret",
    "supersecret",
    "test",
    "key",
    "qwerty",
    "secretkey",
    "mysecret",
]

# Registered HMAC algorithms we can confirm a secret against.
_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JWTFormatError(ValueError):
    """Raised when a token is not a structurally valid JWT."""


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"code": self.code, "severity": self.severity, "message": self.message}
        if self.detail is not None:
            d["detail"] = self.detail
        return d


@dataclass
class InspectionResult:
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature_present: bool
    findings: List[Finding] = field(default_factory=list)
    cracked_secret: Optional[str] = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def ok(self) -> bool:
        """True when nothing more serious than 'low' was found."""
        return SEVERITY_ORDER[self.max_severity] < SEVERITY_ORDER["medium"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "payload": self.payload,
            "signature_present": self.signature_present,
            "max_severity": self.max_severity,
            "ok": self.ok,
            "cracked_secret": self.cracked_secret,
            "findings": [f.to_dict() for f in self.findings],
        }


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise JWTFormatError(f"invalid base64url segment: {exc}") from exc


def decode_segment(segment: str) -> Dict[str, Any]:
    """Decode a single base64url JSON segment into a dict."""
    raw = _b64url_decode(segment)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JWTFormatError(f"segment is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise JWTFormatError("segment did not decode to a JSON object")
    return obj


def _split(token: str):
    if not isinstance(token, str):
        raise JWTFormatError("token must be a string")
    token = token.strip()
    if not token:
        raise JWTFormatError("token is empty")
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise JWTFormatError(
            f"expected 2 or 3 dot-separated segments, got {len(parts)}"
        )
    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2] if len(parts) == 3 else ""
    return header_b64, payload_b64, sig_b64


def _try_crack_hmac(
    header_b64: str,
    payload_b64: str,
    sig_b64: str,
    alg: str,
    wordlist: List[str],
) -> Optional[str]:
    """Return a secret from *wordlist* that validates the signature, else None.

    This only confirms whether a token was signed with a *known-weak* secret.
    It is a defensive detection ("is this token using a guessable key?"),
    not an offline brute force engine.
    """
    hash_alg = _HMAC_ALGS.get(alg.upper())
    if hash_alg is None or not sig_b64:
        return None
    try:
        expected = _b64url_decode(sig_b64)
    except JWTFormatError:
        return None
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    for candidate in wordlist:
        if not isinstance(candidate, str):
            continue
        try:
            mac = hmac.new(candidate.encode("utf-8"), signing_input, hash_alg).digest()
        except (TypeError, ValueError):
            continue
        if hmac.compare_digest(mac, expected):
            return candidate
    return None


def lint_token(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    signature_present: bool,
    *,
    now: Optional[int] = None,
    required_claims: Optional[List[str]] = None,
    max_lifetime_seconds: Optional[int] = None,
) -> List[Finding]:
    """Lint a decoded header/payload pair, returning a list of findings."""
    if now is None:
        now = int(time.time())
    findings: List[Finding] = []

    alg = header.get("alg")
    alg_norm = str(alg).lower() if alg is not None else None

    # --- alg=none -----------------------------------------------------
    if alg_norm in ("none", ""):
        findings.append(
            Finding(
                "ALG_NONE",
                Severity.CRITICAL,
                "Token uses the 'none' algorithm (unsigned).",
                "An attacker can craft arbitrary tokens. Reject 'none' on the "
                "verifier and pin an explicit allow-list of algorithms.",
            )
        )
    elif alg is None:
        findings.append(
            Finding(
                "ALG_MISSING",
                Severity.HIGH,
                "Header has no 'alg' field.",
                "Verifiers that default to a permissive algorithm are exploitable.",
            )
        )

    # --- alg confusion potential -------------------------------------
    if alg_norm and alg_norm.startswith("hs") and signature_present:
        # informational; flagged together with a weak-secret crack below
        pass
    if alg_norm in ("rs256", "es256", "ps256") and "jwk" in header:
        findings.append(
            Finding(
                "EMBEDDED_JWK",
                Severity.HIGH,
                "Header embeds a 'jwk' public key.",
                "Verifiers that trust the embedded key allow key-injection "
                "forgery. Resolve keys from a trusted store, never the header.",
            )
        )
    if "jku" in header or "x5u" in header:
        findings.append(
            Finding(
                "REMOTE_KEY_URL",
                Severity.MEDIUM,
                "Header references a remote key URL (jku/x5u).",
                "Unrestricted jku/x5u enables SSRF and key-injection. Pin to an "
                "allow-listed host.",
            )
        )

    # --- signature presence ------------------------------------------
    if not signature_present and alg_norm not in ("none", ""):
        findings.append(
            Finding(
                "SIGNATURE_MISSING",
                Severity.HIGH,
                "Token has no signature segment but a signing algorithm is set.",
            )
        )

    # --- claim checks -------------------------------------------------
    if "exp" not in payload:
        findings.append(
            Finding(
                "NO_EXP",
                Severity.MEDIUM,
                "Token has no 'exp' (expiration) claim.",
                "Tokens without expiry are valid forever if leaked.",
            )
        )
    else:
        exp = _as_int(payload.get("exp"))
        if exp is not None and exp < now:
            findings.append(
                Finding(
                    "EXPIRED",
                    Severity.LOW,
                    "Token is expired.",
                    f"exp={exp} is {now - exp}s in the past.",
                )
            )
        iat = _as_int(payload.get("iat"))
        if (
            exp is not None
            and iat is not None
            and max_lifetime_seconds is not None
            and (exp - iat) > max_lifetime_seconds
        ):
            findings.append(
                Finding(
                    "LONG_LIFETIME",
                    Severity.MEDIUM,
                    "Token lifetime exceeds the configured maximum.",
                    f"lifetime={exp - iat}s > max={max_lifetime_seconds}s",
                )
            )

    nbf = _as_int(payload.get("nbf"))
    if nbf is not None and nbf > now:
        findings.append(
            Finding(
                "NOT_YET_VALID",
                Severity.INFO,
                "Token 'nbf' (not-before) is in the future.",
                f"nbf={nbf} is {nbf - now}s ahead.",
            )
        )

    if "alg" in header and "iat" not in payload:
        findings.append(
            Finding(
                "NO_IAT",
                Severity.LOW,
                "Token has no 'iat' (issued-at) claim.",
            )
        )

    for claim in required_claims or []:
        if claim not in payload:
            findings.append(
                Finding(
                    "MISSING_REQUIRED_CLAIM",
                    Severity.MEDIUM,
                    f"Required claim '{claim}' is missing.",
                )
            )

    return findings


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def inspect_token(
    token: str,
    *,
    now: Optional[int] = None,
    required_claims: Optional[List[str]] = None,
    max_lifetime_seconds: Optional[int] = None,
    wordlist: Optional[List[str]] = None,
    check_weak_secret: bool = True,
) -> InspectionResult:
    """Decode and lint a JWT, returning an :class:`InspectionResult`.

    Raises :class:`JWTFormatError` on a structurally invalid token.
    """
    header_b64, payload_b64, sig_b64 = _split(token)
    header = decode_segment(header_b64)
    payload = decode_segment(payload_b64)
    signature_present = bool(sig_b64)

    result = InspectionResult(
        header=header,
        payload=payload,
        signature_present=signature_present,
    )
    result.findings.extend(
        lint_token(
            header,
            payload,
            signature_present,
            now=now,
            required_claims=required_claims,
            max_lifetime_seconds=max_lifetime_seconds,
        )
    )

    # Weak-secret detection (dictionary confirmation only).
    alg = str(header.get("alg", "")).upper()
    if check_weak_secret and alg in _HMAC_ALGS and signature_present:
        words = list(wordlist) if wordlist else list(BUILTIN_WEAK_SECRETS)
        cracked = _try_crack_hmac(header_b64, payload_b64, sig_b64, alg, words)
        if cracked is not None:
            result.cracked_secret = cracked
            result.findings.append(
                Finding(
                    "WEAK_SECRET",
                    Severity.CRITICAL,
                    "Token is signed with a weak/guessable HMAC secret.",
                    f"Confirmed secret from dictionary: {cracked!r}. Rotate the "
                    "key immediately and use a high-entropy random secret.",
                )
            )

    # Stable severity-then-code ordering for deterministic output.
    result.findings.sort(
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.code)
    )
    return result
