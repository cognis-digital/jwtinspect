"""Command-line interface for JWTINSPECT.

Subcommand:
    inspect   Decode + lint a JWT from an argument, --file, or stdin.

Global:
    --version
    --format {table,json}

Exit codes:
    0  no finding at or above medium severity
    1  one or more findings at medium severity or worse
    2  usage / format / I/O error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import SEVERITY_ORDER, JWTFormatError, inspect_token


def _read_token(args: argparse.Namespace) -> str:
    if args.token:
        return args.token
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    data = sys.stdin.read().strip()
    if not data:
        raise ValueError("no token provided (argument, --file, or stdin)")
    return data


def _load_wordlist(path: Optional[str]) -> Optional[List[str]]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def _render_table(result, stream) -> None:
    h = result.header
    p = result.payload
    print(f"== {TOOL_NAME} {TOOL_VERSION} ==", file=stream)
    print(f"alg           : {h.get('alg')}", file=stream)
    print(f"typ           : {h.get('typ')}", file=stream)
    print(f"signature     : {'present' if result.signature_present else 'ABSENT'}", file=stream)
    print(f"payload claims: {', '.join(sorted(p)) or '(none)'}", file=stream)
    if result.cracked_secret is not None:
        print(f"weak secret   : {result.cracked_secret!r}", file=stream)
    print(f"max severity  : {result.max_severity.upper()}", file=stream)
    print("", file=stream)
    if not result.findings:
        print("No findings.", file=stream)
        return
    print(f"{'SEVERITY':<9} {'CODE':<24} MESSAGE", file=stream)
    print(f"{'-' * 8:<9} {'-' * 23:<24} {'-' * 40}", file=stream)
    for f in result.findings:
        print(f"{f.severity.upper():<9} {f.code:<24} {f.message}", file=stream)
        if f.detail:
            print(f"{'':<9} {'':<24} -> {f.detail}", file=stream)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Decode JWTs and lint for alg=none, weak secrets, and "
        "missing claims (defensive / authorized testing only).",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    insp = sub.add_parser("inspect", help="decode + lint a JWT")
    insp.add_argument("token", nargs="?", help="the JWT; omit to read --file or stdin")
    insp.add_argument("-f", "--file", help="read the token from a file")
    insp.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="CLAIM",
        help="require this claim to be present (repeatable)",
    )
    insp.add_argument(
        "--max-lifetime",
        type=int,
        default=None,
        metavar="SECONDS",
        help="flag tokens whose exp-iat exceeds this many seconds",
    )
    insp.add_argument(
        "--wordlist",
        help="newline-delimited weak-secret list for HMAC confirmation",
    )
    insp.add_argument(
        "--no-secret-check",
        action="store_true",
        help="skip the weak-HMAC-secret dictionary check",
    )
    insp.add_argument(
        "--now",
        type=int,
        default=None,
        metavar="EPOCH",
        help="override 'current time' for exp/nbf checks (testing)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "inspect":
        parser.error("unknown command")
        return 2

    try:
        token = _read_token(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        wordlist = _load_wordlist(args.wordlist)
    except OSError as exc:
        print(f"error: cannot read wordlist: {exc}", file=sys.stderr)
        return 2

    try:
        result = inspect_token(
            token,
            now=args.now,
            required_claims=args.require,
            max_lifetime_seconds=args.max_lifetime,
            wordlist=wordlist,
            check_weak_secret=not args.no_secret_check,
        )
    except JWTFormatError as exc:
        print(f"error: not a valid JWT: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        json.dump(result.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        _render_table(result, sys.stdout)

    # Non-zero exit when anything at medium severity or worse is present.
    if SEVERITY_ORDER[result.max_severity] >= SEVERITY_ORDER["medium"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
