"""Smoke tests for JWTINSPECT. Standard library only, no network."""
import base64
import hashlib
import hmac
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from jwtinspect import TOOL_NAME, TOOL_VERSION, inspect_token  # noqa: E402
from jwtinspect.cli import main  # noqa: E402
from jwtinspect.core import JWTFormatError, SEVERITY_ORDER  # noqa: E402


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, secret: str = None) -> str:
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode("ascii")
    if secret is None:
        return h + "." + p + "."
    mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return h + "." + p + "." + _b64(mac)


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "jwtinspect")
        self.assertTrue(TOOL_VERSION)

    def test_alg_none_is_critical(self):
        tok = make_token({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999, "iat": 1})
        res = inspect_token(tok, now=1000)
        codes = {f.code for f in res.findings}
        self.assertIn("ALG_NONE", codes)
        self.assertEqual(res.max_severity, "critical")
        self.assertFalse(res.ok)

    def test_weak_secret_detected(self):
        tok = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999, "iat": 1}, secret="secret")
        res = inspect_token(tok, now=1000)
        self.assertEqual(res.cracked_secret, "secret")
        self.assertIn("WEAK_SECRET", {f.code for f in res.findings})

    def test_strong_secret_not_flagged(self):
        tok = make_token(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1", "exp": 9999999999, "iat": 1, "iss": "x"},
            secret="a-very-long-high-entropy-random-secret-9f8e7d6c",
        )
        res = inspect_token(tok, now=1000)
        self.assertIsNone(res.cracked_secret)
        self.assertTrue(res.ok)

    def test_missing_exp(self):
        tok = make_token(
            {"alg": "HS256"},
            {"sub": "1", "iat": 1},
            secret="a-very-long-high-entropy-random-secret-9f8e7d6c",
        )
        res = inspect_token(tok, now=1000)
        self.assertIn("NO_EXP", {f.code for f in res.findings})

    def test_expired_is_low(self):
        tok = make_token(
            {"alg": "HS256"},
            {"sub": "1", "exp": 500, "iat": 1},
            secret="a-very-long-high-entropy-random-secret-9f8e7d6c",
        )
        res = inspect_token(tok, now=1000)
        self.assertIn("EXPIRED", {f.code for f in res.findings})

    def test_required_claim(self):
        tok = make_token(
            {"alg": "HS256"},
            {"sub": "1", "exp": 9999999999, "iat": 1},
            secret="a-very-long-high-entropy-random-secret-9f8e7d6c",
        )
        res = inspect_token(tok, now=1000, required_claims=["iss"])
        self.assertIn("MISSING_REQUIRED_CLAIM", {f.code for f in res.findings})

    def test_invalid_token_raises(self):
        with self.assertRaises(JWTFormatError):
            inspect_token("not-a-jwt")
        with self.assertRaises(JWTFormatError):
            inspect_token("a.b.c.d")

    def test_max_lifetime(self):
        tok = make_token(
            {"alg": "HS256"},
            {"sub": "1", "iat": 1000, "exp": 1000 + 100000},
            secret="a-very-long-high-entropy-random-secret-9f8e7d6c",
        )
        res = inspect_token(tok, now=1000, max_lifetime_seconds=3600)
        self.assertIn("LONG_LIFETIME", {f.code for f in res.findings})

    def test_severity_ordering_sane(self):
        self.assertLess(SEVERITY_ORDER["low"], SEVERITY_ORDER["critical"])


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_alg_none_exit_one_json(self):
        tok = make_token({"alg": "none"}, {"sub": "1"})
        code, out, _ = self._run(["--format", "json", "inspect", tok, "--now", "1000"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["max_severity"], "critical")

    def test_clean_token_exit_zero(self):
        tok = make_token(
            {"alg": "HS256"},
            {"sub": "1", "exp": 9999999999, "iat": 1, "iss": "acme"},
            secret="a-very-long-high-entropy-random-secret-9f8e7d6c",
        )
        code, out, _ = self._run(["inspect", tok, "--now", "1000"])
        self.assertEqual(code, 0)
        self.assertIn("No findings.", out)

    def test_invalid_token_exit_two(self):
        code, _, err = self._run(["inspect", "garbage"])
        self.assertEqual(code, 2)
        self.assertIn("not a valid JWT", err)

    def test_missing_file_exit_two(self):
        """--file pointing to a non-existent path should exit 2 with a clear error."""
        code, _, err = self._run(["inspect", "--file", "/nonexistent/path/token.jwt"])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_empty_token_file_exit_two(self):
        """An empty token file should exit 2 with a clear error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jwt", delete=False) as tf:
            tf.write("   \n")
            tmp_path = tf.name
        try:
            code, _, err = self._run(["inspect", "--file", tmp_path])
            self.assertEqual(code, 2)
            self.assertIn("error", err.lower())
        finally:
            os.unlink(tmp_path)

    def test_negative_max_lifetime_exit_two(self):
        """--max-lifetime with a non-positive value should exit 2."""
        tok = make_token({"alg": "HS256"}, {"sub": "1", "exp": 9999999999, "iat": 1},
                         secret="a-very-long-high-entropy-random-secret-9f8e7d6c")
        code, _, err = self._run(["inspect", tok, "--max-lifetime", "-60"])
        self.assertEqual(code, 2)
        self.assertIn("max-lifetime", err)

    def test_empty_token_string_raises_format_error(self):
        """inspect_token on an empty string must raise JWTFormatError."""
        from jwtinspect.core import JWTFormatError
        with self.assertRaises(JWTFormatError):
            inspect_token("")
        with self.assertRaises(JWTFormatError):
            inspect_token("   ")

    def test_wordlist_file_not_found_exit_two(self):
        """--wordlist pointing to a missing file should exit 2."""
        tok = make_token({"alg": "HS256"}, {"sub": "1", "exp": 9999999999, "iat": 1},
                         secret="a-very-long-high-entropy-random-secret-9f8e7d6c")
        code, _, err = self._run(["inspect", tok, "--wordlist", "/no/such/file.txt"])
        self.assertEqual(code, 2)
        self.assertIn("wordlist", err.lower())

    def test_mcp_server_compiles(self):
        """mcp_server module must import cleanly (no broken references)."""
        import importlib
        import jwtinspect.mcp_server  # noqa: F401
        # Re-import to exercise the module-level code path
        importlib.reload(jwtinspect.mcp_server)


if __name__ == "__main__":
    unittest.main()
