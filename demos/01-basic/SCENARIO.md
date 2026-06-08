# Demo 01 - Basic JWT triage

This demo shows JWTINSPECT flagging two classic JWT misconfigurations in a
single CI-style pass: an `alg=none` token and an HMAC token signed with a
weak, guessable secret.

## Files

- `alg_none.jwt` - a token whose header sets `"alg": "none"` and carries **no**
  signature segment. A naive verifier that honors the header algorithm would
  accept attacker-forged tokens.
- `weak_secret.jwt` - an `HS256` token signed with the secret `secret`
  (present in the built-in weak-secret dictionary) and missing an `exp` claim.

> These are sample/test tokens for demonstration only. No real credentials.

## Run it

```bash
# alg=none -> CRITICAL, exits 1
python -m jwtinspect inspect --file demos/01-basic/alg_none.jwt

# weak HMAC secret + missing exp -> CRITICAL, exits 1, JSON for CI
python -m jwtinspect --format json inspect --file demos/01-basic/weak_secret.jwt

# Pipe from stdin and require an issuer claim
cat demos/01-basic/weak_secret.jwt | python -m jwtinspect inspect --require iss
```

## Expected

Both tokens produce a non-zero exit code (`1`) because findings reach at least
`medium` severity, so they fail a CI gate.

- `alg_none.jwt`: `ALG_NONE` (critical), plus `NO_EXP` / `NO_IAT`.
- `weak_secret.jwt`: `WEAK_SECRET` (critical) with the confirmed secret
  `'secret'`, plus `NO_EXP`.

A well-formed token (signed with a strong secret, carrying `exp`/`iat`/`iss`)
produces no medium-or-worse findings and exits `0`.
