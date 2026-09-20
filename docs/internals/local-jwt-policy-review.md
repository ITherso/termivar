# Local JWT policy review

`jwt-policy-review` is a non-default, development-only scanner and CLI feature.
Its local JWT evaluator performs no network operation and adds no target request.
The surrounding `scan` command still performs its ordinary authorized
web-review requests. The feature is not part of `default`, the seven-member
`release-bundle`, or the published `v0.10.0-alpha.2` archives. Compilation alone
activates nothing.

Build a feature-specific development binary:

```bash
cargo build --locked -p termivar-cli --no-default-features \
  --features jwt-policy-review
```

Select the review only with explicit `web-review`, one strict policy, one local
public JWK, and exactly one token source:

```bash
termivar scan <AUTHORIZED_EXACT_ROOT> \
  --profile web-review \
  --jwt-policy jwt-policy.toml \
  --jwt-public-jwk public-key.jwk \
  --jwt-token-file compact-token.txt \
  --report-dir jwt-assessment
```

The token may instead come from `--jwt-token-env ENV_VAR` or
`--jwt-token-stdin`. Token bytes never belong in argv. The three token-source
options are mutually exclusive. The policy plus the closed public-JWK structure
and canonical 32-byte `x`/`y` coordinates are validated before the token is
read. Curve membership and signature validity are decided only during local
ES256 verification; failure remains unauthenticated with
`local_signature_status=invalid`. The original token, expected claim values, JWK
coordinates, input paths, and environment-variable name are not saved in the
audit or ordinary diagnostics.

The policy file is strict TOML with schema `security.jwt-local-policy/v1` and
these fields. Intended `typ`, issuer, and audience are mandatory V1 bindings;
none of the three checks can be disabled:

```toml
schema = "security.jwt-local-policy/v1"
policy_reference = "owned-fixture"
policy_revision = "owned-fixture-v1"
expected_type = "JWT"
expected_issuer = "https://issuer.example.invalid/"
expected_audience = "termivar-fixture"
required_claims = ["sub"]
require_expiration = true
allowed_clock_skew_seconds = 30
```

`policy_reference` and `policy_revision` are bounded, non-secret operator
labels. The revision must change whenever the private expected-value or
required-claim policy changes; Termivar cannot derive a publicly comparable
policy digest without exposing a dictionary-testable identifier for those
private values. Reports also include a SHA-256 identifier over the exact
supplied public P-256 point. That public-key identifier detects changed key
bytes but does not authenticate the key, its owner, or its source.

V1 accepts only a compact JWS whose protected header and claims fit the fixed
parser bounds and whose algorithm is exactly ES256. The local JWK must be an
EC/P-256/ES256 public key containing exactly `kty`, `crv`, `alg`, `x`, and `y`.
This structural admission does not establish that the coordinates are on the
P-256 curve before verification.
Private key material, embedded keys, `jku`, `x5u`, JWE, nested or compressed
JOSE, critical headers, unencoded payloads, unsecured algorithms, and other
algorithms are rejected or unsupported. Duplicate JSON keys and structural or
byte-limit overflows fail closed.

The audit keeps four states separate:

- parsing says only whether the token belongs to the supported compact profile;
- policy consistency says only whether the mandatory intended `typ`, issuer and
  audience bindings plus the selected local claim/time rules held;
- local signature status says only whether ES256 verification succeeded against
  the explicitly supplied local public key;
- target acceptance is always `not_performed` in this slice.

A parsed token is not thereby signature-verified. A locally verified signature
does not authenticate the issuer or source, establish that a server accepts the
token, or establish authorization. The evaluator never forwards or replays the
token, retrieves a remote key, or adds a target request. Policy, public-JWK and
token files must be local regular files; Windows UNC, device and named-pipe
namespaces are rejected before open. Mapped drives, mounted network filesystems
and mutable trusted-parent paths are not remotely distinguishable by this
lexical guard, so the operator remains responsible for supplying a trusted local
parent. Exploit execution and impact validation are not performed. The
evaluation clock is the local system clock and is not independently
authenticated.

Reports use `security.jwt-policy-review-audit/v1` and contain only bounded,
value-free status, methodology, policy-violation class, and zero-network facts.
The strict saved-report reader and semantic comparison keep parsing, local
policy, local signature, target acceptance, methodology, and coverage changes
distinct. Methodology comparison includes the declared policy revision and the
actual public-key-byte identifier. Offline Verify checks bundle integrity; it
does not authenticate the token, key, issuer, source, or target claim.

## Primary development references

These references define the reviewed development contract; they are not
scan-time fetch targets and do not authorize any runtime network request:

- [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 7515 — JSON Web Signature and compact JWS](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7518 — JSON Web Algorithms, including ES256](https://www.rfc-editor.org/rfc/rfc7518.html)
- [RFC 7519 — JSON Web Token and NumericDate](https://www.rfc-editor.org/rfc/rfc7519.html)
- [RFC 7797 — JWS unencoded payload (`b64`), rejected by V1](https://www.rfc-editor.org/rfc/rfc7797.html)
- [`ring` 0.17.14 fixed ES256 verification API](https://docs.rs/ring/0.17.14/ring/signature/static.ECDSA_P256_SHA256_FIXED.html)
