# Supplied-session authenticated assessment

The non-default `supplied-session-review` feature adds one deliberately narrow
authenticated collection path to an explicit `web-review` assessment. It is a
development Preview, is not compiled into the curated `release-bundle`, and
does nothing unless the operator supplies both a policy and one out-of-band
Authorization value.

This first slice supports one operator-declared principal and one complete
`Authorization` header value. It does not load a browser profile, discover a
login form, manage cookies, refresh a token, perform OAuth or MFA, send a request
body or non-GET method, or enable an existing active vulnerability family under
the supplied credential. Application-defined `GET` handling can still have
server-side effects, so the operator must authorize every selected resource. A
principal alias is an operator assertion, not authenticated identity.

## Build and invoke

Build an isolated candidate with the feature selected explicitly:

```bash
cargo build --locked -p termivar-cli \
  --no-default-features --features supplied-session-review
```

For an authorized HTTPS application:

```bash
termivar scan https://app.example.test/app/ \
  --profile web-review \
  --session-policy ./session-policy.toml \
  --session-auth-file ./authorization.secret \
  --report-dir ./assessment-session
```

`--session-auth-env` and `--session-auth-stdin` are alternatives to the regular
file. Exactly one source is required. There is no raw credential argument. HTTP
is refused except for numeric-loopback development fixtures; the exception does
not relax TLS for a real target.

The secret source contains the complete bounded header value, for example a
scheme and its credentials. Its bytes must not contain control characters. The
value is never a target, a scope grant, a principal identifier, or a report
field.

## Policy V1

The strict bounded policy is TOML. This example selects two query-free,
root-relative resources beneath the already selected application:

```toml
schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-reader"
credential_mechanism = "authorization_header"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000
```

The selected target supplies the immutable scheme, host, effective port and
application directory. V1 accepts one to four resource paths. Paths and the
health endpoint must remain inside that application, be query- and
fragment-free, and pass the raw-reference safety checks. Login, logout, action,
download and administration-style paths are rejected by V1. This bounded
denylist narrows accidental selection; it does not prove that an admitted `GET`
is side-effect-free. A discovered link cannot extend the policy.

The policy may allow at most nine supplied-session requests. It must budget one
startup health check plus one resource request and one following health check
for every selected resource. Per-body, total-response and wall-time limits are
narrowing ceilings; the assessment's smaller parent limits, cancellation and
deadline always win.

The health response must be a complete successful JSON representation whose
named top-level field is exactly the Boolean `true`. A `200` login page, a
truthy string, missing field, duplicate JSON key, truncated body, redirect or
transport error does not establish healthy session context.

## Execution and evidence

The runtime creates a context-isolated, redirect-disabled, no-proxy child of the
existing assessment broker. It sends the configured Authorization value only to
the exact selected application and never forwards it across a redirect. A
startup health check gates collection. Each dispatched resource is followed by
a deterministic health checkpoint before it can become committed authenticated
coverage; loss stops later supplied-session work.
There is no silent anonymous retry or refresh.

Each complete `200` resource response remains a body-free staged observation
until its immediately following health checkpoint is both healthy and committed.
Only then does it count as authenticated `committed` coverage. If that checkpoint
is unhealthy or unavailable, the response remains `health_unqualified`, counts
as dispatched activity, and does not count as authenticated coverage.

The central report adds `security.supplied-session-audit/v1`. It records opaque
policy, application, principal and resource references; the operator-declared
assurance; checkpoint and resource outcomes; and reconciled request/byte counts.
The configured response-byte limit and an exact exceeded flag are separate from
the unclamped transport count because the broker charges a final delivered chunk
even when only the bounded prefix is retained.
It never records the Authorization value, response body, readable resource URL,
or an unkeyed credential digest. Evidence committed before a later loss remains
qualified by its recorded checkpoints. Startup and boundary checks do not prove
continuous authentication between them.

This slice produces an audit, not a vulnerability item. Exploit execution and
impact validation remain `not_performed`. An empty or interrupted authenticated
coverage window is not proof that the application denied access or is secure.
Offline Verify checks bundle integrity; Compare describes audit/context and
coverage changes without treating logout or a different principal as
remediation.

## Secret boundary

Policy validation happens before the selected secret source is read. File input
uses the shared regular-file, final-component no-follow and bounded-read
contract; trusted parents and mutable-file limitations still apply. Owned CLI
intake bytes are guarded through constructor handoff, but this is not a claim
that operating-system environment storage, allocator history, process dumps,
HTTP-library buffers or every downstream copy is erased. See
[Credential-input guarantees and limits](credential-input.md).

## Protocol references

The V1 boundaries follow the current [OWASP Session Management Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
for encrypted session transport and scoped session handling, and [RFC
9110](https://www.rfc-editor.org/rfc/rfc9110.html) for HTTP semantics. Cookie
processing is deliberately absent from this slice; future cookie work must apply
the protocol scope rules in [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html)
in addition to the operator's narrower application authority. These references
define protocol expectations, not proof that an observed principal or session is
authentic.
