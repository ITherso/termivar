# Active TLS negotiation review

The non-default scanner and CLI feature `tls-negotiation-review` adds a small,
active TLS handshake matrix to the existing `WebAssessmentRuntime`. It is an
Experimental capability on the unreleased `0.10.0-alpha.3` development line.
It is outside `default`, every aggregate feature, the seven-member
`release-bundle`, and the published `v0.10.0-alpha.2` archives.

Compilation does not activate it. A feature-enabled binary requires explicit
`web-review` selection and a credential-free DNS HTTPS target:

```console
termivar scan https://app.example.test/ \
  --profile web-review \
  --tls-negotiation-review \
  --report-dir assessment-active-tls
```

The operator must already be authorized to make connections to that exact
host, SNI and effective port. HTTP targets, IP-literal targets and URLs carrying
userinfo are rejected before runtime or output reservation. The option is not
a general port scanner and does not accept a separate destination, SNI, trust
store, protocol list or cipher list.

## Fixed matrix and transport boundary

V1 has exactly five rows in this order:

1. TLS 1.3 with the Rustls ring default provider;
2. TLS 1.2 with the same provider;
3. TLS 1.1 — not tested because the client backend does not support it;
4. TLS 1.0 — not tested because the client backend does not support it; and
5. legacy cipher suites — not tested because the client backend does not
   implement a safe reviewed offer for this matrix.

Only the first two rows may connect. They execute sequentially, one connection
at a time. A single bounded DNS lookup retains at most sixteen addresses and
selects one deterministic address; no alternate-address fallback occurs. Each
cell has a five-second ceiling and the whole child has a ten-second ceiling,
subject to the smaller remaining parent deadline.

The child uses ordinary certificate-chain and hostname validation with the
configured production web roots. It disables resumption and early data and
offers no ALPN. It sends only TLS handshake and close-notify bytes—never an HTTP
request, application payload, credential, cookie, authorization header or
client certificate. There is no retry, redirect, proxy use, conditional request
or connection reuse. A certificate failure is retained as a typed cell outcome;
validation is never disabled to obtain more data.

The direct socket is private to this reviewed child. Construction derives its
host, SNI, port, accounting broker, cancellation token and deadline from the
already narrowed parent authority. It cannot mint a second runtime or create an
independent budget. The fixed owned-HTTPS process fixture may substitute its
loopback address and task-owned root certificate only through the closed
`xml-external-entity-owned-https-test-profile`; production callers cannot supply
that transport profile.

## Bounds and accounting

Each network cell consumes one parent request and one active-verification slot.
The default assessment allowance is enlarged by exactly two only when this
option is selected and the parent still uses its default active limit. Custom
smaller limits continue to win.

Raw TLS ingress is charged through the parent's response-byte accounting. The
additional child bounds are:

- 128 KiB ingress and 64 KiB egress per connection;
- 256 KiB aggregate ingress and 128 KiB aggregate egress;
- at most one in-flight connection;
- at most two dispatched cells; and
- at most sixteen DNS answers considered before deterministic selection.

A read or write that reaches a local or parent ceiling is a budget outcome, not
a successful negotiated cell. Partial bytes and failed handshakes remain
accounted. Cancellation, deadline and parent exhaustion prevent later cells.
If the bounded parent transport audit cannot retain both possible cell receipts,
the child refuses before DNS or connection work. Any stop that leaves a
network-capable row unattempted marks the selected TLS review incomplete.
The three backend-unsupported rows consume zero requests and zero bytes.

## Evidence and interpretation

A completed selected assessment contains the strict optional
`security.tls-negotiation-review-audit/v1` section under policy
`termivar.active-tls-negotiation-review/v1`. It records the fixed methodology,
terminal/dispatch outcomes, raw TLS byte counts and, only for a successful
cell, the protocol and cipher suite Rustls says were negotiated. It does not
save the hostname, IP address, certificate bytes, readable certificate names,
alerts, peer prose or raw transport bytes.

The saved address-selection token describes one deterministic address under the
selected authority. Normal execution obtains that address from the bounded DNS
answers above; the closed owned-HTTPS fixture uses its prevalidated fixed
loopback binding instead and does not claim that DNS ran.

A negotiated row establishes only that this exact client offer completed with
that protocol/cipher at that connection attempt under the configured trust
material. It does not enumerate everything the server supports, authenticate
the operator or deployment, prove worldwide trust, establish revocation or
certificate-transparency status, or show application behavior. A failed,
cancelled, unavailable or budget-limited row does not prove the server rejected
or lacks the offered protocol. Client-backend-unsupported rows say nothing
about the server.

The audit produces no assessment item or finding. JSON, HTML, Markdown and CSV
render from the same typed state. Feature-independent saved readers validate
the exact matrix even when the producer feature is absent. Offline Verify checks
bundle integrity and supported report consistency, not target truth. Compare
separates methodology, coverage and successful capability-observation changes;
a one-sided or changed row is not vulnerability, exploitation, impact,
hardening or remediation evidence.

The passive `tls-observation` option remains separate. It observes a bounded
leaf certificate only on existing successful HTTP response connections and
never opens a connection. Enabling active negotiation does not turn the passive
audit's `active_tls_matrix` field into performed work, and passive response
observations are not reused as active-matrix proof.

## Owned-fixture acceptance

The four-platform feature-enabled process acceptance uses the existing isolated
owned HTTPS fixture and repository test CA. Two scans each retain their ordinary
HTTP request trace and add exactly two TLS-only connections, ordered TLS 1.3 then
TLS 1.2. The server independently records the expected SNI, negotiated
protocol/cipher, absent ALPN and zero decrypted application bytes. It then shuts
down before bundle Verify, self-Compare and controlled Compare, proving those
operations remain offline.

This acceptance is evidence for the fixed fixture and exact binaries only. It
is not a universal interoperability, performance, production-readiness or
server-security result.

## Explicit non-goals

V1 does not:

- enumerate every server protocol, cipher suite, curve or signature scheme;
- implement TLS 1.1, TLS 1.0, RC4, DES, EXPORT or another obsolete primitive;
- disable certificate validation or infer support from the client library;
- send HTTP/application data or any credential;
- fetch AIA, CRL, OCSP, CT or certificate-linked URLs;
- perform revocation, source authentication, exploit or impact validation;
- prove a vulnerability, compliance state, remediation or production readiness;
  or
- enter the stock release package merely because it compiles.

The [Rustls documentation](https://docs.rs/rustls/0.23/),
[TLS 1.3 specification](https://www.rfc-editor.org/rfc/rfc8446.html), and
[HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html) are development
references. Runtime execution never retrieves them.
