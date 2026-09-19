# Existing-connection TLS observation

The non-default scanner and CLI feature `tls-observation` adds a bounded,
passive observer to the existing `WebAssessmentRuntime`. It is a Preview
capability on the unreleased `0.10.0-alpha.3` development line. It is not part
of `default` or `release-bundle`, and it is absent from the published
`v0.10.0-alpha.2` archives.

Compilation does not activate the observer. A feature-enabled binary requires
both the `web-review` profile and the explicit option:

```console
termivar scan https://app.example.test/ \
  --profile web-review \
  --tls-observation \
  --report-dir assessment-tls
```

The operator must already be authorized to assess the selected target. This
option does not schedule a request, open a connection, force a new handshake,
or change action selection. It only asks the existing Reqwest clients to expose
TLS information on responses they already obtain. Plain HTTP remains usable
and is recorded as not applicable.

## Backend boundary

The current Reqwest 0.12 response extension exposes only the peer leaf
certificate as DER bytes. It does not expose the negotiated TLS version,
cipher suite, ALPN result, full peer chain, connection identity, handshake
kind, session resumption, or whether two responses reused one connection.
Those fields are therefore reported as `not_exposed_by_backend`; they are not
inferred from the configured Rustls version or client preferences.

A successful HTTPS response means that the configured Rustls transport
completed its ordinary server-certificate authentication for that connection.
This observation does not independently revalidate a chain. Revocation, OCSP,
certificate-transparency and AIA retrieval are not performed. The reported
validation scope is `successful_https_response_connection/v1`, not a claim of
universal trust or of every client configuration.

The saved source scope is
`assessment_exact_origin_existing_connections/v1`: observations are aggregated
under the containing assessment's exact-origin authority. V1 deliberately does
not retain a request URL, request purpose, WordPress operation, or principal on
each certificate row. Associating a TLS leaf with one HTTP principal would
overstate what the handshake established, while saving a stable origin hash
could expose private host names to dictionary testing.

One selected connection is not an active negotiation matrix. It says nothing
about every protocol or cipher the server might support. Active finite
handshake probing belongs to a separately authorized later capability, not
this observer.

## Admission and retained facts

TLS metadata is reduced immediately after a successful response is received,
before response-body processing. A candidate leaf is accepted only when:

- the request URL used HTTPS;
- Reqwest supplied TLS information for that response;
- the peer leaf DER is present and no larger than 64 KiB;
- the DER is one complete parseable X.509 certificate; and
- the bounded observation can be retained under the assessment limits.

The runtime never saves the DER certificate or readable subject, issuer, DNS,
IP, or other SAN values. For at most 16 distinct leaf certificates it retains:

- SHA-256 of the complete DER bytes and exact byte length;
- `notBefore`, `notAfter`, and observation time as Unix seconds;
- a bounded time-status classification;
- bounded DNS, IP, and other SAN counts plus a truncation marker;
- successful-transport-validation scope; and
- the number of successful responses on which the same leaf bytes appeared.

The SAN count is bounded at 256 entries per certificate. A duplicate leaf
increments its response occurrence rather than adding another row. Matching
DER bytes identify the same supplied certificate bytes; they do not prove the
same socket, handshake, server instance, deployment, or source authenticity.
Certificate hashes are not signatures or reproducible-build evidence.

Validity status is relative to the recorded local system-clock instant. Its
assurance is explicitly
`local_system_clock_not_independently_verified`; Termivar does not claim that
the host clock is accurate or externally synchronized.

The audit separately reconciles successful plain-HTTP responses, successful
HTTPS responses, HTTPS responses whose backend metadata was unavailable,
malformed or over-limit leaves, and unique/unretained observations. A missing
TLS extension is `unavailable`, not evidence that the server supplied no
certificate. A TLS failure produces no successful response and cannot be
turned into invented leaf facts by parsing error strings.

## Report, readers, and comparison

A selected completed assessment contains the optional strict
`security.tls-observation-audit/v1` section with policy
`termivar.existing-connection-tls-observation/v1`. A selected plain-HTTP run
has a valid empty leaf set and an explicit not-applicable count. The audit
produces no vulnerability item, active verification, exploit execution, or
impact conclusion.

JSON, HTML, Markdown, and CSV are rendered from the same validated typed
document. Feature-independent saved-report readers validate the optional audit
and its accounting even when the producer feature is not compiled. Offline
Verify checks bundle integrity and supported report consistency; it does not
authenticate a certificate source or prove report truth.

Offline Compare treats a changed leaf, observation time/validity coverage, or
backend/methodology boundary as certificate, coverage, or methodology change.
It must not describe a one-sided observation or failed later connection as a
new vulnerability, remediation, or complete server-configuration change.

## Owned-fixture acceptance

Tests use an isolated loopback TLS server and a task-owned test CA. The test
client adds that CA while keeping certificate and hostname validation enabled;
production code has no accept-invalid-certificate fallback. Independent server
configuration supplies the expected leaf and validity facts. Plain-HTTP,
malformed/over-limit DER, missing metadata, duplicate leaves, SAN limits and
option-off behavior are tested separately.

The native CLI process case demonstrates explicit option selection, unchanged
request count, report publication, Verify, and offline self-Compare. The
loopback trusted-TLS transport test exercises the broker response extension and
collector directly; neither is represented as active cipher enumeration.

## Explicit non-goals

V1 does not:

- open an additional connection or force a handshake;
- enumerate supported TLS versions or cipher suites;
- infer negotiated fields that Reqwest does not expose;
- retain a peer chain or prove chain completeness;
- fetch AIA, CRL, OCSP, CT, or certificate-linked URLs;
- disable certificate or hostname validation;
- treat a self-issued certificate as a verified self-signature;
- authenticate the server operator, application, or deployment from a hash;
- prove that every request used the same certificate or connection; or
- confirm a vulnerability, exploit, impact, remediation, or production
  readiness.

The [Reqwest `TlsInfo` documentation](https://docs.rs/reqwest/0.12/reqwest/tls/struct.TlsInfo.html),
[Rustls documentation](https://docs.rs/rustls/0.23/), and
[TLS 1.3 specification](https://www.rfc-editor.org/rfc/rfc8446.html) are
development references. Runtime execution never retrieves them.
