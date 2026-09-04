# Native OAST provider V1

`termivar-oast` is an unpublished, self-hosted auxiliary service for receiving
bounded HTTP callbacks. It is not a scanner, does not select targets or
parameters, and cannot create assessment evidence, findings, or reports. No
Termivar scan path uses the provider in this foundation release.

## Security and deployment model

The production binary, `termivar-oast-provider`, binds only to an explicitly
configured IPv4 or IPv6 loopback address. An operator places it behind an
operator-managed HTTPS reverse proxy and supplies exactly one externally
visible HTTPS origin with a DNS hostname. Wildcard and non-loopback binds, IP
literal public origins, user information, queries, fragments, and non-root
origin paths are rejected. Termivar supplies no hosted provider and chooses or
deploys no provider automatically.

V1 relies on HTTPS for transport confidentiality and integrity. It does not
claim end-to-end application-layer encryption and does not implement an RSA,
AES, or Interactsh-compatible callback envelope. A high-entropy administrator
Bearer token authorizes only session creation. Each session receives a fresh
high-entropy Bearer token, delivered once, for callback allocation, polling,
and cleanup. Secret wrapper types are move-only, redacted, zeroized, and do not
implement serialization; the session token crosses only the registration
response's narrow wire-construction boundary. Provider state retains only
domain-separated SHA-256 token digests compared in constant time.

The provider administrator token is loaded from exactly one of:

```text
--admin-token-env <NAME>
--admin-token-file <PATH>
--admin-token-stdin
```

There is deliberately no raw-token command-line argument. The bounded file
loader rejects symlinks and the stdin source is consumed once. A single
trailing LF or CRLF is normalized; embedded line breaks are rejected.

Reverse-proxy access logging should exclude `Authorization` values and public
callback paths. The callback endpoint always emits the same non-reflective
`204 No Content` response for syntactically valid callback paths so callers
cannot use the response as a live-session oracle.

## Fixed protocol

The management API has four fixed operations:

| Operation | Route | Authorization |
| --- | --- | --- |
| Register | `POST /v1/sessions` | administrator Bearer token |
| Allocate | `POST /v1/sessions/{session_id}/callbacks` | session Bearer token |
| Poll | `GET /v1/sessions/{session_id}/events?after={cursor}` | session Bearer token |
| Cleanup | `DELETE /v1/sessions/{session_id}` | session Bearer token |

The public callback route accepts only `GET` and `HEAD` at
`/c/{session_id}/{callback_id}`. There is no arbitrary endpoint, GraphQL,
WebSocket, long poll, server-sent event, retry middleware, redirect following,
cookie jar, proxy inheritance, or callback request body.

Wire schemas are versioned independently:

```text
security.termivar-oast.session/v1
security.termivar-oast.callback/v1
security.termivar-oast.poll/v1
security.termivar-oast.cleanup/v1
```

This foundation revision implements the protocol and provider only. It opens no
outbound HTTP client or TLS stack. The exact-origin HTTPS management client and
narrowing scanner authority are deferred to a separately reviewed follow-up;
no assessment can use this provider until that authority exists.

## Raw-free in-memory state

For a valid allocated callback, the provider retains only opaque random event,
session, and callback identifiers, the `HTTP` protocol class, a monotonic
cursor, a bounded duplicate count, and internal expiry state. It immediately
discards the source address, port, URL, query, headers, cookies, body, user
agent, time, TLS details, and reverse-proxy metadata. Unknown, expired, or
deleted callback identities are not recorded.

State lives only in checked, bounded in-memory collections. There is no
database, filesystem persistence, session serialization, background cleanup,
or network work in `Drop`. Cleanup is an explicit authenticated operation and
removes the session's token digest, callbacks, and events without affecting
another session.

## Hard bounds

V1 enforces named ceilings at or below:

- 256 active sessions;
- 8 callbacks per session;
- 64 accepted events per session;
- 32 polls per session;
- 32 events per poll response;
- 120 seconds per session;
- 256 concurrently admitted loopback requests;
- 64 KiB per management request body;
- 256 KiB per management response;
- 4,096 bytes per administrator token.

Limit exhaustion is typed and fail-closed. A bounded response is never marked
complete after silent truncation. Production identifiers come from the
operating-system CSPRNG and use strict unpadded URL-safe encoding.

## Product boundary

The provider is excluded from `termivar-cli`'s `release-bundle` and from
release packaging and publication. It does not import `termivar-scanner`,
`WebAssessmentRuntime`, legacy SSRF phases, reporting, or finding types. Its
HTTP callback observation is not evidence of SSRF and produces no scanner
claim. A later, separately reviewed scanner adapter must provide a narrowing
provider authority before an assessment can use this service.
