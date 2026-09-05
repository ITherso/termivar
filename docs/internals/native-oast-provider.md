# Native OAST provider V1

`termivar-oast` is an unpublished, self-hosted auxiliary service for receiving
bounded HTTP callbacks. It is not a scanner, does not select targets or
parameters, and cannot create assessment evidence, findings, or reports. A
separately gated scanner adapter can use this service under narrowing host
authority; the provider itself owns no target authority.

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
implement serialization. The session token necessarily crosses the private
registration response and subsequent authenticated management-request header
boundaries. Provider state retains only
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

The server remains independent from its separately feature-gated HTTPS client.
The non-default scanner adapter described in
[Native OAST provider authority](native-oast-provider-authority.md) may use that
client only through a host-minted, exact-origin narrowing permit and the parent
assessment budget. The provider itself still owns no scanner or target
authority.

## Raw-free in-memory state

For a valid allocated callback, the provider retains only opaque random event,
session, and callback identifiers, the `HTTP` protocol class, a monotonic
cursor, a bounded duplicate count, and internal expiry state. Stored events do
not include the source address, port, URL, query, headers, cookies, body, user
agent, time, TLS details, or reverse-proxy metadata. This is a retained-state
guarantee, not a claim that transient HTTP buffers contain none of those values.
Unknown, expired, or
deleted callback identities are not recorded.

State lives only in checked, bounded in-memory collections. There is no
database, filesystem persistence, session serialization, background cleanup,
or network work in `Drop`. Explicit authenticated cleanup removes the session's
token digest, callbacks, and events without affecting another session.

Acceptance expiry and result retention are separate. Callbacks stop being
accepted at the declared session expiry. Existing events remain pollable with
the session credential and remaining poll allowance for a further 120 seconds,
up to but not including the retention deadline. These retained sessions still
count against capacity; neither live sessions nor retained results are evicted
early to admit another registration.

Valid administrator-authenticated registration, or authenticated session
allocation/poll/cleanup, triggers lazy reclamation over at most the existing
256 retained sessions. Invalid registration input does not trigger a sweep.
This recovers abandoned sessions, including
when the registration response and its cleanup credential were lost. The sweep
is bounded and visits every retained entry, without a starvation-prone cursor.
Idle state is not physically erased at its deadline: removal occurs on later
authenticated management activity or provider drop. Removal zeroizes the owned
secret digest. A reclaimed session receives the existing `SessionNotFound`
result and generic HTTP error; callback responses remain non-reflective and
cannot resurrect state. Invalid credentials do not trigger maintenance.

## HTTP resource lifetimes

The loopback HTTP/1 backend uses fixed, checked finite limits:

| Boundary | Limit | Scope |
| --- | --- | --- |
| Header read | 10 seconds | Hyper timer, including the next keep-alive request |
| Request | 15 seconds | Admission, body extraction, state wait and handler |
| I/O inactivity | 30 seconds | No actual bytes read or written |
| Connection lifetime | 120 seconds | Absolute, regardless of ongoing progress |

Admission is immediate and precedes body extraction. Saturation does not create
an admission queue or read a management body. The existing 64 KiB body ceiling
still applies while streaming. No provider-state mutex is held while reading
the network body. Owned permits and connection futures are dropped on timeout,
disconnect, cancellation or listener shutdown; there is no detached task.

Healthy requests can reuse a connection. A silent keep-alive connection can
hit the header timeout before the outer inactivity limit. An operator's reverse
proxy must tolerate ordinary backend connection rotation; clients must not
silently retry management operations whose completion is unknown. Request
timeout uses a generic `408` response with connection closure; transport/header
timeouts can close without an application response. Saturated management
requests use generic `503` with closure. Callback paths retain the generic
non-reflective `204` behavior on saturation. Existing successful protocol and
body-limit responses are unchanged.

## Hard bounds

V1 enforces named ceilings at or below:

- 256 retained sessions (live and expired-with-results combined);
- 8 callbacks per session;
- 64 accepted events per session;
- 32 polls per session;
- 32 events per poll response;
- 120 seconds of callback acceptance per session;
- 120 further seconds of result retention;
- 256 concurrently admitted loopback requests;
- 64 KiB per management request body;
- 256 KiB per management response;
- 4,096 bytes per administrator token.

Limit exhaustion is typed and fail-closed. A bounded response is never marked
complete after silent truncation. Production identifiers come from the
operating-system CSPRNG and use strict unpadded URL-safe encoding.

## Product boundary

The provider and its client adapter are excluded from `termivar-cli`'s
`release-bundle` and from release packaging and publication. The provider does
not import `termivar-scanner`,
`WebAssessmentRuntime`, legacy SSRF phases, reporting, or finding types. Its
HTTP callback observation is not evidence of SSRF and produces no scanner
claim. The separately reviewed adapter can register, allocate, poll, reduce,
and clean up under narrowing authority; it still creates no target request,
report, finding, or scanner action.
