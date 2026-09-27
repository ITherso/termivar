# Bounded WebSocket review

Status: Preview, development-only, explicit opt-in. This document describes
the anonymous S11-A slice. S11 remains `IMPLEMENTING`; authenticated/session
context integration is deliberately deferred to S11-B.

## Selection and authority

The capability is compiled only with the non-default `websocket-review`
feature and is selected only by:

```text
termivar scan AUTHORIZED_TARGET \
  --profile web-review \
  --websocket-review-policy FILE \
  --report-dir NEW_DIRECTORY
```

The strict `security.websocket-review-policy/v1` file declares one exact
endpoint, a finite ordered message exchange and finite limits. It must state
`target_authorized=true`, `messages_read_only_acknowledged=true` and
`message_content_is_non_secret=true`. Those are operator assertions, not facts
Termivar authenticates. V1 does not support credentials or other secret material
inside message bodies. A GET, Upgrade or application message is not guaranteed
to be side-effect-free by protocol alone.

The endpoint must retain the target's exact host and effective port and remain
inside the selected application path using segment-aware matching. The policy
cannot discover another endpoint or expand target scope. Plain `ws` is admitted
only when both the target and endpoint use numeric loopback. Other execution
requires `wss` and ordinary certificate validation. Userinfo, fragments, query
strings, unsafe raw encodings and path traversal are rejected before dispatch.

The runtime mints one one-shot child from the existing assessment authority.
One connection attempt consumes one request-accounting lease and shares the
parent deadline, cancellation and response-byte ceiling. There is no second
scanner, background worker or resettable budget. The exchange is passive-stage
protocol observation; it does not mint active-verification or finding
authority.

## Transport contract

V1 implements RFC 6455 over an HTTP/1.1 Upgrade. HTTP/2 extended CONNECT is
unsupported. It uses one isolated anonymous connection and never inherits a
supplied session. It sends no Cookie, Authorization or Proxy-Authorization
header and does not use ambient proxies. Redirect following, retries,
reconnection and per-message connection resets are absent. Compression is
disabled and an unexpected negotiated extension is refused.

An optional subprotocol is an exact bounded token. The server must select that
exact token when one was requested, and must not invent one when none was
requested. `Origin` may either be omitted or derived from the authorized
application origin. Because a non-browser client can choose `Origin`, server
behavior observed with that header is not evidence of a browser exploit path
or cross-site WebSocket hijacking.

The compiled ceilings are:

- one connection at a time and one connection attempt;
- one to eight sequential operator-declared text messages;
- at most 64 KiB aggregate application payload in each direction;
- bounded per-message sizes no greater than the aggregate ceiling;
- at most sixteen observable Ping/Pong/Close control-frame events, narrowed by
  the policy;
- at most ten seconds or the smaller remaining parent deadline.

Binary application messages and unexpected message sequences fail closed.
Ping/Pong/Close events are handled only within the bounded exchange; there is
no keepalive or reconnection loop. The WebSocket backend yields complete
application messages and observable control events, but not a trustworthy
count of physical continuation frames. The audit therefore marks physical
frame count unavailable instead of inventing one. Per-frame/per-message size
configuration, control-event limits, cumulative application-byte limits and
the absolute deadline bound processing despite that limitation.

## Byte and completeness accounting

Two scopes remain distinct:

- raw socket transport bytes are counted at the owned stream boundary so a
  handshake failure, partial frame or timeout is not reported as zero work;
  for `wss` this scope is TLS ciphertext and includes transport framing;
- application bytes are counted only for complete delivered text messages and
  are used for expected-response length and digest comparison.

Raw transport bytes must not be described as decoded application payload, and
complete-message accounting must not hide a partial transport failure. The
parent response budget charges raw inbound socket bytes. Outbound application
bytes are a child-local counter because the HTTP request-body budget has a
different semantic meaning. Configured bytes are not counted as sent until the
send operation succeeds.

Completeness is `configured_exchange_complete` only when the one Upgrade and
every declared send/response pair complete inside all limits. Cancellation,
deadline, authority refusal, handshake failure, mismatched protocol negotiation,
partial/oversized input, response-budget exhaustion or another transport error
leaves the review incomplete with a bounded value-free failure class.

## Evidence and claims

The report section uses `security.websocket-review-audit/v1` and capability
identity `termivar.websocket-review/v1`. It retains only opaque policy,
application, endpoint, message and expected/observed response references;
lengths; bounded counters; classified outcomes; limits; and completeness. It
does not retain endpoint paths or queries, message IDs/text, subprotocol values,
credentials, raw server errors or transcripts.

Each message `id` is a non-secret operator revision handle and must change when
the corresponding outbound or expected-response semantics change. Public
message and expected-response references derive only from that handle and public
lengths; they do not hash either private byte sequence and therefore do not
publish a low-entropy dictionary oracle. The exact expected-response SHA-256
remains private inside the selected runtime.

An expected response is compared using its complete byte length and SHA-256.
A match proves only that the complete next application message equalled the
operator-declared bytes in that run. A successful Upgrade or match does not
establish:

- browser-origin security;
- authentication or authorization;
- availability;
- source authenticity;
- a vulnerability, exploitability or impact.

The capability adds no assessment item or severity. Report Verify checks saved
bundle integrity and schema consistency, not endpoint truth. Report Compare
separates methodology, coverage and outcome changes; a missing/incomplete later
exchange is not a vulnerability fix or resource removal. Offline Verify and
Compare never reconnect.

## Packaging and acceptance

`websocket-review` is outside `default`, the seven-member `release-bundle`, the
published alpha.2 archives and the initial curated package. Stock package
capabilities must list it as `not_compiled`. Feature-specific CI builds and
executes the actual CLI against an owned numeric-loopback fixture on Linux,
Windows, Intel macOS and Apple Silicon. That fixture is development evidence,
not authorization to contact a public endpoint or a claim of general protocol
compatibility.

Primary protocol references are [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html)
and [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html). They are development
references and are never scan-time destinations.
