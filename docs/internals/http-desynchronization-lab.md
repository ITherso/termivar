# Isolated HTTP parser-boundary laboratory

Status: `LAB_QUALIFIED_ONLY`, repository test-only.

This S15B laboratory answers one narrow question: can two deliberately
different parsers place the end of one fixed harmless HTTP/1.1 message at
different byte offsets? It is not a Termivar scanner feature and is not a
supported live-target test.

## Reachability boundary

The implementation is a private `termivar-scanner` module guarded by exact
`cfg(test)` beneath the existing `cfg(feature = "scanning")` `web_runtime`
module, so its effective reachability still requires both test and scanning
builds. Its source is a non-target support file under `tests/support`, bound into
the library test harness by one exact private module path; Cargo does not
discover it as a standalone integration crate. It has no CLI flag, Cargo
product feature, public API, target policy, report/audit schema, capability row,
release-bundle member or package scenario. Ordinary scanner transports and
connection pools cannot call it.

Every socket binds an ephemeral `127.0.0.1` port and accepts one loopback peer.
Each case owns a fresh front-end listener; the three complete cases also own a
fresh back-end listener, while the incomplete control never opens one.
Connections are never shared with scanner traffic or another case. Cases run
sequentially. The client task is joined on ordinary completion and an
abort-on-drop guard closes it if an outer case or matrix deadline cancels the
future; no later case starts after such a failure.

## Closed matrix

The matrix has exactly four versioned test cases:

1. A complete Content-Length message whose front and back boundaries both end
   at exclusive offset 63.
2. A complete message for which the Content-Length parser ends at 91 and the
   chunked parser ends at 101.
3. A complete message for which the chunked parser ends at 94 and the
   Content-Length parser ends at 102.
4. An incomplete Content-Length control with 62 available bytes and a required
   boundary at 64. The front end times out and never creates or dispatches a
   back-end connection.

The fixed input sizes are 63, 101, 102 and 62 bytes: 328 bytes arrive at the
front end. The three complete cases forward 266 bytes to their isolated back
ends, so the separately recorded physical request-direction total is 594 bytes.
The broker charges the 328-byte logical case input once; it is not presented as
the total socket traffic. The two disagreement suffixes are inert data, not a
second request line. The parsers run once for one message and never enter a
pipeline or recursive framing loop.

The only valid conclusions are `agreement`,
`parser_boundary_disagreement`, and `inconclusive_timeout`. A timeout is not a
disagreement. A disagreement is not a request-smuggling vulnerability or an
exploit result.

## Accounting and time bounds

A single test-owned `RequestAccountingBroker` admits a case at the active stage
and charges its complete fixed request bytes before any bind or connect. The
matrix permits four total requests/four active cases, at most 2 KiB per case,
at most 8 KiB admitted request bytes, one byte of response budget that remains
unused, one case in flight, at most one second per case and at most five seconds
for the matrix. Parser-declared complete or required boundaries above the 2 KiB
case ceiling are rejected before any remainder allocation. The broker enforces
the fixed count and byte ceilings; explicit timeout wrappers independently
enforce the one- and five-second ceilings. This private test does not receive an
external parent deadline.

The completed matrix has four receipts: three `Completed` and one
`RequestTimeout`. It records four front-end and three back-end connections, 328
front-end request bytes, 266 back-end request bytes and zero response bytes. An
independently tested fifth attempt fails the broker's total-request limit before
listener construction or connection.

Cancellation, timeout and limit failures close owned tasks and sockets. No
retry, redirect, credential, proxy, application request handler, public
listener or background continuation exists.

## Evidence and claims

Test output is limited to the case identifier, parser identifier, exclusive
boundary offsets, connection/byte counts, outcome and explicit limitations.
Raw request bytes are never printed or stored as evidence.

The exact release-profile test runs in the existing four-platform runtime-smoke
matrix on Linux x86_64, Windows MSVC x86_64, Intel macOS and Apple Silicon. That
native execution qualifies only the owned laboratory. It does not establish a
target vulnerability, exploitability, cache poisoning, response interception,
authorization bypass, user impact, production readiness or live-target support.
