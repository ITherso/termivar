# Native OAST provider authority V1

The non-default `termivar-scanner/oast-native-provider` feature connects the
provider-neutral OAST correlation contracts to one explicitly self-hosted
`termivar-oast` HTTPS management origin. This is a host-library adapter, not a
scanner action. It adds no CLI flag, target request, report field, finding, or
vulnerability conclusion, and it is excluded from the release bundle.

## Narrowing authority

Only the assessment host can mint a provider permit. A permit binds one
canonical HTTPS provider origin, one assessment identity and authority epoch,
the four fixed management operation classes, and checked ceilings for
registrations, callback allocations, management requests, polls, request and
response bytes, and provider wall time. The permit is move-only and cannot be
deserialized or reused by another assessment.

`SharedWebRuntimeAuthority` can mint this adapter only once per assessment.
That mint-once state is shared across authority clones, so cloning the parent
cannot reset the guard or create a parallel provider permit. Adapter
construction consumes a private move-only token whose seal can be constructed
only inside the shared-authority module.

Provider authority is separate from target authority. A provider origin cannot
be submitted to the target request broker, and a target URL cannot be supplied
to the provider adapter. The adapter receives a narrowing child reservation of
the parent assessment budget; provider traffic is therefore auxiliary traffic
accounted inside the existing assessment limit rather than a second or
unmetered budget.

The provider client can address only these protocol operations:

| Operation | Fixed route shape |
| --- | --- |
| Register | `POST /v1/sessions` |
| Allocate callback | `POST /v1/sessions/{session_id}/callbacks` |
| Poll | `GET /v1/sessions/{session_id}/events?after={cursor}` |
| Cleanup | `DELETE /v1/sessions/{session_id}` |

The configured origin cannot contribute a path, query, fragment, user
information, IP literal, or arbitrary operation URL. Redirect following,
cookies, ambient proxy discovery, implicit retries, background polling, and
network work in `Drop` remain disabled.

## Lifecycle and correlation

The adapter advances explicitly through:

```text
Configured -> Registered -> CallbackAllocated -> Polling -> Closing -> Closed
```

Registration occurs once, callback allocation and polling consume their
separate bounds, and cleanup is attempted explicitly at most once. Dropping an
adapter performs no network operation. A malformed, oversized, foreign,
expired, cancelled, or out-of-order provider response commits no correlation
event.

`Closed` is a local lifecycle state, not proof of remote deletion. Cleanup
attempt, transport admission and verified provider response remain distinct
receipt facts. Cancellation, expired authority and exhausted parent budget
remain terminal: they must not be bypassed to force a cleanup request. When
cleanup cannot legally run, the provider's finite result-retention window and
later authenticated management activity recover abandoned capacity. Available
raw-free observations do not turn incomplete cleanup into a complete review.

Poll responses are reduced immediately. Provider session, callback, and event
identifiers remain private transport details; an accepted HTTP callback becomes
only an existing `OastHttpEvent` and opaque `OastEventKey` under the exact
assessment/case/correlation binding. The provider-neutral correlation state
machine remains responsible for replay suppression, protocol grants, expiry,
and atomic poll completion. One provider event cannot bypass that state
machine.

## Secret and receipt boundary

The administrator credential and returned session credential are move-only,
redacted, zeroized, and non-serializable. They cross only the fixed request
construction boundary and never enter an error, receipt, log, stable identity,
or report.

Adapter receipts retain only bounded typed facts such as the provider-origin
fingerprint, operation class, request and response byte counts, lifecycle
transition, allocation and poll counts, accepted and duplicate event counts,
expiry, and cleanup status. They do not retain the provider origin, callback
URL, session or callback identity, credential, header, body, address, path,
query, or provider timestamp.

## Deliberate exclusions

This revision does not configure a provider from the CLI, start the provider,
send an SSRF or XXE payload, register a `WebAssessmentRuntime` action, project
evidence or an `AssessmentItem`, or expose the adapter to plugins, Lua, exploit
orchestration, GraphQL, OpenAPI, REST, SQL, SSTI, XSS, or the legacy scanner.
No public provider is bundled or selected. The separately gated
[SSRF OAST query review](ssrf-oast-query-review.md) supplies a narrow,
operator-acknowledged target-side authority without broadening this adapter:
at most one eligible query occurrence, two independent callbacks, bounded
polling, and no confirmed SSRF conclusion.
