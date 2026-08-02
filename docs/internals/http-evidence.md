# HTTP evidence executor internals

`HttpEvidenceExecutor` is the first real I/O implementation behind `DecisionActionExecutor`. It turns one decision case into a bounded discovery request and returns typed `Evidence`; it does not classify the response or choose another action.

## Execution boundary

```text
DecisionExecutionRequest
          |
          v
HttpProbeProvider
          |
          v
HttpProbe + HttpEvidencePolicy
          |
          v
host-owned HttpRequestBroker
          |
          v
accounting lease + redirect-disabled reqwest client
          |
          v
bounded response collection
          |
          v
Vec<Evidence>
```

The runner performs the later provenance validation, atomic knowledge write, and passive or active verifier handoff.

## Scope policy

Every policy contains at least one normalized authorized origin. A provider may select paths and query strings inside those origins, but the executor rejects a different scheme, host, or effective port before network I/O. Only `GET`, `HEAD`, and `OPTIONS` are supported by this collector.

The executor has no direct HTTP client. It delegates request construction, timeout, dispatch, and bounded body collection to `HttpRequestBroker`. The broker's client has redirect following and implicit reqwest retries disabled. A redirect becomes ordinary status, `Location`, and final-URL evidence; it consumes exactly the dispatch that received it and never expands scan scope automatically. A semantic retry must re-enter the broker and acquire another lease. Embedded URL credentials and destination/framing request headers such as `Host`, `Content-Length`, and `Transfer-Encoding` are rejected before a dispatch lease is acquired.

## Evidence emitted

One completed request may produce:

- request method and URL;
- response status, protocol version, and final URL;
- allowlisted response headers;
- response cookie names without cookie values or attributes;
- time to first byte and total response time;
- observed body bytes, truncation state, and SHA-256;
- an optional bounded text sample for textual media types;
- rate-limit detection, advertisement, retry delay, limit, remaining quota, and reset values.

The `http.response.status` predicate intentionally matches the standard adaptive pipeline conditions for `403`, `404`, and `429` responses.

## Resource and data safety

The complete request plus body read has one timeout. Body retention has a configurable positive per-response limit and a hard 16 MiB ceiling. `StandardWebDecisionRuntime` gives every built-in executor a clone of one broker backed by one atomic accounting authority. The broker acquires a non-refundable request lease immediately before dispatch and charges every response chunk delivered by transport before retaining its bounded prefix. A host runtime may also attach a smaller per-execution retention allowance. Partial bytes remain accounted even when a later read times out or fails. Metadata-only capture is the default. Text sampling must be enabled explicitly and remains bounded by the body buffer.

The native authorization-context visibility workflow is the deliberate
exception to connection-pool sharing, not to broker accounting. It creates one
fresh redirect-disabled client pool per principal so connection-bound state
cannot cross from control to candidate, while both brokers retain the same
policy and atomic accounting authority. Each leg therefore acquires its own
total-request and active-verification lease and contributes response bytes to
the same runtime usage counters.

`RuntimeUsage.response_bytes` counts complete chunks delivered to the broker collector. `http.response.body-bytes-observed` records only the prefix retained for evidence. A shared response-read gate prevents another collector from starting a read after the session threshold is full; the one chunk that reveals a crossing is charged in full and becomes a typed runtime limit.

Response headers use a conservative allowlist. `Set-Cookie` is omitted by default because it may contain session secrets; a host may opt in only when its evidence retention policy permits that data. The executor hashes exactly the bytes it observed, so a truncated-body hash is not presented as a hash of the complete representation.

Cookie names are extracted separately as `http.cookie.name`. Duplicate names are collapsed and malformed names are ignored. Values and attributes never enter evidence, so framework and authentication reasoning can use stable cookie-name signals without retaining session secrets.

## Rate-limit normalization

Standard `RateLimit-*` fields take precedence over legacy `X-RateLimit-*` fields. Numeric values become unsigned evidence; date or vendor-specific values remain text. HTTP `429` independently sets `http.rate-limit.detected`, allowing the decision layer to distinguish active throttling from merely advertised quota metadata.
