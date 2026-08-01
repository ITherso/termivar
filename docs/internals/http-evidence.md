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
redirect-disabled reqwest client
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

The executor uses a client configured with redirect following disabled. A redirect becomes ordinary status, `Location`, and final-URL evidence; it never expands scan scope automatically. Embedded URL credentials and destination/framing request headers such as `Host`, `Content-Length`, and `Transfer-Encoding` are rejected.

## Evidence emitted

One completed request may produce:

- request method and URL;
- response status, protocol version, and final URL;
- allowlisted response headers;
- time to first byte and total response time;
- observed body bytes, truncation state, and SHA-256;
- an optional bounded text sample for textual media types;
- rate-limit detection, advertisement, retry delay, limit, remaining quota, and reset values.

The `http.response.status` predicate intentionally matches the standard adaptive pipeline conditions for `403`, `404`, and `429` responses.

## Resource and data safety

The complete request plus body read has one timeout. Body buffering has a configurable positive limit and a hard 16 MiB ceiling. Metadata-only capture is the default. Text sampling must be enabled explicitly and remains bounded by the body buffer.

Response headers use a conservative allowlist. `Set-Cookie` is omitted by default because it may contain session secrets; a host may opt in only when its evidence retention policy permits that data. The executor hashes exactly the bytes it observed, so a truncated-body hash is not presented as a hash of the complete representation.

## Rate-limit normalization

Standard `RateLimit-*` fields take precedence over legacy `X-RateLimit-*` fields. Numeric values become unsigned evidence; date or vendor-specific values remain text. HTTP `429` independently sets `http.rate-limit.detected`, allowing the decision layer to distinguish active throttling from merely advertised quota metadata.
