# OpenAPI contract catalog

The OpenAPI contract catalog is a transport-neutral, in-memory metadata
foundation for caller-supplied API contracts. V1 accepts JSON documents in the
OpenAPI 3.0.x and 3.1.x families and reduces supported declarations to a
deterministic operation catalog. It is not loaded by `termivar scan`, does not
discover contracts, and is not a scanner action, request planner, or executor.

## Input and version contract

The caller supplies one complete byte slice. Before semantic catalog
construction, the parser applies these compiled hard ceilings:

| Input property | V1 ceiling |
| --- | ---: |
| Document size | 2 MiB |
| JSON nesting depth | 64 |
| JSON nodes | 100,000 |
| Aggregate object members | 50,000 |
| Elements in one array | 4,096 |
| Bytes in one JSON string | 256 KiB |
| Paths | 4,096 |
| Operations | 4,096 |
| Parameters per operation | 64 |
| Media entries per operation (request and all responses combined) | 64 |
| Response entries per operation | 64 |
| Security requirements | 64 |
| Servers | 16 |
| Path bytes | 2,048 |
| Path segments | 256 |
| Identifier/token bytes | 256 |

Callers may narrow the exposed document, JSON-structure, path-count, and
operation-count limits but cannot widen any compiled ceiling. The remaining
catalog and token ceilings are fixed in V1.
Empty or oversized input, malformed JSON, an unsupported version or document
shape, and any exceeded structural or catalog limit fail closed. A successful
parse therefore never means that unbounded remainder was silently ignored.

V1 intentionally supports JSON only. It does not infer an encoding from a file
name, media type, or document contents. YAML is a future format that would need
its own dependency, limit, and conformance review before becoming a supported
input. Swagger/OpenAPI 2.0 is classified as metadata-only and yields no
operation catalog; it is not converted or treated as executable OpenAPI 3.x.

## Reduced deterministic catalog

For supported OpenAPI 3.x JSON, the catalog retains only bounded metadata used
to identify and query operations: path and HTTP method, parameter location and
requiredness, primitive/format class, normalized request and response media,
response status/summary, deprecated state, coarse security- and
server-declaration classes, and conservative candidate tags. Declared
`operationId` and parameter names are reduced to fingerprints. Source ordering
does not affect catalog ordering or stable identities.

Descriptions, examples, defaults, raw security-scheme names, operation names,
tags, and raw server values are not retained. External references are rejected.
The parser may resolve a bounded local parameter reference under
`#/components/parameters/`; other references remain unsupported and are never
followed outside the supplied document. Unknown extensions do not acquire
meaning or authority.

Servers are reduced to `ExactOrigin`, `Relative`, `CrossOrigin`, `Templated`,
or `Unsupported`. Raw server URLs do not enter the document or operation
identity; a domain-separated digest of the normalized resolved identity keeps
material server changes in the semantic document contract. Security
declarations are reduced to HTTP Basic/Bearer, API-key
location, OAuth2, OpenID Connect, mutual-TLS, or unknown metadata together with
inheritance/override and anonymous-declaration state. In particular,
`security: []` remains metadata and is not proof of anonymous reachability.

Pure catalog queries select deterministic operation views by method, parameter
presence/location, URL-like input, multipart request media, anonymous or
explicit security metadata, JSON-compatible response media, and conservative
candidate tag. Candidate tags cover future authorization, SQL-input, URL/SSRF,
upload, OAuth, and binary-response review. They create no actions, requests,
findings, or budget obligations.

## Authority boundary

A catalog records what an untrusted document declares. It does not establish
that an endpoint exists, is reachable, belongs to the target, accepts a method,
or has any authorization or vulnerability property. Security declarations are
classification metadata, not credentials, authentication instructions, or
authorization evidence.

Parsing and catalog queries perform no network I/O, redirects, DNS resolution,
filesystem access, credential lookup, request construction, request dispatch,
payload execution, evidence writes, report emission, findings, or claims. A
consumer must receive separately reviewed authority before it can do any of
those things; the catalog itself never grants it.

## Conformance scope

Repository cases may exercise supported OpenAPI 3.0/3.1 JSON, rejection and
limit behavior, and deterministic ordering. YAML and Swagger/OpenAPI 2.0 may
appear only as future or metadata-only expectations. Passing those cases proves
agreement with the bounded parser/catalog contract, not live endpoint coverage
or scanner accuracy. See the
[scanner conformance corpus](scanner-conformance-corpus.md) for the repository
harness boundary and the [runtime map](runtime-map.md) for executable truth.

## Optional live consumer

The separately feature-gated [OpenAPI surface review](openapi-surface-review.md)
is the V1 network consumer of this catalog. Catalog membership alone never
causes work: explicit `--openapi-review` under `web-review` selects at most one
exact-origin document, and a positive observation requires a complete candidate
and exact replay with the same semantic document identity. The review does not
execute any described operation.
