# Semantic Producer Contract (Phase 1.5)

## Contract class policy

Every fixture must declare one `contract_class`:

- `production_backed`
- `synthetic_extractor_contract`
- `negative_deferred`
- `bounded_mechanics`

`EntityExtractor` only consumes `KnowledgeSnapshot::evidence()`. It does **not** convert
`Hypothesis` or `Fact` records into semantic entities. So even if reasoning engines produce
conclusions, those conclusions are not transformed by `EntityExtractor` unless they are emitted as raw `Evidence` with the same tuple shape
(`EvidenceKind`, `predicate.namespace`, `predicate.name`, `EvidenceValue`, `EvidenceSource`).

The contract distinguishes where data can be produced today versus what is currently
represented only via synthetic fixtures.

Production-backed fixtures in tests additionally require a shared `correlation_id`
inside `EvidenceSource` for all evidence records belonging to the same scenario.

## A. Current production-backed mappings

These are the predicates that are actually emitted by runtime producers in this repository.

| EvidenceKind | predicate.namespace | predicate.name | EvidenceValue | actual producer | source method | entity output | persisted fields | contract class | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Http` | `http.request` | `url` | `Text` | `crates/termivar-scanner/src/http_evidence.rs::to_evidence` | `request-url` | `endpoint` (`url` attr) | `source_evidence_ids` | `production_backed` | URL is normalized to `(http|https)` endpoint and canonicalized (query/fragment removed). |
| `Http` | `http.request` | `method` | `Text` | `crates/termivar-scanner/src/http_evidence.rs::to_evidence` | `request-method` | `endpoint` (`method` attr) | `source_evidence_ids` | `production_backed` | Method is token-validated and uppercased in extractor. |
| `Http` | `http.header` | `<normalized-name>` | `Text` | `crates/termivar-scanner/src/http_evidence.rs::to_evidence` | `response-header:<normalized-name>` | `header` (`name` attr) | `source_evidence_ids` | `production_backed` | Header value intentionally not persisted. |
| `Authentication` | `http.cookie` | `name` | `Text` | `crates/termivar-scanner/src/http_evidence.rs::to_evidence` | `response-set-cookie-name` | _ignored_ | _ignored_ | `production_backed` | Cookie names are intentionally ignored and do not create entities. |

**Extractor persistence behavior**

- `source_evidence_ids`: evidence ids contributing to each kept entity.
- `dropped_entities` / `dropped_attributes` / `dropped_sources` / `truncated`: snapshot-level truncation flags in `SemanticExtractionResult`.
- unsupported/ignored predicates are simply absent.

## B. Synthetic extractor contracts (supported by Phase 1 fixtures)

These fixtures validate extractor logic but are not produced from current runtime evidence producers.

| EvidenceKind | predicate.namespace | predicate.name | EvidenceValue | semantic entity output | Contract class | Typical fixture source |
| --- | --- | --- | --- | --- | --- | --- |
| `Authentication` | `authentication` | `jwt` | `Text` | `auth_artifact` (`auth_kind=jwt`) | `synthetic_extractor_contract` | `semantic.fixture` |
| `Authentication` | `authentication` | `bearer` | `Text` | `auth_artifact` (`auth_kind=bearer_token`, or `jwt` if the value is a JWT) | `synthetic_extractor_contract` | `semantic.fixture` |
| `Authentication` | `authentication` | `api_key` | `Text` | `auth_artifact` (`auth_kind=api_key`) | `synthetic_extractor_contract` | `semantic.fixture` |
| `Dns` | `dns` | `ip` | `Text` | `ip_address` | `synthetic_extractor_contract` | `semantic.fixture` |
| `Dns` | `dns` | `domain`, `hostname` | `Text` | `domain` | `synthetic_extractor_contract` | `semantic.fixture` |
| `Technology` | `technology` | `web-server` | `Text` | `technology` | `synthetic_extractor_contract` | `semantic.fixture` |
| `Http` | `http.request` | `url` + `method=post` | `Text` | `endpoint` (`url`, `method`) | `synthetic_extractor_contract` | `semantic.fixture` |

## C. Explicitly deferred / unsupported mappings

| EvidenceKind | predicate.namespace | predicate.name | EvidenceValue | status | Why deferred |
| --- | --- | --- | --- | --- | --- |
| `Http` | `http.request` | `query` | `Text` | `negative_deferred` | No endpoint query-parameter entity contract is implemented in extractor. |

> `bounded_mechanics` is a fixture class used for extraction truncation behavior.
> It intentionally validates budget accounting, not a mapping contract.

## Routing rules

Extraction routes by exact tuple only:

`EvidenceKind + predicate.namespace() + predicate.name()`

There is no cross-namespace fallback for HTTP-like names. For example, `api.request.url`
or `api.request.method` must not map to HTTP endpoint contracts.

### Endpoint subject convention (production-backed)

The URL+method merge is production-backed only for the standard `http.evidence`
executor driven by `SubjectHttpProbeProvider`. In that path the case subject and
the probe URL are the **same absolute request URL**, so both the
`http.request.url` value and the `http.request.method` subject resolve to the same
method-agnostic endpoint identity:

`subject = endpoint:<same absolute request URL>`

Endpoint identity is method-agnostic: the observed method is stored as a `method`
attribute, never as part of the id (there is no `#GET` suffix).

A custom `HttpProbeProvider` may return a probe URL that differs from the case
subject. In that case the `http.request.method` evidence (keyed by subject) and the
`http.request.url` evidence (keyed by value) can resolve to two different endpoint
entities. Correlation-aware batch joining across a divergent provider is
**deferred** — the production-backed contract above covers only the standard
provider identity.

### Authentication predicate allowlist

The `authentication` namespace routes exactly `{jwt, bearer, api_key}`. `jwt` and
`bearer` values that parse as a JWT structure classify as `auth_kind=jwt`; a
non-JWT `bearer` value classifies as `auth_kind=bearer_token`; `api_key` classifies
as `auth_kind=api_key`. There is no `cookie` or `token` predicate in this
allowlist — cookie names arrive via `http.cookie` and are intentionally ignored.

## Golden fixtures used for contract verification

The following fixtures live under `crates/termivar-scanner/tests/fixtures/semantic/`:

- `rest_request_url_and_method.json`
- `response_header_concepts.json`
- `authentication_artifact_kinds.json`
- `session_cookie_name_is_not_a_credential.json`
- `graphql_request_surface.json`
- `dns_domain_and_ip_are_distinct.json`
- `unsupported_query_parameter_contract.json`
- `technology_product_and_version_gap.json`
- `bounded_truncation_receipt.json`

`crates/termivar-scanner/tests/semantic_golden_fixtures.rs` checks:

- `contract_class` presence and expected class per fixture name;
- order-independent extraction;
- full `SemanticExtractionResult` serialization stability;
- exact truncated counts;
- secret redaction in entity JSON and debug output;
- production-backed HTTP header/URL/method cookie source fingerprints where applicable.
