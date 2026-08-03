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

## A. Current production-backed mappings

These are the predicates that are actually emitted by runtime producers in this repository.

| EvidenceKind | predicate.namespace | predicate.name | EvidenceValue | actual producer | source method | entity output | persisted fields | contract class | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Http` | `http.request` | `url` | `Text` | `crates/venom-scanner/src/http_evidence.rs::to_evidence` | `request-url` | `endpoint` (`url` attr) | `source_evidence_ids` | `production_backed` | URL is normalized to `(http|https)` endpoint and canonicalized (query/fragment removed). |
| `Http` | `http.request` | `method` | `Text` | `crates/venom-scanner/src/http_evidence.rs::to_evidence` | `request-method` | `endpoint` (`method` attr) | `source_evidence_ids` | `production_backed` | Method is token-validated and uppercased in extractor. |
| `Http` | `http.header` | `<normalized-name>` | `Text` | `crates/venom-scanner/src/http_evidence.rs::to_evidence` | `response-header:<normalized-name>` | `header` (`name` attr) | `source_evidence_ids` | `production_backed` | Header value intentionally not persisted. |
| `Authentication` | `http.cookie` | `name` | `Text` | `crates/venom-scanner/src/http_evidence.rs::to_evidence` | `response-set-cookie-name` | _ignored_ | _ignored_ | `production_backed` | Cookie names are intentionally ignored and do not create entities. |

**Extractor persistence behavior**

- `source_evidence_ids`: evidence ids contributing to each kept entity.
- `dropped_entities` / `dropped_attributes` / `dropped_sources` / `truncated`: snapshot-level truncation flags in `SemanticExtractionResult`.
- unsupported/ignored predicates are simply absent.

## B. Synthetic extractor contracts (supported by Phase 1 fixtures)

These fixtures validate extractor logic but are not produced from current runtime evidence producers.

| EvidenceKind | predicate.namespace | predicate.name | EvidenceValue | semantic entity output | Contract class | Typical fixture source |
| --- | --- | --- | --- | --- | --- | --- |
| `Authentication` | `authentication` | `jwt` | `Text` | `auth_artifact` | `synthetic_extractor_contract` | `semantic.fixture` |
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

## Golden fixtures used for contract verification

The following fixtures live under `crates/venom-scanner/tests/fixtures/semantic/`:

- `rest_request_url_and_method.json`
- `response_header_concepts.json`
- `jwt_or_bearer_auth_artifact.json`
- `session_cookie_name_is_not_a_credential.json`
- `graphql_request_surface.json`
- `dns_domain_and_ip_are_distinct.json`
- `unsupported_query_parameter_contract.json`
- `technology_product_and_version_gap.json`
- `bounded_truncation_receipt.json`

`crates/venom-scanner/tests/semantic_golden_fixtures.rs` checks:

- `contract_class` presence and expected class per fixture name;
- order-independent extraction;
- full `SemanticExtractionResult` serialization stability;
- exact truncated counts;
- secret redaction in entity JSON and debug output;
- production-backed HTTP header/URL/method cookie source fingerprints where applicable.
