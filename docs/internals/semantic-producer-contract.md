# Semantic Producer Contract (Phase 1.5 alignment)

This document captures the production evidence contracts that are compatible with
the current `EntityExtractor` implementation.

It is intentionally narrow: no relation graph, no planes, no hypotheses,
no planning integration, and no runtime behavior changes are introduced here.

## Scope

Phase: Semantic Model Builder — Phase 1.5 (Production Evidence Contract Alignment)

- Evidence producer contracts that already exist are mapped to semantic entities.
- Unsupported or ambiguous evidence does **not** create entities.
- Raw credential material is never stored in identifiers, attributes, entity source
  collections, or serialized outputs.

## Supported evidence-to-entity mapping

| EvidenceKind | predicate.namespace | predicate.name | Entity type | Notes |
| --- | --- | --- | --- | --- |
| `Http` | `http.request` | `url` | `Endpoint` | Creates endpoint from URL evidence. Can merge with a later `http.request.method` for the same subject. |
| `Http` | `http.request` | `method` | `Endpoint` | Adds `method` attribute (uppercased) to the endpoint entity. Missing/empty method is ignored. |
| `Http` | `http.header` | `<name>` | `Header` | Name-only entity (`name`) from predicate namespace+name. Header value is intentionally ignored in entity output. |
| `Authentication` | `authentication` | `bearer` | `AuthArtifact` | Only accepted credential-like predicate names are mapped. |
| `Authentication` | `authentication` | `api_key` | `AuthArtifact` | Only accepted credential-like predicate names are mapped. |
| `Authentication` | `authentication` | `jwt` | `AuthArtifact` | Only accepted predicate names are mapped. |
| `Dns` / `Network` | `dns` | `ip` | `IpAddress` | IP is canonicalized and cannot fallback to domain. |
| `Dns` / `Network` | `dns` | `domain`, `hostname` | `Domain` | Canonicalized DNS-like value to lowercase and trimmed host shape. |
| `Technology` | `technology` | `web-server`, `language`, `framework`, `ui-framework` | `Technology` | Only alpha-containing values are accepted for `Technology` entity creation. |

## Unsupported or deferred contracts (explicitly not mapped)

- `http.request.query`: currently no `Parameter` entity is generated in Phase 1.
- `http.cookie.name`: cookie names are not converted to `AuthArtifact` and no
  dedicated cookie entity exists yet.
- `technology` payload-like version values (for example `1.27.3`): values without
  product semantics are ignored as technology entities.
- Non-authentication credential-like subjects (`authentication` names outside
  `{bearer,api_key,jwt}`): no entities.
- Namespace collisions where namespace differs (for example `api.request.url`) do
  not route to HTTP contracts.

## Canonical identity and attribute conventions

- Endpoint entities are method-agnostic in identity:
  `v1:endpoint:<canonical-http-or-https-url>`.
- Query strings and fragments are removed before endpoint identity is built.
- IPv6 and DNS values are normalized before identity generation.
- Standard header identity is `v1:header:<normalized-header-name>`.
- Auth artifact identity is `v1:auth_artifact:<stable hash>`, where the hash is
  produced from the canonicalized value and artifact kind.
- Tech entities are `v1:tech:<normalized-name>`.
- Domain identity is `v1:domain:<domain>`.
- IP identity is `v1:ip:<ip>`.

## Secret handling

- For `Authentication` input values, raw token text is never persisted.
- `AuthArtifact` entities keep:
  - `auth_kind`
  - `fingerprint`
  - `length`
- Neither raw token values nor header values are stored in entity attributes.

## Fixtures (reference)

The contract is validated by golden fixtures at:
`crates/venom-scanner/tests/fixtures/semantic/`
and the dedicated integration test:
`crates/venom-scanner/tests/semantic_golden_fixtures.rs`.

Each fixture has deterministic, ordered expectations and explicit truncation cases.

## Roll-forward note

This table is production-aligned but intentionally does not claim future phases.
If a new predicate or source shape is required, update this contract and add a
dedicated fixture in the same folder before introducing Phase 2 behavior.
