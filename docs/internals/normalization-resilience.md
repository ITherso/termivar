# Normalization-resilience review

Normalization resilience is a non-default Preview capability for reviewing a
small set of equivalent representations of Termivar's existing inert XSS
structural probes. It is not a generic WAF-bypass engine. A positive result
means only that a transformed representation reproduced the same inert
application-parser structure while the canonical candidate produced
candidate-specific defensive engagement, and that a distinct replay reproduced
the relationship.

The maximum product projection is `NeedsReview` under `KnowledgeOnly` authority.
The capability cannot produce `Confirmed`, an XSS verdict, an exploit result, or
a product-specific firewall-bypass claim.

## Build and operator boundary

Both compile-time and run-time opt-in are required:

```text
termivar-cli feature: normalization-resilience
termivar-scanner feature: normalization-resilience
runtime flag:       --normalization-resilience
required profile:   --profile web-review
```

For example, from a reviewed checkout:

```bash
cargo run --locked -p termivar-cli --features normalization-resilience -- \
  scan https://authorized.example.test \
  --profile web-review \
  --normalization-resilience
```

The flag is absent from default CLI builds. A feature-enabled CLI rejects it
without an explicit profile and with `baseline`. The option is carried beside
the stable `venom.scan-profile/v1` value, so it does not change that schema or
the no-profile `decision-scan/v1` contract. A defense fingerprint or status code
never enables the review automatically.

## Eligibility

The assessment may create at most one normalization child after all of the
following typed facts have been committed:

- the parent XSS control and canonical candidate completed on the same exact
  subject and selected parameter;
- the control was not defensively blocking;
- the canonical candidate caused a new candidate-specific blocking transition;
- the transition was not a standing block, a rate-limit-only signal, a timeout,
  or an incomplete/truncated response;
- the source/DOM context and the parent's existing semantic verifier are exact;
- one executable transform is compatible with that parent family; and
- the shared request and active-verification budget still has capacity.

A WAF/product fingerprint is optional context and a compatible-candidate
tie-break hint only. It grants no execution authority, does not increase a
budget or claim, and cannot make an incompatible transform eligible. A bare
`403`, `406`, `418`, `429`, timeout, or `5xx` is insufficient. A `429` retains
the existing backoff behavior and creates no normalization child.

## Versioned transform catalog

V1 selects metadata before materializing payload bytes. It selects at most one
family and fixes the maximum transform-chain depth at one.

| Transform | V1 availability | Compatible parent | Exact behavior |
| --- | --- | --- | --- |
| `xss.html-token-case@1` | Executable | HTML-text boundary | Changes ASCII case only on scanner-owned inert HTML tag and attribute names; scanner identity values and target-controlled text remain unchanged |
| `xss.html-inter-token-tab@1` | Executable | Ordinary, URI, or event-handler attribute boundary | Replaces one scanner-owned syntactic HTML separator with one horizontal tab; it cannot emit CR, LF, NUL, a new attribute, or a new query parameter |
| `query.percent-decode-depth-one@1` | Metadata only | HTML structural parents | No request obligation because V1 has no independently proven one-layer wire/decode contract |
| `query.percent-decode-depth-two@1` | Metadata only | HTML structural parents | No request obligation because repeated generic encoding does not prove an exact two-layer wire/decode contract |

The executable transforms consume a typed scanner-owned probe representation;
they are not general string case or whitespace mutation functions. Script
lexical probes, SQL/SSTI transforms, HTML entities, Unicode escapes, parameter
pollution, duplicate/decoy parameters, method or content-type changes, header
rotation, payload truncation, CRLF, request splitting/smuggling, pacing, and
browser normalization remain non-executable in V1.

The payload strategy is `web.review.normalization-resilience@1`. Like other
modern strategies, it produces bounded `PayloadArtifact` values and digest-only
receipts; raw canonical/transformed payloads, query values, scanner identities,
credentials, cookies, and response bodies do not enter reports or Debug output.

## Execution and accounting

The already committed parent control and canonical candidate are reused; they
are not sent again. One selected child uses exactly:

1. one shared-authority child bootstrap request;
2. one transformed candidate request; and
3. one transformed replay request with a distinct scanner-owned identity.

This is a ceiling of three child requests and one child active verification.
Every request crosses the existing redirect-disabled shared broker, retains the
same exact-origin and parameter authority, and charges the assessment's single
`RuntimeBudget`. Catalog growth does not add materializations, parsers, actions,
or requests. Budget exhaustion, cancellation, missing executor support, or any
incomplete evidence remains typed incomplete and cannot become successful
assessment output.

## Positive evidence and projection

`SemanticNormalizationGapObserved` requires all of these facts for both the
transformed candidate and its replay:

- complete response and accounting receipts with no redirect, origin expansion,
  or truncation;
- the exact transform ID/revision, parent family/revision, subject, parameter,
  and strategy lineage;
- absence of the canonical candidate's candidate-specific defensive block;
- the same exact inert DOM semantic verifier that the parent family uses; and
- committed observer/ledger evidence with candidate and replay identities that
  are exact and distinct.

Consequently, `canonical -> 403` and `transformed -> 200` is not a positive
result by itself. An accepted variant without the same inert parser structure
is `VariantAcceptedSemanticsUnknown`; a missing/mismatched replay, wrong host or
attribute, changed query shape, or source/DOM disagreement creates no
normalization-gap item.

The final item capability is a defensive normalization gap, never
`WafBypassConfirmed`. Its stable identity uses only opaque subject/parameter
identity plus versioned family, transform, verifier, and capability metadata.
Shared parent `EvidenceId` values are registered once by the aggregate
projection and may support both parent and normalization items.

## Deliberate limitations

- No generic or product-specific WAF-bypass claim.
- No SQL or SSTI normalization transforms.
- No script-context transform.
- No parameter pollution or other request-shape mutation.
- No request-framing, CRLF, splitting, or smuggling technique.
- No rate-limit evasion.
- No browser or JavaScript execution.
- No product-specific transform packs or automatic scanner-to-exploit path.

The removed historical `waf.rs` and blind `EvasionTechnique` dispatcher remain
forbidden. Modern defense fingerprinting remains observation-only and monotonic
enforcement can still only narrow existing work. The separately versioned
[post-workspace salvage ledger](../history/post-workspace-waf-evasion-salvage.md)
records only the typed HTML case and separator concepts as restored; unsafe,
blind, misleading, and request-shape behavior remains rejected or planned for a
different reviewed domain.
