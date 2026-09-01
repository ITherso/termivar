# Post-workspace WAF/evasion salvage ledger

This report is generated from the authoritative TOML ledger. Historical WAF/evasion source is recovery evidence, not current product authority. This is a separate source epoch from the pre-workspace 38-file scanner inventory.

## Timeline and identity

| Event | Git identity |
| --- | --- |
| Historical source snapshot | 52238460484e7a1469f1028fdd6361072a0daba5 |
| Quarantine/removal | 5a0563886658859b6e3e163f732a298914b10800 |
| Current replacement baseline | e1e4077d159d6df5cdca8e274ecd40b40bb2f9c5 |
| Semantic ledger digest | waf-evasion-salvage-sha256:2218688ac3f99b707d6206a8351b8deb2af4cd8e640a6e6f3e41df01c4f3efef |
| Prior source-epoch digest | salvage-sha256:8c949aaea6e19707bcf1b1eee6e3552827c87ea0639915d6153c607209011165 |

## Classification summary

- Historical files: 13
- Classified components: 39
- P0/P1 recovery candidates: 10

| Disposition | Components |
| --- | ---: |
| archive-reference | 5 |
| import-metadata-only | 5 |
| move-to-different-capability | 2 |
| reject-blind-dispatcher | 6 |
| reject-misleading-claim | 4 |
| reject-unsafe-technique | 1 |
| rewrite-from-contract | 8 |
| superseded-by-current-runtime | 8 |

## Historical file inventory

| Path | Blob | Bytes | Quarantine | Role | Replacement |
| --- | --- | ---: | --- | --- | --- |
| crates/venom-scanner/src/adaptive/mod.rs | 98075bcbbd7ab1dd140b59d14277d1f8b1b8cf07 | 5286 | materially-narrowed | adaptive-orchestration | crates/venom-scanner/src/adaptive/pipeline.rs, crates/venom-scanner/src/defense/state.rs, crates/venom-scanner/src/defense/transition.rs |
| crates/venom-scanner/src/adaptive/payloads.rs | 75e5c863e53cf580ed6d3df2a3b86818ee7b8b41 | 17516 | removed | adaptive-payload-transforms | crates/venom-scanner/src/payload_strategies/encoding.rs, crates/venom-scanner/src/payload_strategy.rs |
| crates/venom-scanner/src/adaptive/scoring.rs | 1e57275eafb0a5b7f4532273cddda2d190d71c5f | 17375 | removed | adaptive-response-scoring | crates/venom-scanner/src/defense/state.rs, crates/venom-scanner/src/defense/transition.rs |
| crates/venom-scanner/src/adaptive/strategy.rs | 5f61539efe99b163e73b7b34f25a25655b4589a3 | 3305 | removed | adaptive-strategy-selection | crates/venom-scanner/src/defense/policy.rs, crates/venom-scanner/src/defense/transition.rs |
| crates/venom-scanner/src/advanced_detection.rs | f1e5cd86985462295148b8f060d3b07c1ebbf4ca | 14944 | materially-narrowed | defense-evasion-analysis | crates/venom-scanner/src/advanced_detection.rs |
| crates/venom-scanner/src/api.rs | 7e396bc2d5ffc7384c8e979b48b6cb60d4387bb9 | 10733 | materially-narrowed | api-configuration | crates/venom-scanner/src/api.rs |
| crates/venom-scanner/src/config.rs | b419bd6404415185592e7171769d07bdf1f17ecd | 8857 | materially-narrowed | scanner-configuration | crates/venom-scanner/src/config.rs |
| crates/venom-scanner/src/config_loader.rs | cebc6c466c84d72c1f0beeb0f0607486ee91c054 | 14147 | materially-narrowed | configuration-loading | crates/venom-scanner/src/config_loader.rs |
| crates/venom-scanner/src/lib.rs | 3c8b6ddf2ed34670fd8d8d07385e75e916482638 | 17487 | materially-narrowed | crate-api-surface | crates/venom-scanner/src/lib.rs, crates/venom-scanner/src/defense/fingerprint.rs, crates/venom-scanner/src/payload_strategies/encoding.rs |
| crates/venom-scanner/src/payload_strategies/encoding.rs | c32c4752e7e2befac8ec0c8086be690476e42269 | 11909 | materially-narrowed | payload-encoding | crates/venom-scanner/src/payload_strategies/encoding.rs, crates/venom-scanner/src/payload_strategy.rs |
| crates/venom-scanner/src/payload_strategies/mod.rs | 43f2faff46737a9e3bd7223d4377d635f4e0e2a9 | 3949 | materially-narrowed | payload-strategy-exports | crates/venom-scanner/src/payload_strategies/mod.rs, crates/venom-scanner/src/payload_strategies/encoding.rs |
| crates/venom-scanner/src/payload_strategies/normalization.rs | c94f06c536b1a2d9dd4bdb0d1e62bde887bd4e09 | 2233 | removed | payload-normalization | — |
| crates/venom-scanner/src/waf.rs | 171a4c324069e5747c747fcdd82a107c1409bc73 | 8777 | removed | waf-fingerprint-and-transforms | crates/venom-scanner/src/defense/fingerprint.rs, crates/venom-scanner/src/defense/state.rs, crates/venom-scanner/src/defense/transition.rs, crates/venom-scanner/src/payload_strategies/encoding.rs, crates/venom-scanner/src/payload_strategy.rs |

## Component classifications

| Component | Source | Disposition | Priority | Status | Destination | Current replacement | Prohibited restoration | Rationale |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| adaptive.legacy-engine-orchestration | crates/venom-scanner/src/adaptive/mod.rs | superseded-by-current-runtime | p1 | superseded | venom-scanner:defense-state-transition | crates/venom-scanner/src/adaptive/pipeline.rs, crates/venom-scanner/src/defense/state.rs, crates/venom-scanner/src/defense/transition.rs | blind-dispatch, status-only-authority, rate-limit-evasion | The old engine had no repository runtime caller and coupled heuristic scoring to mutations; current observation and execution authority are separate. |
| adaptive.composite-chains | crates/venom-scanner/src/adaptive/payloads.rs | import-metadata-only | p2 | metadata-only | venom-scanner:normalization-resilience | — | unbounded-transform-chain, generic-string-mutation | Composition may remain catalog metadata, while V1 execution stays at one compatible transform. |
| adaptive.decoy-parameters | crates/venom-scanner/src/adaptive/payloads.rs | move-to-different-capability | p2 | planned | future-typed-request-shape | — | generic-string-mutation, request-shape-mutation | Adding parameters changes request shape and is not a payload-byte normalization. |
| adaptive.pattern-mutation-dispatch | crates/venom-scanner/src/adaptive/payloads.rs | reject-blind-dispatcher | never | rejected | none | — | blind-dispatch, status-only-authority, rate-limit-evasion, request-shape-mutation | Response labels do not prove transform compatibility, semantic equivalence, or request authority. |
| adaptive.payload-reduction | crates/venom-scanner/src/adaptive/payloads.rs | reject-misleading-claim | never | rejected | none | — | semantic-truncation, generic-string-mutation, misleading-bypass-claim | Truncation is not semantic-preserving and cannot be called an equivalent representation. |
| adaptive.raw-transformers | crates/venom-scanner/src/adaptive/payloads.rs | rewrite-from-contract | p1 | planned | venom-scanner:normalization-resilience | — | generic-string-mutation, misleading-bypass-claim | Useful concepts require separate HTML and future SQL contracts, not restoration of raw mutations. |
| adaptive.transformer-taxonomy | crates/venom-scanner/src/adaptive/payloads.rs | import-metadata-only | p1 | metadata-only | venom-scanner:normalization-resilience | — | blind-dispatch, generic-string-mutation | Family names may enter a catalog without making every entry executable. |
| adaptive.unbounded-transformer-trait | crates/venom-scanner/src/adaptive/payloads.rs | rewrite-from-contract | p1 | planned | venom-scanner:normalization-resilience | — | generic-string-mutation, unbounded-transform-chain, blind-dispatch | The open trait provided no compatibility, risk, request-cost, or semantic guarantees. |
| adaptive.scoring-dimensions | crates/venom-scanner/src/adaptive/scoring.rs | import-metadata-only | p1 | metadata-only | venom-scanner:defense-state-transition | — | status-only-authority, misleading-bypass-claim | Dimensions can inform metadata-first ranking, but the old numeric score did not measure bypass probability. |
| adaptive.uncalibrated-detection-score | crates/venom-scanner/src/adaptive/scoring.rs | reject-misleading-claim | never | rejected | none | — | status-only-authority, blind-dispatch, misleading-bypass-claim | The score was uncalibrated and did not prove candidate-specific defense or semantic equivalence. |
| adaptive.no-pattern-hpp-map | crates/venom-scanner/src/adaptive/strategy.rs | reject-blind-dispatcher | never | rejected | none | — | blind-dispatch, request-shape-mutation | Missing evidence cannot authorize duplicate parameters. |
| adaptive.rate-limit-map | crates/venom-scanner/src/adaptive/strategy.rs | superseded-by-current-runtime | p1 | superseded | venom-scanner:defense-state-transition | crates/venom-scanner/src/defense/policy.rs, crates/venom-scanner/src/defense/state.rs | rate-limit-evasion, blind-dispatch, request-shape-mutation | Current policy backs off or suppresses work; rate limiting never authorizes method rotation. |
| adaptive.status-evasion-map | crates/venom-scanner/src/adaptive/strategy.rs | reject-blind-dispatcher | never | rejected | none | — | status-only-authority, blind-dispatch, semantic-truncation, request-shape-mutation | Selection instead requires candidate-specific evidence, compatibility, budget, semantic proof, and replay. |
| adaptive.strategy-taxonomy | crates/venom-scanner/src/adaptive/strategy.rs | import-metadata-only | p1 | metadata-only | venom-scanner:normalization-resilience | — | blind-dispatch, rate-limit-evasion, request-shape-mutation | The taxonomy stays inert until each family has its own authority and verifier contract. |
| advanced.signature-evasion-selection | crates/venom-scanner/src/advanced_detection.rs | reject-blind-dispatcher | never | rejected | none | — | blind-dispatch, misleading-bypass-claim, fingerprint-as-authority | A label and self-reported score cannot authorize a transform or prove defensive success. |
| advanced.transform-taxonomy | crates/venom-scanner/src/advanced_detection.rs | import-metadata-only | p2 | metadata-only | venom-scanner:normalization-resilience | — | misleading-bypass-claim, fingerprint-as-authority | Taxonomy may remain inert metadata while executable transforms use separate typed contracts. |
| advanced.uncalibrated-bypass-ranking | crates/venom-scanner/src/advanced_detection.rs | reject-misleading-claim | never | rejected | none | — | misleading-bypass-claim, fingerprint-as-authority, blind-dispatch | Uncalibrated metadata is neither effectiveness evidence nor execution authority. |
| api.dead-waf-adaptive-flags | crates/venom-scanner/src/api.rs | archive-reference | p3 | archived | documentation-only | — | blind-dispatch, fingerprint-as-authority | The flags carried no authority and must not return as compatibility switches. |
| config.dead-evasion-presets | crates/venom-scanner/src/config.rs | archive-reference | p3 | archived | documentation-only | — | blind-dispatch, fingerprint-as-authority | Descriptive presets cannot grant transformation or request authority. |
| config-loader.dead-waf-labels | crates/venom-scanner/src/config_loader.rs | archive-reference | p3 | archived | documentation-only | — | blind-dispatch, fingerprint-as-authority | A label cannot replace feature gating, opt-in, executor binding, and evidence completeness. |
| lib.legacy-waf-adaptive-exports | crates/venom-scanner/src/lib.rs | archive-reference | p3 | archived | documentation-only | — | blind-dispatch, fingerprint-as-authority, misleading-bypass-claim | Public history is provenance, not authority to restore removed modules. |
| relocated.artifact-envelope | crates/venom-scanner/src/payload_strategies/encoding.rs | superseded-by-current-runtime | p0 | superseded | venom-scanner:payload-artifact | crates/venom-scanner/src/payload_strategy.rs | raw-payload-evidence | PayloadArtifact remains the mandatory output boundary for future transforms. |
| relocated.double-encoding | crates/venom-scanner/src/payload_strategies/encoding.rs | rewrite-from-contract | p2 | planned | venom-scanner:normalization-resilience | — | ambiguous-encoding-layer, generic-string-mutation, misleading-bypass-claim | Two generic encoding calls do not establish a valid two-layer application contract. |
| relocated.evasion-dispatch | crates/venom-scanner/src/payload_strategies/encoding.rs | reject-blind-dispatcher | never | rejected | none | — | blind-dispatch, generic-string-mutation, request-shape-mutation, http-splitting, crlf-injection | The dispatcher lacked compatibility, semantic proof, risk selection, accounting, and lineage. |
| relocated.neutral-percent-hex | crates/venom-scanner/src/payload_strategies/encoding.rs | superseded-by-current-runtime | p1 | superseded | venom-scanner:payload-strategies-encoding | crates/venom-scanner/src/payload_strategies/encoding.rs | ambiguous-encoding-layer, misleading-bypass-claim | Current percent and hex primitives remove attack dispatch and bypass claims. |
| payload-strategies.legacy-normalization-exports | crates/venom-scanner/src/payload_strategies/mod.rs | archive-reference | p3 | archived | documentation-only | — | blind-dispatch, generic-string-mutation | The export itself has no runtime value and must not recreate the removed raw-string mutation boundary. |
| relocated.raw-normalization-helpers | crates/venom-scanner/src/payload_strategies/normalization.rs | rewrite-from-contract | p0 | planned | venom-scanner:normalization-resilience | — | generic-string-mutation, misleading-bypass-claim | Only a contract-driven rewrite can separate equivalent representation review from blind evasion mutation. |
| waf.case-variation | crates/venom-scanner/src/waf.rs | rewrite-from-contract | p0 | planned | venom-scanner:normalization-resilience | — | generic-string-mutation, misleading-bypass-claim | Grammar-aware token transformation is required so identity values and target-controlled text remain unchanged. |
| waf.double-url-encoding | crates/venom-scanner/src/waf.rs | rewrite-from-contract | p2 | planned | venom-scanner:normalization-resilience | — | ambiguous-encoding-layer, generic-string-mutation, misleading-bypass-claim | Two encoder calls do not establish a valid two-layer representation contract. |
| waf.generic-evasion-dispatch | crates/venom-scanner/src/waf.rs | reject-blind-dispatcher | never | rejected | none | — | blind-dispatch, generic-string-mutation, unbounded-transform-chain, request-shape-mutation, misleading-bypass-claim | The dispatcher lacked context compatibility, semantic verification, request accounting, evidence lineage, and risk-aware selection. |
| waf.header-body-fingerprint | crates/venom-scanner/src/waf.rs | superseded-by-current-runtime | p0 | superseded | venom-scanner:defense-fingerprint | crates/venom-scanner/src/defense/fingerprint.rs | fingerprint-as-authority, product-misclassification, status-only-authority | Modern bounded fingerprinting supersedes exact header reconstruction and ambiguous infrastructure claims. |
| waf.hex-encoding | crates/venom-scanner/src/waf.rs | superseded-by-current-runtime | p1 | superseded | venom-scanner:payload-strategies-encoding | crates/venom-scanner/src/payload_strategies/encoding.rs | ambiguous-encoding-layer, misleading-bypass-claim | Neutral hexadecimal output does not imply application-semantic equivalence or defense bypass. |
| waf.http-splitting | crates/venom-scanner/src/waf.rs | reject-unsafe-technique | never | rejected | future-request-framing | — | http-splitting, crlf-injection, request-shape-mutation | Request framing and CRLF techniques are forbidden in the low-risk normalization domain. |
| waf.parameter-pollution | crates/venom-scanner/src/waf.rs | move-to-different-capability | p1 | planned | future-typed-request-shape | — | request-shape-mutation, generic-string-mutation, blind-dispatch | HPP is not an ordinary payload representation and must not execute in normalization V1. |
| waf.product-vocabulary | crates/venom-scanner/src/waf.rs | superseded-by-current-runtime | p2 | superseded | venom-scanner:defense | crates/venom-scanner/src/defense/fingerprint.rs | product-misclassification, fingerprint-as-authority | Restoring the legacy enum would duplicate current defense identity without adding authority. |
| waf.sql-comment-injection | crates/venom-scanner/src/waf.rs | rewrite-from-contract | p1 | planned | venom-scanner:payload-catalog | — | generic-string-mutation, blind-dispatch, misleading-bypass-claim | Generic string replacement cannot establish SQL semantic equivalence and is not executable in normalization V1. |
| waf.status-only-detection | crates/venom-scanner/src/waf.rs | reject-misleading-claim | never | rejected | venom-scanner:defense-state-transition | — | status-only-authority, fingerprint-as-authority, misleading-bypass-claim | A status code alone cannot prove a defensive product or candidate-specific engagement. |
| waf.url-percent-encoding | crates/venom-scanner/src/waf.rs | superseded-by-current-runtime | p1 | superseded | venom-scanner:payload-strategies-encoding | crates/venom-scanner/src/payload_strategies/encoding.rs | ambiguous-encoding-layer, misleading-bypass-claim | Any active resilience use still requires a separate versioned exact-wire decode-layer contract. |
| waf.whitespace-variation | crates/venom-scanner/src/waf.rs | rewrite-from-contract | p0 | planned | venom-scanner:normalization-resilience | — | generic-string-mutation, crlf-injection, misleading-bypass-claim | Whitespace transformation must be grammar-specific and bounded rather than string-wide. |

## Current replacement map

- Historical WAF fingerprinting maps to defense::fingerprint.
- Historical status/body observation maps to DefenseState and DefenseTransition.
- Historical neutral percent/hex encoding maps to payload_strategies::encoding.
- Historical blind adaptive selection remains rejected; an evidence-driven selector belongs to a separately reviewed capability.
- Historical generic evasion output maps to the PayloadArtifact boundary, not to raw report evidence.
- Historical response comparison maps to committed control/candidate/replay evidence.

WAF fingerprinting was not lost; it was replaced more safely. Blind evasion selection was removed. Several useful transformation concepts remain recoverable. HTTP splitting does not belong in a low-risk normalization domain. PR B restores only a bounded, semantically verified first subset.
