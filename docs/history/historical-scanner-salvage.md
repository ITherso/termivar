# Historical scanner salvage ledger

This report is generated from `salvage/historical-scanner/ledger.toml`. Historical source is recovery evidence, not current product authority. No listed historical module participates in the current runtime merely because it appears here.

## Timeline and identity

| Event | Git identity |
| --- | --- |
| Workspace split | 3c90364279284bdbb82494b4e03d71b5066657c4 |
| Pre-deletion snapshot | ede3d9e5b1098434a771ae6ca3cb530941e22210 |
| Physical deletion | 28bfb2d8ae3a4f707b7423cac65b6be8e11085b6 |
| Current replacement baseline | cbca14d10db4ee641308f3b3e290bf75d937c8a7 |
| Semantic ledger digest | salvage-sha256:8c949aaea6e19707bcf1b1eee6e3552827c87ea0639915d6153c607209011165 |

## Classification summary

- Historical files: 38
- Classified components: 74
- P0/P1 recovery candidates: 11

| Disposition | Components |
| --- | ---: |
| archive-reference | 2 |
| import-fixture-corpus | 3 |
| import-metadata-only | 15 |
| port-algorithm | 1 |
| reject-fabricated-behavior | 9 |
| reject-misleading-claim | 18 |
| reject-unsafe-adapter | 5 |
| rewrite-from-contract | 11 |
| superseded-by-current-runtime | 10 |

## Historical file inventory

| Path | Blob | Bytes | Role | Build | Default runtime | Priority | Replacement |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| `src/scanner/analyzer.rs` | `ce5ddb0590e12dead0a57553d4391ffc36e20e67` | 10718 | analysis | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/anomaly_detector.rs` | `3b019843708d77d7dc6d8e6479dad49b00fb60f7` | 15154 | anomaly | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/api_scanner.rs` | `838ced24e954235b40e760ae24fd01eac025cba7` | 27680 | api-assessment | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/baseline.rs` | `a338ed2ebc654f5c0e95526bbf2bc818dd5d2b11` | 7250 | baseline | declared-but-unbuilt | unreachable | p2 | Current web assessment reflection and response evidence contracts. |
| `src/scanner/behavioral_analyzer.rs` | `a1b4122a8249956acee105d8827ae01cdfa4a9c5` | 16751 | behavioral | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/business_logic_fuzzer.rs` | `8e992960e378711db07e9fb4ad15957234399cae` | 38908 | business-logic | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/deserialization.rs` | `20bd32b0eb2120be2d0bc7ac8a6fa719ea85b628` | 27235 | deserialization | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/detector.rs` | `9796e2527fd32b794d98ff009f3d07cc08c3b1e8` | 8278 | signature-detection | declared-but-unbuilt | partially-reachable | p0 | — |
| `src/scanner/endpoint_fuzzer.rs` | `68c3c05b6df281d4967a2040de27d1858d1b5c5b` | 16423 | endpoint-fuzzing | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/error_handling.rs` | `a9660987663e7f1d75cf38567f16127939fadd69` | 11409 | error-handling | declared-but-unbuilt | unreachable | p3 | venom-core errors, scanner policy, shared broker, and RuntimeBudget. |
| `src/scanner/exploit_automation.rs` | `d660b09aded30620bd671a84dc4bf74866dad86c` | 36383 | exploit-research | declared-but-unbuilt | unreachable | p3 | venom-exploit manifest, authorization, plan, receipt, impact, and cleanup contracts. |
| `src/scanner/exploiter.rs` | `2d9b2c69ca6914004f49cc593af3861f25a10366` | 8407 | exploit-research | declared-but-unbuilt | reachable | never | — |
| `src/scanner/gadget_analyzer.rs` | `3c78ede7d4fffa83b74fde86a4651d13062c8c03` | 15883 | gadget-analysis | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/idor_detector.rs` | `93901e476a700049e773d3ae64a2108c5ef2ab1e` | 16748 | authorization | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/infrastructure_scanner.rs` | `f1c757819f3ab141a18ee4df7f676378d4e93029` | 41006 | infrastructure | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/integration_tests.rs` | `41366a4f6da3f252e7f0035f6a8314465054fe0b` | 20796 | test-fixture | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/ml_detection.rs` | `5a536fbecbee1bbe402d9fe15f379f9c4e20068e` | 15891 | machine-learning | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/mod.rs` | `ec9bb91213cadb8df21acf15f6655be92e73e30c` | 8690 | module-root | declared-but-unbuilt | reachable | p3 | Current venom-scanner WebAssessmentRuntime, shared broker, evidence ledger, and typed review actions. |
| `src/scanner/mutation.rs` | `736ebe80707de7d9080f88566e5a7871ed50a93e` | 13261 | mutation | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/oauth_jwt_breaker.rs` | `43b2c07af78435db1f3c203bc3e39efb5a541f29` | 32098 | authentication | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/osint_reconnaissance.rs` | `b2291695af02cfb435e59166c8c87cd8e83c29ad` | 31943 | reconnaissance | declared-but-unbuilt | unreachable | p3 | — |
| `src/scanner/parallel.rs` | `f84ce2c2ad5bd5dfc2241df8dbaf6b0ab8408904` | 9541 | concurrency | declared-but-unbuilt | unreachable | p3 | Current shared broker, bounded execution plans, cancellation, and RuntimeBudget. |
| `src/scanner/payloads.rs` | `1c698ec19d1a219edb665809517d69f5811cf994` | 1678 | payload-catalog | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/performance_benchmark.rs` | `2c18559a76fb8dd6cbef7930a56815315a49e420` | 13398 | benchmark | declared-but-unbuilt | unreachable | p3 | — |
| `src/scanner/release_config.rs` | `d783e621884dd0eabc77b758cd62f6c7dd0d23fe` | 15960 | release-configuration | declared-but-unbuilt | unreachable | p3 | — |
| `src/scanner/scoring.rs` | `87c55c601b59cc60f0a83a5a06b38c049ebf1e30` | 20714 | scoring | declared-but-unbuilt | unreachable | p2 | Current AssessmentDisposition, verifier policy, and evidence-backed projection. |
| `src/scanner/source_code_analyzer.rs` | `136727f6f74bbb81811390de9d546fc12d8e96fc` | 37449 | source-analysis | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/sqli_advanced.rs` | `7f2b920a998dc48d25a0c1a1511dacd3b535e0a4` | 22998 | sql-injection | declared-but-unbuilt | unreachable | p2 | Current bounded SQL structural control, candidate, replay, observer, and ledger review. |
| `src/scanner/sqli_expert.rs` | `5fcfb7ec4f53a1eaef85542ed2e121114f5b3dec` | 13244 | sql-injection | declared-but-unbuilt | unreachable | p3 | Current SQL structural review and replay evidence. |
| `src/scanner/sqli_payloads.rs` | `9968dad1f39750e9045c25d9d9884e07619b7387` | 17027 | payload-catalog | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/ssrf_detector.rs` | `ae7f38ef5aaa5521a5072378a5590fb8b8a8ec88` | 15430 | server-side-request | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/ssti_expert.rs` | `a550407e6e8f215371b2577a1b1ef681a281e0d7` | 10024 | template-injection | declared-but-unbuilt | unreachable | p2 | Current SSTI structural control, candidate, replay, observer, and ledger review. |
| `src/scanner/test_fixtures.rs` | `5f9baec25ca5d1b8049b70b477e94eac9e5972a9` | 15512 | test-fixture | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/threat_intelligence.rs` | `05f4751986c0a06d146ebbf6d39414a0d945c03c` | 12457 | threat-intelligence | declared-but-unbuilt | unreachable | p2 | — |
| `src/scanner/websocket_scanner.rs` | `ace607e084037d947e22bad5dd6bb657856786da` | 17627 | websocket | declared-but-unbuilt | unreachable | p1 | — |
| `src/scanner/xss_advanced.rs` | `88a0adae4606f754454cd9aab6955482171abaa5` | 23484 | cross-site-scripting | declared-but-unbuilt | unreachable | p2 | Current HTML, attribute, and JavaScript source-context XSS structural review. |
| `src/scanner/xss_expert.rs` | `2bb71e3f709d4c745729020b5e3654224cc5dd16` | 10631 | cross-site-scripting | declared-but-unbuilt | unreachable | p3 | Current source, DOM, and JavaScript-context XSS evidence and structural families. |
| `src/scanner/xss_payloads.rs` | `35a48a5754fb8286c3efd493932b60585c0f47c4` | 19551 | payload-catalog | declared-but-unbuilt | unreachable | p1 | — |

## Component classifications

| Component | Source | Disposition | Priority | Status | Destination | Prohibited restoration |
| --- | --- | --- | --- | --- | --- | --- |
| `analyzer.response-factors` | `src/scanner/analyzer.rs` | rewrite-from-contract | p2 | planned | venom-scanner:anomaly | misleading-claim, raw-sensitive-evidence |
| `analyzer.vulnerability-threshold` | `src/scanner/analyzer.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, automatic-severity |
| `anomaly.attack-classification` | `src/scanner/anomaly_detector.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, automatic-severity |
| `anomaly.feature-statistics` | `src/scanner/anomaly_detector.rs` | rewrite-from-contract | p2 | planned | future-venom-ml | unbounded-io, raw-sensitive-evidence |
| `api.protocol-taxonomy` | `src/scanner/api_scanner.rs` | rewrite-from-contract | p1 | planned | venom-scanner:api-assessment | legacy-runtime-coupling, random-identity |
| `api.unconditional-tests` | `src/scanner/api_scanner.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, random-identity, automatic-severity |
| `baseline.direct-collector` | `src/scanner/baseline.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | direct-network-authority, unbounded-io, legacy-runtime-coupling |
| `baseline.fingerprint-vocabulary` | `src/scanner/baseline.rs` | rewrite-from-contract | p2 | planned | venom-scanner:web-assessment | raw-sensitive-evidence, misleading-claim |
| `behavior.actor-classification` | `src/scanner/behavioral_analyzer.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, automatic-severity, raw-sensitive-evidence |
| `behavior.feature-vocabulary` | `src/scanner/behavioral_analyzer.rs` | rewrite-from-contract | p2 | planned | future-venom-ml | unbounded-io, raw-sensitive-evidence |
| `business-logic.fixed-findings` | `src/scanner/business_logic_fuzzer.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, random-identity, automatic-severity, raw-sensitive-evidence |
| `business-logic.workflow-taxonomy` | `src/scanner/business_logic_fuzzer.rs` | import-metadata-only | p1 | planned | venom-scanner:authz | fabricated-finding, automatic-severity |
| `deserialization.format-gadget-taxonomy` | `src/scanner/deserialization.rs` | import-metadata-only | p2 | planned | venom-exploit | raw-sensitive-evidence, automatic-severity |
| `deserialization.rce-inference` | `src/scanner/deserialization.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, random-identity, automatic-severity, raw-sensitive-evidence |
| `detector.byte-pattern` | `src/scanner/detector.rs` | port-algorithm | p0 | restored | venom-artifact | unbounded-io, misleading-claim, raw-sensitive-evidence |
| `detector.mmap-file-adapter` | `src/scanner/detector.rs` | reject-unsafe-adapter | never | rejected | none | unsafe-adapter, direct-filesystem-authority, unbounded-io |
| `detector.request-vulnerability` | `src/scanner/detector.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, random-identity, raw-sensitive-evidence, automatic-severity, legacy-runtime-coupling |
| `detector.unused-bmh-claim` | `src/scanner/detector.rs` | reject-misleading-claim | never | rejected | none | misleading-claim |
| `endpoint.simulated-discovery` | `src/scanner/endpoint_fuzzer.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, random-identity |
| `endpoint.wordlist-taxonomy` | `src/scanner/endpoint_fuzzer.rs` | import-metadata-only | p2 | planned | venom-scanner:api-assessment | direct-network-authority, unbounded-io |
| `error.legacy-config` | `src/scanner/error_handling.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | raw-sensitive-evidence, legacy-runtime-coupling |
| `exploit-automation.fabricated-success` | `src/scanner/exploit_automation.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, raw-sensitive-evidence, automatic-severity, random-identity |
| `exploit-automation.lifecycle-vocabulary` | `src/scanner/exploit_automation.rs` | superseded-by-current-runtime | p3 | superseded | venom-exploit | raw-sensitive-evidence, unconditional-success, legacy-runtime-coupling |
| `exploiter.generated-suggestions` | `src/scanner/exploiter.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, raw-sensitive-evidence, automatic-severity, legacy-runtime-coupling |
| `exploiter.searchsploit-process` | `src/scanner/exploiter.rs` | reject-unsafe-adapter | never | rejected | none | process-authority, unbounded-io, raw-sensitive-evidence, legacy-runtime-coupling |
| `gadget.library-taxonomy` | `src/scanner/gadget_analyzer.rs` | import-metadata-only | p2 | planned | venom-exploit | raw-sensitive-evidence, automatic-severity |
| `gadget.rce-score` | `src/scanner/gadget_analyzer.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, random-identity, automatic-severity, raw-sensitive-evidence |
| `idor.direct-prober` | `src/scanner/idor_detector.rs` | reject-unsafe-adapter | never | rejected | none | direct-network-authority, unbounded-io, legacy-runtime-coupling, misleading-claim |
| `idor.reference-mutation` | `src/scanner/idor_detector.rs` | rewrite-from-contract | p1 | planned | venom-scanner:authz | direct-network-authority, misleading-claim |
| `infrastructure.example-findings` | `src/scanner/infrastructure_scanner.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, random-identity, raw-sensitive-evidence, automatic-severity |
| `infrastructure.resource-taxonomy` | `src/scanner/infrastructure_scanner.rs` | import-metadata-only | p2 | planned | documentation-only | fabricated-finding, raw-sensitive-evidence |
| `integration.fixture-cases` | `src/scanner/integration_tests.rs` | import-fixture-corpus | p2 | planned | fixture-corpus | fabricated-finding, raw-sensitive-evidence |
| `integration.generated-report` | `src/scanner/integration_tests.rs` | archive-reference | p3 | planned | documentation-only | misleading-claim |
| `ml.feature-clustering-research` | `src/scanner/ml_detection.rs` | rewrite-from-contract | p1 | planned | future-venom-ml | raw-sensitive-evidence, automatic-severity, misleading-claim |
| `ml.zero-day-claims` | `src/scanner/ml_detection.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, automatic-severity |
| `scanner-root.direct-client` | `src/scanner/mod.rs` | reject-unsafe-adapter | never | rejected | none | direct-network-authority, unbounded-io, legacy-runtime-coupling |
| `scanner-root.facade-intent` | `src/scanner/mod.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | legacy-runtime-coupling, raw-sensitive-evidence |
| `scanner-root.heuristic-findings` | `src/scanner/mod.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, random-identity, raw-sensitive-evidence, automatic-severity |
| `mutation.payload-taxonomy` | `src/scanner/mutation.rs` | import-metadata-only | p1 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |
| `oauth-jwt.fabricated-findings` | `src/scanner/oauth_jwt_breaker.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, random-identity, raw-sensitive-evidence, automatic-severity |
| `oauth-jwt.protocol-taxonomy` | `src/scanner/oauth_jwt_breaker.rs` | rewrite-from-contract | p1 | planned | venom-scanner:authz | raw-sensitive-evidence, automatic-severity |
| `osint.category-taxonomy` | `src/scanner/osint_reconnaissance.rs` | import-metadata-only | p3 | planned | documentation-only | raw-sensitive-evidence, fabricated-finding |
| `osint.fabricated-recon` | `src/scanner/osint_reconnaissance.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, random-identity, raw-sensitive-evidence, automatic-severity |
| `parallel.scheduler-contract` | `src/scanner/parallel.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | unbounded-io, legacy-runtime-coupling |
| `parallel.stub-completion` | `src/scanner/parallel.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, unconditional-success |
| `payloads.small-corpus` | `src/scanner/payloads.rs` | import-metadata-only | p2 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |
| `benchmark.scenario-corpus` | `src/scanner/performance_benchmark.rs` | import-fixture-corpus | p3 | planned | fixture-corpus | misleading-claim |
| `benchmark.simulated-results` | `src/scanner/performance_benchmark.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, unconditional-success |
| `release.fabricated-quality-metrics` | `src/scanner/release_config.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, unconditional-success |
| `release.historical-inventory` | `src/scanner/release_config.rs` | archive-reference | p3 | planned | documentation-only | misleading-claim |
| `scoring.automatic-disposition` | `src/scanner/scoring.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, random-identity, automatic-severity |
| `scoring.factor-vocabulary` | `src/scanner/scoring.rs` | rewrite-from-contract | p2 | planned | documentation-only | automatic-severity, misleading-claim |
| `source-analysis.pattern-taxonomy` | `src/scanner/source_code_analyzer.rs` | rewrite-from-contract | p2 | planned | venom-artifact | raw-sensitive-evidence, automatic-severity |
| `source-analysis.substring-findings` | `src/scanner/source_code_analyzer.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, random-identity, raw-sensitive-evidence, automatic-severity |
| `sqli-advanced.direct-extraction` | `src/scanner/sqli_advanced.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | direct-network-authority, unbounded-io, raw-sensitive-evidence, misleading-claim |
| `sqli-advanced.technique-taxonomy` | `src/scanner/sqli_advanced.rs` | import-metadata-only | p2 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |
| `sqli-expert.differential-intent` | `src/scanner/sqli_expert.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | direct-network-authority, legacy-runtime-coupling |
| `sqli-expert.heuristic-confirmation` | `src/scanner/sqli_expert.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, direct-network-authority, automatic-severity, raw-sensitive-evidence |
| `sqli-payloads.catalog` | `src/scanner/sqli_payloads.rs` | import-metadata-only | p1 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |
| `ssrf.direct-prober` | `src/scanner/ssrf_detector.rs` | reject-unsafe-adapter | never | rejected | none | direct-network-authority, unbounded-io, legacy-runtime-coupling, misleading-claim |
| `ssrf.vector-taxonomy` | `src/scanner/ssrf_detector.rs` | import-metadata-only | p2 | planned | venom-scanner:oast | direct-network-authority, unbounded-io |
| `ssti.direct-review` | `src/scanner/ssti_expert.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | direct-network-authority, legacy-runtime-coupling, misleading-claim |
| `ssti.engine-taxonomy` | `src/scanner/ssti_expert.rs` | import-metadata-only | p2 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |
| `fixtures.request-response-corpus` | `src/scanner/test_fixtures.rs` | import-fixture-corpus | p1 | planned | fixture-corpus | raw-sensitive-evidence, fabricated-finding |
| `fixtures.synthetic-vulnerabilities` | `src/scanner/test_fixtures.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, fabricated-finding, automatic-severity |
| `threat-intel.ioc-taxonomy` | `src/scanner/threat_intelligence.rs` | rewrite-from-contract | p2 | planned | documentation-only | raw-sensitive-evidence, automatic-severity |
| `threat-intel.static-claims` | `src/scanner/threat_intelligence.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, unconditional-success, automatic-severity |
| `websocket.protocol-taxonomy` | `src/scanner/websocket_scanner.rs` | import-metadata-only | p1 | planned | future-websocket-domain | fabricated-finding, raw-sensitive-evidence |
| `websocket.unconditional-findings` | `src/scanner/websocket_scanner.rs` | reject-fabricated-behavior | never | rejected | none | fabricated-finding, unconditional-success, random-identity, raw-sensitive-evidence, automatic-severity |
| `xss-advanced.context-taxonomy` | `src/scanner/xss_advanced.rs` | import-metadata-only | p2 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |
| `xss-advanced.direct-scanner` | `src/scanner/xss_advanced.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | direct-network-authority, legacy-runtime-coupling, misleading-claim, raw-sensitive-evidence |
| `xss-expert.context-intent` | `src/scanner/xss_expert.rs` | superseded-by-current-runtime | p3 | superseded | venom-scanner:web-assessment | legacy-runtime-coupling, raw-sensitive-evidence |
| `xss-expert.reflection-claim` | `src/scanner/xss_expert.rs` | reject-misleading-claim | never | rejected | none | misleading-claim, direct-network-authority, raw-sensitive-evidence, automatic-severity |
| `xss-payloads.catalog` | `src/scanner/xss_payloads.rs` | import-metadata-only | p1 | planned | venom-scanner:payload-catalog | direct-network-authority, raw-sensitive-evidence |

## P0/P1 recovery roadmap

- `api.protocol-taxonomy` → `venom-scanner:api-assessment` (planned): Rebuild from typed protocol evidence rather than preserve the scaffold.
- `business-logic.workflow-taxonomy` → `venom-scanner:authz` (planned): Only metadata can be imported before real workflow authority exists.
- `detector.byte-pattern` → `venom-artifact` (restored; implementation `venom_artifact::ArtifactScanner (venom.artifact-signature-scan/v1)`): Venom Artifact V1 cleanly reimplements the bounded exact/wildcard matcher and does not copy the historical monolith.
- `idor.reference-mutation` → `venom-scanner:authz` (planned): Authorization review must be rebuilt around identity and authority, not response similarity alone.
- `ml.feature-clustering-research` → `future-venom-ml` (planned): Rebuild only after a genuine model and evaluation contract exists.
- `mutation.payload-taxonomy` → `venom-scanner:payload-catalog` (planned): Import only reviewed metadata in a later payload-catalog mission.
- `oauth-jwt.protocol-taxonomy` → `venom-scanner:authz` (planned): Rebuild from protocol and identity evidence rather than reuse the analyzer.
- `sqli-payloads.catalog` → `venom-scanner:payload-catalog` (planned): Candidate strings require individual evidence-compatible review before activation.
- `fixtures.request-response-corpus` → `fixture-corpus` (planned): Selected inputs may improve current tests after evidence expectations are rewritten.
- `websocket.protocol-taxonomy` → `future-websocket-domain` (planned): Only metadata should survive until a real bounded protocol domain exists.
- `xss-payloads.catalog` → `venom-scanner:payload-catalog` (planned): Each future candidate requires separate safe evidence review before activation.

## Explicitly rejected historical behavior

- `analyzer.vulnerability-threshold`: A response difference is not vulnerability confirmation.
- `anomaly.attack-classification`: Heuristic anomalies cannot silently become attack or vulnerability claims.
- `api.unconditional-tests`: No API request or response evidence supported the findings.
- `behavior.actor-classification`: Uncalibrated behavioral heuristics cannot establish attacker identity.
- `business-logic.fixed-findings`: No target workflow was executed or observed.
- `deserialization.rce-inference`: A serialized marker or gadget name does not prove trigger or impact.
- `detector.mmap-file-adapter`: A future CLI must use a safe bounded reader and explicit file authority.
- `detector.request-vulnerability`: Payload presence in a request is not target evidence or a vulnerability.
- `detector.unused-bmh-claim`: The production loop was a sliding window and skipped overlapping matches after success.
- `endpoint.simulated-discovery`: Discovery requires real bounded response evidence.
- `exploit-automation.fabricated-success`: Fabricated trigger and impact records violate current exploit lifecycle semantics.
- `exploiter.generated-suggestions`: A label cannot authorize or substantiate an exploit.
- `exploiter.searchsploit-process`: No implicit external process belongs in scanner finding projection.
- `gadget.rce-score`: Gadget names do not prove deserialization, trigger, or impact.
- `idor.direct-prober`: Any future IDOR execution must use explicit subject and authorization contracts.
- `infrastructure.example-findings`: Hard-coded examples cannot be emitted as target observations.
- `ml.zero-day-claims`: No trained, wired, calibrated, or provenance-bound model existed.
- `scanner-root.direct-client`: Every current request must use exact-origin shared authority and RuntimeBudget.
- `scanner-root.heuristic-findings`: Current structural evidence produces at most conservative review unless a verifier is authorized.
- `oauth-jwt.fabricated-findings`: Token metadata does not prove server acceptance or authorization bypass.
- `osint.fabricated-recon`: No source query or provenance supported the output.
- `parallel.stub-completion`: A queued task is not completed execution.
- `benchmark.simulated-results`: Synthetic helper timing is not product performance evidence.
- `release.fabricated-quality-metrics`: Quality metrics require measured reproducible evidence.
- `scoring.automatic-disposition`: Severity cannot create vulnerability evidence or confirmation authority.
- `source-analysis.substring-findings`: Substring presence does not prove reachability, control flow, or impact.
- `sqli-expert.heuristic-confirmation`: Timing and error strings alone cannot confirm SQL injection.
- `ssrf.direct-prober`: Sensitive SSRF targets require separate explicit authority and correlated evidence.
- `fixtures.synthetic-vulnerabilities`: A fixture can exercise a contract but cannot prove real vulnerability behavior.
- `threat-intel.static-claims`: Threat intelligence requires source provenance and freshness evidence.
- `websocket.unconditional-findings`: No WebSocket connection, message exchange, or target evidence occurred.
- `xss-expert.reflection-claim`: Reflection and sink text do not establish structural control or execution.

## Restoration policy

A future restoration must update the relevant component from `planned` to `restored`, name its modern implementation, and pass current architecture, evidence, coverage, and exact-head CI contracts. The old monolith is not restored as a product runtime.
