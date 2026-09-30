# Harmless template-evaluation semantics review

`template-evaluation-review` is an experimental, development-only scanner and
CLI feature. It is unavailable in the default build, the seven-member
`release-bundle`, and published `v0.10.0-alpha.2` archives. Compilation alone
does not run it.

## Selection

The actual interface is:

```text
termivar scan http://127.0.0.1:<owned-port>/?name=seed \
  --profile web-review \
  --template-evaluation-review \
  --report-dir <new-directory>
```

The option is valid only with explicit `web-review`. Option absence preserves
the existing plan and adds no template-evaluation request, retained state,
audit, or item. An eligible query parameter name must already be present on the
explicit root URL and pass the existing bounded SSTI query-name selection. The
feature does not discover a new endpoint or input.

## Closed harmless case

V1 owns exactly two independently seeded semantic cases: primary and replay.
Each sends one literal control and one candidate through the existing
exact-origin assessment broker. The candidate applies the Jinja-compatible
`upper` filter to a scanner-owned lowercase ASCII literal. It contains no
function call, attribute or object traversal, indexing, statement separator,
path, URL, file operation, process operation, or callback primitive.

The pairs join the root native-review runtime and reuse its existing bootstrap.
The additional ceiling is exactly four broker requests, of which the two
candidate legs are active work. These counts share the existing parent request,
active, byte, deadline, cancellation, evidence, and defense authority; smaller
parent limits still win. Requests are sequential, anonymous, bodyless GETs.
Redirects remain disabled and no retry or alternate payload family exists.

Only complete supported textual responses that commit through the ordinary
evidence transaction can affect the result. The primary and replay candidates
must each contain their own exact transformed value while their controls do
not. Results are classified as `parent_not_observed`, `literal_or_escaped`,
`unsupported_representation`, `replay_mismatch`,
`candidate_specific_evaluation`, or `incomplete`.

## Claim boundary

A complete `candidate_specific_evaluation` may add one
`web.review.template-evaluation.jinja-compatible-semantics@1` item with
`NeedsReview` disposition and `KnowledgeOnly` authority. It means only that the
two responses were consistent with the finite listed expression semantics.
It does not identify Jinja, MiniJinja, or any other engine. It does not establish
a vulnerability, code execution, file access, outbound interaction,
exploitability, or impact. The other outcomes add no item.

The value-free `security.template-evaluation-review-audit/v1` records the fixed
family and policy identities, reconciled selection/request/response/commit/item
counts, terminal outcome, and explicit claim limits. It never stores the query
name, candidate, expected value, response body, raw URL, local path, or engine
error. The central JSON, HTML, Markdown and CSV behavior remains under existing
report rules. Report Verify checks bundle bytes and strict schema consistency;
it does not prove the target interpretation. Report Compare treats policy,
coverage and outcome changes separately and does not relabel them remediation.

## Qualification

Unit tests cover derivation, bounded response classification, evidence
commitment, replay disagreement, cancellation and limits. Real-process
acceptance uses a numeric-loopback owned MiniJinja fixture with independently
declared expected behavior. MiniJinja is test-only: production does not embed a
template engine or infer its identity from target responses. Offline Verify and
Compare acceptance runs only after the fixture is stopped.
