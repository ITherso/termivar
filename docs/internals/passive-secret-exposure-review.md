# Passive response secret-exposure review

The non-default scanner and CLI feature `secret-exposure-review` adds a
bounded, value-free observer to the existing `WebAssessmentRuntime`. It is a
Preview capability on the unreleased `0.10.0-alpha.3` development line. It is
not part of `default` or `release-bundle`, and it is absent from the published
`v0.10.0-alpha.2` archives.

Compilation does not activate the observer. A feature-enabled binary requires
both the `web-review` profile and the explicit option:

```console
termivar scan https://app.example.test/ \
  --profile web-review \
  --secret-exposure-review \
  --report-dir assessment-secret-exposure
```

The operator must already be authorized to assess the selected target. This
option schedules no target or provider request of its own, never widens action
selection, and does not turn a `HEAD` into a `GET`. It observes only ordinary
anonymous response bodies inside the same evidence transaction; only the later
validated commit can make its value-free records usable by the audit. Every
observed body, including an evaluated zero-match, uses value-free lineage in
place of its public whole-body digest and is withheld from generic and WordPress
body-derived projection. The fixed catalogue is finite, so zero matches cannot
prove that another low-entropy secret is absent. The audit counts these withheld
responses; the option can therefore reduce downstream body-derived selection
without adding work of its own.

## Admission boundary

One response can enter the detector only when all of these conditions hold:

- the request was an ordinary bodyless `GET` with no explicit request headers;
- the response belongs to the exact requested URL, with no redirect;
- the response status is exactly `200`;
- the body is complete and its retained byte count is consistent with the
  response evidence;
- no `Content-Encoding` was present;
- `Content-Length`, when supplied, is consistent with the complete body;
- the media type is a supported textual type;
- the body is valid UTF-8 and no larger than 128 KiB; and
- the evidence transaction committed before the observation can affect the
  final audit or item set.

Supported media types are `text/*`, JSON and XML types (including structured
`+json` and `+xml` suffixes), JavaScript, URL-encoded form data, XHTML, and SVG.
An absent or unsupported media type is not guessed from the URL or contents.
Compressed, partial, redirected, credentialed, probe/control, failed, and
uncommitted representations remain typed non-evaluated outcomes.

The first slice deliberately does not inspect supplied-session response bodies.
Selecting `supplied-session-review` does not transfer its credentials or
authenticated body authority to this observer.

V1 fails closed when the same invocation selects WordPress discovery, or
selects both OpenAPI and SSRF-OAST. Those separate
response-producing paths do not yet implement this feature's complete value-free
body-digest boundary. This is a preflight refusal before target traffic or output
reservation, not an assertion that those reviews found or leaked a secret.
Merely compiling OpenAPI or SSRF-OAST does not select either review.
Supplied-session review remains compatible because its authenticated bodies are
reduced inside their context-specific runtime and are never selected by this
anonymous observer.

## Explicit GraphQL composition

A binary compiled with both `graphql-review` and `secret-exposure-review` may
select both options under the existing web-review profile:

```console
termivar scan https://app.example.test/ \
  --profile web-review --graphql-review --secret-exposure-review \
  --report-dir assessment-graphql-value-free
```

The fixed anonymous GraphQL `POST` control, candidate and replay responses do
not enter the passive detector. They add no detector response, interpreted-byte,
match or exposure-observation count. Their existing bounded categorical
classification, root-presence facts and candidate/replay agreement remain
available. The schema-root names remain transient and are not published.

With secret-exposure review selected, neither the ordinary whole-body SHA-256
nor the separate framed GraphQL response digest is retained for these responses,
including zero-detector-match and unsuccessful classifications. An opaque
value-free record binds each classification and defense projection to its exact
committed response receipt. It is not a secret finding, source authentication
or a substitute for response completeness. Ordinary passive detector admission
remains the GET-only contract above.

GraphQL still consumes its own existing authorized parent request, byte, deadline
and replay allowances; the privacy guard creates no request, retry or budget.
Without secret-exposure review, its historical digest evidence and classification
contract remain unchanged. A matched fixture with no links or forms retains the
same GraphQL request trace with the privacy option off or on. This is not a
general promise that all body-derived discovery is unchanged: ordinary selected
responses still have the documented generic-body projection suppression.

The process tests use synthetic GraphQL root-name and error-message canaries,
independent literal request/operation expectations, and both raw and framed body
digest checks. The owned fixture is stopped and joined before bundle Verify and
self-Compare; these offline operations must preserve bundle bytes. Incomplete
GraphQL collection must not publish a completed bundle. No inventory, account,
real secret or external provider is required by these fixtures.

## Explicit OpenAPI composition

A binary compiled with both `openapi-review` and `secret-exposure-review` may
select the existing options against an authorized application. For an already
running owned loopback fixture, substitute its actual port:

```console
termivar scan http://127.0.0.1:<fixture-port>/ \
  --profile web-review --openapi-review --secret-exposure-review \
  --report-dir assessment-openapi-value-free
```

OpenAPI's separately planned anonymous GET candidate and exact replay are not
ordinary passive detector inputs: they do not add detector response,
interpreted-byte, match or observation counts. OpenAPI still consumes its
existing parent-accounted allowance of at most two requests and one logical
active verification. This privacy composition adds no request, retry, budget,
described operation execution or extra assessment.

The complete semantic comparison stays private and still compares the actual
bounded catalogues, not just aggregate counts. Different paths with equal
counts must not qualify as a replay match. All received OpenAPI responses use
exact receipt-bound, committed value-free lineage instead of a public whole-body
hash. The public document evidence omits the catalogue digest, and the existing
`security.openapi-review-audit/v1` keeps `semantic_digest` explicitly present
and null. A qualifying informational item uses the existing coarse
`assessment_subject` target rather than a content-derived document identity.
No schema, feature or installed-version authority is added.

The coarse item can compare unchanged across different private catalogues; this
does not establish cross-run document or byte equality. The before/after audits
retain their categorical outcomes and counts, and the existing Compare
interpretation limits still apply. Historical option-off digest and document
identity behavior is unchanged. Current serialized and previously admitted
candidate-source spellings remain readable by feature-independent Verify/Compare readers.
Those readers reject a non-null OpenAPI semantic digest when the selected
secret-exposure audit is also present.

The existing S04 suppression of entry-body discovery facts remains in force.
An OpenAPI link found only in that withheld body cannot nominate a custom
document; the explicit conventional `/openapi.json` fallback can still run.
No second parse bypasses the privacy boundary. Off/on trace equality is proven
only for the controlled fallback fixture, not every possible application.

Process regressions cover stable and reordered catalogues, equal-count semantic
mismatch, terminal/incomplete responses and all central formats with original
synthetic canaries. The fixture shuts down before actual Verify, self-Compare
and controlled Compare; these offline operations must preserve the saved bytes.
No credentials, vendor feed or live service is required.

## Explicit REST composition

A binary compiled with `rest-review` (which includes `openapi-review`) and
`secret-exposure-review` may select the existing options. For an already
running owned loopback fixture, substitute its actual port:

```console
termivar scan http://127.0.0.1:<fixture-port>/ \
  --profile web-review --openapi-review --rest-review --secret-exposure-review \
  --report-dir assessment-rest-value-free
```

The same-run OpenAPI catalogue must still pass its complete private semantic
replay before the existing selector can nominate one anonymous, bodyless,
exact-origin GET with no required inputs. REST's separately planned candidate
and replay are not passive detector inputs and add no detector response,
interpreted-byte, match or exposure-observation count. REST retains its own
existing two-request/one-active allowance inside the same parent budget; this
composition adds no REST request, retry, client or budget.

The existing value-sensitive `Status`, `Fields` and `Resources` comparison stays
private. Equal status and field counts with different scalar values must not
qualify as stable replay. Exact committed response receipts, writes, lineage
and classifications must reconcile before a positive item can be composed;
staged views alone are not report authority. Terminal, truncated, cancelled,
budget-limited or mismatched responses do not become positive items.

With this option selected, REST omits its public whole-body/view response
digests and the catalogue-derived operation/target identities. The existing
`security.rest-readonly-review-audit/v1` omits `selected_operation_identity`, while a
qualifying `api.rest-readonly-surface-observed@1` item uses the existing coarse
`assessment_subject` target. OpenAPI's audit continues to carry an explicitly
present/null `semantic_digest`. No new audit schema or feature is introduced.
Feature-independent readers require a valid selected privacy audit before
accepting the withheld REST identity; historical positive REST audits without
that selection still require their operation identity.

The coarse item does not establish cross-run resource or byte equality:
different private resources can yield the same coarse informational item.
The exact execution URL remains private request/provenance data; this public
report boundary does not promise that all internal transport or knowledge
buffers are URL-free. Without secret-exposure review, historical REST digest,
operation identity, target and request behavior remain unchanged.

Original synthetic process fixtures cover reordered JSON, same-shape scalar
mismatch, a schema-derived path canary, all central report formats and
preflight/terminal/incomplete refusals. The owned fixture is stopped before
actual bundle Verify, self-Compare and controlled byte/catalogue/option
comparisons. Offline checks must add no requests and preserve bundle bytes.
These are synthetic HTTP tests, not real-CMS or live-service acceptance.

## Explicit resource authorization composition

A binary compiled with `authorization-review` and `secret-exposure-review`
may select the existing options. This owned-fixture operator example is not an
execution record; substitute an already running fixture's actual port and
explicitly prepared synthetic policy/credential files:

```console
termivar scan http://127.0.0.1:<fixture-port>/ \
  --profile web-review --secret-exposure-review \
  --authorization-review-policy authorization-policy.toml \
  --authz-primary-file primary-authorization.txt \
  --authz-peer-file peer-authorization.txt \
  --report-dir assessment-authorization-value-free
```

The existing four bodyless JSON GET legs retain their exact
primary-candidate, peer-candidate, primary-replay, peer-replay order and
principal-isolated, ambient-proxy-free pools. They are credentialed comparison
responses, not anonymous detector inputs. They add no detector response,
interpreted-byte, match or exposure-observation count. The child keeps its
existing four-request/one-active allowance under the same parent scope,
accounting, deadline and cancellation; S04 adds no request or budget.

Full value-sensitive `Status`, `Fields` and `Resources` comparison stays
private. Matching field shapes or counts alone cannot establish equivalence.
With privacy selected, general leg evidence omits the response SHA-256 and
body-derived receipt SHA-256. Bounded typed role/transport facts and their
derived classification must reconcile with exact parent-runner receipts,
committed writes and stored rows before projection. Staged views alone are
not authority, and finalization independently checks the canonical assessment
privacy selection against its private binding.

The existing `security.authorization-review-audit/v1` retains counts,
classified stability/equivalence booleans and operator-derived policy identity.
The review item's identity remains bound to the declared policy/resource, not
response contents. Identical public items across two runs therefore do not
prove cross-run body equality. Stable equivalence remains only `NeedsReview` /
`KnowledgeOnly`, never a confirmed authorization defect or business impact.
No public schema or installed-version authority changes.

The comparator's bounded private view/receipt correlation remains separate
from general evidence publication. The exact resource remains private broker
and provenance data; this boundary does not promise that all internal transport,
KnowledgeBase or HTTP-library buffers are URL-free. Without S04, historical
leg evidence and comparison behavior stay unchanged. Supplied-session bodies
remain excluded, and this composition does not admit WordPress discovery or
the selected OpenAPI-plus-SSRF-OAST response path.

Original synthetic process fixtures distinguish stable all-role equality,
same-shape cross-principal scalar differences and unstable primary replay.
They also cover all central formats, typed terminal refusals, input-byte
preservation and request isolation. Fixtures must stop before Verify,
self-Compare and controlled Compare; offline commands must preserve bundle
bytes and issue no requests. These fixtures are not real-service acceptance
or evidence that a supplied principal is authentic.

## Fixed V1 detector catalogue

`termivar.high-specificity-secret-detectors` revision `v1` contains four
closed detector classes:

| Detector class | Capability | Required V1 shape |
| --- | --- | --- |
| `pem_private_key_block` | `exposure.response-private-key-material@1` | A structurally plausible, bounded PKCS#8, RSA, EC, or OpenSSH private-key block with matching begin/end markers |
| `aws_access_key_pair` | `exposure.response-aws-access-key-pair@1` | A plausible `AKIA` or `ASIA` access-key ID and a plausible secret-access-key assignment within the bounded 4 KiB / 16-line pairing window |
| `stripe_live_secret` | `exposure.response-stripe-live-secret@1` | A bounded `sk_live_` or `rk_live_` secret/restricted-key shape; publishable `pk_*` keys are not this detector class |
| `authorization_bearer_assignment` | `exposure.response-bearer-authorization@1` | An explicit bounded `Authorization: Bearer ...`-style assignment with a plausible token68 value |

Common documentation placeholders and low-variety synthetic filler are
rejected. An AWS access-key ID by itself is not the secret-access-key half and
does not satisfy the paired detector. The catalogue is not configurable by a
target response, user regex, downloaded file, or remote provider.

These observations describe secret-shaped material returned in one eligible
response. They do not establish that the value is valid, current, owned by the
target, accepted by a provider, privileged, exploitable, or visible to another
principal. The runtime never contacts AWS, Stripe, an identity provider, or
any other service to validate a match.

## Limits and retained data

The V1 observer applies the smaller enclosing assessment limits plus these
fixed ceilings:

- 128 KiB per eligible response;
- 4 MiB of admitted detector-work bytes per assessment, reserved before UTF-8
  and detector parsing;
- 1,024 response outcome records;
- 64 matched occurrences per response; and
- 32 retained subject/class observations per assessment.

Limit refusal is represented separately from an evaluated response with no
matches. Once a body passes the response/context/representation checks and the
128 KiB per-response bound, its full length consumes the private detector-work
allowance even if UTF-8 or detector parsing later refuses it. The saved
`interpreted_byte_count` remains the smaller count of successfully evaluated
bodies; V1 intentionally does not expose the private admission counter as a
report field. The audit reconciles response, evaluated/non-evaluated,
interpreted-byte, retained/omitted-observation, and occurrence counts from
committed evidence. It also reports
`body_derived_projection_suppressed_response_count` so this privacy boundary is
not mistaken for exhaustive generic/WordPress body coverage.

No matched value, fragment, surrounding source, reversible encoding, or digest
of secret material enters evidence, items, progress, reports, or comparison.
Evidence retains only the response outcome, inspected byte count, bounded
occurrence counts, detector class, and existing opaque evidence references.
Those references identify committed evidence inside the assessment; they do
not authenticate the response source.

Active native-review control and candidate responses are deliberately outside
the detector catalogue because they may contain reflected probe material.
Selecting this feature nevertheless replaces their ordinary public body digest
with value-free, exact-receipt lineage. Their existing semantic projection,
request schedule and defense accounting remain intact; the replacement is not
a secret finding and does not add a request.

## Report and comparison meaning

A selected completed assessment contains the optional strict
`security.passive-secret-exposure-audit/v1` section with policy
`termivar.passive-secret-exposure/v1` and representation
`complete-uncoded-response-body/v1`. A selected run with zero eligible matches
still carries a valid empty audit. A match may produce an `Informational` /
`KnowledgeOnly` assessment item for its detector class. It never produces
`NeedsReview` or `Confirmed` by itself.

JSON, HTML, Markdown, and CSV are rendered from the same validated typed
document. The audit explicitly records:

- `additional_request_count = 0`;
- source authentication as `not_established`;
- secret validity as `not_tested`;
- provider validation, exploit execution, and impact validation as
  `not_performed`; and
- raw-value and public-secret-hash retention as `false`.

Feature-independent saved-report readers validate the optional section and its
item/evidence-reference conservation. Offline Verify checks bundle integrity
and supported report consistency; it does not prove a secret or authenticate a
source. Offline Compare keeps the existing four outer item arrays and adds the
optional `termivar-secret-exposure-comparison/v1` methodology/coverage facet.
Catalogue, policy, representation, context, or limit changes are methodology
changes. Missing or reduced coverage, and a one-sided observation, are not
proof that exposure began, ended, or was remediated.

## Explicit non-goals

V1 does not:

- guess `.env`, source-map, repository, or backup paths;
- recursively decode or decompress response bodies;
- validate a candidate against a live provider;
- inspect browser storage or search the operator's filesystem/accounts;
- execute returned JavaScript or follow instructions in response content;
- inspect authenticated supplied-session bodies;
- infer a credential's owner, permissions, audience, or operational impact; or
- claim complete secret detection, source authentication, exploitability, or
  remediation.

Provider format references used to review this fixed catalogue are
development-only inputs, not scan-time destinations. The
[AWS IAM access-key documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
distinguishes an access-key ID from its secret-access-key half, and the
[Stripe key documentation](https://docs.stripe.com/keys) distinguishes
publishable keys from secret and restricted keys. Runtime execution never
retrieves those references.
