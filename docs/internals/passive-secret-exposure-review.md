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

V1 fails closed when the same invocation selects GraphQL, OpenAPI, REST,
resource authorization, or WordPress discovery. Those separate
response-producing paths do not yet implement this feature's value-free body
digest boundary. This is a preflight refusal before target traffic or output
reservation, not an assertion that those reviews found or leaked a secret.
Supplied-session review remains compatible because its authenticated bodies are
reduced inside their context-specific runtime and are never selected by this
anonymous observer.

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
