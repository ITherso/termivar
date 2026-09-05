# SSRF OAST query review V1

The non-default `ssrf-oast-review` feature adds one explicitly configured
native action to the existing `WebAssessmentRuntime`. It is a narrow
correlation review, not a general SSRF fuzzer. The operator supplies a strict
`--ssrf-oast-review` enable flag and a strict
`security.ssrf-oast-review-policy/v1` file through `--ssrf-oast-policy`,
acknowledges the outbound callback
test, and supplies the self-hosted native provider administrator token through
one bounded environment, regular-file, or stdin source. No credential value is
accepted on the command line. The shared
[credential-input guarantees and limits](credential-input.md) apply to that
source and the policy-file loader.

The target and provider authorities remain separate. The target must be the
assessment's exact origin. The provider must be a different, exact HTTPS DNS
origin selected by the operator; there is no Termivar-hosted or other public
default. Provider management traffic uses the narrowing authority, shared
parent `RuntimeBudget`, cancellation token, and deadline introduced by the
native OAST provider adapter. The provider remains an auxiliary raw-free
callback mailbox and never becomes a scanner.

## Candidate boundary

V1 selects at most one query parameter from one of two structural sources:

- an exact-origin `GET` target containing exactly one occurrence whose current
  value is an absolute HTTP or HTTPS URL; or
- one optional `url`/`uri` query parameter on an anonymous, bodyless,
  zero-required-input exact-origin `GET` from a complete replay-stable OpenAPI
  catalog already committed by the same assessment.

OpenAPI is never fetched or enabled on behalf of this review. A parameter name,
example, default, description, or model guess is not eligibility. Duplicate
names, malformed encoding, required inputs, authentication, request bodies,
templated or cross-origin servers, and path/header/body/cookie candidates fail
closed. Unrelated query pairs keep their order and exact encoded values.

## Bounded execution

One complete review owns one logical active verification and exactly three
target request legs:

1. `Control`, using a case-bound HTTPS URL under the reserved `.invalid` TLD;
2. `Candidate`, using a freshly allocated provider callback;
3. `Replay`, using a second independently allocated callback.

All three target requests are anonymous, bodyless `GET`s to the same exact
origin and path. Redirects, retries, cookies, authorization, forwarding
headers, alternate schemes, internal/private/link-local/cloud destinations,
redirectors, DNS rebinding, and timing inference are absent.

The provider lifecycle is fixed: register one session, allocate the two
callbacks, require one clean preflight poll, dispatch and poll Candidate,
dispatch and poll Replay, then explicitly clean up. The policy permits one to
four polls per phase, but the scheduler also enforces the stricter whole-review
ceiling: at most seven post-dispatch polls. Together with register, two
allocations, preflight, and cleanup, provider HTTP requests can never exceed
twelve. There is no background or post-finalization polling and no network work
in `Drop`.

## Evidence and claim

A positive observation requires both independently allocated callback IDs to
produce distinct exact event IDs after their corresponding target dispatches.
They must bind the same assessment, action, case, resource, parameter, and
authority epoch; preflight must be clean; cleanup and all parent accounting
must reconcile. Candidate-only, Replay-only, duplicate-only, stale, wrong-case,
wrong-session, preflight, expired, malformed, rate-limited, unauthenticated,
cancelled, budget-exhausted, or cleanup-incomplete states produce no item.
Target timing and target status are never callback evidence.

The strongest V1 item is:

- capability: `ssrf.oast-repeated-outbound-interaction@1`;
- title: `Repeated out-of-band interaction observed`;
- disposition: `NeedsReview`;
- authority: `KnowledgeOnly`;
- severity: none.

Two callbacks show a repeated, correlated outbound interaction only. They do
not confirm SSRF, identify the server-side component, prove internal-service or
cloud-metadata reachability, demonstrate data exposure, or establish business
impact.

The private feature-gated audit contains only bounded counts, typed states,
opaque fingerprints, and boolean reconciliation facts. It never retains or
emits the target URL, raw query, provider origin, callback URL/path, provider or
session token, clear session/callback/event IDs, IP, port, header, cookie, body,
timestamp, or reverse-proxy metadata. Projection still ends in the one composed
assessment report.

This feature remains outside `release-bundle`. The operator must self-host the
provider behind an HTTPS reverse proxy. V1 observes HTTP callbacks only; it has
no DNS-only detection, XXE path, automatic chaining, public deployment, or
public-network CI.
