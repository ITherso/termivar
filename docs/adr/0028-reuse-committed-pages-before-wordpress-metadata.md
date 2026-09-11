# ADR 0028: Reuse committed pages before WordPress metadata collection

## Status

Accepted

## Context

Entry-only WordPress metadata discovery executes while the authorized root is
handled. An eligible component asset can instead appear on an ordinary page
that the same assessment completes later. Transport callbacks occur before the
runner's evidence transaction is committed, so callback data alone cannot
authorize additional metadata requests. Fetching from an observer would also
create a second scheduling surface outside the parent broker and completeness
lifecycle.

The existing entry-only behavior is already a compatibility contract. Page
breadth must therefore be explicit, bounded, and unable to change application
or layout authority selected from the entry.

## Decision

Keep the absent-option entry-only schedule unchanged. For explicit page scope,
the root parser retains a deterministic bounded set of eligible first-hop
ordinary anchor candidates. An observer may stage reduced page facts, but they
become usable only after the runtime verifies the exact committed page subject,
request URL, final URL, anonymous GET purpose, complete supported HTML body, and
evidence receipt.

For observed mode, no page request is dispatched. After the ordinary eligible
collection finishes, the runtime freezes entry and accepted-page component
candidates and executes the existing WordPress metadata collector once through
the same broker, budget, deadline, evidence registry, and assessment. Secondary
pages cannot replace the frozen selected application, role bases, or REST index.

The strict page-scoped discovery document is versioned as
`security.wordpress-discovery-audit/v3` and paired with review audit `/v7`.
Its closed acquisition vocabulary is coordinated for observed reuse and the
separately delivered bounded linked-page slice; accepting a saved `linked` row
does not activate retrieval in a binary whose CLI exposes only observed mode.

## Consequences

- Observed mode adds no page GET or HEAD-to-GET promotion, but newly accepted
  component hints can consume metadata attempts inside the existing shared
  WordPress ceiling.
- Page evidence is counted beside metadata evidence in the one projected
  discovery item and keeps bounded opaque page-to-component relationships.
- Scheduling waits for committed evidence in the explicit page-scoped path;
  legacy entry-only request order and audit meaning remain unchanged.
- Missing, partial, credentialed, probe, redirected, conflicting, or otherwise
  ineligible representations cannot authorize metadata work.
- The bounded sample is not exhaustive application coverage, source
  authentication, installed-component proof, or exploit validation.

## Alternatives considered

- Fetch from the response observer: rejected because pre-commit transport data
  is not committed evidence and the callback is not an execution authority.
- Run metadata discovery once per page: rejected because it duplicates work and
  fragments the shared request ledger.
- Always broaden discovery: rejected because it would change established
  entry-only behavior and request accounting without explicit operator choice.
- Treat secondary pages as generic scan subjects: rejected because it would
  trigger unrelated review families and create crawler semantics.
