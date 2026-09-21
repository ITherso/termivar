# Cert Spotter CT reconnaissance provider

## Status and selection

`recon-ct-provider` is a non-default, development-only scanner/CLI feature. It
is not a member of the seven-member `release-bundle` and is absent from the
published alpha.2 archives. Compilation does not activate provider traffic.
The operator must select all of the following:

- `--profile web-review`;
- `--recon-certspotter-policy FILE`;
- `provider_use_authorized: true` in that policy; and
- `privacy_disclosure_acknowledged: true` in that policy.

The CLI opens one explicitly named regular local file and accepts one strict,
bounded `security.recon-certspotter-policy/v1` JSON document. The policy is
validated before output reservation, credential acquisition, or target/provider
network construction. The `production` execution-mode token binds one query
domain and an opaque operator revision/reference to the fixed live provider
route; the query domain must match the exact target host. The production token
names only the fixed live-endpoint mode. It does not claim that the provider
considers this use production-ready or account-entitled.

The two acknowledgement fields are fail-closed operator declarations.
`provider_use_authorized` records the operator's decision that the intended
query fits the provider-documented limited unauthenticated personal/evaluation
use basis, hourly quota, and current terms. It does not prove provider approval,
an account entitlement, or a general production entitlement.
`privacy_disclosure_acknowledged` records the operator's disclosure decision.
Neither field is evidence of ownership, authorization from another party, legal
compliance, or the provider's acceptance of a request.

An illustrative fixed-live-endpoint policy is:

```json
{
  "schema": "security.recon-certspotter-policy/v1",
  "revision": "scope-2026-09-21",
  "query_domain": "example.com",
  "query_reference": "approved-scope-17",
  "execution_mode": "production",
  "provider_use_authorized": true,
  "privacy_disclosure_acknowledged": true
}
```

The `production` token cannot override the provider origin. The only alternative
execution mode is `owned_loopback_fixture`, which requires an explicit root-only
`http` origin with a numeric loopback address and explicit port. That mode exists
for operator-owned tests; it does not authorize a public substitute provider.

## Fixed provider and bounded execution

The fixed live-endpoint mode uses only
`https://api.certspotter.com/v1/issuances`, following the provider's official
[CT Search API v1 reference](https://sslmate.com/help/reference/ct_search_api_v1).
That reference permits a limited number of unauthenticated list queries per hour
for personal or evaluation purposes and directs production launches to use an
authenticated account. Termivar sends `domain` plus `expand=dns_names`; a second
request may add the last accepted issuance ID as `after`. The fixed live route
or the explicit owned numeric-loopback fixture is the complete V1 endpoint set.

The child runtime has these closed bounds:

- at most two sequential pages and one in-flight provider request;
- at most 256 KiB retained/interpreted per page and 512 KiB total;
- at most 256 retained unique names; and
- at most ten seconds elapsed for the collection, further narrowed by the
  parent assessment deadline, cancellation, request, and byte authority.

Redirects and ambient proxies are disabled. V1 performs no retries and no
polling. It supplies no API token, `Authorization` header, cookie, client
certificate, or other provider credential. Account-backed authenticated use is
therefore unsupported in V1. An access rejection or throttling response is a
terminal observed outcome, not permission to retry or switch providers.

Before setting either acknowledgement, the operator should review the
provider's official [privacy policy](https://sslmate.com/policies/privacy) and
[Terms of Service](https://sslmate.com/policies/tos), confirm that the request
fits the documented unauthenticated basis and quota, and decide that disclosing
the selected domain and request metadata to the external service is acceptable.
The local acknowledgements record those operator decisions; they neither make
the disclosure private nor establish provider permission. The upstream
[Cert Spotter source repository](https://github.com/SSLMate/certspotter) is the
primary implementation reference. These links document the external service;
Termivar's stricter two-page, byte, name, no-retry, no-polling, and
no-credentials limits remain authoritative for this integration.

## Evidence and claim boundary

Accepted certificate-transparency names remain source-qualified hypotheses.
They never become scan subjects, broker permits, target requests, ownership
evidence, authentication evidence, assessment items, or findings. A returned
name does not establish that a certificate is current, that the queried party
owns the name, that the provider response authenticates the asset owner, or
that the operator may contact it. The provider child cannot expand the exact
target authority selected for the surrounding assessment.

Reports retain bounded provider execution/accounting and reduced hypothesis
metadata, not raw provider pages or credentials. Opaque provider issuance IDs
remain runtime-only pagination data; saved output uses a SHA-256 reference plus
the exact UTF-8 byte length, which neither authenticates nor reveals the ID.
Report verification can check saved bytes and schema consistency; it cannot
establish provider truth, freshness, ownership, authorization, or source
authenticity.

## Acceptance status

Repository tests exercise strict policy parsing and operator-owned
numeric-loopback fixtures. Release-candidate acceptance does not contact the
live Cert Spotter service because no production query input or disclosure
authorization is supplied to that workflow. Its explicit live-service status
is therefore `NOT_RUN_NO_INPUT`. This marker is neither a passed live-service
test nor evidence of current service availability or behavior.
