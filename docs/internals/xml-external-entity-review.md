# Controlled XML external-entity review

Status: Preview, development-only, explicit opt-in, and excluded from `default`,
`release-bundle`, and the published `v0.10.0-alpha.2` archives.

The `xml-external-entity-review` feature adds one narrow `web-review` action for
an operator-owned disposable XML endpoint. It is not endpoint discovery, a
general XML fuzzer, a file-reading probe, or a confirmed XXE verifier. A
correlated external interaction can produce at most `NeedsReview` with
`KnowledgeOnly` authority.

## Explicit authority

The CLI requires all of the following:

- `--profile web-review`;
- `--xml-external-entity-review`;
- one bounded `--xml-external-entity-policy FILE`; and
- exactly one of `--oast-admin-token-env`, `--oast-admin-token-file`, or
  `--oast-admin-token-stdin`.

The strict `security.xml-external-entity-review-policy/v1` document binds one
exact-origin, application-contained endpoint, the literal method `POST`, the
literal media type `application/xml; charset=utf-8`, and one distinct
self-hosted OAST provider origin. It also requires explicit acknowledgements
for the XML POST, external interaction, and disposable test endpoint, plus
bounded polling and lifetime values. The policy grants no authority to another
target, path, method, media type, provider, or credential.

The administrator token is never accepted in argv. Policy bytes are read from
one bounded regular non-symlink UTF-8 file and parsed before output reservation,
secret acquisition, or network construction. The selected secret source is
read once only after all non-secret preflight and report-output reservation
succeed. Errors are static and do not repeat private paths, environment names,
tokens, endpoint paths, callback URLs, or policy contents.

SSRF OAST query review and XML external-entity review cannot be selected in the
same assessment. V1 gives each review exclusive ownership of the shared native
provider administrator credential and callback session.

## Feature-enabled development invocation

The option is available only in a binary compiled with
`xml-external-entity-review`; it is not part of the stock `release-bundle`.
The following placeholders must name an operator-owned disposable HTTPS target,
a separately owned HTTPS provider, and a local token file. They are not public
test destinations:

```console
termivar scan https://app.example.test/application/ \
  --profile web-review \
  --xml-external-entity-review \
  --xml-external-entity-policy xml-review.toml \
  --oast-admin-token-file oast-admin-token.txt \
  --report-dir assessment-xml
```

One strict policy for that example is:

```toml
schema = "security.xml-external-entity-review-policy/v1"
endpoint = "https://app.example.test/application/xml-parser"
provider_origin = "https://oast.example.test/"
method = "POST"
media_type = "application/xml; charset=utf-8"
acknowledge_xml_post = true
acknowledge_external_interaction = true
acknowledge_disposable_test_endpoint = true
polls_per_leg = 2
poll_interval_ms = 500
lifetime_ms = 10000
```

The provider administrator token is secret input and must not be placed in the
policy, command line, URL, report, or shell history. A valid policy acknowledges
the bounded stateful POST and external interaction; it does not prove the target
is safe to test or grant authority outside the exact application and provider.

## Fixed request grammar

The runtime generates the XML; callers cannot supply an XML body or template.
The fixed UTF-8 XML 1.0 envelope uses one external general entity with an HTTPS
provider URL. `PUBLIC` identifiers, parameter entities, external DTDs,
XInclude, schema retrieval, nested or recursive entities, and `file:` URLs are
not supported.

One bounded execution uses at most three anonymous target POSTs with distinct
callback identities. A completed positive path uses all three target legs:

1. a control contains the same `SYSTEM`-URL shape but does not reference the
   declared entity;
2. a candidate references its entity once; and
3. a replay repeats the candidate structure with a fresh callback.

There is no redirect following, retry, ambient proxy, cookie, Authorization
header, arbitrary header, query mutation, or response-content oracle. Target
and provider work remain separately metered narrowing children of the parent
assessment deadline, cancellation, request, active-verification, byte, and
evidence authorities.

## Outcome and claim ceiling

A positive review requires a clean provider preflight, no control callback,
distinct correctly bound post-dispatch callback events for both candidate and
replay, complete provider cleanup, and reconciled target/provider accounting.
Stale, duplicate, foreign, wrong-phase, single, or control callbacks; target
status or body text; timeout; cancellation; budget exhaustion; malformed
provider data; or incomplete cleanup cannot produce an assessment item.

Even the complete repeated differential establishes only that two controlled
XML documents preceded two independently correlated external interactions.
It does not establish confirmed XXE, parser or component identity, arbitrary
SSRF, local file read, data exfiltration, internal-network access, source
authenticity, exploitability, or impact. No XML review path produces
`Confirmed` or assigns severity.

Reports retain only bounded value-free methodology, state, count, accounting,
and opaque reference fields. They never retain the XML body, target endpoint
path, provider origin or token, callback URL/token, event identity, response
body, or raw transport/provider error.
