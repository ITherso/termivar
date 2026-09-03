# Scan profiles

Termivar implements exactly two built-in product profiles selected by name:

```text
termivar scan --profile baseline <TARGET>
termivar scan --profile web-review <TARGET>
```

- `baseline` preserves the conservative single-resource scan behavior and uses
  the additive `web-assessment/v1` profile audit.
- `web-review` opts into bounded, deterministic discovery under one authorized
  exact-origin authority, then composes bounded semantic extraction, defense
  observation/shadow planning, passive header/cookie review, and a closed
  matched low-risk differential catalog over committed evidence.

Omitting `--profile` is a separate compatibility state. It preserves the
existing text/`--explain` behavior and `decision-scan/v1` JSON contract rather
than silently selecting a new crawler or assessment document.

The serialized profile schema is `venom.scan-profile/v1`. Its capability matrix
is closed and exact. In the current `web-review` profile, passive security
review and low-risk differential review are enabled. Passive security-header,
value-free cookie, and non-dangerous reflection observations are
`Informational`. Exact matched CORS/redirect relationships and dangerous HTML
reflection can produce only `NeedsReview`; every native review action is
KnowledgeOnly and cannot produce `Confirmed`.

The differential catalog always reviews CORS on the authorized starting
resource, additively with otherwise eligible standard actions. A CORS review
item requires successful control and candidate status classes. Redirect/reflection review is added only when the starting URL
already contains one recognized navigation query-parameter name. Its original
value is discarded; a deterministic `.invalid` candidate is sent only as an
encoded same-origin query value. Redirects remain disabled, so that external
destination is observed in `Location` only for 301/302/303/307/308 and is never
contacted.

Stable item identity currently covers only the exact origin root (`/`). A
non-root starting target or eligible condition on a discovered non-root subject
makes the assessment incomplete rather than deriving identity from a URL.

The historical `enterprise`, `cloud`, `aggressive`, and `stealth` profile
samples were removed because those names do not represent executable product
behavior.

Custom profile files are not supported. Termivar does not load TOML files from
this directory and defines no custom-file precedence, override, or merge
semantics.

Defense observation and shadow planning do not imply enforcement. Defense
enforcement is disabled by default and requires an explicit supported opt-in.
It can only narrow already-authorized work; it cannot expand origin authority,
request budgets, or action intensity.

Profile selection never supplies targets, credentials, headers, raw transport
settings, or additional origins. Exact-origin authorization, host-owned network
accounting, compiled ceilings, and bounded runtime limits remain authoritative.

Completed `web-review` runs use the central bounded
`venom-rendered-assessment/v1` renderer. JSON, CSV, HTML, and Markdown are
available through `--report-format`; `--report-output` creates a new file and
never overwrites an existing one. Incomplete or started-failed origin runs emit
a `web-assessment/v2` diagnostic audit, return nonzero, and create no report
artifact.
