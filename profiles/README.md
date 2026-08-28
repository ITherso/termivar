# Scan profiles

Venom implements exactly two built-in product profiles selected by name:

```text
venom scan --profile baseline <TARGET>
venom scan --profile web-review <TARGET>
```

- `baseline` preserves the conservative single-resource scan behavior and uses
  the additive `web-assessment/v1` profile audit.
- `web-review` opts into bounded, deterministic discovery under one authorized
  exact-origin authority, then composes bounded semantic extraction, defense
  observation/shadow planning, and passive header/cookie review over committed
  evidence.

Omitting `--profile` is a separate compatibility state. It preserves the
existing text/`--explain` behavior and `decision-scan/v1` JSON contract rather
than silently selecting a new crawler or assessment document.

The serialized profile schema is `venom.scan-profile/v1`. Its capability matrix
is closed and exact. In the current `web-review` profile, passive security
review is enabled and low-risk differential review is disabled. Passive
security-header and value-free cookie observations can produce only
`Informational` `AssessmentItem` values; no native assessment capability
currently produces `Confirmed`.

Stable item identity currently covers only the exact origin root (`/`). A
non-root starting target or eligible condition on a discovered non-root subject
makes the assessment incomplete rather than deriving identity from a URL.

The historical `enterprise`, `cloud`, `aggressive`, and `stealth` profile
samples were removed because those names do not represent executable product
behavior.

Custom profile files are not supported. Venom does not load TOML files from
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
