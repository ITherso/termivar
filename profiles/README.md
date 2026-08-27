# Scan profiles

Venom implements exactly two built-in product profiles selected by name:

```text
venom scan --profile baseline <TARGET>
venom scan --profile web-review <TARGET>
```

- `baseline` preserves the conservative single-resource scan behavior.
- `web-review` opts into bounded, deterministic discovery under one authorized
  exact-origin authority.

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
