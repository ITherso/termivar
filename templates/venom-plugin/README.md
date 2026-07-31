# {{ project-name }}

{{ plugin_description }}

This crate was generated from Venom's alpha plugin template. Implement detection
inside `GeneratedPlugin::execute`, keep the plugin independent of runner
internals, and return structured `ScanFinding` values.

## Verify

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test
```

The template tracks Venom's `main` branch during the alpha period. Pin the
dependency to a release tag or commit before publishing a plugin.

Venom checks the plugin API major/minor line during registration. Public plugin
types are non-exhaustive; use defaults and wildcard match arms so patch releases
can add compatible fields or variants.
