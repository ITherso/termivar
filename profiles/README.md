# Scanning profile scaffolds

> **Status: experimental and not CLI-wired.** The TOML files in this directory are illustrative configuration samples. Neither `venom scan` nor `venom decision-scan` reads them, and their named plugins, scripts, compliance options, cloud checks, or reporting settings are not proof that those behaviors execute.

The current CLI does **not** implement `--profile`, `--merge-profile`, or `--target` flags. Targets are positional arguments:

```text
venom scan <TARGET>
venom decision-scan <TARGET>
```

`venom-scanner` also exposes an experimental in-memory `ConfigLoader` /
`config_loader::ScanProfile` library scaffold. No repository runtime caller
connects that loader to either CLI command, and it does not load the TOML files
in this directory.

The files are retained as design inputs for a future, explicitly versioned configuration contract:

- `enterprise.toml`
- `cloud.toml`
- `aggressive.toml`
- `stealth.toml`

The files now contain identity/lifecycle metadata only. They intentionally do
not enumerate plugins, scripts, phases, payload behavior, platform checks,
compliance claims, or reporting behavior.

Do not use these samples as operational security, compliance, cloud, WAF-evasion, plugin, or reporting profiles. A future profile loader must define schema validation, authorization, runtime ownership, supported capabilities, and fail-closed handling before these files can become executable configuration.

For current commands and runtime boundaries, use the root [README](../README.md), [Getting Started](../docs/GETTING_STARTED.md), and [runtime map](../docs/internals/runtime-map.md).
