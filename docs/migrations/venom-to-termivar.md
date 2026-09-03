# Venom to Termivar migration

Termivar is the current product identity. Venom is the former project name.
This alpha-stage migration changes the current package, crate, and executable
names without duplicating the scanner or changing assessment behavior.

## Current identity mapping

| Former package | Current package | Current Rust crate |
| --- | --- | --- |
| `venom-core` | `termivar-core` | `termivar_core` |
| `venom-scanner` | `termivar-scanner` | `termivar_scanner` |
| `venom-cli` | `termivar-cli` | n/a |
| `venom-api` | `termivar-api` | `termivar_api` |
| `venom-proxy` | `termivar-proxy` | `termivar_proxy` |
| `venom-artifact` | `termivar-artifact` | `termivar_artifact` |
| `venom-exploit` | `termivar-exploit` | `termivar_exploit` |

The command-line executable is now `termivar`. Subcommands, options, feature
names, profiles, request plans, and report semantics are unchanged. The
public `v0.9.0-alpha` artifacts used the former `venom` executable name, but
that prerelease did not establish a stable binary contract. Consequently this
migration does not ship a second executable or parser under the old name.

The endpoint-performance harness now uses `TERMIVAR_PERF_*` variables and
Termivar-named temporary paths. Historical `VENOM_*` configuration variables
owned by the explicitly gated legacy contracts remain unchanged. The active
container uses `.termivar`; `.venom` remains ignored so an old local secret
directory cannot accidentally be committed.

## Compatibility identities

Branding alone does not justify changing a serialized or deterministic
identity. Existing wire schemas, capability identifiers, digest domain
separators, evidence fingerprints, scanner-owned correlation tokens, corpus
placeholders, and historical report schemas therefore retain their exact
versioned values, including values whose spelling contains `venom`.

In particular, `venom.scan-profile/v1`, `venom-run/v1`, the rendered and
assessment report schemas, artifact and exploit schemas, coverage schemas,
and their existing digest domains are preserved. Changing these values would
be a protocol or identity migration and requires an independently versioned
change, not a product-name edit.

Historical scanner and WAF/evasion salvage records also retain their original
Venom schemas, commits, source paths, blob identities, and terminology.
References that describe the current replacement implementation are resolved
to the renamed Termivar crate without rewriting the historical source epoch.

The repository-owned artifact and exploit lab canaries are current fixtures,
not historical identities. Their package/pack/module names and resulting
semantic catalog or manifest digests change deliberately to Termivar. The
versioned artifact/exploit schema strings and digest domain separators remain
unchanged, so this does not redefine either wire format or digest algorithm.

The accepted coverage baseline and omission inventory also retain their
pre-rename source identities. The coverage gate maps the reviewed Termivar
crate paths onto those stable identities and measures only real edited lines
across the directory move; it does not treat the rename as new covered code.

## Repository boundary

Package metadata continues to point to `ITherso/venom` until the separate
public-repository migration is completed. After that transition, developers
can update an existing checkout with:

```bash
git remote set-url origin https://github.com/ITherso/termivar.git
```

No package publication, release, website, or second scanner implementation is
created by this migration.
