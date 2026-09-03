# Artifact signature packs

This directory contains repository-owned metadata for the Preview
`termivar-artifact` domain. V1 packs use the strict
`venom.artifact-signatures/v1` schema and contain only bounded signature
descriptions and exact/wildcard byte patterns. They contain no executable
content, target paths, credentials, exploit payloads, or verdict policy.

The initial `lab/termivar-canary` pack is a harmless deterministic fixture. A
match is an observation: it is not a malware verdict, vulnerability finding,
severity assignment, or authorization to execute the matched bytes.

Repository validation is explicit and non-executing:

```console
cargo run --locked -p xtask -- artifact-catalog
```

The validator reads only this repository-owned root, rejects unexpected or
executable files, compiles bounded patterns, and seals a deterministic catalog.
It never scans an artifact.
