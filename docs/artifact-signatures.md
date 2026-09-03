# Artifact signature scanning

`termivar-artifact` is a separate, non-published Preview library for deterministic
byte-pattern observations. It is independent from the web scanner and exploit
domains and has no network, process, browser, or filesystem authority.

## Capability boundary

The library accepts caller-supplied byte slices and bounded `Read` streams. It
supports exact bytes plus `?`/`??` wildcard atoms, preserves overlapping
matches, and reports stable absolute offsets without retaining input or matched
bytes. A completed scan identifies the full artifact with SHA-256. An incomplete
scan labels the digest only as a consumed prefix and reports the exclusive
matcher-start frontier separately, so bounded read-ahead is never presented as
complete signature coverage or a complete artifact identity. Input,
match-observation, reader-chunk, and matcher-work limits are finite; reaching
any execution ceiling remains a typed incomplete result.

The `venom.artifact-signatures/v1` pack schema contains a bounded pack identity,
revision, title, summary, and ordered signature definitions. Each signature has
a stable identity and revision, a label, a closed observation class, a canonical
pattern, bounded tags, and optional descriptive metadata. Unknown fields,
all-wildcard or under-specified patterns, duplicate identities/patterns, and
compiled limits fail closed.

Canonical patterns use uppercase two-digit hexadecimal bytes and `??` for a
wildcard:

```text
56 45 4E 4F 4D ?? 43 41 4E 41 52 59
```

Lowercase input and a single `?` normalize to this form. Canonicalization and
matching are non-evaluating; the bytes are never interpreted as code.

V1 has finite compiled ceilings. Hosts may narrow scan limits but cannot widen
them:

| Dimension | V1 ceiling |
| --- | ---: |
| Manifest bytes | 256 KiB |
| Packs per catalog | 64 |
| Signatures per pack | 1,024 |
| Total signatures | 4,096 |
| Bytes per compiled pattern | 256 |
| Input bytes per scan | 512 MiB (64 MiB default) |
| Reader chunk bytes | 1 MiB (64 KiB default) |
| Match observations | 30,000 (10,000 default) |
| Match work units | 1,700,000,000 (250,000,000 default) |
| Serialized report bytes | 16 MiB |

## Repository catalog

The repository ships only a harmless lab canary pack under
`artifact-signatures/lab/termivar-canary`. Validate repository metadata with:

```console
cargo run --locked -p xtask -- artifact-catalog
```

This operation does not scan files. It reads only the repository-owned pack
root, rejects unexpected executable content and path indirection, enforces byte
and entry limits, and prints a deterministic count and catalog digest.

## Opt-in local-file adapter

The library does not open paths. An explicit non-default CLI feature owns the
local read-only boundary:

```console
cargo run --locked -p termivar-cli --features artifact-adapter -- \
  artifact scan-file \
  --signatures artifact-signatures/lab/termivar-canary/signatures.toml \
  --input ./authorized-sample.bin \
  --format json
```

The adapter accepts one explicitly selected regular file and one signature
manifest. It performs no recursion, glob expansion, directory scan, process
memory acquisition, network request, file write, or automatic invocation from
`termivar scan`. JSON output omits the input path and matched bytes. A completed
scan exits successfully whether or not observations exist; invalid or incomplete
execution is nonzero.

## Claims and limitations

A signature match is an observation only. V1 is not antivirus, EDR, malware
confirmation, process-memory forensics, real-time protection, YARA compatibility,
or vulnerability confirmation. It neither assigns severity nor invokes exploit
orchestration. Whole-machine and recursive directory scanning are not
implemented.
