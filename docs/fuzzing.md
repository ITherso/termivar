# Fuzzing

The `fuzz/` package contains one Venom-owned semantic target plus bounded
upstream-parser targets. Only `html_form_controls` exercises a product contract;
the five parser targets are dependency-level signals and must not be reported as
Venom decision-runtime coverage.

## Setup

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fuzz list
cargo fuzz run html_form_controls
```

Every pull request replays the committed semantic corpus and compiles the
Venom-owned target. The `Scheduled Fuzzing` workflow runs all six targets in
bounded weekly campaigns and when fuzz harnesses change on `main`. Every target
uploads its libFuzzer log and a structured campaign summary for 90 days;
failures also retain crash artifacts. This provides regression pressure, not
proof of parser or decision-runtime safety.

Run fuzzing on a dedicated machine or bounded CI job. Start with a small, non-sensitive seed corpus. Crashes must preserve the minimized input and exact commit SHA.

## Targets

| Target | Ownership | Contract |
| --- | --- | --- |
| `html_form_controls` | Venom | Bounded HTML sample to exact, names-only, sorted and deduplicated form-control observations |
| `http_parser` | Upstream | `httparse` request parser survival |
| `json_parser` | Upstream | `serde_json` value parser survival |
| `yaml_parser` | Upstream-only dependency | `serde_yaml` value parser survival |
| `xml_parser` | Upstream-only dependency | `quick-xml` event reader survival |
| `text_parser` | Upstream | URL and UTF-8 parser survival |

`html_form_controls` compiles the same private extractor source used by
`HttpEvidenceExecutor`; no production API is made public for fuzzability. Its
oracle asserts exact HTML `name` preservation (including whitespace), excludes
empty names and non-control/decoy content, protects the names-only privacy
boundary, and requires deterministic sorted/deduplicated output. The harness
accepts at most 64 KiB per input.

## Semantic corpus and reproduction

Reviewed seeds under `fuzz/corpus/html_form_controls/` include the minimized
whitespace-normalization reproducer, exact and substring-only convention names,
real/empty/duplicate/Unicode controls, quote-state spoofing, raw-text/comment
decoys, values, character references, malformed/truncated markup, a long name,
and modest nesting. Generated hash-named corpus files remain ignored until they
are deliberately reviewed and promoted.

Replay all committed seeds without libFuzzer:

```bash
cargo test --manifest-path fuzz/harness/Cargo.toml --locked
```

Replay or minimize one retained finding:

```bash
cd fuzz
cargo fuzz run html_form_controls artifacts/html_form_controls/<artifact>
cargo fuzz tmin html_form_controls artifacts/html_form_controls/<artifact>
```

Scheduled campaigns use explicit 60-second, 64-KiB input, five-second per-input,
and 1024-MiB RSS limits with a recorded deterministic seed. A timeout, assertion
failure, panic, excessive allocation, or sanitizer finding requires the same
minimize-classify-regress-fix triage as a normal test failure.

Fuzz harnesses should have no network, filesystem, clock, or random dependencies. A parser rejection is not a crash; panics, hangs, excessive allocation, and sanitizer findings require triage.

## Published reports

Reports committed under `docs/reports/fuzzing/` record the exact commit, bounded runtime, target outcomes, corpus counts, and workflow provenance. A report is published only after all target jobs complete; absence of a crash in a bounded run is not a safety claim.

- [`7515b79`: five 60-second campaigns, 32,500,714 executions, no observed crashes](reports/fuzzing/7515b79.md)
