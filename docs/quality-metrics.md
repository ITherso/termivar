# Quality metrics

Venom publishes measurements as CI artifacts instead of embedding hand-maintained numbers in the README.

Evidence-backed release baselines are committed under `docs/reports/benchmarks/`. The latest published record is [commit `f7d5120`](reports/benchmarks/f7d5120.md), with raw values in [JSON](reports/benchmarks/f7d5120.json).

## Every push and pull request

The `Quality Metrics` workflow records:

- release compile wall time;
- release binary size;
- build peak resident memory;
- Criterion suite wall time and peak resident memory;
- detailed Cargo timing and Criterion reports;
- commit SHA and Rust compiler version.

Results are runner-local regression signals. They are not comparable across arbitrary hardware and are not endpoint-capacity claims.

Coverage is produced by the Tests workflow and uploaded to Codecov. Unit, integration, compatibility, and security results remain separate required checks.

`scripts/generate-metrics.sh` derives package roots from locked Cargo metadata,
then reports only Rust files that Git identifies as tracked below those roots.
The architecture gate separately rejects loose top-level Rust files in the
examples package that are not declared Cargo targets. These repository-size
counts are not a coverage or quality score. Running the script requires Bash,
Git, Cargo, and Python 3 for decoding Cargo's JSON output.

## Scoped mutation evidence

Mutation testing is used as a review technique for selected semantic contracts,
not as a permanent repository-wide score. Recent hardening work used pinned
`cargo-mutants` campaigns around declarative policy, planner/runtime authority,
and HTML extraction boundaries in [PR #53](https://github.com/ITherso/venom/pull/53),
[PR #54](https://github.com/ITherso/venom/pull/54), and
[PR #55](https://github.com/ITherso/venom/pull/55). Viable survivors were
classified by behavior; serious semantic gaps became focused deterministic
regressions and were rerun in narrowed campaigns.

Those pull-request records are scoped evidence for their exact revisions. Venom
does not have a committed mutation workflow, an aggregate workspace score, or a
claim that every mutation-relevant function has been exercised.

## Not measured yet

| Metric | State | Exit criterion |
| --- | --- | --- |
| Project-wide mutation baseline | Missing | Commit a repeatable scope, exclusions, survivor policy, and comparable baseline |
| Endpoint throughput/latency | Missing | Controlled fixture at 100, 1,000, and 10,000 request scales |
| Scanner peak RAM/CPU | Missing | End-to-end workload with pinned hardware and feature flags |
| External audit findings | Missing | Independent scope, report, and remediation record |

If a permanent mutation job is introduced, it should normally run on a schedule
rather than every push because it executes many modified test builds. Scoped
campaign evidence must not be represented as complete mutation coverage.

## Reproduce microbenchmarks

```bash
cargo bench -p venom-scanner --bench scanner_benchmarks
```

See [Benchmarks](benchmarks.md) for the controlled release-baseline schema and [Profiling](profiling.md) for flamegraph guidance.
