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

`scripts/generate-metrics.sh` reports tracked Rust lines and files only for
declared workspace-package roots (`crates/`, `examples/`, and `xtask/`). These
repository-size counts are not a coverage or quality score.

## Not measured yet

| Metric | State | Exit criterion |
| --- | --- | --- |
| Mutation score | Missing | Select a tool, define exclusions, and publish a repeatable baseline |
| Endpoint throughput/latency | Missing | Controlled fixture at 100, 1,000, and 10,000 request scales |
| Scanner peak RAM/CPU | Missing | End-to-end workload with pinned hardware and feature flags |
| External audit findings | Missing | Independent scope, report, and remediation record |

Mutation testing should normally run on a schedule rather than every push because it executes many modified test builds. It must not be represented as complete until an actual score and survivor policy exist.

## Reproduce microbenchmarks

```bash
cargo bench -p venom-scanner --bench scanner_benchmarks
```

See [Benchmarks](benchmarks.md) for the controlled release-baseline schema and [Profiling](profiling.md) for flamegraph guidance.
