# Profiling

Profiling is evidence collection, not a release claim. Capture profiles against a controlled local target containing no sensitive data.

## Flamegraph

Install the tool and profile a release build:

```bash
cargo install flamegraph
cargo flamegraph -p termivar-cli -- scan http://127.0.0.1:3000
```

Linux may require `perf` permissions. Record the commit, feature flags, target fixture, and workload next to every flamegraph. Do not commit profiles containing target URLs, tokens, payloads, or response data.

## Criterion

```bash
cargo bench -p termivar-scanner --bench scanner_benchmarks
```

Use Criterion comparison baselines for micro-level regressions. Use an end-to-end harness for CPU, RAM, throughput, and latency; microbenchmarks cannot establish scanner capacity.
