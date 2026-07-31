# Benchmarks

Venom uses Criterion for repeatable microbenchmarks. Run:

```bash
cargo bench -p venom-scanner --bench scanner_benchmarks
```

The active suite measures cache access, WAF header detection, and payload encoding. Criterion stores reports under `target/criterion/`.

## Release baseline

Endpoint-scale numbers have not yet been published. Do not substitute synthetic or estimated results for measurements. The first release baseline should record:

| Scenario | Requests | Concurrency | CPU | Peak RAM | Wall time | p50 | p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 endpoints | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| 1,000 endpoints | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| 10,000 requests | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

Every published result must include commit SHA, Rust version, OS, CPU, memory, target fixture, feature flags, scan profile, and warm-up method. Compare releases only on the same controlled target and hardware class.

## Graphs

Criterion generates per-benchmark plots. Endpoint-scale graphs should show throughput and p95 latency against concurrency, plus peak memory against request count. Commit raw machine-readable output with any published chart.
