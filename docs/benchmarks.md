# Benchmarks

Venom uses Criterion for repeatable microbenchmarks. Run:

```bash
cargo bench -p venom-scanner --bench scanner_benchmarks
# or
cargo xtask benchmark
```

The active suite measures generic LRU-cache access and neutral percent encoding.
Criterion stores reports under `target/criterion/`.

The `Quality Metrics` GitHub Actions workflow runs this suite on every push and pull request, then uploads Criterion output with build timing, binary size, and runner peak-RSS measurements. See [Quality metrics](quality-metrics.md).

## Historical baseline (not the current suite)

The first committed baseline comes from green main commit
[`f7d5120`](reports/benchmarks/f7d5120.md). It measured the now-removed URL-only
response cache, WAF detector, and double-encoding façade, so its values are
historical evidence and are not a baseline for the current suite:

| Benchmark | Mean | 95% confidence interval |
| --- | ---: | ---: |
| Response cache hit, 4 KiB | 213.71 ns | 213.00–214.86 ns |
| WAF header detection | 152.28 ns | 151.27–153.99 ns |
| Double URL encoding | 3.113 µs | 3.106–3.124 µs |

The [full historical report](reports/benchmarks/f7d5120.md) includes workflow
provenance, the compiler version, process-level resource measurements,
limitations, and a [machine-readable JSON record](reports/benchmarks/f7d5120.json).
A new current-suite baseline must come from a green run at the remediated commit;
this document does not invent replacement measurements.

## Release baseline

Endpoint-scale numbers have not yet been published. Do not substitute these microbenchmarks, synthetic values, or estimates for capacity measurements. A future end-to-end release baseline must record:

| Scenario | Requests | Concurrency | CPU | Peak RAM | Wall time | p50 | p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 endpoints | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| 1,000 endpoints | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| 10,000 requests | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

Every published result must include commit SHA, Rust version, OS, CPU, memory, target fixture, feature flags, scan profile, and warm-up method. Compare releases only on the same controlled target and hardware class.

## Graphs

Criterion generates per-benchmark plots. Endpoint-scale graphs should show throughput and p95 latency against concurrency, plus peak memory against request count. Commit raw machine-readable output with any published chart.
