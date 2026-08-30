# Venom endpoint performance evidence

Schema: `venom.endpoint-performance/v1`

This record contains measurements, not accepted speed thresholds. `thresholds` is deliberately `null`; no workload receives a speed pass/fail result.

## Environment

| Field | Value |
| --- | --- |
| Commit | `27321efbbf49cb2adbc72afb699d1b31ea407486` |
| Rust | `rustc 1.88.0 (6b00bc388 2025-06-23) binary: rustc commit-hash: 6b00bc3880198600130e1cf62b8f8a93494488cc commit-date: 2025-06-23 host: x86_64-unknown-linux-gnu release: 1.88.0 LLVM version: 20.1.5` |
| OS | Linux 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 GNU/Linux |
| Architecture | `x86_64` |
| Build profile | `bench` |
| CPU | AMD EPYC 9V74 80-Core Processor |
| Logical CPUs | 4 |
| Total memory | 16766414848 bytes |

## Process resources

GNU `time` measures the already-built benchmark process across the selected workloads, warmups, and measured samples.

| User CPU | System CPU | Total CPU | CPU utilization | Peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 68.640 s | 9.740 s | 78.380 s | 46.0% | 333036 KiB |

## Configuration

- Fixture: `hard-coded-127.0.0.1-http1` (harness-owned loopback only)
- Fixture response delay: 1 ms
- Profile: `web-review`
- Runtime concurrency: 1
- Active verifications per authority: 1
- Warmups: 1
- Measured samples: 3
- Latency source: `broker-dispatch-receipt-elapsed-ms`

The 10,000-request workload is ten independent 998-subject origin assessments. Each assessment owns one 1,000-request broker/budget authority; the batch is not represented as one global authority.

## Workload summaries

| Workload | Endpoints | Requests | Authorities | Wall median | Wall CV | RPS median | p50 | p95 | p99 | Response bytes median |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `endpoints-100` | 100 | 102 | 1 | 325.865 ms | 0.14% | 313.01 | 2.00 ms | 2.00 ms | 2.00 ms | 16755 |
| `endpoints-1000` | 1000 | 1002 | 1 | 3747.424 ms | 0.48% | 267.38 | 2.00 ms | 2.00 ms | 2.00 ms | 167955 |
| `requests-10000` | 9980 | 10000 | 10 | 37454.359 ms | 0.48% | 266.99 | 2.00 ms | 2.00 ms | 2.00 ms | 1676190 |

## Samples

### `endpoints-100`

Authority request counts: `[102]`

| Sample | Wall | Requests/s | p50 | p95 | p99 | Response bytes |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 325.069 ms | 313.78 | 2 ms | 2 ms | 2 ms | 16755 |
| 2 | 325.865 ms | 313.01 | 2 ms | 2 ms | 2 ms | 16755 |
| 3 | 326.178 ms | 312.71 | 2 ms | 2 ms | 2 ms | 16755 |

### `endpoints-1000`

Authority request counts: `[1002]`

| Sample | Wall | Requests/s | p50 | p95 | p99 | Response bytes |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 3724.381 ms | 269.04 | 2 ms | 2 ms | 2 ms | 167955 |
| 2 | 3747.424 ms | 267.38 | 2 ms | 2 ms | 2 ms | 167955 |
| 3 | 3768.777 ms | 265.87 | 2 ms | 2 ms | 2 ms | 167955 |

### `requests-10000`

Authority request counts: `[1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000]`

| Sample | Wall | Requests/s | p50 | p95 | p99 | Response bytes |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 37725.583 ms | 265.07 | 2 ms | 2 ms | 2 ms | 1676190 |
| 2 | 37454.359 ms | 266.99 | 2 ms | 2 ms | 2 ms | 1676190 |
| 3 | 37289.746 ms | 268.17 | 2 ms | 2 ms | 2 ms | 1676190 |
