# Benchmarks

Venom uses Criterion for repeatable microbenchmarks. Run:

```bash
cargo bench -p venom-scanner --bench scanner_benchmarks
# or
cargo xtask benchmark
```

The active Criterion suite measures neutral percent encoding. Criterion stores
reports under `target/criterion/`.

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

## Endpoint assessment harness

The endpoint-scale harness executes the real `WebAssessmentRuntime` with a
validated `web-review` profile. Every HTTP dispatch goes through the runtime's
broker and checked budget authority. The fixture is created by the harness on
`127.0.0.1`; there is no target argument and no public network target can be
supplied.
The fixture applies a fixed one-millisecond response delay so the runtime's
millisecond broker receipts retain useful latency resolution; that delay is
recorded in the machine report and cannot be configured by the caller.
The executable also rejects non-empty standard HTTP/HTTPS/ALL proxy variables
before binding a fixture. The canonical wrapper clears those variables only
after Cargo has built the binary and pins both `NO_PROXY` spellings to loopback.

The fixed workloads are:

| Workload | Retained/executed endpoints | Requests | Authority model |
| --- | ---: | ---: | --- |
| `endpoints-100` | 100 | 102 | One shared origin-assessment authority |
| `endpoints-1000` | 1,000 | 1,002 | One shared origin-assessment authority |
| `requests-10000` | 9,980 | 10,000 | Ten independent 998-subject assessments, 1,000 requests each |

The two requests beyond each authority's endpoint count are the matched CORS
control/candidate observations enabled by `web-review`. Both are transport
receipts and action outcomes; only the candidate consumes the authority's one
active-verification slot. The 10,000-request workload is deliberately not
described as one global authority: it is a batch of ten independent
assessments, each with its own broker, cancellation, deadline, and request
budget.

For every authority, the harness fails unless execution is complete, every
subject was executed, request and active-verification usage match the expected
counts, no transport receipt was omitted, receipt sequence is contiguous,
every dispatch completed, and receipt bytes reconcile with runtime usage.
Latency percentiles come from the broker's monotonic dispatch receipts.

Use the canonical Linux wrapper so process CPU and peak RSS are collected from
GNU `time` after the benchmark executable has already been built. The wrapper
requires a clean worktree so its recorded commit SHA cannot label uncommitted
source:

```bash
bash scripts/run-endpoint-performance.sh \
  --workload all \
  --warmups 1 \
  --samples 3 \
  --output-dir target/endpoint-performance
```

Warmups are hard-bounded to 1–3 and measured samples to 3–10. The command
writes each validated JSON and Markdown file atomically under the selected
output directory; a failure returns nonzero and is never reported as a
successful evidence pair. The JSON schema is
`venom.endpoint-performance/v1`; it records wall time, requests/second,
p50/p95/p99 dispatch latency, response bytes, endpoint and request counts,
authority partitioning, profile, commit, Rust version, OS, CPU, memory, build
profile, process CPU, peak RSS, and sample variance. Unknown fields, incomplete
accounting, mismatched summaries, and partially observed environment data fail
closed.

The `Endpoint Performance Evidence` workflow runs small harness and renderer
contract tests when their paths change. Once the workflow is on the default
branch, a manual dispatch can select a fixed workload and sample count. Before
that, an authorized maintainer may explicitly apply the
`endpoint-performance-evidence` label to a same-repository pull request; that
event runs only the fixed `all`, one-warmup, three-sample measurement. Fork pull
requests cannot activate it. The measurement checkout and artifact identity are
pinned to the pull request head commit rather than GitHub's synthetic merge
commit. Artifacts are measurements, not performance claims.

### Initial controlled endpoint evidence

Source commit `27321efbbf49cb2adbc72afb699d1b31ea407486` completed the fixed
all-workload run with one warmup and three measured samples in
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976).
The exact artifact is retained as the [human-readable record](reports/benchmarks/27321ef-endpoint-assessment.md)
and [validated JSON](reports/benchmarks/27321ef-endpoint-assessment.json).

| Workload | Wall median | Wall CV | Requests/s median | p95 dispatch latency |
| --- | ---: | ---: | ---: | ---: |
| 100 endpoints / 102 requests | 325.865 ms | 0.14% | 313.01 | 2 ms |
| 1,000 endpoints / 1,002 requests | 3,747.424 ms | 0.48% | 267.38 | 2 ms |
| 9,980 endpoints / 10,000 requests / 10 authorities | 37,454.359 ms | 0.48% | 266.99 | 2 ms |

GNU `time` observed 78.38 total CPU seconds, 46% process CPU utilization, and
333,036 KiB peak RSS across every selected workload, warmup, and measured
sample. These are runner-local observations with a fixed one-millisecond
fixture delay and millisecond receipt resolution. They are not an SLA, capacity
limit, concurrency result, or accepted regression threshold.

## Release baseline

Initial controlled endpoint evidence now exists, but a repeatable accepted
baseline has not yet been established. Do not substitute microbenchmarks, one
workflow run, synthetic values, or estimates for a release capacity claim. The
machine schema keeps `thresholds` exactly `null` and emits no speed pass/fail
field. Multiple comparable runs must establish inter-run variance on a pinned
hardware class before a later reviewed change can propose regression
thresholds.

Every published result must preserve commit SHA, Rust version, OS, CPU, memory,
fixture identity, build profile, scan profile, and warm-up/sample method.
Compare releases only on the same controlled fixture and hardware class.

## Graphs

Criterion generates per-benchmark plots. Endpoint-scale evidence currently has
fixed runtime concurrency of one; it must not be relabeled as a concurrency
scaling result. Any future chart must retain the raw validated JSON beside the
human-readable projection.
