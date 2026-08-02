# Observability

Observability support in Venom `0.9.0-alpha` is Preview. The compiled scanner
provides in-process logging, counters, scan profiles, and benchmark records. It
does not currently provide a stable Prometheus exporter, OpenTelemetry
pipeline, remote telemetry service, health-check server, or Sentry integration.

## Current modules

| Module | Availability | Responsibility |
| --- | --- | --- |
| `venom_scanner::logging` | Default build | Console-oriented `LogEntry`, `LogLevel`, and `Logger` types |
| `venom_scanner::metrics` | Default build | Process-local atomic counters and snapshots |
| `venom_scanner::monitoring` | `monitoring` feature | In-memory phase/resource profiles and comparisons |
| Criterion suite | Repository tooling | Repeatable microbenchmark samples and regression artifacts |
| Quality Metrics workflow | CI | Compile time, binary size, and runner peak-memory artifacts |

These contracts are diagnostic. They are not a durability boundary and their
state is lost when the process exits.

## Metrics collector

`MetricsCollector` is cloneable and uses atomics for its counters:

```rust
use venom_scanner::MetricsCollector;

let metrics = MetricsCollector::new();
metrics.record_request(128);
metrics.record_response(512);
metrics.record_finding();

let snapshot = metrics.summary();
assert_eq!(snapshot.total_requests, 1);
assert_eq!(snapshot.total_responses, 1);
assert_eq!(snapshot.total_findings, 1);
```

The collector records what its caller reports. It must not be used to enforce
request, response-byte, timeout, retry, redirect, or verification limits. The
decision runtime's host-owned request broker and `RuntimeUsage` receipts are the
authoritative resource-accounting boundary.

## Logging

The current logger emits formatted entries to standard output:

```rust
use venom_scanner::{LogEntry, LogLevel, Logger};

let logger = Logger::new(LogLevel::Info);
logger.log(
    LogEntry::new(LogLevel::Info, "scan phase started".to_owned())
        .with_phase(1),
);
```

Do not put credentials, cookies, authorization headers, raw evidence values,
customer identifiers, or target response bodies in a log message. Context IDs
and comparison handles should be treated as opaque even when their transport
representation is serializable.

`Logger` is intentionally small and is not yet a facade over `tracing`. Hosts
that need structured collection should translate approved, redacted events at
their application boundary.

## Monitoring feature

Enable the optional in-memory profile types with:

```toml
[dependencies]
venom-scanner = { version = "0.9.0-alpha", features = ["monitoring"] }
```

The feature exposes `PhaseProfile`, `ResourceMetrics`, `ScanProfile`,
`PerformanceAnalyzer`, `BenchmarkSuite`, and related value types. Values are
caller-supplied observations; Venom does not sample operating-system CPU or RAM
usage on behalf of the host.

## CI evidence

The Quality Metrics workflow publishes per-commit artifacts containing:

- release compile wall time and peak resident memory;
- release CLI binary size;
- Criterion suite wall time and peak resident memory;
- Cargo timing and Criterion reports;
- the commit SHA and Rust compiler version.

Those values are runner-local regression signals, not endpoint-capacity claims.
See [Quality metrics](quality-metrics.md), [Benchmarks](benchmarks.md), and
[Profiling](profiling.md).

## Stable exporter requirements

A future exporter must define and test:

- a versioned, bounded metric vocabulary;
- redaction and cardinality limits;
- backpressure and exporter-failure semantics;
- opt-in remote transport with no secret-bearing defaults;
- separation between diagnostic metrics and security budget enforcement;
- compatibility and retention policy.

Until those requirements are implemented, deployment examples must not claim
that `/metrics`, `/health`, `/ready`, remote telemetry, or distributed tracing
are built-in Venom endpoints.
