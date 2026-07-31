# VENOM Observability & Monitoring

Observability design notes for Venom v0.9.0-alpha.

## Observability Architecture

```
Observability Stack
├─ Health Checks
│  ├─ /health endpoint (liveness)
│  ├─ /readiness endpoint (readiness)
│  ├─ /liveness endpoint (liveness probe)
│  └─ Component status dashboard
│
├─ Logging
│  ├─ Structured JSON logging
│  ├─ Log levels (TRACE, DEBUG, INFO, WARN, ERROR)
│  ├─ Contextual logging (request IDs, user IDs)
│  ├─ Log aggregation (ELK, Datadog)
│  └─ Retention policies (configurable)
│
├─ Metrics
│  ├─ Prometheus /metrics endpoint
│  ├─ CPU, memory, disk usage
│  ├─ Request latency percentiles
│  ├─ Throughput & error rates
│  ├─ Cache hit rates
│  └─ Database connection pools
│
├─ Telemetry (opt-in)
│  ├─ Usage analytics (anonymized)
│  ├─ Error tracking
│  ├─ Performance metrics
│  ├─ Feature usage tracking
│  └─ Crash reporting (Sentry)
│
├─ Tracing
│  ├─ OpenTelemetry support
│  ├─ Jaeger integration
│  ├─ Zipkin integration
│  ├─ Distributed tracing
│  └─ Request flow visualization
│
└─ Uptime Monitoring
   ├─ Status page (statuspage.io)
   ├─ Incident history
   ├─ SLA tracking
   ├─ Target: 99.9% uptime
   └─ Maintenance windows
```

## Health Checks

### Endpoints

**Liveness Probe** (`/health`):
```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "Healthy",
  "timestamp": "2026-07-15T10:30:00Z",
  "version": "0.9.0-alpha",
  "uptime_seconds": 86400,
  "checks_passed": 5,
  "checks_failed": 0,
  "components": {
    "api": {
      "name": "api",
      "status": "Healthy",
      "message": "Running",
      "response_time_ms": 5
    },
    "database": {
      "name": "database",
      "status": "Healthy",
      "message": "Connected",
      "response_time_ms": 10
    }
  }
}
```

**Readiness Probe** (`/readiness`):
```bash
curl http://localhost:3000/readiness
```

Indicates whether the service is ready to handle traffic (all dependencies online).

**Liveness Probe** (`/liveness`):
```bash
curl http://localhost:3000/liveness
```

Indicates whether the service is still running (used by container orchestrators).

### Component Status

Components monitored:
- API Server
- Database Connection Pool
- Redis Cache
- File Storage
- External Services

Dependencies monitored:
- PostgreSQL
- Redis
- Elasticsearch
- Sentry

## Logging

### Configuration

```rust
use venom::observability::{LogConfig, LogLevel, LogFormat};

let config = LogConfig {
    level: LogLevel::Info,
    format: LogFormat::Json,
    structured: true,
    retention_days: 30,
    max_file_size_mb: 100,
    max_files: 10,
};
```

### Log Levels

```
TRACE - Detailed debug information
DEBUG - General debug information
INFO  - Informational messages
WARN  - Warning messages
ERROR - Error messages
```

### Structured Logging

All logs are output as structured JSON:

```json
{
  "timestamp": "2026-07-15T10:30:00Z",
  "level": "INFO",
  "module": "scanner",
  "message": "Vulnerability found",
  "request_id": "req-abc-123",
  "user_id": "user-xyz-789",
  "context": {
    "vulnerability_type": "SQL Injection",
    "severity": "High",
    "scan_id": "scan-123"
  }
}
```

### Log Aggregation

**ELK Stack Integration:**
```yaml
filebeat.prospectors:
  - type: log
    enabled: true
    paths:
      - /var/log/venom/*.json
    processors:
      - decode_json_fields:
          fields: ["message"]
          target: ""

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "venom-%{+yyyy.MM.dd}"
```

**Datadog Integration:**
```yaml
logs:
  - type: file
    path: /var/log/venom/*.json
    service: venom
    source: venom
    tags:
      - env:production
```

### Log Retention

Configurable retention policies:
- Default: 30 days
- Production: 90+ days
- Compliance: 1+ years (GDPR/HIPAA)

## Metrics Export

### Prometheus Metrics Endpoint

**Endpoint:** `GET /metrics`

```bash
curl http://localhost:9090/metrics
```

**Sample Output:**
```
# HELP venom_uptime_seconds Uptime in seconds
# TYPE venom_uptime_seconds gauge
venom_uptime_seconds 86400

# HELP venom_cpu_usage_percent CPU usage percentage
# TYPE venom_cpu_usage_percent gauge
venom_cpu_usage_percent 25.5

# HELP venom_memory_usage_mb Memory usage in MB
# TYPE venom_memory_usage_mb gauge
venom_memory_usage_mb 512.0

# HELP venom_request_count Total requests
# TYPE venom_request_count counter
venom_request_count 10000

# HELP venom_request_latency_ms Request latency in milliseconds
# TYPE venom_request_latency_ms gauge
venom_request_latency_ms 45.5
```

### Prometheus Configuration

Add VENOM to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'venom'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    scrape_timeout: 10s
```

### Grafana Dashboards

Pre-built dashboards:
- System metrics (CPU, memory, disk)
- Request metrics (latency, throughput, errors)
- Database metrics (connections, queries, latency)
- Cache metrics (hit rate, evictions)
- Custom dashboards (JSON export)

**Dashboard IDs:**
- 1001: VENOM System Overview
- 1002: VENOM Request Metrics
- 1003: VENOM Database Performance
- 1004: VENOM Cache Performance

### Alerting Rules

**Alert Rules:**
```yaml
groups:
  - name: venom
    rules:
      - alert: HighCPUUsage
        expr: venom_cpu_usage_percent > 80
        for: 5m
        annotations:
          summary: "High CPU usage ({{ $value }}%)"
      
      - alert: HighErrorRate
        expr: venom_request_errors / venom_request_count > 0.05
        for: 5m
        annotations:
          summary: "High error rate ({{ $value | humanizePercentage }})"
      
      - alert: LowCacheHitRate
        expr: venom_cache_hits / (venom_cache_hits + venom_cache_misses) < 0.70
        for: 10m
        annotations:
          summary: "Low cache hit rate ({{ $value | humanizePercentage }})"
```

## Telemetry (Opt-in)

### Configuration

Telemetry is **disabled by default** and requires explicit opt-in.

```rust
use venom::observability::TelemetryConfig;

let config = TelemetryConfig {
    enabled: true,  // Opt-in required
    endpoint: "https://telemetry.venom.dev".to_string(),
    sample_rate: 0.1,  // 10% sampling
    api_key: Some("your-api-key".to_string()),
    batch_size: 100,
    flush_interval_seconds: 60,
    error_tracking_enabled: true,
    performance_tracking_enabled: true,
    feature_tracking_enabled: true,
    crash_reporting_enabled: false,
};
```

### Event Types

Tracked events:
- `AppStart` - Application startup
- `AppStop` - Application shutdown
- `ScanStarted` - Vulnerability scan started
- `ScanCompleted` - Vulnerability scan completed
- `ExploitExecuted` - Exploit execution
- `Error` - Error/exception occurred
- `FeatureUsage` - Feature was used
- `PerformanceMetric` - Performance measurement

### Error Tracking

Automatic error tracking with:
- Error type & message
- Stack trace
- Context (module, user, request)
- Severity level (Low/Medium/High/Critical)

**Error Report Example:**
```json
{
  "id": "error-abc-123",
  "timestamp": "2026-07-15T10:30:00Z",
  "error_type": "DatabaseConnectionError",
  "message": "Connection pool exhausted",
  "severity": "High",
  "context": {
    "module": "scanner",
    "user_id": "user-123"
  }
}
```

### Privacy & Anonymization

Telemetry data:
- ✅ Anonymized (no personally identifiable information)
- ✅ Encrypted in transit (TLS 1.3)
- ✅ Encrypted at rest (AES-256)
- ✅ User opt-in required
- ✅ Can be disabled at any time
- ✅ Local-only option available

**Anonymization:**
- User IDs are hashed
- IP addresses are excluded
- Session IDs are randomly generated
- Sensitive data is filtered

### Crash Reporting

Optional crash reporting via Sentry:

```rust
let config = TelemetryConfig {
    crash_reporting_enabled: true,
    endpoint: "https://sentry.io/projects/venom".to_string(),
    ..Default::default()
};
```

## Distributed Tracing

### Configuration

```rust
use venom::observability::{TracingConfig, ExporterType};

let config = TracingConfig {
    enabled: true,
    endpoint: "http://localhost:4317".to_string(),
    sample_rate: 0.1,  // 10% sampling
    exporter_type: ExporterType::OpenTelemetry,
    max_attributes: 128,
    max_events: 128,
};
```

### Supported Exporters

- **OpenTelemetry** (OTLP) - Default
- **Jaeger** - Uber's distributed tracing
- **Zipkin** - Twitter's distributed tracing
- **Datadog** - Datadog APM

### Trace Visualization

Traces include:
- Request flow across services
- Database query tracing
- Cache operations
- External API calls
- Performance bottlenecks

**Example Trace:**
```
POST /api/scan
├─ Authenticate user (5ms)
├─ Create scan record (10ms)
├─ Start scanner
│  ├─ Port scan (1000ms)
│  ├─ Service enumeration (500ms)
│  └─ Vulnerability detection (2000ms)
└─ Return response (50ms)
Total: 3565ms
```

### Trace Context

Propagated via:
- `traceparent` header (W3C standard)
- `tracestate` header (vendor extensions)
- Message queue headers (Kafka, RabbitMQ)
- Database query comments

## Uptime Monitoring

### Status Page

Public status page: https://status.venom.dev

Shows:
- System status (Operational/Degraded/Down)
- Component status
- Incident history
- Maintenance windows
- Response times
- SLA metrics

### SLA Tracking

**Target SLAs:**
- Availability: 99.9% (44 minutes downtime/month)
- Latency: <100ms (P95)
- Error Rate: <0.5%

**SLA Calculation:**
```
SLA % = (Total Time - Downtime) / Total Time × 100
```

### Incident Management

Incident tracking:
- Incident title & description
- Start & end time
- Impact (number of affected users)
- Root cause
- Resolution steps
- Postmortem

### Maintenance Windows

Scheduled maintenance:
- Planned downtime
- Expected duration
- Affected components
- Maintenance reason

## Monitoring in Production

### Kubernetes Monitoring

**PrometheusServiceMonitor:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: venom
spec:
  selector:
    matchLabels:
      app: venom
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

**PodMonitor for Kubernetes Metrics:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: venom
spec:
  selector:
    matchLabels:
      app: venom
  podMetricsEndpoints:
    - port: metrics
      interval: 30s
```

### Docker Monitoring

Mount volumes for logs:
```bash
docker run \
  -v /var/log/venom:/var/log/venom \
  -p 9090:9090 \
  ghcr.io/itherso/venom:latest
```

### Alerting

Set up alerts for:
- Service downtime (pagerduty, slack)
- High error rates (email)
- Resource exhaustion (slack)
- SLA violations (email)
- Performance degradation (slack)

**Slack Integration:**
```
[ALERT] High CPU Usage
Service: VENOM API
Current: 85% | Threshold: 80%
Duration: 5 minutes
https://grafana.example.com/d/abc
```

## Best Practices

### Logging

✅ Log structured data (JSON)
✅ Include request IDs for tracing
✅ Add relevant context (user, scan, etc.)
✅ Use appropriate log levels
✅ Avoid logging sensitive data
✅ Set retention policies
❌ Don't log in tight loops
❌ Don't log raw responses/requests

### Metrics

✅ Use descriptive metric names
✅ Include labels for dimensions
✅ Set appropriate retention
✅ Use consistent units
✅ Aggregate at source
❌ Don't create unbounded cardinality
❌ Don't expose sensitive data

### Tracing

✅ Sample appropriately (10% is good)
✅ Include relevant attributes
✅ Propagate trace context
✅ Use descriptive span names
✅ Tag with service name
❌ Don't trace everything
❌ Don't include huge payloads

### Health Checks

✅ Check all critical dependencies
✅ Set reasonable timeouts
✅ Return correct HTTP status codes
✅ Include helpful error messages
✅ Cache results briefly
❌ Don't check external services
❌ Don't do heavy operations

## Troubleshooting

### High Memory Usage

1. Check log retention policies
2. Reduce telemetry sample rate
3. Limit trace history
4. Check for log backups

### High Disk Usage

1. Rotate logs (enable log rotation)
2. Compress old logs
3. Clean up temporary files
4. Check backup storage

### High CPU Usage

1. Reduce metric scraping frequency
2. Reduce telemetry sample rate
3. Profile CPU usage
4. Check for logging bottlenecks

### Missing Metrics

1. Verify Prometheus scrape config
2. Check /metrics endpoint
3. Verify port is open
4. Check firewall rules

## References

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Jaeger Tracing](https://www.jaegertracing.io/)
- [ELK Stack](https://www.elastic.co/what-is/elk-stack)
- [Datadog Docs](https://docs.datadoghq.com/)
