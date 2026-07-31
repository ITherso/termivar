# VENOM Testing Framework

Testing guidance for Venom v0.9.0-alpha, covering unit, integration, performance, security, and compatibility checks.

## Testing Architecture

```
Testing Framework
├─ Unit Tests (301+ tests)
├─ Integration Tests
│  ├─ Proxy ↔ Scanner
│  ├─ Scanner ↔ Exploiter
│  ├─ API ↔ Database
│  ├─ C2 ↔ Agent
│  └─ End-to-End
├─ E2E Tests (Selenium/Playwright)
│  ├─ Dashboard workflows
│  ├─ Team collaboration
│  ├─ Report generation
│  ├─ Settings management
│  └─ User authentication
├─ Performance Tests
│  ├─ Proxy latency
│  ├─ Concurrent connections
│  ├─ Scanner throughput
│  ├─ Memory usage
│  └─ CSS rendering
├─ Security Tests
│  ├─ SQLi injection
│  ├─ XSS payloads
│  ├─ CSRF tokens
│  ├─ Auth bypass
│  ├─ RBAC permissions
│  └─ Secret management
├─ Compatibility Tests
│  ├─ Browser compatibility
│  ├─ OS compatibility
│  ├─ Rust versions
│  ├─ Database versions
│  └─ Dependencies
└─ CI/CD Pipelines
   ├─ Automated testing
   ├─ Security scanning
   ├─ Code coverage
   ├─ Performance regression
   ├─ Dependency checks
   └─ Automated releases
```

## Running Tests

### Unit Tests

```bash
# Run all unit tests
cargo test --lib

# Run specific test module
cargo test --lib security::tests

# Run with output
cargo test --lib -- --nocapture

# Run with backtrace
RUST_BACKTRACE=1 cargo test --lib
```

### Integration Tests

```bash
# Run integration tests (requires PostgreSQL & Redis)
cargo test --test '*'

# Set database URL
export DATABASE_URL=postgres://test:test@localhost:5432/venom_test
export REDIS_URL=redis://localhost:6379
cargo test --test '*'
```

### E2E Tests

```bash
# Install Playwright browsers
cd web && npx playwright install --with-deps

# Run E2E tests
npm run test:e2e

# Run with specific browser
npx playwright test --project=chromium
npx playwright test --project=firefox
npx playwright test --project=webkit
```

### Performance Tests

```bash
# Run performance benchmarks
cargo bench

# Run specific benchmark
cargo bench -- proxy_latency
```

### Security Tests

```bash
# Run security audits
cargo audit

# Check for outdated dependencies
cargo outdated -R

# Run static analysis
cargo clippy -- -D warnings

# Run Semgrep security analysis
semgrep --config=p/security-audit .
```

### Compatibility Tests

```bash
# Test with different Rust versions
rustup install stable beta nightly
cargo +stable check
cargo +beta check
cargo +nightly check

# Test frontend compatibility
cd web && npm run test:a11y
```

## Test Modules

### Chaos Testing (`src/testing/chaos.rs`)

Test system resilience under failure conditions.

```rust
use venom::testing::{ChaosTest, ChaosScenario};

let test = ChaosTest::new(
    "Network Latency Test".to_string(),
    ChaosScenario::NetworkLatency { add_ms: 500 },
    "api-service".to_string(),
);
```

**Scenarios:**
- `NetworkLatency`: Inject network delay (0-1000ms)
- `NetworkPacketLoss`: Simulate packet loss (0-100%)
- `ServiceDowntime`: Simulate service outage (seconds)
- `CPUSpike`: CPU usage spike (duration + %)
- `MemoryExhaustion`: Memory pressure testing
- `DatabaseFailure`: Database unavailability
- `CascadingFailure`: Multi-service failures
- `PartialResponseFailure`: Failure rate testing
- `RequestTimeout`: Request timeout simulation

### Security Labs (`src/testing/security_labs.rs`)

Interactive security training environments.

```rust
use venom::testing::{SecurityLab, DifficultyLevel, LabCategory};

let mut lab = SecurityLab::new(
    "SQL Injection Lab".to_string(),
    "Learn SQL injection techniques".to_string(),
    DifficultyLevel::Beginner,
    LabCategory::WebApplication,
);
```

**Difficulty Levels:**
- `Beginner`: Basic security concepts (1-2 hours)
- `Intermediate`: Real-world scenarios (2-4 hours)
- `Advanced`: Complex vulnerabilities (4-8 hours)
- `Expert`: Enterprise security (8+ hours)

**Categories:**
- Web Application (SQLi, XSS, CSRF, etc.)
- API Security (REST/GraphQL attacks)
- Infrastructure (network, cloud, containers)
- Authentication (auth bypass, session hijacking)
- Data Protection (encryption, privacy)
- Network Security (MITM, DNS spoofing)
- Cloud Security (AWS, Azure, GCP)

### Integration Tests (`src/testing/integration_tests.rs`)

Test component interactions and data flow.

```rust
use venom::testing::{IntegrationTestSuite, IntegrationCategory};

let mut suite = IntegrationTestSuite::new(
    "Proxy-Scanner Integration".to_string()
);

let mut test = IntegrationTestCase::new(
    "Test proxy to scanner".to_string(),
    IntegrationCategory::ProxyScanner,
);
```

**Integration Categories:**
- `ProxyScanner`: MITM proxy → vulnerability scanner
- `ScannerExploiter`: Scanner → exploit execution
- `APIDatabase`: REST API → database operations
- `C2Agent`: C2 server → implant communication
- `EndToEnd`: Complete attack workflows

### E2E Tests (`src/testing/e2e_tests.rs`)

User workflow testing with real browsers.

```rust
use venom::testing::{E2ETestSuite, BrowserType, E2EWorkflow};

let mut suite = E2ETestSuite::new(
    "Dashboard Tests".to_string(),
    BrowserType::Chrome,
    "http://localhost:3000".to_string(),
);
```

**Supported Browsers:**
- Chrome/Chromium (Latest)
- Firefox (Latest)
- Safari (macOS only)
- Edge (Windows/macOS)

**Workflows:**
- `DashboardNavigation`: UI navigation & responsiveness
- `TeamCollaboration`: Team features & sharing
- `ReportGeneration`: Report creation & export
- `SettingsManagement`: Configuration changes
- `UserAuthentication`: Login & access control

### Performance Tests (`src/testing/performance_tests.rs`)

Performance benchmarking with threshold validation.

```rust
use venom::testing::PerformanceTestSuite;

let test = PerformanceTestSuite::proxy_latency_test(50.0); // target: <50ms
let test = PerformanceTestSuite::concurrent_connections_test(1000.0);
let test = PerformanceTestSuite::scanner_throughput_test(100.0); // 100 req/sec
let test = PerformanceTestSuite::memory_usage_test(100.0); // <100MB
let test = PerformanceTestSuite::css_rendering_test(200.0); // <200ms
```

**Metrics:**
- Response time (avg, P95, P99, max)
- Throughput (requests/sec)
- Memory usage (MB)
- CPU usage (%)
- Error rates (%)

### Security Tests (`src/testing/security_tests.rs`)

Automated security vulnerability testing.

```rust
use venom::testing::SecurityTestSuite;

let test = SecurityTestSuite::sqli_test(
    "' OR '1'='1".to_string(),
    "/api/users".to_string(),
);

let test = SecurityTestSuite::xss_test(
    "<script>alert('xss')</script>".to_string(),
    "/api/comment".to_string(),
);
```

**Test Types:**
- `SQLInjection`: SQL injection payload testing
- `XSSPayload`: Cross-site scripting detection
- `CSRFToken`: CSRF token validation
- `AuthenticationBypass`: Auth mechanism testing
- `RBACPermission`: Role-based access control
- `SecretManagement`: Secret protection verification
- `EncryptionValidation`: Encryption implementation
- `InputValidation`: Input sanitization checks
- `OutputEncoding`: Output encoding verification
- `HeaderInjection`: HTTP header injection

### Compatibility Tests (`src/testing/compatibility_tests.rs`)

Cross-platform & multi-version compatibility testing.

```rust
use venom::testing::CompatibilityTestSuite;

let test = CompatibilityTestSuite::browser_chrome_test("120.0".to_string());
let test = CompatibilityTestSuite::os_windows_test("11".to_string());
let test = CompatibilityTestSuite::rust_version_test("1.75".to_string());
```

**Compatibility Types:**
- Browser compatibility (Chrome, Firefox, Safari, Edge)
- OS compatibility (Windows, macOS, Linux)
- Rust version compatibility (stable, beta, nightly)
- Database compatibility (PostgreSQL, MySQL)
- Dependency version compatibility

### CI/CD Pipeline (`src/testing/ci_cd_tests.rs`)

Automated build & deployment pipeline.

```rust
use venom::testing::{CICDPipeline, JobType};

let mut pipeline = CICDPipeline::new("Main CI Pipeline".to_string());
let workflow = CICDPipeline::with_unit_tests();
pipeline.add_workflow(workflow);
```

**Job Types:**
- `UnitTests`: Run unit test suite
- `IntegrationTests`: Run integration tests
- `SecurityScanning`: Dependency & security audit
- `CodeCoverage`: Generate coverage reports
- `PerformanceRegression`: Detect performance regressions
- `DependencyCheck`: Check for outdated/vulnerable deps
- `ReleaseCandidate`: Prepare release candidate
- `Deployment`: Deploy to production

## GitHub Actions Workflows

### `.github/workflows/tests.yml`

**Triggers:** Push, Pull Request on main/develop

**Jobs:**
1. `unit-tests`: Run full unit test suite
2. `integration-tests`: Test with PostgreSQL & Redis
3. `security-tests`: Audit & clippy checks
4. `code-coverage`: Generate & upload coverage
5. `compatibility`: Test Rust stable/beta/nightly
6. `performance-regression`: Detect performance drops

### `.github/workflows/security.yml`

**Triggers:** Push, Pull Request, Schedule (daily 2 AM)

**Jobs:**
1. `dependency-check`: cargo-audit, outdated
2. `trivy-scan`: Container vulnerability scanning
3. `semgrep-scan`: SAST security analysis
4. `codeql`: CodeQL database analysis

### `.github/workflows/release.yml`

**Triggers:** Tag push (v*)

**Jobs:**
1. `test-before-release`: Full test suite
2. `build-release`: Multi-platform builds (Linux, macOS x2, Windows)
3. `create-release`: GitHub release with artifacts
4. `publish-crates`: Publish to crates.io

### `.github/workflows/web.yml`

**Triggers:** Changes in `web/` directory

**Jobs:**
1. `lint`: ESLint & TypeScript checks
2. `test`: Jest unit tests with coverage
3. `build`: Production build
4. `e2e`: Playwright E2E tests
5. `accessibility`: WCAG accessibility tests

## Test Configuration

```rust
use venom::testing::TestingConfig;

let config = TestingConfig {
    chaos_testing_enabled: true,
    security_labs_enabled: true,
    integration_tests_enabled: true,
    stress_testing_enabled: true,
    e2e_testing_enabled: true,
    performance_testing_enabled: true,
    security_testing_enabled: true,
    compatibility_testing_enabled: true,
    ci_cd_enabled: true,
    test_timeout_seconds: 300,
    max_concurrent_tests: 10,
    min_code_coverage_percent: 80.0,
};
```

## Test Results & Metrics

### Coverage Goals

- **Line Coverage**: ≥80%
- **Branch Coverage**: ≥75%
- **Function Coverage**: ≥80%

### Performance Benchmarks

| Component | Target | Tolerance |
|-----------|--------|-----------|
| Proxy Latency | <50ms | ±10ms |
| Concurrent Connections | 1000+ | -50 |
| Scanner Throughput | 100 req/sec | ±10 |
| Memory Usage | <100MB | ±10MB |
| CSS Rendering | <200ms | ±50ms |
| API Response Time | <100ms | ±20ms |
| DB Query Time | <50ms | ±10ms |

### Compatibility Matrix

**Browsers:** Chrome, Firefox, Safari, Edge (Latest versions)
**OS:** Windows 10+, macOS 10.15+, Ubuntu 18.04+
**Rust:** 1.70+, Beta, Nightly
**Databases:** PostgreSQL 12+, MySQL 8+
**Node.js:** 16+

## Best Practices

1. **Write Tests First**: Follow TDD principles
2. **Isolated Tests**: Each test should be independent
3. **Clear Names**: Use descriptive test names
4. **Meaningful Assertions**: Test one thing per assertion
5. **Fast Tests**: Unit tests should run in <100ms
6. **Deterministic**: Tests should produce consistent results
7. **No Side Effects**: Clean up test resources
8. **Documentation**: Comment complex test logic

## Troubleshooting

### Common Issues

**Issue: Tests timeout**
```bash
# Increase timeout
RUST_BACKTRACE=1 cargo test --lib -- --test-threads=1
```

**Issue: Database connection refused**
```bash
# Ensure PostgreSQL & Redis are running
docker run -d -p 5432:5432 postgres:15
docker run -d -p 6379:6379 redis:7
```

**Issue: E2E tests fail**
```bash
# Install Playwright
cd web && npx playwright install --with-deps

# Run with debug info
npx playwright test --debug
```

**Issue: Performance regression**
```bash
# Compare with baseline
cargo bench -- --save-baseline main
cargo bench -- --baseline main
```

## References

- [Rust Testing Documentation](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Criterion.rs Benchmarking](https://bheisler.github.io/criterion.rs/book/)
- [Playwright Testing](https://playwright.dev/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [WCAG Accessibility Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
