# VENOM Code Quality Standards

Code quality practices for Venom v0.9.0-alpha.

## Overview

VENOM maintains enterprise-grade code quality through:

- ✅ Rust idioms & best practices
- ✅ Strict linting (Clippy)
- ✅ Automatic formatting (rustfmt)
- ✅ Security scanning (cargo-audit)
- ✅ Dependency management (Dependabot)
- ✅ Software Bill of Materials (SBOM)
- ✅ Continuous integration (GitHub Actions)
- ✅ Code review process

## Rust Style Guide

### Naming Conventions

**Functions:**
```rust
// snake_case for function names
pub fn calculate_hash() {}
pub async fn fetch_data_async() {}
```

**Types & Traits:**
```rust
// PascalCase for types and traits
pub struct UserConfiguration;
pub trait SecurityValidator;
pub enum ErrorType;
```

**Constants:**
```rust
// SCREAMING_SNAKE_CASE for constants
const MAX_CONNECTIONS: u32 = 1000;
const ENCRYPTION_ALGORITHM: &str = "AES-256-GCM";
```

**Modules:**
```rust
// snake_case for module names
mod security;
mod compliance;
```

### Code Organization

**Module Structure:**
```
src/
├─ lib.rs                    # Main library export
├─ main.rs                   # CLI entry point
├─ proxy/
│  ├─ mod.rs                # Module root
│  ├─ interceptor.rs        # Internal module
│  └─ certificate.rs        # Internal module
└─ security/
   ├─ mod.rs                # Module root
   ├─ encryption.rs         # Internal module
   └─ audit.rs              # Internal module
```

**File Organization:**
```rust
// 1. Module documentation
/// This module handles...

// 2. Imports
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// 3. Constants
const MAX_SIZE: usize = 1024;

// 4. Type definitions
pub struct MyStruct {
    field: String,
}

// 5. Trait implementations
impl MyStruct {
    pub fn new() -> Self { }
}

// 6. Tests
#[cfg(test)]
mod tests {
    use super::*;
}
```

### Documentation

**Module Documentation:**
```rust
/// Handles proxy operations including request interception,
/// response modification, and certificate generation.
///
/// # Examples
///
/// ```
/// use venom::proxy::ProxyServer;
/// let server = ProxyServer::new(8080);
/// ```
pub mod proxy;
```

**Function Documentation:**
```rust
/// Encrypts data using AES-256-GCM algorithm.
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt
/// * `key` - The encryption key (256 bits)
///
/// # Returns
///
/// Returns encrypted data or error if encryption fails.
///
/// # Examples
///
/// ```
/// let ciphertext = encrypt_data(b"secret", &key)?;
/// ```
///
/// # Errors
///
/// Returns `EncryptionError` if:
/// - Key is invalid
/// - Data encoding fails
pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
```

**Type Documentation:**
```rust
/// Configuration for security settings.
///
/// This struct controls encryption algorithms, secret rotation,
/// audit logging, and threat detection capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable/disable encryption
    pub encryption_enabled: bool,
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
}
```

## Clippy Linting

### Enabled Lint Rules

```
-D warnings              # Treat all warnings as errors
-D unsafe_code          # Disallow unsafe code (explicit opt-in)
-W missing_docs         # Warn on missing documentation
-W rustdoc::all         # Warn on all rustdoc issues
-W clippy::all          # Enable all clippy lints
```

### Common Clippy Violations to Avoid

**❌ Don't:**
```rust
// Unnecessary clone
let x = value.clone();

// Unnecessary collect
let sum: i32 = vec.iter().collect::<Vec<_>>().iter().sum();

// Long function chains
data
    .iter()
    .filter(|x| x > &5)
    .map(|x| x * 2)
    .filter(|x| x < &20)
    .collect()
```

**✅ Do:**
```rust
// Use references
let x = &value;

// Simpler chains
let sum: i32 = vec.iter().filter(|x| x > &&5).map(|x| x * 2).sum();

// Break into readable steps
let filtered: Vec<_> = data.iter()
    .filter(|x| *x > 5)
    .map(|x| x * 2)
    .collect();
```

## Formatting with rustfmt

### Automatic Formatting

```bash
# Format all files
cargo fmt

# Check without modifying
cargo fmt -- --check

# Format specific file
cargo fmt --bin venom

# Format all workspace packages
cargo fmt --all
```

### Format Configuration

See `rustfmt.toml` for detailed settings:
- Line length: 100 characters
- Tab width: 4 spaces
- Edition: 2021

### Code Formatting Examples

**✅ Correct:**
```rust
pub struct Configuration {
    pub proxy_port: u16,
    pub api_port: u16,
    pub database_url: String,
}

impl Configuration {
    pub fn new(
        proxy_port: u16,
        api_port: u16,
        database_url: String,
    ) -> Self {
        Self {
            proxy_port,
            api_port,
            database_url,
        }
    }
}
```

**❌ Incorrect:**
```rust
pub struct Configuration { proxy_port: u16, api_port: u16, database_url: String }
impl Configuration {pub fn new(proxy_port: u16,api_port: u16,database_url: String)->Self{Self{proxy_port,api_port,database_url}}}
```

## Security Scanning

### cargo-audit

Scans for known security vulnerabilities in dependencies:

```bash
# Scan for vulnerabilities
cargo audit

# Audit with detailed output
cargo audit -D

# Check specific advisory
cargo audit --advisories RUSTSEC-2024-0001
```

**Policy:**
- Critical: Patch within 24 hours
- High: Patch within 1 week
- Medium: Patch within 2 weeks
- Low: Patch in next release

### Dependency Updates

**Dependabot Configuration:**
```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
```

**Manual Update Process:**
```bash
# Check for outdated dependencies
cargo outdated

# Update single dependency
cargo update -p regex

# Update all dependencies
cargo update
```

## Code Review Checklist

Before submitting a PR, verify:

### Correctness
- ✅ Tests pass (`cargo test`)
- ✅ Code compiles (`cargo check`)
- ✅ No clippy warnings (`cargo clippy`)
- ✅ Formatting correct (`cargo fmt --check`)
- ✅ No security issues (`cargo audit`)

### Quality
- ✅ Functions have documentation
- ✅ Types are well-documented
- ✅ Examples included for public APIs
- ✅ Error handling is explicit
- ✅ No code duplication
- ✅ Complexity is reasonable

### Security
- ✅ No `unsafe` blocks (unless unavoidable)
- ✅ Input validation present
- ✅ Error messages don't leak info
- ✅ Secrets not logged
- ✅ Dependencies are secure

### Performance
- ✅ No unnecessary allocations
- ✅ No infinite loops
- ✅ Reasonable time complexity
- ✅ Caching used where appropriate

### Documentation
- ✅ README updated if needed
- ✅ CHANGELOG.md updated
- ✅ Public API documented
- ✅ Examples provided

## SBOM Generation

### Generate Software Bill of Materials

```bash
# Install syft
cargo install syft

# Generate SBOM in JSON format
syft packages . -o json > sbom.json

# Generate SBOM in SPDX format
syft packages . -o spdx-json > sbom-spdx.json

# Generate SBOM in CycloneDX format
syft packages . -o cyclonedx-json > sbom-cyclonedx.json
```

### SBOM Contents

The SBOM includes:
- All dependencies (direct and transitive)
- Version numbers
- License information
- Known vulnerabilities
- Checksums

### SBOM Distribution

Published with each release:
- `venom-1.0.0-sbom.json` (GitHub Releases)
- `venom-1.0.0-sbom-spdx.json` (SPDX format)
- `sbom.json` (Latest version)

## Continuous Integration

### GitHub Actions Pipeline

**Quality Checks (runs on every commit):**

```yaml
- cargo fmt --check        # Format check
- cargo clippy             # Linting
- cargo test               # Tests
- cargo audit              # Security audit
- cargo tarpaulin          # Code coverage
```

**Performance Checks (nightly):**

```yaml
- cargo bench              # Benchmark suite
- cargo bloat              # Binary size analysis
- cargo tree               # Dependency tree
```

### Build Matrix

Tested on:
- Rust: stable, beta, nightly
- OS: Ubuntu, macOS, Windows
- Architecture: x86_64, aarch64

## Performance Standards

### Benchmarks

Run with: `cargo bench`

Target metrics:
- Proxy latency: <50ms (avg)
- Scanner throughput: >100 req/sec
- Memory usage: <100MB
- Cache hit rate: >80%

### Code Complexity

Maximum allowed:
- Function length: 100 lines
- Cyclomatic complexity: 20
- Nested levels: 5

### Test Coverage

Minimum required:
- Overall: 80%
- Critical paths: 95%
- Security code: 100%

## Pre-commit Hooks

Enable automatic checks before commit:

```bash
# Install pre-commit hook
cp .githooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit

# Configure git to use hooks directory
git config core.hooksPath .githooks
```

**Hook checks:**
```bash
cargo fmt --check        # Format
cargo clippy             # Linting
cargo test               # Tests
cargo audit              # Security
```

## References

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Clippy Lint List](https://rust-lang.github.io/rust-clippy/)
- [rustfmt Documentation](https://rust-lang.github.io/rustfmt/)
- [OWASP Secure Coding](https://owasp.org/www-project-secure-coding-practices/)
