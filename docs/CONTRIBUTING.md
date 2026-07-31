# Contributing to VENOM

Thank you for your interest in contributing to Venom v0.9.0-alpha.

---

## Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## Development Setup

### Prerequisites
- Rust 1.70+ (use `rustup`)
- Git
- Docker (optional, for testing)

### Clone & Setup

```bash
# Clone repository
git clone https://github.com/ITherso/venom.git
cd venom

# Create development branch
git checkout -b feature/your-feature

# Build in debug mode (faster compilation)
cargo build

# Run tests
cargo test

# Check code quality
cargo clippy
cargo fmt
```

---

## Code Style

### Rust Conventions

**Naming:**
```rust
// Functions: snake_case
fn scan_for_vulnerabilities() {}

// Types: PascalCase
struct VulnerabilityFinding {}

// Constants: SCREAMING_SNAKE_CASE
const MAX_CONNECTIONS: usize = 100;
```

**Formatting:**
```bash
# Format all code
cargo fmt

# Check formatting without changing
cargo fmt -- --check
```

**Linting:**
```bash
# Check for common mistakes
cargo clippy

# Fix automatically where possible
cargo clippy --fix
```

### Comments

Only add comments for **non-obvious** logic:

```rust
// Good: explains the WHY
let backoff = Duration::from_millis(2_u64.pow(attempt as u32));

// Bad: explains the WHAT (the code already does this)
let x = y + 1; // Add one to y

// Good: explains subtle behavior
// We use Arc<RwLock<>> instead of Mutex<> because this hot path
// has 10:1 read-to-write ratio, making RwLock 3x faster (benchmarked)
let state = Arc::new(RwLock::new(DatabaseState::new()));
```

---

## Making Changes

### 1. Create a Feature Branch

```bash
git checkout -b feature/add-new-detector
# or
git checkout -b fix/sql-injection-false-positive
```

### 2. Make Small, Focused Commits

```bash
git add src/scanner/sql_detector.rs
git commit -m "Add improved SQL injection detection

- Reduce false positives by 15%
- Add support for parameterized CASE statements
- Add 8 new test cases"
```

### 3. Write Tests

Every feature needs tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let detector = SqlInjectionDetector::new();
        let vulnerable = Request {
            url: "/?id=' OR '1'='1".into(),
            ..Default::default()
        };
        
        let result = detector.detect(&vulnerable, &Response::default());
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, Severity::High);
    }
}
```

Run tests with:
```bash
cargo test

# Test a specific module
cargo test scanner

# Test with output
cargo test -- --nocapture
```

### 4. Update Documentation

Add doc comments:

```rust
/// Detects SQL injection vulnerabilities in HTTP requests.
///
/// # Arguments
/// * `request` - HTTP request to analyze
/// * `response` - HTTP response received
///
/// # Returns
/// Option containing Finding if vulnerability detected
///
/// # Example
/// ```
/// let detector = SqlInjectionDetector::new();
/// let finding = detector.detect(&request, &response);
/// ```
pub fn detect(&self, request: &Request, response: &Response) -> Option<Finding> {
    // Implementation
}
```

---

## Pull Request Process

### 1. Create Pull Request

```bash
# Push your branch
git push origin feature/add-new-detector

# Create PR via GitHub CLI
gh pr create --title "Add improved SQL injection detection" \
  --body "$(cat <<EOF
## Summary
- Reduce false positives by 15%
- Add support for new SQL patterns
- Add comprehensive test coverage

## Testing
- [ ] All tests pass: \`cargo test\`
- [ ] Clippy clean: \`cargo clippy\`
- [ ] Formatting correct: \`cargo fmt\`

## Related
Fixes #123
EOF
)"
```

### 2. Checklist for Review

Before submitting:

- [ ] Code compiles without warnings: `cargo build`
- [ ] All tests pass: `cargo test`
- [ ] No clippy warnings: `cargo clippy`
- [ ] Code formatted: `cargo fmt`
- [ ] Commits are descriptive and focused
- [ ] Documentation updated
- [ ] Tests added for new features
- [ ] No unnecessary dependencies added

### 3. Respond to Review

Address feedback:

```bash
# Make changes
# Commit with clear message
git commit -m "Address review feedback

- Refactor error handling per review
- Add additional edge case tests"

# Push updates (don't force push)
git push origin feature/add-new-detector
```

---

## Adding New Features

### Vulnerability Detector

```rust
// src/scanner/custom_detector.rs
pub struct CustomDetector {}

impl CustomDetector {
    pub fn new() -> Self {
        Self {}
    }

    pub fn detect(&self, request: &Request, response: &Response) -> Option<Finding> {
        // Your detection logic
        
        if let Some(evidence) = self.find_evidence(request, response) {
            Some(Finding {
                finding_type: VulnerabilityType::Custom,
                severity: Severity::High,
                evidence,
                ..Default::default()
            })
        } else {
            None
        }
    }

    fn find_evidence(&self, request: &Request, response: &Response) -> Option<String> {
        // Detection implementation
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_vulnerability() {
        // Test your detector
    }
}
```

Then register in `src/scanner/mod.rs`:

```rust
pub mod custom_detector;
pub use custom_detector::CustomDetector;
```

### New Module

1. Create directory: `src/your_module/`
2. Create `src/your_module/mod.rs`
3. Export in `src/lib.rs`
4. Add tests alongside code
5. Document in `/docs/modules/`

---

## Common Issues

### Merge Conflicts

```bash
# Update from main
git fetch origin
git rebase origin/main

# Resolve conflicts in your editor
# Then continue
git add .
git rebase --continue
git push origin feature/your-feature --force-with-lease
```

### Large Files

VENOM avoids large files. If your change adds >1000 lines:
1. Consider splitting into multiple commits
2. Each commit should be reviewable independently
3. Related changes should stay together

### Dependency Conflicts

```bash
# Update dependencies
cargo update

# Check for security issues
cargo audit

# Remove unused dependencies
cargo tree
```

---

## Performance Considerations

### Benchmarking

Before/after performance:

```bash
# Build release with optimizations
cargo build --release

# Run benchmarks
cargo bench

# Compare results
```

### Common Optimizations

- Use `Arc<T>` for shared ownership
- Use `RwLock<T>` for read-heavy workloads
- Batch database writes
- Cache frequently accessed data
- Profile with `cargo flamegraph`

---

## Documentation

### Updating Docs

1. **API Changes:** Update [docs/API.md](API.md)
2. **Architecture:** Update [docs/architecture.md](architecture.md)
3. **New Features:** Add to [docs/GETTING_STARTED.md](GETTING_STARTED.md)
4. **Module Guide:** Create [docs/modules/your_module.md]

### Example Documentation Format

```markdown
## Your Feature Name

### Overview
Brief description of what the feature does.

### Usage
```rust
// Code example
```

### Configuration
Any configuration options needed.

### Performance
Performance characteristics and optimization tips.

### Testing
How to test the feature.
```

---

## Release Process

Only maintainers can cut releases, but here's what happens:

1. Bump version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Tag commit: `git tag vX.Y.Z`
4. Push tag: `git push origin vX.Y.Z`
5. GitHub Actions builds and releases

---

## Getting Help

- **Questions:** Open GitHub discussion
- **Issues:** Report bugs on GitHub issues
- **Slack:** Join our community slack (link in README)
- **Email:** security@venom.dev

---

## Recognition

Contributors are listed in:
- [GitHub contributors](https://github.com/ITherso/venom/graphs/contributors)
- GitHub contributors page
- Release notes

---

## License

By contributing, you agree that your contributions will be licensed under the same MIT license as VENOM.

---

**Thank you for contributing to VENOM! 🐍**
