//! Supply-chain policy: every external action referenced by a workflow must be
//! pinned to an immutable selector — a full 40-character commit SHA for GitHub
//! and reusable actions, or a `sha256:` digest for container actions, job
//! containers, and service containers.
//!
//! A mutable ref (`@v4`, `@main`, `@stable`, a container tag, …) lets the
//! upstream owner change the code a pinned name points at; an immutable selector
//! closes that supply-chain hole. Local actions (`uses: ./…`) are exempt because
//! they are versioned by this repository itself.
//!
//! The parser is **fail-closed**: a line that clearly starts as a `uses:` mapping
//! key but cannot be parsed is reported as a violation rather than silently
//! skipped, so a malformed reference can never slip through unvalidated. Text
//! inside a YAML block scalar (`run: |`, `run: >`) is treated as literal script,
//! not as workflow keys. This check reads only tracked files and does no network.

use std::{collections::BTreeSet, error::Error, fs, io, path::Path};

use cargo_metadata::MetadataCommand;

const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
#[cfg(test)]
const RELEASE_AUDIT_RUNNER_PATH: &str = "      - \"scripts/ci/run-cargo-audit.sh\"";
const CANONICAL_FORMAT_GATE: &str = "run: cargo +1.88.0 fmt --all -- --check";
const RELEASE_FORMAT_STEP: &str =
    "      - name: Check formatting\n        run: cargo +1.88.0 fmt --all -- --check";
const METADATA_GATE: &str = "cargo run --locked -p xtask -- release-metadata \"$tag_version\"";
const INITIAL_TAG_TYPE_GATE: &str = "test \"$(git cat-file -t \"$GITHUB_REF\")\" = tag";
const MAIN_ANCESTRY_GATE: &str = "git merge-base --is-ancestor \"$GITHUB_SHA\" origin/main";
const VERSION_EQUALITY_GATE: &str = "test \"$tag_version\" = \"$workspace_version\"";
const RELEASE_BUILD_GATE: &str = "run: cargo build --locked --release --target ${{ matrix.target }} -p termivar-cli --features release-bundle";
const UNIX_SMOKE_VERSION_GATE: &str = "test \"$version_output\" = \"termivar 0.10.0-alpha.2\"";
const WINDOWS_SMOKE_VERSION_GATE: &str = "if ($versionOutput -ne \"termivar 0.10.0-alpha.2\") {";
const UNIX_QUARANTINE_SMOKE_GATE: &str =
    "if grep -Eq '^  (legacy-scan|api|proxy)[[:space:]]' <<<\"$help_output\"; then";
const WINDOWS_QUARANTINE_SMOKE_GATE: &str =
    "if ($helpOutput -match '(?m)^  (legacy-scan|api|proxy)\\s') {";
const RELEASE_SMOKE_OPTIONS: &[&str] = &[
    "--normalization-resilience",
    "--graphql-review",
    "--openapi-review",
    "--rest-review",
    "--authorization-review-policy",
];
const RELEASE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];
const PROVENANCE_GATE: &str =
    "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1";
const UNIX_STAGE_GATE: &str =
    "cp \"target/${{ matrix.target }}/release/${{ matrix.binary }}\" dist/stage/termivar";
const UNIX_ARCHIVE_GATE: &str = "tar -C dist/stage -czf \"dist/termivar-${GITHUB_REF_NAME}-${{ matrix.target }}.tar.gz\" termivar";
const WINDOWS_STAGE_GATE: &str = "Copy-Item \"target/${{ matrix.target }}/release/${{ matrix.binary }}\" \"dist/stage/termivar.exe\"";
const WINDOWS_ARCHIVE_GATE: &str = "Compress-Archive -Path \"dist/stage/termivar.exe\" -DestinationPath \"dist/termivar-$env:GITHUB_REF_NAME-${{ matrix.target }}.zip\"";
const TAG_FETCH_GATE: &str = "git fetch --force --no-tags origin \"refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}\"";
const TAG_TYPE_GATE: &str = "test \"$(git cat-file -t \"refs/tags/${GITHUB_REF_NAME}\")\" = tag";
const TAG_COMMIT_GATE: &str =
    "test \"$(git rev-parse \"refs/tags/${GITHUB_REF_NAME}^{commit}\")\" = \"$(git rev-parse \"${GITHUB_SHA}^{commit}\")\"";
const CHECKSUM_GATE: &str = "sha256sum termivar-* | sort -k2 > ../SHA256SUMS";
const RELEASE_ABSENCE_GATE: &str = "if gh release view \"$GITHUB_REF_NAME\" >/dev/null 2>&1; then";
const RELEASE_NOTES_PATH_GATE: &str = "notes_file=\".github/release-notes/${GITHUB_REF_NAME}.md\"";
const RELEASE_NOTES_FILE_GATE: &str = "test -f \"$notes_file\"";
const RELEASE_NOTES_LINK_GATE: &str = "test ! -L \"$notes_file\"";
const RELEASE_CREATE_GATE: &str = "gh release create \"$GITHUB_REF_NAME\" \\";
const RELEASE_NOTES_FLAG_GATE: &str = "--notes-file \"$notes_file\" \\";
const RELEASE_TITLE_GATE: &str = "--title \"Termivar $GITHUB_REF_NAME\" \\";
const RELEASE_PRERELEASE_GATE: &str = "--prerelease";
const TESTS_WORKFLOW: &str = ".github/workflows/tests.yml";
const SECURITY_WORKFLOW: &str = ".github/workflows/security.yml";
const AUDIT_RUNNER: &str = "scripts/ci/run-cargo-audit.sh";
const DEVELOPMENT_LINE_CHECKOUT: &str = r#"      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          fetch-tags: true
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}"#;
const DEVELOPMENT_LINE_DEFAULTS: &str = r#"    defaults:
      run:
        shell: bash
        working-directory: ."#;
const DEVELOPMENT_LINE_GATE: &str = r#"      - name: Verify post-release development-line provenance
        run: cargo run --locked -p xtask -- development-line"#;
const ARCHITECTURE_GATE: &str = r#"      - name: Verify workspace and reasoning boundaries
        run: cargo run --locked -p xtask -- architecture"#;
const EXPECTED_ARCHITECTURE_JOB: &str = r#"  architecture:
    name: Architecture Boundaries
    runs-on: ubuntu-latest
    defaults:
      run:
        shell: bash
        working-directory: .
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          fetch-tags: true
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable
        with:
          toolchain: stable
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
      - name: Test development-line provenance contract
        run: cargo test --locked -p xtask development_line
      - name: Verify post-release development-line provenance
        run: cargo run --locked -p xtask -- development-line
      - name: Verify workspace and reasoning boundaries
        run: cargo run --locked -p xtask -- architecture
      - name: Test transport-free scanner contracts
        run: cargo test --locked -p termivar-scanner --no-default-features --lib"#;
const EXPECTED_SECURITY_JOB: &str = r#"  security-tests:
    name: Security Tests
    runs-on: ubuntu-latest
    permissions:
      contents: read
    defaults:
      run:
        shell: bash
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable
        with:
          toolchain: stable
          components: clippy
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
      - name: Install canonical Rust 1.88.0 formatter
        run: rustup toolchain install 1.88.0 --profile minimal --component rustfmt --no-self-update
      - name: Check canonical formatting
        run: cargo +1.88.0 fmt --all -- --check
      - name: Run pinned RustSec audit
        run: bash scripts/ci/run-cargo-audit.sh
      - name: Run clippy (security lints)
        run: cargo +stable clippy --workspace --all-targets --all-features --locked -- -D warnings"#;
const EXPECTED_DEPENDENCY_POLICY_JOB: &str = r#"  rust-dependencies:
    name: Rust dependency policy
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
    defaults:
      run:
        shell: bash
    steps:
      - name: Check out repository
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false

      - name: Install audit toolchain
        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable
        with:
          toolchain: "1.88.0"

      - name: Run pinned RustSec audit
        run: bash scripts/ci/run-cargo-audit.sh

      - name: Enforce licenses, sources, bans, and advisories
        uses: EmbarkStudios/cargo-deny-action@3c6349835b2b7b196a839186cb8b78e02f7b5f25 # v2.1.1
        with:
          rust-version: '1.88.0'
          command: check
          arguments: --all-features"#;
const EXPECTED_RELEASE_SECURITY_JOB: &str = r#"  release-rust-security:
    name: Release Rust security gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
    defaults:
      run:
        shell: bash
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false

      - name: Install audit toolchain
        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable
        with:
          toolchain: "1.88.0"

      - name: Run pinned RustSec audit
        run: bash scripts/ci/run-cargo-audit.sh

      - name: Enforce licenses, sources, bans, and advisories
        uses: EmbarkStudios/cargo-deny-action@3c6349835b2b7b196a839186cb8b78e02f7b5f25 # v2.1.1
        with:
          rust-version: "1.88.0"
          command: check
          arguments: --all-features"#;
const EXPECTED_AUDIT_RUNNER: &str = r#"#!/usr/bin/env bash
set -euo pipefail

readonly CARGO_AUDIT_VERSION="0.22.2"
readonly CARGO_AUDIT_TOOLCHAIN="1.88.0"

workspace_root="$(git rev-parse --show-toplevel)"
cd -- "$workspace_root"

if [[ ! -f Cargo.lock || -L Cargo.lock ]]; then
  echo "Cargo.lock must be a regular, non-symlinked file" >&2
  exit 1
fi
git ls-files --error-unmatch -- Cargo.lock >/dev/null

lock_fingerprint="$(git hash-object -- Cargo.lock)"
tool_root="$(mktemp -d "${TMPDIR:-/tmp}/termivar-cargo-audit.XXXXXX")"
trap 'rm -rf -- "$tool_root"' EXIT

cargo +"$CARGO_AUDIT_TOOLCHAIN" install \
  cargo-audit \
  --version "$CARGO_AUDIT_VERSION" \
  --locked \
  --root "$tool_root" \
  --no-track

audit_bin="$tool_root/bin/cargo-audit"
expected_version="cargo-audit $CARGO_AUDIT_VERSION"
actual_version="$("$audit_bin" --version)"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "installed cargo-audit version did not match the reviewed version" >&2
  exit 1
fi
printf '%s\n' "$actual_version"

audit_home="$tool_root/audit-home"
audit_worktree="$tool_root/audit-worktree"
mkdir -p -- "$audit_home/.cargo" "$audit_worktree"
(
  cd -- "$audit_worktree"
  HOME="$audit_home" \
    CARGO_HOME="$audit_home/.cargo" \
    "$audit_bin" audit --file "$workspace_root/Cargo.lock"
)

if [[ "$(git hash-object -- Cargo.lock)" != "$lock_fingerprint" ]]; then
  echo "cargo-audit modified the committed Cargo.lock" >&2
  exit 1
fi
"#;
const COVERAGE_BASELINE_POINTER: &str = "docs/reports/coverage/accepted-baseline.txt";
const EXPECTED_WORKFLOW_TRIGGERS: &str =
    "on:\n  push:\n    branches: [ main, develop ]\n  pull_request:\n    branches: [ main, develop, 'agent/**' ]";
const EXPECTED_WORKFLOW_ENV: &str = "env:\n  CARGO_TERM_COLOR: always\n  RUST_BACKTRACE: 1";
const EXPECTED_CARGO_CONFIG: &[u8] = b"[alias]\nxtask = \"run --locked -p xtask --\"\n";
const EXPECTED_COVERAGE_JOB: &str = r#"  code-coverage:
    name: Code Coverage
    runs-on: ubuntu-latest
    permissions:
      contents: read
    defaults:
      run:
        shell: bash
        working-directory: .
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable
        with:
          toolchain: "1.88.0"
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
      - name: Test coverage policy checker
        run: python3 -m unittest discover -s scripts/tests -p 'test_coverage_gate.py'
      - name: Install pinned tarpaulin
        run: |
          rustup toolchain install 1.91.0 --profile minimal
          cargo +1.91.0 install cargo-tarpaulin --version 0.37.2 --locked
      - name: Generate coverage
        run: cargo +1.88.0 tarpaulin --locked --workspace --all-features --ignore-tests --ignore-config --engine llvm --out Xml --timeout 300
      - name: Attempt best-effort advisory Codecov upload
        uses: codecov/codecov-action@fb8b3582c8e4def4969c97caa2f19720cb33a72f # v7.0.0
        with:
          files: ./cobertura.xml
          fail_ci_if_error: false
      - name: Calibrate repository coverage policy
        env:
          COVERAGE_BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}
          COVERAGE_HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
        run: python3 scripts/coverage_gate.py --cobertura cobertura.xml --baseline-pointer docs/reports/coverage/accepted-baseline.txt --summary-json coverage-summary.json --summary-markdown coverage-summary.md --calibrate --require-base
      - name: Upload coverage evidence
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: coverage-evidence
          path: |
            cobertura.xml
            coverage-summary.json
            coverage-summary.md
          if-no-files-found: error"#;

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let roots = [
        workspace_root.join(".github").join("workflows"),
        workspace_root.join(".github").join("actions"),
    ];

    let mut files = Vec::new();
    for root in roots {
        if root.is_dir() {
            collect_workflow_files(workspace_root, &root, &mut files)?;
        }
    }
    files.sort();

    let mut violations = workflow_pin_violations(&files);
    violations.extend(release_workflow_policy_violations(&files));
    violations.extend(security_workflow_policy_violations(&files));
    let audit_runner_path = workspace_root.join(AUDIT_RUNNER);
    let audit_runner = match fs::read_to_string(&audit_runner_path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    violations.extend(cargo_audit_policy_violations(
        &files,
        audit_runner.as_deref(),
    ));
    violations.extend(development_line_workflow_policy_violations(&files));
    let baseline_accepted = workspace_root.join(COVERAGE_BASELINE_POINTER).is_file();
    violations.extend(coverage_workflow_policy_violations(
        &files,
        baseline_accepted,
    ));
    violations.extend(coverage_build_input_policy_violations(workspace_root)?);
    Ok(violations)
}

fn development_line_workflow_policy_violations(files: &[(String, String)]) -> Vec<String> {
    let Some((_, contents)) = files.iter().find(|(path, _)| path == TESTS_WORKFLOW) else {
        return vec![format!(
            "{TESTS_WORKFLOW}: reviewed development-line workflow is missing"
        )];
    };
    let normalized = contents.replace("\r\n", "\n");
    let jobs = named_job_blocks(&normalized, "architecture");
    let valid = jobs.len() == 1
        && jobs[0] == EXPECTED_ARCHITECTURE_JOB
        && jobs[0].contains(DEVELOPMENT_LINE_DEFAULTS)
        && jobs[0].contains(DEVELOPMENT_LINE_CHECKOUT)
        && jobs[0].contains(DEVELOPMENT_LINE_GATE)
        && jobs[0].contains(ARCHITECTURE_GATE)
        && jobs[0]
            .find(DEVELOPMENT_LINE_GATE)
            .zip(jobs[0].find(ARCHITECTURE_GATE))
            .is_some_and(|(development, architecture)| development < architecture)
        && !jobs[0]
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("continue-on-error:"));
    if valid {
        Vec::new()
    } else {
        vec![format!(
            "{TESTS_WORKFLOW}: `Architecture Boundaries` must match the reviewed exact-head contract, fetch complete tag history, and run the unsuppressed development-line gate before architecture validation"
        )]
    }
}

fn security_workflow_policy_violations(files: &[(String, String)]) -> Vec<String> {
    let Some((_, contents)) = files.iter().find(|(path, _)| path == TESTS_WORKFLOW) else {
        return vec![format!(
            "{TESTS_WORKFLOW}: reviewed Security Tests workflow is missing"
        )];
    };
    let normalized = contents.replace("\r\n", "\n");
    let jobs = named_job_blocks(&normalized, "security-tests");
    if jobs.len() != 1 || jobs[0] != EXPECTED_SECURITY_JOB {
        return vec![format!(
            "{TESTS_WORKFLOW}: `Security Tests` must match the reviewed contract exactly; it installs canonical Rust 1.88.0 rustfmt, calls the pinned shared RustSec runner, checks the whole workspace without suppression, and retains current-stable Clippy with `-D warnings`"
        )];
    }
    Vec::new()
}

fn cargo_audit_policy_violations(
    files: &[(String, String)],
    audit_runner: Option<&str>,
) -> Vec<String> {
    let mut violations = Vec::new();

    for (workflow, job_id, expected, description) in [
        (
            SECURITY_WORKFLOW,
            "rust-dependencies",
            EXPECTED_DEPENDENCY_POLICY_JOB,
            "Rust dependency policy",
        ),
        (
            RELEASE_WORKFLOW,
            "release-rust-security",
            EXPECTED_RELEASE_SECURITY_JOB,
            "Release Rust security gate",
        ),
    ] {
        let jobs = files
            .iter()
            .find(|(path, _)| path == workflow)
            .map(|(_, contents)| contents.replace("\r\n", "\n"))
            .map_or_else(Vec::new, |contents| named_job_blocks(&contents, job_id));
        if jobs.len() != 1 || jobs[0] != expected {
            violations.push(format!(
                "{workflow}: `{description}` must use the reviewed pinned RustSec runner and retain the exact cargo-deny policy"
            ));
        }
    }

    let runner_is_reviewed = audit_runner
        .map(|contents| contents.replace("\r\n", "\n"))
        .is_some_and(|contents| contents == EXPECTED_AUDIT_RUNNER);
    if !runner_is_reviewed {
        violations.push(format!(
            "{AUDIT_RUNNER}: cargo-audit must be installed as exact version 0.22.2 with Rust 1.88.0 and its packaged lockfile, version-checked, and run without advisory suppression"
        ));
    }

    for (path, contents) in files {
        if workflow_has_forbidden_audit_execution(contents) {
            violations.push(format!(
                "{path}: workflows must delegate RustSec auditing only to `{AUDIT_RUNNER}`"
            ));
        }
    }

    violations
}

fn workflow_has_forbidden_audit_execution(contents: &str) -> bool {
    let normalized = contents.replace("\r\n", "\n").replace("\\\n", " ");
    let lines: Vec<_> = normalized.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if matches!(
            parse_uses_line(line),
            UsesLine::Reference(reference)
                if reference
                    .get(.."rustsec/audit-check@".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("rustsec/audit-check@"))
        ) {
            return true;
        }
        if !is_mapping_key(line, "run") {
            index += 1;
            continue;
        }

        let mut script = line
            .split_once(':')
            .map_or("", |(_, value)| value)
            .trim()
            .to_owned();
        if opens_block_scalar(line) {
            script.clear();
            let open_indent = leading_whitespace(line);
            index += 1;
            while index < lines.len()
                && (lines[index].trim().is_empty()
                    || leading_whitespace(lines[index]) > open_indent)
            {
                script.push_str(" ; ");
                script.push_str(lines[index].trim());
                index += 1;
            }
        } else {
            index += 1;
        }
        if shell_invokes_cargo_audit(&script) {
            return true;
        }
    }
    false
}

fn shell_invokes_cargo_audit(script: &str) -> bool {
    let separated = script
        .replace("&&", " && ")
        .replace("||", " || ")
        .replace(';', " ; ")
        .replace('|', " | ");
    let tokens: Vec<_> = separated
        .split_ascii_whitespace()
        .map(|token| token.trim_matches(|character| "\"'()".contains(character)))
        .collect();
    let mut command_position = true;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if matches!(token, ";" | "&&" | "||" | "|") {
            command_position = true;
            index += 1;
            continue;
        }
        if !command_position {
            index += 1;
            continue;
        }
        if token.contains('=')
            || matches!(
                token,
                "!" | "command" | "do" | "elif" | "env" | "if" | "then" | "until" | "while"
            )
        {
            index += 1;
            continue;
        }
        if token == "cargo-audit" || token.ends_with("/cargo-audit") {
            return true;
        }
        if token == "cargo" {
            let mut command = index + 1;
            if tokens
                .get(command)
                .is_some_and(|token| token.starts_with('+'))
            {
                command += 1;
            }
            if tokens.get(command) == Some(&"audit") {
                return true;
            }
            let command_end = tokens[command..]
                .iter()
                .position(|token| matches!(*token, ";" | "&&" | "||" | "|"))
                .map_or(tokens.len(), |offset| command + offset);
            let command = &tokens[command..command_end];
            if command.contains(&"install")
                && command
                    .iter()
                    .any(|token| *token == "cargo-audit" || token.starts_with("cargo-audit@"))
            {
                return true;
            }
        }
        command_position = false;
        index += 1;
    }
    false
}

fn named_job_blocks(contents: &str, job_id: &str) -> Vec<String> {
    let lines: Vec<_> = contents.lines().collect();
    let Some((jobs_start, jobs_end)) = top_level_block_bounds(&lines, "jobs") else {
        return Vec::new();
    };
    let marker = format!("  {job_id}:");
    let mut blocks = Vec::new();
    for start in (jobs_start + 1..jobs_end).filter(|index| lines[*index] == marker) {
        let end = (start + 1..jobs_end)
            .find(|index| {
                let line = lines[*index];
                line.starts_with("  ") && !line.starts_with("    ") && line.ends_with(':')
            })
            .unwrap_or(jobs_end);
        blocks.push(
            lines[start..end]
                .join("\n")
                .trim_end_matches('\n')
                .to_owned(),
        );
    }
    blocks
}

fn expected_coverage_job(baseline_accepted: bool) -> String {
    if baseline_accepted {
        EXPECTED_COVERAGE_JOB
            .replace(
                "      - name: Calibrate repository coverage policy",
                "      - name: Enforce repository coverage policy",
            )
            .replace(" --calibrate --require-base", " --require-base")
    } else {
        EXPECTED_COVERAGE_JOB.to_owned()
    }
}

fn coverage_workflow_policy_violations(
    files: &[(String, String)],
    baseline_accepted: bool,
) -> Vec<String> {
    let Some((_, contents)) = files.iter().find(|(path, _)| path == TESTS_WORKFLOW) else {
        return vec![format!(
            "{TESTS_WORKFLOW}: reviewed coverage workflow is missing"
        )];
    };
    let normalized = contents.replace("\r\n", "\n");
    let mut violations = Vec::new();
    if !has_exact_top_level_block(&normalized, "on", EXPECTED_WORKFLOW_TRIGGERS) {
        violations.push(format!(
            "{TESTS_WORKFLOW}: top-level triggers must equal the reviewed push and main/develop/agent stacked pull-request branch block exactly"
        ));
    }
    if !has_exact_top_level_block(&normalized, "env", EXPECTED_WORKFLOW_ENV) {
        violations.push(format!(
            "{TESTS_WORKFLOW}: top-level env must equal the reviewed coverage-safe block exactly"
        ));
    }
    let lines: Vec<_> = normalized.lines().collect();
    let Some((jobs_start, jobs_end)) = top_level_block_bounds(&lines, "jobs") else {
        violations.push(format!(
            "{TESTS_WORKFLOW}: expected exactly one canonical top-level `jobs:` block"
        ));
        return violations;
    };
    let jobs = lines[jobs_start + 1..jobs_end].join("\n") + "\n";
    let markers: Vec<_> = jobs.match_indices("  code-coverage:\n").collect();
    if markers.len() != 1 {
        violations.push(format!(
            "{TESTS_WORKFLOW}: expected exactly one reviewed `code-coverage` job"
        ));
        return violations;
    }
    let start = markers[0].0;
    let suffix = &jobs[start..];
    let end = suffix
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            let line = suffix[offset + 1..]
                .split_once('\n')
                .map_or(&suffix[offset + 1..], |(line, _)| line);
            (line.starts_with("  ") && !line.starts_with("    ") && line.ends_with(':'))
                .then_some(offset)
        })
        .unwrap_or(suffix.len());
    let actual = suffix[..end].trim_end_matches('\n');
    if actual != expected_coverage_job(baseline_accepted) {
        let mode = if baseline_accepted {
            "enforcement"
        } else {
            "calibration"
        };
        violations.push(format!(
            "{TESTS_WORKFLOW}: `code-coverage` must match the reviewed {mode} contract exactly; it pins measurement Rust 1.88.0 with llvm-tools-preview, installer Rust 1.91.0, cargo-tarpaulin 0.37.2, and the LLVM backend, fetches full history, tests and runs the fail-closed checker with event base/head SHAs, retains best-effort advisory Codecov upload, and always uploads Cobertura plus both summaries"
        ));
    }
    violations
}

fn top_level_block_bounds(lines: &[&str], expected_key: &str) -> Option<(usize, usize)> {
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            if line.starts_with(' ') || line.starts_with('\t') {
                return None;
            }
            let (key, _) = line.split_once(':')?;
            let key = key.trim();
            let key = key
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
                .or_else(|| {
                    key.strip_prefix('"')
                        .and_then(|value| value.strip_suffix('"'))
                })
                .unwrap_or(key);
            (key == expected_key).then_some(index)
        })
        .collect();
    let [start] = starts.as_slice() else {
        return None;
    };
    if lines[*start] != format!("{expected_key}:") {
        return None;
    }
    let end = lines[*start + 1..]
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t'))
        .map_or(lines.len(), |offset| *start + 1 + offset);
    Some((*start, end))
}

fn has_exact_top_level_block(contents: &str, key: &str, expected: &str) -> bool {
    let lines: Vec<_> = contents.lines().collect();
    let Some((start, end)) = top_level_block_bounds(&lines, key) else {
        return false;
    };
    lines[start..end].join("\n").trim_end_matches('\n') == expected
}

fn cargo_configuration_violations(
    config: Option<&[u8]>,
    legacy_config_exists: bool,
) -> Vec<String> {
    let mut violations = Vec::new();
    if config != Some(EXPECTED_CARGO_CONFIG) {
        violations.push(
            ".cargo/config.toml: coverage requires the exact reviewed alias-only bytes".to_owned(),
        );
    }
    if legacy_config_exists {
        violations
            .push(".cargo/config: legacy workspace-local Cargo config is forbidden".to_owned());
    }
    violations
}

fn custom_build_target_violation(package: &str, target: &str, kinds: &[String]) -> Option<String> {
    kinds.iter().any(|kind| kind == "custom-build").then(|| {
        format!(
            "{package}: workspace custom-build target `{target}` is forbidden because it can alter coverage instrumentation"
        )
    })
}

fn coverage_build_input_policy_violations(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let config_path = workspace_root.join(".cargo").join("config.toml");
    let config = match fs::read(config_path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(Box::new(error)),
    };
    let legacy_exists = workspace_root.join(".cargo").join("config").try_exists()?;
    let mut violations = cargo_configuration_violations(config.as_deref(), legacy_exists);

    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    for package in metadata.workspace_packages() {
        for target in &package.targets {
            if let Some(violation) =
                custom_build_target_violation(&package.name, &target.name, &target.kind)
            {
                violations.push(violation);
            }
        }
    }
    Ok(violations)
}

fn release_workflow_policy_violations(files: &[(String, String)]) -> Vec<String> {
    let Some((_, contents)) = files.iter().find(|(path, _)| path == RELEASE_WORKFLOW) else {
        return vec![format!(
            "{RELEASE_WORKFLOW}: reviewed release workflow is missing"
        )];
    };
    let normalized = contents.replace("\r\n", "\n");
    let lines: Vec<_> = normalized.lines().map(str::trim).collect();
    let mut violations = Vec::new();
    if release_push_paths(&normalized).is_none_or(|paths| {
        paths
            .iter()
            .filter(|path| {
                path.strip_prefix('"')
                    .and_then(|path| path.strip_suffix('"'))
                    == Some(AUDIT_RUNNER)
            })
            .count()
            != 1
    }) {
        violations.push(format!(
            "{RELEASE_WORKFLOW}: release path filters must include the exact audit runner `{AUDIT_RUNNER}`"
        ));
    }
    let release_gate_jobs = named_job_blocks(&normalized, "test-before-release");
    if release_gate_jobs.len() != 1 || !release_gate_jobs[0].contains(RELEASE_FORMAT_STEP) {
        violations.push(format!(
            "{RELEASE_WORKFLOW}: Release gates must run canonical Rust 1.88.0 formatting with `{CANONICAL_FORMAT_GATE}`"
        ));
    }
    if release_gate_jobs.iter().any(|job| {
        job.lines()
            .map(str::trim)
            .any(|line| line.starts_with("continue-on-error:"))
    }) {
        violations.push(format!(
            "{RELEASE_WORKFLOW}: Release gates must not suppress failures with `continue-on-error`"
        ));
    }
    for (required, purpose) in [
        (INITIAL_TAG_TYPE_GATE, "reject lightweight release tags"),
        (
            MAIN_ANCESTRY_GATE,
            "require the tagged commit to descend from main",
        ),
        (
            VERSION_EQUALITY_GATE,
            "bind the tag version to the workspace version",
        ),
        (
            METADATA_GATE,
            "run the exact changelog/support metadata gate",
        ),
    ] {
        if !lines.contains(&required) {
            violations.push(format!(
                "{RELEASE_WORKFLOW}: tag publication must {purpose} with `{required}`"
            ));
        }
    }

    let release_builds: Vec<_> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("run: cargo build") && line.contains("-p termivar-cli"))
        .collect();
    if release_builds != [RELEASE_BUILD_GATE] {
        violations.push(format!(
            "{RELEASE_WORKFLOW}: distributable binaries must use exactly `{RELEASE_BUILD_GATE}` and never `--all-features`; found {release_builds:?}"
        ));
    }

    for (required, purpose) in [
        (
            UNIX_SMOKE_VERSION_GATE,
            "verify the Unix binary identity and version",
        ),
        (
            WINDOWS_SMOKE_VERSION_GATE,
            "verify the Windows binary identity and version",
        ),
        (
            UNIX_QUARANTINE_SMOKE_GATE,
            "reject quarantined commands in Unix help",
        ),
        (
            WINDOWS_QUARANTINE_SMOKE_GATE,
            "reject quarantined commands in Windows help",
        ),
        (PROVENANCE_GATE, "retain build-provenance generation"),
        (UNIX_STAGE_GATE, "stage only the Termivar Unix binary"),
        (
            UNIX_ARCHIVE_GATE,
            "package one Termivar-rooted Unix archive",
        ),
        (WINDOWS_STAGE_GATE, "stage only the Termivar Windows binary"),
        (
            WINDOWS_ARCHIVE_GATE,
            "package one Termivar-rooted Windows archive",
        ),
    ] {
        if !lines.contains(&required) {
            violations.push(format!(
                "{RELEASE_WORKFLOW}: release workflow must {purpose} with `{required}`"
            ));
        }
    }
    for option in RELEASE_SMOKE_OPTIONS {
        let count = lines.iter().filter(|line| line.contains(option)).count();
        if count != 2 {
            violations.push(format!(
                "{RELEASE_WORKFLOW}: `{option}` must be checked once by each native release-binary smoke test, found {count} checks"
            ));
        }
    }

    let declared_targets: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("target: "))
        .collect();
    let actual_target_set: BTreeSet<_> = declared_targets.iter().copied().collect();
    let expected_targets: BTreeSet<_> = RELEASE_TARGETS.iter().copied().collect();
    if declared_targets.len() != RELEASE_TARGETS.len() || actual_target_set != expected_targets {
        violations.push(format!(
            "{RELEASE_WORKFLOW}: release target matrix must remain exactly {expected_targets:?}, found {declared_targets:?}"
        ));
    }

    let mut next_line = 0;
    for (required, purpose) in [
        (TAG_FETCH_GATE, "force-fetch the triggering tag"),
        (TAG_TYPE_GATE, "revalidate the annotated tag object"),
        (
            TAG_COMMIT_GATE,
            "bind the fetched tag to the normalized triggering commit",
        ),
        (CHECKSUM_GATE, "checksum the verified build artifacts"),
        (
            RELEASE_ABSENCE_GATE,
            "refuse to replace an existing release",
        ),
        (
            RELEASE_NOTES_PATH_GATE,
            "bind publication to the triggering tag's curated note",
        ),
        (
            RELEASE_NOTES_FILE_GATE,
            "require the curated note to be a repository file",
        ),
        (
            RELEASE_NOTES_LINK_GATE,
            "reject a symlinked curated release note",
        ),
        (RELEASE_CREATE_GATE, "create the GitHub Release"),
        (
            RELEASE_NOTES_FLAG_GATE,
            "publish the exact curated release body",
        ),
        (
            RELEASE_TITLE_GATE,
            "use the reviewed Termivar release title",
        ),
        (
            RELEASE_PRERELEASE_GATE,
            "publish the release as a prerelease",
        ),
    ] {
        let Some(offset) = lines[next_line..].iter().position(|line| *line == required) else {
            violations.push(format!(
                "{RELEASE_WORKFLOW}: release publication must {purpose} with the exact ordered command `{required}`"
            ));
            break;
        };
        next_line += offset + 1;
    }

    for forbidden in ["--generate-notes", "--latest"] {
        if lines.iter().any(|line| line.contains(forbidden)) {
            violations.push(format!(
                "{RELEASE_WORKFLOW}: release publication must not use `{forbidden}`"
            ));
        }
    }

    violations
}

fn release_push_paths(contents: &str) -> Option<Vec<&str>> {
    let lines: Vec<_> = contents.lines().collect();
    let on_positions: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == "on:").then_some(index))
        .collect();
    let [on_start] = on_positions.as_slice() else {
        return None;
    };
    let on_end = lines[*on_start + 1..]
        .iter()
        .position(|line| !line.trim().is_empty() && leading_whitespace(line) == 0)
        .map_or(lines.len(), |offset| on_start + 1 + offset);
    let push_positions: Vec<_> = (*on_start + 1..on_end)
        .filter(|index| lines[*index] == "  push:")
        .collect();
    let [push_start] = push_positions.as_slice() else {
        return None;
    };
    let push_end = lines[*push_start + 1..on_end]
        .iter()
        .position(|line| !line.trim().is_empty() && leading_whitespace(line) <= 2)
        .map_or(on_end, |offset| push_start + 1 + offset);
    let paths_positions: Vec<_> = (*push_start + 1..push_end)
        .filter(|index| lines[*index] == "    paths:")
        .collect();
    let [paths_start] = paths_positions.as_slice() else {
        return None;
    };
    let paths_end = lines[*paths_start + 1..push_end]
        .iter()
        .position(|line| !line.trim().is_empty() && leading_whitespace(line) <= 4)
        .map_or(push_end, |offset| paths_start + 1 + offset);
    Some(
        lines[*paths_start + 1..paths_end]
            .iter()
            .filter_map(|line| line.strip_prefix("      - "))
            .collect(),
    )
}

fn collect_workflow_files(
    workspace_root: &Path,
    root: &Path,
    files: &mut Vec<(String, String)>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_workflow_files(workspace_root, &path, files)?;
            continue;
        }
        let is_workflow = matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yml") | Some("yaml")
        );
        if !is_workflow {
            continue;
        }
        let relative = path
            .strip_prefix(workspace_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        files.push((relative, fs::read_to_string(&path)?));
    }
    Ok(())
}

/// The classification of a single source line with respect to `uses:` keys.
enum UsesLine<'a> {
    /// Not a `uses:` mapping key (blank, comment, other key, or plain text).
    NotUses,
    /// A `uses:` key whose value parsed to this reference token.
    Reference(&'a str),
    /// A `uses:` key whose value could not be parsed. Fail-closed: reported.
    Malformed(&'static str),
}

/// Pure, filesystem-free core so the policy is unit-testable: given
/// `(display_path, contents)` pairs, return one violation per unpinned or
/// malformed action reference, with file and 1-based line information.
fn workflow_pin_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (path, contents) in files {
        // Indentation of the key that opened the current YAML block scalar, if any.
        // Lines indented deeper than this are literal scalar content, not keys.
        let mut block_scalar_indent: Option<usize> = None;

        for (index, line) in contents.lines().enumerate() {
            let line_number = index + 1;
            let indent = leading_whitespace(line);

            if let Some(open_indent) = block_scalar_indent {
                // Blank lines and deeper-indented lines are scalar body: skip.
                if line.trim().is_empty() || indent > open_indent {
                    continue;
                }
                // Dedent: the block scalar ended; fall through to process this line.
                block_scalar_indent = None;
            }

            let unsupported_key_syntax = if is_quoted_mapping_key(line) {
                violations.push(format!(
                    "{path}:{line_number}: quoted YAML mapping keys are forbidden in workflow policy files"
                ));
                true
            } else if uses_yaml_key_indirection(line) {
                violations.push(format!(
                    "{path}:{line_number}: YAML explicit, tagged, anchored, or aliased keys/values are forbidden in workflow policy files"
                ));
                true
            } else if contains_flow_mapping(line) {
                violations.push(format!(
                    "{path}:{line_number}: YAML flow mappings are forbidden in workflow policy files"
                ));
                true
            } else {
                false
            };

            // A `key: |` / `key: >` line opens a block scalar; its body follows.
            if opens_block_scalar(line) {
                for key in ["uses", "image", "container"] {
                    if is_mapping_key(line, key) {
                        violations.push(format!(
                            "{path}:{line_number}: `{key}:` references must use a plain scalar, not a block scalar"
                        ));
                    }
                }
                block_scalar_indent = Some(indent);
                continue;
            }
            if unsupported_key_syntax {
                continue;
            }

            match parse_uses_line(line) {
                UsesLine::NotUses => {},
                UsesLine::Malformed(reason) => violations.push(format!(
                    "{path}:{line_number}: malformed `uses:` reference ({reason})"
                )),
                UsesLine::Reference(reference) => {
                    if let Some(reason) = reference_violation(reference) {
                        violations.push(format!("{path}:{line_number}: {reason}"));
                    }
                },
            }

            match parse_image_line(line) {
                UsesLine::NotUses => {},
                UsesLine::Malformed(reason) => violations.push(format!(
                    "{path}:{line_number}: malformed container `image:` reference ({reason})"
                )),
                UsesLine::Reference(reference) => {
                    if !is_immutable_image_reference(reference) {
                        violations.push(format!(
                            "{path}:{line_number}: container image `{reference}` is not an immutable digest; \
                             use `image:tag@sha256:<64-lowercase-hex>`"
                        ));
                    }
                },
            }

            match parse_container_line(line) {
                UsesLine::NotUses => {},
                UsesLine::Malformed(reason) => violations.push(format!(
                    "{path}:{line_number}: malformed job `container:` reference ({reason})"
                )),
                UsesLine::Reference(reference) => {
                    if !is_immutable_image_reference(reference) {
                        violations.push(format!(
                            "{path}:{line_number}: job container `{reference}` is not an immutable digest; \
                             use `image:tag@sha256:<64-lowercase-hex>`"
                        ));
                    }
                },
            }
        }
    }
    violations
}

fn leading_whitespace(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Whether `line` is a `key: |` / `key: >` mapping entry that opens a YAML block
/// scalar (optionally with chomping/indentation indicators and a trailing
/// comment). Such a line's body is literal text on the following deeper lines.
fn opens_block_scalar(line: &str) -> bool {
    let Some(colon) = line.find(':') else {
        return false;
    };
    let value = line[colon + 1..].trim();
    let value = value.split('#').next().unwrap_or(value).trim();
    let mut chars = value.chars();
    match chars.next() {
        Some('|') | Some('>') => chars
            .all(|character| character == '-' || character == '+' || character.is_ascii_digit()),
        _ => false,
    }
}

/// Classify a line as a `uses:` key and, if so, extract its reference token.
/// Fail-closed: a recognizable-but-broken `uses:` value yields `Malformed`.
fn parse_uses_line(line: &str) -> UsesLine<'_> {
    parse_reference_line(line, "uses", false)
}

fn parse_image_line(line: &str) -> UsesLine<'_> {
    parse_reference_line(line, "image", false)
}

fn parse_container_line(line: &str) -> UsesLine<'_> {
    parse_reference_line(line, "container", true)
}

fn parse_reference_line<'a>(line: &'a str, key: &str, allow_empty_mapping: bool) -> UsesLine<'a> {
    let trimmed = line.trim_start();
    // Drop an optional YAML list dash (`- uses: …`, `-   uses: …`).
    let trimmed = match trimmed.strip_prefix('-') {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => trimmed,
    };
    // The key must be exactly `uses` followed by optional spaces and a colon.
    let Some(after_key) = trimmed.strip_prefix(key) else {
        return UsesLine::NotUses;
    };
    let Some(value) = after_key.trim_start().strip_prefix(':') else {
        return UsesLine::NotUses;
    };

    let value = value.trim();
    if value.is_empty() {
        return if allow_empty_mapping {
            UsesLine::NotUses
        } else {
            UsesLine::Malformed("empty value")
        };
    }
    if let Some(rest) = value.strip_prefix('"') {
        return parse_quoted_value(rest, '"');
    }
    if let Some(rest) = value.strip_prefix('\'') {
        return parse_quoted_value(rest, '\'');
    }

    // Unquoted scalar: the token runs up to the first whitespace or comment.
    let token = value
        .split(|character: char| character.is_ascii_whitespace() || character == '#')
        .next()
        .unwrap_or("");
    if token.is_empty() {
        UsesLine::Malformed("empty value")
    } else {
        UsesLine::Reference(token)
    }
}

fn is_mapping_key(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    let trimmed = match trimmed.strip_prefix('-') {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => trimmed,
    };
    trimmed
        .strip_prefix(key)
        .is_some_and(|after| after.trim_start().starts_with(':'))
}

fn is_quoted_mapping_key(line: &str) -> bool {
    let trimmed = line.trim_start();
    let trimmed = match trimmed.strip_prefix('-') {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => trimmed,
    };
    let Some(quote @ ('"' | '\'')) = trimmed.chars().next() else {
        return false;
    };
    let rest = &trimmed[quote.len_utf8()..];
    rest.match_indices(quote)
        .any(|(end, _)| rest[end + quote.len_utf8()..].trim_start().starts_with(':'))
}

fn uses_yaml_key_indirection(line: &str) -> bool {
    let trimmed = line.trim_start();
    let trimmed = match trimmed.strip_prefix('-') {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => trimmed,
    };
    if trimmed
        .chars()
        .next()
        .is_some_and(|character| matches!(character, '?' | '!' | '&' | '*'))
    {
        return true;
    }
    trimmed.find(':').is_some_and(|colon| {
        trimmed[colon + 1..]
            .trim_start()
            .chars()
            .next()
            .is_some_and(|character| matches!(character, '!' | '&' | '*'))
    })
}

fn contains_flow_mapping(line: &str) -> bool {
    let trimmed = line.trim_start();
    let trimmed = match trimmed.strip_prefix('-') {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => trimmed,
    };
    if trimmed.starts_with('{') {
        return true;
    }
    trimmed.find(':').is_some_and(|colon| {
        let value = trimmed[colon + 1..].trim_start();
        value.starts_with('{') || (value.starts_with('[') && value.contains('{'))
    })
}

/// Parse the remainder of a quoted `uses:` value (`rest` starts just after the
/// opening quote). Only a trailing comment may follow the closing quote.
fn parse_quoted_value(rest: &str, quote: char) -> UsesLine<'_> {
    let Some(end) = rest.find(quote) else {
        return UsesLine::Malformed("unterminated quoted value");
    };
    let inner = &rest[..end];
    let after = rest[end + quote.len_utf8()..].trim_start();
    if !after.is_empty() && !after.starts_with('#') {
        return UsesLine::Malformed("trailing characters after quoted value");
    }
    if inner.is_empty() {
        return UsesLine::Malformed("empty quoted value");
    }
    UsesLine::Reference(inner)
}

/// Apply the immutable-reference policy to a parsed reference. Returns the
/// violation message (without file/line) if it is not immutably pinned.
fn reference_violation(reference: &str) -> Option<String> {
    // Local composite/reusable actions are versioned by this repository.
    if reference.starts_with("./") {
        return None;
    }
    if reference.starts_with("docker://") {
        return if is_immutable_docker_reference(reference) {
            None
        } else {
            Some(format!(
                "container action `{reference}` is not an immutable digest; \
                 use `docker://image@sha256:<64-lowercase-hex>`"
            ))
        };
    }
    match reference.rsplit_once('@') {
        Some(("", _)) => Some(format!(
            "action `{reference}` has an empty owner/repository before `@`"
        )),
        Some((_, git_ref)) if is_full_commit_sha(git_ref) => None,
        Some((action, git_ref)) => Some(format!(
            "action `{action}` is pinned to `{git_ref}`, not a full 40-character commit SHA"
        )),
        None => Some(format!(
            "action `{reference}` is not pinned to a commit SHA"
        )),
    }
}

fn is_full_commit_sha(git_ref: &str) -> bool {
    git_ref.len() == 40 && git_ref.bytes().all(is_lowercase_hex)
}

fn is_immutable_docker_reference(reference: &str) -> bool {
    let Some(reference) = reference.strip_prefix("docker://") else {
        return false;
    };
    let Some((image, digest)) = reference.rsplit_once("@sha256:") else {
        return false;
    };
    !image.is_empty() && digest.len() == 64 && digest.bytes().all(is_lowercase_hex)
}

fn is_immutable_image_reference(reference: &str) -> bool {
    let Some((image, digest)) = reference.rsplit_once("@sha256:") else {
        return false;
    };
    !image.is_empty() && digest.len() == 64 && digest.bytes().all(is_lowercase_hex)
}

fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "d23441a48e516b6c34aea4fa41551a30e30af803";
    const DOCKER_DIGEST: &str = "0f1bf58a2f0e55ad8f1f3d8f8f1a9c0e58f1f0e0f1f5e2f3c8a0bb1f1e0a2c4d";

    fn violations(contents: &str) -> Vec<String> {
        workflow_pin_violations(&[("wf.yml".to_owned(), contents.to_owned())])
    }

    fn reviewed_release_workflow_fixture() -> String {
        let mut lines = vec![
            RELEASE_FORMAT_STEP.to_owned(),
            INITIAL_TAG_TYPE_GATE.to_owned(),
            MAIN_ANCESTRY_GATE.to_owned(),
            VERSION_EQUALITY_GATE.to_owned(),
            METADATA_GATE.to_owned(),
            RELEASE_BUILD_GATE.to_owned(),
            UNIX_SMOKE_VERSION_GATE.to_owned(),
            WINDOWS_SMOKE_VERSION_GATE.to_owned(),
            UNIX_QUARANTINE_SMOKE_GATE.to_owned(),
            WINDOWS_QUARANTINE_SMOKE_GATE.to_owned(),
        ];
        for option in RELEASE_SMOKE_OPTIONS {
            lines.push(format!("unix smoke {option}"));
            lines.push(format!("windows smoke {option}"));
        }
        for target in RELEASE_TARGETS {
            lines.push(format!("target: {target}"));
        }
        lines.extend([
            PROVENANCE_GATE.to_owned(),
            UNIX_STAGE_GATE.to_owned(),
            UNIX_ARCHIVE_GATE.to_owned(),
            WINDOWS_STAGE_GATE.to_owned(),
            WINDOWS_ARCHIVE_GATE.to_owned(),
            TAG_FETCH_GATE.to_owned(),
            TAG_TYPE_GATE.to_owned(),
            TAG_COMMIT_GATE.to_owned(),
            CHECKSUM_GATE.to_owned(),
            RELEASE_ABSENCE_GATE.to_owned(),
            RELEASE_NOTES_PATH_GATE.to_owned(),
            RELEASE_NOTES_FILE_GATE.to_owned(),
            RELEASE_NOTES_LINK_GATE.to_owned(),
            RELEASE_CREATE_GATE.to_owned(),
            RELEASE_NOTES_FLAG_GATE.to_owned(),
            RELEASE_TITLE_GATE.to_owned(),
            RELEASE_PRERELEASE_GATE.to_owned(),
        ]);
        format!(
            "on:\n  push:\n    paths:\n{RELEASE_AUDIT_RUNNER_PATH}\n\njobs:\n  test-before-release:\n{}\n",
            lines.join("\n")
        )
    }

    fn reviewed_security_workflow_fixture() -> String {
        format!("jobs:\n{EXPECTED_SECURITY_JOB}\n")
    }

    fn reviewed_cargo_audit_workflow_fixtures() -> Vec<(String, String)> {
        vec![
            (
                TESTS_WORKFLOW.to_owned(),
                reviewed_security_workflow_fixture(),
            ),
            (
                SECURITY_WORKFLOW.to_owned(),
                format!("jobs:\n{EXPECTED_DEPENDENCY_POLICY_JOB}\n"),
            ),
            (
                RELEASE_WORKFLOW.to_owned(),
                format!("jobs:\n{EXPECTED_RELEASE_SECURITY_JOB}\n"),
            ),
        ]
    }

    #[test]
    fn repository_release_workflow_matches_the_reviewed_release_contract() {
        let contents = include_str!("../../../.github/workflows/release.yml");
        let violations = release_workflow_policy_violations(&[(
            RELEASE_WORKFLOW.to_owned(),
            contents.to_owned(),
        )]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn repository_security_job_matches_the_reviewed_formatter_and_clippy_contract() {
        let contents = include_str!("../../../.github/workflows/tests.yml");
        let violations = security_workflow_policy_violations(&[(
            TESTS_WORKFLOW.to_owned(),
            contents.to_owned(),
        )]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn repository_cargo_audit_installation_is_pinned_locked_and_shared() {
        let files = vec![
            (
                TESTS_WORKFLOW.to_owned(),
                include_str!("../../../.github/workflows/tests.yml").to_owned(),
            ),
            (
                SECURITY_WORKFLOW.to_owned(),
                include_str!("../../../.github/workflows/security.yml").to_owned(),
            ),
            (
                RELEASE_WORKFLOW.to_owned(),
                include_str!("../../../.github/workflows/release.yml").to_owned(),
            ),
        ];
        let runner = include_str!("../../../scripts/ci/run-cargo-audit.sh");
        let violations = cargo_audit_policy_violations(&files, Some(runner));
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn repository_architecture_job_enforces_the_development_line_with_full_history() {
        let contents = include_str!("../../../.github/workflows/tests.yml");
        let violations = development_line_workflow_policy_violations(&[(
            TESTS_WORKFLOW.to_owned(),
            contents.to_owned(),
        )]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn development_line_workflow_rejects_missing_history_suppression_and_reordering() {
        let path = TESTS_WORKFLOW.to_owned();
        let valid = include_str!("../../../.github/workflows/tests.yml").replace("\r\n", "\n");
        let mutations = [
            valid.replacen(DEVELOPMENT_LINE_DEFAULTS, "", 1),
            valid.replacen("        shell: bash\n", "        shell: bash {0} || true\n", 1),
            valid.replacen("        working-directory: .\n", "        working-directory: elsewhere\n", 1),
            valid.replacen("          fetch-depth: 0\n", "", 1),
            valid.replacen("          fetch-tags: true\n", "", 1),
            valid.replacen(DEVELOPMENT_LINE_GATE, "", 1),
            valid.replacen(
                DEVELOPMENT_LINE_GATE,
                &format!("{DEVELOPMENT_LINE_GATE}\n        continue-on-error: true"),
                1,
            ),
            valid.replacen(
                &format!("{DEVELOPMENT_LINE_GATE}\n{ARCHITECTURE_GATE}"),
                &format!("{ARCHITECTURE_GATE}\n{DEVELOPMENT_LINE_GATE}"),
                1,
            ),
            valid.replacen(
                DEVELOPMENT_LINE_GATE,
                &format!("{DEVELOPMENT_LINE_GATE}\n        if: false"),
                1,
            ),
            valid.replacen(
                DEVELOPMENT_LINE_GATE,
                &format!("{DEVELOPMENT_LINE_GATE}\n        shell: bash {{0}} || true"),
                1,
            ),
            valid.replacen(
                DEVELOPMENT_LINE_GATE,
                &format!(
                    "{DEVELOPMENT_LINE_GATE}\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4"
                ),
                1,
            ),
        ];
        for mutation in mutations {
            assert_ne!(mutation, valid, "mutation fixture must change the workflow");
            let violations =
                development_line_workflow_policy_violations(&[(path.clone(), mutation)]);
            assert_eq!(violations.len(), 1, "{violations:?}");
        }
    }

    #[test]
    fn security_tests_rejects_formatter_and_clippy_contract_mutations() {
        let path = TESTS_WORKFLOW.to_owned();
        let valid = reviewed_security_workflow_fixture();
        assert!(security_workflow_policy_violations(&[(path.clone(), valid.clone())]).is_empty());
        assert_eq!(security_workflow_policy_violations(&[]).len(), 1);
        assert_eq!(
            security_workflow_policy_violations(&[(
                path.clone(),
                "name: Tests\n\njobs:\n  unit:\n    name: Unit Tests\n".to_owned(),
            )])
            .len(),
            1
        );

        let mutations = [
            valid.replacen(
                "      - name: Install canonical Rust 1.88.0 formatter\n        run: rustup toolchain install 1.88.0 --profile minimal --component rustfmt --no-self-update\n",
                "",
                1,
            ),
            valid.replacen("cargo +1.88.0 fmt", "cargo +stable fmt", 1),
            valid.replacen("fmt --all -- --check", "fmt -p xtask -- --check", 1),
            valid.replacen(
                CANONICAL_FORMAT_GATE,
                &format!("{CANONICAL_FORMAT_GATE}\n        continue-on-error: true"),
                1,
            ),
            valid.replacen("name: Security Tests", "name: Security Checks", 1),
            valid.replacen(
                "cargo +stable clippy --workspace --all-targets --all-features --locked -- -D warnings",
                "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
                1,
            ),
        ];
        for mutation in mutations {
            let violations = security_workflow_policy_violations(&[(path.clone(), mutation)]);
            assert_eq!(violations.len(), 1, "{violations:?}");
            assert!(violations[0].contains("Security Tests"), "{violations:?}");
        }
    }

    #[test]
    fn cargo_audit_runner_rejects_mutable_suppressed_or_unverified_tools() {
        let files = reviewed_cargo_audit_workflow_fixtures();
        assert!(cargo_audit_policy_violations(&files, Some(EXPECTED_AUDIT_RUNNER)).is_empty());
        assert!(cargo_audit_policy_violations(
            &files,
            Some(&EXPECTED_AUDIT_RUNNER.replace('\n', "\r\n")),
        )
        .is_empty());
        assert!(!cargo_audit_policy_violations(&files, None).is_empty());

        let mutations = [
            EXPECTED_AUDIT_RUNNER.replacen("0.22.2", "latest", 1),
            EXPECTED_AUDIT_RUNNER.replacen("1.88.0", "stable", 1),
            EXPECTED_AUDIT_RUNNER.replacen("  --version \"$CARGO_AUDIT_VERSION\" \\\n", "", 1),
            EXPECTED_AUDIT_RUNNER.replacen("  --locked \\\n", "", 1),
            EXPECTED_AUDIT_RUNNER.replacen(
                "cargo +\"$CARGO_AUDIT_TOOLCHAIN\" install",
                "cargo install",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                "actual_version=\"$(\"$audit_bin\" --version)\"",
                "actual_version=\"$expected_version\"",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                "\"$audit_bin\" audit --file \"$workspace_root/Cargo.lock\"",
                "\"$audit_bin\" audit --file \"$workspace_root/Cargo.lock\" || true",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                "\"$audit_bin\" audit --file \"$workspace_root/Cargo.lock\"",
                "\"$audit_bin\" audit --ignore RUSTSEC-0000-0000 --file \"$workspace_root/Cargo.lock\"",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                "\"$audit_bin\" audit --file \"$workspace_root/Cargo.lock\"",
                "\"$audit_bin\" audit --no-fetch --file \"$workspace_root/Cargo.lock\"",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                "  HOME=\"$audit_home\" \\\n    CARGO_HOME=\"$audit_home/.cargo\" \\\n",
                "",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                " --file \"$workspace_root/Cargo.lock\"",
                "",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen(
                "  cd -- \"$audit_worktree\"",
                "  cd -- \"$workspace_root\"",
                1,
            ),
            EXPECTED_AUDIT_RUNNER.replacen("set -euo pipefail", "set -u", 1),
        ];
        for mutation in mutations {
            assert_ne!(
                mutation, EXPECTED_AUDIT_RUNNER,
                "mutation must change runner"
            );
            let violations = cargo_audit_policy_violations(&files, Some(&mutation));
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(AUDIT_RUNNER)),
                "{violations:?}"
            );
        }
    }

    #[test]
    fn cargo_audit_execution_scan_rejects_commands_but_not_prose_or_the_runner() {
        for allowed in [
            "# cargo install cargo-audit\n",
            "      - name: Explain cargo-audit policy\n",
            "      - run: bash scripts/ci/run-cargo-audit.sh\n",
            "      - run: echo cargo audit policy\n",
        ] {
            assert!(
                !workflow_has_forbidden_audit_execution(allowed),
                "{allowed}"
            );
        }
        for forbidden in [
            "      - run: cargo install cargo-audit\n",
            "      - run: cargo install --locked cargo-audit\n",
            "      - run: cargo install --version 0.22.2 cargo-audit\n",
            "      - run: cargo install cargo-audit@0.22.2 --locked\n",
            "      - run: cargo +stable install cargo-audit\n",
            "      - run: cargo +stable install --locked cargo-audit\n",
            "      - run: cargo audit\n",
            "      - run: cargo-audit audit\n",
            "      - run: |\n          cargo install \\\n            cargo-audit\n",
            "      - uses: rustsec/audit-check@69366f33c96575abad1ee0dba8212993eecbe998\n",
            "      - uses: RustSec/Audit-Check@69366f33c96575abad1ee0dba8212993eecbe998\n",
        ] {
            assert!(
                workflow_has_forbidden_audit_execution(forbidden),
                "{forbidden}"
            );
        }
    }

    #[test]
    fn cargo_audit_workflows_reject_bypasses_wrapper_reintroduction_and_policy_drift() {
        let files = reviewed_cargo_audit_workflow_fixtures();
        let runner = Some(EXPECTED_AUDIT_RUNNER);
        assert!(cargo_audit_policy_violations(&files, runner).is_empty());

        let mutations = [
            (TESTS_WORKFLOW, "run: cargo install cargo-audit"),
            (SECURITY_WORKFLOW, "run: cargo install cargo-audit"),
            (RELEASE_WORKFLOW, "run: cargo install cargo-audit"),
            (
                SECURITY_WORKFLOW,
                "uses: rustsec/audit-check@69366f33c96575abad1ee0dba8212993eecbe998",
            ),
            (
                SECURITY_WORKFLOW,
                "run: bash scripts/ci/run-cargo-audit.sh || true",
            ),
            (
                SECURITY_WORKFLOW,
                "run: bash scripts/ci/run-cargo-audit.sh\n        continue-on-error: true",
            ),
            (SECURITY_WORKFLOW, "arguments: --licenses"),
            (RELEASE_WORKFLOW, "arguments: --licenses"),
            (SECURITY_WORKFLOW, "shell: bash {0} || true"),
            (RELEASE_WORKFLOW, "shell: bash {0} || true"),
            (SECURITY_WORKFLOW, "persist-credentials: true"),
            (RELEASE_WORKFLOW, "persist-credentials: true"),
        ];
        for (path, replacement) in mutations {
            let mut mutation = files.clone();
            let (_, contents) = mutation
                .iter_mut()
                .find(|(candidate, _)| candidate == path)
                .expect("reviewed workflow fixture");
            let source = if replacement.starts_with("arguments:") {
                "arguments: --all-features"
            } else if replacement.starts_with("shell:") {
                "shell: bash"
            } else if replacement.starts_with("persist-credentials:") {
                "persist-credentials: false"
            } else {
                "run: bash scripts/ci/run-cargo-audit.sh"
            };
            *contents = contents.replacen(source, replacement, 1);
            let original = files
                .iter()
                .find(|(candidate, _)| candidate == path)
                .expect("source workflow fixture")
                .1
                .as_str();
            assert_ne!(contents.as_str(), original, "mutation must change {path}");
            let violations = cargo_audit_policy_violations(&mutation, runner);
            assert!(!violations.is_empty(), "{path}: {replacement}");
        }

        for (path, job) in [
            (SECURITY_WORKFLOW, EXPECTED_DEPENDENCY_POLICY_JOB),
            (RELEASE_WORKFLOW, EXPECTED_RELEASE_SECURITY_JOB),
        ] {
            let missing: Vec<_> = files
                .iter()
                .filter(|(candidate, _)| candidate != path)
                .cloned()
                .collect();
            assert!(!cargo_audit_policy_violations(&missing, runner).is_empty());

            let mut duplicate = files.clone();
            let (_, contents) = duplicate
                .iter_mut()
                .find(|(candidate, _)| candidate == path)
                .expect("reviewed workflow fixture");
            contents.push('\n');
            contents.push_str(job);
            assert!(!cargo_audit_policy_violations(&duplicate, runner).is_empty());
        }

        let hostile_top_level_defaults = files
            .iter()
            .map(|(path, contents)| {
                (
                    path.clone(),
                    format!("defaults:\n  run:\n    shell: bash {{0}} || true\n\n{contents}"),
                )
            })
            .collect::<Vec<_>>();
        assert!(cargo_audit_policy_violations(&hostile_top_level_defaults, runner).is_empty());
    }

    #[test]
    fn release_workflow_requires_the_same_unsuppressed_canonical_formatter() {
        let path = RELEASE_WORKFLOW.to_owned();
        let valid = reviewed_release_workflow_fixture();
        assert!(release_workflow_policy_violations(&[(path.clone(), valid.clone())]).is_empty());

        let ambient = valid.replacen("cargo +1.88.0 fmt", "cargo fmt", 1);
        let violations = release_workflow_policy_violations(&[(path.clone(), ambient)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("canonical Rust 1.88.0"));

        let one_crate = valid.replacen("fmt --all -- --check", "fmt -p xtask -- --check", 1);
        let violations = release_workflow_policy_violations(&[(path.clone(), one_crate)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("canonical Rust 1.88.0"));

        let suppressed = valid.replacen(
            CANONICAL_FORMAT_GATE,
            &format!("{CANONICAL_FORMAT_GATE}\n        continue-on-error: true"),
            1,
        );
        let violations = release_workflow_policy_violations(&[(path, suppressed)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("must not suppress"));

        let misplaced = format!(
            "{}\n  release-docs:\n{}\n",
            valid.replacen(RELEASE_FORMAT_STEP, "", 1),
            RELEASE_FORMAT_STEP
        );
        let violations =
            release_workflow_policy_violations(&[(RELEASE_WORKFLOW.to_owned(), misplaced)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("canonical Rust 1.88.0"));
    }

    #[test]
    fn release_workflow_path_filters_include_the_shared_audit_runner() {
        let path = RELEASE_WORKFLOW.to_owned();
        let valid = reviewed_release_workflow_fixture();
        assert!(release_workflow_policy_violations(&[(path.clone(), valid.clone())]).is_empty());

        let missing_runner = valid.replacen(&format!("{RELEASE_AUDIT_RUNNER_PATH}\n"), "", 1);
        let violations = release_workflow_policy_violations(&[(path, missing_runner)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("release path filters"));

        let relocated_runner = format!(
            "{}\nother:\n  nested:\n{RELEASE_AUDIT_RUNNER_PATH}\n",
            valid.replacen(&format!("{RELEASE_AUDIT_RUNNER_PATH}\n"), "", 1)
        );
        let violations =
            release_workflow_policy_violations(&[(RELEASE_WORKFLOW.to_owned(), relocated_runner)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("release path filters"));
    }

    #[test]
    fn release_workflow_requires_the_tag_metadata_gate() {
        let path = ".github/workflows/release.yml".to_owned();
        let valid = reviewed_release_workflow_fixture();
        assert!(release_workflow_policy_violations(&[(path.clone(), valid.to_owned())]).is_empty());

        for invalid in [
            valid.replacen(METADATA_GATE, &format!("# {METADATA_GATE}"), 1),
            valid.replacen(
                METADATA_GATE,
                &format!("name: document this command: {METADATA_GATE}"),
                1,
            ),
        ] {
            let violations = release_workflow_policy_violations(&[(path.clone(), invalid)]);
            assert_eq!(violations.len(), 1, "{violations:?}");
            assert!(violations[0].contains("changelog/support metadata gate"));
        }
    }

    #[test]
    fn release_workflow_reverifies_tag_identity_before_checksums_and_publication() {
        let path = ".github/workflows/release.yml".to_owned();
        let valid = reviewed_release_workflow_fixture();
        assert!(release_workflow_policy_violations(&[(path.clone(), valid)]).is_empty());

        let valid = reviewed_release_workflow_fixture();
        let missing_commit = valid.replacen(&format!("{TAG_COMMIT_GATE}\n"), "", 1);
        let violations = release_workflow_policy_violations(&[(path.clone(), missing_commit)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0].contains("triggering commit"),
            "{violations:?}"
        );

        let valid = reviewed_release_workflow_fixture();
        let without_create = valid.replacen(&format!("{RELEASE_CREATE_GATE}\n"), "", 1);
        let reordered = format!("{RELEASE_CREATE_GATE}\n{without_create}");
        let violations = release_workflow_policy_violations(&[(path, reordered)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("create the GitHub Release"));
    }

    #[test]
    fn release_workflow_builds_and_smokes_only_the_reviewed_bundle() {
        let path = RELEASE_WORKFLOW.to_owned();
        let valid = reviewed_release_workflow_fixture();
        assert!(release_workflow_policy_violations(&[(path.clone(), valid.clone())]).is_empty());

        let all_features = valid.replacen("--features release-bundle", "--all-features", 1);
        assert!(
            release_workflow_policy_violations(&[(path.clone(), all_features)])
                .iter()
                .any(|violation| violation.contains("never `--all-features`"))
        );

        let missing_smoke = valid.replacen("unix smoke --graphql-review\n", "", 1);
        assert!(
            release_workflow_policy_violations(&[(path.clone(), missing_smoke)])
                .iter()
                .any(|violation| violation.contains("--graphql-review"))
        );

        let missing_target = valid.replacen("target: aarch64-apple-darwin\n", "", 1);
        assert!(
            release_workflow_policy_violations(&[(path, missing_target)])
                .iter()
                .any(|violation| violation.contains("target matrix"))
        );
    }

    #[test]
    fn release_workflow_uses_create_once_curated_prerelease_notes() {
        let path = RELEASE_WORKFLOW.to_owned();
        let valid = reviewed_release_workflow_fixture();
        assert!(release_workflow_policy_violations(&[(path.clone(), valid.clone())]).is_empty());

        let generated = valid.replacen(RELEASE_NOTES_FLAG_GATE, "--generate-notes \\", 1);
        let violations = release_workflow_policy_violations(&[(path.clone(), generated)]);
        assert!(violations
            .iter()
            .any(|violation| violation.contains("curated release body")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must not use `--generate-notes`")));

        let replace_existing = valid.replacen(&format!("{RELEASE_ABSENCE_GATE}\n"), "", 1);
        assert!(
            release_workflow_policy_violations(&[(path.clone(), replace_existing)])
                .iter()
                .any(|violation| violation.contains("refuse to replace"))
        );

        let latest = format!("{valid}\n--latest");
        assert!(release_workflow_policy_violations(&[(path, latest)])
            .iter()
            .any(|violation| violation.contains("must not use `--latest`")));
    }

    fn coverage_violations(contents: &str) -> Vec<String> {
        coverage_workflow_policy_violations(
            &[(TESTS_WORKFLOW.to_owned(), contents.to_owned())],
            false,
        )
    }

    #[test]
    fn coverage_workflow_requires_the_exact_reviewed_calibration_job() {
        let workflow = format!(
            "name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n\n  compatibility:\n    runs-on: ubuntu-latest\n"
        );
        assert!(coverage_violations(&workflow).is_empty());
        assert!(coverage_violations(&workflow.replace('\n', "\r\n")).is_empty());
    }

    #[test]
    fn coverage_workflow_cannot_silently_weaken_measurement_or_enforcement() {
        let workflow = format!(
            "name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n\n  compatibility:\n    runs-on: ubuntu-latest\n"
        );
        let mutations = [
            ("fetch-depth: 0", "fetch-depth: 1", "shallow checkout"),
            (
                "toolchain: \"1.88.0\"",
                "toolchain: stable",
                "mutable Rust selector",
            ),
            (
                "components: llvm-tools-preview",
                "components: rustfmt",
                "missing LLVM coverage tools",
            ),
            (
                "rustup toolchain install 1.91.0 --profile minimal",
                "rustup toolchain install stable",
                "mutable installer Rust selector",
            ),
            (
                "cargo +1.91.0 install cargo-tarpaulin --version 0.37.2 --locked",
                "cargo install cargo-tarpaulin",
                "unpinned Tarpaulin",
            ),
            (
                "cargo +1.88.0 tarpaulin",
                "cargo tarpaulin",
                "implicit measurement Rust selector",
            ),
            (
                "--all-features --ignore-tests",
                "--all-features",
                "changed instrumentation scope",
            ),
            (
                "--ignore-tests --ignore-config",
                "--ignore-tests",
                "configuration fail-open",
            ),
            ("--engine llvm", "--engine ptrace", "unstable coverage backend"),
            ("shell: bash", "shell: ./fake-shell {0}", "inherited shell bypass"),
            (
                "working-directory: .",
                "working-directory: scripts",
                "inherited working-directory bypass",
            ),
            (
                "python3 -m unittest discover -s scripts/tests -p 'test_coverage_gate.py'",
                "echo checker-tests-skipped",
                "skipped checker tests",
            ),
            (
                "COVERAGE_BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}",
                "COVERAGE_BASE_SHA: ''",
                "missing event base",
            ),
            (" --calibrate", "", "disabled calibration contract"),
            (" --require-base", "", "base fail-open"),
            (
                "fail_ci_if_error: false",
                "continue-on-error: true",
                "misplaced advisory behavior",
            ),
            ("if: always()", "if: success()", "lost failure artifact"),
            (
                "coverage-summary.md",
                "coverage-summary.txt",
                "changed evidence bundle",
            ),
        ];
        for (from, to, description) in mutations {
            let mutated = workflow.replacen(from, to, 1);
            assert_ne!(mutated, workflow, "mutation fixture failed: {description}");
            let violations = coverage_violations(&mutated);
            assert_eq!(violations.len(), 1, "{description}: {violations:?}");
            assert!(
                violations[0].contains("reviewed calibration contract"),
                "{description}: {violations:?}"
            );
        }
    }

    #[test]
    fn accepted_pointer_switches_the_exact_job_from_calibration_to_enforcement() {
        let calibration = format!(
            "{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n"
        );
        let enforcement_job = expected_coverage_job(true);
        let enforcement = format!(
            "{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{enforcement_job}\n"
        );
        assert!(coverage_workflow_policy_violations(
            &[(TESTS_WORKFLOW.to_owned(), enforcement.clone())],
            true,
        )
        .is_empty());
        assert_eq!(
            coverage_workflow_policy_violations(&[(TESTS_WORKFLOW.to_owned(), calibration)], true,)
                .len(),
            1
        );
        assert_eq!(coverage_violations(&enforcement).len(), 1);
        assert!(!enforcement_job.contains(" --calibrate"));
        assert!(enforcement_job.contains(" --require-base"));
    }

    #[test]
    fn coverage_workflow_rejects_missing_or_duplicate_jobs() {
        let missing = coverage_workflow_policy_violations(&[], false);
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(missing[0].contains("missing"), "{missing:?}");

        let duplicate = format!(
            "{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n\n{EXPECTED_COVERAGE_JOB}\n"
        );
        let violations = coverage_violations(&duplicate);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("exactly one"), "{violations:?}");
    }

    #[test]
    fn coverage_workflow_rejects_inherited_compiler_environment() {
        let workflow =
            format!("name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n");
        for variable in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
            let mutated = workflow.replacen(
                "  RUST_BACKTRACE: 1",
                &format!("  RUST_BACKTRACE: 1\n  {variable}: --cfg hidden"),
                1,
            );
            let violations = coverage_violations(&mutated);
            assert_eq!(violations.len(), 1, "{variable}: {violations:?}");
            assert!(violations[0].contains("top-level env"), "{violations:?}");
        }
        let duplicate = format!("{workflow}\n'env':\n  RUSTFLAGS: --cfg hidden\n");
        let violations = coverage_violations(&duplicate);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("top-level env"), "{violations:?}");
    }

    #[test]
    fn coverage_workflow_rejects_trigger_suppression() {
        let workflow = format!(
            "name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n"
        );
        let mutations = [
            workflow.replacen(
                "    branches: [ main, develop ]",
                "    branches: [ main, develop ]\n    paths-ignore: [ '**.rs' ]",
                1,
            ),
            workflow.replace(
                "    branches: [ main, develop, 'agent/**' ]",
                "    branches: [ main, develop ]",
            ),
            workflow.replace(EXPECTED_WORKFLOW_TRIGGERS, "on: workflow_dispatch"),
            workflow.replace(
                EXPECTED_WORKFLOW_TRIGGERS,
                &format!("{EXPECTED_WORKFLOW_TRIGGERS}\n\n'on': workflow_dispatch"),
            ),
        ];
        for mutated in mutations {
            let violations = coverage_violations(&mutated);
            assert_eq!(violations.len(), 1, "{violations:?}");
            assert!(
                violations[0].contains("top-level triggers"),
                "{violations:?}"
            );
        }
    }

    #[test]
    fn coverage_job_must_be_under_one_canonical_jobs_key() {
        let workflow = format!(
            "name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n"
        );
        let duplicate = format!("{workflow}\n'jobs':\n  decoy:\n    runs-on: ubuntu-latest\n");
        let violations = coverage_violations(&duplicate);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0].contains("top-level `jobs:`"),
            "{violations:?}"
        );

        let misplaced = format!(
            "name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\ndecoy:\n{EXPECTED_COVERAGE_JOB}\n\njobs:\n  compatibility:\n    runs-on: ubuntu-latest\n"
        );
        let violations = coverage_violations(&misplaced);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0].contains("exactly one reviewed"),
            "{violations:?}"
        );
    }

    #[test]
    fn coverage_job_defaults_override_untrusted_workflow_run_defaults() {
        let workflow = format!(
            "name: Tests\n\n{EXPECTED_WORKFLOW_TRIGGERS}\n\n{EXPECTED_WORKFLOW_ENV}\n\ndefaults:\n  run:\n    shell: ./scripts/fake-shell {{0}}\n    working-directory: elsewhere\n\njobs:\n{EXPECTED_COVERAGE_JOB}\n"
        );
        assert!(coverage_violations(&workflow).is_empty());
    }

    #[test]
    fn coverage_cargo_configuration_and_custom_build_targets_are_closed() {
        assert!(cargo_configuration_violations(Some(EXPECTED_CARGO_CONFIG), false).is_empty());
        assert_eq!(
            cargo_configuration_violations(
                Some(b"[build]\nrustflags = ['--cfg', 'hidden']\n"),
                false
            )
            .len(),
            1
        );
        assert_eq!(
            cargo_configuration_violations(Some(EXPECTED_CARGO_CONFIG), true).len(),
            1
        );

        let ordinary = vec!["lib".to_owned()];
        assert!(custom_build_target_violation("demo", "demo", &ordinary).is_none());
        let custom = vec!["custom-build".to_owned()];
        let violation = custom_build_target_violation("demo", "custom", &custom)
            .expect("custom build must be rejected");
        assert!(violation.contains("custom-build"), "{violation}");
    }

    // --- accepted forms ------------------------------------------------------

    #[test]
    fn a_full_sha_pin_is_accepted() {
        let contents = format!("    steps:\n      - uses: actions/checkout@{SHA} # v6\n");
        assert!(violations(&contents).is_empty());
    }

    #[test]
    fn nested_action_path_with_sha_is_accepted() {
        let contents = format!("        uses: github/codeql-action/init@{SHA} # v4\n");
        assert!(violations(&contents).is_empty());
    }

    #[test]
    fn reusable_workflow_with_full_sha_is_accepted() {
        let contents = format!(
            "    uses: owner/termivar/.github/workflows/reusable.yml@{SHA} # reusable workflow\n"
        );
        assert!(violations(&contents).is_empty());
    }

    #[test]
    fn local_actions_are_exempt() {
        assert!(violations("      - uses: ./.github/actions/setup\n").is_empty());
    }

    #[test]
    fn uses_with_multiple_spaces_after_dash_is_recognized() {
        let contents = format!("    -   uses: actions/checkout@{SHA}\n");
        assert!(violations(&contents).is_empty());
    }

    #[test]
    fn uses_with_space_around_colon_is_recognized() {
        let contents = format!("      uses : actions/checkout@{SHA}\n");
        assert!(violations(&contents).is_empty());
    }

    #[test]
    fn a_quoted_reference_followed_by_a_comment_is_accepted() {
        let contents = format!("      - uses: \"actions/checkout@{SHA}\" # v6\n");
        assert!(violations(&contents).is_empty());
        let single = format!("      - uses: 'actions/checkout@{SHA}' # v6\n");
        assert!(violations(&single).is_empty());
    }

    // --- mutable / unpinned references --------------------------------------

    #[test]
    fn a_mutable_tag_is_rejected_with_location() {
        let out = violations("      - uses: actions/checkout@v4\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("wf.yml:1:"));
        assert!(out[0].contains("actions/checkout"));
        assert!(out[0].contains("not a full 40-character commit SHA"));
    }

    #[test]
    fn a_branch_ref_is_rejected() {
        assert_eq!(violations("      - uses: some/action@main\n").len(), 1);
        assert_eq!(
            violations("      - uses: dtolnay/rust-toolchain@stable\n").len(),
            1
        );
    }

    #[test]
    fn a_reference_without_a_ref_is_rejected() {
        let out = violations("      - uses: actions/checkout\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("not pinned to a commit SHA"));
    }

    #[test]
    fn a_shortened_or_uppercase_sha_is_rejected() {
        assert_eq!(violations("      - uses: a/b@d23441a\n").len(), 1);
        let upper = SHA.to_uppercase();
        assert_eq!(violations(&format!("      - uses: a/b@{upper}\n")).len(), 1);
    }

    #[test]
    fn an_empty_owner_before_at_is_rejected() {
        let out = violations(&format!("      - uses: @{SHA}\n"));
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("empty owner/repository"));
    }

    // --- fail-closed malformed handling -------------------------------------

    #[test]
    fn an_unterminated_double_quote_is_a_malformed_violation() {
        let out = violations("      - uses: \"actions/checkout@v4\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("wf.yml:1:"));
        assert!(out[0].contains("malformed"));
        assert!(out[0].contains("unterminated"));
    }

    #[test]
    fn an_unterminated_single_quote_is_a_malformed_violation() {
        let out = violations("      - uses: 'actions/checkout@v4\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("malformed"));
    }

    #[test]
    fn an_empty_quoted_value_is_rejected() {
        assert_eq!(violations("      - uses: \"\"\n").len(), 1);
        assert_eq!(violations("      - uses: ''\n").len(), 1);
    }

    #[test]
    fn a_missing_value_is_rejected() {
        let out = violations("      - uses:\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("malformed"));
    }

    #[test]
    fn trailing_garbage_after_a_quoted_reference_is_rejected() {
        let out = violations(&format!("      - uses: \"a/b@{SHA}\" garbage\n"));
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("trailing characters"));
    }

    // --- block scalars are literal text, not keys ---------------------------

    #[test]
    fn uses_inside_a_literal_block_scalar_is_ignored() {
        let contents = "      - run: |\n          uses: this-is-script-text\n          echo done\n";
        assert!(
            violations(contents).is_empty(),
            "{:?}",
            violations(contents)
        );
    }

    #[test]
    fn uses_inside_a_folded_block_scalar_is_ignored() {
        let contents = "      - run: >\n          uses: still-script-text\n";
        assert!(
            violations(contents).is_empty(),
            "{:?}",
            violations(contents)
        );
    }

    #[test]
    fn a_quoted_uses_mention_inside_a_run_script_is_ignored() {
        let contents = "      - run: |\n          echo \"this uses: actions/checkout@v4\"\n";
        assert!(violations(contents).is_empty());
    }

    #[test]
    fn a_real_step_after_a_block_scalar_is_still_validated() {
        let contents = "      - run: |\n          echo hi\n      - uses: actions/checkout@v4\n";
        let out = violations(contents);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("wf.yml:3:"), "{out:?}");
    }

    // --- container (docker) references --------------------------------------

    #[test]
    fn a_docker_digest_reference_is_accepted() {
        let line = format!("      - uses: docker://alpine@sha256:{DOCKER_DIGEST}\n");
        assert!(violations(&line).is_empty());
    }

    #[test]
    fn job_and_service_container_images_require_digests() {
        let pinned =
            format!("    container:\n      image: semgrep/semgrep:1.2.3@sha256:{DOCKER_DIGEST}\n");
        assert!(violations(&pinned).is_empty(), "{:?}", violations(&pinned));

        let mutable = "    services:\n      database:\n        image: postgres:16\n";
        let out = violations(mutable);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("container image `postgres:16`"), "{out:?}");

        let shorthand = format!("    container: rust:1.88@sha256:{DOCKER_DIGEST}\n");
        assert!(
            violations(&shorthand).is_empty(),
            "{:?}",
            violations(&shorthand)
        );
        assert_eq!(violations("    container: rust:latest\n").len(), 1);
    }

    #[test]
    fn block_scalar_and_flow_reference_forms_fail_closed() {
        let block_uses = "      - uses: >-\n          owner/action@v4\n";
        let block_image = "    container:\n      image: |\n        postgres:16\n";
        let flow_uses = "      - { uses: owner/action@v4, name: fixture }\n";
        let flow_image = "      database: { image: postgres:16 }\n";

        for contents in [block_uses, block_image, flow_uses, flow_image] {
            assert_eq!(violations(contents).len(), 1, "{contents:?}");
        }
    }

    #[test]
    fn quoted_explicit_tagged_and_aliased_keys_fail_closed() {
        let quoted = "      - \"uses\": owner/action@v4\n";
        let escaped = "      - \"u\\u0073es\": owner/action@v4\n";
        let explicit = "      - ? uses\n        : owner/action@v4\n";
        let tagged = "      - !!str uses: owner/action@v4\n";
        let anchored = "      - &step uses: owner/action@v4\n";
        let aliased = "      - *step\n";

        for contents in [quoted, escaped, explicit, tagged, anchored, aliased] {
            assert!(!violations(contents).is_empty(), "{contents:?}");
        }
    }

    #[test]
    fn quoted_keys_are_rejected_when_values_reuse_or_change_the_quote_style() {
        let fixtures = [
            "      - \"uses\": \"owner/action@v4\"\n",
            "      - \"uses\": 'owner/action@v4'\n",
            "    \"container\": \"rust:latest\"\n",
            "    'container': \"rust:latest\"\n",
            "        \"image\": 'postgres:16'\n",
            "        'image': 'postgres:16'\n",
        ];

        for contents in fixtures {
            let out = violations(contents);
            assert_eq!(out.len(), 1, "{contents:?}: {out:?}");
            assert!(out[0].contains("quoted YAML mapping keys"), "{out:?}");
        }
    }

    #[test]
    fn a_docker_tag_and_digest_reference_is_accepted() {
        let line = format!("      - uses: docker://registry/image:tag@sha256:{DOCKER_DIGEST}\n");
        assert!(violations(&line).is_empty());
    }

    #[test]
    fn docker_tag_and_latest_references_are_rejected() {
        assert_eq!(violations("      - uses: docker://alpine:3.20\n").len(), 1);
        assert_eq!(
            violations("      - uses: docker://alpine:latest\n").len(),
            1
        );
        assert_eq!(violations("      - uses: docker://alpine@main\n").len(), 1);
    }

    #[test]
    fn a_docker_digest_with_empty_image_is_rejected() {
        let out = violations(&format!("      - uses: docker://@sha256:{DOCKER_DIGEST}\n"));
        assert_eq!(out.len(), 1, "{out:?}");
    }

    #[test]
    fn a_short_or_uppercase_docker_digest_is_rejected() {
        assert_eq!(
            violations("      - uses: docker://alpine@sha256:1234\n").len(),
            1
        );
        let upper = DOCKER_DIGEST.to_uppercase();
        assert_eq!(
            violations(&format!("      - uses: docker://alpine@sha256:{upper}\n")).len(),
            1
        );
    }

    // --- reporting -----------------------------------------------------------

    #[test]
    fn line_numbers_are_one_based_and_accurate() {
        let contents = format!("steps:\n  - uses: a/b@{SHA}\n  - uses: c/d@v1\n");
        let out = violations(&contents);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("wf.yml:3:"), "{out:?}");
    }

    #[test]
    fn an_ordinary_non_uses_line_produces_no_violation() {
        assert!(violations("      - name: Check out the repository\n").is_empty());
        assert!(violations("        with:\n").is_empty());
        assert!(violations("      # uses: actions/checkout@v4 (a comment)\n").is_empty());
    }
}
