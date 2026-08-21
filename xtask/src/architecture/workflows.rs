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

use std::{error::Error, fs, io, path::Path};

use cargo_metadata::MetadataCommand;

const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const METADATA_GATE: &str = "cargo run --locked -p xtask -- release-metadata \"$tag_version\"";
const TAG_FETCH_GATE: &str = "git fetch --force --no-tags origin \"refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}\"";
const TAG_TYPE_GATE: &str = "test \"$(git cat-file -t \"refs/tags/${GITHUB_REF_NAME}\")\" = tag";
const TAG_COMMIT_GATE: &str =
    "test \"$(git rev-parse \"refs/tags/${GITHUB_REF_NAME}^{commit}\")\" = \"$(git rev-parse \"${GITHUB_SHA}^{commit}\")\"";
const CHECKSUM_GATE: &str = "sha256sum venom-* | sort -k2 > ../SHA256SUMS";
const RELEASE_CREATE_GATE: &str = "gh release create \"$GITHUB_REF_NAME\" \\";
const TESTS_WORKFLOW: &str = ".github/workflows/tests.yml";
const COVERAGE_BASELINE_POINTER: &str = "docs/reports/coverage/accepted-baseline.txt";
const EXPECTED_WORKFLOW_TRIGGERS: &str =
    "on:\n  push:\n    branches: [ main, develop ]\n  pull_request:\n    branches: [ main, develop ]";
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
    let baseline_accepted = workspace_root.join(COVERAGE_BASELINE_POINTER).is_file();
    violations.extend(coverage_workflow_policy_violations(
        &files,
        baseline_accepted,
    ));
    violations.extend(coverage_build_input_policy_violations(workspace_root)?);
    Ok(violations)
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
            "{TESTS_WORKFLOW}: top-level triggers must equal the reviewed push/pull-request branch block exactly"
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
    let lines: Vec<_> = contents.lines().map(str::trim).collect();
    let mut violations = Vec::new();
    if !lines.contains(&METADATA_GATE) {
        violations.push(format!(
            "{RELEASE_WORKFLOW}: tag publication must run the exact changelog/support metadata gate `{METADATA_GATE}`"
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
        (RELEASE_CREATE_GATE, "create the GitHub Release"),
    ] {
        let Some(offset) = lines[next_line..].iter().position(|line| *line == required) else {
            violations.push(format!(
                "{RELEASE_WORKFLOW}: release publication must {purpose} with the exact ordered command `{required}`"
            ));
            break;
        };
        next_line += offset + 1;
    }

    violations
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

    #[test]
    fn release_workflow_requires_the_tag_metadata_gate() {
        let path = ".github/workflows/release.yml".to_owned();
        let publication = [
            TAG_FETCH_GATE,
            TAG_TYPE_GATE,
            TAG_COMMIT_GATE,
            CHECKSUM_GATE,
            RELEASE_CREATE_GATE,
        ]
        .join("\n  ");
        let valid = format!("run: |\n  {METADATA_GATE}\n  {publication}\n");
        assert!(release_workflow_policy_violations(&[(path.clone(), valid.to_owned())]).is_empty());

        for invalid in [
            format!("run: |\n  # {METADATA_GATE}\n  {publication}\n"),
            format!("name: document this command: {METADATA_GATE}\n  {publication}\n"),
        ] {
            let violations = release_workflow_policy_violations(&[(path.clone(), invalid)]);
            assert_eq!(violations.len(), 1, "{violations:?}");
            assert!(violations[0].contains("changelog/support metadata gate"));
        }
    }

    #[test]
    fn release_workflow_reverifies_tag_identity_before_checksums_and_publication() {
        let path = ".github/workflows/release.yml".to_owned();
        let valid = [
            METADATA_GATE,
            TAG_FETCH_GATE,
            TAG_TYPE_GATE,
            TAG_COMMIT_GATE,
            CHECKSUM_GATE,
            RELEASE_CREATE_GATE,
        ]
        .join("\n");
        assert!(release_workflow_policy_violations(&[(path.clone(), valid)]).is_empty());

        let missing_commit = [
            METADATA_GATE,
            TAG_FETCH_GATE,
            TAG_TYPE_GATE,
            CHECKSUM_GATE,
            RELEASE_CREATE_GATE,
        ]
        .join("\n");
        let violations = release_workflow_policy_violations(&[(path.clone(), missing_commit)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0].contains("triggering commit"),
            "{violations:?}"
        );

        let reordered = [
            METADATA_GATE,
            RELEASE_CREATE_GATE,
            TAG_FETCH_GATE,
            TAG_TYPE_GATE,
            TAG_COMMIT_GATE,
            CHECKSUM_GATE,
        ]
        .join("\n");
        let violations = release_workflow_policy_violations(&[(path, reordered)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("create the GitHub Release"));
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
            "    uses: owner/venom/.github/workflows/reusable.yml@{SHA} # reusable workflow\n"
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
