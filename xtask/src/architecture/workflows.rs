//! Supply-chain policy: every external GitHub Action referenced by a workflow
//! must be pinned to a full 40-character commit SHA.
//!
//! A mutable ref (`@v4`, `@main`, `@stable`, …) lets the upstream owner change
//! the code a pinned tag points at. Pinning to an immutable commit SHA closes
//! that supply-chain hole. Local actions (`uses: ./…`) are exempt because they
//! are versioned by this repository itself. This check reads only tracked files
//! and performs no network access.

use std::{error::Error, fs, path::Path};

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let roots = vec![
        workspace_root.join(".github").join("workflows"),
        workspace_root.join(".github").join("actions"),
    ];

    let mut files = Vec::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        files.extend(collect_workflow_files(workspace_root, &root)?);
    }
    files.sort();

    Ok(workflow_pin_violations(&files))
}

fn collect_workflow_files(
    workspace_root: &Path,
    root: &Path,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            files.extend(collect_workflow_files(workspace_root, &path)?);
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

    Ok(files)
}

/// Pure, filesystem-free core so the policy is unit-testable: given
/// `(display_path, contents)` pairs, return one violation per unpinned external
/// action reference, with file and 1-based line information.
fn workflow_pin_violations(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (path, contents) in files {
        for (index, line) in contents.lines().enumerate() {
            let Some(reference) = uses_reference(line) else {
                continue;
            };
            // Local composite/reusable actions are versioned by this repo.
            if reference.starts_with("./") {
                continue;
            }
            // Container actions are addressed separately and are absent here.
            if reference.starts_with("docker://") {
                continue;
            }
            let line_number = index + 1;
            match reference.rsplit_once('@') {
                Some((action, git_ref)) if is_full_commit_sha(git_ref) => {
                    let _ = action;
                },
                Some((action, git_ref)) => violations.push(format!(
                    "{path}:{line_number}: action `{action}` is pinned to `{git_ref}`, \
                     not a full 40-character commit SHA"
                )),
                None => violations.push(format!(
                    "{path}:{line_number}: action `{reference}` is not pinned to a commit SHA"
                )),
            }
        }
    }
    violations
}

/// Extract the action reference from a `uses:` step line, or `None` if the line
/// is not a `uses:` key. Requires `uses:` to sit at the step-key position (after
/// optional list dash) so `uses:` mentioned inside a `run:` script is ignored.
fn uses_reference(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    let rest = trimmed.strip_prefix("uses:")?;
    // The token is everything up to the first whitespace (drops any `# comment`).
    rest.split_whitespace().next()
}

fn is_full_commit_sha(git_ref: &str) -> bool {
    git_ref.len() == 40
        && git_ref
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "d23441a48e516b6c34aea4fa41551a30e30af803";

    fn violations(contents: &str) -> Vec<String> {
        workflow_pin_violations(&[("wf.yml".to_owned(), contents.to_owned())])
    }

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
    fn local_and_container_actions_are_exempt() {
        assert!(violations("      - uses: ./.github/actions/setup\n").is_empty());
        assert!(violations("      - uses: docker://alpine:3.20\n").is_empty());
    }

    #[test]
    fn uses_inside_a_run_script_is_ignored() {
        // A `uses:` mention that is not a step key must not be scanned.
        let contents = "      - run: |\n          echo \"this uses: actions/checkout@v4\"\n";
        assert!(violations(contents).is_empty());
    }

    #[test]
    fn line_numbers_are_one_based_and_accurate() {
        let contents = format!("steps:\n  - uses: a/b@{SHA}\n  - uses: c/d@v1\n",);
        let out = violations(&contents);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("wf.yml:3:"), "{out:?}");
    }
}
