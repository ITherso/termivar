//! Repository deployment-truth policy.
//!
//! Venom `0.9.0-alpha` has no supported deployment surface. To stop incomplete,
//! non-deployable infrastructure from silently returning, this fail-closed gate
//! forbids **executable** orchestration manifests (Helm, Terraform, Kubernetes)
//! in active infrastructure directories while the repository's machine-readable
//! deployment status is [`DeploymentStatus::Unsupported`].
//!
//! Design intent is preserved as Markdown (see
//! `docs/experimental/deployment-blueprint.md`), which this gate allows. Raising
//! the status beyond `Unsupported` is a deliberate, reviewed decision (a future
//! ADR), never a side effect of adding a manifest. This check reads only tracked
//! files and performs no network access.

use std::{error::Error, fs, io, path::Path};

/// The repository's current deployment status. Changing this is an explicit
/// policy decision, gated by review.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeploymentStatus {
    /// No supported deployment surface exists; executable manifests are forbidden.
    Unsupported,
    /// A supported deployment surface exists; manifests are governed elsewhere.
    #[allow(dead_code)]
    Supported,
}

const DEPLOYMENT_STATUS: DeploymentStatus = DeploymentStatus::Unsupported;

/// Active deployment directories that would hold executable orchestration source.
const ACTIVE_INFRA_DIRS: &[&str] = &["helm", "terraform", "k8s", "kubernetes"];

/// File extensions treated as executable infrastructure manifests.
const EXECUTABLE_INFRA_EXTENSIONS: &[&str] = &["yaml", "yml", "tf", "tfvars", "tpl"];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut manifests = Vec::new();
    for dir in ACTIVE_INFRA_DIRS {
        let root = workspace_root.join(dir);
        if root.is_dir() {
            collect_executable_manifests(dir, &root, &mut manifests)?;
        }
    }
    manifests.sort();
    Ok(deployment_violations(DEPLOYMENT_STATUS, &manifests))
}

fn collect_executable_manifests(
    top_dir: &str,
    root: &Path,
    manifests: &mut Vec<String>,
) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_executable_manifests(top_dir, &path, manifests)?;
            continue;
        }
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if is_executable_infra_file(name) {
                let relative = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(name);
                // Report as `<top_dir>/…/<file>` for actionable context.
                let display = path
                    .strip_prefix(root)
                    .ok()
                    .and_then(|suffix| suffix.to_str())
                    .map(|suffix| format!("{top_dir}/{}", suffix.replace('\\', "/")))
                    .unwrap_or_else(|| format!("{top_dir}/{relative}"));
                manifests.push(display);
            }
        }
    }
    Ok(())
}

/// Whether `file_name` is an executable infrastructure manifest. Markdown and
/// other documentation are intentionally *not* executable and are allowed.
fn is_executable_infra_file(file_name: &str) -> bool {
    match file_name.rsplit_once('.') {
        Some((_, extension)) => EXECUTABLE_INFRA_EXTENSIONS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension)),
        None => false,
    }
}

/// Pure policy core: while the status is `Unsupported`, every executable
/// infrastructure manifest is a violation. When `Supported`, the policy defers to
/// other governance and reports nothing here.
fn deployment_violations(status: DeploymentStatus, manifests: &[String]) -> Vec<String> {
    if status == DeploymentStatus::Supported {
        return Vec::new();
    }
    manifests
        .iter()
        .map(|path| {
            format!(
                "deployment status is `unsupported`, but executable infrastructure manifest \
                 `{path}` is present; remove it or preserve the design intent as Markdown \
                 (see docs/experimental/deployment-blueprint.md)"
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_infra_extensions_are_recognized() {
        assert!(is_executable_infra_file("values.yaml"));
        assert!(is_executable_infra_file("deployment.yml"));
        assert!(is_executable_infra_file("main.tf"));
        assert!(is_executable_infra_file("prod.tfvars"));
        assert!(is_executable_infra_file("_helpers.tpl"));
        assert!(is_executable_infra_file("Chart.YAML")); // case-insensitive
    }

    #[test]
    fn documentation_files_are_allowed() {
        assert!(!is_executable_infra_file("README.md"));
        assert!(!is_executable_infra_file("blueprint.md"));
        assert!(!is_executable_infra_file("NOTES.txt"));
        assert!(!is_executable_infra_file("Makefile"));
    }

    #[test]
    fn unsupported_status_forbids_executable_manifests() {
        let manifests = vec![
            "helm/values.yaml".to_owned(),
            "terraform/main.tf".to_owned(),
            "k8s/deployment.yaml".to_owned(),
        ];
        let violations = deployment_violations(DeploymentStatus::Unsupported, &manifests);
        assert_eq!(violations.len(), 3, "{violations:?}");
        assert!(violations[0].contains("helm/values.yaml"));
        assert!(violations
            .iter()
            .all(|violation| violation.contains("deployment status is `unsupported`")));
    }

    #[test]
    fn unsupported_status_with_no_manifests_passes() {
        assert!(deployment_violations(DeploymentStatus::Unsupported, &[]).is_empty());
    }

    #[test]
    fn supported_status_defers_and_reports_nothing() {
        let manifests = vec!["helm/values.yaml".to_owned()];
        assert!(deployment_violations(DeploymentStatus::Supported, &manifests).is_empty());
    }

    #[test]
    fn the_repository_currently_declares_unsupported() {
        // Guards against silently flipping the policy without review.
        assert!(DEPLOYMENT_STATUS == DeploymentStatus::Unsupported);
    }
}
