//! Repository deployment-truth policy.
//!
//! The unreleased Termivar `0.10.0-alpha.2` development source line has no supported deployment
//! surface. To stop incomplete,
//! non-deployable infrastructure from silently returning, this fail-closed gate
//! forbids **executable** orchestration manifests (Helm, Terraform, Kubernetes)
//! in active infrastructure directories and Compose manifests at the repository
//! root while the repository's machine-readable deployment status is
//! `unsupported`.
//!
//! Design intent is preserved as Markdown (see
//! `docs/experimental/deployment-blueprint.md`), which this gate allows. Raising
//! the status beyond `Unsupported` is a deliberate, reviewed decision (a future
//! ADR), never a side effect of adding a manifest. This check reads only
//! workspace files and performs no network access.

use std::{collections::BTreeSet, error::Error, fs, io, path::Path};

const DEPLOYMENT_STATUS: &str = "unsupported";

/// Active deployment directories that would hold executable orchestration source.
const ACTIVE_INFRA_DIRS: &[&str] = &["helm", "terraform", "k8s", "kubernetes"];

/// File extensions treated as executable infrastructure manifests.
const EXECUTABLE_INFRA_EXTENSIONS: &[&str] = &["yaml", "yml", "tf", "tfvars", "tpl"];

/// Historical distribution entrypoints that implied an installation or
/// release workflow the repository does not currently support.
const FORBIDDEN_DISTRIBUTION_ARTIFACTS: &[(&str, &str)] = &[
    (
        "install.sh",
        "repository installer must remain absent until a remediated release tag exists",
    ),
    (
        "scripts/build-releases.sh",
        "obsolete alternate release builder must remain absent; .github/workflows/release.yml is the sole reviewed release builder",
    ),
    (
        ".env.example",
        "root .env.example must remain absent while no environment-variable deployment contract exists",
    ),
];

/// Local state and credential-shaped files that must never enter `docker build`
/// context, even when they are untracked.
const REQUIRED_DOCKERIGNORE_PATTERNS: &[&str] = &[
    "/.termivar",
    ".env*",
    "secrets.toml",
    "config.local.toml",
    "*.key",
    "*.pem",
    "*.crt",
    "db.sqlite3",
    "*.db",
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut manifests = Vec::new();
    for entry in fs::read_dir(workspace_root)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.is_file() && is_root_compose_file(file_name) {
            manifests.push(file_name.to_owned());
            continue;
        }
        if path.is_dir() && is_active_infra_dir(file_name) {
            collect_executable_manifests(file_name, &path, &path, &mut manifests)?;
        }
    }
    manifests.sort();
    let mut violations = deployment_violations(&manifests);
    violations.extend(forbidden_distribution_artifact_violations(workspace_root));
    let dockerignore = fs::read_to_string(workspace_root.join(".dockerignore"))?;
    violations.extend(dockerignore_violations(&dockerignore));
    Ok(violations)
}

fn forbidden_distribution_artifact_violations(workspace_root: &Path) -> Vec<String> {
    FORBIDDEN_DISTRIBUTION_ARTIFACTS
        .iter()
        .filter(|(relative_path, _)| workspace_root.join(*relative_path).exists())
        .map(|(_, violation)| (*violation).to_owned())
        .collect()
}

fn collect_executable_manifests(
    top_dir: &str,
    base_root: &Path,
    current_dir: &Path,
    manifests: &mut Vec<String>,
) -> io::Result<()> {
    for entry in fs::read_dir(current_dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_executable_manifests(top_dir, base_root, &path, manifests)?;
            continue;
        }
        let is_manifest = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_executable_infra_file);
        if is_manifest {
            // Report the full path relative to the directory root so nested
            // manifests (e.g. `helm/templates/deployment.yaml`) are named exactly.
            let suffix = path.strip_prefix(base_root).unwrap_or(&path);
            manifests.push(format!(
                "{top_dir}/{}",
                suffix.to_string_lossy().replace('\\', "/")
            ));
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

/// Root Compose manifests are deployment entrypoints even when their names use
/// override/profile suffixes or casing variants.
fn is_root_compose_file(file_name: &str) -> bool {
    let normalized = file_name.to_ascii_lowercase();
    let is_yaml = normalized.ends_with(".yml") || normalized.ends_with(".yaml");
    is_yaml
        && ["compose.", "compose-", "docker-compose.", "docker-compose-"]
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
}

fn is_active_infra_dir(file_name: &str) -> bool {
    ACTIVE_INFRA_DIRS
        .iter()
        .any(|active| active.eq_ignore_ascii_case(file_name))
}

/// Pure policy core: every executable infrastructure manifest is a violation
/// while the repository's distribution status is unsupported.
fn deployment_violations(manifests: &[String]) -> Vec<String> {
    manifests
        .iter()
        .map(|path| {
            format!(
                "deployment status is `{DEPLOYMENT_STATUS}`, but executable infrastructure manifest \
                 `{path}` is present; remove it or preserve the design intent as Markdown \
                 (see docs/experimental/deployment-blueprint.md)"
            )
        })
        .collect()
}

fn dockerignore_violations(source: &str) -> Vec<String> {
    let patterns: BTreeSet<_> = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let mut violations: Vec<_> = patterns
        .iter()
        .filter(|pattern| pattern.starts_with('!'))
        .map(|pattern| {
            format!(
                ".dockerignore negation rule `{pattern}` may re-include sensitive or local state"
            )
        })
        .collect();
    violations.extend(REQUIRED_DOCKERIGNORE_PATTERNS
        .iter()
        .filter(|pattern| !patterns.contains(**pattern))
        .map(|pattern| {
            format!(
                ".dockerignore must exclude sensitive/local-state pattern `{pattern}` from build context"
            )
        })
    );
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn nested_manifest_reports_complete_relative_path() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("helm");
        fs::create_dir_all(base.join("templates")).unwrap();
        fs::write(base.join("templates").join("deployment.yaml"), b"").unwrap();
        fs::write(base.join("values.yaml"), b"").unwrap();

        let mut manifests = Vec::new();
        collect_executable_manifests("helm", &base, &base, &mut manifests).unwrap();
        manifests.sort();

        // The intermediate `templates/` directory must survive in the report.
        assert_eq!(
            manifests,
            vec![
                "helm/templates/deployment.yaml".to_owned(),
                "helm/values.yaml".to_owned(),
            ]
        );
    }

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
            "docker-compose.yml".to_owned(),
            "helm/values.yaml".to_owned(),
            "terraform/main.tf".to_owned(),
            "k8s/deployment.yaml".to_owned(),
        ];
        let violations = deployment_violations(&manifests);
        assert_eq!(violations.len(), 4, "{violations:?}");
        assert!(violations[0].contains("docker-compose.yml"));
        assert!(violations
            .iter()
            .all(|violation| violation.contains("deployment status is `unsupported`")));
    }

    #[test]
    fn unsupported_status_with_no_manifests_passes() {
        assert!(deployment_violations(&[]).is_empty());
    }

    #[test]
    fn retired_distribution_entrypoints_remain_absent() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("scripts")).unwrap();
        for relative_path in ["install.sh", "scripts/build-releases.sh", ".env.example"] {
            fs::write(temp.path().join(relative_path), b"historical fixture\n").unwrap();
        }
        fs::write(
            temp.path().join(".dockerignore"),
            REQUIRED_DOCKERIGNORE_PATTERNS.join("\n"),
        )
        .unwrap();

        let violations = check(temp.path()).unwrap();
        assert_eq!(violations.len(), 3, "{violations:?}");
        assert!(violations
            .iter()
            .any(|violation| violation.contains("installer")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("alternate release builder")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("root .env.example")));
    }

    #[test]
    fn the_repository_currently_declares_unsupported() {
        // Guards against silently flipping the policy without review.
        assert_eq!(DEPLOYMENT_STATUS, "unsupported");
    }

    #[test]
    fn root_compose_names_are_explicitly_gated() {
        for file_name in [
            "compose.yml",
            "compose.yaml",
            "compose.prod.yml",
            "compose-prod.yml",
            "docker-compose.yml",
            "docker-compose.override.yml",
            "docker-compose-prod.yaml",
            "Docker-Compose.CI.YAML",
        ] {
            assert!(is_root_compose_file(file_name), "{file_name}");
        }
        for file_name in [
            "compose.md",
            "docker-compose.txt",
            "my-compose.yml",
            "docker-composeyml",
        ] {
            assert!(!is_root_compose_file(file_name), "{file_name}");
        }
    }

    #[test]
    fn active_infrastructure_directories_are_case_insensitive() {
        for directory in ["helm", "Helm", "TERRAFORM", "K8s", "KUBERNETES"] {
            assert!(is_active_infra_dir(directory), "{directory}");
        }
        for directory in ["helm-notes", "terraform-backup", "k8"] {
            assert!(!is_active_infra_dir(directory), "{directory}");
        }

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("Helm");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("values.yaml"), b"services: {}\n").unwrap();
        fs::write(
            temp.path().join(".dockerignore"),
            REQUIRED_DOCKERIGNORE_PATTERNS.join("\n"),
        )
        .unwrap();

        let violations = check(temp.path()).unwrap();
        assert!(violations
            .iter()
            .any(|violation| violation.contains("Helm/values.yaml")));
    }

    #[test]
    fn docker_build_context_must_exclude_sensitive_local_state() {
        let valid = REQUIRED_DOCKERIGNORE_PATTERNS.join("\n");
        assert!(dockerignore_violations(&valid).is_empty());

        let narrow_environment_files = valid.replace(".env*", ".env\n.env.local");
        assert_eq!(
            dockerignore_violations(&narrow_environment_files),
            vec![
                ".dockerignore must exclude sensitive/local-state pattern `.env*` from build context"
            ]
        );

        let missing_secret = valid.replace("secrets.toml\n", "");
        assert_eq!(
            dockerignore_violations(&missing_secret),
            vec![
                ".dockerignore must exclude sensitive/local-state pattern `secrets.toml` from build context"
            ]
        );

        let reinclude_secret = format!("{valid}\n!.env\n");
        assert_eq!(
            dockerignore_violations(&reinclude_secret),
            vec![".dockerignore negation rule `!.env` may re-include sensitive or local state"]
        );

        let commented_negation = format!("{valid}\n# !.env\n");
        assert!(dockerignore_violations(&commented_negation).is_empty());
    }
}
