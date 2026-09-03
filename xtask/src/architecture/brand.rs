//! Current-product identity boundary for the Termivar migration.
//!
//! This deliberately does not assert that the repository contains no `venom`
//! text. Historical salvage, stable wire identifiers, digest domains, migration
//! notes, and the pre-rename repository URL remain valid compatibility data.
//! The gate covers only machine-readable current package, crate-directory,
//! template, and CLI identities.

use std::{error::Error, fs, io, path::Path};

use cargo_metadata::MetadataCommand;

const FORMER_PACKAGES: &[&str] = &[
    "venom-api",
    "venom-artifact",
    "venom-cli",
    "venom-core",
    "venom-examples",
    "venom-exploit",
    "venom-proxy",
    "venom-scanner",
];

const FORMER_CRATE_DIRECTORIES: &[&str] = &[
    "venom-api",
    "venom-artifact",
    "venom-cli",
    "venom-core",
    "venom-exploit",
    "venom-proxy",
    "venom-scanner",
];

const FORMER_TEMPLATES: &[&str] = &["venom-plugin", "venom-scanner"];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let mut violations = Vec::new();

    for package in metadata.workspace_packages() {
        if FORMER_PACKAGES.contains(&package.name.as_str()) {
            violations.push(format!(
                "current workspace package `{}` still uses the former Venom product identity",
                package.name
            ));
        }
        if package.name != "xtask" && !package.name.starts_with("termivar-") {
            violations.push(format!(
                "current first-party workspace package `{}` must use the `termivar-` prefix",
                package.name
            ));
        }
        for dependency in &package.dependencies {
            if FORMER_PACKAGES.contains(&dependency.name.as_str())
                || dependency
                    .rename
                    .as_deref()
                    .is_some_and(|rename| FORMER_PACKAGES.contains(&rename))
            {
                violations.push(format!(
                    "current workspace package `{}` retains former package dependency identity `{}`",
                    package.name,
                    dependency
                        .rename
                        .as_deref()
                        .unwrap_or(dependency.name.as_str())
                ));
            }
        }
        for target in &package.targets {
            if target.name == "venom" {
                violations.push(format!(
                    "current workspace package `{}` still exposes the former `venom` target",
                    package.name
                ));
            }
        }
    }

    violations.extend(forbidden_current_directories(
        &workspace_root.join("crates"),
        FORMER_CRATE_DIRECTORIES,
        "crate",
    )?);
    violations.extend(forbidden_current_directories(
        &workspace_root.join("templates"),
        FORMER_TEMPLATES,
        "template",
    )?);

    let cli = metadata
        .workspace_packages()
        .into_iter()
        .find(|package| package.name == "termivar-cli")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "current Termivar CLI package is missing",
            )
        })?;
    let binary_names = cli
        .targets
        .iter()
        .filter(|target| target.kind.iter().any(|kind| kind == "bin"))
        .map(|target| target.name.as_str())
        .collect::<Vec<_>>();
    if binary_names != ["termivar"] {
        violations.push(format!(
            "termivar-cli must expose exactly one canonical `termivar` binary, found {binary_names:?}"
        ));
    }

    let cli_source = fs::read_to_string(workspace_root.join("crates/termivar-cli/src/main.rs"))?;
    violations.extend(cli_brand_violations(&cli_source));
    let starter_task =
        fs::read_to_string(workspace_root.join(".github/ISSUE_TEMPLATE/starter-task.yml"))?;
    violations.extend(starter_task_brand_violations(&starter_task));
    Ok(violations)
}

fn forbidden_current_directories(
    root: &Path,
    forbidden: &[&str],
    kind: &str,
) -> io::Result<Vec<String>> {
    if !root.is_dir() {
        return Ok(vec![format!(
            "current Termivar {kind} root `{}` is missing",
            root.display()
        )]);
    }
    let mut violations = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if forbidden.contains(&name.as_ref()) {
            violations.push(format!(
                "current {kind} directory `{name}` still uses the former Venom product identity"
            ));
        }
    }
    Ok(violations)
}

fn cli_brand_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !source.contains("#[command(name = \"termivar\", bin_name = \"termivar\")]") {
        violations.push(
            "current CLI must declare canonical Clap name and platform-stable binary name `termivar`"
                .to_owned(),
        );
    }
    if source.contains("#[command(name = \"venom\")]") {
        violations.push("current CLI must not declare the former Clap name `venom`".to_owned());
    }
    violations
}

fn starter_task_brand_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !source.contains("`cargo test -p termivar-core` passes.") {
        violations
            .push("starter task must validate the current `termivar-core` package".to_owned());
    }
    if source.contains("cargo test -p venom-core") {
        violations.push(
            "starter task must not direct contributors to the former `venom-core` package"
                .to_owned(),
        );
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_cli_name_is_exact_without_banning_compatibility_text() {
        assert!(cli_brand_violations(
            "#[command(name = \"termivar\", bin_name = \"termivar\")] // venom.scan-profile/v1 remains stable"
        )
        .is_empty());
        assert_eq!(
            cli_brand_violations("#[command(name = \"venom\")]").len(),
            2
        );
    }

    #[test]
    fn starter_task_uses_only_the_current_package_selector() {
        assert!(
            starter_task_brand_violations("- [ ] `cargo test -p termivar-core` passes.").is_empty()
        );
        assert_eq!(
            starter_task_brand_violations("- [ ] `cargo test -p venom-core` passes.").len(),
            2
        );
    }

    #[test]
    fn former_current_directories_are_rejected_but_other_history_is_out_of_scope() {
        let temporary = tempfile::TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("venom-core")).unwrap();
        fs::create_dir(temporary.path().join("historical-salvage")).unwrap();
        let violations =
            forbidden_current_directories(temporary.path(), FORMER_CRATE_DIRECTORIES, "crate")
                .unwrap();
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("venom-core"));
    }

    #[test]
    fn termivar_current_directories_are_accepted() {
        let temporary = tempfile::TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("termivar-core")).unwrap();
        fs::create_dir(temporary.path().join("termivar-scanner")).unwrap();
        assert!(
            forbidden_current_directories(temporary.path(), FORMER_CRATE_DIRECTORIES, "crate",)
                .unwrap()
                .is_empty()
        );
    }
}
