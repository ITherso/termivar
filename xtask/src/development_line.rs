//! Post-release source-line provenance validation.
//!
//! Once a workspace version has an immutable Git tag, that version describes
//! exactly the tagged source. Any descendant commit must advance the workspace
//! version before it can pass the required architecture check.

use cargo_metadata::MetadataCommand;
use std::{error::Error, path::Path, process::Command};

const RELEASE_CLI_PACKAGE: &str = "termivar-cli";
const MAX_GIT_OUTPUT_BYTES: usize = 1024;

pub(crate) fn check(workspace_root: &Path) -> Result<(), Box<dyn Error>> {
    let version = workspace_version(workspace_root)?;
    check_repository(workspace_root, &version)?;
    println!("development line passed for {version}");
    Ok(())
}

fn workspace_version(workspace_root: &Path) -> Result<String, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let package = metadata
        .workspace_packages()
        .into_iter()
        .find(|package| package.name.as_str() == RELEASE_CLI_PACKAGE)
        .ok_or("termivar-cli is absent from workspace metadata")?;
    Ok(package.version.to_string())
}

fn check_repository(repository: &Path, version: &str) -> Result<(), Box<dyn Error>> {
    let shallow = git_text(repository, &["rev-parse", "--is-shallow-repository"])?;
    if shallow != "false" {
        return Err("development-line validation requires complete Git history and tags".into());
    }

    let tag = format!("refs/tags/v{version}");
    let tag_status = Command::new("git")
        .args(["show-ref", "--verify", "--quiet", &tag])
        .current_dir(repository)
        .status()?;
    match tag_status.code() {
        Some(0) => {},
        Some(1) => return Ok(()),
        _ => return Err("development-line tag lookup failed".into()),
    }

    let tag_commit = git_text(repository, &["rev-parse", &format!("{tag}^{{commit}}")])?;
    let head_commit = git_text(repository, &["rev-parse", "HEAD^{commit}"])?;
    if tag_commit == head_commit {
        return Ok(());
    }

    let ancestry = Command::new("git")
        .args(["merge-base", "--is-ancestor", &tag_commit, &head_commit])
        .current_dir(repository)
        .status()?;
    if ancestry.success() {
        return Err(format!(
            "workspace version {version} is already tagged at {tag_commit}; advance the development-line version before committing beyond that tag"
        )
        .into());
    }
    if ancestry.code() == Some(1) {
        return Err(format!(
            "workspace version {version} collides with {tag}, which does not identify HEAD or an ancestor of HEAD"
        )
        .into());
    }
    Err("development-line ancestry lookup failed".into())
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()?;
    if !output.status.success() {
        return Err("development-line bounded Git read failed".into());
    }
    if output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
        return Err("development-line bounded Git read exceeded its byte limit".into());
    }
    Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::{check, check_repository, git_text, workspace_version, MAX_GIT_OUTPUT_BYTES};
    use std::{fs, path::Path, process::Command};
    use tempfile::tempdir;

    fn git(repository: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .status()
            .expect("run Git fixture command");
        assert!(
            status.success(),
            "Git fixture command failed: {arguments:?}"
        );
    }

    fn repository() -> tempfile::TempDir {
        let repository = tempdir().expect("temporary Git repository");
        git(repository.path(), &["init", "--quiet"]);
        git(
            repository.path(),
            &[
                "-c",
                "user.name=Termivar Tests",
                "-c",
                "user.email=tests@termivar.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "initial",
            ],
        );
        repository
    }

    #[test]
    fn untagged_development_version_passes() {
        let repository = repository();
        git(repository.path(), &["tag", "v0.9.0-alpha"]);
        assert!(check_repository(repository.path(), "0.10.0-alpha.2").is_ok());
    }

    #[test]
    fn untagged_workspace_passes_the_top_level_gate() {
        let workspace = repository();
        fs::create_dir_all(workspace.path().join("termivar-cli/src"))
            .expect("create fixture package source directory");
        fs::write(
            workspace.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = [\"termivar-cli\"]\n\
             [workspace.package]\nversion = \"0.10.0-alpha.2\"\nedition = \"2021\"\n\
             rust-version = \"1.88\"\n",
        )
        .expect("write fixture workspace manifest");
        fs::write(
            workspace.path().join("termivar-cli/Cargo.toml"),
            "[package]\nname = \"termivar-cli\"\nversion.workspace = true\n\
             edition.workspace = true\nrust-version.workspace = true\n",
        )
        .expect("write fixture package manifest");
        fs::write(
            workspace.path().join("termivar-cli/src/main.rs"),
            "fn main() {}\n",
        )
        .expect("write fixture package source");
        fs::write(
            workspace.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"termivar-cli\"\nversion = \"0.10.0-alpha.2\"\n",
        )
        .expect("write fixture lockfile");
        check(workspace.path()).expect("untagged development line must pass");
    }

    #[test]
    fn current_workspace_resolves_the_advanced_product_version() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask must be inside the workspace");
        assert_eq!(
            workspace_version(workspace).expect("resolve workspace version"),
            "0.10.0-alpha.2"
        );
    }

    #[test]
    fn exact_tag_commit_passes() {
        let repository = repository();
        git(repository.path(), &["tag", "v0.10.0-alpha.1"]);
        assert!(check_repository(repository.path(), "0.10.0-alpha.1").is_ok());
    }

    #[test]
    fn annotated_tag_is_peeled_to_its_commit() {
        let repository = repository();
        git(
            repository.path(),
            &[
                "-c",
                "user.name=Termivar Tests",
                "-c",
                "user.email=tests@termivar.invalid",
                "tag",
                "--annotate",
                "--message=release",
                "v0.10.0-alpha.1",
            ],
        );
        assert!(check_repository(repository.path(), "0.10.0-alpha.1").is_ok());
    }

    #[test]
    fn shallow_repository_is_rejected_before_tag_reasoning() {
        let repository = repository();
        let head = git_text(repository.path(), &["rev-parse", "HEAD"])
            .expect("resolve fixture head before marking it shallow");
        fs::write(repository.path().join(".git/shallow"), format!("{head}\n"))
            .expect("mark fixture repository shallow");
        let error = check_repository(repository.path(), "0.10.0-alpha.2")
            .expect_err("shallow history must not prove release provenance")
            .to_string();
        assert!(error.contains("complete Git history and tags"));
    }

    #[test]
    fn commit_beyond_matching_tag_requires_a_version_advance() {
        let repository = repository();
        git(repository.path(), &["tag", "v0.10.0-alpha.1"]);
        git(
            repository.path(),
            &[
                "-c",
                "user.name=Termivar Tests",
                "-c",
                "user.email=tests@termivar.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "post-release change",
            ],
        );
        let error = check_repository(repository.path(), "0.10.0-alpha.1")
            .expect_err("tagged version must not identify later source")
            .to_string();
        assert!(error.contains("advance the development-line version"));
        assert!(check_repository(repository.path(), "0.10.0-alpha.2").is_ok());
    }

    #[test]
    fn matching_tag_on_a_divergent_commit_fails_closed() {
        let repository = repository();
        git(repository.path(), &["tag", "v0.10.0-alpha.1"]);
        git(
            repository.path(),
            &["checkout", "--quiet", "--orphan", "divergent"],
        );
        git(
            repository.path(),
            &[
                "-c",
                "user.name=Termivar Tests",
                "-c",
                "user.email=tests@termivar.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "divergent",
            ],
        );
        let error = check_repository(repository.path(), "0.10.0-alpha.1")
            .expect_err("divergent version tag must be rejected")
            .to_string();
        assert!(error.contains("collides"));
    }

    #[test]
    fn bounded_git_reader_rejects_failed_and_oversized_reads() {
        let repository = repository();
        assert!(git_text(repository.path(), &["rev-parse", "missing-ref"]).is_err());

        let oversized = "x".repeat(MAX_GIT_OUTPUT_BYTES + 1);
        fs::write(repository.path().join("oversized.txt"), oversized)
            .expect("write oversized fixture");
        git(repository.path(), &["add", "oversized.txt"]);
        git(
            repository.path(),
            &[
                "-c",
                "user.name=Termivar Tests",
                "-c",
                "user.email=tests@termivar.invalid",
                "commit",
                "--quiet",
                "-m",
                "oversized fixture",
            ],
        );
        let error = git_text(repository.path(), &["show", "HEAD:oversized.txt"])
            .expect_err("oversized Git output must fail closed")
            .to_string();
        assert!(error.contains("exceeded its byte limit"));
    }
}
