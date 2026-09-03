//! Pinned public-API compatibility check for `termivar-core`.

use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};

use super::{run, TaskResult};

const PACKAGE: &str = "termivar-core";
const BASELINE_REVISION: &str = "9f65c661028af2d7129caeee640f9b6185c357ca";
const BASELINE_PACKAGE: &str = "venom-core";
const BASELINE_LIBRARY: &str = "venom_core";
const BASELINE_CRATE_ROOT: &str = "crates/venom-core";
const MAX_BASELINE_TREE_BYTES: usize = 64 * 1024;
const MAX_BASELINE_FILE_BYTES: usize = 1024 * 1024;
const MAX_BASELINE_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_BASELINE_FILES: usize = 128;
const SEMVER_CHECKS_VERSION: &str = "0.50.0";
const INSTALL_COMMAND: &str = "cargo install cargo-semver-checks --version 0.50.0 --locked";

pub(super) fn check(root: &Path) -> TaskResult {
    verify_tool_version()?;
    let baseline = BaselineWorkspace::materialize(root)?;
    let baseline_root = baseline.path().to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary SemVer baseline path is not valid UTF-8",
        )
    })?;
    let arguments = check_arguments(baseline_root);
    let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run(root, "cargo", &borrowed)
}

fn check_arguments(baseline_root: &str) -> Vec<String> {
    [
        "semver-checks",
        "--package",
        PACKAGE,
        "--baseline-root",
        baseline_root,
        "--release-type",
        "patch",
        "--all-features",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Materializes the immutable pre-rename core crate under `target/` and changes
/// only its Cargo package/library identity. `cargo-semver-checks` pairs current
/// and baseline packages by exact name, so this transient adapter lets the
/// renamed `termivar-core` keep checking the same historical public API without
/// shipping a compatibility crate or weakening the patch-level gate.
struct BaselineWorkspace {
    path: PathBuf,
}

impl BaselineWorkspace {
    fn materialize(repository_root: &Path) -> TaskResult<Self> {
        let target = repository_root.join("target");
        fs::create_dir_all(&target)?;
        let path = target.join(format!("termivar-semver-baseline-{}", std::process::id()));
        validate_temporary_baseline_path(&target, &path)?;
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir(&path)?;
        let baseline = Self { path };

        let workspace_manifest = git_file(
            repository_root,
            BASELINE_REVISION,
            "Cargo.toml",
            MAX_BASELINE_FILE_BYTES,
        )?;
        let workspace_manifest = std::str::from_utf8(&workspace_manifest)?;
        fs::write(
            baseline.path.join("Cargo.toml"),
            rewrite_workspace_manifest(workspace_manifest)?,
        )?;

        let entries = baseline_tree_entries(repository_root)?;
        let mut total_bytes = 0usize;
        for entry in entries {
            total_bytes = total_bytes.checked_add(entry.byte_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "SemVer baseline size overflow")
            })?;
            if total_bytes > MAX_BASELINE_TOTAL_BYTES {
                return Err("SemVer baseline exceeds its aggregate byte limit".into());
            }
            let bytes = git_file(
                repository_root,
                BASELINE_REVISION,
                &entry.path,
                entry.byte_size,
            )?;
            if bytes.len() != entry.byte_size {
                return Err(format!(
                    "SemVer baseline blob `{}` size did not match its Git tree entry",
                    entry.path
                )
                .into());
            }
            let destination = baseline.path.join(&entry.path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            if entry.path == format!("{BASELINE_CRATE_ROOT}/Cargo.toml") {
                let manifest = std::str::from_utf8(&bytes)?;
                fs::write(destination, rewrite_core_manifest(manifest)?)?;
            } else {
                fs::write(destination, bytes)?;
            }
        }

        Ok(baseline)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BaselineWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validate_temporary_baseline_path(target: &Path, path: &Path) -> TaskResult {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("temporary SemVer baseline has no UTF-8 file name")?;
    let suffix = name
        .strip_prefix("termivar-semver-baseline-")
        .ok_or("temporary SemVer baseline has an unexpected name")?;
    if path.parent() == Some(target)
        && target.file_name().and_then(|name| name.to_str()) == Some("target")
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(
            "temporary SemVer baseline must remain a direct, process-scoped child of target/"
                .into(),
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
struct BaselineTreeEntry {
    path: String,
    byte_size: usize,
}

fn baseline_tree_entries(repository_root: &Path) -> TaskResult<Vec<BaselineTreeEntry>> {
    let output = git_output(
        repository_root,
        &[
            "ls-tree",
            "-r",
            "-l",
            "--full-tree",
            BASELINE_REVISION,
            "--",
            BASELINE_CRATE_ROOT,
        ],
        MAX_BASELINE_TREE_BYTES,
    )?;
    parse_baseline_tree(std::str::from_utf8(&output)?)
}

fn parse_baseline_tree(source: &str) -> TaskResult<Vec<BaselineTreeEntry>> {
    let mut entries = Vec::new();
    for line in source.lines() {
        if entries.len() == MAX_BASELINE_FILES {
            return Err("SemVer baseline contains too many files".into());
        }
        let (metadata, path) = line
            .split_once('\t')
            .ok_or("malformed SemVer baseline tree entry")?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "100644" || fields[1] != "blob" {
            return Err("SemVer baseline permits only regular Git blobs".into());
        }
        validate_baseline_relative_path(path)?;
        let byte_size = fields[3]
            .parse::<usize>()
            .map_err(|_| "SemVer baseline blob has an invalid size")?;
        if byte_size > MAX_BASELINE_FILE_BYTES {
            return Err(format!("SemVer baseline blob `{path}` exceeds its byte limit").into());
        }
        entries.push(BaselineTreeEntry {
            path: path.to_owned(),
            byte_size,
        });
    }
    if entries.is_empty()
        || !entries
            .iter()
            .any(|entry| entry.path == format!("{BASELINE_CRATE_ROOT}/Cargo.toml"))
        || !entries
            .iter()
            .any(|entry| entry.path == format!("{BASELINE_CRATE_ROOT}/src/lib.rs"))
    {
        return Err("SemVer baseline is missing its manifest or library root".into());
    }
    Ok(entries)
}

fn validate_baseline_relative_path(path: &str) -> TaskResult {
    let candidate = Path::new(path);
    let valid_components = candidate
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    let allowed = path == format!("{BASELINE_CRATE_ROOT}/Cargo.toml")
        || (path.starts_with(&format!("{BASELINE_CRATE_ROOT}/src/"))
            && candidate
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("rs"));
    if valid_components && allowed {
        Ok(())
    } else {
        Err(format!("unexpected SemVer baseline path `{path}`").into())
    }
}

fn git_file(root: &Path, revision: &str, path: &str, max_bytes: usize) -> TaskResult<Vec<u8>> {
    git_output(root, &["show", &format!("{revision}:{path}")], max_bytes)
}

fn git_output(root: &Path, arguments: &[&str], max_bytes: usize) -> TaskResult<Vec<u8>> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "bounded Git read failed with status {}: {}",
            output.status,
            diagnostic.trim().chars().take(512).collect::<String>()
        )
        .into());
    }
    if output.stdout.len() > max_bytes {
        return Err("bounded Git read exceeded its byte limit".into());
    }
    Ok(output.stdout)
}

fn rewrite_workspace_manifest(source: &str) -> TaskResult<String> {
    let mut manifest = source.parse::<toml::Value>()?;
    let workspace = manifest
        .get_mut("workspace")
        .and_then(toml::Value::as_table_mut)
        .ok_or("historical SemVer baseline root is not a workspace")?;
    let members = workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .ok_or("historical SemVer baseline has no workspace members")?;
    if !members
        .iter()
        .any(|member| member.as_str() == Some(BASELINE_CRATE_ROOT))
    {
        return Err("historical SemVer baseline does not contain venom-core".into());
    }
    workspace.insert(
        "members".to_owned(),
        toml::Value::Array(vec![toml::Value::String(BASELINE_CRATE_ROOT.to_owned())]),
    );
    workspace.remove("default-members");
    Ok(toml::to_string(&manifest)?)
}

fn rewrite_core_manifest(source: &str) -> TaskResult<String> {
    let mut manifest = source.parse::<toml::Value>()?;
    let package = manifest
        .get_mut("package")
        .and_then(toml::Value::as_table_mut)
        .ok_or("historical SemVer baseline has no package table")?;
    match package.get("name").and_then(toml::Value::as_str) {
        Some(BASELINE_PACKAGE) => {
            package.insert("name".to_owned(), toml::Value::String(PACKAGE.to_owned()));
        },
        _ => return Err("historical SemVer baseline package identity is unexpected".into()),
    }
    let library = manifest
        .get_mut("lib")
        .and_then(toml::Value::as_table_mut)
        .ok_or("historical SemVer baseline has no library table")?;
    match library.get("name").and_then(toml::Value::as_str) {
        Some(BASELINE_LIBRARY) => {
            library.insert(
                "name".to_owned(),
                toml::Value::String("termivar_core".to_owned()),
            );
        },
        _ => return Err("historical SemVer baseline library identity is unexpected".into()),
    }
    Ok(toml::to_string(&manifest)?)
}

fn verify_tool_version() -> TaskResult {
    let output = match Command::new("cargo-semver-checks")
        .arg("--version")
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(format!(
                "required tool cargo-semver-checks {SEMVER_CHECKS_VERSION} is not installed; run `{INSTALL_COMMAND}`"
            )
            .into());
        },
        Err(error) => return Err(error.into()),
    };

    validate_tool_version(&output)
}

fn validate_tool_version(output: &Output) -> TaskResult {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reported = if stdout.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };

    if !output.status.success() {
        return Err(format!(
            "failed to query cargo-semver-checks version (status {}): {}",
            output.status,
            if reported.is_empty() {
                "no diagnostic output"
            } else {
                reported
            }
        )
        .into());
    }

    let expected = format!("cargo-semver-checks {SEMVER_CHECKS_VERSION}");
    if reported == expected {
        Ok(())
    } else {
        Err(format!(
            "cargo-semver-checks {SEMVER_CHECKS_VERSION} is required, but `{reported}` was found; run `{INSTALL_COMMAND} --force`"
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitStatus;

    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    fn version_output(status: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: exit_status(status),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn run_git(root: &Path, arguments: &[&str]) -> Output {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(root)
            .output()
            .expect("run Git fixture command");
        assert!(
            output.status.success(),
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn git_fixture(files: impl IntoIterator<Item = (String, Vec<u8>)>) -> TempDir {
        let repository = TempDir::new().expect("temporary Git repository");
        run_git(repository.path(), &["init", "--quiet"]);
        for (relative, contents) in files {
            let path = repository.path().join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture parent");
            }
            fs::write(path, contents).expect("write fixture file");
        }
        run_git(repository.path(), &["add", "--all"]);
        run_git(
            repository.path(),
            &[
                "-c",
                "user.name=Termivar SemVer Fixture",
                "-c",
                "user.email=semver@example.invalid",
                "commit",
                "--quiet",
                "--message",
                "fixture",
            ],
        );
        repository
    }

    fn fixture_tree(repository: &Path) -> String {
        let output = git_output(
            repository,
            &[
                "ls-tree",
                "-r",
                "-l",
                "--full-tree",
                "HEAD",
                "--",
                BASELINE_CRATE_ROOT,
            ],
            MAX_BASELINE_TREE_BYTES,
        )
        .expect("read bounded fixture tree");
        String::from_utf8(output).expect("Git tree output is UTF-8")
    }

    fn bind_fixture_to_historical_revision(repository: &Path) {
        let head = String::from_utf8(run_git(repository, &["rev-parse", "HEAD"]).stdout)
            .expect("fixture head is UTF-8");
        let replacement = format!("refs/replace/{BASELINE_REVISION}");
        run_git(repository, &["update-ref", &replacement, head.trim()]);
    }

    #[test]
    fn command_is_scoped_to_the_pinned_core_patch_baseline() {
        let baseline = "target/termivar-semver-baseline-test";
        assert_eq!(
            check_arguments(baseline),
            [
                "semver-checks",
                "--package",
                "termivar-core",
                "--baseline-root",
                baseline,
                "--release-type",
                "patch",
                "--all-features",
            ]
            .map(str::to_owned)
        );
    }

    #[test]
    fn baseline_tree_accepts_only_the_pinned_core_manifest_and_rust_sources() {
        let tree = concat!(
            "100644 blob 1111111111111111111111111111111111111111 42\tcrates/venom-core/Cargo.toml\n",
            "100644 blob 2222222222222222222222222222222222222222 12\tcrates/venom-core/src/lib.rs\n",
            "100644 blob 3333333333333333333333333333333333333333 9\tcrates/venom-core/src/model.rs\n",
        );
        assert_eq!(
            parse_baseline_tree(tree).unwrap(),
            vec![
                BaselineTreeEntry {
                    path: "crates/venom-core/Cargo.toml".to_owned(),
                    byte_size: 42,
                },
                BaselineTreeEntry {
                    path: "crates/venom-core/src/lib.rs".to_owned(),
                    byte_size: 12,
                },
                BaselineTreeEntry {
                    path: "crates/venom-core/src/model.rs".to_owned(),
                    byte_size: 9,
                },
            ]
        );

        for invalid in [
            "100644 blob 1 1\tcrates/venom-core/../Cargo.toml\n",
            "120000 blob 1 1\tcrates/venom-core/src/lib.rs\n",
            "100644 blob 1 1\tcrates/venom-core/build.rs\n",
            "100644 blob 1 1\tcrates/termivar-core/src/lib.rs\n",
        ] {
            assert!(parse_baseline_tree(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn historical_baseline_materializes_as_one_identity_only_adapter() {
        let repository = git_fixture([
            (
                "Cargo.toml".to_owned(),
                br#"[workspace]
members = ["crates/venom-core", "crates/venom-cli"]
default-members = ["crates/venom-cli"]
resolver = "2"
"#
                .to_vec(),
            ),
            (
                "crates/venom-core/Cargo.toml".to_owned(),
                br#"[package]
name = "venom-core"
version = "0.9.0-alpha"

[lib]
name = "venom_core"
path = "src/lib.rs"
"#
                .to_vec(),
            ),
            (
                "crates/venom-core/src/lib.rs".to_owned(),
                b"mod model;\npub use model::Baseline;\n".to_vec(),
            ),
            (
                "crates/venom-core/src/model.rs".to_owned(),
                b"pub struct Baseline;\n".to_vec(),
            ),
        ]);
        bind_fixture_to_historical_revision(repository.path());

        let materialized_path = repository
            .path()
            .join("target")
            .join(format!("termivar-semver-baseline-{}", std::process::id()));
        fs::create_dir_all(&materialized_path).expect("create stale materialization");
        fs::write(materialized_path.join("stale"), b"stale")
            .expect("write stale materialization marker");

        let baseline = BaselineWorkspace::materialize(repository.path())
            .expect("materialize pinned historical baseline");
        assert_eq!(baseline.path(), materialized_path);
        assert!(!baseline.path().join("stale").exists());

        let workspace = fs::read_to_string(baseline.path().join("Cargo.toml"))
            .expect("read materialized workspace")
            .parse::<toml::Value>()
            .expect("parse materialized workspace");
        assert_eq!(
            workspace["workspace"]["members"].as_array().unwrap(),
            &[toml::Value::String(BASELINE_CRATE_ROOT.to_owned())]
        );
        assert!(workspace["workspace"].get("default-members").is_none());

        let core_manifest =
            fs::read_to_string(baseline.path().join(BASELINE_CRATE_ROOT).join("Cargo.toml"))
                .expect("read materialized core manifest")
                .parse::<toml::Value>()
                .expect("parse materialized core manifest");
        assert_eq!(core_manifest["package"]["name"].as_str(), Some(PACKAGE));
        assert_eq!(core_manifest["lib"]["name"].as_str(), Some("termivar_core"));

        let expected_library = git_file(
            repository.path(),
            BASELINE_REVISION,
            &format!("{BASELINE_CRATE_ROOT}/src/lib.rs"),
            MAX_BASELINE_FILE_BYTES,
        )
        .expect("read pinned library blob");
        assert_eq!(
            fs::read(baseline.path().join(BASELINE_CRATE_ROOT).join("src/lib.rs"))
                .expect("read materialized library"),
            expected_library
        );

        let cleanup_path = baseline.path().to_owned();
        drop(baseline);
        assert!(!cleanup_path.exists());
    }

    #[test]
    fn bounded_git_reads_report_command_failure_and_output_overrun() {
        let repository = git_fixture([(
            "crates/venom-core/src/lib.rs".to_owned(),
            b"pub struct Baseline;\n".to_vec(),
        )]);

        assert_eq!(
            git_file(
                repository.path(),
                "HEAD",
                "crates/venom-core/src/lib.rs",
                64,
            )
            .unwrap(),
            b"pub struct Baseline;\n"
        );

        let missing = git_output(
            repository.path(),
            &["show", "missing-revision:Cargo.toml"],
            64,
        )
        .expect_err("an absent revision must fail closed")
        .to_string();
        assert!(missing.contains("bounded Git read failed with status"));

        let oversized = git_output(
            repository.path(),
            &["show", "HEAD:crates/venom-core/src/lib.rs"],
            3,
        )
        .expect_err("output beyond the caller's bound must fail closed")
        .to_string();
        assert_eq!(oversized, "bounded Git read exceeded its byte limit");
    }

    #[test]
    fn real_git_trees_enforce_file_count_size_and_required_roots() {
        let mut too_many_files = vec![
            (
                "crates/venom-core/Cargo.toml".to_owned(),
                b"[package]\nname = \"venom-core\"\n".to_vec(),
            ),
            (
                "crates/venom-core/src/lib.rs".to_owned(),
                b"pub struct Baseline;\n".to_vec(),
            ),
        ];
        for index in 0..MAX_BASELINE_FILES {
            too_many_files.push((
                format!("crates/venom-core/src/generated_{index:03}.rs"),
                b"pub const VALUE: usize = 1;\n".to_vec(),
            ));
        }
        let repository = git_fixture(too_many_files);
        assert_eq!(
            parse_baseline_tree(&fixture_tree(repository.path()))
                .expect_err("the baseline file-count bound must fail closed")
                .to_string(),
            "SemVer baseline contains too many files"
        );

        let repository = git_fixture([
            (
                "crates/venom-core/Cargo.toml".to_owned(),
                b"[package]\nname = \"venom-core\"\n".to_vec(),
            ),
            (
                "crates/venom-core/src/lib.rs".to_owned(),
                b"pub struct Baseline;\n".to_vec(),
            ),
            (
                "crates/venom-core/src/oversized.rs".to_owned(),
                vec![b'x'; MAX_BASELINE_FILE_BYTES + 1],
            ),
        ]);
        let oversized = parse_baseline_tree(&fixture_tree(repository.path()))
            .expect_err("an oversized baseline blob must fail closed")
            .to_string();
        assert!(oversized.contains("oversized.rs"));
        assert!(oversized.contains("exceeds its byte limit"));

        let repository = git_fixture([(
            "crates/venom-core/Cargo.toml".to_owned(),
            b"[package]\nname = \"venom-core\"\n".to_vec(),
        )]);
        assert_eq!(
            parse_baseline_tree(&fixture_tree(repository.path()))
                .expect_err("the library root is mandatory")
                .to_string(),
            "SemVer baseline is missing its manifest or library root"
        );

        let repository = git_fixture([
            (
                "crates/venom-core/Cargo.toml".to_owned(),
                b"[package]\nname = \"venom-core\"\n".to_vec(),
            ),
            (
                "crates/venom-core/src/lib.rs".to_owned(),
                b"pub struct Baseline;\n".to_vec(),
            ),
            (
                "crates/venom-core/README.md".to_owned(),
                b"not part of the bounded source baseline\n".to_vec(),
            ),
        ]);
        bind_fixture_to_historical_revision(repository.path());
        assert_eq!(
            baseline_tree_entries(repository.path())
                .expect_err("a committed path outside the allowlist must fail closed")
                .to_string(),
            "unexpected SemVer baseline path `crates/venom-core/README.md`"
        );
    }

    #[test]
    fn materialization_enforces_aggregate_size_and_cleans_partial_output() {
        let mut files = vec![
            (
                "Cargo.toml".to_owned(),
                b"[workspace]\nmembers = [\"crates/venom-core\"]\n".to_vec(),
            ),
            (
                "crates/venom-core/Cargo.toml".to_owned(),
                br#"[package]
name = "venom-core"
version = "0.9.0-alpha"

[lib]
name = "venom_core"
path = "src/lib.rs"
"#
                .to_vec(),
            ),
            (
                "crates/venom-core/src/lib.rs".to_owned(),
                b"pub struct Baseline;\n".to_vec(),
            ),
        ];
        for index in 0..5 {
            files.push((
                format!("crates/venom-core/src/large_{index}.rs"),
                vec![b'x'; 900 * 1024],
            ));
        }
        let repository = git_fixture(files);
        bind_fixture_to_historical_revision(repository.path());

        let materialized_path = repository
            .path()
            .join("target")
            .join(format!("termivar-semver-baseline-{}", std::process::id()));
        assert_eq!(
            BaselineWorkspace::materialize(repository.path())
                .map(|_| ())
                .expect_err("aggregate baseline size must fail closed")
                .to_string(),
            "SemVer baseline exceeds its aggregate byte limit"
        );
        assert!(
            !materialized_path.exists(),
            "the partially materialized baseline must be cleaned by its guard"
        );
    }

    #[test]
    fn temporary_baseline_cleanup_target_is_narrow_and_process_scoped() {
        let target = Path::new("workspace/target");
        assert!(validate_temporary_baseline_path(
            target,
            &target.join("termivar-semver-baseline-42")
        )
        .is_ok());
        for invalid in [
            target.join("termivar-semver-baseline-any"),
            target.join("other-42"),
            PathBuf::from("workspace/termivar-semver-baseline-42"),
        ] {
            assert!(validate_temporary_baseline_path(target, &invalid).is_err());
        }
    }

    #[test]
    fn baseline_manifest_adapter_changes_only_package_and_library_identity() {
        let source = r#"
            [package]
            name = "venom-core"
            version.workspace = true

            [lib]
            name = "venom_core"
            path = "src/lib.rs"

            [dependencies]
            serde = { workspace = true }
        "#;
        let rewritten = rewrite_core_manifest(source).unwrap();
        let manifest = rewritten.parse::<toml::Value>().unwrap();
        assert_eq!(manifest["package"]["name"].as_str(), Some("termivar-core"));
        assert_eq!(manifest["lib"]["name"].as_str(), Some("termivar_core"));
        assert_eq!(manifest["lib"]["path"].as_str(), Some("src/lib.rs"));
        assert!(manifest["dependencies"].get("serde").is_some());

        assert!(rewrite_core_manifest(&source.replace("venom-core", "other-core")).is_err());
        assert!(rewrite_core_manifest(&source.replace("venom_core", "other_core")).is_err());
    }

    #[test]
    fn baseline_workspace_adapter_keeps_only_the_historical_core_member() {
        let source = r#"
            [workspace]
            members = ["crates/venom-core", "crates/venom-cli"]
            default-members = ["crates/venom-cli"]

            [workspace.package]
            version = "0.9.0-alpha"

            [workspace.dependencies]
            serde = "1"
        "#;
        let rewritten = rewrite_workspace_manifest(source).unwrap();
        let manifest = rewritten.parse::<toml::Value>().unwrap();
        assert_eq!(
            manifest["workspace"]["members"].as_array().unwrap(),
            &[toml::Value::String("crates/venom-core".to_owned())]
        );
        assert!(manifest["workspace"].get("default-members").is_none());
        assert_eq!(
            manifest["workspace"]["dependencies"]["serde"].as_str(),
            Some("1")
        );
        assert!(rewrite_workspace_manifest(&source.replace("venom-core", "other-core")).is_err());
    }

    #[test]
    fn exact_tool_version_is_accepted() {
        let output = version_output(0, "cargo-semver-checks 0.50.0\n", "");
        assert!(validate_tool_version(&output).is_ok());
    }

    #[test]
    fn another_tool_version_reports_the_pinned_install_command() {
        let output = version_output(0, "cargo-semver-checks 0.51.0\n", "");
        let error = validate_tool_version(&output)
            .expect_err("a different version must be rejected")
            .to_string();

        assert!(error.contains("cargo-semver-checks 0.50.0 is required"));
        assert!(error.contains(INSTALL_COMMAND));
        assert!(error.contains("--force"));
    }
}
