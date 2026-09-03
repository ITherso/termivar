//! Repository maintenance commands exposed through `cargo xtask`.

mod architecture;
mod artifact_catalog;
mod development_line;
mod exploit_catalog;
mod release_metadata;
mod scanner_corpus;
mod scanner_salvage;
mod semver;
mod waf_evasion_salvage;

use cargo_metadata::MetadataCommand;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

type TaskResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RELEASE_CLI_PACKAGE: &str = "termivar-cli";
const RELEASE_BUNDLE_FEATURE: &str = "release-bundle";
const RELEASE_FORMAT_ARGS: &[&str] = &["+1.88.0", "fmt", "--all", "--", "--check"];
const RELEASE_BUILD_ARGS: &[&str] = &[
    "build",
    "--release",
    "--locked",
    "-p",
    RELEASE_CLI_PACKAGE,
    "--features",
    RELEASE_BUNDLE_FEATURE,
];

#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
#[command(about = "Termivar repository maintenance commands")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Verify workspace and reasoning-module dependency direction.
    Architecture,
    /// Validate repository-owned artifact signature packs and catalog identity.
    ArtifactCatalog,
    /// Run the maintained Criterion scanner benchmark suite.
    Benchmark,
    /// Build MkDocs and Rust API documentation.
    Docs,
    /// Ensure post-release source has advanced beyond an existing version tag.
    DevelopmentLine,
    /// Validate repository-owned exploit-pack manifests and catalog identity.
    ExploitCatalog,
    /// Validate the repository-owned security-assessment conformance corpus.
    ScannerCorpus {
        /// Rewrite the stored semantic digest and generated corpus inventory.
        #[arg(long)]
        write: bool,
    },
    /// Run the local release preflight without tagging or publishing.
    Release,
    /// Verify tag-time changelog and supported-version metadata.
    ReleaseMetadata { version: String },
    /// Check termivar-core's public API against the pinned compatibility baseline.
    Semver,
    /// Validate the deleted scanner tree's historical salvage ledger.
    ScannerSalvage {
        /// Rewrite the stored semantic digest and generated Markdown report.
        #[arg(long)]
        write: bool,
    },
    /// Validate the post-workspace WAF/evasion salvage ledger.
    WafEvasionSalvage {
        /// Rewrite the stored semantic digest and generated Markdown report.
        #[arg(long)]
        write: bool,
    },
    /// Generate an SDK starter project.
    Generate {
        #[arg(value_enum)]
        template: Template,
        name: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Template {
    Plugin,
    Scanner,
}

fn main() -> TaskResult {
    let root = workspace_root();
    match Cli::parse().command {
        Task::Architecture => architecture_preflight(&root),
        Task::ArtifactCatalog => artifact_catalog::check(&root),
        Task::Benchmark => run(
            &root,
            "cargo",
            &[
                "bench",
                "-p",
                "termivar-scanner",
                "--bench",
                "scanner_benchmarks",
            ],
        ),
        Task::Docs => {
            run(
                &root,
                "cargo",
                &[
                    "doc",
                    "--workspace",
                    "--all-features",
                    "--no-deps",
                    "--locked",
                ],
            )?;
            run_mkdocs(&root)
        },
        Task::DevelopmentLine => development_line::check(&root),
        Task::ExploitCatalog => exploit_catalog::check(&root),
        Task::Release => release_preflight(&root),
        Task::ReleaseMetadata { version } => release_metadata::check(&root, &version),
        Task::ScannerCorpus { write } => scanner_corpus::run(&root, write),
        Task::Semver => semver::check(&root),
        Task::ScannerSalvage { write } => scanner_salvage::run(&root, write),
        Task::WafEvasionSalvage { write } => waf_evasion_salvage::run(&root, write),
        Task::Generate { template, name } => generate(&root, template, &name),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live under the workspace root")
        .to_path_buf()
}

fn release_preflight(root: &Path) -> TaskResult {
    let version = workspace_release_version(root)?;
    release_metadata::check(root, &version)?;
    architecture_preflight(root)?;
    run(root, "cargo", RELEASE_FORMAT_ARGS)?;
    run(
        root,
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        root,
        "cargo",
        &["test", "--workspace", "--all-features", "--locked"],
    )?;
    run(root, "cargo", RELEASE_BUILD_ARGS)?;
    println!("release preflight passed; no tag or artifact was published");
    Ok(())
}

fn workspace_release_version(root: &Path) -> TaskResult<String> {
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let package = metadata
        .workspace_packages()
        .into_iter()
        .find(|package| package.name.as_str() == RELEASE_CLI_PACKAGE)
        .ok_or("termivar-cli is absent from release workspace metadata")?;
    Ok(package.version.to_string())
}

fn architecture_preflight(root: &Path) -> TaskResult {
    architecture::check(root)?;
    run(
        root,
        "cargo",
        &[
            "check",
            "--locked",
            "-p",
            "termivar-scanner",
            "--no-default-features",
        ],
    )
}

fn generate(root: &Path, template: Template, name: &str) -> TaskResult {
    validate_project_name(name)?;
    let template_name = match template {
        Template::Plugin => "termivar-plugin",
        Template::Scanner => "termivar-scanner",
    };
    let template_path = root.join("templates").join(template_name);
    let template_path = template_path
        .to_str()
        .ok_or("template path is not valid UTF-8")?;

    run(
        root,
        "cargo",
        &["generate", "--path", template_path, "--name", name],
    )
}

fn validate_project_name(name: &str) -> TaskResult {
    let valid = !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_'
        });
    if valid {
        Ok(())
    } else {
        Err("project name must contain only lowercase ASCII letters, digits, '-' or '_'".into())
    }
}

fn run_mkdocs(root: &Path) -> TaskResult {
    if run_if_available(root, "mkdocs", &["build", "--strict"])? {
        return Ok(());
    }
    for python in ["python3", "python"] {
        if run_if_available(root, python, &["-m", "mkdocs", "build", "--strict"])? {
            return Ok(());
        }
    }
    Err("MkDocs is not installed; run `pip install -r requirements-docs.txt`".into())
}

fn run(root: &Path, program: &str, args: &[&str]) -> TaskResult {
    println!("+ {} {}", program, args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}: {program}").into())
    }
}

fn run_if_available(root: &Path, program: &str, args: &[&str]) -> TaskResult<bool> {
    println!("+ {} {}", program, args.join(" "));
    match Command::new(program).args(args).current_dir(root).status() {
        Ok(status) if status.success() => Ok(true),
        Ok(status) => Err(format!("command failed with status {status}: {program}").into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_templates_exist() {
        let root = workspace_root();
        assert!(root.join("templates/termivar-plugin").is_dir());
        assert!(root.join("templates/termivar-scanner").is_dir());
    }

    #[test]
    fn project_names_are_restricted() {
        assert!(validate_project_name("custom-scanner").is_ok());
        assert!(validate_project_name("Custom Scanner").is_err());
        assert!(validate_project_name("../scanner").is_err());
    }

    #[test]
    fn release_preflight_builds_the_reviewed_non_default_bundle() {
        assert_eq!(
            RELEASE_BUILD_ARGS,
            [
                "build",
                "--release",
                "--locked",
                "-p",
                "termivar-cli",
                "--features",
                "release-bundle",
            ]
        );
        assert!(!RELEASE_BUILD_ARGS.contains(&"--all-features"));
    }

    #[test]
    fn release_preflight_uses_the_canonical_formatter_without_installing_it() {
        assert_eq!(
            RELEASE_FORMAT_ARGS,
            ["+1.88.0", "fmt", "--all", "--", "--check"]
        );
        assert!(!RELEASE_FORMAT_ARGS.contains(&"install"));
    }

    #[test]
    fn waf_evasion_salvage_command_has_an_explicit_write_mode() {
        let check = Cli::try_parse_from(["cargo xtask", "waf-evasion-salvage"])
            .expect("parse validation command");
        assert!(matches!(
            check.command,
            Task::WafEvasionSalvage { write: false }
        ));

        let write = Cli::try_parse_from(["cargo xtask", "waf-evasion-salvage", "--write"])
            .expect("parse generation command");
        assert!(matches!(
            write.command,
            Task::WafEvasionSalvage { write: true }
        ));
    }

    #[test]
    fn scanner_corpus_command_has_an_explicit_write_mode() {
        let check = Cli::try_parse_from(["cargo xtask", "scanner-corpus"])
            .expect("parse validation command");
        assert!(matches!(
            check.command,
            Task::ScannerCorpus { write: false }
        ));

        let write = Cli::try_parse_from(["cargo xtask", "scanner-corpus", "--write"])
            .expect("parse generation command");
        assert!(matches!(write.command, Task::ScannerCorpus { write: true }));
    }

    #[test]
    fn development_line_command_is_explicit() {
        let parsed = Cli::try_parse_from(["cargo xtask", "development-line"])
            .expect("parse development-line validation command");
        assert!(matches!(parsed.command, Task::DevelopmentLine));
    }
}
