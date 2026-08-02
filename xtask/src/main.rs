//! Repository maintenance commands exposed through `cargo xtask`.

mod architecture;

use clap::{Parser, Subcommand, ValueEnum};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

type TaskResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
#[command(about = "Venom repository maintenance commands")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Verify workspace and reasoning-module dependency direction.
    Architecture,
    /// Run the maintained Criterion scanner benchmark suite.
    Benchmark,
    /// Build MkDocs and Rust API documentation.
    Docs,
    /// Run the local release preflight without tagging or publishing.
    Release,
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
        Task::Benchmark => run(
            &root,
            "cargo",
            &[
                "bench",
                "-p",
                "venom-scanner",
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
        Task::Release => release_preflight(&root),
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
    architecture_preflight(root)?;
    run(root, "cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        root,
        "cargo",
        &["clippy", "--workspace", "--all-targets", "--all-features"],
    )?;
    run(
        root,
        "cargo",
        &["test", "--workspace", "--all-features", "--locked"],
    )?;
    run(
        root,
        "cargo",
        &["build", "--release", "--locked", "-p", "venom-cli"],
    )?;
    println!("release preflight passed; no tag or artifact was published");
    Ok(())
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
            "venom-scanner",
            "--no-default-features",
        ],
    )
}

fn generate(root: &Path, template: Template, name: &str) -> TaskResult {
    validate_project_name(name)?;
    let template_name = match template {
        Template::Plugin => "venom-plugin",
        Template::Scanner => "venom-scanner",
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
        assert!(root.join("templates/venom-plugin").is_dir());
        assert!(root.join("templates/venom-scanner").is_dir());
    }

    #[test]
    fn project_names_are_restricted() {
        assert!(validate_project_name("custom-scanner").is_ok());
        assert!(validate_project_name("Custom Scanner").is_err());
        assert!(validate_project_name("../scanner").is_err());
    }
}
