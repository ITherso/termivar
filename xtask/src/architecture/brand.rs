//! Current-product identity boundary for the Termivar migration.
//!
//! This deliberately does not assert that the repository contains no `venom`
//! text. Historical salvage, stable wire identifiers, digest domains, migration
//! notes, and the pre-rename repository URL remain valid compatibility data.
//! The gate covers machine-readable package, crate-directory, template, and
//! CLI identities plus path-classified current public text. Provenance trees
//! and exact compatibility phrases remain outside the current-brand ban.

use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

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

const CURRENT_PUBLIC_ROOT_FILES: &[&str] = &[
    "CHANGELOG.md",
    "README.md",
    "FEATURES.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "PROJECT_STATUS.md",
    "mkdocs.yml",
    "Dockerfile",
];

const CURRENT_PUBLIC_TREES: &[&str] = &[
    "docs",
    "examples",
    "templates",
    ".github",
    "scripts",
    "artifact-signatures",
    "exploit-packs",
    "profiles",
    "web",
];

const PUBLIC_SCAN_EXCLUDED_PREFIXES: &[&str] = &[
    "docs/history",
    "docs/migrations",
    "docs/adr",
    "docs/audits",
    "docs/reports",
    ".github/release-notes",
    "scripts/tests",
    "web/build",
    "web/dist",
    "web/node_modules",
];

const PUBLIC_TEXT_EXTENSIONS: &[&str] = &[
    "md", "toml", "yml", "yaml", "svg", "drawio", "html", "css", "js", "jsx", "ts", "tsx", "sh",
    "ps1", "py",
];

const README_FORMER_NAME_NOTE: &str = "Termivar was formerly developed under the name Venom.";
const COMPATIBILITY_FORMER_NAME_PHRASE: &str = "accepted previous Venom revision";
const PROJECT_STATUS_FORMER_NAME_PHRASE: &str = "release under the former Venom name";
const CHANGELOG_RENAME_PHRASE: &str = "Venom to Termivar.";

const FORMER_CLI_FORMS: &[&str] = &[
    "venom scan",
    "venom decision-scan",
    "venom legacy-scan",
    "venom artifact",
    "venom api",
    "venom proxy",
];

const FORMER_RUST_CRATE_PATHS: &[&str] = &[
    "venom_api::",
    "venom_artifact::",
    "venom_core::",
    "venom_exploit::",
    "venom_proxy::",
    "venom_scanner::",
];

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
        if package
            .description
            .as_deref()
            .is_some_and(contains_former_brand_word)
        {
            violations.push(format!(
                "current workspace package `{}` description still uses the former Venom product identity",
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
    violations.extend(public_brand_violations(workspace_root)?);
    Ok(violations)
}

fn public_brand_violations(workspace_root: &Path) -> io::Result<Vec<String>> {
    let mut files = CURRENT_PUBLIC_ROOT_FILES
        .iter()
        .map(|path| workspace_root.join(path))
        .collect::<Vec<_>>();
    for root in CURRENT_PUBLIC_TREES {
        collect_public_text_files(workspace_root, &workspace_root.join(root), &mut files)?;
    }
    files.sort();
    files.dedup();

    let mut violations = Vec::new();
    for file in files {
        let relative = normalized_relative_path(workspace_root, &file)?;
        let source = fs::read_to_string(&file)?;
        violations.extend(public_text_brand_violations(
            &relative,
            current_public_text(&relative, &source),
        ));
    }
    Ok(violations)
}

fn current_public_text<'a>(path: &str, source: &'a str) -> &'a str {
    if path != "CHANGELOG.md" {
        return source;
    }

    let mut headings = source.match_indices("\n## [");
    let _unreleased = headings.next();
    headings
        .next()
        .map_or(source, |(released_heading, _)| &source[..released_heading])
}

fn collect_public_text_files(
    workspace_root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> io::Result<()> {
    if !current.try_exists()? {
        return Ok(());
    }
    let relative = normalized_relative_path(workspace_root, current)?;
    if is_public_scan_excluded_path(&relative) {
        return Ok(());
    }
    if current.is_file() {
        if current
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| PUBLIC_TEXT_EXTENSIONS.contains(&extension))
        {
            files.push(current.to_path_buf());
        }
        return Ok(());
    }

    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        collect_public_text_files(workspace_root, &entry.path(), files)?;
    }
    Ok(())
}

fn normalized_relative_path(workspace_root: &Path, path: &Path) -> io::Result<String> {
    path.strip_prefix(workspace_root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "public brand path `{}` is outside workspace root `{}`",
                    path.display(),
                    workspace_root.display()
                ),
            )
        })
}

fn is_public_scan_excluded_path(path: &str) -> bool {
    PUBLIC_SCAN_EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

fn public_text_brand_violations(path: &str, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if path == "README.md" {
        let note_count = source.matches(README_FORMER_NAME_NOTE).count();
        if note_count != 1 {
            violations.push(format!(
                "current public `{path}` must contain exactly one former-name migration note, found {note_count}"
            ));
        }
    }

    let mut readme_note_available = path == "README.md";
    let mut compatibility_phrase_available = path == "docs/public-api-compatibility.md";
    let mut project_status_phrase_available = path == "PROJECT_STATUS.md";
    let mut changelog_rename_phrase_available = path == "CHANGELOG.md";
    for (index, line) in source.lines().enumerate() {
        let mut reviewable = line.to_owned();
        if readme_note_available && reviewable.contains(README_FORMER_NAME_NOTE) {
            reviewable = reviewable.replacen(README_FORMER_NAME_NOTE, "", 1);
            readme_note_available = false;
        }
        if compatibility_phrase_available && reviewable.contains(COMPATIBILITY_FORMER_NAME_PHRASE) {
            reviewable = reviewable.replacen(COMPATIBILITY_FORMER_NAME_PHRASE, "", 1);
            compatibility_phrase_available = false;
        }
        if project_status_phrase_available && reviewable.contains(PROJECT_STATUS_FORMER_NAME_PHRASE)
        {
            reviewable = reviewable.replacen(PROJECT_STATUS_FORMER_NAME_PHRASE, "", 1);
            project_status_phrase_available = false;
        }
        if changelog_rename_phrase_available && reviewable.contains(CHANGELOG_RENAME_PHRASE) {
            reviewable = reviewable.replacen(CHANGELOG_RENAME_PHRASE, "", 1);
            changelog_rename_phrase_available = false;
        }

        let line_number = index + 1;
        if contains_former_brand_word(&reviewable) {
            violations.push(format!(
                "current public `{path}:{line_number}` still uses Venom as the active product name"
            ));
        }
        for former in FORMER_CLI_FORMS {
            if reviewable.contains(former) {
                violations.push(format!(
                    "current public `{path}:{line_number}` retains former CLI form `{former}`"
                ));
            }
        }
        if reviewable.contains("-p venom-") {
            violations.push(format!(
                "current public `{path}:{line_number}` retains a former Cargo package selector"
            ));
        }
        if reviewable.contains("use venom_")
            || FORMER_RUST_CRATE_PATHS
                .iter()
                .any(|crate_path| reviewable.contains(crate_path))
        {
            violations.push(format!(
                "current public `{path}:{line_number}` retains a former Rust crate path"
            ));
        }
        if reviewable.contains("VENOM_") {
            violations.push(format!(
                "current public `{path}:{line_number}` retains a former active environment example"
            ));
        }
        if reviewable.contains(".venom") {
            violations.push(format!(
                "current public `{path}:{line_number}` retains a former active cache or host example"
            ));
        }
    }
    violations
}

fn contains_former_brand_word(source: &str) -> bool {
    source.char_indices().any(|(start, _)| {
        let former = source.as_bytes().get(start..start + 5);
        if !former.is_some_and(|candidate| candidate.eq_ignore_ascii_case(b"venom")) {
            return false;
        }
        let before = source[..start].chars().next_back();
        let after = source[start + 5..].chars().next();
        if before.is_some_and(is_brand_word_character) || after.is_some_and(is_brand_word_character)
        {
            return false;
        }

        let spelling = &source[start..start + 5];
        !spelling.eq("venom") || !is_lowercase_compatibility_identity(source, start, start + 5)
    })
}

fn is_lowercase_compatibility_identity(source: &str, start: usize, end: usize) -> bool {
    let before = source[..start].chars().next_back();
    let after = source[end..].chars().next();
    if matches!(before, Some('/' | ':' | '@' | '_' | '-'))
        || matches!(after, Some('/' | ':' | '@' | '_' | '-'))
    {
        return true;
    }

    if before == Some('.') {
        return source[..start]
            .chars()
            .rev()
            .nth(1)
            .is_some_and(|character| character.is_ascii_alphanumeric());
    }
    if after == Some('.') {
        return source[end + 1..]
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric());
    }
    false
}

fn is_brand_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
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

    #[test]
    fn current_public_surfaces_reject_former_product_prose_and_commands() {
        let source = concat!(
            "Venom is the current scanner.\n",
            "venom scan https://example.test\n",
            "cargo test -p venom-scanner\n",
            "use venom_core::Evidence;\n",
            "VENOM_AUTH_CONTEXT=value\n",
            "cache=.venom\n",
        );
        let violations = public_text_brand_violations("docs/scanner.md", source);
        assert_eq!(violations.len(), 8);
        assert!(violations
            .iter()
            .any(|violation| violation.contains("active product")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("CLI form")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("Cargo package selector")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("Rust crate path")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("environment")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("cache or host")));
    }

    #[test]
    fn stable_wire_digest_and_repository_identities_remain_accepted() {
        let source = concat!(
            "`venom.scan-profile/v1` remains stable.\n",
            "`venom-rendered-assessment/v1` remains stable.\n",
            "digest domain `venom.assessment-item/v1` remains stable.\n",
            "https://github.com/ITherso/venom remains the pre-rename repository.\n",
            "https://itherso.github.io/venom/ remains the pre-rename Pages URL.\n",
        );
        assert!(public_text_brand_violations("docs/reporting.md", source).is_empty());
    }

    #[test]
    fn readme_allows_exactly_one_former_name_migration_note() {
        let source = format!(
            "# Termivar\n\n{README_FORMER_NAME_NOTE} Historical identities remain stable.\n"
        );
        assert!(public_text_brand_violations("README.md", &source).is_empty());

        let missing = public_text_brand_violations("README.md", "# Termivar\n");
        assert_eq!(missing.len(), 1);
        assert!(missing[0].contains("exactly one"));

        let duplicated = format!("{README_FORMER_NAME_NOTE}\n{README_FORMER_NAME_NOTE}\n");
        let violations = public_text_brand_violations("README.md", &duplicated);
        assert_eq!(violations.len(), 2);
        assert!(violations[0].contains("found 2"));
        assert!(violations[1].contains("active product"));
    }

    #[test]
    fn public_api_compatibility_allows_only_the_exact_prior_revision_phrase() {
        assert!(public_text_brand_violations(
            "docs/public-api-compatibility.md",
            "compare the current API with an accepted previous Venom revision;"
        )
        .is_empty());
        assert_eq!(
            public_text_brand_violations(
                "docs/public-api-compatibility.md",
                "Venom is the current API."
            )
            .len(),
            1
        );
    }

    #[test]
    fn project_status_allows_only_the_exact_former_release_phrase() {
        assert!(public_text_brand_violations(
            "PROJECT_STATUS.md",
            "The latest release under the former Venom name is historical."
        )
        .is_empty());
        assert_eq!(
            public_text_brand_violations("PROJECT_STATUS.md", "Venom is current.").len(),
            1
        );
    }

    #[test]
    fn provenance_and_untracked_web_build_trees_are_excluded() {
        for path in [
            "docs/history/historical-scanner-salvage.md",
            "docs/migrations/venom-to-termivar.md",
            "docs/adr/0001-use-workspace.md",
            "docs/audits/runtime-truth-remediation.md",
            "docs/reports/coverage/accepted.md",
            ".github/release-notes/v0.9.0-alpha.md",
            "scripts/tests/test_coverage_gate.py",
        ] {
            assert!(is_public_scan_excluded_path(path), "{path}");
        }
        for path in ["web/build", "web/dist", "web/node_modules"] {
            assert!(is_public_scan_excluded_path(path), "{path}");
        }
        assert!(!is_public_scan_excluded_path("README.md"));
        assert!(!is_public_scan_excluded_path("docs/scanner.md"));
    }

    #[test]
    fn public_scan_walks_current_files_and_skips_provenance() {
        let temporary = tempfile::TempDir::new().unwrap();
        for relative in CURRENT_PUBLIC_ROOT_FILES {
            let path = temporary.path().join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let source = if *relative == "README.md" {
                format!("# Termivar\n\n{README_FORMER_NAME_NOTE}\n")
            } else {
                "Termivar current surface.\n".to_owned()
            };
            fs::write(path, source).unwrap();
        }
        for relative in CURRENT_PUBLIC_TREES {
            fs::create_dir_all(temporary.path().join(relative)).unwrap();
        }
        fs::write(
            temporary.path().join("docs/scanner.md"),
            "Venom is the current scanner.\n",
        )
        .unwrap();
        fs::create_dir_all(temporary.path().join("docs/history")).unwrap();
        fs::write(
            temporary.path().join("docs/history/legacy.md"),
            "Venom is historical here.\n",
        )
        .unwrap();
        fs::write(
            temporary.path().join("examples/ignored.bin"),
            "Venom is outside the public text extension set.\n",
        )
        .unwrap();

        let violations = public_brand_violations(temporary.path()).unwrap();
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("docs/scanner.md:1"));
    }

    #[test]
    fn public_file_collection_ignores_missing_and_non_text_paths() {
        let temporary = tempfile::TempDir::new().unwrap();
        let mut files = Vec::new();
        collect_public_text_files(
            temporary.path(),
            &temporary.path().join("missing"),
            &mut files,
        )
        .unwrap();
        let non_text = temporary.path().join("preview.bin");
        fs::write(&non_text, "Termivar").unwrap();
        collect_public_text_files(temporary.path(), &non_text, &mut files).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn public_path_normalization_rejects_paths_outside_the_workspace() {
        let workspace = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let error = normalized_relative_path(workspace.path(), outside.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("outside workspace root"));
    }

    #[test]
    fn former_word_matching_is_bounded_to_the_product_token() {
        assert!(contains_former_brand_word("Venom runtime"));
        assert!(contains_former_brand_word("VENOM is current"));
        assert!(contains_former_brand_word("venom is current"));
        assert!(contains_former_brand_word("the binary is venom."));
        assert!(contains_former_brand_word("(Venom)"));
        assert!(!contains_former_brand_word("Venomous input"));
        assert!(!contains_former_brand_word("FormerVenom"));
        assert!(!contains_former_brand_word("VENOM_SCHEMA/v1"));
        assert!(!contains_former_brand_word("venom.scan-profile/v1"));
        assert!(!contains_former_brand_word("venom-rendered-assessment/v1"));
        assert!(!contains_former_brand_word("venom:assessment-item:v1"));
        assert!(!contains_former_brand_word(
            "https://github.com/ITherso/venom"
        ));
    }

    #[test]
    fn changelog_scan_covers_only_unreleased_current_metadata() {
        let source = concat!(
            "# Changelog\n\n",
            "## [Unreleased]\n\nTermivar is current.\n",
            "## [0.9.0-alpha]\n\nVenom is historical.\n",
        );
        assert_eq!(
            current_public_text("CHANGELOG.md", source),
            "# Changelog\n\n## [Unreleased]\n\nTermivar is current."
        );
        assert!(public_text_brand_violations(
            "CHANGELOG.md",
            current_public_text("CHANGELOG.md", source)
        )
        .is_empty());

        let stale = source.replacen("Termivar is current.", "VENOM is current.", 1);
        assert_eq!(
            public_text_brand_violations(
                "CHANGELOG.md",
                current_public_text("CHANGELOG.md", &stale)
            )
            .len(),
            1
        );
    }
}
