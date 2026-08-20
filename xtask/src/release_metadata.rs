//! Tag-time release metadata validation.
//!
//! A tag is publishable only after its version has moved out of the Unreleased
//! changelog section and into the supported-version table. This keeps the
//! create-once release workflow from publishing generated notes for source that
//! still describes itself only as unreleased.

use cargo_metadata::MetadataCommand;
use std::{error::Error, fs, io, path::Path};

const VERSIONED_PACKAGES: &[&str] = &[
    "venom-api",
    "venom-cli",
    "venom-core",
    "venom-proxy",
    "venom-scanner",
];

pub(crate) fn check(workspace_root: &Path, version: &str) -> Result<(), Box<dyn Error>> {
    validate_version_token(version)?;

    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    for package_name in VERSIONED_PACKAGES {
        let package = metadata
            .workspace_packages()
            .into_iter()
            .find(|package| package.name.as_str() == *package_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("release package `{package_name}` is absent from the workspace"),
                )
            })?;
        if package.version.to_string() != version {
            return Err(format!(
                "release version `{version}` does not match {package_name} version `{}`",
                package.version
            )
            .into());
        }
    }

    let changelog = fs::read_to_string(workspace_root.join("CHANGELOG.md"))?;
    let security = fs::read_to_string(workspace_root.join("SECURITY.md"))?;
    let violations = metadata_violations(version, &changelog, &security);
    if violations.is_empty() {
        println!("release metadata passed for v{version}");
        return Ok(());
    }

    Err(violations.join("\n").into())
}

fn validate_version_token(version: &str) -> Result<(), Box<dyn Error>> {
    let valid = !version.is_empty()
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        && version.bytes().any(|byte| byte == b'.');
    if valid {
        Ok(())
    } else {
        Err(format!("invalid release version token `{version}`").into())
    }
}

fn metadata_violations(version: &str, changelog: &str, security: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let heading_prefix = format!("## [{version}] - ");
    let headings: Vec<_> = changelog
        .lines()
        .enumerate()
        .filter(|(_, line)| line.starts_with(&heading_prefix))
        .collect();

    if headings.len() != 1 {
        violations.push(format!(
            "CHANGELOG.md must contain exactly one dated `## [{version}] - YYYY-MM-DD` release heading"
        ));
    } else {
        let (heading_index, heading) = headings[0];
        let date = &heading[heading_prefix.len()..];
        if !is_iso_date(date) {
            violations.push(format!(
                "CHANGELOG.md release heading for `{version}` must use an ISO YYYY-MM-DD date"
            ));
        }

        let section = changelog
            .lines()
            .skip(heading_index + 1)
            .take_while(|line| !line.starts_with("## ["))
            .collect::<Vec<_>>()
            .join("\n");
        if !section.lines().any(|line| line.starts_with("### "))
            || !section.lines().any(|line| line.starts_with("- "))
        {
            violations.push(format!(
                "CHANGELOG.md release section for `{version}` must contain a category and at least one entry"
            ));
        }
        if version == "0.10.0-alpha.1"
            && (!section.contains("### Upgrade notes")
                || !section.contains("migrations/scan-context-construction.md"))
        {
            violations.push(
                "CHANGELOG.md 0.10.0-alpha.1 release section must include the ScanContext upgrade note and migration-guide link"
                    .to_owned(),
            );
        }
    }

    let release_link =
        format!("[{version}]: https://github.com/ITherso/venom/releases/tag/v{version}");
    if !changelog.lines().any(|line| line == release_link) {
        violations.push(format!(
            "CHANGELOG.md must define the exact `{release_link}` reference"
        ));
    }
    let compare_link =
        format!("[Unreleased]: https://github.com/ITherso/venom/compare/v{version}...HEAD");
    if !changelog.lines().any(|line| line == compare_link) {
        violations.push(format!(
            "CHANGELOG.md must advance the Unreleased comparison to `v{version}`"
        ));
    }

    let supported_row_prefix = format!("| `v{version}` | Yes |");
    if !security
        .lines()
        .any(|line| line.starts_with(&supported_row_prefix))
    {
        violations.push(format!(
            "SECURITY.md must list released `v{version}` as supported"
        ));
    }

    violations
}

fn is_iso_date(value: &str) -> bool {
    value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

#[cfg(test)]
mod tests {
    use super::metadata_violations;

    const VERSION: &str = "0.11.0-alpha.1";

    fn changelog() -> String {
        format!(
            "# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-08-14\n\n### Changed\n\n- Reviewed release.\n\n[Unreleased]: https://github.com/ITherso/venom/compare/v{VERSION}...HEAD\n[{VERSION}]: https://github.com/ITherso/venom/releases/tag/v{VERSION}\n"
        )
    }

    fn security() -> String {
        format!("## Supported versions\n\n| Version | Supported | Notes |\n| --- | --- | --- |\n| `v{VERSION}` | Yes | Current release |\n")
    }

    #[test]
    fn completed_release_metadata_is_accepted() {
        assert!(metadata_violations(VERSION, &changelog(), &security()).is_empty());
    }

    #[test]
    fn unreleased_only_changelog_is_rejected() {
        let changelog = changelog().replace(
            &format!("## [{VERSION}] - 2026-08-14"),
            "## [Unreleased copy]",
        );
        assert!(metadata_violations(VERSION, &changelog, &security())
            .iter()
            .any(|violation| violation.contains("dated")));
    }

    #[test]
    fn malformed_date_and_missing_supported_row_are_rejected() {
        let changelog = changelog().replace("2026-08-14", "14-08-2026");
        let violations = metadata_violations(VERSION, &changelog, "## Supported versions\n");
        assert!(violations.iter().any(|violation| violation.contains("ISO")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("as supported")));
    }

    #[test]
    fn current_scanner_transition_requires_upgrade_guidance() {
        let version = "0.10.0-alpha.1";
        let changelog = format!(
            "## [{version}] - 2026-08-14\n\n### Changed\n\n- Changed.\n\n[Unreleased]: https://github.com/ITherso/venom/compare/v{version}...HEAD\n[{version}]: https://github.com/ITherso/venom/releases/tag/v{version}\n"
        );
        let security = format!("| `v{version}` | Yes | Current release |\n");
        assert!(metadata_violations(version, &changelog, &security)
            .iter()
            .any(|violation| violation.contains("ScanContext")));
    }

    #[test]
    fn current_scanner_transition_accepts_the_required_migration_note() {
        let version = "0.10.0-alpha.1";
        let changelog = format!(
            "## [{version}] - 2026-08-14\n\n### Upgrade notes\n\n- Follow [the ScanContext migration](docs/migrations/scan-context-construction.md).\n\n[Unreleased]: https://github.com/ITherso/venom/compare/v{version}...HEAD\n[{version}]: https://github.com/ITherso/venom/releases/tag/v{version}\n"
        );
        let security = format!("| `v{version}` | Yes | Current release |\n");
        assert!(metadata_violations(version, &changelog, &security).is_empty());
    }
}
