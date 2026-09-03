//! Tag-time release metadata validation.
//!
//! A tag is publishable only after its version has moved out of the Unreleased
//! changelog section, entered the supported-version table, and gained one
//! bounded curated release note. This keeps the create-once release workflow
//! from publishing source that still describes itself only as unreleased.

use cargo_metadata::MetadataCommand;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File},
    io::{Read, Result as IoResult},
    path::Path,
};

const CURRENT_RELEASE: &str = "0.10.0-alpha.1";
const CURRENT_RELEASE_DATE: &str = "2026-09-03";
const MAX_RELEASE_NOTE_BYTES: u64 = 128 * 1024;
const VERSIONED_PACKAGES: &[&str] = &[
    "termivar-api",
    "termivar-artifact",
    "termivar-cli",
    "termivar-core",
    "termivar-exploit",
    "termivar-proxy",
    "termivar-scanner",
];
const REQUIRED_CHANGELOG_SECTIONS: &[&str] =
    &["Upgrade notes", "Added", "Changed", "Fixed", "Security"];
const REQUIRED_RELEASE_NOTE_SECTIONS: &[&str] = &[
    "What this release is",
    "Highlights",
    "Included downloadable binary capabilities",
    "Evidence and claim model",
    "Upgrade from Venom",
    "Installation and verification",
    "Known limitations",
];

pub(crate) fn check(workspace_root: &Path, version: &str) -> Result<(), Box<dyn Error>> {
    validate_version_token(version)?;

    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let packages: BTreeMap<_, _> = metadata
        .workspace_packages()
        .into_iter()
        .map(|package| (package.name.to_string(), package.version.to_string()))
        .collect();

    let changelog = fs::read_to_string(workspace_root.join("CHANGELOG.md"))?;
    let security = fs::read_to_string(workspace_root.join("SECURITY.md"))?;
    let mut violations = package_version_violations(version, &packages);
    violations.extend(metadata_violations(version, &changelog, &security));
    violations.extend(release_note_file_violations(workspace_root, version));
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

fn package_version_violations(version: &str, packages: &BTreeMap<String, String>) -> Vec<String> {
    let mut violations = Vec::new();
    for package_name in VERSIONED_PACKAGES {
        match packages.get(*package_name) {
            None => violations.push(format!(
                "release package `{package_name}` is absent from the workspace"
            )),
            Some(package_version) if package_version != version => violations.push(format!(
                "release version `{version}` does not match {package_name} version `{package_version}`"
            )),
            Some(_) => {}
        }
    }
    violations
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
        } else if version == CURRENT_RELEASE && date != CURRENT_RELEASE_DATE {
            violations.push(format!(
                "CHANGELOG.md release heading for `{CURRENT_RELEASE}` must use `{CURRENT_RELEASE_DATE}`"
            ));
        }

        let section = changelog
            .lines()
            .skip(heading_index + 1)
            .take_while(|line| !line.starts_with("## ["))
            .collect::<Vec<_>>()
            .join("\n");
        validate_release_section(version, &section, &mut violations);
    }

    let release_link = if version == CURRENT_RELEASE {
        format!(
            "[{version}]: https://github.com/ITherso/termivar/compare/v0.9.0-alpha...v{version}"
        )
    } else {
        format!("[{version}]: https://github.com/ITherso/termivar/releases/tag/v{version}")
    };
    if !changelog.lines().any(|line| line == release_link) {
        violations.push(format!(
            "CHANGELOG.md must define the exact `{release_link}` reference"
        ));
    }
    let compare_link =
        format!("[Unreleased]: https://github.com/ITherso/termivar/compare/v{version}...HEAD");
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

fn validate_release_section(version: &str, section: &str, violations: &mut Vec<String>) {
    if version != CURRENT_RELEASE {
        if !section.lines().any(|line| line.starts_with("### "))
            || !section.lines().any(|line| line.starts_with("- "))
        {
            violations.push(format!(
                "CHANGELOG.md release section for `{version}` must contain a category and at least one entry"
            ));
        }
        return;
    }

    for required in REQUIRED_CHANGELOG_SECTIONS {
        let heading = format!("### {required}");
        match markdown_section(section, &heading) {
            None => violations.push(format!(
                "CHANGELOG.md `{CURRENT_RELEASE}` release section must contain `{heading}`"
            )),
            Some(body) if !body.lines().any(|line| line.starts_with("- ")) => {
                violations.push(format!(
                    "CHANGELOG.md `{CURRENT_RELEASE}` `{heading}` must contain at least one entry"
                ));
            },
            Some(_) => {},
        }
    }

    let upgrade = markdown_section(section, "### Upgrade notes").unwrap_or_default();
    for (needle, description) in [
        ("Venom", "former product name"),
        ("Termivar", "current product name"),
        ("`venom`", "former CLI name"),
        ("`termivar`", "current CLI name"),
        ("`venom-*`", "former package prefix"),
        ("`termivar-*`", "current package prefix"),
        ("`venom_*`", "former Rust crate prefix"),
        ("`termivar_*`", "current Rust crate prefix"),
        ("`VENOM_PERF_*`", "former performance environment prefix"),
        (
            "`TERMIVAR_PERF_*`",
            "current performance environment prefix",
        ),
        ("`.venom`", "former cache/container identity"),
        ("`.termivar`", "current cache/container identity"),
    ] {
        if !upgrade.contains(needle) {
            violations.push(format!(
                "CHANGELOG.md `{CURRENT_RELEASE}` Upgrade notes must mention the {description}"
            ));
        }
    }
    let upgrade_lower = upgrade.to_ascii_lowercase();
    for (needle, description) in [
        (
            "no legacy `venom` binary alias",
            "legacy-binary compatibility decision",
        ),
        ("stable", "stable compatibility-identity guidance"),
        ("historical", "historical provenance guidance"),
    ] {
        if !upgrade_lower.contains(needle) {
            violations.push(format!(
                "CHANGELOG.md `{CURRENT_RELEASE}` Upgrade notes must mention the {description}"
            ));
        }
    }
    for migration in [
        "docs/migrations/scan-context-construction.md",
        "docs/migrations/venom-to-termivar.md",
    ] {
        if !upgrade.contains(migration) {
            violations.push(format!(
                "CHANGELOG.md `{CURRENT_RELEASE}` Upgrade notes must link `{migration}`"
            ));
        }
    }
}

fn release_note_file_violations(workspace_root: &Path, version: &str) -> Vec<String> {
    let relative = format!(".github/release-notes/v{version}.md");
    let path = workspace_root.join(&relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return vec![format!(
                "release note `{relative}` must exist as a readable regular repository file"
            )];
        },
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return vec![format!(
            "release note `{relative}` must be a regular file, not a symlink or directory"
        )];
    }
    if metadata.len() > MAX_RELEASE_NOTE_BYTES {
        return vec![format!(
            "release note `{relative}` exceeds the {MAX_RELEASE_NOTE_BYTES}-byte limit"
        )];
    }

    let mut bytes = Vec::new();
    let read_result: IoResult<_> = File::open(&path).and_then(|file| {
        file.take(MAX_RELEASE_NOTE_BYTES + 1)
            .read_to_end(&mut bytes)
    });
    if read_result.is_err() {
        return vec![format!(
            "release note `{relative}` must exist as a readable regular repository file"
        )];
    }
    if bytes.len() as u64 > MAX_RELEASE_NOTE_BYTES {
        return vec![format!(
            "release note `{relative}` exceeds the {MAX_RELEASE_NOTE_BYTES}-byte limit"
        )];
    }
    let note = match std::str::from_utf8(&bytes) {
        Ok(note) => note,
        Err(_) => {
            return vec![format!("release note `{relative}` must be valid UTF-8")];
        },
    };
    release_note_text_violations(version, note)
}

fn release_note_text_violations(version: &str, note: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let expected_title = format!("# Termivar v{version}");
    if note.lines().next() != Some(expected_title.as_str()) {
        violations.push(format!(
            "release note must begin with the exact title `{expected_title}`"
        ));
    }
    if note.trim().is_empty() {
        violations.push("release note must not be empty".to_owned());
        return violations;
    }

    let normalized = note.lines().collect::<Vec<_>>().join("\n");
    let expected_callout = format!(
        "> [!IMPORTANT]\n> Termivar v{version} is an experimental prerelease. It is not\n> production-ready and has not completed an independent security audit. Use it\n> only on systems you own or are explicitly authorized to test."
    );
    if !normalized.contains(&expected_callout) {
        violations.push(
            "release note must contain the exact experimental, unaudited, authorization-only warning"
                .to_owned(),
        );
    }

    for required in REQUIRED_RELEASE_NOTE_SECTIONS {
        let heading = format!("## {required}");
        if markdown_section(&normalized, &heading).is_none() {
            violations.push(format!("release note must contain `{heading}`"));
        }
    }

    let lower = normalized.to_ascii_lowercase();
    for (claim, description) in [
        ("termivar is production-ready", "production readiness"),
        ("termivar is production ready", "production readiness"),
        ("ready for production", "production readiness"),
        (
            "termivar has completed an independent security audit",
            "completed independent audit",
        ),
        (
            "termivar is independently audited",
            "completed independent audit",
        ),
        ("termivar is a burp suite replacement", "Burp Suite parity"),
        ("termivar replaces burp suite", "Burp Suite parity"),
        ("provides generic waf bypass", "generic WAF bypass"),
        ("supports generic waf bypass", "generic WAF bypass"),
        ("reports confirmed idor", "confirmed IDOR"),
        ("provides confirmed idor", "confirmed IDOR"),
        ("reports confirmed bola", "confirmed BOLA"),
        ("provides confirmed bola", "confirmed BOLA"),
        (
            "provides browser-backed xss confirmation",
            "browser-backed XSS confirmation",
        ),
        ("includes real exploit modules", "real exploit modules"),
        ("includes the legacy scanner", "bundled legacy scanner"),
        ("bundles the legacy scanner", "bundled legacy scanner"),
        ("includes the api adapter", "bundled API adapter"),
        ("bundles the api adapter", "bundled API adapter"),
        ("includes the proxy adapter", "bundled proxy adapter"),
        ("bundles the proxy adapter", "bundled proxy adapter"),
    ] {
        if lower.contains(claim) {
            violations.push(format!("release note must not claim {description}"));
        }
    }
    if lower.contains(&format!("venom v{version}"))
        || lower.contains("venom is the current product")
        || lower.contains("current venom release")
    {
        violations.push("release note must not present Venom as the current product".to_owned());
    }

    violations
}

fn markdown_section(document: &str, heading: &str) -> Option<String> {
    let mut lines = document.lines();
    lines.find(|line| *line == heading)?;
    Some(
        lines
            .take_while(|line| !line.starts_with("## ") && !line.starts_with("### "))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_owned(),
    )
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
    use super::{
        metadata_violations, package_version_violations, release_note_file_violations,
        release_note_text_violations, validate_version_token, CURRENT_RELEASE,
        MAX_RELEASE_NOTE_BYTES, VERSIONED_PACKAGES,
    };
    use std::{collections::BTreeMap, fs, path::Path};
    use tempfile::tempdir;

    fn changelog() -> String {
        format!(
            "# Changelog\n\n## [Unreleased]\n\n## [{CURRENT_RELEASE}] - 2026-09-03\n\n### Upgrade notes\n\n- Venom is now Termivar: `venom` becomes `termivar`, `venom-*` becomes `termivar-*`, and `venom_*` becomes `termivar_*`.\n- Migrate `VENOM_PERF_*` to `TERMIVAR_PERF_*` and `.venom` to `.termivar`; no legacy `venom` binary alias is shipped. Stable compatibility identities remain intentional and historical provenance retains the former name.\n- Follow [ScanContext](docs/migrations/scan-context-construction.md) and [the identity migration](docs/migrations/venom-to-termivar.md).\n\n### Added\n\n- Added release behavior.\n\n### Changed\n\n- Changed release behavior.\n\n### Fixed\n\n- Fixed release behavior.\n\n### Security\n\n- Documented release boundaries.\n\n[Unreleased]: https://github.com/ITherso/termivar/compare/v{CURRENT_RELEASE}...HEAD\n[{CURRENT_RELEASE}]: https://github.com/ITherso/termivar/compare/v0.9.0-alpha...v{CURRENT_RELEASE}\n"
        )
    }

    fn security() -> String {
        format!(
            "## Supported versions\n\n| Version | Supported | Notes |\n| --- | --- | --- |\n| `v{CURRENT_RELEASE}` | Yes | Current prerelease |\n"
        )
    }

    fn release_note() -> String {
        format!(
            "# Termivar v{CURRENT_RELEASE}\n\n> [!IMPORTANT]\n> Termivar v{CURRENT_RELEASE} is an experimental prerelease. It is not\n> production-ready and has not completed an independent security audit. Use it\n> only on systems you own or are explicitly authorized to test.\n\n## What this release is\n\nBounded Preview software.\n\n## Highlights\n\nEvidence-first review.\n\n## Included downloadable binary capabilities\n\nApproved bounded capabilities.\n\n## Evidence and claim model\n\nObservations are not verdicts.\n\n## Upgrade from Venom\n\nUse `termivar`.\n\n## Installation and verification\n\nVerify SHA256SUMS.\n\n## Known limitations\n\nNo production guarantee.\n"
        )
    }

    fn packages() -> BTreeMap<String, String> {
        VERSIONED_PACKAGES
            .iter()
            .map(|name| ((*name).to_owned(), CURRENT_RELEASE.to_owned()))
            .collect()
    }

    #[test]
    fn completed_release_metadata_is_accepted() {
        let violations = metadata_violations(CURRENT_RELEASE, &changelog(), &security());
        assert!(violations.is_empty(), "{violations:?}");
        assert!(release_note_text_violations(CURRENT_RELEASE, &release_note()).is_empty());
        assert!(package_version_violations(CURRENT_RELEASE, &packages()).is_empty());
    }

    #[test]
    fn published_release_files_remain_valid_after_the_development_line_advances() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask must be inside the workspace");
        let changelog =
            fs::read_to_string(workspace.join("CHANGELOG.md")).expect("read repository changelog");
        let security =
            fs::read_to_string(workspace.join("SECURITY.md")).expect("read security policy");
        assert!(metadata_violations(CURRENT_RELEASE, &changelog, &security).is_empty());
        assert!(release_note_file_violations(workspace, CURRENT_RELEASE).is_empty());
    }

    #[test]
    fn unsafe_release_version_tokens_fail_before_path_construction() {
        for version in ["", "release", "../0.10.0", "0.10.0/notes", "0.10.0 alpha"] {
            assert!(
                validate_version_token(version).is_err(),
                "accepted `{version}`"
            );
        }
        assert!(validate_version_token(CURRENT_RELEASE).is_ok());
    }

    #[test]
    fn missing_or_duplicate_release_heading_is_rejected() {
        let missing = changelog().replace(
            &format!("## [{CURRENT_RELEASE}] - 2026-09-03"),
            "## [Unreleased copy]",
        );
        let duplicate = format!(
            "{}\n## [{CURRENT_RELEASE}] - 2026-09-03\n\n### Added\n\n- duplicate\n",
            changelog()
        );
        assert!(metadata_violations(CURRENT_RELEASE, &missing, &security())
            .iter()
            .any(|violation| violation.contains("exactly one dated")));
        assert!(
            metadata_violations(CURRENT_RELEASE, &duplicate, &security())
                .iter()
                .any(|violation| violation.contains("exactly one dated"))
        );
    }

    #[test]
    fn malformed_or_wrong_release_date_is_rejected() {
        for replacement in ["03-09-2026", "2026-09-02"] {
            let input = changelog().replace("2026-09-03", replacement);
            assert!(metadata_violations(CURRENT_RELEASE, &input, &security())
                .iter()
                .any(|violation| violation.contains("date") || violation.contains("2026-09-03")));
        }
    }

    #[test]
    fn every_required_changelog_category_needs_an_entry() {
        let missing = changelog().replace("### Fixed", "### Repairs");
        let empty = changelog().replace("- Documented release boundaries.", "No entry.");
        let empty_added = changelog().replace("- Added release behavior.", "No entry.");
        assert!(metadata_violations(CURRENT_RELEASE, &missing, &security())
            .iter()
            .any(|violation| violation.contains("### Fixed")));
        assert!(metadata_violations(CURRENT_RELEASE, &empty, &security())
            .iter()
            .any(|violation| violation.contains("### Security") && violation.contains("entry")));
        assert!(
            metadata_violations(CURRENT_RELEASE, &empty_added, &security())
                .iter()
                .any(|violation| violation.contains("### Added") && violation.contains("entry"))
        );
    }

    #[test]
    fn migration_links_and_upgrade_identity_are_required() {
        for required in [
            "docs/migrations/scan-context-construction.md",
            "docs/migrations/venom-to-termivar.md",
            "`TERMIVAR_PERF_*`",
            "no legacy `venom` binary alias",
        ] {
            let input = changelog().replace(required, "missing-required-release-guidance");
            assert!(metadata_violations(CURRENT_RELEASE, &input, &security())
                .iter()
                .any(|violation| violation.contains("Upgrade notes")));
        }

        let guidance_outside_upgrade = changelog().replace(
            "- Follow [ScanContext](docs/migrations/scan-context-construction.md) and [the identity migration](docs/migrations/venom-to-termivar.md).",
            "- Upgrade guidance is listed below.\n\n### Added\n\n- Follow [ScanContext](docs/migrations/scan-context-construction.md) and [the identity migration](docs/migrations/venom-to-termivar.md).",
        );
        assert!(
            metadata_violations(CURRENT_RELEASE, &guidance_outside_upgrade, &security())
                .iter()
                .any(|violation| violation.contains("Upgrade notes must link"))
        );
    }

    #[test]
    fn release_and_unreleased_compare_links_are_exact() {
        for required in [
            format!(
                "[{CURRENT_RELEASE}]: https://github.com/ITherso/termivar/compare/v0.9.0-alpha...v{CURRENT_RELEASE}"
            ),
            format!(
                "[Unreleased]: https://github.com/ITherso/termivar/compare/v{CURRENT_RELEASE}...HEAD"
            ),
        ] {
            let input = changelog().replace(&required, "[removed]: missing");
            assert!(!metadata_violations(CURRENT_RELEASE, &input, &security()).is_empty());
        }
    }

    #[test]
    fn released_version_must_be_supported() {
        assert!(
            metadata_violations(CURRENT_RELEASE, &changelog(), "## Supported versions")
                .iter()
                .any(|violation| violation.contains("as supported"))
        );
    }

    #[test]
    fn curated_note_title_warning_and_sections_are_exact() {
        let malformed_title = release_note().replacen("# Termivar", "# Venom", 1);
        assert!(
            release_note_text_violations(CURRENT_RELEASE, &malformed_title)
                .iter()
                .any(|violation| violation.contains("exact title"))
        );
        for removed in [
            "> [!IMPORTANT]",
            "only on systems you own or are explicitly authorized to test.",
            "## Upgrade from Venom",
            "## Known limitations",
        ] {
            let input = release_note().replace(removed, "removed-required-release-text");
            assert!(!release_note_text_violations(CURRENT_RELEASE, &input).is_empty());
        }
        assert!(release_note_text_violations(CURRENT_RELEASE, "")
            .iter()
            .any(|violation| violation.contains("must not be empty")));
    }

    #[test]
    fn prohibited_release_claims_fail_closed_without_rejecting_negations() {
        assert!(release_note_text_violations(CURRENT_RELEASE, &release_note()).is_empty());
        for claim in [
            "Termivar is production-ready.",
            "Termivar has completed an independent security audit.",
            "Termivar is a Burp Suite replacement.",
            "The binary includes the legacy scanner.",
            "The binary bundles the API adapter.",
            "The binary includes the proxy adapter.",
            "This provides confirmed IDOR.",
        ] {
            let input = format!("{}\n{claim}\n", release_note());
            assert!(
                !release_note_text_violations(CURRENT_RELEASE, &input).is_empty(),
                "claim should be rejected: {claim}"
            );
        }
    }

    #[test]
    fn stale_current_product_name_is_rejected_but_upgrade_history_is_allowed() {
        assert!(release_note_text_violations(CURRENT_RELEASE, &release_note()).is_empty());
        let stale = format!("{}\nVenom is the current product.\n", release_note());
        assert!(release_note_text_violations(CURRENT_RELEASE, &stale)
            .iter()
            .any(|violation| violation.contains("current product")));
    }

    #[test]
    fn missing_non_regular_invalid_and_oversized_note_files_are_rejected() {
        let root = tempdir().expect("temporary workspace");
        assert!(release_note_file_violations(root.path(), CURRENT_RELEASE)
            .iter()
            .any(|violation| violation.contains("must exist")));

        let notes = root.path().join(".github/release-notes");
        fs::create_dir_all(notes.join(format!("v{CURRENT_RELEASE}.md")))
            .expect("release-note directory fixture");
        assert!(release_note_file_violations(root.path(), CURRENT_RELEASE)
            .iter()
            .any(|violation| violation.contains("regular file")));
        fs::remove_dir(notes.join(format!("v{CURRENT_RELEASE}.md")))
            .expect("remove directory fixture");

        fs::write(
            notes.join(format!("v{CURRENT_RELEASE}.md")),
            [0xff, 0xfe, 0xfd],
        )
        .expect("invalid UTF-8 fixture");
        assert!(release_note_file_violations(root.path(), CURRENT_RELEASE)
            .iter()
            .any(|violation| violation.contains("UTF-8")));

        fs::write(
            notes.join(format!("v{CURRENT_RELEASE}.md")),
            vec![b'x'; MAX_RELEASE_NOTE_BYTES as usize + 1],
        )
        .expect("oversized fixture");
        assert!(release_note_file_violations(root.path(), CURRENT_RELEASE)
            .iter()
            .any(|violation| violation.contains("exceeds")));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_release_note_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("temporary workspace");
        let notes = root.path().join(".github/release-notes");
        fs::create_dir_all(&notes).expect("release-note directory");
        let target = root.path().join("outside.md");
        fs::write(&target, release_note()).expect("target note");
        symlink(&target, notes.join(format!("v{CURRENT_RELEASE}.md")))
            .expect("release-note symlink");
        assert!(release_note_file_violations(root.path(), CURRENT_RELEASE)
            .iter()
            .any(|violation| violation.contains("regular file")));
    }

    #[test]
    fn matching_curated_note_file_is_accepted() {
        let root = tempdir().expect("temporary workspace");
        let notes = root.path().join(".github/release-notes");
        fs::create_dir_all(&notes).expect("release-note directory");
        fs::write(notes.join(format!("v{CURRENT_RELEASE}.md")), release_note())
            .expect("release-note fixture");
        assert!(release_note_file_violations(root.path(), CURRENT_RELEASE).is_empty());
    }

    #[test]
    fn all_first_party_product_packages_must_match_the_release() {
        let mut missing = packages();
        missing.remove("termivar-artifact");
        assert!(package_version_violations(CURRENT_RELEASE, &missing)
            .iter()
            .any(
                |violation| violation.contains("termivar-artifact") && violation.contains("absent")
            ));

        let mut mismatch = packages();
        mismatch.insert("termivar-exploit".to_owned(), "0.9.0-alpha".to_owned());
        assert!(package_version_violations(CURRENT_RELEASE, &mismatch)
            .iter()
            .any(|violation| violation.contains("termivar-exploit")
                && violation.contains("0.9.0-alpha")));

        let mut ignored_non_product = packages();
        ignored_non_product.insert("termivar-examples".to_owned(), "0.0.0".to_owned());
        ignored_non_product.insert("xtask".to_owned(), "0.0.0".to_owned());
        assert!(package_version_violations(CURRENT_RELEASE, &ignored_non_product).is_empty());
    }
}
