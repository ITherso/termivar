//! Bounded local inputs for the opt-in WordPress evidence review.
//!
//! This CLI-owned module opens at most four explicit regular files. It passes
//! only scanner-validated values across the runtime boundary; paths and
//! filesystem authority are never retained by the assessment.

use std::{fmt, io::Read, path::PathBuf};

use sha2::{Digest, Sha256};
use termivar_scanner::wordpress_review::{
    parse_wordpress_advisory_catalog, parse_wordpress_context, parse_wordpress_saved_inventory,
    WordPressLocalInputClass, WordPressLocalInputProvenance, WordPressReviewInputs,
    MAX_WORDPRESS_SAVED_INVENTORY_BYTES, MAX_WORDPRESS_VERSION_BYTES,
};
use url::Url;

use crate::auth_input::{self, AuthorizationInputError};

pub(crate) const MAX_WORDPRESS_CONTEXT_BYTES: usize =
    termivar_scanner::wordpress_review::MAX_WORDPRESS_CONTEXT_BYTES;
pub(crate) const MAX_WORDPRESS_ADVISORIES_BYTES: usize =
    termivar_scanner::wordpress_review::MAX_WORDPRESS_ADVISORY_CATALOG_BYTES;
pub(crate) const MAX_WORDPRESS_INVENTORY_BYTES: usize = MAX_WORDPRESS_SAVED_INVENTORY_BYTES;
const MAX_WORDPRESS_CORE_VERSION_FILE_BYTES: usize = MAX_WORDPRESS_VERSION_BYTES + 2;

/// Deferred source selection. Construction performs no filesystem access.
pub(crate) struct WordPressReviewInput {
    context: Option<PathBuf>,
    advisories: Option<PathBuf>,
    plugins_json: Option<PathBuf>,
    themes_json: Option<PathBuf>,
    core_version_file: Option<PathBuf>,
}

impl fmt::Debug for WordPressReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WordPressReviewInput")
            .field("context", &self.context.as_ref().map(|_| "<redacted>"))
            .field(
                "advisories",
                &self.advisories.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "plugins_json",
                &self.plugins_json.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "themes_json",
                &self.themes_json.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "core_version_file",
                &self.core_version_file.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl WordPressReviewInput {
    /// Selects the optional files without reading either one. Enabling the
    /// review without local inputs remains meaningful because response-only
    /// WordPress signals are interpreted by the existing assessment.
    pub(crate) fn select(
        enabled: bool,
        context: Option<PathBuf>,
        advisories: Option<PathBuf>,
        plugins_json: Option<PathBuf>,
        themes_json: Option<PathBuf>,
        core_version_file: Option<PathBuf>,
    ) -> Result<Option<Self>, WordPressInputError> {
        let saved_inventory_selected =
            plugins_json.is_some() || themes_json.is_some() || core_version_file.is_some();
        if !enabled {
            return if context.is_some() || advisories.is_some() || saved_inventory_selected {
                Err(WordPressInputError::ExplicitEnableRequired)
            } else {
                Ok(None)
            };
        }
        if context.is_some() && saved_inventory_selected {
            return Err(WordPressInputError::ContextInventoryConflict);
        }
        Ok(Some(Self {
            context,
            advisories,
            plugins_json,
            themes_json,
            core_version_file,
        }))
    }

    /// Opens and parses each selected document exactly once before any
    /// credential or network construction. The context root must equal the
    /// invocation target after URL parsing and normalization.
    pub(crate) fn load(self, target: &Url) -> Result<WordPressReviewInputs, WordPressInputError> {
        let Self {
            context,
            advisories,
            plugins_json,
            themes_json,
            core_version_file,
        } = self;
        let context = context
            .map(|path| {
                let bytes = read_bounded_regular_file(path, MAX_WORDPRESS_CONTEXT_BYTES)
                    .map_err(WordPressInputError::ContextSource)?;
                let context = parse_wordpress_context(&bytes)
                    .map_err(|_| WordPressInputError::InvalidContext)?;
                if context.root_url() != target {
                    return Err(WordPressInputError::ContextRootMismatch);
                }
                Ok(context)
            })
            .transpose()?;
        let mut remaining_inventory_bytes = MAX_WORDPRESS_INVENTORY_BYTES;
        let plugins = capture_inventory_source(
            plugins_json,
            WordPressLocalInputClass::PluginsJson,
            &mut remaining_inventory_bytes,
            MAX_WORDPRESS_INVENTORY_BYTES,
        )
        .map_err(|error| inventory_source_error(WordPressLocalInputClass::PluginsJson, error))?;
        let themes = capture_inventory_source(
            themes_json,
            WordPressLocalInputClass::ThemesJson,
            &mut remaining_inventory_bytes,
            MAX_WORDPRESS_INVENTORY_BYTES,
        )
        .map_err(|error| inventory_source_error(WordPressLocalInputClass::ThemesJson, error))?;
        let core = capture_inventory_source(
            core_version_file,
            WordPressLocalInputClass::CoreVersionFile,
            &mut remaining_inventory_bytes,
            MAX_WORDPRESS_CORE_VERSION_FILE_BYTES,
        )
        .map_err(|error| {
            inventory_source_error(WordPressLocalInputClass::CoreVersionFile, error)
        })?;

        let catalog = advisories
            .map(|path| {
                let bytes = read_bounded_regular_file(path, MAX_WORDPRESS_ADVISORIES_BYTES)
                    .map_err(WordPressInputError::AdvisorySource)?;
                parse_wordpress_advisory_catalog(&bytes)
                    .map_err(|_| WordPressInputError::InvalidAdvisories)
            })
            .transpose()?;
        if let Some(context) = context {
            return Ok(WordPressReviewInputs::new(Some(context), catalog));
        }
        if plugins.is_some() || themes.is_some() || core.is_some() {
            let inventory = parse_wordpress_saved_inventory(
                target.clone(),
                plugins.as_ref().map(CapturedInventoryInput::bytes),
                themes.as_ref().map(CapturedInventoryInput::bytes),
                core.as_ref().map(CapturedInventoryInput::bytes),
            )
            .map_err(|_| WordPressInputError::InvalidSavedInventory)?;
            let provenance = [plugins.as_ref(), themes.as_ref(), core.as_ref()]
                .into_iter()
                .flatten()
                .map(CapturedInventoryInput::provenance)
                .collect();
            return WordPressReviewInputs::from_saved_inventory(inventory, catalog, provenance)
                .map_err(|_| WordPressInputError::InvalidSavedInventory);
        }
        Ok(WordPressReviewInputs::new(None, catalog))
    }
}

/// Static acquisition failures; no selected path or document text is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WordPressInputError {
    ExplicitEnableRequired,
    ContextInventoryConflict,
    ContextSource(WordPressFileError),
    AdvisorySource(WordPressFileError),
    PluginsSource(WordPressFileError),
    ThemesSource(WordPressFileError),
    CoreVersionSource(WordPressFileError),
    InventoryTooLarge,
    InvalidContext,
    ContextRootMismatch,
    InvalidAdvisories,
    InvalidSavedInventory,
}

impl fmt::Display for WordPressInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExplicitEnableRequired => {
                "WordPress inputs require explicit `--wordpress-review`"
            },
            Self::ContextInventoryConflict => {
                "saved WordPress inventory inputs conflict with `--wordpress-context`"
            },
            Self::ContextSource(_) => "WordPress context must be a bounded regular local file",
            Self::AdvisorySource(_) => {
                "WordPress advisory catalogue must be a bounded regular local file"
            },
            Self::PluginsSource(_) => {
                "WordPress plugin inventory must be a bounded regular local file"
            },
            Self::ThemesSource(_) => {
                "WordPress theme inventory must be a bounded regular local file"
            },
            Self::CoreVersionSource(_) => {
                "WordPress core version must be a bounded regular local file"
            },
            Self::InventoryTooLarge => "saved WordPress inventory exceeds its aggregate byte limit",
            Self::InvalidContext => "WordPress context document is invalid",
            Self::ContextRootMismatch => {
                "WordPress context root must match the exact assessment target"
            },
            Self::InvalidAdvisories => "WordPress advisory catalogue is invalid",
            Self::InvalidSavedInventory => "saved WordPress inventory is invalid",
        })
    }
}

impl std::error::Error for WordPressInputError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WordPressFileError {
    Unavailable,
    NotRegular,
    TooLarge,
    ReadFailed,
}

struct CapturedInventoryInput {
    class: WordPressLocalInputClass,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

enum InventoryCaptureError {
    File(WordPressFileError),
    AggregateTooLarge,
}

impl CapturedInventoryInput {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn provenance(&self) -> WordPressLocalInputProvenance {
        WordPressLocalInputProvenance::new(self.class, self.bytes.len(), self.sha256)
    }
}

fn capture_inventory_source(
    path: Option<PathBuf>,
    class: WordPressLocalInputClass,
    remaining_bytes: &mut usize,
    per_file_limit: usize,
) -> Result<Option<CapturedInventoryInput>, InventoryCaptureError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let aggregate_limit_is_tighter = *remaining_bytes <= per_file_limit;
    let limit = (*remaining_bytes).min(per_file_limit);
    let bytes = read_bounded_regular_file(path, limit).map_err(|error| {
        if error == WordPressFileError::TooLarge && aggregate_limit_is_tighter {
            InventoryCaptureError::AggregateTooLarge
        } else {
            InventoryCaptureError::File(error)
        }
    })?;
    *remaining_bytes = remaining_bytes
        .checked_sub(bytes.len())
        .ok_or(InventoryCaptureError::AggregateTooLarge)?;
    let sha256 = Sha256::digest(&bytes).into();
    Ok(Some(CapturedInventoryInput {
        class,
        bytes,
        sha256,
    }))
}

fn inventory_source_error(
    class: WordPressLocalInputClass,
    error: InventoryCaptureError,
) -> WordPressInputError {
    let InventoryCaptureError::File(error) = error else {
        return WordPressInputError::InventoryTooLarge;
    };
    match class {
        WordPressLocalInputClass::PluginsJson => WordPressInputError::PluginsSource(error),
        WordPressLocalInputClass::ThemesJson => WordPressInputError::ThemesSource(error),
        WordPressLocalInputClass::CoreVersionFile => WordPressInputError::CoreVersionSource(error),
    }
}

fn read_bounded_regular_file(
    path: PathBuf,
    max_bytes: usize,
) -> Result<Vec<u8>, WordPressFileError> {
    validate_explicit_local_file_path(&path)?;
    let mut file = auth_input::open_regular_file(path).map_err(map_open_error)?;
    let declared_length = file
        .metadata()
        .map_err(|_| WordPressFileError::Unavailable)?
        .len();
    if declared_length > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(WordPressFileError::TooLarge);
    }

    let retained_limit = max_bytes
        .checked_add(1)
        .ok_or(WordPressFileError::TooLarge)?;
    let initial_capacity = usize::try_from(declared_length)
        .unwrap_or(max_bytes)
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.by_ref()
        .take(u64::try_from(retained_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| WordPressFileError::ReadFailed)?;
    if bytes.len() > max_bytes {
        return Err(WordPressFileError::TooLarge);
    }
    Ok(bytes)
}

fn validate_explicit_local_file_path(path: &std::path::Path) -> Result<(), WordPressFileError> {
    // Apply the same URL/stdin/UNC/device/stream rejection used by the offline
    // report commands before asking the operating system to open anything.
    crate::report_compare::validate_local_path(path)
        .map_err(|_| WordPressFileError::Unavailable)?;

    // A selected input must also name an ordinary final component. Parent
    // components remain a caller-trusted boundary, as documented; this check
    // only rejects path spellings that cannot designate that final file.
    let bytes = path.as_os_str().as_encoded_bytes();
    let final_component = bytes
        .rsplit(|byte| matches!(*byte, b'/' | b'\\'))
        .next()
        .unwrap_or_default();
    if final_component.is_empty()
        || matches!(final_component, b"." | b"..")
        || final_component.contains(&b'\0')
    {
        return Err(WordPressFileError::Unavailable);
    }
    Ok(())
}

fn map_open_error(error: AuthorizationInputError) -> WordPressFileError {
    match error {
        AuthorizationInputError::SourceNotRegularFile => WordPressFileError::NotRegular,
        AuthorizationInputError::SourceReadFailed => WordPressFileError::ReadFailed,
        AuthorizationInputError::ValueTooLarge => WordPressFileError::TooLarge,
        AuthorizationInputError::ConflictingSources
        | AuthorizationInputError::SourceNameInvalid
        | AuthorizationInputError::SourceUnavailable
        | AuthorizationInputError::SourceNotUnicode
        | AuthorizationInputError::InvalidValue => WordPressFileError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_uses_the_scanner_owned_document_ceilings() {
        assert_eq!(MAX_WORDPRESS_CONTEXT_BYTES, 1024 * 1024);
        assert_eq!(MAX_WORDPRESS_ADVISORIES_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_WORDPRESS_INVENTORY_BYTES, 1024 * 1024);
        assert_eq!(MAX_WORDPRESS_CORE_VERSION_FILE_BYTES, 66);
    }

    #[test]
    fn selection_is_explicit_lazy_and_path_redacted() {
        assert!(
            WordPressReviewInput::select(false, None, None, None, None, None)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            WordPressReviewInput::select(
                false,
                Some(PathBuf::from("private-context")),
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            WordPressInputError::ExplicitEnableRequired
        );
        let selected = WordPressReviewInput::select(
            true,
            Some(PathBuf::from("PRIVATE-CONTEXT-PATH")),
            Some(PathBuf::from("PRIVATE-ADVISORY-PATH")),
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{selected:?}");
        assert!(!debug.contains("PRIVATE-CONTEXT-PATH"));
        assert!(!debug.contains("PRIVATE-ADVISORY-PATH"));
        assert!(
            WordPressReviewInput::select(true, None, None, None, None, None)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            WordPressReviewInput::select(
                true,
                Some(PathBuf::from("PRIVATE-CONTEXT")),
                None,
                Some(PathBuf::from("PRIVATE-PLUGINS")),
                None,
                None,
            )
            .unwrap_err(),
            WordPressInputError::ContextInventoryConflict
        );
    }

    #[test]
    fn bounded_reader_accepts_the_limit_and_rejects_one_more_byte() {
        let directory = tempfile::tempdir().unwrap();
        let exact = directory.path().join("exact.json");
        let oversized = directory.path().join("oversized.json");
        std::fs::write(&exact, vec![b'x'; 64]).unwrap();
        std::fs::write(&oversized, vec![b'x'; 65]).unwrap();
        assert_eq!(read_bounded_regular_file(exact, 64).unwrap().len(), 64);
        assert_eq!(
            read_bounded_regular_file(oversized, 64).unwrap_err(),
            WordPressFileError::TooLarge
        );
    }

    #[test]
    fn missing_and_non_regular_sources_are_typed_without_paths() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("PRIVATE-WORDPRESS-PATH");
        let error = read_bounded_regular_file(private, 64).unwrap_err();
        assert_eq!(error, WordPressFileError::Unavailable);
        assert!(!format!("{error:?}").contains("PRIVATE-WORDPRESS-PATH"));

        let error = read_bounded_regular_file(directory.path().to_path_buf(), 64).unwrap_err();
        assert_eq!(error, WordPressFileError::NotRegular);
    }

    #[test]
    fn explicit_local_file_policy_rejects_urls_streams_unc_devices_and_bad_final_components() {
        for value in [
            "",
            "-",
            "https://example.test/PRIVATE.json",
            "file:/PRIVATE.json",
            "data:PRIVATE",
            "//server/share/PRIVATE.json",
            r"\\server\share\PRIVATE.json",
            r"\\.\pipe\PRIVATE",
            r"\\?\C:\PRIVATE.json",
            r"C:\PRIVATE.json:stream",
            "C:PRIVATE.json",
            ".",
            "..",
            "/",
            "input/",
            "bad\0name",
        ] {
            assert_eq!(
                validate_explicit_local_file_path(std::path::Path::new(value)),
                Err(WordPressFileError::Unavailable),
                "unexpectedly accepted {value:?}"
            );
        }
        for value in [
            "wordpress.json",
            "./wordpress.json",
            "../wordpress.json",
            "/tmp/wordpress.json",
            r"C:\reports\wordpress.json",
            "C:/reports/wordpress.json",
        ] {
            assert_eq!(
                validate_explicit_local_file_path(std::path::Path::new(value)),
                Ok(()),
                "unexpectedly rejected {value:?}"
            );
        }
    }

    #[test]
    fn explicit_non_local_spelling_is_rejected_before_open_and_remains_redacted() {
        let path = PathBuf::from("https://PRIVATE-WORDPRESS-HOST/input.json");
        let error = read_bounded_regular_file(path, 64).unwrap_err();
        assert_eq!(error, WordPressFileError::Unavailable);
        assert!(!format!("{error:?}").contains("PRIVATE-WORDPRESS-HOST"));
    }

    #[test]
    fn public_errors_never_echo_paths_or_document_text() {
        for error in [
            WordPressInputError::ContextSource(WordPressFileError::Unavailable),
            WordPressInputError::AdvisorySource(WordPressFileError::ReadFailed),
            WordPressInputError::PluginsSource(WordPressFileError::Unavailable),
            WordPressInputError::ThemesSource(WordPressFileError::ReadFailed),
            WordPressInputError::CoreVersionSource(WordPressFileError::NotRegular),
            WordPressInputError::InventoryTooLarge,
            WordPressInputError::InvalidContext,
            WordPressInputError::ContextRootMismatch,
            WordPressInputError::InvalidAdvisories,
            WordPressInputError::InvalidSavedInventory,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("PRIVATE"));
            assert!(!rendered.contains('{'));
            assert!(rendered.len() < 96);
        }
    }

    #[test]
    fn documented_context_and_catalogue_load_as_validated_values() {
        let directory = tempfile::tempdir().unwrap();
        let context_path = directory.path().join("context.json");
        let advisory_path = directory.path().join("advisories.json");
        std::fs::write(
            &context_path,
            include_bytes!("../../../docs/examples/wordpress-review/context.synthetic.json"),
        )
        .unwrap();
        std::fs::write(
            &advisory_path,
            include_bytes!("../../../docs/examples/wordpress-review/advisories.synthetic.json"),
        )
        .unwrap();

        let selected = WordPressReviewInput::select(
            true,
            Some(context_path),
            Some(advisory_path),
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let inputs = selected
            .load(&Url::parse("https://example.test/").unwrap())
            .unwrap();
        assert_eq!(inputs.context().unwrap().components().len(), 4);
        assert_eq!(inputs.catalog().unwrap().records().len(), 3);
    }

    #[test]
    fn context_root_must_equal_the_normalized_invocation_target() {
        let directory = tempfile::tempdir().unwrap();
        let context_path = directory.path().join("PRIVATE-CONTEXT.json");
        std::fs::write(
            &context_path,
            include_bytes!("../../../docs/examples/wordpress-review/context.synthetic.json"),
        )
        .unwrap();
        let selected =
            WordPressReviewInput::select(true, Some(context_path), None, None, None, None)
                .unwrap()
                .unwrap();
        assert_eq!(
            selected
                .load(&Url::parse("https://other.example.test/").unwrap())
                .unwrap_err(),
            WordPressInputError::ContextRootMismatch
        );
    }

    #[test]
    fn response_only_review_has_no_local_values_or_filesystem_authority() {
        let selected = WordPressReviewInput::select(true, None, None, None, None, None)
            .unwrap()
            .unwrap();
        let inputs = selected
            .load(&Url::parse("https://example.test/").unwrap())
            .unwrap();
        assert!(inputs.context().is_none());
        assert!(inputs.catalog().is_none());
    }

    #[test]
    fn saved_inventory_is_hashed_from_exact_bytes_and_bound_to_the_target() {
        use termivar_scanner::wordpress_review::{
            WordPressInventoryCategoryStatus, WordPressLocalInputClass,
        };

        let directory = tempfile::tempdir().unwrap();
        let plugins_path = directory.path().join("PRIVATE-PLUGINS.json");
        let themes_path = directory.path().join("PRIVATE-THEMES.json");
        let core_path = directory.path().join("PRIVATE-CORE.txt");
        let plugins = br#"[{"name":"example-plugin","status":"active","version":"1.2.3"}]"#;
        let themes = br#"[{"name":"example-theme","status":"parent","version":"2.0"}]"#;
        let core = b"6.9.4\r\n";
        std::fs::write(&plugins_path, plugins).unwrap();
        std::fs::write(&themes_path, themes).unwrap();
        std::fs::write(&core_path, core).unwrap();

        let selected = WordPressReviewInput::select(
            true,
            None,
            None,
            Some(plugins_path),
            Some(themes_path),
            Some(core_path),
        )
        .unwrap()
        .unwrap();
        let inputs = selected
            .load(&Url::parse("https://example.test/").unwrap())
            .unwrap();
        let summary = inputs.inventory_summary().unwrap();
        assert_eq!(summary.component_count(), 3);
        assert_eq!(
            summary.coverage().plugins(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(
            summary.coverage().themes(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(
            summary.coverage().core(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(
            inputs.context().unwrap().root_url().as_str(),
            "https://example.test/"
        );

        let provenance = inputs.local_input_provenance();
        assert_eq!(provenance.len(), 3);
        for (class, bytes) in [
            (WordPressLocalInputClass::PluginsJson, plugins.as_slice()),
            (WordPressLocalInputClass::ThemesJson, themes.as_slice()),
            (WordPressLocalInputClass::CoreVersionFile, core.as_slice()),
        ] {
            let entry = provenance
                .iter()
                .find(|entry| entry.class() == class)
                .unwrap();
            assert_eq!(entry.byte_length(), bytes.len());
            let expected: [u8; 32] = Sha256::digest(bytes).into();
            assert_eq!(entry.sha256(), &expected);
        }
    }

    #[test]
    fn aggregate_inventory_limit_is_enforced_while_acquiring_sources() {
        let directory = tempfile::tempdir().unwrap();
        let plugins_path = directory.path().join("plugins.json");
        let themes_path = directory.path().join("themes.json");
        std::fs::write(
            &plugins_path,
            vec![b' '; MAX_WORDPRESS_INVENTORY_BYTES / 2 + 1],
        )
        .unwrap();
        std::fs::write(
            &themes_path,
            vec![b' '; MAX_WORDPRESS_INVENTORY_BYTES / 2 + 1],
        )
        .unwrap();
        let selected = WordPressReviewInput::select(
            true,
            None,
            None,
            Some(plugins_path),
            Some(themes_path),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected
                .load(&Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            WordPressInputError::InventoryTooLarge
        );
    }
}
