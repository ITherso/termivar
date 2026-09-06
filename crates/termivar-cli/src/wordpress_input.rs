//! Bounded local inputs for the opt-in WordPress evidence review.
//!
//! This CLI-owned module opens at most two explicit regular files. It passes
//! only scanner-validated values across the runtime boundary; paths and
//! filesystem authority are never retained by the assessment.

use std::{fmt, io::Read, path::PathBuf};

use termivar_scanner::wordpress_review::{
    parse_wordpress_advisory_catalog, parse_wordpress_context, WordPressReviewInputs,
};
use url::Url;

use crate::auth_input::{self, AuthorizationInputError};

pub(crate) const MAX_WORDPRESS_CONTEXT_BYTES: usize =
    termivar_scanner::wordpress_review::MAX_WORDPRESS_CONTEXT_BYTES;
pub(crate) const MAX_WORDPRESS_ADVISORIES_BYTES: usize =
    termivar_scanner::wordpress_review::MAX_WORDPRESS_ADVISORY_CATALOG_BYTES;

/// Deferred source selection. Construction performs no filesystem access.
pub(crate) struct WordPressReviewInput {
    context: Option<PathBuf>,
    advisories: Option<PathBuf>,
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
    ) -> Result<Option<Self>, WordPressInputError> {
        if !enabled {
            return if context.is_some() || advisories.is_some() {
                Err(WordPressInputError::ExplicitEnableRequired)
            } else {
                Ok(None)
            };
        }
        Ok(Some(Self {
            context,
            advisories,
        }))
    }

    /// Opens and parses each selected document exactly once before any
    /// credential or network construction. The context root must equal the
    /// invocation target after URL parsing and normalization.
    pub(crate) fn load(self, target: &Url) -> Result<WordPressReviewInputs, WordPressInputError> {
        let context = self
            .context
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
        let catalog = self
            .advisories
            .map(|path| {
                let bytes = read_bounded_regular_file(path, MAX_WORDPRESS_ADVISORIES_BYTES)
                    .map_err(WordPressInputError::AdvisorySource)?;
                parse_wordpress_advisory_catalog(&bytes)
                    .map_err(|_| WordPressInputError::InvalidAdvisories)
            })
            .transpose()?;
        Ok(WordPressReviewInputs::new(context, catalog))
    }
}

/// Static acquisition failures; no selected path or document text is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WordPressInputError {
    ExplicitEnableRequired,
    ContextSource(WordPressFileError),
    AdvisorySource(WordPressFileError),
    InvalidContext,
    ContextRootMismatch,
    InvalidAdvisories,
}

impl fmt::Display for WordPressInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExplicitEnableRequired => {
                "WordPress inputs require explicit `--wordpress-review`"
            },
            Self::ContextSource(_) => "WordPress context must be a bounded regular local file",
            Self::AdvisorySource(_) => {
                "WordPress advisory catalogue must be a bounded regular local file"
            },
            Self::InvalidContext => "WordPress context document is invalid",
            Self::ContextRootMismatch => {
                "WordPress context root must match the exact assessment target"
            },
            Self::InvalidAdvisories => "WordPress advisory catalogue is invalid",
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

fn read_bounded_regular_file(
    path: PathBuf,
    max_bytes: usize,
) -> Result<Vec<u8>, WordPressFileError> {
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
    }

    #[test]
    fn selection_is_explicit_lazy_and_path_redacted() {
        assert!(WordPressReviewInput::select(false, None, None)
            .unwrap()
            .is_none());
        assert_eq!(
            WordPressReviewInput::select(false, Some(PathBuf::from("private-context")), None)
                .unwrap_err(),
            WordPressInputError::ExplicitEnableRequired
        );
        let selected = WordPressReviewInput::select(
            true,
            Some(PathBuf::from("PRIVATE-CONTEXT-PATH")),
            Some(PathBuf::from("PRIVATE-ADVISORY-PATH")),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{selected:?}");
        assert!(!debug.contains("PRIVATE-CONTEXT-PATH"));
        assert!(!debug.contains("PRIVATE-ADVISORY-PATH"));
        assert!(WordPressReviewInput::select(true, None, None)
            .unwrap()
            .is_some());
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
    fn public_errors_never_echo_paths_or_document_text() {
        for error in [
            WordPressInputError::ContextSource(WordPressFileError::Unavailable),
            WordPressInputError::AdvisorySource(WordPressFileError::ReadFailed),
            WordPressInputError::InvalidContext,
            WordPressInputError::ContextRootMismatch,
            WordPressInputError::InvalidAdvisories,
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

        let selected = WordPressReviewInput::select(true, Some(context_path), Some(advisory_path))
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
        let selected = WordPressReviewInput::select(true, Some(context_path), None)
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
        let selected = WordPressReviewInput::select(true, None, None)
            .unwrap()
            .unwrap();
        let inputs = selected
            .load(&Url::parse("https://example.test/").unwrap())
            .unwrap();
        assert!(inputs.context().is_none());
        assert!(inputs.catalog().is_none());
    }
}
