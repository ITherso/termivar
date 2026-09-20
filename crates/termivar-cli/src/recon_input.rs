//! Bounded acquisition of one explicit local reconnaissance snapshot.
//!
//! The CLI owns filesystem authority and opens the selected path exactly once.
//! Only the scanner-owned, inert typed audit crosses into report composition;
//! the pathname and raw bytes are never retained there.

use std::{fmt, io::Read, path::PathBuf};

use termivar_scanner::recon_snapshot::{
    parse_recon_snapshot, ReconSnapshot, MAX_RECON_SNAPSHOT_BYTES,
};

use crate::auth_input::{self, AuthorizationInputError};

/// Deferred, explicit local-file selection. Construction performs no I/O.
pub(crate) struct ReconSnapshotInput {
    path: PathBuf,
}

impl ReconSnapshotInput {
    pub(crate) const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Opens, bounds, reads, and parses the selected file exactly once.
    pub(crate) fn load(self) -> Result<ReconSnapshot, ReconSnapshotInputError> {
        validate_explicit_local_file_path(&self.path)?;
        let mut file = auth_input::open_regular_file(self.path).map_err(map_open_error)?;
        let declared_length = file
            .metadata()
            .map_err(|_| ReconSnapshotInputError::Unavailable)?
            .len();
        if declared_length > u64::try_from(MAX_RECON_SNAPSHOT_BYTES).unwrap_or(u64::MAX) {
            return Err(ReconSnapshotInputError::TooLarge);
        }
        let retained_limit = MAX_RECON_SNAPSHOT_BYTES
            .checked_add(1)
            .ok_or(ReconSnapshotInputError::TooLarge)?;
        let initial_capacity = usize::try_from(declared_length)
            .unwrap_or(MAX_RECON_SNAPSHOT_BYTES)
            .min(MAX_RECON_SNAPSHOT_BYTES);
        let mut bytes = Vec::with_capacity(initial_capacity);
        file.by_ref()
            .take(u64::try_from(retained_limit).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|_| ReconSnapshotInputError::ReadFailed)?;
        if bytes.len() > MAX_RECON_SNAPSHOT_BYTES {
            return Err(ReconSnapshotInputError::TooLarge);
        }
        parse_recon_snapshot(&bytes).map_err(|_| ReconSnapshotInputError::InvalidDocument)
    }
}

impl fmt::Debug for ReconSnapshotInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconSnapshotInput")
            .field("path", &"<redacted>")
            .finish()
    }
}

/// Static, path-free acquisition failures safe for CLI error output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReconSnapshotInputError {
    Unavailable,
    NotRegular,
    TooLarge,
    ReadFailed,
    InvalidDocument,
}

impl fmt::Display for ReconSnapshotInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "reconnaissance snapshot source is unavailable",
            Self::NotRegular => "reconnaissance snapshot must be a regular local file",
            Self::TooLarge => "reconnaissance snapshot exceeds the compiled byte limit",
            Self::ReadFailed => "reconnaissance snapshot could not be read completely",
            Self::InvalidDocument => "reconnaissance snapshot document is invalid",
        })
    }
}

impl std::error::Error for ReconSnapshotInputError {}

fn validate_explicit_local_file_path(
    path: &std::path::Path,
) -> Result<(), ReconSnapshotInputError> {
    crate::report_compare::validate_local_path(path)
        .map_err(|_| ReconSnapshotInputError::Unavailable)?;
    let bytes = path.as_os_str().as_encoded_bytes();
    let final_component = bytes
        .rsplit(|byte| matches!(*byte, b'/' | b'\\'))
        .next()
        .unwrap_or_default();
    if final_component.is_empty()
        || matches!(final_component, b"." | b"..")
        || final_component.contains(&b'\0')
    {
        return Err(ReconSnapshotInputError::Unavailable);
    }
    Ok(())
}

fn map_open_error(error: AuthorizationInputError) -> ReconSnapshotInputError {
    match error {
        AuthorizationInputError::SourceNotRegularFile => ReconSnapshotInputError::NotRegular,
        AuthorizationInputError::SourceReadFailed => ReconSnapshotInputError::ReadFailed,
        AuthorizationInputError::ValueTooLarge => ReconSnapshotInputError::TooLarge,
        AuthorizationInputError::ConflictingSources
        | AuthorizationInputError::SourceNameInvalid
        | AuthorizationInputError::SourceUnavailable
        | AuthorizationInputError::SourceNotUnicode
        | AuthorizationInputError::InvalidValue => ReconSnapshotInputError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_path_is_redacted_and_open_is_deferred() {
        let selected = ReconSnapshotInput::new(PathBuf::from("private-recon-snapshot.json"));
        let debug = format!("{selected:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private-recon-snapshot.json"));
    }

    #[test]
    fn invalid_local_path_spellings_fail_without_opening() {
        for path in ["-", "https://example.test/recon.json", ".", ".."] {
            assert_eq!(
                validate_explicit_local_file_path(std::path::Path::new(path)),
                Err(ReconSnapshotInputError::Unavailable),
                "{path}"
            );
        }
    }

    #[test]
    fn errors_are_static_and_value_free() {
        for error in [
            ReconSnapshotInputError::Unavailable,
            ReconSnapshotInputError::NotRegular,
            ReconSnapshotInputError::TooLarge,
            ReconSnapshotInputError::ReadFailed,
            ReconSnapshotInputError::InvalidDocument,
        ] {
            let text = error.to_string();
            assert!(text.starts_with("reconnaissance snapshot"));
            assert!(!text.contains('/') && !text.contains('\\'));
        }
    }
}
