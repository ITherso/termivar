//! Bounded, redacted authorization-context input for the opt-in web review.
//!
//! This module is the only CLI boundary that reads credential material. It
//! never accepts a credential as a command-line value, never serializes or
//! logs one, and converts the bounded bytes directly into the scanner-owned
//! authorization-context contract.

use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

use venom_scanner::web_runtime::WebAssessmentRootAuthorizationContext;

/// The CLI deliberately uses the standard payload-strategy seed ceiling.
pub(crate) const MAX_AUTHORIZATION_CONTEXT_BYTES: usize = 4 * 1024;

/// One explicit out-of-band source for a complete Authorization header value.
///
/// Source identifiers and paths are redacted as well as the value. This type
/// intentionally implements neither `Clone` nor `Serialize`.
pub(crate) enum AuthorizationInputSource {
    Environment(OsString),
    File(PathBuf),
    Stdin,
}

impl fmt::Debug for AuthorizationInputSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match self {
            Self::Environment(_) => "environment",
            Self::File(_) => "file",
            Self::Stdin => "stdin",
        };
        formatter
            .debug_struct("AuthorizationInputSource")
            .field("source", &source)
            .field("location", &"<redacted>")
            .finish()
    }
}

impl AuthorizationInputSource {
    /// Selects zero or one source without reading it.
    pub(crate) fn select(
        environment: Option<OsString>,
        file: Option<PathBuf>,
        stdin: bool,
    ) -> Result<Option<Self>, AuthorizationInputError> {
        let selected = usize::from(environment.is_some())
            .saturating_add(usize::from(file.is_some()))
            .saturating_add(usize::from(stdin));
        if selected > 1 {
            return Err(AuthorizationInputError::ConflictingSources);
        }
        Ok(match (environment, file, stdin) {
            (Some(name), None, false) => Some(Self::Environment(name)),
            (None, Some(path), false) => Some(Self::File(path)),
            (None, None, true) => Some(Self::Stdin),
            (None, None, false) => None,
            _ => return Err(AuthorizationInputError::ConflictingSources),
        })
    }

    /// Reads and validates the selected source exactly once.
    pub(crate) fn load(
        self,
    ) -> Result<WebAssessmentRootAuthorizationContext, AuthorizationInputError> {
        let bytes = match self {
            Self::Environment(name) => read_environment(name)?,
            Self::File(path) => {
                let mut file =
                    File::open(path).map_err(|_| AuthorizationInputError::SourceUnavailable)?;
                read_bounded_line_source(&mut file)?
            },
            Self::Stdin => {
                let stdin = io::stdin();
                let mut input = stdin.lock();
                read_bounded_line_source(&mut input)?
            },
        };
        WebAssessmentRootAuthorizationContext::new(bytes)
            .map_err(|_| AuthorizationInputError::InvalidValue)
    }
}

/// Static, credential-free authorization input failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationInputError {
    ConflictingSources,
    SourceNameInvalid,
    SourceUnavailable,
    SourceNotUnicode,
    SourceReadFailed,
    ValueTooLarge,
    InvalidValue,
}

impl fmt::Display for AuthorizationInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConflictingSources => "select exactly one authorization-context input source",
            Self::SourceNameInvalid => "authorization-context environment name is invalid",
            Self::SourceUnavailable => "authorization-context input source is unavailable",
            Self::SourceNotUnicode => {
                "authorization-context environment value is not valid Unicode"
            },
            Self::SourceReadFailed => "authorization-context input source could not be read",
            Self::ValueTooLarge => "authorization-context value exceeds the compiled byte limit",
            Self::InvalidValue => "authorization-context value is not a safe HTTP header value",
        })
    }
}

impl std::error::Error for AuthorizationInputError {}

fn read_environment(name: OsString) -> Result<Vec<u8>, AuthorizationInputError> {
    let name = name
        .into_string()
        .map_err(|_| AuthorizationInputError::SourceNameInvalid)?;
    if name.is_empty()
        || name
            .chars()
            .any(|character| matches!(character, '=' | '\0'))
    {
        return Err(AuthorizationInputError::SourceNameInvalid);
    }
    let value = std::env::var_os(name).ok_or(AuthorizationInputError::SourceUnavailable)?;
    let value = value
        .into_string()
        .map_err(|_| AuthorizationInputError::SourceNotUnicode)?;
    let bytes = value.into_bytes();
    if bytes.len() > MAX_AUTHORIZATION_CONTEXT_BYTES {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    Ok(bytes)
}

/// Reads at most the credential ceiling plus one terminal CRLF and then probes
/// for one additional byte so a longer stream cannot masquerade as an exact
/// `MAX + CRLF` value. Only one terminal LF or CRLF is removed; no trimming or
/// lossy decoding occurs.
fn read_bounded_line_source(reader: &mut impl Read) -> Result<Vec<u8>, AuthorizationInputError> {
    let retained_limit = MAX_AUTHORIZATION_CONTEXT_BYTES.saturating_add(2);
    let mut bytes = Vec::with_capacity(retained_limit);
    reader
        .by_ref()
        .take(u64::try_from(retained_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorizationInputError::SourceReadFailed)?;

    let mut overflow = [0_u8; 1];
    if reader
        .read(&mut overflow)
        .map_err(|_| AuthorizationInputError::SourceReadFailed)?
        != 0
    {
        return Err(AuthorizationInputError::ValueTooLarge);
    }

    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len().saturating_sub(2));
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len().saturating_sub(1));
    }
    if bytes.len() > MAX_AUTHORIZATION_CONTEXT_BYTES {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::*;

    #[test]
    fn source_selection_is_exact_and_debug_is_redacted() {
        assert!(AuthorizationInputSource::select(None, None, false)
            .unwrap()
            .is_none());
        let source = AuthorizationInputSource::select(
            Some(OsString::from("AUTH_SOURCE_NAME_SENTINEL")),
            None,
            false,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{source:?}");
        assert!(debug.contains("environment"));
        assert!(!debug.contains("AUTH_SOURCE_NAME_SENTINEL"));

        let error = AuthorizationInputSource::select(
            Some(OsString::from("first")),
            Some(PathBuf::from("second-secret-path")),
            false,
        )
        .unwrap_err();
        assert_eq!(error, AuthorizationInputError::ConflictingSources);
        assert!(!error.to_string().contains("first"));
        assert!(!error.to_string().contains("second-secret-path"));
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_one_line_ending() {
        let exact = vec![b'a'; MAX_AUTHORIZATION_CONTEXT_BYTES];
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(exact.clone())).unwrap(),
            exact
        );

        let mut lf = exact.clone();
        lf.push(b'\n');
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(lf)).unwrap(),
            exact
        );

        let mut crlf = exact.clone();
        crlf.extend_from_slice(b"\r\n");
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(crlf)).unwrap(),
            exact
        );
    }

    #[test]
    fn invalid_environment_names_fail_without_calling_the_process_environment() {
        for name in ["", "INVALID=NAME", "INVALID\0NAME"] {
            assert_eq!(
                read_environment(OsString::from(name)).unwrap_err(),
                AuthorizationInputError::SourceNameInvalid
            );
        }
    }

    #[test]
    fn bounded_reader_rejects_oversize_and_data_after_allowed_crlf() {
        let oversized = vec![b'a'; MAX_AUTHORIZATION_CONTEXT_BYTES + 1];
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(oversized)).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );

        let mut disguised = vec![b'a'; MAX_AUTHORIZATION_CONTEXT_BYTES];
        disguised.extend_from_slice(b"\r\nextra");
        assert_eq!(
            read_bounded_line_source(&mut Cursor::new(disguised)).unwrap_err(),
            AuthorizationInputError::ValueTooLarge
        );
    }

    #[test]
    fn bounded_reader_removes_only_one_terminal_line_ending() {
        let value = read_bounded_line_source(&mut Cursor::new(b" Bearer token \n\n")).unwrap();
        assert_eq!(value, b" Bearer token \n");
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("PRIVATE_SOURCE_DIAGNOSTIC"))
        }
    }

    #[test]
    fn read_failures_discard_private_diagnostics() {
        let error = read_bounded_line_source(&mut FailingReader).unwrap_err();
        assert_eq!(error, AuthorizationInputError::SourceReadFailed);
        assert!(!error.to_string().contains("PRIVATE_SOURCE_DIAGNOSTIC"));
    }
}
