//! Bounded, redacted authorization-context input for the opt-in web review.
//!
//! This module is the only CLI boundary that reads credential material. It
//! never accepts a credential as a command-line value, never serializes or
//! logs one, and converts bounded bytes directly into the scanner-owned root
//! context or role-bound two-principal authorization contracts.

use std::{
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::PathBuf,
};

#[cfg(feature = "authorization-review")]
use venom_scanner::authorization_review::{
    AuthorizationPrincipalPair, AuthorizationReviewPolicy, PeerAuthorizationPrincipal,
    PrimaryAuthorizationPrincipal, HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES,
};
use venom_scanner::{
    web_runtime::WebAssessmentRootAuthorizationContext, DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES,
};

/// The CLI deliberately uses the standard payload-strategy seed ceiling.
pub(crate) const MAX_AUTHORIZATION_CONTEXT_BYTES: usize =
    DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES as usize;

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
        let bytes = self.read_bytes()?;
        WebAssessmentRootAuthorizationContext::new(bytes)
            .map_err(|_| AuthorizationInputError::InvalidValue)
    }

    fn read_bytes(self) -> Result<Vec<u8>, AuthorizationInputError> {
        match self {
            Self::Environment(name) => read_environment(name),
            Self::File(path) => {
                let mut file = open_regular_file(path)?;
                read_bounded_line_source(&mut file)
            },
            Self::Stdin => {
                let stdin = io::stdin();
                let mut input = stdin.lock();
                read_bounded_line_source(&mut input)
            },
        }
    }
}

/// Complete, preflight-checked CLI input for one resource authorization review.
///
/// Paths, source names, and credential values are deliberately omitted from
/// `Debug`. Selecting inputs performs no filesystem, environment, or stdin I/O.
#[cfg(feature = "authorization-review")]
pub(crate) struct AuthorizationReviewInput {
    policy_file: PathBuf,
    primary: AuthorizationInputSource,
    peer: AuthorizationInputSource,
}

/// One role's unvalidated source-selection arguments. The wrapper keeps the
/// public CLI flow small without exposing source identifiers through `Debug`.
#[cfg(feature = "authorization-review")]
pub(crate) struct AuthorizationSourceOptions {
    environment: Option<OsString>,
    file: Option<PathBuf>,
    stdin: bool,
}

#[cfg(feature = "authorization-review")]
impl AuthorizationSourceOptions {
    pub(crate) const fn new(
        environment: Option<OsString>,
        file: Option<PathBuf>,
        stdin: bool,
    ) -> Self {
        Self {
            environment,
            file,
            stdin,
        }
    }
}

#[cfg(feature = "authorization-review")]
impl fmt::Debug for AuthorizationSourceOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationSourceOptions(<redacted>)")
    }
}

#[cfg(feature = "authorization-review")]
impl fmt::Debug for AuthorizationReviewInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationReviewInput")
            .field("policy_file", &"<redacted>")
            .field("primary", &"<redacted>")
            .field("peer", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "authorization-review")]
impl AuthorizationReviewInput {
    /// Requires one policy and exactly one source for each role without reading
    /// any selected input. A shared stdin cannot represent two principals.
    pub(crate) fn select(
        policy_file: Option<PathBuf>,
        primary: AuthorizationSourceOptions,
        peer: AuthorizationSourceOptions,
    ) -> Result<Option<Self>, AuthorizationReviewInputError> {
        let any_selected = policy_file.is_some()
            || primary.environment.is_some()
            || primary.file.is_some()
            || primary.stdin
            || peer.environment.is_some()
            || peer.file.is_some()
            || peer.stdin;
        if !any_selected {
            return Ok(None);
        }

        let policy_file = policy_file.ok_or(AuthorizationReviewInputError::MissingPolicy)?;
        let both_stdin = primary.stdin && peer.stdin;
        let primary =
            AuthorizationInputSource::select(primary.environment, primary.file, primary.stdin)
                .map_err(|_| AuthorizationReviewInputError::ConflictingPrimarySources)?
                .ok_or(AuthorizationReviewInputError::MissingPrimarySource)?;
        let peer = AuthorizationInputSource::select(peer.environment, peer.file, peer.stdin)
            .map_err(|_| AuthorizationReviewInputError::ConflictingPeerSources)?
            .ok_or(AuthorizationReviewInputError::MissingPeerSource)?;
        if both_stdin {
            return Err(AuthorizationReviewInputError::AmbiguousStdin);
        }

        Ok(Some(Self {
            policy_file,
            primary,
            peer,
        }))
    }

    /// Reads the policy first, then each credential exactly once, producing the
    /// move-only scanner contracts without exposing any input bytes.
    pub(crate) fn load(
        self,
        target: &url::Url,
    ) -> Result<
        (AuthorizationReviewPolicy, AuthorizationPrincipalPair),
        AuthorizationReviewInputError,
    > {
        let policy_source =
            read_bounded_regular_file(self.policy_file, HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES)
                .map_err(AuthorizationReviewInputError::PolicySource)?;
        let policy = AuthorizationReviewPolicy::parse_toml(target, &policy_source)
            .map_err(|_| AuthorizationReviewInputError::InvalidPolicy)?;

        let primary = self
            .primary
            .read_bytes()
            .map_err(AuthorizationReviewInputError::PrimarySource)
            .and_then(|bytes| {
                PrimaryAuthorizationPrincipal::new(bytes)
                    .map_err(|_| AuthorizationReviewInputError::InvalidPrimaryValue)
            })?;
        let peer = self
            .peer
            .read_bytes()
            .map_err(AuthorizationReviewInputError::PeerSource)
            .and_then(|bytes| {
                PeerAuthorizationPrincipal::new(bytes)
                    .map_err(|_| AuthorizationReviewInputError::InvalidPeerValue)
            })?;
        let principals = AuthorizationPrincipalPair::new(primary, peer)
            .map_err(|_| AuthorizationReviewInputError::PrincipalsNotDistinct)?;
        Ok((policy, principals))
    }
}

/// Static, value-free failures for the two-principal CLI boundary.
#[cfg(feature = "authorization-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationReviewInputError {
    MissingPolicy,
    MissingPrimarySource,
    MissingPeerSource,
    ConflictingPrimarySources,
    ConflictingPeerSources,
    AmbiguousStdin,
    PolicySource(AuthorizationInputError),
    InvalidPolicy,
    PrimarySource(AuthorizationInputError),
    PeerSource(AuthorizationInputError),
    InvalidPrimaryValue,
    InvalidPeerValue,
    PrincipalsNotDistinct,
}

#[cfg(feature = "authorization-review")]
impl fmt::Display for AuthorizationReviewInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPolicy => "authorization review requires one policy file",
            Self::MissingPrimarySource => {
                "authorization review requires exactly one primary input source"
            },
            Self::MissingPeerSource => {
                "authorization review requires exactly one peer input source"
            },
            Self::ConflictingPrimarySources => {
                "authorization review requires exactly one primary input source"
            },
            Self::ConflictingPeerSources => {
                "authorization review requires exactly one peer input source"
            },
            Self::AmbiguousStdin => {
                "authorization review cannot read both principal contexts from stdin"
            },
            Self::PolicySource(_) => "authorization review policy must be a bounded regular file",
            Self::InvalidPolicy => "authorization review policy is invalid",
            Self::PrimarySource(_) => {
                "authorization review primary input source could not be loaded"
            },
            Self::PeerSource(_) => "authorization review peer input source could not be loaded",
            Self::InvalidPrimaryValue => {
                "authorization review primary value is not a safe HTTP header value"
            },
            Self::InvalidPeerValue => {
                "authorization review peer value is not a safe HTTP header value"
            },
            Self::PrincipalsNotDistinct => {
                "authorization review requires distinct principal credentials"
            },
        })
    }
}

#[cfg(feature = "authorization-review")]
impl std::error::Error for AuthorizationReviewInputError {}

/// Static, credential-free authorization input failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationInputError {
    ConflictingSources,
    SourceNameInvalid,
    SourceUnavailable,
    SourceNotRegularFile,
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
            Self::SourceNotRegularFile => {
                "authorization-context file source must be a regular file"
            },
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

fn open_regular_file(path: PathBuf) -> Result<File, AuthorizationInputError> {
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| AuthorizationInputError::SourceUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(AuthorizationInputError::SourceNotRegularFile);
    }
    let file = File::open(path).map_err(|_| AuthorizationInputError::SourceUnavailable)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| AuthorizationInputError::SourceUnavailable)?;
    if !opened_metadata.is_file() {
        return Err(AuthorizationInputError::SourceNotRegularFile);
    }
    Ok(file)
}

#[cfg(feature = "authorization-review")]
fn read_bounded_regular_file(
    path: PathBuf,
    max_bytes: usize,
) -> Result<Vec<u8>, AuthorizationInputError> {
    let mut file = open_regular_file(path)?;
    let length = file
        .metadata()
        .map_err(|_| AuthorizationInputError::SourceUnavailable)?
        .len();
    if length > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(AuthorizationInputError::ValueTooLarge);
    }
    let retained = max_bytes.saturating_add(1);
    let mut bytes = Vec::with_capacity(length.try_into().unwrap_or(max_bytes).min(max_bytes));
    file.by_ref()
        .take(u64::try_from(retained).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorizationInputError::SourceReadFailed)?;
    if bytes.len() > max_bytes {
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

    #[test]
    #[cfg(unix)]
    fn file_source_rejects_a_non_regular_object_before_opening_or_reading() {
        let error = AuthorizationInputSource::File(PathBuf::from("/dev/null"))
            .load()
            .unwrap_err();
        assert_eq!(error, AuthorizationInputError::SourceNotRegularFile);
    }

    #[cfg(feature = "authorization-review")]
    fn valid_policy(resource: &str, handle: &str) -> String {
        format!(
            r#"schema = "security.authorization-review-policy/v1"
resource = "{resource}"
resource_handle = "{handle}"
expectation = "primary-only"
method = "GET"

[comparison]
selected_paths = ["/data/account"]
ignored_paths = ["/data/account/updated_at"]
unordered_array_paths = []
max_diff_paths = 8
"#
        )
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_selection_requires_a_policy_and_exactly_one_source_per_role() {
        assert!(AuthorizationReviewInput::select(
            None,
            AuthorizationSourceOptions::new(None, None, false),
            AuthorizationSourceOptions::new(None, None, false),
        )
        .unwrap()
        .is_none());
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(None, None, false),
                AuthorizationSourceOptions::new(None, None, false),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::MissingPrimarySource
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    None,
                    false,
                ),
                AuthorizationSourceOptions::new(None, None, false),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::MissingPeerSource
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                None,
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    None,
                    false,
                ),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PEER_PRIVATE_NAME")),
                    None,
                    false,
                ),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::MissingPolicy
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    Some(PathBuf::from("primary-private-path")),
                    false,
                ),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PEER_PRIVATE_NAME")),
                    None,
                    false,
                ),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::ConflictingPrimarySources
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PRIMARY_PRIVATE_NAME")),
                    None,
                    false,
                ),
                AuthorizationSourceOptions::new(
                    Some(OsString::from("PEER_PRIVATE_NAME")),
                    Some(PathBuf::from("peer-private-path")),
                    false,
                ),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::ConflictingPeerSources
        );
        assert_eq!(
            AuthorizationReviewInput::select(
                Some(PathBuf::from("private-policy")),
                AuthorizationSourceOptions::new(None, None, true),
                AuthorizationSourceOptions::new(None, None, true),
            )
            .unwrap_err(),
            AuthorizationReviewInputError::AmbiguousStdin
        );
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_input_debug_and_errors_redact_every_source_identifier() {
        let options = AuthorizationSourceOptions::new(
            Some(OsString::from("PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19")),
            None,
            false,
        );
        assert_eq!(
            format!("{options:?}"),
            "AuthorizationSourceOptions(<redacted>)"
        );
        let input = AuthorizationReviewInput::select(
            Some(PathBuf::from(
                "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            )),
            AuthorizationSourceOptions::new(
                Some(OsString::from("PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19")),
                None,
                false,
            ),
            AuthorizationSourceOptions::new(
                None,
                Some(PathBuf::from("PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44")),
                false,
            ),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{input:?}");
        for secret in [
            "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19",
            "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44",
        ] {
            assert!(!debug.contains(secret));
        }
        assert_eq!(
            AuthorizationReviewInputError::PolicySource(AuthorizationInputError::SourceUnavailable)
                .to_string(),
            "authorization review policy must be a bounded regular file"
        );
        let messages = [
            AuthorizationReviewInputError::MissingPolicy,
            AuthorizationReviewInputError::MissingPrimarySource,
            AuthorizationReviewInputError::MissingPeerSource,
            AuthorizationReviewInputError::ConflictingPrimarySources,
            AuthorizationReviewInputError::ConflictingPeerSources,
            AuthorizationReviewInputError::AmbiguousStdin,
            AuthorizationReviewInputError::InvalidPolicy,
            AuthorizationReviewInputError::PrimarySource(
                AuthorizationInputError::SourceUnavailable,
            ),
            AuthorizationReviewInputError::PeerSource(AuthorizationInputError::SourceUnavailable),
            AuthorizationReviewInputError::InvalidPrimaryValue,
            AuthorizationReviewInputError::InvalidPeerValue,
            AuthorizationReviewInputError::PrincipalsNotDistinct,
        ]
        .map(|error| error.to_string());
        assert!(messages.iter().all(|message| {
            !message.contains("PRIVATE")
                && !message.contains("credential bytes")
                && !message.contains("source path")
        }));
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_input_loads_a_strict_policy_and_distinct_file_principals() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        std::fs::write(
            &policy_path,
            valid_policy(
                "/api/account?opaque=RESOURCE-QUERY-MUST-NOT-LEAK-51A9BC",
                "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            ),
        )
        .unwrap();
        std::fs::write(
            &primary_path,
            b"Bearer PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19\r\n",
        )
        .unwrap();
        std::fs::write(
            &peer_path,
            b"Bearer PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44\n",
        )
        .unwrap();

        let input = AuthorizationReviewInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        let (policy, principals) = input
            .load(&url::Url::parse("https://example.test/").unwrap())
            .unwrap();
        let rendered = format!("{policy:?} {principals:?}");
        for secret in [
            "RESOURCE-QUERY-MUST-NOT-LEAK-51A9BC",
            "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A",
            "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19",
            "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn relative_policy_resource_is_bound_to_the_assessment_origin_root() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        let source = valid_policy("api/account", "account-self");
        std::fs::write(&policy_path, &source).unwrap();
        std::fs::write(&primary_path, b"Bearer primary").unwrap();
        std::fs::write(&peer_path, b"Bearer peer").unwrap();

        let input = AuthorizationReviewInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        let (policy, _) = input
            .load(&url::Url::parse("https://example.test/nested/base/").unwrap())
            .unwrap();
        let root_policy = AuthorizationReviewPolicy::parse_toml(
            &url::Url::parse("https://example.test/").unwrap(),
            source.as_bytes(),
        )
        .unwrap();
        assert_eq!(policy.resource_scope_id(), root_policy.resource_scope_id());
        assert_eq!(policy.policy_id(), root_policy.policy_id());
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_input_rejects_equal_values_after_loading_distinct_sources() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        std::fs::write(&policy_path, valid_policy("/api/account", "account-self")).unwrap();
        std::fs::write(&primary_path, b"Bearer same-context\n").unwrap();
        std::fs::write(&peer_path, b"Bearer same-context\r\n").unwrap();
        let input = AuthorizationReviewInput::select(
            Some(policy_path),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            AuthorizationReviewInputError::PrincipalsNotDistinct
        );
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_policy_source_must_be_a_bounded_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        std::fs::write(&primary_path, b"Bearer primary").unwrap();
        std::fs::write(&peer_path, b"Bearer peer").unwrap();

        let input = AuthorizationReviewInput::select(
            Some(directory.path().to_path_buf()),
            AuthorizationSourceOptions::new(None, Some(primary_path.clone()), false),
            AuthorizationSourceOptions::new(None, Some(peer_path.clone()), false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            AuthorizationReviewInputError::PolicySource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );

        let oversized = directory.path().join("oversized.toml");
        std::fs::write(
            &oversized,
            vec![b'x'; HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES + 1],
        )
        .unwrap();
        let input = AuthorizationReviewInput::select(
            Some(oversized),
            AuthorizationSourceOptions::new(None, Some(primary_path), false),
            AuthorizationSourceOptions::new(None, Some(peer_path), false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            input
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err(),
            AuthorizationReviewInputError::PolicySource(AuthorizationInputError::ValueTooLarge)
        );
    }

    #[cfg(feature = "authorization-review")]
    #[test]
    fn review_loading_classifies_policy_source_and_role_failures_without_values() {
        let directory = tempfile::tempdir().unwrap();
        let policy_path = directory.path().join("review.toml");
        let invalid_policy_path = directory.path().join("invalid.toml");
        let primary_path = directory.path().join("primary.txt");
        let peer_path = directory.path().join("peer.txt");
        let missing_path = directory.path().join("missing-private-source");
        std::fs::write(&policy_path, valid_policy("/api/account", "account-self")).unwrap();
        std::fs::write(&invalid_policy_path, "unknown = 'policy'").unwrap();
        std::fs::write(&primary_path, b"Bearer primary").unwrap();
        std::fs::write(&peer_path, b"Bearer peer").unwrap();

        let load_error =
            |policy: PathBuf, primary: PathBuf, peer: PathBuf| -> AuthorizationReviewInputError {
                AuthorizationReviewInput::select(
                    Some(policy),
                    AuthorizationSourceOptions::new(None, Some(primary), false),
                    AuthorizationSourceOptions::new(None, Some(peer), false),
                )
                .unwrap()
                .unwrap()
                .load(&url::Url::parse("https://example.test/").unwrap())
                .unwrap_err()
            };

        assert_eq!(
            load_error(
                missing_path.clone(),
                primary_path.clone(),
                peer_path.clone()
            ),
            AuthorizationReviewInputError::PolicySource(AuthorizationInputError::SourceUnavailable)
        );
        assert_eq!(
            load_error(invalid_policy_path, primary_path.clone(), peer_path.clone()),
            AuthorizationReviewInputError::InvalidPolicy
        );
        assert_eq!(
            load_error(policy_path.clone(), missing_path.clone(), peer_path.clone()),
            AuthorizationReviewInputError::PrimarySource(
                AuthorizationInputError::SourceUnavailable
            )
        );
        assert_eq!(
            load_error(policy_path.clone(), primary_path.clone(), missing_path),
            AuthorizationReviewInputError::PeerSource(AuthorizationInputError::SourceUnavailable)
        );

        let invalid_primary = directory.path().join("invalid-primary.txt");
        let invalid_peer = directory.path().join("invalid-peer.txt");
        std::fs::write(&invalid_primary, b"Bearer primary\nembedded").unwrap();
        std::fs::write(&invalid_peer, b"Bearer peer\0embedded").unwrap();
        assert_eq!(
            load_error(policy_path.clone(), invalid_primary, peer_path),
            AuthorizationReviewInputError::InvalidPrimaryValue
        );
        assert_eq!(
            load_error(policy_path, primary_path, invalid_peer),
            AuthorizationReviewInputError::InvalidPeerValue
        );
    }

    #[cfg(all(feature = "authorization-review", unix))]
    #[test]
    fn review_policy_and_principal_sources_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let policy_target = directory.path().join("policy-target.toml");
        let policy_link = directory.path().join("policy-link.toml");
        let primary_target = directory.path().join("primary-target.txt");
        let primary_link = directory.path().join("primary-link.txt");
        let peer = directory.path().join("peer.txt");
        std::fs::write(&policy_target, valid_policy("/api/account", "account-self")).unwrap();
        std::fs::write(&primary_target, b"Bearer primary").unwrap();
        std::fs::write(&peer, b"Bearer peer").unwrap();
        symlink(&policy_target, &policy_link).unwrap();
        symlink(&primary_target, &primary_link).unwrap();

        let error = AuthorizationReviewInput::select(
            Some(policy_link),
            AuthorizationSourceOptions::new(None, Some(primary_target), false),
            AuthorizationSourceOptions::new(None, Some(peer.clone()), false),
        )
        .unwrap()
        .unwrap()
        .load(&url::Url::parse("https://example.test/").unwrap())
        .unwrap_err();
        assert_eq!(
            error,
            AuthorizationReviewInputError::PolicySource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );

        let error = AuthorizationReviewInput::select(
            Some(policy_target),
            AuthorizationSourceOptions::new(None, Some(primary_link), false),
            AuthorizationSourceOptions::new(None, Some(peer), false),
        )
        .unwrap()
        .unwrap()
        .load(&url::Url::parse("https://example.test/").unwrap())
        .unwrap_err();
        assert_eq!(
            error,
            AuthorizationReviewInputError::PrimarySource(
                AuthorizationInputError::SourceNotRegularFile
            )
        );
    }
}
