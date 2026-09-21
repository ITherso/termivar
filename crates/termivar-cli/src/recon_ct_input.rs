//! Bounded acquisition of one explicit local certificate-transparency provider policy.
//!
//! The CLI retains filesystem authority: selection is inert, the chosen path
//! is opened exactly once, and only the scanner-owned validated policy crosses
//! this boundary. No secret material is supported by this input.

use std::{fmt, io::Read, path::PathBuf};

use termivar_scanner::recon_ct_provider::{
    parse_recon_ct_provider_policy, ReconCtProviderPolicy, MAX_RECON_CT_PROVIDER_POLICY_BYTES,
};

use crate::auth_input::{self, AuthorizationInputError};

/// Deferred selection of one explicit regular local policy file.
///
/// Construction deliberately performs no filesystem I/O.
pub(crate) struct ReconCtProviderPolicyInput {
    path: PathBuf,
}

impl ReconCtProviderPolicyInput {
    pub(crate) const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Opens, bounds, reads, and parses the selected policy exactly once.
    pub(crate) fn load(self) -> Result<ReconCtProviderPolicy, ReconCtProviderPolicyInputError> {
        validate_explicit_local_file_path(&self.path)?;
        let mut file = auth_input::open_regular_file(self.path).map_err(map_open_error)?;
        let declared_length = file
            .metadata()
            .map_err(|_| ReconCtProviderPolicyInputError::Unavailable)?
            .len();
        if declared_length > u64::try_from(MAX_RECON_CT_PROVIDER_POLICY_BYTES).unwrap_or(u64::MAX) {
            return Err(ReconCtProviderPolicyInputError::TooLarge);
        }

        // The metadata check is only a precheck. Retaining at most max + 1
        // bytes also detects a same-handle file that grows after metadata was
        // observed without permitting an unbounded allocation.
        let retained_limit = MAX_RECON_CT_PROVIDER_POLICY_BYTES
            .checked_add(1)
            .ok_or(ReconCtProviderPolicyInputError::TooLarge)?;
        let initial_capacity = usize::try_from(declared_length)
            .unwrap_or(MAX_RECON_CT_PROVIDER_POLICY_BYTES)
            .min(MAX_RECON_CT_PROVIDER_POLICY_BYTES);
        let mut bytes = Vec::with_capacity(initial_capacity);
        file.by_ref()
            .take(u64::try_from(retained_limit).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|_| ReconCtProviderPolicyInputError::ReadFailed)?;
        if bytes.len() > MAX_RECON_CT_PROVIDER_POLICY_BYTES {
            return Err(ReconCtProviderPolicyInputError::TooLarge);
        }

        parse_recon_ct_provider_policy(&bytes)
            .map_err(|_| ReconCtProviderPolicyInputError::InvalidDocument)
    }
}

impl fmt::Debug for ReconCtProviderPolicyInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconCtProviderPolicyInput")
            .field("path", &"<redacted>")
            .finish()
    }
}

/// Static, path- and value-free acquisition failures safe for CLI output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReconCtProviderPolicyInputError {
    Unavailable,
    NotRegular,
    TooLarge,
    ReadFailed,
    InvalidDocument,
}

impl fmt::Display for ReconCtProviderPolicyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "certificate-transparency provider policy source is unavailable",
            Self::NotRegular => {
                "certificate-transparency provider policy must be a regular local file"
            },
            Self::TooLarge => {
                "certificate-transparency provider policy exceeds the compiled byte limit"
            },
            Self::ReadFailed => {
                "certificate-transparency provider policy could not be read completely"
            },
            Self::InvalidDocument => "certificate-transparency provider policy document is invalid",
        })
    }
}

impl std::error::Error for ReconCtProviderPolicyInputError {}

fn validate_explicit_local_file_path(
    path: &std::path::Path,
) -> Result<(), ReconCtProviderPolicyInputError> {
    crate::report_compare::validate_local_path(path)
        .map_err(|_| ReconCtProviderPolicyInputError::Unavailable)?;
    let bytes = path.as_os_str().as_encoded_bytes();
    let final_component = bytes
        .rsplit(|byte| matches!(*byte, b'/' | b'\\'))
        .next()
        .unwrap_or_default();
    if final_component.is_empty()
        || matches!(final_component, b"." | b"..")
        || final_component.contains(&b'\0')
    {
        return Err(ReconCtProviderPolicyInputError::Unavailable);
    }
    Ok(())
}

fn map_open_error(error: AuthorizationInputError) -> ReconCtProviderPolicyInputError {
    match error {
        AuthorizationInputError::SourceNotRegularFile => {
            ReconCtProviderPolicyInputError::NotRegular
        },
        AuthorizationInputError::SourceReadFailed => ReconCtProviderPolicyInputError::ReadFailed,
        AuthorizationInputError::ValueTooLarge => ReconCtProviderPolicyInputError::TooLarge,
        AuthorizationInputError::ConflictingSources
        | AuthorizationInputError::SourceNameInvalid
        | AuthorizationInputError::SourceUnavailable
        | AuthorizationInputError::SourceNotUnicode
        | AuthorizationInputError::InvalidValue => ReconCtProviderPolicyInputError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_error(path: PathBuf) -> ReconCtProviderPolicyInputError {
        match ReconCtProviderPolicyInput::new(path).load() {
            Ok(_) => panic!("policy unexpectedly loaded"),
            Err(error) => error,
        }
    }

    #[test]
    fn selected_path_is_redacted_and_open_is_deferred() {
        let selected = ReconCtProviderPolicyInput::new(PathBuf::from(
            "private-cert-spotter-provider-policy.toml",
        ));
        let debug = format!("{selected:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private-cert-spotter-provider-policy.toml"));
    }

    #[test]
    fn invalid_local_path_spellings_fail_before_opening() {
        for path in [
            "",
            "-",
            "https://example.test/provider.toml",
            "file:/provider.toml",
            "data:provider-policy",
            ".",
            "..",
            "policy/.",
            "policy/..",
            "bad\0policy.toml",
        ] {
            assert_eq!(
                validate_explicit_local_file_path(std::path::Path::new(path)),
                Err(ReconCtProviderPolicyInputError::Unavailable),
                "unexpectedly accepted {path:?}"
            );
        }
    }

    #[test]
    fn ordinary_local_path_spellings_pass_lexical_validation() {
        for path in [
            "provider.toml",
            "./provider.toml",
            "../provider.toml",
            "/tmp/provider.toml",
            r"C:\reports\provider.toml",
            "C:/reports/provider.toml",
        ] {
            assert_eq!(
                validate_explicit_local_file_path(std::path::Path::new(path)),
                Ok(()),
                "unexpectedly rejected {path:?}"
            );
        }
    }

    #[test]
    fn missing_and_non_regular_sources_are_typed_without_paths() {
        let directory = tempfile::tempdir().unwrap();
        let private_path = directory.path().join("PRIVATE-CERT-SPOTTER-POLICY.toml");

        let missing = load_error(private_path);
        assert_eq!(missing, ReconCtProviderPolicyInputError::Unavailable);
        assert!(!format!("{missing:?}").contains("PRIVATE-CERT-SPOTTER"));

        assert_eq!(
            load_error(directory.path().to_path_buf()),
            ReconCtProviderPolicyInputError::NotRegular
        );
    }

    #[test]
    fn malformed_document_is_reduced_to_a_static_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("PRIVATE-POLICY.toml");
        std::fs::write(&path, b"not a provider policy").unwrap();

        let error = load_error(path);
        assert_eq!(error, ReconCtProviderPolicyInputError::InvalidDocument);
        assert!(!error.to_string().contains("not a provider policy"));
    }

    #[test]
    fn valid_cert_spotter_policy_loads_without_modifying_the_source() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider-policy.json");
        let bytes = br#"{"schema":"security.recon-certspotter-policy/v1","revision":"rev-1","query_domain":"example.com","query_reference":"scope-1","execution_mode":"production","provider_use_authorized":true,"privacy_disclosure_acknowledged":true}"#;
        std::fs::write(&path, bytes).unwrap();

        let policy = match ReconCtProviderPolicyInput::new(path.clone()).load() {
            Ok(policy) => policy,
            Err(error) => panic!("valid policy did not load: {error}"),
        };
        assert_eq!(policy.revision(), "rev-1");
        assert_eq!(policy.query_domain(), "example.com");
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn bounded_reader_accepts_the_ceiling_and_rejects_one_more_byte() {
        assert_eq!(MAX_RECON_CT_PROVIDER_POLICY_BYTES, 16 * 1024);
        let directory = tempfile::tempdir().unwrap();
        let exact = directory.path().join("exact.toml");
        let oversized = directory.path().join("oversized.toml");
        std::fs::write(&exact, vec![b' '; MAX_RECON_CT_PROVIDER_POLICY_BYTES]).unwrap();
        std::fs::write(
            &oversized,
            vec![b' '; MAX_RECON_CT_PROVIDER_POLICY_BYTES + 1],
        )
        .unwrap();

        assert_eq!(
            load_error(exact),
            ReconCtProviderPolicyInputError::InvalidDocument
        );
        assert_eq!(
            load_error(oversized),
            ReconCtProviderPolicyInputError::TooLarge
        );
    }

    #[test]
    fn public_errors_are_static_and_value_free() {
        for error in [
            ReconCtProviderPolicyInputError::Unavailable,
            ReconCtProviderPolicyInputError::NotRegular,
            ReconCtProviderPolicyInputError::TooLarge,
            ReconCtProviderPolicyInputError::ReadFailed,
            ReconCtProviderPolicyInputError::InvalidDocument,
        ] {
            let text = error.to_string();
            assert!(text.starts_with("certificate-transparency provider policy"));
            assert!(!text.contains('/') && !text.contains('\\'));
            assert!(!text.contains('{') && !text.contains('}'));
            assert!(text.len() < 96);
        }
    }
}
