//! Bounded acquisition of one explicit local WebSocket review policy.
//!
//! The CLI retains filesystem authority: selection is inert, the chosen path
//! is opened exactly once, and only a validated scanner-owned policy crosses
//! this boundary. The policy contains protocol messages, so neither its path
//! nor parser diagnostics are exposed by public errors or `Debug` output.

use std::{fmt, io::Read, path::PathBuf};

use termivar_scanner::websocket_review::{
    WebSocketReviewPolicy, MAX_WEBSOCKET_REVIEW_POLICY_BYTES,
};
use url::Url;

use crate::auth_input::{self, AuthorizationInputError};

/// Deferred selection of one explicit regular local policy file.
///
/// Construction deliberately performs no filesystem I/O.
pub(crate) struct WebSocketReviewPolicyInput {
    path: PathBuf,
}

impl WebSocketReviewPolicyInput {
    pub(crate) const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Opens, bounds, reads, target-binds and parses the selected policy once.
    pub(crate) fn load(
        self,
        application_target: &Url,
    ) -> Result<WebSocketReviewPolicy, WebSocketReviewPolicyInputError> {
        validate_explicit_local_file_path(&self.path)?;
        let mut file = auth_input::open_regular_file(self.path).map_err(map_open_error)?;
        let declared_length = file
            .metadata()
            .map_err(|_| WebSocketReviewPolicyInputError::Unavailable)?
            .len();
        if declared_length > u64::try_from(MAX_WEBSOCKET_REVIEW_POLICY_BYTES).unwrap_or(u64::MAX) {
            return Err(WebSocketReviewPolicyInputError::TooLarge);
        }

        // The metadata check is only a precheck. Retaining at most max + 1
        // bytes also detects growth on the same open handle without allowing an
        // unbounded allocation.
        let retained_limit = MAX_WEBSOCKET_REVIEW_POLICY_BYTES
            .checked_add(1)
            .ok_or(WebSocketReviewPolicyInputError::TooLarge)?;
        let initial_capacity = usize::try_from(declared_length)
            .unwrap_or(MAX_WEBSOCKET_REVIEW_POLICY_BYTES)
            .min(MAX_WEBSOCKET_REVIEW_POLICY_BYTES);
        let mut bytes = Vec::with_capacity(initial_capacity);
        file.by_ref()
            .take(u64::try_from(retained_limit).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|_| WebSocketReviewPolicyInputError::ReadFailed)?;
        if bytes.len() > MAX_WEBSOCKET_REVIEW_POLICY_BYTES {
            return Err(WebSocketReviewPolicyInputError::TooLarge);
        }

        WebSocketReviewPolicy::parse_json(application_target, &bytes)
            .map_err(|_| WebSocketReviewPolicyInputError::InvalidDocument)
    }
}

impl fmt::Debug for WebSocketReviewPolicyInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketReviewPolicyInput")
            .field("path", &"<redacted>")
            .finish()
    }
}

/// Static, path- and value-free acquisition failures safe for CLI output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebSocketReviewPolicyInputError {
    Unavailable,
    NotRegular,
    TooLarge,
    ReadFailed,
    InvalidDocument,
}

impl fmt::Display for WebSocketReviewPolicyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "WebSocket review policy source is unavailable",
            Self::NotRegular => "WebSocket review policy must be a regular local file",
            Self::TooLarge => "WebSocket review policy exceeds the compiled byte limit",
            Self::ReadFailed => "WebSocket review policy could not be read completely",
            Self::InvalidDocument => "WebSocket review policy document is invalid",
        })
    }
}

impl std::error::Error for WebSocketReviewPolicyInputError {}

fn validate_explicit_local_file_path(
    path: &std::path::Path,
) -> Result<(), WebSocketReviewPolicyInputError> {
    crate::report_compare::validate_local_path(path)
        .map_err(|_| WebSocketReviewPolicyInputError::Unavailable)?;
    let bytes = path.as_os_str().as_encoded_bytes();
    let final_component = bytes
        .rsplit(|byte| matches!(*byte, b'/' | b'\\'))
        .next()
        .unwrap_or_default();
    if final_component.is_empty()
        || matches!(final_component, b"." | b"..")
        || final_component.contains(&b'\0')
    {
        return Err(WebSocketReviewPolicyInputError::Unavailable);
    }
    Ok(())
}

fn map_open_error(error: AuthorizationInputError) -> WebSocketReviewPolicyInputError {
    match error {
        AuthorizationInputError::SourceNotRegularFile => {
            WebSocketReviewPolicyInputError::NotRegular
        },
        AuthorizationInputError::SourceReadFailed => WebSocketReviewPolicyInputError::ReadFailed,
        AuthorizationInputError::ValueTooLarge => WebSocketReviewPolicyInputError::TooLarge,
        AuthorizationInputError::ConflictingSources
        | AuthorizationInputError::SourceNameInvalid
        | AuthorizationInputError::SourceUnavailable
        | AuthorizationInputError::SourceNotUnicode
        | AuthorizationInputError::InvalidValue => WebSocketReviewPolicyInputError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_error(path: PathBuf) -> WebSocketReviewPolicyInputError {
        let target = Url::parse("http://127.0.0.1:8123/app/").unwrap();
        match WebSocketReviewPolicyInput::new(path).load(&target) {
            Ok(_) => panic!("policy unexpectedly loaded"),
            Err(error) => error,
        }
    }

    #[test]
    fn selected_path_is_redacted_and_open_is_deferred() {
        let selected = WebSocketReviewPolicyInput::new(PathBuf::from(
            "PRIVATE-WEBSOCKET-PROTOCOL-POLICY.json",
        ));
        let debug = format!("{selected:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("PRIVATE-WEBSOCKET"));
    }

    #[test]
    fn invalid_local_path_spellings_fail_before_opening() {
        for path in [
            "",
            "-",
            "https://example.test/policy.json",
            "file:/policy.json",
            "data:policy",
            ".",
            "..",
            "policy/.",
            "policy/..",
            "bad\0policy.json",
        ] {
            assert_eq!(
                validate_explicit_local_file_path(std::path::Path::new(path)),
                Err(WebSocketReviewPolicyInputError::Unavailable),
                "unexpectedly accepted {path:?}"
            );
        }
    }

    #[test]
    fn malformed_document_and_oversized_source_are_static_failures() {
        let directory = tempfile::tempdir().unwrap();
        let malformed = directory.path().join("PRIVATE-POLICY.json");
        std::fs::write(&malformed, b"not a policy").unwrap();
        assert_eq!(
            load_error(malformed),
            WebSocketReviewPolicyInputError::InvalidDocument
        );

        let oversized = directory.path().join("PRIVATE-OVERSIZED.json");
        std::fs::write(
            &oversized,
            vec![b' '; MAX_WEBSOCKET_REVIEW_POLICY_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            load_error(oversized),
            WebSocketReviewPolicyInputError::TooLarge
        );
    }

    #[test]
    fn valid_policy_is_read_once_and_bound_to_the_selected_application() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("websocket-review.json");
        let bytes = br#"{"schema":"security.websocket-review-policy/v1","target_authorized":true,"messages_read_only_acknowledged":true,"message_content_is_non_secret":true,"endpoint":"ws://127.0.0.1:8123/app/socket","origin_mode":"omit","subprotocol":null,"compression":false,"reconnect":false,"messages":[{"id":"ping","text":"{\"type\":\"ping\"}","expected_response":{"sha256":"b94f1fbb072a53089df2bd74bd78c1a4d4ef81f6c0e9c316492583edc79830d3","length":15}}],"limits":{"max_inbound_message_bytes":4096,"max_outbound_message_bytes":4096,"max_messages":1,"max_control_frames":2,"max_wall_time_ms":1000}}"#;
        std::fs::write(&path, bytes).unwrap();
        let target = Url::parse("http://127.0.0.1:8123/app/").unwrap();

        let policy = WebSocketReviewPolicyInput::new(path.clone())
            .load(&target)
            .expect("valid policy");
        assert_eq!(policy.schema(), "security.websocket-review-policy/v1");
        assert_eq!(policy.message_count(), 1);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn public_errors_are_value_free() {
        for error in [
            WebSocketReviewPolicyInputError::Unavailable,
            WebSocketReviewPolicyInputError::NotRegular,
            WebSocketReviewPolicyInputError::TooLarge,
            WebSocketReviewPolicyInputError::ReadFailed,
            WebSocketReviewPolicyInputError::InvalidDocument,
        ] {
            let text = error.to_string();
            assert!(text.starts_with("WebSocket review policy"));
            assert!(!text.contains('/') && !text.contains('\\'));
            assert!(!text.contains('{') && !text.contains('}'));
            assert!(text.len() < 96);
        }
    }
}
