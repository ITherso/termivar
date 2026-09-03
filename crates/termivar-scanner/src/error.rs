//! Error types and handling for Termivar Scanner
//!
//! ## Runtime scope
//!
//! - **Build:** non-default `legacy-scanner` feature.
//! - **Execution:** Surface A error contract used by historical scan phases.
//! - **Default `termivar scan`:** no.
//! - **Support:** legacy alpha.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Comprehensive error handling with contextual information for all scanner phases.
//! Implements proper error propagation with conversion from external error types.

use std::fmt;

/// Scanner error types with detailed context
///
/// # Variants
/// - `NetworkError`: HTTP client, connection, or response parsing failures
/// - `UrlParseError`: Invalid URL format or scheme
/// - `PayloadGenerationError`: Malformed payload generation parameters
/// - `PhaseTimeout`: Scanning phase exceeded timeout threshold
/// - `TaskJoinFailed`: A structurally owned scanner worker failed to join
/// - `Cancelled`: Host cancellation stopped bounded legacy transport
/// - `BudgetExceeded`: A bounded legacy resource threshold stopped work
/// - `InvalidDiscoveryLimits`: A discovery policy is incoherent or too large
/// - `InvalidVerificationLimits`: A verification policy is incoherent or too large
/// - `DiscoveryStateLimitExceeded`: A staged state transition exceeds retention bounds
/// - `InvalidLegacyVerificationReport`: A legacy phase attempted to bypass claim policy
/// - `LegacyVerificationStateLimitExceeded`: Verification outcome retention is exhausted
/// - `InvalidTarget`: Target URL doesn't meet validation requirements
/// - `IoError`: File system or I/O operation failures
#[derive(Debug)]
#[non_exhaustive]
pub enum ScannerError {
    /// Network I/O failures with detailed error message
    NetworkError(String),
    /// URL parsing failures with detailed error message
    UrlParseError(String),
    /// Payload generation failures with detailed error message
    PayloadGenerationError(String),
    /// Phase execution timeout
    PhaseTimeout,
    /// A structurally owned worker task failed to join.
    ///
    /// Deliberately carries no [`tokio::task::JoinError`] or panic payload so
    /// target-controlled panic details cannot cross the scanner boundary.
    TaskJoinFailed,
    /// Host cancellation stopped bounded legacy transport.
    Cancelled,
    /// A shared bounded legacy resource limit denied or stopped work.
    BudgetExceeded(crate::RuntimeLimitExceeded),
    /// Discovery limits are zero, inconsistent, or exceed hard bounds.
    InvalidDiscoveryLimits,
    /// Verification limits are zero, inconsistent, or exceed hard bounds.
    InvalidVerificationLimits,
    /// A staged discovery update exceeded a deterministic state bound.
    DiscoveryStateLimitExceeded,
    /// A corrected legacy phase supplied a report outside the constrained
    /// active, knowledge-only, manual-review bridge.
    InvalidLegacyVerificationReport,
    /// Accepted legacy verification outcomes exceeded the report bound.
    LegacyVerificationStateLimitExceeded,
    /// Target validation failure
    InvalidTarget,
    /// File I/O operation failure
    IoError(std::io::Error),
    /// Typed run report construction failed closed.
    RunReport(termivar_core::RunReportError),
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::NetworkError(e) => {
                write!(
                    f,
                    "Network error: {e}. Check connectivity and target availability."
                )
            },
            ScannerError::UrlParseError(e) => {
                write!(
                    f,
                    "URL parse error: {e}. Ensure URL is valid and properly formatted."
                )
            },
            ScannerError::PayloadGenerationError(e) => {
                write!(
                    f,
                    "Payload generation error: {e}. Check payload parameters and syntax."
                )
            },
            ScannerError::PhaseTimeout => {
                write!(
                    f,
                    "Phase execution timeout. Increase timeout or reduce scan scope."
                )
            },
            ScannerError::InvalidTarget => {
                write!(f, "Invalid target URL. Provide valid HTTP/HTTPS URL.")
            },
            ScannerError::IoError(e) => {
                write!(f, "IO error: {e}. Check file permissions and disk space.")
            },
            ScannerError::TaskJoinFailed => {
                write!(
                    f,
                    "Scanner worker task failed to join; no result was accepted."
                )
            },
            ScannerError::Cancelled => {
                write!(f, "Host cancellation stopped bounded legacy transport.")
            },
            ScannerError::BudgetExceeded(limit) => {
                write!(f, "Bounded legacy transport budget exhausted: {limit}")
            },
            ScannerError::InvalidDiscoveryLimits => {
                write!(f, "Invalid bounded discovery limits.")
            },
            ScannerError::InvalidVerificationLimits => {
                write!(f, "Invalid bounded legacy verification limits.")
            },
            ScannerError::DiscoveryStateLimitExceeded => {
                write!(f, "Bounded discovery state limit exceeded.")
            },
            ScannerError::InvalidLegacyVerificationReport => {
                write!(f, "Invalid legacy verification report was rejected.")
            },
            ScannerError::LegacyVerificationStateLimitExceeded => {
                write!(f, "Bounded legacy verification outcome limit exceeded.")
            },
            ScannerError::RunReport(error) => write!(f, "Run report error: {error}"),
        }
    }
}

impl std::error::Error for ScannerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScannerError::IoError(e) => Some(e),
            ScannerError::RunReport(error) => Some(error),
            ScannerError::BudgetExceeded(error) => Some(error),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for ScannerError {
    fn from(err: reqwest::Error) -> Self {
        let msg = if err.is_timeout() {
            format!("HTTP timeout: {err}")
        } else if err.is_connect() {
            format!("Connection failed: {err}")
        } else if err.status().is_some() {
            format!("HTTP error: {err}")
        } else {
            err.to_string()
        };
        ScannerError::NetworkError(msg)
    }
}

impl From<url::ParseError> for ScannerError {
    fn from(err: url::ParseError) -> Self {
        ScannerError::UrlParseError(err.to_string())
    }
}

impl From<std::io::Error> for ScannerError {
    fn from(err: std::io::Error) -> Self {
        ScannerError::IoError(err)
    }
}

impl From<termivar_core::RunReportError> for ScannerError {
    fn from(error: termivar_core::RunReportError) -> Self {
        Self::RunReport(error)
    }
}

/// Result type for scanner operations
pub type Result<T> = std::result::Result<T, ScannerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        let errors = vec![
            (ScannerError::PhaseTimeout, "timeout"),
            (ScannerError::TaskJoinFailed, "failed to join"),
            (ScannerError::InvalidTarget, "Invalid target"),
            (
                ScannerError::NetworkError("connection refused".to_string()),
                "Network error",
            ),
            (
                ScannerError::UrlParseError("invalid scheme".to_string()),
                "URL parse error",
            ),
            (
                ScannerError::PayloadGenerationError("invalid payload".to_owned()),
                "Payload generation error",
            ),
            (
                ScannerError::IoError(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "denied",
                )),
                "IO error",
            ),
        ];

        for (err, expected_text) in errors {
            let display = format!("{err}");
            assert!(display.contains(expected_text), "Error message: {display}");
        }
    }

    #[test]
    fn test_error_from_conversion() {
        let url_err = url::Url::parse("invalid url").err().unwrap();
        let scanner_err = ScannerError::from(url_err);
        assert!(format!("{scanner_err:?}").contains("UrlParseError"));
    }

    #[test]
    fn test_error_source_trait() {
        use std::error::Error;
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let scanner_err = ScannerError::from(io_err);
        assert!(scanner_err.source().is_some());
    }

    #[tokio::test]
    async fn reqwest_conversion_classifies_local_failures() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let status_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let status_address = status_listener.local_addr().unwrap();
        let status_server = tokio::spawn(async move {
            let (mut stream, _) = status_listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let status_error = client
            .get(format!("http://{status_address}/"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        status_server.await.unwrap();
        assert!(status_error.status().is_some());
        assert!(ScannerError::from(status_error)
            .to_string()
            .contains("HTTP error"));

        let timeout_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let timeout_address = timeout_listener.local_addr().unwrap();
        let timeout_server = tokio::spawn(async move {
            let (mut stream, _) = timeout_listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        });
        let timeout_client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(25))
            .build()
            .unwrap();
        let timeout_error = timeout_client
            .get(format!("http://{timeout_address}/"))
            .send()
            .await
            .unwrap_err();
        timeout_server.abort();
        let _ = timeout_server.await;
        assert!(timeout_error.is_timeout());
        assert!(ScannerError::from(timeout_error)
            .to_string()
            .contains("HTTP timeout"));

        let closed_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let closed_address = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        let connect_error = client
            .get(format!("http://{closed_address}/"))
            .send()
            .await
            .unwrap_err();
        assert!(connect_error.is_connect());
        assert!(ScannerError::from(connect_error)
            .to_string()
            .contains("Connection failed"));
    }

    #[test]
    fn bounded_legacy_errors_have_stable_text_and_sources() {
        use std::error::Error;

        let budget = crate::RuntimeLimitExceeded::new(
            crate::RuntimeBudgetDimension::TotalRequests,
            1,
            2,
            None,
        );
        let report = termivar_core::RunReportError::Blank {
            field: "run target",
        };
        let cases = [
            (
                ScannerError::Cancelled,
                "Host cancellation stopped bounded legacy transport.",
            ),
            (
                ScannerError::BudgetExceeded(budget.clone()),
                "Bounded legacy transport budget exhausted:",
            ),
            (
                ScannerError::InvalidDiscoveryLimits,
                "Invalid bounded discovery limits.",
            ),
            (
                ScannerError::InvalidVerificationLimits,
                "Invalid bounded legacy verification limits.",
            ),
            (
                ScannerError::DiscoveryStateLimitExceeded,
                "Bounded discovery state limit exceeded.",
            ),
            (
                ScannerError::InvalidLegacyVerificationReport,
                "Invalid legacy verification report was rejected.",
            ),
            (
                ScannerError::LegacyVerificationStateLimitExceeded,
                "Bounded legacy verification outcome limit exceeded.",
            ),
            (
                ScannerError::RunReport(report.clone()),
                "Run report error: run target must not be blank",
            ),
        ];
        for (error, expected) in cases {
            assert!(error.to_string().contains(expected));
        }

        assert!(ScannerError::BudgetExceeded(budget).source().is_some());
        let converted = ScannerError::from(report);
        assert!(converted.source().is_some());
        assert!(matches!(converted, ScannerError::RunReport(_)));
    }
}
