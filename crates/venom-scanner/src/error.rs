//! Error types and handling for VENOM Scanner
//!
//! ## Runtime scope
//!
//! - **Build:** non-default `legacy-scanner` feature.
//! - **Execution:** Surface A error contract used by historical scan phases.
//! - **Default `venom scan`:** no.
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
    RunReport(venom_core::RunReportError),
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::NetworkError(e) => {
                write!(
                    f,
                    "Network error: {}. Check connectivity and target availability.",
                    e
                )
            },
            ScannerError::UrlParseError(e) => {
                write!(
                    f,
                    "URL parse error: {}. Ensure URL is valid and properly formatted.",
                    e
                )
            },
            ScannerError::PayloadGenerationError(e) => {
                write!(
                    f,
                    "Payload generation error: {}. Check payload parameters and syntax.",
                    e
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
                write!(f, "IO error: {}. Check file permissions and disk space.", e)
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
            format!("HTTP timeout: {}", err)
        } else if err.is_connect() {
            format!("Connection failed: {}", err)
        } else if err.status().is_some() {
            format!("HTTP error: {}", err)
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

impl From<venom_core::RunReportError> for ScannerError {
    fn from(error: venom_core::RunReportError) -> Self {
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
        ];

        for (err, expected_text) in errors {
            let display = format!("{}", err);
            assert!(
                display.contains(expected_text),
                "Error message: {}",
                display
            );
        }
    }

    #[test]
    fn test_error_from_conversion() {
        let url_err = url::Url::parse("invalid url").err().unwrap();
        let scanner_err = ScannerError::from(url_err);
        assert!(format!("{:?}", scanner_err).contains("UrlParseError"));
    }

    #[test]
    fn test_error_source_trait() {
        use std::error::Error;
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let scanner_err = ScannerError::from(io_err);
        assert!(scanner_err.source().is_some());
    }
}
