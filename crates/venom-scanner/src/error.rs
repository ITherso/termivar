//! Error types and handling for VENOM Scanner
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
/// - `InvalidTarget`: Target URL doesn't meet validation requirements
/// - `IoError`: File system or I/O operation failures
#[derive(Debug)]
pub enum ScannerError {
    /// Network I/O failures with detailed error message
    NetworkError(String),
    /// URL parsing failures with detailed error message
    UrlParseError(String),
    /// Payload generation failures with detailed error message
    PayloadGenerationError(String),
    /// Phase execution timeout
    PhaseTimeout,
    /// Target validation failure
    InvalidTarget,
    /// File I/O operation failure
    IoError(std::io::Error),
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
        }
    }
}

impl std::error::Error for ScannerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScannerError::IoError(e) => Some(e),
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

/// Result type for scanner operations
pub type Result<T> = std::result::Result<T, ScannerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        let errors = vec![
            (ScannerError::PhaseTimeout, "timeout"),
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
