//! Rich Error Handling with thiserror
//!
//! Provides structured error types with:
//! - Automatic Display/Error trait impl via thiserror
//! - Source chain tracking for debugging
//! - Type-safe error variants
//! - Easy logging integration

use std::io;
use thiserror::Error;

/// VENOM Error types with rich context
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration validation or loading error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Proxy/MITM operation failed
    #[error("Proxy error: {0}")]
    Proxy(String),

    /// Scanner execution failed
    #[error("Scanner error: {0}")]
    Scanner(String),

    /// Vulnerability detection or analysis failed
    #[error("Detection error: {0}")]
    Detection(String),

    /// Plugin loading or execution failed
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// API endpoint or communication error
    #[error("API error: {0}")]
    Api(String),

    /// Network operation failed
    #[error("Network error: {0}")]
    Network(String),

    /// TLS/Certificate operation failed
    #[error("TLS error: {0}")]
    Tls(String),

    /// Target URL parsing or validation failed
    #[error("Target error: {0}")]
    Target(String),

    /// Payload generation or encoding failed
    #[error("Payload error: {0}")]
    Payload(String),

    /// Pattern matching or analysis failed
    #[error("Pattern error: {0}")]
    Pattern(String),

    /// Rate limiting or throttling error
    #[error("Rate limit error: {0}")]
    RateLimit(String),

    /// Thread pool or async operation error
    #[error("Threading error: {0}")]
    Threading(String),

    /// Database or persistence error
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization/Deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// IO operation failed (transparent source chain)
    #[error(transparent)]
    Io(#[from] io::Error),

    /// JSON serialization failed (transparent source chain)
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// TOML serialization failed (transparent source chain)
    #[error(transparent)]
    Toml(#[from] toml::de::Error),

    /// Custom error with context
    #[error("{context}: {message}")]
    Custom { context: String, message: String },

    /// Generic error (fallback)
    #[error("Error: {0}")]
    Other(String),
}

impl Error {
    /// Creates a config error with context
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Creates a scanner error with context
    pub fn scanner(msg: impl Into<String>) -> Self {
        Error::Scanner(msg.into())
    }

    /// Creates an API error with context
    pub fn api(msg: impl Into<String>) -> Self {
        Error::Api(msg.into())
    }

    /// Creates a network error with context
    pub fn network(msg: impl Into<String>) -> Self {
        Error::Network(msg.into())
    }

    /// Creates a plugin error with context
    pub fn plugin(msg: impl Into<String>) -> Self {
        Error::Plugin(msg.into())
    }

    /// Creates a target error with context
    pub fn target(msg: impl Into<String>) -> Self {
        Error::Target(msg.into())
    }

    /// Creates a custom error with context label
    pub fn custom(context: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Custom {
            context: context.into(),
            message: message.into(),
        }
    }

    /// Returns error kind as string (for logging, metrics)
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Config(_) => "CONFIG",
            Error::Proxy(_) => "PROXY",
            Error::Scanner(_) => "SCANNER",
            Error::Detection(_) => "DETECTION",
            Error::Plugin(_) => "PLUGIN",
            Error::Api(_) => "API",
            Error::Network(_) => "NETWORK",
            Error::Tls(_) => "TLS",
            Error::Target(_) => "TARGET",
            Error::Payload(_) => "PAYLOAD",
            Error::Pattern(_) => "PATTERN",
            Error::RateLimit(_) => "RATE_LIMIT",
            Error::Threading(_) => "THREADING",
            Error::Database(_) => "DATABASE",
            Error::Serialization(_) => "SERIALIZATION",
            Error::Io(_) => "IO",
            Error::Json(_) => "JSON",
            Error::Toml(_) => "TOML",
            Error::Custom { .. } => "CUSTOM",
            Error::Other(_) => "OTHER",
        }
    }

    /// Returns true if error is transient (can retry)
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Network(_)
                | Error::RateLimit(_)
                | Error::Threading(_)
                | Error::Io(_)
                | Error::Custom { .. }
        )
    }

    /// Returns true if error is critical (should stop)
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Error::Config(_) | Error::Tls(_) | Error::Target(_) | Error::Database(_)
        )
    }
}

/// Standard Result type using VENOM Error
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::scanner("test scanner error");
        assert_eq!(err.to_string(), "Scanner error: test scanner error");
    }

    #[test]
    fn test_error_kind() {
        assert_eq!(Error::scanner("msg").kind(), "SCANNER");
        assert_eq!(Error::config("msg").kind(), "CONFIG");
        assert_eq!(Error::network("msg").kind(), "NETWORK");
        assert_eq!(Error::plugin("msg").kind(), "PLUGIN");
    }

    #[test]
    fn test_error_is_transient() {
        assert!(Error::network("msg").is_transient());
        assert!(Error::rate_limit("msg").is_transient());
        assert!(!Error::config("msg").is_transient());
    }

    #[test]
    fn test_error_is_critical() {
        assert!(Error::config("msg").is_critical());
        assert!(Error::tls("msg").is_critical());
        assert!(!Error::network("msg").is_critical());
    }

    #[test]
    fn test_error_custom() {
        let err = Error::custom("SCAN", "Target unreachable");
        assert_eq!(err.to_string(), "SCAN: Target unreachable");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert_eq!(err.kind(), "IO");
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let _err: Error = json_err.into();
    }

    #[test]
    fn test_error_source_chain() {
        let err = Error::scanner("test");
        // Custom variant display includes message
        assert_eq!(err.to_string(), "Scanner error: test");

        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: Error = io_err.into();
        // IO error preserves the original error
        assert_eq!(err.kind(), "IO");
    }
}

// Additional helper methods for common patterns
impl Error {
    /// Creates a proxy error
    pub fn proxy(msg: impl Into<String>) -> Self {
        Error::Proxy(msg.into())
    }

    /// Creates a detection error
    pub fn detection(msg: impl Into<String>) -> Self {
        Error::Detection(msg.into())
    }

    /// Creates a TLS error
    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    /// Creates a payload error
    pub fn payload(msg: impl Into<String>) -> Self {
        Error::Payload(msg.into())
    }

    /// Creates a rate limit error
    pub fn rate_limit(msg: impl Into<String>) -> Self {
        Error::RateLimit(msg.into())
    }

    /// Creates a threading error
    pub fn threading(msg: impl Into<String>) -> Self {
        Error::Threading(msg.into())
    }

    /// Creates a database error
    pub fn database(msg: impl Into<String>) -> Self {
        Error::Database(msg.into())
    }
}
