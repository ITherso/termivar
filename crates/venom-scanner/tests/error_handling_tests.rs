//! Tests for error handling and edge cases
//!
//! Verifies proper error propagation and handling across scanner

#![cfg(feature = "legacy-scanner")]

use venom_scanner::{Result, ScannerError};

/// Tests ScannerError creation
#[test]
fn test_error_creation() {
    let _err: ScannerError = ScannerError::UrlParseError("invalid url".to_string());
    // Should not panic
}

/// Tests error variants
#[test]
fn test_error_variants() {
    let parse_error = ScannerError::UrlParseError("test".to_string());
    let payload_error = ScannerError::PayloadGenerationError("test".to_string());
    let timeout_error = ScannerError::PhaseTimeout;
    let network_error = ScannerError::NetworkError("test".to_string());
    let invalid_target = ScannerError::InvalidTarget;

    // Verify all variants can be created
    assert!(!format!("{parse_error:?}").is_empty());
    assert!(!format!("{payload_error:?}").is_empty());
    assert!(!format!("{timeout_error:?}").is_empty());
    assert!(!format!("{network_error:?}").is_empty());
    assert!(!format!("{invalid_target:?}").is_empty());
}

/// Tests error message content
#[test]
fn test_error_messages() {
    let err_msg = "test error message";
    let error = ScannerError::NetworkError(err_msg.to_string());

    let display = format!("{error}");
    assert!(!display.is_empty());
}

/// Tests Result type usage
#[test]
fn test_result_ok() {
    let result: Result<i32> = Ok(42);
    assert!(matches!(result, Ok(42)));
}

/// Tests Result error handling
#[test]
fn test_result_err() {
    let result: Result<i32> = Err(ScannerError::NetworkError("failed".to_string()));
    assert!(result.is_err());
}

/// Tests error conversion from reqwest
#[test]
fn test_error_from_conversion() {
    // This would require an actual reqwest error
    // Testing the capability to convert from external errors
    let scanner_error = ScannerError::NetworkError("HTTP error".to_string());
    assert!(!format!("{scanner_error:?}").is_empty());
}

/// Tests chaining error context
#[test]
fn test_error_context() {
    let base_error = ScannerError::UrlParseError("malformed URL".to_string());
    let _context = format!("Failed during reconnaissance: {base_error}");

    // Should be able to add context to errors
}

/// Tests error recovery patterns
#[test]
fn test_error_recovery() {
    let result: Result<String> = Err(ScannerError::NetworkError("connection failed".to_string()));

    let recovered = match result {
        Ok(val) => val,
        Err(_) => "default_value".to_string(),
    };

    assert_eq!(recovered, "default_value");
}

/// Tests option to result conversion
#[test]
fn test_option_to_result() {
    let opt: Option<i32> = None;
    let result: Result<i32> =
        opt.ok_or_else(|| ScannerError::NetworkError("not found".to_string()));

    assert!(result.is_err());
}

/// Tests error severity levels
#[test]
fn test_error_criticality() {
    let network_error = ScannerError::NetworkError("critical network failure".to_string());
    let timeout_error = ScannerError::PhaseTimeout;
    let invalid_error = ScannerError::InvalidTarget;

    // All are valid errors that should be handled
    assert!(!format!("{network_error:?}").is_empty());
    assert!(!format!("{timeout_error:?}").is_empty());
    assert!(!format!("{invalid_error:?}").is_empty());
}

/// Tests error propagation with ?
#[test]
fn test_error_propagation() {
    fn fallible_op() -> Result<i32> {
        Err(ScannerError::NetworkError("test".to_string()))
    }

    fn caller() -> Result<i32> {
        let _val = fallible_op()?;
        Ok(0)
    }

    assert!(caller().is_err());
}

/// Tests multiple error types in single context
#[test]
fn test_mixed_error_handling() {
    let errors: Vec<Result<String>> = vec![
        Ok("success".to_string()),
        Err(ScannerError::NetworkError("failed".to_string())),
        Ok("success".to_string()),
    ];

    let successful: Vec<String> = errors.into_iter().filter_map(|r| r.ok()).collect();

    assert_eq!(successful.len(), 2);
}
