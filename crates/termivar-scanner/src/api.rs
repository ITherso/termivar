//! REST API data models
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `termivar scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Request/response data contracts only. This module does not bind a listener
//! or route HTTP requests.

use crate::ScanFinding;
use serde::{Deserialize, Serialize};

/// API Request to start a new scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartScanRequest {
    pub target: String,
    pub config: Option<ScanConfigRequest>,
    pub tags: Option<Vec<String>>,
}

/// Uninterpreted host configuration metadata.
///
/// The repository API model does not authorize or apply these values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigRequest {
    pub intensity: Option<String>,
    pub timeout_secs: Option<u64>,
    pub max_concurrency: Option<u32>,
    #[serde(with = "optional_positive_f32")]
    pub rate_limit: Option<f32>,
    /// Historical phase identifiers; this record does not execute them.
    pub phases: Option<Vec<u8>>,
}

/// Scan status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub target: String,
    pub status: ScanStatusType,
    #[serde(with = "percent_f32")]
    pub progress: f32,
    pub findings_count: u64,
    pub elapsed_ms: u64,
    pub started_at: u64,
    pub current_phase: Option<u8>,
}

/// Scan status types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatusType {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "paused")]
    Paused,
}

impl ScanStatusType {
    pub fn as_str(&self) -> &str {
        match self {
            ScanStatusType::Queued => "queued",
            ScanStatusType::Running => "running",
            ScanStatusType::Completed => "completed",
            ScanStatusType::Failed => "failed",
            ScanStatusType::Paused => "paused",
        }
    }
}

/// API Response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: u64,
}

impl<T> ApiResponse<T> {
    /// Builds a success record at a caller-supplied timestamp.
    pub fn ok_at(data: T, timestamp: u64) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp,
        }
    }

    /// Builds an error record at a caller-supplied timestamp.
    pub fn err_at(error: String, timestamp: u64) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp,
        }
    }
}

/// Scan result response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultResponse {
    pub scan_id: String,
    pub target: String,
    pub status: String,
    pub findings: Vec<ScanFinding>,
    #[serde(with = "unit_interval_f32")]
    pub risk_score: f32,
    pub duration_ms: u64,
    pub completed_at: u64,
}

/// Finding filter for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingFilter {
    pub severity: Option<String>,
    pub phase: Option<u8>,
    pub module: Option<String>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
}

/// Statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub total_scans: u64,
    pub completed_scans: u64,
    pub total_findings: u64,
    pub critical_count: u64,
    pub high_count: u64,
    pub medium_count: u64,
    pub low_count: u64,
    #[serde(with = "nonnegative_f64")]
    pub avg_scan_duration_ms: f64,
}

mod optional_positive_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<f32>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) if value.is_finite() && *value > 0.0 => serializer.serialize_some(value),
            Some(_) => Err(serde::ser::Error::custom(
                "rate limit must be finite and greater than zero",
            )),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<f32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<f32>::deserialize(deserializer)?;
        match value {
            Some(value) if value.is_finite() && value > 0.0 => Ok(Some(value)),
            Some(_) => Err(serde::de::Error::custom(
                "rate limit must be finite and greater than zero",
            )),
            None => Ok(None),
        }
    }
}

macro_rules! ranged_float_serde {
    ($module:ident, $type:ty, $minimum:expr, $maximum:expr, $message:literal) => {
        mod $module {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S>(value: &$type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if value.is_finite() && ($minimum..=$maximum).contains(value) {
                    serializer.serialize_f64(*value as f64)
                } else {
                    Err(serde::ser::Error::custom($message))
                }
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<$type, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = <$type>::deserialize(deserializer)?;
                if value.is_finite() && ($minimum..=$maximum).contains(&value) {
                    Ok(value)
                } else {
                    Err(serde::de::Error::custom($message))
                }
            }
        }
    };
}

ranged_float_serde!(
    percent_f32,
    f32,
    0.0_f32,
    100.0_f32,
    "progress must be finite and between 0 and 100"
);
ranged_float_serde!(
    unit_interval_f32,
    f32,
    0.0_f32,
    1.0_f32,
    "risk score must be finite and between 0 and 1"
);

mod nonnegative_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.is_finite() && *value >= 0.0 {
            serializer.serialize_f64(*value)
        } else {
            Err(serde::ser::Error::custom(
                "average duration must be finite and non-negative",
            ))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        if value.is_finite() && value >= 0.0 {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "average duration must be finite and non-negative",
            ))
        }
    }
}

/// API error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiError {
    ScanNotFound(String),
    InvalidConfig(String),
    InvalidTarget(String),
    ScanAlreadyRunning(String),
    InternalError(String),
}

impl ApiError {
    pub fn message(&self) -> String {
        match self {
            ApiError::ScanNotFound(id) => format!("Scan not found: {id}"),
            ApiError::InvalidConfig(msg) => format!("Invalid configuration: {msg}"),
            ApiError::InvalidTarget(url) => format!("Invalid target URL: {url}"),
            ApiError::ScanAlreadyRunning(id) => format!("Scan already running: {id}"),
            ApiError::InternalError(msg) => format!("Internal error: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_scan_request() {
        let req = StartScanRequest {
            target: "https://example.com".to_string(),
            config: None,
            tags: None,
        };

        assert_eq!(req.target, "https://example.com");
    }

    #[test]
    fn test_scan_status() {
        let status = ScanStatus {
            scan_id: "scan123".to_string(),
            target: "https://example.com".to_string(),
            status: ScanStatusType::Running,
            progress: 50.0,
            findings_count: 10,
            elapsed_ms: 5000,
            started_at: 1000,
            current_phase: Some(5),
        };

        assert_eq!(status.progress, 50.0);
        assert_eq!(status.findings_count, 10);
    }

    #[test]
    fn test_scan_status_type_str() {
        assert_eq!(ScanStatusType::Running.as_str(), "running");
        assert_eq!(ScanStatusType::Completed.as_str(), "completed");
    }

    #[test]
    fn test_api_response_ok() {
        let response: ApiResponse<String> = ApiResponse::ok_at("Success".to_string(), 123);
        assert!(response.success);
        assert_eq!(response.data, Some("Success".to_string()));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_err() {
        let response: ApiResponse<String> = ApiResponse::err_at("Error".to_string(), 123);
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some("Error".to_string()));
    }

    #[test]
    fn test_finding_filter() {
        let filter = FindingFilter {
            severity: Some("CRITICAL".to_string()),
            phase: Some(5),
            module: None,
            offset: Some(0),
            limit: Some(50),
        };

        assert_eq!(filter.severity, Some("CRITICAL".to_string()));
        assert_eq!(filter.limit, Some(50));
    }

    #[test]
    fn test_stats_response() {
        let stats = StatsResponse {
            total_scans: 100,
            completed_scans: 95,
            total_findings: 500,
            critical_count: 10,
            high_count: 50,
            medium_count: 200,
            low_count: 240,
            avg_scan_duration_ms: 5000.0,
        };

        assert_eq!(stats.total_scans, 100);
        assert_eq!(stats.critical_count, 10);
    }

    #[test]
    fn test_api_error_messages() {
        let cases = [
            (
                ApiError::ScanNotFound("abc123".to_owned()),
                "Scan not found: abc123",
            ),
            (
                ApiError::InvalidConfig("bounded".to_owned()),
                "Invalid configuration: bounded",
            ),
            (
                ApiError::InvalidTarget("invalid".to_owned()),
                "Invalid target URL: invalid",
            ),
            (
                ApiError::ScanAlreadyRunning("abc123".to_owned()),
                "Scan already running: abc123",
            ),
            (
                ApiError::InternalError("redacted".to_owned()),
                "Internal error: redacted",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.message(), expected);
        }
    }

    #[test]
    fn test_scan_result_response() {
        let result = ScanResultResponse {
            scan_id: "scan1".to_string(),
            target: "https://example.com".to_string(),
            status: "completed".to_string(),
            findings: vec![],
            risk_score: 0.65,
            duration_ms: 10000,
            completed_at: 2000,
        };

        assert_eq!(result.risk_score, 0.65);
        assert_eq!(result.findings.len(), 0);
    }

    #[test]
    fn test_scan_config_request() {
        let config = ScanConfigRequest {
            intensity: Some("aggressive".to_string()),
            timeout_secs: Some(10),
            max_concurrency: Some(100),
            rate_limit: Some(50.0),
            phases: Some(vec![1, 2, 3, 5, 6, 7, 8]),
        };

        assert_eq!(config.intensity, Some("aggressive".to_string()));
        assert_eq!(config.max_concurrency, Some(100));
        assert_eq!(config.phases, Some(vec![1, 2, 3, 5, 6, 7, 8]));
    }

    #[test]
    fn api_wire_rejects_nonfinite_and_out_of_range_numbers() {
        let invalid_status = ScanStatus {
            scan_id: "scan".into(),
            target: "https://example.test".into(),
            status: ScanStatusType::Running,
            progress: f32::NAN,
            findings_count: 0,
            elapsed_ms: 0,
            started_at: 0,
            current_phase: None,
        };
        assert!(serde_json::to_string(&invalid_status).is_err());

        let invalid_config = r#"{
            "intensity": null,
            "timeout_secs": null,
            "max_concurrency": null,
            "rate_limit": -1.0,
            "phases": null
        }"#;
        assert!(serde_json::from_str::<ScanConfigRequest>(invalid_config).is_err());

        let invalid_stats = StatsResponse {
            total_scans: 0,
            completed_scans: 0,
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            avg_scan_duration_ms: f64::INFINITY,
        };
        assert!(serde_json::to_string(&invalid_stats).is_err());

        let invalid_optional_rate = ScanConfigRequest {
            intensity: None,
            timeout_secs: None,
            max_concurrency: None,
            rate_limit: Some(f32::NAN),
            phases: None,
        };
        assert!(serde_json::to_string(&invalid_optional_rate).is_err());

        let invalid_duration = r#"{
            "total_scans":0,"completed_scans":0,"total_findings":0,
            "critical_count":0,"high_count":0,"medium_count":0,"low_count":0,
            "avg_scan_duration_ms":-1.0
        }"#;
        assert!(serde_json::from_str::<StatsResponse>(invalid_duration).is_err());
    }

    #[test]
    fn api_wire_valid_numeric_boundaries_round_trip() {
        let optional_rate = ScanConfigRequest {
            intensity: None,
            timeout_secs: None,
            max_concurrency: None,
            rate_limit: None,
            phases: None,
        };
        let encoded = serde_json::to_string(&optional_rate).unwrap();
        let decoded: ScanConfigRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.rate_limit, None);

        let status = ScanStatus {
            scan_id: "scan".to_string(),
            target: "https://example.test".to_string(),
            status: ScanStatusType::Running,
            progress: 100.0,
            findings_count: 0,
            elapsed_ms: 1,
            started_at: 1,
            current_phase: None,
        };
        let encoded = serde_json::to_string(&status).unwrap();
        let decoded: ScanStatus = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.progress, 100.0);

        let result = ScanResultResponse {
            scan_id: "scan".to_string(),
            target: "https://example.test".to_string(),
            status: "complete".to_string(),
            findings: Vec::new(),
            risk_score: 1.0,
            duration_ms: 1,
            completed_at: 1,
        };
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded: ScanResultResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.risk_score, 1.0);

        let stats = StatsResponse {
            total_scans: 1,
            completed_scans: 1,
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            avg_scan_duration_ms: 0.0,
        };
        let encoded = serde_json::to_string(&stats).unwrap();
        let decoded: StatsResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.avg_scan_duration_ms, 0.0);
    }

    #[test]
    fn api_wire_counts_are_fixed_width() {
        let filter = FindingFilter {
            severity: None,
            phase: None,
            module: None,
            offset: Some(u64::MAX),
            limit: Some(u64::MAX),
        };
        let encoded = serde_json::to_string(&filter).expect("fixed-width record serializes");
        let decoded: FindingFilter = serde_json::from_str(&encoded).expect("record round-trips");
        assert_eq!(decoded.offset, Some(u64::MAX));
        assert_eq!(decoded.limit, Some(u64::MAX));
    }
}
