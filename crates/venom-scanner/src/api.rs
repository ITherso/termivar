//! REST API Module
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Comprehensive REST API for scan management, reporting, and control.
//! Supports JSON requests/responses, error handling, and real-time updates.

use crate::ScanFinding;
use serde::{Deserialize, Serialize};

/// API Request to start a new scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartScanRequest {
    pub target: String,
    pub config: Option<ScanConfigRequest>,
    pub tags: Option<Vec<String>>,
}

/// API Request for scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigRequest {
    pub intensity: Option<String>,
    pub timeout_secs: Option<u64>,
    pub max_concurrency: Option<usize>,
    pub rate_limit: Option<f32>,
    pub enable_waf_evasion: Option<bool>,
    pub enable_adaptive_payloads: Option<bool>,
    pub enable_anomaly_detection: Option<bool>,
    pub phases: Option<Vec<u8>>,
}

/// Scan status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub target: String,
    pub status: ScanStatusType,
    pub progress: f32,
    pub findings_count: usize,
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
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn err(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
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
    pub offset: Option<usize>,
    pub limit: Option<usize>,
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
    pub avg_scan_duration_ms: f64,
}

/// Endpoint definitions
pub struct ApiEndpoints;

impl ApiEndpoints {
    /// POST /api/v1/scans - Start new scan
    pub fn start_scan() -> &'static str {
        "POST /api/v1/scans"
    }

    /// GET /api/v1/scans/{scan_id} - Get scan status
    pub fn get_scan_status() -> &'static str {
        "GET /api/v1/scans/{scan_id}"
    }

    /// GET /api/v1/scans - List all scans
    pub fn list_scans() -> &'static str {
        "GET /api/v1/scans"
    }

    /// DELETE /api/v1/scans/{scan_id} - Cancel scan
    pub fn cancel_scan() -> &'static str {
        "DELETE /api/v1/scans/{scan_id}"
    }

    /// POST /api/v1/scans/{scan_id}/pause - Pause scan
    pub fn pause_scan() -> &'static str {
        "POST /api/v1/scans/{scan_id}/pause"
    }

    /// POST /api/v1/scans/{scan_id}/resume - Resume scan
    pub fn resume_scan() -> &'static str {
        "POST /api/v1/scans/{scan_id}/resume"
    }

    /// GET /api/v1/scans/{scan_id}/results - Get scan results
    pub fn get_scan_results() -> &'static str {
        "GET /api/v1/scans/{scan_id}/results"
    }

    /// GET /api/v1/scans/{scan_id}/report - Export report
    pub fn export_report() -> &'static str {
        "GET /api/v1/scans/{scan_id}/report?format=json|csv|html|markdown"
    }

    /// GET /api/v1/findings - Query findings
    pub fn query_findings() -> &'static str {
        "GET /api/v1/findings?severity=CRITICAL&phase=5&limit=50"
    }

    /// GET /api/v1/stats - Get statistics
    pub fn get_statistics() -> &'static str {
        "GET /api/v1/stats"
    }

    /// GET /api/v1/health - Health check
    pub fn health_check() -> &'static str {
        "GET /api/v1/health"
    }

    /// Lists all endpoints
    pub fn all_endpoints() -> Vec<&'static str> {
        vec![
            Self::start_scan(),
            Self::get_scan_status(),
            Self::list_scans(),
            Self::cancel_scan(),
            Self::pause_scan(),
            Self::resume_scan(),
            Self::get_scan_results(),
            Self::export_report(),
            Self::query_findings(),
            Self::get_statistics(),
            Self::health_check(),
        ]
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
            ApiError::ScanNotFound(id) => format!("Scan not found: {}", id),
            ApiError::InvalidConfig(msg) => format!("Invalid configuration: {}", msg),
            ApiError::InvalidTarget(url) => format!("Invalid target URL: {}", url),
            ApiError::ScanAlreadyRunning(id) => format!("Scan already running: {}", id),
            ApiError::InternalError(msg) => format!("Internal error: {}", msg),
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
        let response: ApiResponse<String> = ApiResponse::ok("Success".to_string());
        assert!(response.success);
        assert_eq!(response.data, Some("Success".to_string()));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_err() {
        let response: ApiResponse<String> = ApiResponse::err("Error".to_string());
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
    fn test_api_endpoints_count() {
        let endpoints = ApiEndpoints::all_endpoints();
        assert_eq!(endpoints.len(), 11);
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
        let err = ApiError::ScanNotFound("abc123".to_string());
        assert!(err.message().contains("abc123"));

        let err2 = ApiError::InvalidTarget("invalid".to_string());
        assert!(err2.message().contains("invalid"));
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
            enable_waf_evasion: Some(true),
            enable_adaptive_payloads: Some(true),
            enable_anomaly_detection: Some(true),
            phases: Some(vec![1, 2, 3, 5, 6, 7, 8]),
        };

        assert_eq!(config.intensity, Some("aggressive".to_string()));
        assert_eq!(config.max_concurrency, Some(100));
        assert!(config.enable_waf_evasion.unwrap());
    }
}
