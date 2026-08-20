//! Historical raw scanner and HTTP record compatibility facade.
//!
//! This module is available only with the non-default `legacy-contracts`
//! feature. The records are not produced by the default decision runtime.
//!
//! ## Deprecated compatibility surface
//!
//! These unconstrained records remain solely for the pinned pre-1.0
//! patch-compatibility baseline. New runtimes should use verified
//! [`crate::Outcome`] and [`crate::RunReport`] records and own transport models
//! at the transport boundary.

use serde::{Deserialize, Serialize};

/// A raw observation returned by a bespoke historical `ScanPhase`.
///
/// # Examples
///
/// ```
/// use venom_core::ScanFinding;
///
/// let finding = ScanFinding {
///     phase: 1,
///     module_name: "legacy-header-phase".into(),
///     severity: "LOW".into(),
///     description: "Example observation".into(),
///     evidence: "response marker".into(),
/// };
///
/// assert_eq!(finding.phase, 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub phase: u8,
    pub module_name: String,
    pub severity: String,
    pub description: String,
    pub evidence: String,
}

/// Historical unconstrained vulnerability record retained for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub url: String,
    pub parameter: String,
    pub payload: String,
    pub evidence: String,
}

/// Historical raw scan result retained for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_time_ms: u64,
}

/// Historical transport request record retained for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// Historical transport response record retained for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}
