use serde::{Deserialize, Serialize};

/// A structured observation produced by a scan phase or plugin.
///
/// # Examples
///
/// ```
/// use venom_core::ScanFinding;
///
/// let finding = ScanFinding {
///     phase: 1,
///     module_name: "example-plugin".into(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}
