//! Compliance & Automated Reporting
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `compliance`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! GDPR, HIPAA, SOC2 compliance frameworks and audit trails.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compliance framework types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    #[serde(rename = "gdpr")]
    GDPR,
    #[serde(rename = "hipaa")]
    HIPAA,
    #[serde(rename = "soc2")]
    SOC2,
    #[serde(rename = "pci_dss")]
    PCIDSS,
}

impl ComplianceFramework {
    pub fn as_str(&self) -> &str {
        match self {
            ComplianceFramework::GDPR => "gdpr",
            ComplianceFramework::HIPAA => "hipaa",
            ComplianceFramework::SOC2 => "soc2",
            ComplianceFramework::PCIDSS => "pci_dss",
        }
    }
}

/// Compliance requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub requirement_id: String,
    pub framework: ComplianceFramework,
    pub name: String,
    pub description: String,
    pub controls: Vec<String>,
}

/// Audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    #[serde(rename = "scan_initiated")]
    ScanInitiated,
    #[serde(rename = "finding_discovered")]
    FindingDiscovered,
    #[serde(rename = "data_accessed")]
    DataAccessed,
    #[serde(rename = "user_login")]
    UserLogin,
    #[serde(rename = "user_logout")]
    UserLogout,
    #[serde(rename = "config_changed")]
    ConfigChanged,
    #[serde(rename = "report_generated")]
    ReportGenerated,
    #[serde(rename = "access_denied")]
    AccessDenied,
}

impl AuditEventType {
    pub fn as_str(&self) -> &str {
        match self {
            AuditEventType::ScanInitiated => "scan_initiated",
            AuditEventType::FindingDiscovered => "finding_discovered",
            AuditEventType::DataAccessed => "data_accessed",
            AuditEventType::UserLogin => "user_login",
            AuditEventType::UserLogout => "user_logout",
            AuditEventType::ConfigChanged => "config_changed",
            AuditEventType::ReportGenerated => "report_generated",
            AuditEventType::AccessDenied => "access_denied",
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub log_id: String,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub user_id: String,
    pub resource: String,
    pub action: String,
    pub status: String,
    pub details: String,
}

/// Audit logger for compliance tracking
pub struct AuditLogger {
    logs: Vec<AuditLogEntry>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self { logs: Vec::new() }
    }

    /// Records an audit event
    pub fn log_event(&mut self, entry: AuditLogEntry) {
        self.logs.push(entry);
    }

    /// Gets logs by event type
    pub fn get_logs_by_type(&self, event_type: AuditEventType) -> Vec<&AuditLogEntry> {
        self.logs
            .iter()
            .filter(|log| log.event_type == event_type)
            .collect()
    }

    /// Gets logs by user
    pub fn get_logs_by_user(&self, user_id: &str) -> Vec<&AuditLogEntry> {
        self.logs
            .iter()
            .filter(|log| log.user_id == user_id)
            .collect()
    }

    /// Gets logs in time range
    pub fn get_logs_since(&self, timestamp: u64) -> Vec<&AuditLogEntry> {
        self.logs
            .iter()
            .filter(|log| log.timestamp >= timestamp)
            .collect()
    }

    pub fn log_count(&self) -> usize {
        self.logs.len()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Compliance assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessment {
    pub assessment_id: String,
    pub framework: ComplianceFramework,
    pub timestamp: u64,
    pub total_controls: u32,
    pub compliant_controls: u32,
    pub non_compliant_controls: u32,
    pub score: f32,
}

impl ComplianceAssessment {
    pub fn compliance_percentage(&self) -> f32 {
        if self.total_controls == 0 {
            return 0.0;
        }
        (self.compliant_controls as f32 / self.total_controls as f32) * 100.0
    }

    pub fn is_compliant(&self) -> bool {
        self.compliance_percentage() >= 95.0
    }
}

/// Compliance assessor
pub struct ComplianceAssessor {
    requirements: HashMap<String, ComplianceRequirement>,
    assessments: Vec<ComplianceAssessment>,
}

impl ComplianceAssessor {
    pub fn new() -> Self {
        Self {
            requirements: HashMap::new(),
            assessments: Vec::new(),
        }
    }

    /// Registers a compliance requirement
    pub fn register_requirement(&mut self, req: ComplianceRequirement) {
        self.requirements.insert(req.requirement_id.clone(), req);
    }

    /// Creates an assessment
    pub fn create_assessment(&mut self, assessment: ComplianceAssessment) {
        self.assessments.push(assessment);
    }

    /// Gets compliance score for framework
    pub fn get_framework_score(&self, framework: ComplianceFramework) -> Option<f32> {
        self.assessments
            .iter()
            .rev()
            .find(|a| a.framework == framework)
            .map(|a| a.score)
    }

    pub fn requirement_count(&self) -> usize {
        self.requirements.len()
    }

    pub fn assessment_count(&self) -> usize {
        self.assessments.len()
    }
}

impl Default for ComplianceAssessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Data protection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionRecord {
    pub record_id: String,
    pub data_type: String,
    pub classification: DataClassification,
    pub owner_id: String,
    pub last_accessed: u64,
    pub access_count: u32,
    pub encrypted: bool,
}

/// Data classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClassification {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "confidential")]
    Confidential,
    #[serde(rename = "restricted")]
    Restricted,
}

impl DataClassification {
    pub fn as_str(&self) -> &str {
        match self {
            DataClassification::Public => "public",
            DataClassification::Internal => "internal",
            DataClassification::Confidential => "confidential",
            DataClassification::Restricted => "restricted",
        }
    }

    pub fn security_level(&self) -> u8 {
        match self {
            DataClassification::Public => 1,
            DataClassification::Internal => 2,
            DataClassification::Confidential => 3,
            DataClassification::Restricted => 4,
        }
    }
}

/// Data protection manager
pub struct DataProtectionManager {
    records: Vec<DataProtectionRecord>,
}

impl DataProtectionManager {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Registers a data protection record
    pub fn register_record(&mut self, record: DataProtectionRecord) {
        self.records.push(record);
    }

    /// Gets records by classification
    pub fn get_by_classification(
        &self,
        classification: DataClassification,
    ) -> Vec<&DataProtectionRecord> {
        self.records
            .iter()
            .filter(|r| r.classification == classification)
            .collect()
    }

    /// Gets unencrypted sensitive data
    pub fn get_unencrypted_sensitive(&self) -> Vec<&DataProtectionRecord> {
        self.records
            .iter()
            .filter(|r| !r.encrypted && r.classification.security_level() >= 3)
            .collect()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl Default for DataProtectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub framework: ComplianceFramework,
    pub generated_at: u64,
    pub assessment_period_days: u32,
    pub overall_compliance_score: f32,
    pub critical_findings: u32,
    pub remediation_actions: Vec<String>,
}

/// Compliance reporter
pub struct ComplianceReporter {
    reports: Vec<ComplianceReport>,
}

impl ComplianceReporter {
    pub fn new() -> Self {
        Self {
            reports: Vec::new(),
        }
    }

    /// Generates a compliance report
    pub fn generate_report(&mut self, report: ComplianceReport) {
        self.reports.push(report);
    }

    /// Gets latest report for framework
    pub fn get_latest_report(&self, framework: ComplianceFramework) -> Option<&ComplianceReport> {
        self.reports.iter().rev().find(|r| r.framework == framework)
    }

    /// Gets report trend (compliance scores over time)
    pub fn get_trend(&self, framework: ComplianceFramework) -> Vec<f32> {
        self.reports
            .iter()
            .filter(|r| r.framework == framework)
            .map(|r| r.overall_compliance_score)
            .collect()
    }

    pub fn report_count(&self) -> usize {
        self.reports.len()
    }
}

impl Default for ComplianceReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_framework() {
        assert_eq!(ComplianceFramework::GDPR.as_str(), "gdpr");
        assert_eq!(ComplianceFramework::HIPAA.as_str(), "hipaa");
        assert_eq!(ComplianceFramework::SOC2.as_str(), "soc2");
    }

    #[test]
    fn test_audit_event_types() {
        assert_eq!(AuditEventType::ScanInitiated.as_str(), "scan_initiated");
        assert_eq!(
            AuditEventType::FindingDiscovered.as_str(),
            "finding_discovered"
        );
    }

    #[test]
    fn test_audit_logger() {
        let mut logger = AuditLogger::new();
        let entry = AuditLogEntry {
            log_id: "log1".to_string(),
            timestamp: 1000,
            event_type: AuditEventType::ScanInitiated,
            user_id: "user1".to_string(),
            resource: "scan_001".to_string(),
            action: "initiated".to_string(),
            status: "success".to_string(),
            details: "Scan started".to_string(),
        };

        logger.log_event(entry);
        assert_eq!(logger.log_count(), 1);
    }

    #[test]
    fn test_compliance_assessment() {
        let assessment = ComplianceAssessment {
            assessment_id: "assess1".to_string(),
            framework: ComplianceFramework::GDPR,
            timestamp: 1000,
            total_controls: 100,
            compliant_controls: 97,
            non_compliant_controls: 3,
            score: 97.0,
        };

        assert_eq!(assessment.compliance_percentage(), 97.0);
        assert!(assessment.is_compliant());
    }

    #[test]
    fn test_data_classification() {
        assert_eq!(DataClassification::Public.as_str(), "public");
        assert_eq!(DataClassification::Restricted.security_level(), 4);
    }

    #[test]
    fn test_compliance_reporter() {
        let mut reporter = ComplianceReporter::new();
        let report = ComplianceReport {
            report_id: "report1".to_string(),
            framework: ComplianceFramework::HIPAA,
            generated_at: 1000,
            assessment_period_days: 90,
            overall_compliance_score: 94.5,
            critical_findings: 2,
            remediation_actions: vec!["Fix access control".to_string()],
        };

        reporter.generate_report(report);
        assert_eq!(reporter.report_count(), 1);
    }
}
