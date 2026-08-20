//! Caller-supplied compliance and audit records.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `compliance`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental data models.
//!
//! The collections in this module are in-memory catalogs. They do not perform
//! an audit, determine legal compliance, generate a report, or persist data.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GDPR => "gdpr",
            Self::HIPAA => "hipaa",
            Self::SOC2 => "soc2",
            Self::PCIDSS => "pci_dss",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub requirement_id: String,
    pub framework: ComplianceFramework,
    pub name: String,
    pub description: String,
    pub controls: Vec<String>,
}

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
    #[serde(rename = "report_recorded")]
    ReportRecorded,
    #[serde(rename = "access_denied")]
    AccessDenied,
}

impl AuditEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanInitiated => "scan_initiated",
            Self::FindingDiscovered => "finding_discovered",
            Self::DataAccessed => "data_accessed",
            Self::UserLogin => "user_login",
            Self::UserLogout => "user_logout",
            Self::ConfigChanged => "config_changed",
            Self::ReportRecorded => "report_recorded",
            Self::AccessDenied => "access_denied",
        }
    }
}

/// Caller-supplied audit event record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub log_id: String,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub user_id: String,
    pub resource: String,
    pub action: String,
    pub reported_status: String,
    pub details: String,
}

/// In-memory audit record collection.
#[derive(Debug, Clone, Default)]
pub struct AuditTrail {
    entries: Vec<AuditLogEntry>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_entry(&mut self, entry: AuditLogEntry) {
        self.entries.push(entry);
    }

    pub fn entries_by_type(&self, event_type: AuditEventType) -> Vec<&AuditLogEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.event_type == event_type)
            .collect()
    }

    pub fn entries_by_user(&self, user_id: &str) -> Vec<&AuditLogEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.user_id == user_id)
            .collect()
    }

    pub fn entries_since(&self, timestamp: u64) -> Vec<&AuditLogEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.timestamp >= timestamp)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Caller-supplied control counts for one assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceAssessment {
    pub assessment_id: String,
    pub framework: ComplianceFramework,
    pub timestamp: u64,
    pub total_controls: u32,
    pub compliant_controls: u32,
    pub non_compliant_controls: u32,
}

impl ComplianceAssessment {
    pub fn has_consistent_control_counts(&self) -> bool {
        u64::from(self.compliant_controls) + u64::from(self.non_compliant_controls)
            == u64::from(self.total_controls)
    }

    /// Calculated percentage, absent for zero or inconsistent control counts.
    pub fn compliance_percentage(&self) -> Option<f64> {
        if self.total_controls == 0 || !self.has_consistent_control_counts() {
            return None;
        }
        Some(f64::from(self.compliant_controls) / f64::from(self.total_controls) * 100.0)
    }

    /// Applies an explicit caller-supplied threshold.
    pub fn meets_threshold(&self, threshold_percent: f64) -> Option<bool> {
        if !threshold_percent.is_finite() || !(0.0..=100.0).contains(&threshold_percent) {
            return None;
        }
        self.compliance_percentage()
            .map(|percentage| percentage >= threshold_percent)
    }
}

/// In-memory requirement and assessment catalog.
#[derive(Debug, Clone, Default)]
pub struct ComplianceCatalog {
    requirements: BTreeMap<String, ComplianceRequirement>,
    assessments: Vec<ComplianceAssessment>,
}

impl ComplianceCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_requirement(
        &mut self,
        requirement: ComplianceRequirement,
    ) -> Option<ComplianceRequirement> {
        self.requirements
            .insert(requirement.requirement_id.clone(), requirement)
    }

    /// Records only assessments whose control counts are internally consistent.
    pub fn record_assessment(&mut self, assessment: ComplianceAssessment) -> bool {
        if !assessment.has_consistent_control_counts() {
            return false;
        }
        self.assessments.push(assessment);
        true
    }

    pub fn requirements_for(&self, framework: ComplianceFramework) -> Vec<&ComplianceRequirement> {
        self.requirements
            .values()
            .filter(|requirement| requirement.framework == framework)
            .collect()
    }

    pub fn assessments_for(&self, framework: ComplianceFramework) -> Vec<&ComplianceAssessment> {
        self.assessments
            .iter()
            .filter(|assessment| assessment.framework == framework)
            .collect()
    }

    pub fn requirement_count(&self) -> usize {
        self.requirements.len()
    }

    pub fn assessment_count(&self) -> usize {
        self.assessments.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataProtectionRecord {
    pub record_id: String,
    pub data_type: String,
    pub classification: DataClassification,
    pub owner_id: String,
    pub last_accessed: u64,
    pub access_count: u32,
    pub reported_encrypted: bool,
}

/// In-memory catalog of caller-supplied data protection records.
#[derive(Debug, Clone, Default)]
pub struct DataProtectionCatalog {
    records: BTreeMap<String, DataProtectionRecord>,
}

impl DataProtectionCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, record: DataProtectionRecord) -> Option<DataProtectionRecord> {
        self.records.insert(record.record_id.clone(), record)
    }

    pub fn records_by_classification(
        &self,
        classification: DataClassification,
    ) -> Vec<&DataProtectionRecord> {
        self.records
            .values()
            .filter(|record| record.classification == classification)
            .collect()
    }

    pub fn records_reported_unencrypted_at_or_above(
        &self,
        minimum: DataClassification,
    ) -> Vec<&DataProtectionRecord> {
        self.records
            .values()
            .filter(|record| !record.reported_encrypted && record.classification >= minimum)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Caller-supplied report record; no report generation is performed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub framework: ComplianceFramework,
    pub generated_at: u64,
    pub assessment_period_days: u32,
    #[serde(with = "optional_percent_f32")]
    pub reported_compliance_score_percent: Option<f32>,
    pub reported_critical_findings: u32,
    pub proposed_remediation_actions: Vec<String>,
}

impl ComplianceReport {
    pub fn has_valid_reported_score(&self) -> bool {
        self.reported_compliance_score_percent
            .is_none_or(|score| score.is_finite() && (0.0..=100.0).contains(&score))
    }
}

mod optional_percent_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<f32>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) if value.is_finite() && (0.0..=100.0).contains(value) => {
                serializer.serialize_some(value)
            },
            Some(_) => Err(serde::ser::Error::custom(
                "reported compliance score must be finite and between 0 and 100",
            )),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<f32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<f32>::deserialize(deserializer)?;
        Ok(match value {
            Some(value) if value.is_finite() && (0.0..=100.0).contains(&value) => Some(value),
            Some(_) => {
                return Err(serde::de::Error::custom(
                    "reported compliance score must be finite and between 0 and 100",
                ));
            },
            None => None,
        })
    }
}

/// In-memory catalog of caller-supplied report records.
#[derive(Debug, Clone, Default)]
pub struct ComplianceReportCatalog {
    reports: Vec<ComplianceReport>,
}

impl ComplianceReportCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records only reports whose optional percentage is finite and in range.
    pub fn record_report(&mut self, report: ComplianceReport) -> bool {
        if !report.has_valid_reported_score() {
            return false;
        }
        self.reports.push(report);
        true
    }

    pub fn reports_for(&self, framework: ComplianceFramework) -> Vec<&ComplianceReport> {
        self.reports
            .iter()
            .filter(|report| report.framework == framework)
            .collect()
    }

    /// Returns all reports tied for the greatest caller-supplied timestamp.
    pub fn most_recent_reports(&self, framework: ComplianceFramework) -> Vec<&ComplianceReport> {
        let reports = self.reports_for(framework);
        let Some(timestamp) = reports.iter().map(|report| report.generated_at).max() else {
            return Vec::new();
        };
        reports
            .into_iter()
            .filter(|report| report.generated_at == timestamp)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.reports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assessment(compliant: u32, non_compliant: u32) -> ComplianceAssessment {
        ComplianceAssessment {
            assessment_id: "assessment".into(),
            framework: ComplianceFramework::GDPR,
            timestamp: 1,
            total_controls: 100,
            compliant_controls: compliant,
            non_compliant_controls: non_compliant,
        }
    }

    #[test]
    fn threshold_is_caller_supplied_not_hardcoded() {
        let assessment = assessment(94, 6);
        assert_eq!(assessment.meets_threshold(90.0), Some(true));
        assert_eq!(assessment.meets_threshold(95.0), Some(false));
        assert_eq!(assessment.meets_threshold(f64::NAN), None);
    }

    #[test]
    fn inconsistent_counts_do_not_produce_a_score() {
        let inconsistent = assessment(90, 5);
        assert!(!inconsistent.has_consistent_control_counts());
        assert_eq!(inconsistent.compliance_percentage(), None);
        assert_eq!(inconsistent.meets_threshold(80.0), None);
    }

    #[test]
    fn catalogs_are_empty_until_records_are_supplied() {
        assert!(AuditTrail::new().is_empty());
        assert!(DataProtectionCatalog::new().is_empty());
        assert!(ComplianceReportCatalog::new().is_empty());
    }

    #[test]
    fn most_recent_report_preserves_timestamp_ties() {
        let mut catalog = ComplianceReportCatalog::new();
        for id in ["one", "two"] {
            assert!(catalog.record_report(ComplianceReport {
                report_id: id.into(),
                framework: ComplianceFramework::SOC2,
                generated_at: 10,
                assessment_period_days: 30,
                reported_compliance_score_percent: None,
                reported_critical_findings: 0,
                proposed_remediation_actions: Vec::new(),
            }));
        }
        assert_eq!(
            catalog.most_recent_reports(ComplianceFramework::SOC2).len(),
            2
        );
    }

    #[test]
    fn catalogs_reject_inconsistent_and_nonfinite_records() {
        let mut assessments = ComplianceCatalog::new();
        assert!(!assessments.record_assessment(assessment(90, 5)));
        assert_eq!(assessments.assessment_count(), 0);

        let mut reports = ComplianceReportCatalog::new();
        let invalid = ComplianceReport {
            report_id: "invalid".into(),
            framework: ComplianceFramework::SOC2,
            generated_at: 1,
            assessment_period_days: 1,
            reported_compliance_score_percent: Some(f32::NAN),
            reported_critical_findings: 0,
            proposed_remediation_actions: Vec::new(),
        };
        assert!(!reports.record_report(invalid.clone()));
        assert!(serde_json::to_string(&invalid).is_err());
        assert!(reports.is_empty());
    }

    #[test]
    fn keyed_catalog_queries_are_stably_ordered() {
        let mut catalog = ComplianceCatalog::new();
        for id in ["zeta", "alpha"] {
            let _ = catalog.record_requirement(ComplianceRequirement {
                requirement_id: id.into(),
                framework: ComplianceFramework::SOC2,
                name: "fixture".into(),
                description: "fixture".into(),
                controls: Vec::new(),
            });
        }
        assert_eq!(
            catalog
                .requirements_for(ComplianceFramework::SOC2)
                .into_iter()
                .map(|requirement| requirement.requirement_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
    }
}
