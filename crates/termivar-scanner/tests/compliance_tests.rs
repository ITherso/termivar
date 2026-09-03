#![cfg(feature = "compliance")]

use termivar_scanner::{
    AuditEventType, AuditLogEntry, AuditTrail, ComplianceAssessment, ComplianceCatalog,
    ComplianceFramework, ComplianceReport, ComplianceReportCatalog, ComplianceRequirement,
    DataClassification, DataProtectionCatalog, DataProtectionRecord,
};

#[test]
fn assessment_calculation_requires_consistent_evidence() {
    let valid = ComplianceAssessment {
        assessment_id: "valid".into(),
        framework: ComplianceFramework::GDPR,
        timestamp: 1_000,
        total_controls: 10,
        compliant_controls: 9,
        non_compliant_controls: 1,
    };
    assert_eq!(valid.compliance_percentage(), Some(90.0));
    assert_eq!(valid.meets_threshold(90.0), Some(true));
    assert_eq!(valid.meets_threshold(95.0), Some(false));

    let inconsistent = ComplianceAssessment {
        non_compliant_controls: 0,
        ..valid.clone()
    };
    assert_eq!(inconsistent.compliance_percentage(), None);
    assert_eq!(inconsistent.meets_threshold(50.0), None);
}

#[test]
fn audit_trail_records_only_caller_supplied_entries() {
    let mut trail = AuditTrail::new();
    assert!(trail.is_empty());
    trail.record_entry(AuditLogEntry {
        log_id: "entry".into(),
        timestamp: 100,
        event_type: AuditEventType::AccessDenied,
        user_id: "fixture-user".into(),
        resource: "fixture-resource".into(),
        action: "read".into(),
        reported_status: "denied-by-fixture".into(),
        details: "caller supplied".into(),
    });

    assert_eq!(trail.len(), 1);
    assert_eq!(trail.entries_by_user("fixture-user").len(), 1);
    assert_eq!(trail.entries_since(101).len(), 0);
}

#[test]
fn compliance_catalog_does_not_invent_assessments() {
    let mut catalog = ComplianceCatalog::new();
    let _ = catalog.record_requirement(ComplianceRequirement {
        requirement_id: "req".into(),
        framework: ComplianceFramework::SOC2,
        name: "fixture requirement".into(),
        description: "caller supplied".into(),
        controls: vec!["control-1".into()],
    });

    assert_eq!(catalog.requirement_count(), 1);
    assert_eq!(catalog.assessment_count(), 0);
    assert!(catalog
        .assessments_for(ComplianceFramework::SOC2)
        .is_empty());
}

#[test]
fn data_protection_query_uses_explicit_classification_threshold() {
    let mut catalog = DataProtectionCatalog::new();
    for (id, classification, encrypted) in [
        ("internal", DataClassification::Internal, false),
        ("confidential", DataClassification::Confidential, false),
        ("restricted", DataClassification::Restricted, true),
    ] {
        let _ = catalog.record(DataProtectionRecord {
            record_id: id.into(),
            data_type: "fixture".into(),
            classification,
            owner_id: "owner".into(),
            last_accessed: 100,
            access_count: 1,
            reported_encrypted: encrypted,
        });
    }

    let records =
        catalog.records_reported_unencrypted_at_or_above(DataClassification::Confidential);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_id, "confidential");
}

#[test]
fn report_catalog_preserves_caller_claims_and_timestamp_ties() {
    let mut catalog = ComplianceReportCatalog::new();
    for id in ["first", "second"] {
        assert!(catalog.record_report(ComplianceReport {
            report_id: id.into(),
            framework: ComplianceFramework::HIPAA,
            generated_at: 500,
            assessment_period_days: 90,
            reported_compliance_score_percent: Some(12.5),
            reported_critical_findings: 7,
            proposed_remediation_actions: vec!["caller proposal".into()],
        }));
    }

    let reports = catalog.most_recent_reports(ComplianceFramework::HIPAA);
    assert_eq!(reports.len(), 2);
    assert!(reports
        .iter()
        .all(|report| report.reported_compliance_score_percent == Some(12.5)));
}

#[test]
fn framework_and_event_labels_are_data_only() {
    assert_eq!(ComplianceFramework::PCIDSS.as_str(), "pci_dss");
    assert_eq!(AuditEventType::ReportRecorded.as_str(), "report_recorded");
    assert_eq!(DataClassification::Restricted.as_str(), "restricted");
}
