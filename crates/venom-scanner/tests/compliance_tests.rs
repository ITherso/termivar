use venom_scanner::{
    AuditEventType, AuditLogEntry, AuditLogger, ComplianceAssessment, ComplianceAssessor,
    ComplianceFramework, ComplianceReport, ComplianceReporter, ComplianceRequirement,
    DataClassification, DataProtectionManager, DataProtectionRecord,
};

#[test]
fn test_compliance_framework_variants() {
    assert_eq!(ComplianceFramework::GDPR.as_str(), "gdpr");
    assert_eq!(ComplianceFramework::HIPAA.as_str(), "hipaa");
    assert_eq!(ComplianceFramework::SOC2.as_str(), "soc2");
    assert_eq!(ComplianceFramework::PCIDSS.as_str(), "pci_dss");
}

#[test]
fn test_compliance_requirement() {
    let req = ComplianceRequirement {
        requirement_id: "gdpr_001".to_string(),
        framework: ComplianceFramework::GDPR,
        name: "Data Processing Agreement".to_string(),
        description: "Must have DPA with all data processors".to_string(),
        controls: vec!["DPA_001".to_string(), "DPA_002".to_string()],
    };

    assert_eq!(req.framework, ComplianceFramework::GDPR);
    assert_eq!(req.controls.len(), 2);
}

#[test]
fn test_audit_event_types() {
    assert_eq!(AuditEventType::ScanInitiated.as_str(), "scan_initiated");
    assert_eq!(
        AuditEventType::FindingDiscovered.as_str(),
        "finding_discovered"
    );
    assert_eq!(AuditEventType::DataAccessed.as_str(), "data_accessed");
    assert_eq!(AuditEventType::UserLogin.as_str(), "user_login");
    assert_eq!(AuditEventType::AccessDenied.as_str(), "access_denied");
}

#[test]
fn test_audit_logger_creation() {
    let logger = AuditLogger::new();
    assert_eq!(logger.log_count(), 0);
}

#[test]
fn test_audit_logger_event_recording() {
    let mut logger = AuditLogger::new();

    for i in 0..5 {
        let entry = AuditLogEntry {
            log_id: format!("log_{}", i),
            timestamp: 1000 + i as u64,
            event_type: AuditEventType::ScanInitiated,
            user_id: format!("user_{}", i % 2),
            resource: format!("scan_{}", i),
            action: "scan_start".to_string(),
            status: "success".to_string(),
            details: "Scan initiated".to_string(),
        };
        logger.log_event(entry);
    }

    assert_eq!(logger.log_count(), 5);
}

#[test]
fn test_audit_logger_filter_by_type() {
    let mut logger = AuditLogger::new();

    let entry1 = AuditLogEntry {
        log_id: "log1".to_string(),
        timestamp: 1000,
        event_type: AuditEventType::ScanInitiated,
        user_id: "user1".to_string(),
        resource: "scan1".to_string(),
        action: "scan".to_string(),
        status: "success".to_string(),
        details: "Started".to_string(),
    };

    let entry2 = AuditLogEntry {
        log_id: "log2".to_string(),
        timestamp: 2000,
        event_type: AuditEventType::UserLogin,
        user_id: "user1".to_string(),
        resource: "session".to_string(),
        action: "login".to_string(),
        status: "success".to_string(),
        details: "User logged in".to_string(),
    };

    logger.log_event(entry1);
    logger.log_event(entry2);

    let scan_logs = logger.get_logs_by_type(AuditEventType::ScanInitiated);
    let login_logs = logger.get_logs_by_type(AuditEventType::UserLogin);

    assert_eq!(scan_logs.len(), 1);
    assert_eq!(login_logs.len(), 1);
}

#[test]
fn test_audit_logger_filter_by_user() {
    let mut logger = AuditLogger::new();

    for i in 0..3 {
        let entry = AuditLogEntry {
            log_id: format!("log_{}", i),
            timestamp: 1000 + i as u64,
            event_type: AuditEventType::DataAccessed,
            user_id: "user_admin".to_string(),
            resource: format!("resource_{}", i),
            action: "access".to_string(),
            status: "success".to_string(),
            details: "Accessed".to_string(),
        };
        logger.log_event(entry);
    }

    let admin_logs = logger.get_logs_by_user("user_admin");
    assert_eq!(admin_logs.len(), 3);
}

#[test]
fn test_audit_logger_filter_by_timestamp() {
    let mut logger = AuditLogger::new();

    for i in 0..5 {
        let entry = AuditLogEntry {
            log_id: format!("log_{}", i),
            timestamp: 1000 + i as u64 * 100,
            event_type: AuditEventType::ScanInitiated,
            user_id: "user1".to_string(),
            resource: format!("scan_{}", i),
            action: "scan".to_string(),
            status: "success".to_string(),
            details: "Initiated".to_string(),
        };
        logger.log_event(entry);
    }

    let recent_logs = logger.get_logs_since(1300);
    assert_eq!(recent_logs.len(), 2);
}

#[test]
fn test_compliance_assessment() {
    let assessment = ComplianceAssessment {
        assessment_id: "assess1".to_string(),
        framework: ComplianceFramework::GDPR,
        timestamp: 1000,
        total_controls: 100,
        compliant_controls: 98,
        non_compliant_controls: 2,
        score: 98.0,
    };

    assert_eq!(assessment.compliance_percentage(), 98.0);
    assert!(assessment.is_compliant());
}

#[test]
fn test_compliance_assessment_non_compliant() {
    let assessment = ComplianceAssessment {
        assessment_id: "assess2".to_string(),
        framework: ComplianceFramework::HIPAA,
        timestamp: 1000,
        total_controls: 100,
        compliant_controls: 90,
        non_compliant_controls: 10,
        score: 90.0,
    };

    assert_eq!(assessment.compliance_percentage(), 90.0);
    assert!(!assessment.is_compliant());
}

#[test]
fn test_compliance_assessor() {
    let mut assessor = ComplianceAssessor::new();

    let req = ComplianceRequirement {
        requirement_id: "req1".to_string(),
        framework: ComplianceFramework::SOC2,
        name: "Access Control".to_string(),
        description: "Must implement access control".to_string(),
        controls: vec!["AC_001".to_string()],
    };

    assessor.register_requirement(req);
    assert_eq!(assessor.requirement_count(), 1);
}

#[test]
fn test_compliance_assessor_assessment() {
    let mut assessor = ComplianceAssessor::new();

    let assessment = ComplianceAssessment {
        assessment_id: "assess1".to_string(),
        framework: ComplianceFramework::GDPR,
        timestamp: 1000,
        total_controls: 100,
        compliant_controls: 97,
        non_compliant_controls: 3,
        score: 97.0,
    };

    assessor.create_assessment(assessment);
    assert_eq!(assessor.assessment_count(), 1);

    let score = assessor.get_framework_score(ComplianceFramework::GDPR);
    assert_eq!(score, Some(97.0));
}

#[test]
fn test_data_classification_levels() {
    assert_eq!(DataClassification::Public.security_level(), 1);
    assert_eq!(DataClassification::Internal.security_level(), 2);
    assert_eq!(DataClassification::Confidential.security_level(), 3);
    assert_eq!(DataClassification::Restricted.security_level(), 4);
}

#[test]
fn test_data_classification_strings() {
    assert_eq!(DataClassification::Public.as_str(), "public");
    assert_eq!(DataClassification::Confidential.as_str(), "confidential");
    assert_eq!(DataClassification::Restricted.as_str(), "restricted");
}

#[test]
fn test_data_protection_manager() {
    let mut manager = DataProtectionManager::new();

    let record = DataProtectionRecord {
        record_id: "rec1".to_string(),
        data_type: "customer_data".to_string(),
        classification: DataClassification::Confidential,
        owner_id: "dept_sales".to_string(),
        last_accessed: 1000,
        access_count: 5,
        encrypted: true,
    };

    manager.register_record(record);
    assert_eq!(manager.record_count(), 1);
}

#[test]
fn test_data_protection_filter_by_classification() {
    let mut manager = DataProtectionManager::new();

    for i in 0..3 {
        let record = DataProtectionRecord {
            record_id: format!("rec_{}", i),
            data_type: "data".to_string(),
            classification: if i % 2 == 0 {
                DataClassification::Confidential
            } else {
                DataClassification::Restricted
            },
            owner_id: "owner".to_string(),
            last_accessed: 1000,
            access_count: 1,
            encrypted: true,
        };
        manager.register_record(record);
    }

    let confidential = manager.get_by_classification(DataClassification::Confidential);
    assert_eq!(confidential.len(), 2);

    let restricted = manager.get_by_classification(DataClassification::Restricted);
    assert_eq!(restricted.len(), 1);
}

#[test]
fn test_data_protection_unencrypted_sensitive() {
    let mut manager = DataProtectionManager::new();

    let unencrypted_sensitive = DataProtectionRecord {
        record_id: "rec1".to_string(),
        data_type: "sensitive".to_string(),
        classification: DataClassification::Restricted,
        owner_id: "owner".to_string(),
        last_accessed: 1000,
        access_count: 1,
        encrypted: false,
    };

    let encrypted_sensitive = DataProtectionRecord {
        record_id: "rec2".to_string(),
        data_type: "sensitive".to_string(),
        classification: DataClassification::Confidential,
        owner_id: "owner".to_string(),
        last_accessed: 1000,
        access_count: 1,
        encrypted: true,
    };

    manager.register_record(unencrypted_sensitive);
    manager.register_record(encrypted_sensitive);

    let unencrypted = manager.get_unencrypted_sensitive();
    assert_eq!(unencrypted.len(), 1);
}

#[test]
fn test_compliance_report() {
    let report = ComplianceReport {
        report_id: "report1".to_string(),
        framework: ComplianceFramework::GDPR,
        generated_at: 1000,
        assessment_period_days: 90,
        overall_compliance_score: 96.5,
        critical_findings: 1,
        remediation_actions: vec![
            "Implement DPA".to_string(),
            "Update privacy policy".to_string(),
        ],
    };

    assert_eq!(report.framework, ComplianceFramework::GDPR);
    assert_eq!(report.remediation_actions.len(), 2);
}

#[test]
fn test_compliance_reporter() {
    let mut reporter = ComplianceReporter::new();

    for i in 0..3 {
        let report = ComplianceReport {
            report_id: format!("report_{}", i),
            framework: ComplianceFramework::HIPAA,
            generated_at: 1000 + i as u64 * 100,
            assessment_period_days: 90,
            overall_compliance_score: 90.0 + i as f32,
            critical_findings: 2 - i as u32,
            remediation_actions: vec![],
        };
        reporter.generate_report(report);
    }

    assert_eq!(reporter.report_count(), 3);
}

#[test]
fn test_compliance_reporter_latest() {
    let mut reporter = ComplianceReporter::new();

    let report1 = ComplianceReport {
        report_id: "report1".to_string(),
        framework: ComplianceFramework::SOC2,
        generated_at: 1000,
        assessment_period_days: 90,
        overall_compliance_score: 94.0,
        critical_findings: 0,
        remediation_actions: vec![],
    };

    let report2 = ComplianceReport {
        report_id: "report2".to_string(),
        framework: ComplianceFramework::SOC2,
        generated_at: 2000,
        assessment_period_days: 90,
        overall_compliance_score: 97.5,
        critical_findings: 0,
        remediation_actions: vec![],
    };

    reporter.generate_report(report1);
    reporter.generate_report(report2);

    let latest = reporter.get_latest_report(ComplianceFramework::SOC2);
    assert!(latest.is_some());
    assert_eq!(latest.unwrap().overall_compliance_score, 97.5);
}

#[test]
fn test_compliance_reporter_trend() {
    let mut reporter = ComplianceReporter::new();

    let scores = [85.0, 88.0, 91.0, 94.0, 97.0];

    for (i, &score) in scores.iter().enumerate() {
        let report = ComplianceReport {
            report_id: format!("report_{}", i),
            framework: ComplianceFramework::PCIDSS,
            generated_at: 1000 + i as u64 * 100,
            assessment_period_days: 90,
            overall_compliance_score: score,
            critical_findings: 0,
            remediation_actions: vec![],
        };
        reporter.generate_report(report);
    }

    let trend = reporter.get_trend(ComplianceFramework::PCIDSS);
    assert_eq!(trend.len(), 5);
    assert_eq!(trend[0], 85.0);
    assert_eq!(trend[4], 97.0);
}

#[test]
fn test_multi_framework_compliance() {
    let mut assessor = ComplianceAssessor::new();

    let frameworks = [
        ComplianceFramework::GDPR,
        ComplianceFramework::HIPAA,
        ComplianceFramework::SOC2,
        ComplianceFramework::PCIDSS,
    ];

    for (i, framework) in frameworks.iter().enumerate() {
        let assessment = ComplianceAssessment {
            assessment_id: format!("assess_{}", i),
            framework: *framework,
            timestamp: 1000,
            total_controls: 100,
            compliant_controls: 90 + i as u32,
            non_compliant_controls: 10 - i as u32,
            score: (90.0 + i as f32),
        };
        assessor.create_assessment(assessment);
    }

    assert_eq!(assessor.assessment_count(), 4);

    assert_eq!(
        assessor.get_framework_score(ComplianceFramework::GDPR),
        Some(90.0)
    );
    assert_eq!(
        assessor.get_framework_score(ComplianceFramework::HIPAA),
        Some(91.0)
    );
}

#[test]
fn test_comprehensive_compliance_scenario() {
    let mut logger = AuditLogger::new();
    let mut assessor = ComplianceAssessor::new();
    let mut reporter = ComplianceReporter::new();

    // Log audit events
    for i in 0..5 {
        let entry = AuditLogEntry {
            log_id: format!("audit_{}", i),
            timestamp: 1000 + i as u64,
            event_type: if i % 2 == 0 {
                AuditEventType::ScanInitiated
            } else {
                AuditEventType::FindingDiscovered
            },
            user_id: "security_team".to_string(),
            resource: format!("target_{}", i),
            action: "scan".to_string(),
            status: "success".to_string(),
            details: "Vulnerability scan completed".to_string(),
        };
        logger.log_event(entry);
    }

    // Create assessment
    let assessment = ComplianceAssessment {
        assessment_id: "assess_final".to_string(),
        framework: ComplianceFramework::GDPR,
        timestamp: 1000,
        total_controls: 100,
        compliant_controls: 95,
        non_compliant_controls: 5,
        score: 95.0,
    };
    assessor.create_assessment(assessment);

    // Generate report
    let report = ComplianceReport {
        report_id: "report_final".to_string(),
        framework: ComplianceFramework::GDPR,
        generated_at: 1500,
        assessment_period_days: 90,
        overall_compliance_score: 95.0,
        critical_findings: 1,
        remediation_actions: vec!["Address 5 non-compliant controls".to_string()],
    };
    reporter.generate_report(report);

    assert_eq!(logger.log_count(), 5);
    assert_eq!(assessor.assessment_count(), 1);
    assert_eq!(reporter.report_count(), 1);
}
