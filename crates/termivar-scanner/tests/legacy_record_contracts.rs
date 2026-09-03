//! Deterministic public-contract tests for quarantined legacy scan records.
//!
//! Shared CI deliberately contains no wall-clock assertions. Endpoint-scale
//! performance belongs to the reproducible benchmark harness.

#![cfg(feature = "legacy-scanner")]

use termivar_scanner::{LogEntry, LogLevel, ScanFinding};

#[test]
fn scan_finding_json_round_trip_preserves_the_legacy_wire_shape() {
    let finding = ScanFinding {
        phase: 4,
        module_name: "legacy-parameter-phase".to_string(),
        severity: "LOW".to_string(),
        description: "Historical observation".to_string(),
        evidence: "bounded marker".to_string(),
    };

    let encoded = serde_json::to_value(&finding).expect("legacy finding should serialize");
    assert_eq!(
        encoded,
        serde_json::json!({
            "phase": 4,
            "module_name": "legacy-parameter-phase",
            "severity": "LOW",
            "description": "Historical observation",
            "evidence": "bounded marker"
        })
    );

    let decoded: ScanFinding =
        serde_json::from_value(encoded).expect("legacy finding should deserialize");
    assert_eq!(decoded.phase, finding.phase);
    assert_eq!(decoded.module_name, finding.module_name);
    assert_eq!(decoded.severity, finding.severity);
    assert_eq!(decoded.description, finding.description);
    assert_eq!(decoded.evidence, finding.evidence);
}

#[test]
fn public_log_entry_builders_preserve_structured_metadata() {
    let entry = LogEntry::new(LogLevel::Info, "Review complete".to_string())
        .with_phase(4)
        .with_context("redacted subject".to_string())
        .with_duration(17);

    assert_eq!(entry.level, LogLevel::Info);
    assert_eq!(entry.phase, Some(4));
    assert_eq!(entry.message, "Review complete");
    assert_eq!(entry.context.as_deref(), Some("redacted subject"));
    assert_eq!(entry.duration_ms, Some(17));
    assert!(entry
        .format()
        .ends_with("[INFO] [Phase 4] Review complete | redacted subject | 17ms"));
}
