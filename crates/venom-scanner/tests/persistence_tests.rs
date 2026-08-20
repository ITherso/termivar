#![cfg(feature = "platform-models")]

use venom_scanner::{
    ColumnDef, EndpointRecord, EntityType, FindingRecord, IndexDef, ScanRecord, SchemaManager,
    TableSchema,
};

fn schema(name: &str) -> TableSchema {
    TableSchema {
        table_name: name.to_string(),
        columns: vec![ColumnDef {
            name: "id".to_string(),
            data_type: "opaque-type-label".to_string(),
            nullable: false,
            indexed: true,
        }],
        indexes: vec![IndexDef {
            name: "by_id".to_string(),
            columns: vec!["id".to_string()],
            unique: true,
        }],
        primary_key: "id".to_string(),
    }
}

#[test]
fn persistence_surface_exposes_records() {
    let scan = ScanRecord {
        scan_id: "scan_001".to_string(),
        target_url: "https://example.test".to_string(),
        status: "observed-complete".to_string(),
        started_at: 1_000,
        completed_at: Some(2_000),
        duration_ms: Some(1_000),
        findings_count: 1,
        critical_count: 0,
        high_count: 1,
    };
    let finding = FindingRecord {
        finding_id: "finding_001".to_string(),
        scan_id: scan.scan_id.clone(),
        phase: 5,
        module_name: "fixture".to_string(),
        severity: "high".to_string(),
        description: "caller supplied".to_string(),
        evidence: "fixture evidence".to_string(),
        discovered_at: 1_500,
    };
    let endpoint = EndpointRecord {
        endpoint_id: "endpoint_001".to_string(),
        scan_id: scan.scan_id.clone(),
        url: "/fixture".to_string(),
        method: "GET".to_string(),
        status_code: 200,
        response_time_ms: 10,
        discovered_at: 1_250,
    };

    assert_eq!(EntityType::Scan.as_str(), "scan");
    assert_eq!(scan.scan_id, finding.scan_id);
    assert_eq!(scan.scan_id, endpoint.scan_id);
}

#[test]
fn schema_catalog_only_records_caller_metadata() {
    let mut catalog = SchemaManager::new();
    assert!(catalog.is_empty());
    assert!(catalog.register_schema(schema("scans")).is_none());
    assert_eq!(catalog.schema_count(), 1);
    assert_eq!(catalog.get_schema("scans"), Some(&schema("scans")));
}

#[test]
fn replacement_is_explicit_and_unknown_schema_is_absent() {
    let mut catalog = SchemaManager::new();
    let _ = catalog.register_schema(schema("scans"));

    let mut replacement = schema("scans");
    replacement.primary_key = "replacement_id".to_string();
    let previous = catalog.register_schema(replacement).unwrap();

    assert_eq!(previous.primary_key, "id");
    assert_eq!(
        catalog.get_schema("scans").unwrap().primary_key,
        "replacement_id"
    );
    assert!(catalog.get_schema("not-recorded").is_none());
}
