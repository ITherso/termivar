use venom_scanner::{
    ColumnDef, ConnectionPool, DbConfig, EndpointRecord, EntityType, FindingRecord, QueryBuilder,
    ScanRecord, SchemaManager, TableSchema, TransactionManager, TransactionStatus,
};

#[test]
fn test_db_config_defaults() {
    let config = DbConfig::default_sqlite();

    assert_eq!(config.pool_size, 10);
    assert_eq!(config.connection_timeout_secs, 30);
    assert!(config.enable_wal);
    assert!(config.enable_journal_mode);
    assert_eq!(config.max_connections, 50);
}

#[test]
fn test_db_config_custom() {
    let config = DbConfig {
        database_path: "/custom/path/db.sqlite".to_string(),
        pool_size: 20,
        connection_timeout_secs: 60,
        enable_wal: false,
        enable_journal_mode: false,
        max_connections: 100,
    };

    assert_eq!(config.pool_size, 20);
    assert!(!config.enable_wal);
}

#[test]
fn test_entity_type_variants() {
    assert_eq!(EntityType::Scan.as_str(), "scan");
    assert_eq!(EntityType::Finding.as_str(), "finding");
    assert_eq!(EntityType::Endpoint.as_str(), "endpoint");
    assert_eq!(EntityType::Vulnerability.as_str(), "vulnerability");
    assert_eq!(EntityType::ScanResult.as_str(), "scan_result");
}

#[test]
fn test_entity_type_table_names() {
    assert_eq!(EntityType::Scan.table_name(), "scans");
    assert_eq!(EntityType::Finding.table_name(), "findings");
    assert_eq!(EntityType::Endpoint.table_name(), "endpoints");
    assert_eq!(EntityType::Vulnerability.table_name(), "vulnerabilities");
    assert_eq!(EntityType::ScanResult.table_name(), "scan_results");
}

#[test]
fn test_scan_record_creation() {
    let record = ScanRecord {
        scan_id: "scan_001".to_string(),
        target_url: "https://example.com".to_string(),
        status: "completed".to_string(),
        started_at: 1000,
        completed_at: Some(2000),
        duration_ms: Some(1000),
        findings_count: 5,
        critical_count: 1,
        high_count: 2,
    };

    assert_eq!(record.scan_id, "scan_001");
    assert_eq!(record.findings_count, 5);
    assert_eq!(record.critical_count, 1);
}

#[test]
fn test_finding_record_creation() {
    let record = FindingRecord {
        finding_id: "find_001".to_string(),
        scan_id: "scan_001".to_string(),
        phase: 5,
        module_name: "SQLi".to_string(),
        severity: "CRITICAL".to_string(),
        description: "SQL injection vulnerability".to_string(),
        evidence: "Error: SQL syntax error".to_string(),
        discovered_at: 1500,
    };

    assert_eq!(record.module_name, "SQLi");
    assert_eq!(record.severity, "CRITICAL");
}

#[test]
fn test_endpoint_record_creation() {
    let record = EndpointRecord {
        endpoint_id: "ep_001".to_string(),
        scan_id: "scan_001".to_string(),
        url: "/api/users".to_string(),
        method: "GET".to_string(),
        status_code: 200,
        response_time_ms: 150,
        discovered_at: 1200,
    };

    assert_eq!(record.status_code, 200);
    assert_eq!(record.response_time_ms, 150);
}

#[test]
fn test_query_builder_basic() {
    let builder = QueryBuilder::new(EntityType::Scan)
        .filter("status".to_string(), "completed".to_string())
        .limit(10);

    let query = builder.build();
    assert!(query.contains("scans"));
    assert!(query.contains("status"));
    assert!(query.contains("LIMIT"));
}

#[test]
fn test_query_builder_multiple_filters() {
    let builder = QueryBuilder::new(EntityType::Finding)
        .filter("scan_id".to_string(), "scan1".to_string())
        .filter("severity".to_string(), "CRITICAL".to_string())
        .filter("phase".to_string(), "5".to_string())
        .limit(50)
        .offset(10);

    assert_eq!(builder.filter_count(), 3);
    let query = builder.build();
    assert!(query.contains("AND"));
    assert!(query.contains("OFFSET 10"));
}

#[test]
fn test_query_builder_pagination() {
    let builder1 = QueryBuilder::new(EntityType::Scan).limit(20).offset(0);
    let builder2 = QueryBuilder::new(EntityType::Scan).limit(20).offset(20);
    let builder3 = QueryBuilder::new(EntityType::Scan).limit(20).offset(40);

    let query1 = builder1.build();
    let query2 = builder2.build();
    let query3 = builder3.build();

    assert!(query1.contains("OFFSET 0"));
    assert!(query2.contains("OFFSET 20"));
    assert!(query3.contains("OFFSET 40"));
}

#[test]
fn test_schema_manager_registration() {
    let mut manager = SchemaManager::new();

    let schema = TableSchema {
        table_name: "findings".to_string(),
        columns: vec![
            ColumnDef {
                name: "finding_id".to_string(),
                data_type: "TEXT".to_string(),
                nullable: false,
                indexed: true,
            },
            ColumnDef {
                name: "severity".to_string(),
                data_type: "TEXT".to_string(),
                nullable: false,
                indexed: true,
            },
        ],
        indexes: vec![],
        primary_key: "finding_id".to_string(),
    };

    manager.register_schema(schema);
    assert_eq!(manager.schema_count(), 1);
}

#[test]
fn test_schema_manager_retrieval() {
    let mut manager = SchemaManager::new();

    let schema = TableSchema {
        table_name: "scans".to_string(),
        columns: vec![ColumnDef {
            name: "scan_id".to_string(),
            data_type: "TEXT".to_string(),
            nullable: false,
            indexed: true,
        }],
        indexes: vec![],
        primary_key: "scan_id".to_string(),
    };

    manager.register_schema(schema);
    let retrieved = manager.get_schema("scans");

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().table_name, "scans");
}

#[test]
fn test_schema_create_statement_generation() {
    let mut manager = SchemaManager::new();

    let schema = TableSchema {
        table_name: "findings".to_string(),
        columns: vec![
            ColumnDef {
                name: "finding_id".to_string(),
                data_type: "TEXT".to_string(),
                nullable: false,
                indexed: true,
            },
            ColumnDef {
                name: "description".to_string(),
                data_type: "TEXT".to_string(),
                nullable: true,
                indexed: false,
            },
        ],
        indexes: vec![],
        primary_key: "finding_id".to_string(),
    };

    manager.register_schema(schema);
    let stmt = manager.generate_create_statement("findings");

    assert!(stmt.is_some());
    let sql = stmt.unwrap();
    assert!(sql.contains("CREATE TABLE"));
    assert!(sql.contains("findings"));
    assert!(sql.contains("PRIMARY KEY"));
}

#[test]
fn test_connection_pool_creation() {
    let config = DbConfig::default_sqlite();
    let pool = ConnectionPool::new(config);

    assert_eq!(pool.connection_count(), 0);
    assert_eq!(pool.total_queries, 0);
    assert_eq!(pool.query_success_rate(), 100.0);
}

#[test]
fn test_connection_pool_query_tracking() {
    let config = DbConfig::default_sqlite();
    let mut pool = ConnectionPool::new(config);

    pool.record_query(true);
    pool.record_query(true);
    pool.record_query(true);

    assert_eq!(pool.total_queries, 3);
    assert_eq!(pool.failed_queries, 0);
    assert_eq!(pool.query_success_rate(), 100.0);
}

#[test]
fn test_connection_pool_failure_tracking() {
    let config = DbConfig::default_sqlite();
    let mut pool = ConnectionPool::new(config);

    pool.record_query(true);
    pool.record_query(true);
    pool.record_query(false);
    pool.record_query(false);

    assert_eq!(pool.total_queries, 4);
    assert_eq!(pool.failed_queries, 2);
    assert_eq!(pool.query_success_rate(), 50.0);
}

#[test]
fn test_transaction_manager_begin() {
    let mut manager = TransactionManager::new();
    let txn = manager.begin_transaction("txn_001".to_string());

    assert_eq!(txn.transaction_id, "txn_001");
    assert_eq!(txn.status, TransactionStatus::Active);
    assert_eq!(manager.transaction_count(), 1);
}

#[test]
fn test_transaction_manager_commit() {
    let mut manager = TransactionManager::new();
    manager.begin_transaction("txn_001".to_string());

    let success = manager.commit("txn_001");
    assert!(success);

    let txn = manager.get_transaction("txn_001").unwrap();
    assert_eq!(txn.status, TransactionStatus::Committed);
}

#[test]
fn test_transaction_manager_commit_nonexistent() {
    let mut manager = TransactionManager::new();
    let success = manager.commit("nonexistent");

    assert!(!success);
}

#[test]
fn test_transaction_status_variants() {
    assert_eq!(TransactionStatus::Active.as_str(), "active");
    assert_eq!(TransactionStatus::Committed.as_str(), "committed");
    assert_eq!(TransactionStatus::RolledBack.as_str(), "rolled_back");
    assert_eq!(TransactionStatus::Failed.as_str(), "failed");
}

#[test]
fn test_multiple_transactions() {
    let mut manager = TransactionManager::new();

    for i in 0..5 {
        manager.begin_transaction(format!("txn_{}", i));
    }

    assert_eq!(manager.transaction_count(), 5);

    for i in 0..5 {
        manager.commit(&format!("txn_{}", i));
    }

    for i in 0..5 {
        let txn = manager.get_transaction(&format!("txn_{}", i)).unwrap();
        assert_eq!(txn.status, TransactionStatus::Committed);
    }
}

#[test]
fn test_complex_schema_definition() {
    let mut manager = SchemaManager::new();

    let schemas = vec![
        TableSchema {
            table_name: "scans".to_string(),
            columns: vec![
                ColumnDef {
                    name: "scan_id".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: false,
                    indexed: true,
                },
                ColumnDef {
                    name: "target_url".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: false,
                    indexed: false,
                },
            ],
            indexes: vec![],
            primary_key: "scan_id".to_string(),
        },
        TableSchema {
            table_name: "findings".to_string(),
            columns: vec![
                ColumnDef {
                    name: "finding_id".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: false,
                    indexed: true,
                },
                ColumnDef {
                    name: "severity".to_string(),
                    data_type: "TEXT".to_string(),
                    nullable: false,
                    indexed: true,
                },
            ],
            indexes: vec![],
            primary_key: "finding_id".to_string(),
        },
    ];

    for schema in schemas {
        manager.register_schema(schema);
    }

    assert_eq!(manager.schema_count(), 2);
}

#[test]
fn test_query_builder_all_features() {
    let builder = QueryBuilder::new(EntityType::Finding)
        .filter("scan_id".to_string(), "scan1".to_string())
        .filter("severity".to_string(), "CRITICAL".to_string())
        .filter("phase".to_string(), "5".to_string())
        .limit(100)
        .offset(50);

    assert_eq!(builder.filter_count(), 3);

    let query = builder.build();
    assert!(query.contains("findings"));
    assert!(query.contains("WHERE"));
    assert!(query.contains("AND"));
    assert!(query.contains("LIMIT 100"));
    assert!(query.contains("OFFSET 50"));
}

#[test]
fn test_database_records_integration() {
    let scan = ScanRecord {
        scan_id: "integration_test".to_string(),
        target_url: "https://integration.test".to_string(),
        status: "running".to_string(),
        started_at: 1000,
        completed_at: None,
        duration_ms: None,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
    };

    let finding = FindingRecord {
        finding_id: "find_int_1".to_string(),
        scan_id: scan.scan_id.clone(),
        phase: 1,
        module_name: "Recon".to_string(),
        severity: "HIGH".to_string(),
        description: "Integration test finding".to_string(),
        evidence: "evidence".to_string(),
        discovered_at: 1100,
    };

    let endpoint = EndpointRecord {
        endpoint_id: "ep_int_1".to_string(),
        scan_id: scan.scan_id.clone(),
        url: "/test".to_string(),
        method: "GET".to_string(),
        status_code: 200,
        response_time_ms: 100,
        discovered_at: 1050,
    };

    assert_eq!(scan.scan_id, finding.scan_id);
    assert_eq!(scan.scan_id, endpoint.scan_id);
}
