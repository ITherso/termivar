//! Database Persistence Layer
//!
//! SQLite abstraction, schema management, and optimized queries.
//!
//! # Runtime scope
//!
//! This module is part of the **platform-shell** boundary in Runtime Consolidation
//! 5.5. It is compiled with the `scanning` feature but is currently not executed
//! by default `venom scan`.
//!
//! Current contract:
//!
//! - Persistence helpers are preserved for platform integrations and future
//!   productization milestones.
//! - The default scan runtime does not depend on this module for its execution
//!   path.
//! - Any production migration into scan runtime requires explicit ADR and runtime
//!   ownership transfer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Database connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    pub database_path: String,
    pub pool_size: u32,
    pub connection_timeout_secs: u32,
    pub enable_wal: bool,
    pub enable_journal_mode: bool,
    pub max_connections: u32,
}

impl DbConfig {
    pub fn default_sqlite() -> Self {
        Self {
            database_path: ".venom/scans.db".to_string(),
            pool_size: 10,
            connection_timeout_secs: 30,
            enable_wal: true,
            enable_journal_mode: true,
            max_connections: 50,
        }
    }
}

/// Database entity types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    #[serde(rename = "scan")]
    Scan,
    #[serde(rename = "finding")]
    Finding,
    #[serde(rename = "endpoint")]
    Endpoint,
    #[serde(rename = "vulnerability")]
    Vulnerability,
    #[serde(rename = "scan_result")]
    ScanResult,
}

impl EntityType {
    pub fn as_str(&self) -> &str {
        match self {
            EntityType::Scan => "scan",
            EntityType::Finding => "finding",
            EntityType::Endpoint => "endpoint",
            EntityType::Vulnerability => "vulnerability",
            EntityType::ScanResult => "scan_result",
        }
    }

    pub fn table_name(&self) -> &str {
        match self {
            EntityType::Scan => "scans",
            EntityType::Finding => "findings",
            EntityType::Endpoint => "endpoints",
            EntityType::Vulnerability => "vulnerabilities",
            EntityType::ScanResult => "scan_results",
        }
    }
}

/// Scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub scan_id: String,
    pub target_url: String,
    pub status: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub duration_ms: Option<u64>,
    pub findings_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
}

/// Finding record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub finding_id: String,
    pub scan_id: String,
    pub phase: u8,
    pub module_name: String,
    pub severity: String,
    pub description: String,
    pub evidence: String,
    pub discovered_at: u64,
}

/// Endpoint record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub endpoint_id: String,
    pub scan_id: String,
    pub url: String,
    pub method: String,
    pub status_code: u32,
    pub response_time_ms: u32,
    pub discovered_at: u64,
}

/// Database query builder
pub struct QueryBuilder {
    entity_type: EntityType,
    filters: HashMap<String, String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

impl QueryBuilder {
    pub fn new(entity_type: EntityType) -> Self {
        Self {
            entity_type,
            filters: HashMap::new(),
            limit: None,
            offset: None,
        }
    }

    /// Adds filter condition
    pub fn filter(mut self, key: String, value: String) -> Self {
        self.filters.insert(key, value);
        self
    }

    /// Sets result limit
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sets result offset
    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Builds SQL query string
    pub fn build(&self) -> String {
        let mut query = format!("SELECT * FROM {}", self.entity_type.table_name());

        if !self.filters.is_empty() {
            query.push_str(" WHERE ");
            let conditions: Vec<String> = self
                .filters
                .iter()
                .map(|(k, v)| format!("{} = '{}'", k, v))
                .collect();
            query.push_str(&conditions.join(" AND "));
        }

        if let Some(limit) = self.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = self.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        query
    }

    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }
}

/// Database schema manager
pub struct SchemaManager {
    schemas: HashMap<String, TableSchema>,
}

/// Table schema definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub table_name: String,
    pub columns: Vec<ColumnDef>,
    pub indexes: Vec<IndexDef>,
    pub primary_key: String,
}

/// Column definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub indexed: bool,
}

/// Index definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDef {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

impl SchemaManager {
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
        }
    }

    /// Registers a table schema
    pub fn register_schema(&mut self, schema: TableSchema) {
        self.schemas.insert(schema.table_name.clone(), schema);
    }

    /// Gets schema by table name
    pub fn get_schema(&self, table_name: &str) -> Option<&TableSchema> {
        self.schemas.get(table_name)
    }

    /// Generates CREATE TABLE statement
    pub fn generate_create_statement(&self, table_name: &str) -> Option<String> {
        if let Some(schema) = self.get_schema(table_name) {
            let mut stmt = format!("CREATE TABLE IF NOT EXISTS {} (", table_name);

            let columns: Vec<String> = schema
                .columns
                .iter()
                .map(|col| {
                    let nullable = if col.nullable { "" } else { " NOT NULL" };
                    format!("{} {}{}", col.name, col.data_type, nullable)
                })
                .collect();

            stmt.push_str(&columns.join(", "));
            stmt.push_str(&format!(", PRIMARY KEY ({})", schema.primary_key));
            stmt.push(')');

            Some(stmt)
        } else {
            None
        }
    }

    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }
}

impl Default for SchemaManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub query: String,
    pub row_count: u32,
    pub execution_time_ms: u32,
    pub success: bool,
}

/// Database connection pool
pub struct ConnectionPool {
    pub config: DbConfig,
    pub active_connections: u32,
    pub total_queries: u64,
    pub failed_queries: u64,
}

impl ConnectionPool {
    pub fn new(config: DbConfig) -> Self {
        Self {
            config,
            active_connections: 0,
            total_queries: 0,
            failed_queries: 0,
        }
    }

    /// Records a query execution
    pub fn record_query(&mut self, success: bool) {
        self.total_queries += 1;
        if !success {
            self.failed_queries += 1;
        }
    }

    /// Gets query success rate
    pub fn query_success_rate(&self) -> f32 {
        if self.total_queries == 0 {
            return 100.0;
        }
        ((self.total_queries - self.failed_queries) as f32 / self.total_queries as f32) * 100.0
    }

    pub fn connection_count(&self) -> u32 {
        self.active_connections
    }
}

/// Database transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub started_at: u64,
    pub operations: u32,
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "committed")]
    Committed,
    #[serde(rename = "rolled_back")]
    RolledBack,
    #[serde(rename = "failed")]
    Failed,
}

impl TransactionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TransactionStatus::Active => "active",
            TransactionStatus::Committed => "committed",
            TransactionStatus::RolledBack => "rolled_back",
            TransactionStatus::Failed => "failed",
        }
    }
}

/// Transaction manager
pub struct TransactionManager {
    transactions: HashMap<String, Transaction>,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    /// Begins a transaction
    pub fn begin_transaction(&mut self, transaction_id: String) -> Transaction {
        let txn = Transaction {
            transaction_id: transaction_id.clone(),
            status: TransactionStatus::Active,
            started_at: current_timestamp(),
            operations: 0,
        };
        self.transactions.insert(transaction_id, txn.clone());
        txn
    }

    /// Gets transaction by ID
    pub fn get_transaction(&self, transaction_id: &str) -> Option<&Transaction> {
        self.transactions.get(transaction_id)
    }

    /// Commits transaction
    pub fn commit(&mut self, transaction_id: &str) -> bool {
        if let Some(txn) = self.transactions.get_mut(transaction_id) {
            txn.status = TransactionStatus::Committed;
            true
        } else {
            false
        }
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_config() {
        let config = DbConfig::default_sqlite();
        assert_eq!(config.pool_size, 10);
        assert!(config.enable_wal);
    }

    #[test]
    fn test_entity_types() {
        assert_eq!(EntityType::Scan.as_str(), "scan");
        assert_eq!(EntityType::Finding.table_name(), "findings");
    }

    #[test]
    fn test_scan_record() {
        let record = ScanRecord {
            scan_id: "scan1".to_string(),
            target_url: "https://example.com".to_string(),
            status: "completed".to_string(),
            started_at: 1000,
            completed_at: Some(2000),
            duration_ms: Some(1000),
            findings_count: 5,
            critical_count: 1,
            high_count: 2,
        };

        assert_eq!(record.findings_count, 5);
    }

    #[test]
    fn test_query_builder() {
        let builder = QueryBuilder::new(EntityType::Finding)
            .filter("scan_id".to_string(), "scan1".to_string())
            .filter("severity".to_string(), "CRITICAL".to_string())
            .limit(10)
            .offset(0);

        assert_eq!(builder.filter_count(), 2);
        let query = builder.build();
        assert!(query.contains("findings"));
    }

    #[test]
    fn test_schema_manager() {
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
        assert_eq!(manager.schema_count(), 1);
    }

    #[test]
    fn test_connection_pool() {
        let config = DbConfig::default_sqlite();
        let mut pool = ConnectionPool::new(config);

        pool.record_query(true);
        pool.record_query(true);
        pool.record_query(false);

        assert_eq!(pool.total_queries, 3);
        assert_eq!(pool.failed_queries, 1);
        assert!(pool.query_success_rate() > 60.0);
    }

    #[test]
    fn test_transaction_manager() {
        let mut manager = TransactionManager::new();
        let txn = manager.begin_transaction("txn1".to_string());

        assert_eq!(txn.status, TransactionStatus::Active);
        assert_eq!(manager.transaction_count(), 1);
    }

    #[test]
    fn test_transaction_commit() {
        let mut manager = TransactionManager::new();
        manager.begin_transaction("txn1".to_string());

        let success = manager.commit("txn1");
        assert!(success);

        let txn = manager.get_transaction("txn1").unwrap();
        assert_eq!(txn.status, TransactionStatus::Committed);
    }
}
