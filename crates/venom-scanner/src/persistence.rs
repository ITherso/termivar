//! Persistence record and schema metadata.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental data models.
//!
//! This module contains serializable records and an in-memory schema catalog.
//! It does not build SQL, connect to a database, manage a pool, execute a
//! transaction, or provide durable storage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Kind of record represented by persistence metadata.
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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Finding => "finding",
            Self::Endpoint => "endpoint",
            Self::Vulnerability => "vulnerability",
            Self::ScanResult => "scan_result",
        }
    }
}

/// Caller-supplied scan record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Caller-supplied finding record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Caller-supplied endpoint record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub endpoint_id: String,
    pub scan_id: String,
    pub url: String,
    pub method: String,
    pub status_code: u32,
    pub response_time_ms: u32,
    pub discovered_at: u64,
}

/// Declarative table metadata. Values are not interpreted as SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSchema {
    pub table_name: String,
    pub columns: Vec<ColumnDef>,
    pub indexes: Vec<IndexDef>,
    pub primary_key: String,
}

/// Declarative column metadata. `data_type` is an opaque caller-supplied label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub indexed: bool,
}

/// Declarative index metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDef {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

/// In-memory catalog of caller-supplied schema metadata.
#[derive(Debug, Clone, Default)]
pub struct SchemaManager {
    schemas: HashMap<String, TableSchema>,
}

impl SchemaManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records metadata and returns the previous value for the same name.
    ///
    /// This method does not create or alter a database table.
    pub fn register_schema(&mut self, schema: TableSchema) -> Option<TableSchema> {
        self.schemas.insert(schema.table_name.clone(), schema)
    }

    pub fn get_schema(&self, table_name: &str) -> Option<&TableSchema> {
        self.schemas.get(table_name)
    }

    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(name: &str, data_type: &str) -> TableSchema {
        TableSchema {
            table_name: name.to_string(),
            columns: vec![ColumnDef {
                name: "scan_id".to_string(),
                data_type: data_type.to_string(),
                nullable: false,
                indexed: true,
            }],
            indexes: Vec::new(),
            primary_key: "scan_id".to_string(),
        }
    }

    #[test]
    fn entity_type_is_metadata_without_table_mapping() {
        assert_eq!(EntityType::Finding.as_str(), "finding");
    }

    #[test]
    fn schema_catalog_is_empty_until_the_caller_records_metadata() {
        let catalog = SchemaManager::new();
        assert!(catalog.is_empty());
        assert!(catalog.get_schema("scans").is_none());
    }

    #[test]
    fn duplicate_schema_names_replace_and_return_the_previous_record() {
        let mut catalog = SchemaManager::new();
        assert!(catalog.register_schema(schema("scans", "TEXT")).is_none());

        let previous = catalog
            .register_schema(schema("scans", "opaque-not-sql"))
            .expect("the original metadata must be returned");

        assert_eq!(previous.columns[0].data_type, "TEXT");
        assert_eq!(catalog.schema_count(), 1);
        assert_eq!(
            catalog.get_schema("scans").unwrap().columns[0].data_type,
            "opaque-not-sql"
        );
    }

    #[test]
    fn schema_values_remain_opaque_metadata() {
        let suspicious = "TEXT); DROP TABLE scans; --";
        let mut catalog = SchemaManager::new();
        let _ = catalog.register_schema(schema("scans", suspicious));

        assert_eq!(
            catalog.get_schema("scans").unwrap().columns[0].data_type,
            suspicious
        );
    }
}
