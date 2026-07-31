//! Stable data and execution contracts shared by scanner components.

use crate::{context::ScanContext, error::Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A structured observation produced by a scan phase or plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub phase: u8,
    pub module_name: String,
    pub severity: String,
    pub description: String,
    pub evidence: String,
}

/// Minimal execution contract understood by the scan runner.
#[async_trait]
pub trait ScanPhase: Send + Sync {
    /// Phase number used to order the pipeline.
    fn phase_number(&self) -> u8;

    /// Human-readable phase name used in logs and events.
    fn name(&self) -> &'static str;

    /// Execute phase logic and return structured findings.
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>>;
}
