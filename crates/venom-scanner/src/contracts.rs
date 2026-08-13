//! Stable data and execution contracts shared by scanner components.
//!
//! ## Runtime scope
//!
//! - **Build:** non-default `legacy-scanner` feature.
//! - **Execution:** Surface A contract used by the historical `ScanRunner`.
//! - **Default `venom scan`:** no.
//! - **Support:** legacy alpha.
//!
//! See `docs/internals/runtime-map.md`.

use crate::{context::ScanContext, error::Result};
use async_trait::async_trait;
pub use venom_core::ScanFinding;

/// Minimal execution contract understood by the scan runner.
///
/// Implementations contain detection logic only. Scheduling, cancellation,
/// event publication, and aggregation remain runner responsibilities.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use venom_scanner::{Result, ScanContext, ScanFinding, ScanPhase};
///
/// struct HeaderPhase;
///
/// #[async_trait]
/// impl ScanPhase for HeaderPhase {
///     fn phase_number(&self) -> u8 { 10 }
///     fn name(&self) -> &'static str { "header-check" }
///
///     async fn execute(&self, _ctx: &ScanContext) -> Result<Vec<ScanFinding>> {
///         Ok(Vec::new())
///     }
/// }
/// ```
#[async_trait]
pub trait ScanPhase: Send + Sync {
    /// Phase number used to order the pipeline.
    fn phase_number(&self) -> u8;

    /// Human-readable phase name used in logs and events.
    fn name(&self) -> &'static str;

    /// Execute phase logic and return structured findings.
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>>;
}
