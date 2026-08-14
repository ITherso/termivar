//! Harmless INFO-only fixtures for the source-level plugin trait.

mod lfi;
mod sql;
mod ssrf;
mod ssti;
mod xss;
mod xxe;

pub use lfi::{LfiMarkerFixture, LFI_MARKER};
pub use sql::{SqlMarkerFixture, SQL_MARKER};
pub use ssrf::{SsrfMarkerFixture, SSRF_MARKER};
pub use ssti::{SstiMarkerFixture, SSTI_MARKER};
pub use xss::{XssMarkerFixture, XSS_MARKER};
pub use xxe::{XxeMarkerFixture, XXE_MARKER};

use venom_scanner::{
    EvidenceKind, EvidenceValue, KnowledgePredicate, PluginContext, PluginError, PluginObservation,
};

pub(super) fn record_exact_marker(
    context: &PluginContext,
    marker: &str,
    predicate_name: &str,
    fixture_name: &str,
) -> Result<(), PluginError> {
    if context.input() != marker.as_bytes() {
        return Ok(());
    }

    let predicate = KnowledgePredicate::new("plugin.fixture", predicate_name)
        .map_err(|_| PluginError::InvalidConfig("fixture predicate is invalid".to_owned()))?;
    context.record(PluginObservation::new(
        EvidenceKind::Custom("plugin.fixture.marker".to_owned()),
        predicate,
        EvidenceValue::Text(format!(
            "INFO observation: {fixture_name} exercised the Plugin trait boundary; no security claim"
        )),
        "trait-boundary",
    )?)
}
