use async_trait::async_trait;
use venom_scanner::{Plugin, PluginCategory, PluginContext, PluginError};

use super::record_exact_marker;

pub const SSRF_MARKER: &str = "venom-fixture:ssrf";

pub struct SsrfMarkerFixture;

#[async_trait]
impl Plugin for SsrfMarkerFixture {
    fn id(&self) -> &str {
        "fixture.ssrf-marker"
    }
    fn name(&self) -> &str {
        "SSRF Marker Trait Fixture"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn description(&self) -> &str {
        "Exercises the Plugin trait with an inert SSRF-labelled marker"
    }
    fn author(&self) -> &str {
        "Venom contributors"
    }
    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        record_exact_marker(context, SSRF_MARKER, "ssrf_marker", "SSRF marker fixture")
    }
}
