use async_trait::async_trait;
use venom_scanner::{Plugin, PluginCategory, PluginContext, PluginError};

use super::record_exact_marker;

pub const SSTI_MARKER: &str = "venom-fixture:ssti";

pub struct SstiMarkerFixture;

#[async_trait]
impl Plugin for SstiMarkerFixture {
    fn id(&self) -> &str {
        "fixture.ssti-marker"
    }
    fn name(&self) -> &str {
        "SSTI Marker Trait Fixture"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn description(&self) -> &str {
        "Exercises the Plugin trait with an inert SSTI-labelled marker"
    }
    fn author(&self) -> &str {
        "Venom contributors"
    }
    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        record_exact_marker(context, SSTI_MARKER, "ssti_marker", "SSTI marker fixture")
    }
}
