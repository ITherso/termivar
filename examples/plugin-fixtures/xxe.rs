use async_trait::async_trait;
use venom_scanner::{Plugin, PluginCategory, PluginContext, PluginError};

use super::record_exact_marker;

pub const XXE_MARKER: &str = "venom-fixture:xxe";

pub struct XxeMarkerFixture;

#[async_trait]
impl Plugin for XxeMarkerFixture {
    fn id(&self) -> &str {
        "fixture.xxe-marker"
    }
    fn name(&self) -> &str {
        "XXE Marker Trait Fixture"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn description(&self) -> &str {
        "Exercises the Plugin trait with an inert XXE-labelled marker"
    }
    fn author(&self) -> &str {
        "Venom contributors"
    }
    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        record_exact_marker(context, XXE_MARKER, "xxe_marker", "XXE marker fixture")
    }
}
