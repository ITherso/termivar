use async_trait::async_trait;
use termivar_scanner::{Plugin, PluginCategory, PluginContext, PluginError};

use super::record_exact_marker;

pub const LFI_MARKER: &str = "venom-fixture:lfi";

pub struct LfiMarkerFixture;

#[async_trait]
impl Plugin for LfiMarkerFixture {
    fn id(&self) -> &str {
        "fixture.lfi-marker"
    }
    fn name(&self) -> &str {
        "LFI Marker Trait Fixture"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn description(&self) -> &str {
        "Exercises the Plugin trait with an inert LFI-labelled marker"
    }
    fn author(&self) -> &str {
        "Termivar contributors"
    }
    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        record_exact_marker(context, LFI_MARKER, "lfi_marker", "LFI marker fixture")
    }
}
