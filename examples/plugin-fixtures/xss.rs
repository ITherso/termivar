use async_trait::async_trait;
use termivar_scanner::{Plugin, PluginCategory, PluginContext, PluginError};

use super::record_exact_marker;

pub const XSS_MARKER: &str = "venom-fixture:xss";

pub struct XssMarkerFixture;

#[async_trait]
impl Plugin for XssMarkerFixture {
    fn id(&self) -> &str {
        "fixture.xss-marker"
    }
    fn name(&self) -> &str {
        "XSS Marker Trait Fixture"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn description(&self) -> &str {
        "Exercises the Plugin trait with an inert XSS-labelled marker"
    }
    fn author(&self) -> &str {
        "Termivar contributors"
    }
    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        record_exact_marker(context, XSS_MARKER, "xss_marker", "XSS marker fixture")
    }
}
