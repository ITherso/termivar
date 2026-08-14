use async_trait::async_trait;
use venom_scanner::{Plugin, PluginCategory, PluginContext, PluginError};

use super::record_exact_marker;

pub const SQL_MARKER: &str = "venom-fixture:sql";

pub struct SqlMarkerFixture;

#[async_trait]
impl Plugin for SqlMarkerFixture {
    fn id(&self) -> &str {
        "fixture.sql-marker"
    }
    fn name(&self) -> &str {
        "SQL Marker Trait Fixture"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn description(&self) -> &str {
        "Exercises the Plugin trait with an inert SQL-labelled marker"
    }
    fn author(&self) -> &str {
        "Venom contributors"
    }
    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        record_exact_marker(context, SQL_MARKER, "sql_marker", "SQL marker fixture")
    }
}
