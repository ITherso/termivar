//! Exercise the six harmless, INFO-only native plugin trait fixtures.
//!
//! Run with:
//! `cargo run -p termivar-examples --bin custom_plugin`

#[path = "plugin-fixtures/mod.rs"]
mod plugin_fixtures;

use async_trait::async_trait;
use plugin_fixtures::{
    LfiMarkerFixture, SqlMarkerFixture, SsrfMarkerFixture, SstiMarkerFixture, XssMarkerFixture,
    XxeMarkerFixture, LFI_MARKER, SQL_MARKER, SSRF_MARKER, SSTI_MARKER, XSS_MARKER, XXE_MARKER,
};
use std::sync::Arc;
use termivar_scanner::{
    EntityId, Plugin, PluginConfig, PluginError, PluginExecutionRequest, PluginHttpRequest,
    PluginHttpResponse, PluginRegistry, PluginRequestBroker, PLUGIN_API_VERSION,
};
use url::Url;

/// This example grants no network authority. The fixtures never call it.
struct NoIoBroker;

#[async_trait]
impl PluginRequestBroker for NoIoBroker {
    async fn execute(
        &self,
        _request: PluginHttpRequest,
    ) -> Result<PluginHttpResponse, PluginError> {
        Err(PluginError::BrokerFailure(
            "the trait-fixture host grants no transport authority".to_owned(),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = PluginRegistry::new();
    let broker: Arc<dyn PluginRequestBroker> = Arc::new(NoIoBroker);
    let subject = EntityId::new("authorized-origin:plugin-fixture")?;
    let origin = Url::parse("https://example.test/")?;
    let fixtures: Vec<(Arc<dyn Plugin>, &'static str)> = vec![
        (Arc::new(SqlMarkerFixture), SQL_MARKER),
        (Arc::new(XssMarkerFixture), XSS_MARKER),
        (Arc::new(LfiMarkerFixture), LFI_MARKER),
        (Arc::new(XxeMarkerFixture), XXE_MARKER),
        (Arc::new(SsrfMarkerFixture), SSRF_MARKER),
        (Arc::new(SstiMarkerFixture), SSTI_MARKER),
    ];

    println!("plugin API: {PLUGIN_API_VERSION}");
    for (fixture, marker) in fixtures {
        let id = fixture.id().to_owned();
        registry.register(fixture, PluginConfig::default())?;
        let request = PluginExecutionRequest::new(
            subject.clone(),
            origin.clone(),
            format!("case:{id}"),
            broker.clone(),
        )?
        .with_input(marker.as_bytes().to_vec())?;
        let receipt = registry.execute(&id, request).await?;
        println!(
            "plugin={} completed=true observations={} requests={} elapsed={}ms",
            receipt.plugin_id(),
            receipt.observations().len(),
            receipt.usage().requests(),
            receipt.elapsed_ms()
        );
    }

    Ok(())
}
