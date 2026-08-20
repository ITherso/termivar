#![cfg(feature = "plugins")]

use async_trait::async_trait;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use url::Url;
use venom_scanner::{
    ConfidenceScore, EntityId, EvidenceKind, EvidenceValue, KnowledgePredicate, Plugin,
    PluginCategory, PluginConfig, PluginContext, PluginError, PluginExecutionRequest,
    PluginHttpRequest, PluginHttpResponse, PluginObservation, PluginRegistry, PluginRequestBroker,
};

const PLUGIN_ID: &str = "fixture.marker";
const CASE_ID: &str = "case:plugin-integration";

struct MarkerFixture {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Plugin for MarkerFixture {
    fn id(&self) -> &str {
        PLUGIN_ID
    }

    fn name(&self) -> &str {
        "Marker Fixture"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn description(&self) -> &str {
        "Exercises the plugin trait boundary without making a security claim"
    }

    fn author(&self) -> &str {
        "Venom"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if context.input() == b"fixture-marker" {
            context.record(PluginObservation::new(
                EvidenceKind::Custom("plugin.fixture".to_owned()),
                KnowledgePredicate::new("plugin.fixture", "marker")
                    .map_err(|error| PluginError::ExecutionFailed(error.to_string()))?,
                EvidenceValue::Boolean(true),
                "marker-match",
            )?)?;
        }
        Ok(())
    }
}

struct IncompatibleFixture;

#[async_trait]
impl Plugin for IncompatibleFixture {
    fn api_version(&self) -> &str {
        "0.1.99"
    }

    fn id(&self) -> &str {
        "fixture.incompatible"
    }

    fn name(&self) -> &str {
        "Incompatible Fixture"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn description(&self) -> &str {
        "Exercises API-line rejection"
    }

    fn author(&self) -> &str {
        "Venom"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }
}

struct NoNetworkBroker;

#[async_trait]
impl PluginRequestBroker for NoNetworkBroker {
    async fn execute(&self, request: PluginHttpRequest) -> Result<PluginHttpResponse, PluginError> {
        Err(PluginError::BrokerFailure(format!(
            "unexpected request to {}",
            request.url().origin().ascii_serialization()
        )))
    }
}

fn request(input: &[u8]) -> PluginExecutionRequest {
    PluginExecutionRequest::new(
        EntityId::new("endpoint:https://fixture.test/").unwrap(),
        Url::parse("https://fixture.test/").unwrap(),
        CASE_ID,
        Arc::new(NoNetworkBroker),
    )
    .unwrap()
    .with_input(input.to_vec())
    .unwrap()
    .with_reliability(ConfidenceScore::from_percent(80).unwrap())
}

#[tokio::test]
async fn registry_returns_host_bound_observation_not_a_finding() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = PluginRegistry::new();
    registry
        .register(
            Arc::new(MarkerFixture {
                calls: Arc::clone(&calls),
            }),
            PluginConfig::default(),
        )
        .unwrap();

    let result = registry
        .execute(PLUGIN_ID, request(b"fixture-marker"))
        .await
        .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.plugin_id(), PLUGIN_ID);
    assert_eq!(result.usage().observations(), 1);
    assert_eq!(result.observations().len(), 1);
    let observation = &result.observations()[0];
    assert_eq!(
        observation.subject().as_str(),
        "endpoint:https://fixture.test/"
    );
    assert_eq!(observation.source().component(), PLUGIN_ID);
    assert_eq!(observation.source().correlation_id(), Some(CASE_ID));
    assert_eq!(observation.predicate().dotted(), "plugin.fixture.marker");
    assert_eq!(observation.value(), &EvidenceValue::Boolean(true));

    let wire = serde_json::to_string(&result).unwrap();
    assert!(!wire.contains("finding"));
    assert!(!wire.contains("confirmed"));
    assert!(!wire.contains("severity"));
}

#[tokio::test]
async fn duplicate_registration_preserves_the_original_entry() {
    let original_calls = Arc::new(AtomicUsize::new(0));
    let duplicate_calls = Arc::new(AtomicUsize::new(0));
    let registry = PluginRegistry::new();
    registry
        .register(
            Arc::new(MarkerFixture {
                calls: Arc::clone(&original_calls),
            }),
            PluginConfig::default(),
        )
        .unwrap();

    assert_eq!(
        registry.register(
            Arc::new(MarkerFixture {
                calls: Arc::clone(&duplicate_calls),
            }),
            PluginConfig::new(false),
        ),
        Err(PluginError::DuplicateId)
    );
    registry.execute(PLUGIN_ID, request(b"")).await.unwrap();

    assert_eq!(registry.count(), 1);
    assert_eq!(original_calls.load(Ordering::SeqCst), 1);
    assert_eq!(duplicate_calls.load(Ordering::SeqCst), 0);
    assert!(registry.get_config(PLUGIN_ID).unwrap().enabled());
}

#[tokio::test]
async fn disabled_plugin_is_rejected_before_plugin_code_runs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = PluginRegistry::new();
    registry
        .register(
            Arc::new(MarkerFixture {
                calls: Arc::clone(&calls),
            }),
            PluginConfig::new(false),
        )
        .unwrap();

    assert_eq!(
        registry
            .execute(PLUGIN_ID, request(b"fixture-marker"))
            .await,
        Err(PluginError::Disabled)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let metadata = registry.get_metadata(PLUGIN_ID).unwrap();
    assert_eq!(metadata.execution_count(), 0);
    assert_eq!(metadata.success_count(), 0);
    assert_eq!(metadata.error_count(), 0);
}

#[test]
fn incompatible_api_line_is_rejected_without_registration() {
    let registry = PluginRegistry::new();
    assert!(matches!(
        registry.register(Arc::new(IncompatibleFixture), PluginConfig::default()),
        Err(PluginError::IncompatibleApiVersion { .. })
    ));
    assert_eq!(registry.count(), 0);
}
