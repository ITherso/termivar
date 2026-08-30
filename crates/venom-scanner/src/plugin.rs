//! Host-owned contract for source-linked native plugins.
//!
//! The opt-in `plugins` feature exposes a Rust trait boundary for trusted,
//! in-process extensions. A plugin receives a borrowed [`PluginContext`]; it
//! does not receive loose target/payload strings and cannot return findings or
//! outcomes. The host owns authorization, transport, resource limits,
//! cancellation, redaction, evidence provenance, and later verification.
//!
//! This is a cooperative capability contract, not a sandbox. Native plugin
//! code linked by a host can still use capabilities obtained outside this API.

use async_trait::async_trait;
use serde::Serialize;

mod context;
mod execution;
mod limits;
mod metadata;
mod recorder;
mod registry;
mod transport;

pub use context::{PluginContext, PluginExecutionRequest, PluginExecutionResult, PluginUsage};
pub use limits::{PluginBudget, PluginConfig};
pub use metadata::PluginMetadata;
pub use recorder::{PluginObservation, PluginRedactionPolicy, SecretRedactionPolicy};
pub use registry::PluginRegistry;
pub use transport::{PluginHttpMethod, PluginHttpRequest, PluginHttpResponse, PluginRequestBroker};

#[cfg(test)]
use limits::{
    invalid_config, HARD_MAX_PLUGIN_OBSERVATION_BYTES, HARD_MAX_PLUGIN_TEXT_LIST_ITEMS,
    MAX_PLUGIN_REDACTION_LITERAL_COUNT, MAX_PLUGIN_TEXT_BYTES, MAX_PLUGIN_URL_BYTES,
};
#[cfg(test)]
use recorder::sanitize_error;
#[cfg(test)]
use std::{
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};
#[cfg(test)]
use tokio_util::sync::CancellationToken;
#[cfg(test)]
use url::Url;
#[cfg(test)]
use venom_core::{EntityId, EvidenceKind, EvidenceValue, KnowledgePredicate};

/// Source-level plugin API version supported by this host.
///
/// Preview compatibility requires the same major and minor components. The
/// `0.2` line intentionally replaces the loose-input/direct-finding `0.1`
/// contract.
pub const PLUGIN_API_VERSION: &str = "0.2.0";

/// Extension contract for source-linked native plugins.
///
/// Implementations record observations through [`PluginContext::record`] and
/// use [`PluginContext::request`] for host-authorized network work. Successful
/// completion grants no finding or verification authority.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Plugin API line targeted by this implementation.
    fn api_version(&self) -> &str {
        PLUGIN_API_VERSION
    }

    /// Stable plugin identity.
    fn id(&self) -> &str;

    /// Human-readable plugin name.
    fn name(&self) -> &str;

    /// Plugin implementation version.
    fn version(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Human-readable author or owner.
    fn author(&self) -> &str;

    /// Informational plugin category.
    fn category(&self) -> PluginCategory;

    /// Validates static plugin prerequisites before registration.
    fn validate(&self) -> Result<(), PluginError> {
        Ok(())
    }

    /// Executes one host-authorized invocation.
    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError>;
}

/// Informational plugin categories; these do not assign severity or findings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCategory {
    /// Browser/reflection-related observation producer.
    XSS,
    /// Database-behavior observation producer.
    SQLi,
    /// File/path observation producer.
    LFI,
    /// XML observation producer.
    XXE,
    /// Server-side request behavior observation producer.
    SSRF,
    /// Template behavior observation producer.
    SSTI,
    /// Execution behavior observation producer.
    RCE,
    /// Host-defined observation producer.
    Custom,
}

impl PluginCategory {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XSS => "xss",
            Self::SQLi => "sqli",
            Self::LFI => "lfi",
            Self::XXE => "xxe",
            Self::SSRF => "ssrf",
            Self::SSTI => "ssti",
            Self::RCE => "rce",
            Self::Custom => "custom",
        }
    }
}

/// Typed plugin-boundary failures.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginError {
    /// Plugin identity was not registered.
    #[error("plugin identity is not registered")]
    NotFound,
    /// Plugin identity is already registered.
    #[error("plugin identity is already registered")]
    DuplicateId,
    /// Plugin identity has an invocation in flight and cannot be removed.
    #[error("plugin identity has an invocation in flight")]
    InUse,
    /// Plugin descriptor, configuration, or request was invalid.
    #[error("invalid plugin configuration: {0}")]
    InvalidConfig(String),
    /// Plugin targets another Preview API line.
    #[error("incompatible plugin API version: expected {expected}, received {actual}")]
    IncompatibleApiVersion {
        /// Host API line.
        expected: String,
        /// Plugin API line.
        actual: String,
    },
    /// Host configuration disabled this plugin.
    #[error("plugin is disabled by host policy")]
    Disabled,
    /// Host cancelled the invocation.
    #[error("plugin invocation was cancelled")]
    Cancelled,
    /// The invocation crossed its wall-clock budget.
    #[error("plugin invocation exhausted its wall-clock budget")]
    WallTimeExceeded,
    /// One request crossed its timeout budget.
    #[error("plugin request exhausted its timeout budget")]
    RequestTimeout,
    /// Plugin code abandoned a polled request before the broker returned.
    #[error("plugin request was abandoned before a broker receipt")]
    RequestAbandoned,
    /// Input exceeded the immutable request budget.
    #[error("plugin input uses {actual} bytes; maximum is {maximum}")]
    InputBudgetExceeded {
        /// Actual bytes.
        actual: usize,
        /// Maximum bytes.
        maximum: usize,
    },
    /// Request dispatch count exceeded the immutable budget.
    #[error("plugin request budget is exhausted")]
    RequestBudgetExceeded,
    /// One response exceeded its delivered-body budget.
    #[error("plugin response delivered {actual} bytes; maximum is {maximum}")]
    ResponseBodyBudgetExceeded {
        /// Delivered bytes.
        actual: u64,
        /// Maximum bytes.
        maximum: u64,
    },
    /// The per-response budget grants no body-capture authority.
    #[error("plugin response body budget grants no capture authority")]
    ResponseBodyBudgetUnavailable,
    /// Invocation-wide delivered response bytes exceeded the budget.
    #[error("plugin cumulative response body budget is exhausted")]
    CumulativeBodyBudgetExceeded,
    /// Observation count exceeded the immutable budget.
    #[error("plugin observation count budget is exhausted")]
    ObservationBudgetExceeded,
    /// Observation text exceeded the immutable byte budget.
    #[error("plugin observation byte budget is exhausted")]
    ObservationBytesBudgetExceeded,
    /// A URL was outside the exact authorized HTTP(S) origin.
    #[error("plugin request is outside the authorized origin")]
    ScopeViolation,
    /// The host-owned broker rejected or failed a request.
    #[error("host plugin request broker failed: {0}")]
    BrokerFailure(String),
    /// Plugin logic returned a failure.
    #[error("plugin execution failed: {0}")]
    ExecutionFailed(String),
    /// Plugin code panicked in a registration callback or while executing.
    #[error("plugin code panicked at the host boundary")]
    Panicked,
    /// A host-supplied plugin policy callback panicked.
    #[error("host plugin policy callback panicked")]
    HostCallbackPanicked,
    /// Observation or request authority was already sealed.
    #[error("plugin context is sealed")]
    ContextSealed,
    /// System time was earlier than the Unix epoch.
    #[error("system clock is earlier than the Unix epoch")]
    ClockBeforeUnixEpoch,
    /// Internal synchronized state was poisoned.
    #[error("plugin host state is unavailable")]
    HostStateUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };

    struct StaticBroker {
        calls: AtomicUsize,
        response: Mutex<Option<Result<PluginHttpResponse, PluginError>>>,
        delay: Duration,
    }

    impl StaticBroker {
        fn success(origin: &Url, body: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                response: Mutex::new(Some(Ok(PluginHttpResponse::new(
                    200,
                    origin.clone(),
                    body.to_vec(),
                )
                .expect("valid response")))),
                delay: Duration::ZERO,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl PluginRequestBroker for StaticBroker {
        async fn execute(
            &self,
            _request: PluginHttpRequest,
        ) -> Result<PluginHttpResponse, PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.response
                .lock()
                .map_err(|_| PluginError::HostStateUnavailable)?
                .take()
                .unwrap_or_else(|| Err(PluginError::BrokerFailure("no response".to_owned())))
        }
    }

    #[derive(Clone, Copy)]
    enum Behavior {
        Record,
        RecordThenPending,
        RecordThenPanic,
        Request,
        ErrorAfterRecord,
        ErrorOnly,
        LongSecretError,
        IncompatibleError,
        Pending,
        Empty,
    }

    struct TestPlugin {
        id: String,
        api: String,
        calls: Arc<AtomicUsize>,
        behavior: Behavior,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn api_version(&self) -> &str {
            &self.api
        }

        fn id(&self) -> &str {
            &self.id
        }

        fn name(&self) -> &str {
            "Trait Boundary Fixture"
        }

        fn version(&self) -> &str {
            "0.1.0"
        }

        fn description(&self) -> &str {
            "Records an informational observation for contract tests"
        }

        fn author(&self) -> &str {
            "Venom tests"
        }

        fn category(&self) -> PluginCategory {
            PluginCategory::Custom
        }

        async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                Behavior::Record
                | Behavior::RecordThenPending
                | Behavior::RecordThenPanic
                | Behavior::ErrorAfterRecord => {
                    context.record(observation(EvidenceValue::Text(
                        String::from_utf8_lossy(context.input()).into_owned(),
                    )))?;
                    if matches!(self.behavior, Behavior::ErrorAfterRecord) {
                        return Err(PluginError::ExecutionFailed(
                            "token=fixture-secret".to_owned(),
                        ));
                    }
                    if matches!(self.behavior, Behavior::RecordThenPending) {
                        std::future::pending::<()>().await;
                    }
                    if matches!(self.behavior, Behavior::RecordThenPanic) {
                        panic!("plugin fixture panic after staged evidence");
                    }
                },
                Behavior::ErrorOnly => {
                    return Err(PluginError::ExecutionFailed(
                        "plugin error for host sanitization".to_owned(),
                    ));
                },
                Behavior::LongSecretError => {
                    return Err(PluginError::ExecutionFailed(
                        "s".repeat(MAX_PLUGIN_TEXT_BYTES + 1),
                    ));
                },
                Behavior::IncompatibleError => {
                    return Err(PluginError::IncompatibleApiVersion {
                        expected: format!(
                            "token=plugin-secret{}",
                            "x".repeat(MAX_PLUGIN_TEXT_BYTES * 4)
                        ),
                        actual: "token=plugin-actual-secret".to_owned(),
                    });
                },
                Behavior::Request => {
                    let url = context
                        .authorized_origin()
                        .join("fixture")
                        .map_err(|_| invalid_config("fixture URL"))?;
                    let response = context.request(PluginHttpMethod::Get, url).await?;
                    context.record(observation(EvidenceValue::Unsigned(u64::from(
                        response.status(),
                    ))))?;
                },
                Behavior::Pending => std::future::pending::<()>().await,
                Behavior::Empty => {},
            }
            Ok(())
        }
    }

    fn plugin(id: &str, behavior: Behavior) -> (Arc<TestPlugin>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(TestPlugin {
                id: id.to_owned(),
                api: PLUGIN_API_VERSION.to_owned(),
                calls: calls.clone(),
                behavior,
            }),
            calls,
        )
    }

    fn origin() -> Url {
        Url::parse("https://example.test/").expect("valid origin")
    }

    fn request(broker: Arc<dyn PluginRequestBroker>) -> PluginExecutionRequest {
        PluginExecutionRequest::new(
            EntityId::new("authorized-origin:test").expect("valid subject"),
            origin(),
            "case:plugin:test",
            broker,
        )
        .expect("valid request")
    }

    fn observation(value: EvidenceValue) -> PluginObservation {
        PluginObservation::new(
            EvidenceKind::Custom("plugin.fixture".to_owned()),
            KnowledgePredicate::new("plugin.fixture", "marker").expect("valid predicate"),
            value,
            "trait-boundary",
        )
        .expect("valid observation")
    }

    #[test]
    fn api_line_and_clock_fail_closed() {
        let registry = PluginRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let incompatible = Arc::new(TestPlugin {
            id: "old-api".to_owned(),
            api: "0.1.9".to_owned(),
            calls,
            behavior: Behavior::Empty,
        });
        assert!(matches!(
            registry.register(incompatible, PluginConfig::default()),
            Err(PluginError::IncompatibleApiVersion { .. })
        ));

        let (before_epoch, _) = plugin("clock", Behavior::Empty);
        assert_eq!(
            registry.register_at(
                before_epoch,
                PluginConfig::default(),
                UNIX_EPOCH - Duration::from_secs(1),
            ),
            Err(PluginError::ClockBeforeUnixEpoch)
        );
        assert_eq!(registry.count(), 0);

        struct PanickingDescriptor;
        #[async_trait]
        impl Plugin for PanickingDescriptor {
            fn id(&self) -> &str {
                panic!("descriptor panic")
            }
            fn name(&self) -> &str {
                "Panicking Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises registration panic isolation"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }
        assert_eq!(
            registry.register(Arc::new(PanickingDescriptor), PluginConfig::default()),
            Err(PluginError::Panicked)
        );
        assert_eq!(registry.count(), 0);

        struct PanickingValidation;
        #[async_trait]
        impl Plugin for PanickingValidation {
            fn id(&self) -> &str {
                "panicking-validation"
            }
            fn name(&self) -> &str {
                "Panicking Validation Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises validation panic isolation"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            fn validate(&self) -> Result<(), PluginError> {
                panic!("validation panic")
            }
            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }
        assert_eq!(
            registry.register(Arc::new(PanickingValidation), PluginConfig::default()),
            Err(PluginError::Panicked)
        );
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn registration_snapshots_each_descriptor_field_once() {
        struct FlappingDescriptor {
            api_calls: AtomicUsize,
            id_calls: AtomicUsize,
            name_calls: AtomicUsize,
            version_calls: AtomicUsize,
            description_calls: AtomicUsize,
            author_calls: AtomicUsize,
            category_calls: AtomicUsize,
            validate_calls: AtomicUsize,
        }

        #[async_trait]
        impl Plugin for FlappingDescriptor {
            fn api_version(&self) -> &str {
                if self.api_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    PLUGIN_API_VERSION
                } else {
                    "0.1.0"
                }
            }

            fn id(&self) -> &str {
                if self.id_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "flapping-descriptor"
                } else {
                    ""
                }
            }

            fn name(&self) -> &str {
                if self.name_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "Flapping Descriptor"
                } else {
                    ""
                }
            }

            fn version(&self) -> &str {
                if self.version_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "1.0.0"
                } else {
                    ""
                }
            }

            fn description(&self) -> &str {
                if self.description_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "Proves one-shot descriptor capture"
                } else {
                    ""
                }
            }

            fn author(&self) -> &str {
                if self.author_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    "Venom tests"
                } else {
                    ""
                }
            }

            fn category(&self) -> PluginCategory {
                if self.category_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    PluginCategory::Custom
                } else {
                    PluginCategory::RCE
                }
            }

            fn validate(&self) -> Result<(), PluginError> {
                self.validate_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }

        let plugin = Arc::new(FlappingDescriptor {
            api_calls: AtomicUsize::new(0),
            id_calls: AtomicUsize::new(0),
            name_calls: AtomicUsize::new(0),
            version_calls: AtomicUsize::new(0),
            description_calls: AtomicUsize::new(0),
            author_calls: AtomicUsize::new(0),
            category_calls: AtomicUsize::new(0),
            validate_calls: AtomicUsize::new(0),
        });
        let registry = PluginRegistry::new();
        registry
            .register(plugin.clone(), PluginConfig::default())
            .expect("the first descriptor snapshot is valid");

        let metadata = registry
            .get_metadata("flapping-descriptor")
            .expect("snapshotted descriptor is registered");
        assert_eq!(metadata.api_version(), PLUGIN_API_VERSION);
        assert_eq!(metadata.name(), "Flapping Descriptor");
        assert_eq!(metadata.category(), PluginCategory::Custom);
        for calls in [
            &plugin.api_calls,
            &plugin.id_calls,
            &plugin.name_calls,
            &plugin.version_calls,
            &plugin.description_calls,
            &plugin.author_calls,
            &plugin.category_calls,
            &plugin.validate_calls,
        ] {
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn duplicate_registration_is_atomic_under_concurrency() {
        let registry = Arc::new(PluginRegistry::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let registry = registry.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let (candidate, _) = plugin("duplicate", Behavior::Empty);
                barrier.wait();
                registry.register(candidate, PluginConfig::default())
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker did not panic"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PluginError::DuplicateId)))
                .count(),
            1
        );
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.list_all().len(), 1);
    }

    #[tokio::test]
    async fn disabled_plugin_is_never_polled_and_metadata_stays_consistent() {
        let registry = PluginRegistry::new();
        let (candidate, calls) = plugin("disabled", Behavior::Record);
        registry
            .register(candidate, PluginConfig::new(false))
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry.execute("disabled", request(broker)).await,
            Err(PluginError::Disabled)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let metadata = registry.get_metadata("disabled").expect("metadata");
        assert!(!metadata.enabled());
        assert_eq!(metadata.execution_count(), 0);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 0);
    }

    #[tokio::test]
    async fn active_invocation_leases_prevent_unregister_reregister_aba() {
        struct HoldingPlugin {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
        }
        #[async_trait]
        impl Plugin for HoldingPlugin {
            fn id(&self) -> &str {
                "leased"
            }
            fn name(&self) -> &str {
                "Invocation Lease Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Holds one invocation while registry mutation is attempted"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                self.entered.notify_one();
                self.release.notified().await;
                context.record(observation(EvidenceValue::Text(
                    String::from_utf8_lossy(context.input()).into_owned(),
                )))
            }
        }

        let registry = Arc::new(PluginRegistry::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        registry
            .register(
                Arc::new(HoldingPlugin {
                    entered: entered.clone(),
                    release: release.clone(),
                }),
                PluginConfig::default(),
            )
            .expect("registration succeeds");
        let invocation_registry = registry.clone();
        let invocation = tokio::spawn(async move {
            invocation_registry
                .execute(
                    "leased",
                    request(StaticBroker::success(&origin(), b""))
                        .with_input(b"original-entry".to_vec())
                        .expect("input"),
                )
                .await
        });
        entered.notified().await;

        assert_eq!(registry.unregister("leased"), Err(PluginError::InUse));
        let (replacement, replacement_calls) = plugin("leased", Behavior::Record);
        assert_eq!(
            registry.register(replacement, PluginConfig::default()),
            Err(PluginError::DuplicateId)
        );
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
        let active_metadata = registry.get_metadata("leased").expect("metadata");
        assert_eq!(active_metadata.execution_count(), 1);
        assert_eq!(active_metadata.success_count(), 0);
        assert_eq!(active_metadata.error_count(), 0);

        release.notify_one();
        let result = invocation
            .await
            .expect("invocation task did not panic")
            .expect("original invocation succeeds");
        assert_eq!(result.plugin_id(), "leased");
        let serialized = serde_json::to_string(&result).expect("result serializes");
        assert!(serialized.contains("original-entry"));
        let completed_metadata = registry.get_metadata("leased").expect("metadata");
        assert_eq!(completed_metadata.execution_count(), 1);
        assert_eq!(completed_metadata.success_count(), 1);
        assert_eq!(completed_metadata.error_count(), 0);

        registry.unregister("leased").expect("lease released");
        let (replacement, replacement_calls) = plugin("leased", Behavior::Record);
        registry
            .register(replacement, PluginConfig::default())
            .expect("same ID can be registered only after the invocation drains");
        let result = registry
            .execute(
                "leased",
                request(StaticBroker::success(&origin(), b""))
                    .with_input(b"replacement-entry".to_vec())
                    .expect("input"),
            )
            .await
            .expect("replacement invocation succeeds");
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);
        let serialized = serde_json::to_string(&result).expect("result serializes");
        assert!(serialized.contains("replacement-entry"));
        assert!(!serialized.contains("original-entry"));
    }

    #[tokio::test]
    async fn successful_observation_has_host_owned_provenance_and_no_claim() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("observer", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        let result = registry
            .execute(
                "observer",
                request(broker)
                    .with_input(b"marker".to_vec())
                    .expect("bounded input"),
            )
            .await
            .expect("execution succeeds");
        assert_eq!(result.observations().len(), 1);
        let evidence = &result.observations()[0];
        assert_eq!(evidence.subject().as_str(), "authorized-origin:test");
        assert_eq!(evidence.source().component(), "observer");
        assert_eq!(evidence.source().correlation_id(), Some("case:plugin:test"));
        let json = serde_json::to_string(&result).expect("serializes");
        assert!(!json.contains("finding"));
        assert!(!json.contains("outcome"));
        assert!(!json.contains("severity"));
        assert_eq!(result.usage().observations(), 1);
    }

    #[tokio::test]
    async fn redaction_removes_headers_literals_and_debug_secrets() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("redactor", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        let redaction = Arc::new(
            SecretRedactionPolicy::new([
                "tenant".to_owned(),
                "tenant-secret".to_owned(),
                "REDACTED".to_owned(),
                "[REDACTED]-tenant-secret".to_owned(),
                "DACTED]-inside-secret".to_owned(),
            ])
            .expect("redaction policy"),
        );
        let literal_cases = [
            "tenant-secret tenant [REDACTED]",
            "[REDACTED]-tenant-secret",
            "[REDACTED]-inside-secret",
        ];
        for value in literal_cases {
            let once = redaction.redact(value);
            assert!(!once.contains("tenant-secret"));
            assert!(!once.contains("inside-secret"));
            assert_eq!(redaction.redact(&once), once);
        }
        let dense = SecretRedactionPolicy::new(
            (1..=MAX_PLUGIN_REDACTION_LITERAL_COUNT).map(|length| "a".repeat(length)),
        )
        .expect("dense overlap policy");
        let dense_input = "a".repeat(HARD_MAX_PLUGIN_OBSERVATION_BYTES as usize);
        let dense_once = dense.redact(&dense_input);
        assert_eq!(dense_once, "[REDACTED]");
        assert_eq!(dense.redact(&dense_once), dense_once);
        let execution = request(broker)
            .with_input(b"Authorization: Bearer abc\ntoken=xyz\ntenant-secret".to_vec())
            .expect("input")
            .with_redaction(redaction.clone());
        let debug = format!("{execution:?} {redaction:?}");
        assert!(!debug.contains("tenant-secret"));
        assert!(!debug.contains("Bearer"));
        let result = registry
            .execute("redactor", execution)
            .await
            .expect("execution succeeds");
        let serialized = serde_json::to_string(&result).expect("serializes");
        assert!(!serialized.contains("Bearer abc"));
        assert!(!serialized.contains("xyz"));
        assert!(!serialized.contains("tenant-secret"));
        assert!(serialized.contains("REDACTED"));

        struct ExpandingRedactor;
        impl PluginRedactionPolicy for ExpandingRedactor {
            fn redact(&self, value: &str) -> String {
                format!("{value}0123456789")
            }
        }
        struct TwoObservationPlugin;
        #[async_trait]
        impl Plugin for TwoObservationPlugin {
            fn id(&self) -> &str {
                "expanding-redactor"
            }
            fn name(&self) -> &str {
                "Expanding Redactor Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises retained observation accounting"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                context.record(observation(EvidenceValue::Text("x".to_owned())))?;
                context.record(observation(EvidenceValue::Text("y".to_owned())))
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(TwoObservationPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let budget = PluginBudget::default()
            .with_max_observation_bytes(25)
            .expect("budget");
        let execution = request(StaticBroker::success(&origin(), b""))
            .with_budget(budget)
            .expect("request")
            .with_redaction(Arc::new(ExpandingRedactor));
        assert_eq!(
            registry.execute("expanding-redactor", execution).await,
            Err(PluginError::ObservationBytesBudgetExceeded)
        );
    }

    #[tokio::test]
    async fn plugin_error_rolls_back_staged_evidence_and_redacts_detail() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("rollback", Behavior::ErrorAfterRecord);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        let error = registry
            .execute("rollback", request(broker))
            .await
            .expect_err("execution must fail");
        assert!(!error.to_string().contains("fixture-secret"));
        assert_eq!(
            error,
            PluginError::ExecutionFailed("plugin execution failed".to_owned())
        );
        let metadata = registry.get_metadata("rollback").expect("metadata");
        assert_eq!(metadata.execution_count(), 1);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 1);

        let oversized = format!(
            "token=fixture-secret{}",
            "x".repeat(MAX_PLUGIN_TEXT_BYTES * 4)
        );
        let bounded = sanitize_error(
            &SecretRedactionPolicy::default(),
            PluginError::ExecutionFailed(oversized),
        );
        let detail = match bounded {
            PluginError::ExecutionFailed(detail) => detail,
            other => panic!("unexpected error: {other}"),
        };
        assert!(detail.len() <= MAX_PLUGIN_TEXT_BYTES);
        assert!(!detail.contains("fixture-secret"));
        assert_eq!(detail, "plugin execution failed");

        let boundary_secret = "s".repeat(MAX_PLUGIN_TEXT_BYTES + 1);
        let redaction = Arc::new(
            SecretRedactionPolicy::new([boundary_secret.clone()])
                .expect("boundary redaction policy"),
        );
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("long-plugin-error", Behavior::LongSecretError);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let execution =
            request(StaticBroker::success(&origin(), b"")).with_redaction(redaction.clone());
        assert_eq!(
            registry.execute("long-plugin-error", execution).await,
            Err(PluginError::ExecutionFailed(
                "plugin execution failed".to_owned()
            ))
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("long-broker-error", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = Arc::new(StaticBroker {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Some(Err(PluginError::BrokerFailure(boundary_secret)))),
            delay: Duration::ZERO,
        });
        let execution = request(broker).with_redaction(redaction);
        assert_eq!(
            registry.execute("long-broker-error", execution).await,
            Err(PluginError::BrokerFailure(
                "host plugin request broker failed".to_owned()
            ))
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("plugin-api-error", Behavior::IncompatibleError);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        assert_eq!(
            registry
                .execute(
                    "plugin-api-error",
                    request(StaticBroker::success(&origin(), b"")),
                )
                .await,
            Err(PluginError::IncompatibleApiVersion {
                expected: PLUGIN_API_VERSION.to_owned(),
                actual: "[invalid]".to_owned(),
            })
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("broker-api-error", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = Arc::new(StaticBroker {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Some(Err(PluginError::IncompatibleApiVersion {
                expected: format!(
                    "token=broker-secret{}",
                    "x".repeat(MAX_PLUGIN_TEXT_BYTES * 4)
                ),
                actual: "token=broker-actual-secret".to_owned(),
            }))),
            delay: Duration::ZERO,
        });
        assert_eq!(
            registry.execute("broker-api-error", request(broker)).await,
            Err(PluginError::IncompatibleApiVersion {
                expected: PLUGIN_API_VERSION.to_owned(),
                actual: "[invalid]".to_owned(),
            })
        );

        struct PanickingRedactor;
        impl PluginRedactionPolicy for PanickingRedactor {
            fn redact(&self, _value: &str) -> String {
                panic!("host redaction panic")
            }
        }
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("panicking-redactor", Behavior::ErrorOnly);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let execution = request(StaticBroker::success(&origin(), b""))
            .with_redaction(Arc::new(PanickingRedactor));
        assert_eq!(
            registry.execute("panicking-redactor", execution).await,
            Err(PluginError::HostCallbackPanicked)
        );
        let metadata = registry
            .get_metadata("panicking-redactor")
            .expect("metadata");
        assert_eq!(metadata.execution_count(), 1);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 1);
    }

    #[tokio::test]
    async fn timeout_cancellation_and_panic_are_typed_failures() {
        for (id, behavior, expected) in [
            (
                "timeout",
                Behavior::RecordThenPending,
                PluginError::WallTimeExceeded,
            ),
            ("panic", Behavior::RecordThenPanic, PluginError::Panicked),
        ] {
            let registry = PluginRegistry::new();
            let (candidate, _) = plugin(id, behavior);
            registry
                .register(candidate, PluginConfig::default())
                .expect("registration succeeds");
            let broker = StaticBroker::success(&origin(), b"");
            let budget = PluginBudget::default()
                .with_max_wall_time(Duration::from_millis(5))
                .expect("budget");
            let error = registry
                .execute(
                    id,
                    request(broker)
                        .with_budget(budget)
                        .and_then(|request| request.with_input(b"staged".to_vec()))
                        .expect("request"),
                )
                .await
                .expect_err("must fail");
            assert_eq!(error, expected);
            let metadata = registry.get_metadata(id).expect("metadata");
            assert_eq!(metadata.execution_count(), 1);
            assert_eq!(metadata.success_count(), 0);
            assert_eq!(metadata.error_count(), 1);
        }

        struct ConstructionPanicPlugin;
        impl Plugin for ConstructionPanicPlugin {
            fn id(&self) -> &str {
                "construction-panic"
            }
            fn name(&self) -> &str {
                "Construction Panic Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Panics while constructing its boxed execution future"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            fn execute<'life0, 'life1, 'async_trait>(
                &'life0 self,
                context: &'life1 PluginContext,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), PluginError>> + Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                context
                    .record(observation(EvidenceValue::Text("staged".to_owned())))
                    .expect("staging succeeds before construction panic");
                panic!("plugin fixture panic during future construction");
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(ConstructionPanicPlugin), PluginConfig::default())
            .expect("registration succeeds");
        assert_eq!(
            registry
                .execute(
                    "construction-panic",
                    request(StaticBroker::success(&origin(), b"")),
                )
                .await,
            Err(PluginError::Panicked)
        );
        let metadata = registry
            .get_metadata("construction-panic")
            .expect("metadata");
        assert_eq!(metadata.execution_count(), 1);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 1);

        struct DropPanicFuture {
            ready: bool,
        }
        impl std::future::Future for DropPanicFuture {
            type Output = Result<(), PluginError>;

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                if self.ready {
                    std::task::Poll::Ready(Ok(()))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
        impl Drop for DropPanicFuture {
            fn drop(&mut self) {
                panic!("plugin fixture panic while dropping execution future");
            }
        }
        struct DropPanicPlugin {
            id: &'static str,
            ready: bool,
        }
        impl Plugin for DropPanicPlugin {
            fn id(&self) -> &str {
                self.id
            }
            fn name(&self) -> &str {
                "Drop Panic Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Panics while dropping its boxed execution future"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            fn execute<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _context: &'life1 PluginContext,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), PluginError>> + Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(DropPanicFuture { ready: self.ready })
            }
        }
        for (id, ready) in [("ready-drop-panic", true), ("pending-drop-panic", false)] {
            let registry = PluginRegistry::new();
            registry
                .register(
                    Arc::new(DropPanicPlugin { id, ready }),
                    PluginConfig::default(),
                )
                .expect("registration succeeds");
            let budget = PluginBudget::default()
                .with_max_wall_time(Duration::from_millis(5))
                .expect("budget");
            assert_eq!(
                registry
                    .execute(
                        id,
                        request(StaticBroker::success(&origin(), b""))
                            .with_budget(budget)
                            .expect("request"),
                    )
                    .await,
                Err(PluginError::Panicked)
            );
            let metadata = registry.get_metadata(id).expect("metadata");
            assert_eq!(metadata.execution_count(), 1);
            assert_eq!(metadata.success_count(), 0);
            assert_eq!(metadata.error_count(), 1);
        }

        struct AbandonRequestPlugin;
        #[async_trait]
        impl Plugin for AbandonRequestPlugin {
            fn id(&self) -> &str {
                "abandon-request"
            }
            fn name(&self) -> &str {
                "Abandoned Request Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Polls and drops a broker request"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                let future =
                    context.request(PluginHttpMethod::Get, context.authorized_origin().clone());
                tokio::pin!(future);
                tokio::select! {
                    biased;
                    result = &mut future => {
                        result?;
                        return Err(invalid_config("pending broker completed unexpectedly"));
                    },
                    () = tokio::task::yield_now() => {},
                }
                Ok(())
            }
        }
        struct PendingBroker {
            calls: AtomicUsize,
            cancellation: Mutex<Option<CancellationToken>>,
        }
        #[async_trait]
        impl PluginRequestBroker for PendingBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self
                    .cancellation
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)? =
                    Some(request.cancellation().clone());
                std::future::pending().await
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(AbandonRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let pending = Arc::new(PendingBroker {
            calls: AtomicUsize::new(0),
            cancellation: Mutex::new(None),
        });
        assert_eq!(
            registry
                .execute("abandon-request", request(pending.clone()))
                .await,
            Err(PluginError::RequestAbandoned)
        );
        assert_eq!(pending.calls.load(Ordering::SeqCst), 1);
        assert!(pending
            .cancellation
            .lock()
            .expect("cancellation receipt")
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled));

        let registry = PluginRegistry::new();
        let (candidate, calls) = plugin("cancelled", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry
                .execute("cancelled", request(broker).with_cancellation(cancellation),)
                .await,
            Err(PluginError::Cancelled)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("mid-cancel", Behavior::Pending);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let cancellation = CancellationToken::new();
        let cancellation_signal = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            cancellation_signal.cancel();
        });
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry
                .execute(
                    "mid-cancel",
                    request(broker).with_cancellation(cancellation),
                )
                .await,
            Err(PluginError::Cancelled)
        );
        cancel_task.await.expect("cancellation task joins");
        assert_eq!(
            registry
                .get_metadata("mid-cancel")
                .expect("metadata")
                .error_count(),
            1
        );
    }

    #[tokio::test]
    async fn input_observation_and_request_budgets_fail_closed() {
        let broker = StaticBroker::success(&origin(), b"");
        let tiny_input = PluginBudget::default()
            .with_max_input_bytes(3)
            .expect("budget");
        assert!(matches!(
            request(broker.clone())
                .with_budget(tiny_input)
                .expect("empty input fits")
                .with_input("éé".as_bytes().to_vec()),
            Err(PluginError::InputBudgetExceeded {
                actual: 4,
                maximum: 3
            })
        ));

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("no-request", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let zero = PluginBudget::default()
            .with_max_requests(0)
            .expect("zero authority");
        assert_eq!(
            registry
                .execute(
                    "no-request",
                    request(broker.clone()).with_budget(zero).expect("request"),
                )
                .await,
            Err(PluginError::RequestBudgetExceeded)
        );
        assert_eq!(broker.calls(), 0);

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("no-observation", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let zero = PluginBudget::default()
            .with_max_observations(0)
            .expect("zero authority");
        assert_eq!(
            registry
                .execute(
                    "no-observation",
                    request(broker).with_budget(zero).expect("request"),
                )
                .await,
            Err(PluginError::ObservationBudgetExceeded)
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("observation-bytes", Behavior::Record);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let bytes = PluginBudget::default()
            .with_max_observation_bytes(3)
            .expect("budget");
        let execution = request(StaticBroker::success(&origin(), b""))
            .with_budget(bytes)
            .expect("request")
            .with_input(b"four".to_vec())
            .expect("input budget");
        assert_eq!(
            registry.execute("observation-bytes", execution).await,
            Err(PluginError::ObservationBytesBudgetExceeded)
        );

        struct EmptyListPlugin;
        #[async_trait]
        impl Plugin for EmptyListPlugin {
            fn id(&self) -> &str {
                "empty-list"
            }
            fn name(&self) -> &str {
                "Empty List Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises structural observation accounting"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                context.record(observation(EvidenceValue::TextList(vec![
                    String::new();
                    HARD_MAX_PLUGIN_TEXT_LIST_ITEMS
                ])))
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(EmptyListPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let zero_bytes = PluginBudget::default()
            .with_max_observation_bytes(0)
            .expect("zero byte authority");
        assert_eq!(
            registry
                .execute(
                    "empty-list",
                    request(StaticBroker::success(&origin(), b""))
                        .with_budget(zero_bytes)
                        .expect("request"),
                )
                .await,
            Err(PluginError::ObservationBytesBudgetExceeded)
        );
    }

    #[tokio::test]
    async fn scope_and_body_budgets_are_enforced_around_the_host_broker() {
        assert!(PluginHttpResponse::new(200, origin(), b"x".to_vec())
            .and_then(|response| response.with_capture_metadata(2, false))
            .is_err());

        struct ScopePlugin;
        #[async_trait]
        impl Plugin for ScopePlugin {
            fn id(&self) -> &str {
                "scope"
            }
            fn name(&self) -> &str {
                "Scope Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises broker scope"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                context
                    .request(
                        PluginHttpMethod::Get,
                        Url::parse("https://other.test/").map_err(|_| invalid_config("URL"))?,
                    )
                    .await?;
                Ok(())
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(ScopePlugin), PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"");
        assert_eq!(
            registry.execute("scope", request(broker.clone())).await,
            Err(PluginError::ScopeViolation)
        );
        assert_eq!(broker.calls(), 0);

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("body", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let broker = StaticBroker::success(&origin(), b"four");
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(3)
            .expect("budget");
        assert!(matches!(
            registry
                .execute(
                    "body",
                    request(broker).with_budget(budget).expect("request")
                )
                .await,
            Err(PluginError::ResponseBodyBudgetExceeded {
                actual: 4,
                maximum: 3
            })
        ));

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("long-final-url", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let long_final = Url::parse(&format!(
            "https://example.test/{}",
            "a".repeat(MAX_PLUGIN_URL_BYTES)
        ))
        .expect("valid long URL");
        let long_final_broker = StaticBroker::success(&long_final, b"");
        assert_eq!(
            registry
                .execute("long-final-url", request(long_final_broker))
                .await,
            Err(PluginError::ScopeViolation)
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("request-timeout", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let slow = Arc::new(StaticBroker {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Some(Ok(
                PluginHttpResponse::new(200, origin(), Vec::new()).expect("response")
            ))),
            delay: Duration::from_millis(50),
        });
        let budget = PluginBudget::default()
            .with_request_timeout(Duration::from_millis(5))
            .expect("budget");
        assert_eq!(
            registry
                .execute(
                    "request-timeout",
                    request(slow).with_budget(budget).expect("request"),
                )
                .await,
            Err(PluginError::RequestTimeout)
        );

        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("redirect-scope", Behavior::Request);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        let other = Url::parse("https://other.test/").expect("valid URL");
        let redirected = StaticBroker::success(&other, b"");
        assert_eq!(
            registry
                .execute("redirect-scope", request(redirected.clone()))
                .await,
            Err(PluginError::ScopeViolation)
        );
        assert_eq!(redirected.calls(), 1);

        struct TwoRequestPlugin;
        #[async_trait]
        impl Plugin for TwoRequestPlugin {
            fn id(&self) -> &str {
                "cumulative"
            }
            fn name(&self) -> &str {
                "Cumulative Body Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises cumulative response accounting"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                for path in ["one", "two"] {
                    let url = context
                        .authorized_origin()
                        .join(path)
                        .map_err(|_| invalid_config("fixture URL"))?;
                    context.request(PluginHttpMethod::Get, url).await?;
                }
                Ok(())
            }
        }
        struct RepeatBroker {
            calls: AtomicUsize,
            captures: Mutex<Vec<(u64, bool)>>,
        }
        #[async_trait]
        impl PluginRequestBroker for RepeatBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.captures
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)?
                    .push((
                        request.max_response_body_bytes(),
                        request.cancellation().is_cancelled(),
                    ));
                PluginHttpResponse::new(200, request.url().clone(), b"abc".to_vec())
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(TwoRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let repeated = Arc::new(RepeatBroker {
            calls: AtomicUsize::new(0),
            captures: Mutex::new(Vec::new()),
        });
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(3)
            .and_then(|budget| budget.with_max_cumulative_body_bytes(3))
            .expect("budget");
        assert_eq!(
            registry
                .execute(
                    "cumulative",
                    request(repeated.clone())
                        .with_budget(budget)
                        .expect("request"),
                )
                .await,
            Err(PluginError::CumulativeBodyBudgetExceeded)
        );
        assert_eq!(repeated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *repeated.captures.lock().expect("capture log"),
            vec![(3, false)]
        );

        struct CappedBroker {
            captures: Mutex<Vec<(u64, bool)>>,
        }
        #[async_trait]
        impl PluginRequestBroker for CappedBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                let limit = request.max_response_body_bytes();
                self.captures
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)?
                    .push((limit, request.cancellation().is_cancelled()));
                let body = b"abcd";
                let retained = usize::try_from(limit).unwrap_or(usize::MAX).min(body.len());
                PluginHttpResponse::new(200, request.url().clone(), body[..retained].to_vec())?
                    .with_capture_metadata(retained as u64, retained < body.len())
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(TwoRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let capped = Arc::new(CappedBroker {
            captures: Mutex::new(Vec::new()),
        });
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(4)
            .and_then(|budget| budget.with_max_cumulative_body_bytes(6))
            .expect("budget");
        let result = registry
            .execute(
                "cumulative",
                request(capped.clone())
                    .with_budget(budget)
                    .expect("request"),
            )
            .await
            .expect("a compliant broker stays inside the shared envelope");
        assert_eq!(result.usage().response_body_bytes(), 6);
        assert_eq!(
            *capped.captures.lock().expect("capture log"),
            vec![(4, false), (2, false)]
        );

        struct ConcurrentRequestPlugin;
        #[async_trait]
        impl Plugin for ConcurrentRequestPlugin {
            fn id(&self) -> &str {
                "concurrent-capture"
            }
            fn name(&self) -> &str {
                "Concurrent Capture Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises in-flight cumulative reservations"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
                let one = context
                    .authorized_origin()
                    .join("one")
                    .map_err(|_| invalid_config("fixture URL"))?;
                let two = context
                    .authorized_origin()
                    .join("two")
                    .map_err(|_| invalid_config("fixture URL"))?;
                tokio::try_join!(
                    context.request(PluginHttpMethod::Get, one),
                    context.request(PluginHttpMethod::Get, two),
                )?;
                Ok(())
            }
        }
        struct ConcurrentCaptureBroker {
            barrier: tokio::sync::Barrier,
            captures: Mutex<Vec<u64>>,
        }
        #[async_trait]
        impl PluginRequestBroker for ConcurrentCaptureBroker {
            async fn execute(
                &self,
                request: PluginHttpRequest,
            ) -> Result<PluginHttpResponse, PluginError> {
                let limit = request.max_response_body_bytes();
                self.captures
                    .lock()
                    .map_err(|_| PluginError::HostStateUnavailable)?
                    .push(limit);
                self.barrier.wait().await;
                PluginHttpResponse::new(
                    200,
                    request.url().clone(),
                    vec![b'x'; usize::try_from(limit).unwrap_or(usize::MAX)],
                )
            }
        }
        let registry = PluginRegistry::new();
        registry
            .register(Arc::new(ConcurrentRequestPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let concurrent = Arc::new(ConcurrentCaptureBroker {
            barrier: tokio::sync::Barrier::new(2),
            captures: Mutex::new(Vec::new()),
        });
        let budget = PluginBudget::default()
            .with_max_response_body_bytes(4)
            .and_then(|budget| budget.with_max_cumulative_body_bytes(6))
            .expect("budget");
        let result = registry
            .execute(
                "concurrent-capture",
                request(concurrent.clone())
                    .with_budget(budget)
                    .expect("request"),
            )
            .await
            .expect("concurrent captures stay inside the shared envelope");
        let mut captures = concurrent.captures.lock().expect("capture log").clone();
        captures.sort_unstable();
        assert_eq!(captures, vec![2, 4]);
        assert_eq!(result.usage().response_body_bytes(), 6);
    }

    #[tokio::test]
    async fn configuration_and_metadata_share_one_entry() {
        let registry = PluginRegistry::new();
        let (candidate, _) = plugin("metadata", Behavior::Empty);
        registry
            .register(candidate, PluginConfig::default())
            .expect("registration succeeds");
        assert!(registry
            .get_config("metadata")
            .expect("configuration")
            .enabled());
        registry
            .update_config("metadata", PluginConfig::new(false))
            .expect("configuration update");
        assert!(!registry
            .get_metadata("metadata")
            .expect("metadata")
            .enabled());
        registry.unregister("metadata").expect("unregister");
        assert!(registry.get("metadata").is_none());
        assert!(registry.get_config("metadata").is_none());
        assert!(registry.get_metadata("metadata").is_none());

        struct YieldingPlugin;
        #[async_trait]
        impl Plugin for YieldingPlugin {
            fn id(&self) -> &str {
                "coherent-stats"
            }
            fn name(&self) -> &str {
                "Coherent Stats Fixture"
            }
            fn version(&self) -> &str {
                "0.1.0"
            }
            fn description(&self) -> &str {
                "Exercises concurrent metadata snapshots"
            }
            fn author(&self) -> &str {
                "Venom tests"
            }
            fn category(&self) -> PluginCategory {
                PluginCategory::Custom
            }
            async fn execute(&self, _context: &PluginContext) -> Result<(), PluginError> {
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                Ok(())
            }
        }
        let registry = Arc::new(PluginRegistry::new());
        registry
            .register(Arc::new(YieldingPlugin), PluginConfig::default())
            .expect("registration succeeds");
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let registry = registry.clone();
            tasks.push(tokio::spawn(async move {
                registry
                    .execute(
                        "coherent-stats",
                        request(StaticBroker::success(&origin(), b"")),
                    )
                    .await
            }));
        }
        while tasks.iter().any(|task| !task.is_finished()) {
            let metadata = registry.get_metadata("coherent-stats").expect("metadata");
            assert!(
                metadata.execution_count()
                    >= metadata
                        .success_count()
                        .saturating_add(metadata.error_count())
            );
            tokio::task::yield_now().await;
        }
        for task in tasks {
            task.await
                .expect("execution task joins")
                .expect("execution succeeds");
        }
        let metadata = registry.get_metadata("coherent-stats").expect("metadata");
        assert_eq!(metadata.execution_count(), 32);
        assert_eq!(metadata.success_count(), 32);
        assert_eq!(metadata.error_count(), 0);
    }
}
