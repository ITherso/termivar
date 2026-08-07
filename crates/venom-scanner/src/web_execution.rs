//! Scope-bound executors for standard web discovery actions.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This profile binds a deliberately small set of semantic planner actions to
//! the existing HTTP evidence boundary. It performs no credential guessing,
//! payload injection, redirect following, or cross-origin navigation.

use std::{collections::BTreeSet, sync::Arc};

use serde::Serialize;
use thiserror::Error;

use crate::{
    decision_runner::{
        DecisionActionExecutor, DecisionExecutionStage, DecisionExecutorRegistry,
        DecisionRunnerError,
    },
    http_evidence::{
        HttpEvidenceError, HttpEvidenceExecutor, HttpEvidencePolicy, HttpProbeMethod,
        HttpRequestBroker, SubjectHttpProbeProvider,
    },
    web_actions::{StandardWebActionKind, STANDARD_WEB_DISCOVERY_ACTION_COUNT},
};

pub use crate::web_actions::STANDARD_WEB_DISCOVERY_ACTIONS;

/// Number of standard semantic actions backed by discovery-only HTTP probes.
pub const STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT: usize = STANDARD_WEB_DISCOVERY_ACTION_COUNT;

/// Failures while constructing or atomically installing discovery executors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebExecutionError {
    /// A semantic action has no built-in discovery transport mapping.
    #[error("standard web action {action:?} has no built-in discovery executor")]
    UnsupportedAction {
        /// Action rejected while the profile was being constructed.
        action: StandardWebActionKind,
    },

    /// A bounded HTTP executor could not be constructed.
    #[error(transparent)]
    Http(#[from] HttpEvidenceError),

    /// An executor identity or action route conflicted with registry state.
    #[error(transparent)]
    Runner(#[from] DecisionRunnerError),
}

/// Count of executors added by an idempotent profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StandardWebDiscoveryInstallReport {
    executors_inserted: usize,
}

impl StandardWebDiscoveryInstallReport {
    /// Returns the number of previously absent executor identities installed.
    pub fn executors_inserted(self) -> usize {
        self.executors_inserted
    }
}

struct ExecutorBinding {
    kind: StandardWebActionKind,
    executor: Arc<dyn DecisionActionExecutor>,
}

/// Built-in low-risk executor bindings for route, component, and auth discovery.
///
/// Every executor inherits the supplied [`HttpEvidencePolicy`]. The policy is
/// therefore the single authority for allowed origins, timeout, body limits,
/// captured headers, and optional text samples. Existing executor identities
/// are treated as explicit host overrides and are never replaced.
///
/// # Examples
///
/// ```rust
/// use url::Url;
/// use venom_scanner::{
///     DecisionExecutorRegistry, HttpEvidencePolicy, StandardWebDiscoveryExecutorProfile,
///     STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT,
/// };
///
/// let target = Url::parse("https://example.test/")?;
/// let profile = StandardWebDiscoveryExecutorProfile::new(
///     HttpEvidencePolicy::for_origin(target)?,
/// )?;
/// let mut registry = DecisionExecutorRegistry::new();
///
/// let report = profile.install(&mut registry)?;
/// assert_eq!(report.executors_inserted(), STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StandardWebDiscoveryExecutorProfile {
    bindings: Vec<ExecutorBinding>,
}

impl StandardWebDiscoveryExecutorProfile {
    /// Constructs all discovery executors under one immutable HTTP policy.
    pub fn new(policy: HttpEvidencePolicy) -> Result<Self, StandardWebExecutionError> {
        Self::new_with_request_broker(HttpRequestBroker::new_unmetered(policy)?)
    }

    pub(crate) fn new_with_request_broker(
        requests: HttpRequestBroker,
    ) -> Result<Self, StandardWebExecutionError> {
        let bindings = STANDARD_WEB_DISCOVERY_ACTIONS
            .into_iter()
            .map(|kind| {
                let provider = Arc::new(SubjectHttpProbeProvider::new(probe_method(kind)?));
                let executor = HttpEvidenceExecutor::with_id_and_request_broker(
                    kind.executor_id(),
                    requests.clone(),
                    provider,
                )?;
                Ok(ExecutorBinding {
                    kind,
                    executor: Arc::new(executor),
                })
            })
            .collect::<Result<Vec<_>, StandardWebExecutionError>>()?;
        Ok(Self { bindings })
    }

    /// Installs executors and passive/active routes as one atomic registry update.
    ///
    /// Reinstalling the same profile is idempotent. A host-provided executor
    /// with a standard ID remains authoritative; conflicting action routes
    /// reject the complete installation without partially changing `registry`.
    pub fn install(
        &self,
        registry: &mut DecisionExecutorRegistry,
    ) -> Result<StandardWebDiscoveryInstallReport, StandardWebExecutionError> {
        let mut prospective = registry.clone();
        let mut executors_inserted = 0;

        for binding in &self.bindings {
            let executor_id = binding.kind.executor_id();
            if !prospective.contains(executor_id) {
                prospective.register(binding.executor.clone())?;
                executors_inserted += 1;
            }
            for stage in [
                DecisionExecutionStage::Passive,
                DecisionExecutionStage::Active,
            ] {
                prospective.route_action(stage, binding.kind.action_id(), executor_id)?;
            }
        }

        *registry = prospective;
        Ok(StandardWebDiscoveryInstallReport { executors_inserted })
    }

    /// Returns the semantic actions supplied by this profile.
    pub const fn actions(&self) -> &'static [StandardWebActionKind] {
        &STANDARD_WEB_DISCOVERY_ACTIONS
    }

    /// Returns the distinct executor identities supplied by this profile.
    pub fn executor_ids(&self) -> BTreeSet<&str> {
        self.bindings
            .iter()
            .map(|binding| binding.kind.executor_id())
            .collect()
    }
}

const fn probe_method(
    kind: StandardWebActionKind,
) -> Result<HttpProbeMethod, StandardWebExecutionError> {
    match kind {
        StandardWebActionKind::LaravelRouteDiscovery => Ok(HttpProbeMethod::Options),
        StandardWebActionKind::LivewireComponentDiscovery => Ok(HttpProbeMethod::Get),
        // A header-only HEAD probe: the nginx/apache configuration signals read
        // the `Server` response header. The probe only needs response metadata
        // already captured from a HEAD response and never requires a body, so it
        // introduces no new capture surface.
        StandardWebActionKind::NginxConfiguration
        | StandardWebActionKind::ApacheConfiguration
        | StandardWebActionKind::SanctumAuthBoundary
        | StandardWebActionKind::HttpBasicAuthBoundary
        | StandardWebActionKind::HttpBearerAuthBoundary => Ok(HttpProbeMethod::Head),
        StandardWebActionKind::PhpInputDiscovery
        | StandardWebActionKind::LaravelInputAnalysis => {
            Err(StandardWebExecutionError::UnsupportedAction { action: kind })
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };
    use url::Url;
    use venom_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
        KnowledgePredicate,
    };

    use super::*;
    use crate::{
        AdaptationLimits, BenefitScore, DecisionActionOrigin, DecisionExecutionFailureKind,
        DecisionLoop, DecisionLoopCommand, DecisionLoopConfig, DecisionRunnerAdapter,
        DecisionSession, ExperiencePolicy, ExperienceStore, KnowledgeBase, PlanningContext,
        RiskScore, StandardWebAttackProfile, StandardWebReasoning, VerificationCase,
    };

    async fn serve_requests(count: usize) -> (Url, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let recorded = methods.clone();
        tokio::spawn(async move {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 2048];
                let bytes = stream.read(&mut request).await.unwrap();
                let line = String::from_utf8_lossy(&request[..bytes]);
                let method = line.split_whitespace().next().unwrap().to_owned();
                recorded.lock().await.push(method);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nAllow: GET, HEAD, OPTIONS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        (
            Url::parse(&format!("http://{address}/app")).unwrap(),
            methods,
        )
    }

    fn case(url: &Url, id: &str, kind: StandardWebActionKind) -> VerificationCase {
        VerificationCase::new(
            id,
            EntityId::new(format!("endpoint:{url}")).unwrap(),
            kind.action_id(),
            "hypothesis:web",
        )
        .unwrap()
    }

    fn command(
        url: &Url,
        id: &str,
        kind: StandardWebActionKind,
        executor: Option<&str>,
    ) -> DecisionLoopCommand {
        DecisionLoopCommand::ExecuteAction {
            case: case(url, id, kind),
            executor: executor.map(str::to_owned),
            origin: DecisionActionOrigin::Planned,
            delay_ms: None,
        }
    }

    fn observed_method(receipt: &crate::DecisionEvidenceReceipt) -> Option<&EvidenceValue> {
        receipt
            .after_execution()
            .evidence()
            .iter()
            .find(|evidence| {
                evidence.source().correlation_id() == Some(receipt.case().id())
                    && evidence.predicate().dotted() == "http.request.method"
            })
            .map(Evidence::value)
    }

    #[test]
    fn profile_installs_atomically_and_idempotently() {
        let target = Url::parse("https://example.test/app").unwrap();
        let profile = StandardWebDiscoveryExecutorProfile::new(
            HttpEvidencePolicy::for_origin(target).unwrap(),
        )
        .unwrap();
        let mut registry = DecisionExecutorRegistry::new();

        let first = profile.install(&mut registry).unwrap();
        let second = profile.install(&mut registry).unwrap();

        assert_eq!(
            first.executors_inserted(),
            STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT
        );
        assert_eq!(second, StandardWebDiscoveryInstallReport::default());
        assert_eq!(registry.len(), STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT);
        assert_eq!(
            profile.executor_ids().len(),
            STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT
        );
    }

    #[test]
    fn every_discovery_action_has_an_executor_mapping() {
        for kind in STANDARD_WEB_DISCOVERY_ACTIONS {
            assert!(probe_method(kind).is_ok(), "missing mapping for {kind:?}");
        }
    }

    #[test]
    fn actions_without_a_discovery_executor_fail_during_mapping() {
        for kind in StandardWebActionKind::all()
            .into_iter()
            .filter(|kind| !STANDARD_WEB_DISCOVERY_ACTIONS.contains(kind))
        {
            assert!(matches!(
                probe_method(kind),
                Err(StandardWebExecutionError::UnsupportedAction { action }) if action == kind
            ));
        }
    }

    #[test]
    fn route_conflict_leaves_the_original_registry_unchanged() {
        let target = Url::parse("https://example.test/app").unwrap();
        let policy = HttpEvidencePolicy::for_origin(target).unwrap();
        let host_executor = HttpEvidenceExecutor::with_id(
            "host.custom",
            policy.clone(),
            Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Head)),
        )
        .unwrap();
        let kind = StandardWebActionKind::LaravelRouteDiscovery;
        let mut registry = DecisionExecutorRegistry::new();
        registry.register(Arc::new(host_executor)).unwrap();
        registry
            .route_action(
                DecisionExecutionStage::Passive,
                kind.action_id(),
                "host.custom",
            )
            .unwrap();
        let profile = StandardWebDiscoveryExecutorProfile::new(policy).unwrap();

        assert!(matches!(
            profile.install(&mut registry),
            Err(StandardWebExecutionError::Runner(
                DecisionRunnerError::ActionRouteConflict { .. }
            ))
        ));
        assert_eq!(registry.len(), 1);
        assert!(registry.contains("host.custom"));
        assert!(!registry.contains(kind.executor_id()));
    }

    #[tokio::test]
    async fn passive_and_active_routes_use_discovery_only_methods() {
        let (target, methods) = serve_requests(3).await;
        let profile = StandardWebDiscoveryExecutorProfile::new(
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
        )
        .unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        profile.install(&mut registry).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();

        let route = StandardWebActionKind::LaravelRouteDiscovery;
        let route_receipt = adapter
            .execute_command(&command(&target, "case:route", route, None), &knowledge)
            .await
            .unwrap();
        assert_eq!(route_receipt.executor_id(), route.executor_id());
        assert_eq!(
            observed_method(&route_receipt),
            Some(&EvidenceValue::Text("OPTIONS".to_owned()))
        );

        let component = StandardWebActionKind::LivewireComponentDiscovery;
        let component_receipt = adapter
            .execute_command(
                &command(
                    &target,
                    "case:component",
                    component,
                    Some(component.executor_id()),
                ),
                &knowledge,
            )
            .await
            .unwrap();
        assert_eq!(
            observed_method(&component_receipt),
            Some(&EvidenceValue::Text("GET".to_owned()))
        );

        let auth = StandardWebActionKind::HttpBasicAuthBoundary;
        let auth_receipt = adapter
            .execute_command(
                &DecisionLoopCommand::CollectActiveEvidence {
                    case: case(&target, "case:auth", auth),
                },
                &knowledge,
            )
            .await
            .unwrap();
        assert_eq!(auth_receipt.executor_id(), auth.executor_id());
        assert_eq!(
            observed_method(&auth_receipt),
            Some(&EvidenceValue::Text("HEAD".to_owned()))
        );
        assert_eq!(methods.lock().await.as_slice(), ["OPTIONS", "GET", "HEAD"]);
    }

    #[tokio::test]
    async fn reasoning_plan_executes_through_the_semantic_registry() {
        let (target, methods) = serve_requests(1).await;
        let subject = EntityId::new(format!("endpoint:{target}")).unwrap();
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(
                ["laravel_session", "XSRF-TOKEN"]
                    .into_iter()
                    .map(|cookie| {
                        Evidence::new(
                            subject.clone(),
                            EvidenceKind::Http,
                            KnowledgePredicate::new("http.cookie", "name").unwrap(),
                            EvidenceValue::Text(cookie.to_owned()),
                            EvidenceSource::new("http.evidence", cookie).unwrap(),
                            ConfidenceScore::MAX,
                        )
                    })
                    .collect(),
            )
            .unwrap();
        let config = DecisionLoopConfig::new(
            PlanningContext::new(
                BenefitScore::from_percent(90).unwrap(),
                200,
                RiskScore::from_percent(100).unwrap(),
            ),
            AdaptationLimits::default(),
            ExperiencePolicy::new(3).unwrap(),
            8,
        )
        .unwrap();
        let mut decision_loop = DecisionLoop::new(config);
        StandardWebReasoning::new()
            .unwrap()
            .install(&knowledge, decision_loop.rules_mut())
            .unwrap();
        StandardWebAttackProfile::new()
            .unwrap()
            .install(decision_loop.planner_mut())
            .unwrap();
        let experience = ExperienceStore::new();
        let mut session = DecisionSession::new(subject);
        let planned = decision_loop
            .plan_next(&knowledge, &experience, &mut session)
            .unwrap();

        let profile = StandardWebDiscoveryExecutorProfile::new(
            HttpEvidencePolicy::for_origin(target).unwrap(),
        )
        .unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        profile.install(&mut registry).unwrap();
        let receipt = DecisionRunnerAdapter::new(registry)
            .execute_command(planned.command(), &knowledge)
            .await
            .unwrap();

        assert_eq!(
            receipt.executor_id(),
            StandardWebActionKind::LaravelRouteDiscovery.executor_id()
        );
        assert_eq!(methods.lock().await.as_slice(), ["OPTIONS"]);
    }

    #[tokio::test]
    async fn policy_rejects_cross_origin_subject_before_network_io() {
        let allowed = Url::parse("http://127.0.0.1:1/app").unwrap();
        let outside = Url::parse("http://127.0.0.1:2/app").unwrap();
        let profile = StandardWebDiscoveryExecutorProfile::new(
            HttpEvidencePolicy::for_origin(allowed).unwrap(),
        )
        .unwrap();
        let mut registry = DecisionExecutorRegistry::new();
        profile.install(&mut registry).unwrap();
        let adapter = DecisionRunnerAdapter::new(registry);
        let knowledge = KnowledgeBase::new();
        let kind = StandardWebActionKind::HttpBearerAuthBoundary;

        let error = adapter
            .execute_command(
                &command(&outside, "case:outside", kind, Some(kind.executor_id())),
                &knowledge,
            )
            .await
            .unwrap_err();

        let failure = error.execution_failure().unwrap();
        assert_eq!(
            failure.kind(),
            DecisionExecutionFailureKind::BlockedByPolicy
        );
        assert_eq!(failure.executor_id(), kind.executor_id());
        assert_eq!(failure.action_id(), kind.action_id());
        assert!(failure.diagnostic().contains("outside policy"));
        assert_eq!(knowledge.stats().evidence, 0);
    }
}
