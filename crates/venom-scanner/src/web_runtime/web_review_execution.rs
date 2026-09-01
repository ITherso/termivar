//! Runtime-local shared-authority executors for native low-risk web review.
//!
//! This crate-private profile binds the transport-neutral review catalog to the
//! existing HTTP evidence executor. It never constructs a request broker:
//! every executor receives a clone of one host-owned broker, whose clones share
//! the same exact-origin policy and request-accounting authority. Redirects
//! remain disabled by that broker.
//!
//! The profile is intentionally opt-in. The redirect/reflection pair is absent
//! unless discovery supplies one already-validated query-parameter name; the
//! profile never invents a parameter or installs a route that cannot execute.

use std::{fmt, sync::Arc};

#[cfg(test)]
use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[cfg(feature = "normalization-resilience")]
use crate::payload_strategies::normalization_resilience_query_pair::{
    NORMALIZATION_RESILIENCE_QUERY_PAIR_ID, NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
};
use crate::payload_strategies::ssti_arithmetic_expression_pair::SstiArithmeticProbe;
use crate::{
    decision_runner::{
        DecisionActionExecutor, DecisionExecutionStage, DecisionExecutorRegistry,
        DecisionRunnerError,
    },
    http_evidence::{
        CompleteHttpResponseObserver, HttpEvidenceError, HttpEvidenceExecutor,
        HttpHeaderPayloadBinding, HttpProbe, HttpProbeMethod, HttpQueryPayloadBinding,
        HttpRequestBroker, SubjectHttpProbeProvider,
    },
    payload_strategies::{
        standard_payload_strategies, CORS_ORIGIN_PAIR_HEADER_NAME, CORS_ORIGIN_PAIR_ID,
        CORS_ORIGIN_PAIR_REVISION, EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION,
        REFLECTION_MARKER_QUERY_PAIR_ID, REFLECTION_MARKER_QUERY_PAIR_REVISION,
        SQL_QUOTE_BALANCE_QUERY_PAIR_ID, SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        SSTI_ARITHMETIC_EXPRESSION_PAIR_ID, SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID, XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
        XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION, XSS_STRUCTURAL_QUERY_PAIR_ID,
        XSS_STRUCTURAL_QUERY_PAIR_REVISION,
    },
    payload_strategy::{
        PayloadSeed, PayloadStrategyError, PayloadStrategyLimits, PayloadStrategyRef,
    },
    web_actions::NativeWebReviewActionKind,
};

#[cfg(feature = "normalization-resilience")]
use super::web_assessment::NormalizationTransformSelection;
use super::web_assessment::XssProbeSelection;

const REVIEW_PAYLOAD_MAX_BYTES: u32 = 256;
const REVIEW_SEED_DIGEST_BYTES: usize = 16;

/// Failure while constructing or atomically installing native review routes.
#[derive(Debug, Error)]
pub(crate) enum NativeWebReviewExecutionError {
    /// The base request must not carry pre-existing query state.
    #[error("native web review requires a query-free root URL")]
    RootQueryNotAllowed,

    /// Fragments are not part of HTTP requests and may not influence a case seed.
    #[error("native web review requires a fragment-free root URL")]
    RootFragmentNotAllowed,

    /// The supplied broker must already be narrowed to exactly the root origin.
    #[error("native web review requires one exact-origin request broker")]
    ExactOriginBrokerRequired,

    /// A seed plan derived for another origin cannot be rebound to this root.
    #[error("native web review seed plan does not match the authorized origin")]
    SeedOriginMismatch,

    /// A request policy, executor, or payload binding rejected construction.
    #[error(transparent)]
    Http(#[from] HttpEvidenceError),

    /// A fixed payload reference, registry, seed, or byte envelope was invalid.
    #[error(transparent)]
    Payload(#[from] PayloadStrategyError),

    /// An executor identity or action route conflicted with host registry state.
    #[error(transparent)]
    Runner(#[from] DecisionRunnerError),
}

/// Count of executors added by one idempotent profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NativeWebReviewExecutionInstallReport {
    executors_inserted: usize,
}

impl NativeWebReviewExecutionInstallReport {
    /// Returns the number of previously absent executor identities installed.
    pub(crate) const fn executors_inserted(self) -> usize {
        self.executors_inserted
    }
}

struct NativeExecutorBinding {
    kind: NativeWebReviewActionKind,
    executor: Arc<HttpEvidenceExecutor>,
}

pub(crate) struct NativeWebReviewQueryParameters {
    redirect: Option<String>,
    reflection: Option<String>,
    sql: Option<String>,
    ssti: Option<String>,
    xss: Option<(String, XssProbeSelection)>,
    #[cfg(feature = "normalization-resilience")]
    normalization: Option<(String, NormalizationTransformSelection)>,
}

impl NativeWebReviewQueryParameters {
    pub(crate) fn full(
        redirect: Option<String>,
        reflection: Option<String>,
        sql: Option<String>,
        ssti: Option<String>,
    ) -> Self {
        Self {
            redirect,
            reflection,
            sql,
            ssti,
            xss: None,
            #[cfg(feature = "normalization-resilience")]
            normalization: None,
        }
    }

    pub(crate) fn structural(
        reflection: Option<String>,
        sql: Option<String>,
        ssti: Option<String>,
    ) -> Self {
        Self::full(None, reflection, sql, ssti)
    }

    pub(crate) fn xss_only(parameter: String, selection: XssProbeSelection) -> Self {
        Self {
            redirect: None,
            reflection: None,
            sql: None,
            ssti: None,
            xss: Some((parameter, selection)),
            #[cfg(feature = "normalization-resilience")]
            normalization: None,
        }
    }

    #[cfg(feature = "normalization-resilience")]
    pub(crate) fn normalization_only(
        parameter: String,
        selection: NormalizationTransformSelection,
    ) -> Self {
        Self {
            redirect: None,
            reflection: None,
            sql: None,
            ssti: None,
            xss: None,
            normalization: Some((parameter, selection)),
        }
    }
}

/// Returns the one closed, deterministic executable subset for a subject.
pub(crate) fn enabled_native_web_review_actions(
    include_cors: bool,
    redirect_query_configured: bool,
    reflection_query_configured: bool,
    sql_query_configured: bool,
    ssti_query_configured: bool,
    xss_action: Option<NativeWebReviewActionKind>,
) -> Vec<NativeWebReviewActionKind> {
    NativeWebReviewActionKind::all()
        .into_iter()
        .filter(|kind| match kind {
            NativeWebReviewActionKind::CorsPolicyPair => include_cors,
            NativeWebReviewActionKind::RedirectReflectionQueryPair => redirect_query_configured,
            NativeWebReviewActionKind::ReflectionContextQueryPair => reflection_query_configured,
            NativeWebReviewActionKind::SqlStructuralQueryPair
            | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => sql_query_configured,
            NativeWebReviewActionKind::SstiStructuralQueryPair
            | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => ssti_query_configured,
            NativeWebReviewActionKind::XssStructuralQueryPair
            | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
            | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => {
                xss_action == Some(*kind)
            },
            #[cfg(feature = "normalization-resilience")]
            NativeWebReviewActionKind::NormalizationResilienceQueryPair => {
                xss_action == Some(*kind)
            },
        })
        .collect()
}

/// Opt-in executor bindings for matched CORS and redirect/reflection review.
///
/// Construction validates the root against the broker's existing authority,
/// then consumes non-secret `.invalid` candidates derived once from a stable
/// digest of the already-public exact-origin identity. Path bytes never enter the digest:
/// path segments can contain tokens, and hashing them would not make them
/// confidential. Raw seed values are owned only by the payload bindings and
/// never appear in this profile's debug representation.
pub(crate) struct NativeWebReviewExecutorProfile {
    bindings: Vec<NativeExecutorBinding>,
    redirect_query_configured: bool,
    reflection_query_configured: bool,
    sql_query_configured: bool,
    ssti_query_configured: bool,
    xss_action: Option<NativeWebReviewActionKind>,
    cors_configured: bool,
}

impl fmt::Debug for NativeWebReviewExecutorProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWebReviewExecutorProfile")
            .field(
                "actions",
                &self
                    .bindings
                    .iter()
                    .map(|binding| binding.kind.action_id())
                    .collect::<Vec<_>>(),
            )
            .field(
                "executor_ids",
                &self
                    .bindings
                    .iter()
                    .map(|binding| binding.kind.executor_id())
                    .collect::<Vec<_>>(),
            )
            .field("redirect_query_configured", &self.redirect_query_configured)
            .field(
                "reflection_query_configured",
                &self.reflection_query_configured,
            )
            .field("sql_query_configured", &self.sql_query_configured)
            .field("ssti_query_configured", &self.ssti_query_configured)
            .field(
                "xss_action",
                &self.xss_action.map(NativeWebReviewActionKind::action_id),
            )
            .field("cors_configured", &self.cors_configured)
            .field("seed_values", &"<redacted>")
            .finish()
    }
}

impl NativeWebReviewExecutorProfile {
    /// Constructs the available native review executors under one broker.
    ///
    /// `redirect_query_parameter == None` installs only the CORS pair. A
    /// supplied query name is validated by [`HttpQueryPayloadBinding`]; invalid
    /// names reject the complete profile before any registry is changed.
    pub(crate) fn new(
        requests: HttpRequestBroker,
        root: Url,
        seeds: NativeWebReviewSeeds,
        observer: Arc<dyn CompleteHttpResponseObserver>,
        query_parameters: NativeWebReviewQueryParameters,
    ) -> Result<Self, NativeWebReviewExecutionError> {
        Self::build(
            requests,
            root,
            seeds,
            Some(observer),
            query_parameters,
            true,
        )
    }

    pub(crate) fn new_structural_only(
        requests: HttpRequestBroker,
        root: Url,
        seeds: NativeWebReviewSeeds,
        observer: Arc<dyn CompleteHttpResponseObserver>,
        query_parameters: NativeWebReviewQueryParameters,
    ) -> Result<Self, NativeWebReviewExecutionError> {
        Self::build(
            requests,
            root,
            seeds,
            Some(observer),
            query_parameters,
            false,
        )
    }

    fn build(
        requests: HttpRequestBroker,
        root: Url,
        seeds: NativeWebReviewSeeds,
        observer: Option<Arc<dyn CompleteHttpResponseObserver>>,
        query_parameters: NativeWebReviewQueryParameters,
        include_cors: bool,
    ) -> Result<Self, NativeWebReviewExecutionError> {
        validate_root(&requests, &root)?;
        if !seeds.matches_origin(&root) {
            return Err(NativeWebReviewExecutionError::SeedOriginMismatch);
        }
        let NativeWebReviewQueryParameters {
            redirect: redirect_query_parameter,
            reflection: reflection_query_parameter,
            sql: sql_query_parameter,
            ssti: ssti_query_parameter,
            xss: xss_query_parameter,
            #[cfg(feature = "normalization-resilience")]
                normalization: normalization_query_parameter,
        } = query_parameters;
        let limits =
            PayloadStrategyLimits::new(REVIEW_PAYLOAD_MAX_BYTES, REVIEW_PAYLOAD_MAX_BYTES)?;
        let strategies = standard_payload_strategies()?;
        let provider = Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get));
        let xss_action = xss_query_parameter
            .as_ref()
            .map(|(_, selection)| selection.action_kind());
        #[cfg(feature = "normalization-resilience")]
        let xss_action = if normalization_query_parameter.is_some() {
            if xss_action.is_some() {
                return Err(NativeWebReviewExecutionError::Payload(
                    PayloadStrategyError::DerivationFailed,
                ));
            }
            Some(NativeWebReviewActionKind::NormalizationResilienceQueryPair)
        } else {
            xss_action
        };
        let enabled_actions = enabled_native_web_review_actions(
            include_cors,
            redirect_query_parameter.is_some(),
            reflection_query_parameter.is_some(),
            sql_query_parameter.is_some(),
            ssti_query_parameter.is_some(),
            xss_action,
        );

        let mut bindings = Vec::new();
        if enabled_actions.contains(&NativeWebReviewActionKind::CorsPolicyPair) {
            let cors_kind = NativeWebReviewActionKind::CorsPolicyPair;
            let cors_strategy = payload_strategy_reference(cors_kind)?;
            let cors_seed = PayloadSeed::new(seeds.cors_origin().as_bytes().to_vec(), limits)?;
            let cors_payload = HttpHeaderPayloadBinding::new(
                strategies.clone(),
                cors_strategy,
                cors_seed,
                limits,
                CORS_ORIGIN_PAIR_HEADER_NAME,
            )?;
            let cors_executor = configure_executor(
                HttpEvidenceExecutor::with_id_and_request_broker(
                    cors_kind.executor_id(),
                    requests.clone(),
                    provider.clone(),
                )?
                .with_payload_binding(cors_payload),
                observer.as_ref(),
            );
            bindings.push(NativeExecutorBinding {
                kind: cors_kind,
                executor: Arc::new(cors_executor),
            });
        }

        let redirect_query_configured =
            enabled_actions.contains(&NativeWebReviewActionKind::RedirectReflectionQueryPair);
        if let Some(parameter) = redirect_query_parameter {
            let redirect_kind = NativeWebReviewActionKind::RedirectReflectionQueryPair;
            let redirect_strategy = payload_strategy_reference(redirect_kind)?;
            let redirect_seed = PayloadSeed::new(seeds.external_url().as_bytes().to_vec(), limits)?;
            let redirect_payload = HttpQueryPayloadBinding::new(
                strategies.clone(),
                redirect_strategy.clone(),
                redirect_seed,
                limits,
                parameter,
            )?;
            let redirect_executor = configure_executor(
                HttpEvidenceExecutor::with_id_and_request_broker(
                    redirect_kind.executor_id(),
                    requests.clone(),
                    provider.clone(),
                )?
                .with_query_payload_binding(redirect_payload),
                observer.as_ref(),
            );
            bindings.push(NativeExecutorBinding {
                kind: redirect_kind,
                executor: Arc::new(redirect_executor),
            });
        }

        let reflection_query_configured =
            enabled_actions.contains(&NativeWebReviewActionKind::ReflectionContextQueryPair);
        if let Some(parameter) = reflection_query_parameter {
            let kind = NativeWebReviewActionKind::ReflectionContextQueryPair;
            let payload = HttpQueryPayloadBinding::new(
                strategies.clone(),
                payload_strategy_reference(kind)?,
                PayloadSeed::new(seeds.reflection_identity().as_bytes().to_vec(), limits)?,
                limits,
                parameter,
            )?;
            let executor = configure_executor(
                HttpEvidenceExecutor::with_id_and_request_broker(
                    kind.executor_id(),
                    requests.clone(),
                    provider.clone(),
                )?
                .with_query_payload_binding(payload),
                observer.as_ref(),
            );
            bindings.push(NativeExecutorBinding {
                kind,
                executor: Arc::new(executor),
            });
        }

        let sql_query_configured =
            enabled_actions.contains(&NativeWebReviewActionKind::SqlStructuralQueryPair);
        if let Some(parameter) = sql_query_parameter {
            let sql_seed = PayloadSeed::new(seeds.sql_token().as_bytes().to_vec(), limits)?;
            for kind in [
                NativeWebReviewActionKind::SqlStructuralQueryPair,
                NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
            ] {
                let strategy = payload_strategy_reference(kind)?;
                let payload = HttpQueryPayloadBinding::new(
                    strategies.clone(),
                    strategy,
                    sql_seed.clone(),
                    limits,
                    parameter.clone(),
                )?;
                let executor = configure_executor(
                    HttpEvidenceExecutor::with_id_and_request_broker(
                        kind.executor_id(),
                        requests.clone(),
                        provider.clone(),
                    )?
                    .with_query_payload_binding(payload),
                    observer.as_ref(),
                );
                bindings.push(NativeExecutorBinding {
                    kind,
                    executor: Arc::new(executor),
                });
            }
        }

        let ssti_query_configured =
            enabled_actions.contains(&NativeWebReviewActionKind::SstiStructuralQueryPair);
        if let Some(parameter) = ssti_query_parameter {
            for (kind, probe) in [
                (
                    NativeWebReviewActionKind::SstiStructuralQueryPair,
                    seeds.ssti_primary_probe(),
                ),
                (
                    NativeWebReviewActionKind::SstiStructuralQueryReplayPair,
                    seeds.ssti_replay_probe(),
                ),
            ] {
                let strategy = payload_strategy_reference(kind)?;
                let payload = HttpQueryPayloadBinding::new(
                    strategies.clone(),
                    strategy,
                    PayloadSeed::new(probe.seed().into_bytes(), limits)?,
                    limits,
                    parameter.clone(),
                )?;
                let executor = configure_executor(
                    HttpEvidenceExecutor::with_id_and_request_broker(
                        kind.executor_id(),
                        requests.clone(),
                        provider.clone(),
                    )?
                    .with_query_payload_binding(payload),
                    observer.as_ref(),
                );
                bindings.push(NativeExecutorBinding {
                    kind,
                    executor: Arc::new(executor),
                });
            }
        }

        if let Some((parameter, selection)) = xss_query_parameter {
            let kind = selection.action_kind();
            let seed = selection.strategy_seed(seeds.reflection_identity());
            let payload = HttpQueryPayloadBinding::new(
                strategies.clone(),
                payload_strategy_reference(kind)?,
                PayloadSeed::new(seed.into_bytes(), limits)?,
                limits,
                parameter,
            )?;
            let executor = configure_executor(
                HttpEvidenceExecutor::with_id_and_request_broker(
                    kind.executor_id(),
                    requests.clone(),
                    provider.clone(),
                )?
                .with_query_payload_binding(payload),
                observer.as_ref(),
            );
            bindings.push(NativeExecutorBinding {
                kind,
                executor: Arc::new(executor),
            });
        }

        #[cfg(feature = "normalization-resilience")]
        if let Some((parameter, selection)) = normalization_query_parameter {
            let kind = NativeWebReviewActionKind::NormalizationResilienceQueryPair;
            debug_assert!(selection.is_executable_v1_contract());
            let strategy = selection.strategy_ref();
            debug_assert_eq!(strategy, payload_strategy_reference(kind)?);
            let seed = selection
                .strategy_seed(
                    &seeds.normalization_candidate_identity(),
                    &seeds.normalization_replay_identity(),
                )
                .ok_or(NativeWebReviewExecutionError::Payload(
                    PayloadStrategyError::DerivationFailed,
                ))?;
            let payload = HttpQueryPayloadBinding::new(
                strategies.clone(),
                strategy,
                PayloadSeed::new(seed.into_bytes(), limits)?,
                limits,
                parameter,
            )?;
            let executor = configure_executor(
                HttpEvidenceExecutor::with_id_and_request_broker(
                    kind.executor_id(),
                    requests.clone(),
                    provider.clone(),
                )?
                .with_query_payload_binding(payload),
                observer.as_ref(),
            );
            bindings.push(NativeExecutorBinding {
                kind,
                executor: Arc::new(executor),
            });
        }

        debug_assert_eq!(
            bindings
                .iter()
                .map(|binding| binding.kind)
                .collect::<Vec<_>>(),
            enabled_actions
        );
        Ok(Self {
            bindings,
            redirect_query_configured,
            reflection_query_configured,
            sql_query_configured,
            ssti_query_configured,
            xss_action,
            cors_configured: include_cors,
        })
    }

    /// Installs each available executor and both stage routes atomically.
    ///
    /// Both `ExecuteAction` and executor-less `CollectActiveEvidence` therefore
    /// resolve to the same exact executor identity. Reinstalling an identical
    /// profile is idempotent. Any route conflict leaves `registry` unchanged.
    pub(crate) fn install(
        &self,
        registry: &mut DecisionExecutorRegistry,
    ) -> Result<NativeWebReviewExecutionInstallReport, NativeWebReviewExecutionError> {
        let mut prospective = registry.clone();
        let mut executors_inserted = 0;

        for binding in &self.bindings {
            let executor_id = binding.kind.executor_id();
            if !prospective.contains(executor_id) {
                let executor: Arc<dyn DecisionActionExecutor> = binding.executor.clone();
                prospective.register(executor)?;
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
        Ok(NativeWebReviewExecutionInstallReport { executors_inserted })
    }

    /// Returns the enabled action kinds in stable catalog order.
    pub(crate) fn actions(&self) -> impl ExactSizeIterator<Item = NativeWebReviewActionKind> + '_ {
        self.bindings.iter().map(|binding| binding.kind)
    }

    /// Returns the distinct exact executor identities supplied by this profile.
    #[cfg(test)]
    pub(crate) fn executor_ids(&self) -> BTreeSet<&str> {
        self.bindings
            .iter()
            .map(|binding| binding.kind.executor_id())
            .collect()
    }

    /// Returns whether the test-visible executor advertises its exact strategy.
    #[cfg(test)]
    pub(crate) fn supports_exact_strategy(&self, kind: NativeWebReviewActionKind) -> bool {
        let Ok(expected) = payload_strategy_reference(kind) else {
            return false;
        };
        self.bindings
            .iter()
            .find(|binding| binding.kind == kind)
            .is_some_and(|binding| {
                binding.executor.supports_payload_strategy(&expected)
                    && binding.executor.payload_strategy_reference() == Some(&expected)
            })
    }

    #[cfg(test)]
    fn new_without_observer_for_test(
        requests: HttpRequestBroker,
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<String>,
    ) -> Result<Self, NativeWebReviewExecutionError> {
        Self::build(
            requests,
            root,
            seeds,
            None,
            NativeWebReviewQueryParameters {
                reflection: redirect_query_parameter.clone(),
                redirect: redirect_query_parameter,
                sql: None,
                ssti: None,
                xss: None,
                #[cfg(feature = "normalization-resilience")]
                normalization: None,
            },
            true,
        )
    }
}

fn payload_strategy_reference(
    kind: NativeWebReviewActionKind,
) -> Result<PayloadStrategyRef, PayloadStrategyError> {
    let (id, revision) = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => {
            (CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            (EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
        },
        NativeWebReviewActionKind::ReflectionContextQueryPair => (
            REFLECTION_MARKER_QUERY_PAIR_ID,
            REFLECTION_MARKER_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => (
            SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
            SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => (
            SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
            SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssStructuralQueryPair => (
            XSS_STRUCTURAL_QUERY_PAIR_ID,
            XSS_STRUCTURAL_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => (
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => (
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => (
            NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
            NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
        ),
    };
    PayloadStrategyRef::new(id, revision)
}

fn configure_executor(
    executor: HttpEvidenceExecutor,
    observer: Option<&Arc<dyn CompleteHttpResponseObserver>>,
) -> HttpEvidenceExecutor {
    let executor = if let Some(observer) = observer {
        executor.with_complete_response_observer(observer.clone())
    } else {
        executor
    };
    executor.with_assessment_defense_projection()
}

fn validate_root(
    requests: &HttpRequestBroker,
    root: &Url,
) -> Result<(), NativeWebReviewExecutionError> {
    if root.query().is_some() {
        return Err(NativeWebReviewExecutionError::RootQueryNotAllowed);
    }
    if root.fragment().is_some() {
        return Err(NativeWebReviewExecutionError::RootFragmentNotAllowed);
    }
    HttpProbe::new(root.clone(), HttpProbeMethod::Get)?;
    requests.policy().require_permitted_target(root)?;
    let expected_origin = root.origin().ascii_serialization();
    if requests.policy().allowed_origins().len() != 1
        || !requests
            .policy()
            .allowed_origins()
            .contains(&expected_origin)
    {
        return Err(NativeWebReviewExecutionError::ExactOriginBrokerRequired);
    }
    Ok(())
}

/// Deterministic non-secret candidates shared by executor and observer setup.
///
/// The only derivation input is the normalized exact-origin serialization.
/// Paths, queries, fragments, and credentials never enter either candidate.
/// Raw getters are crate-private because only the native executor binding and
/// its sealed response observer need the exact correlation values.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NativeWebReviewSeeds {
    origin_identity: String,
    cors_origin: String,
    external_url: String,
    reflection_identity: String,
    sql_token: String,
    ssti_primary_probe: SstiArithmeticProbe,
    ssti_replay_probe: SstiArithmeticProbe,
}

impl fmt::Debug for NativeWebReviewSeeds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWebReviewSeeds")
            .field("origin", &"<redacted>")
            .field("cors_origin_bytes", &self.cors_origin.len())
            .field("external_url_bytes", &self.external_url.len())
            .field("reflection_marker_bytes", &72_usize)
            .field("sql_token_bytes", &self.sql_token.len())
            .field(
                "ssti_probe_family",
                &"web.review.ssti.family.brace-arithmetic@1",
            )
            .field("values", &"<redacted>")
            .finish()
    }
}

impl NativeWebReviewSeeds {
    /// Derives one stable pair from the normalized HTTP(S) origin only.
    pub(crate) fn from_authorized_origin(root: &Url) -> Result<Self, HttpEvidenceError> {
        HttpProbe::new(root.clone(), HttpProbeMethod::Get)?;
        let origin = root.origin().ascii_serialization();
        let digest = Sha256::digest(origin.as_bytes());
        let identity = lowercase_hex(&digest[..REVIEW_SEED_DIGEST_BYTES]);
        let primary_left = 2 + (digest[16] % 5);
        let primary_right = 7 + (digest[17] % 3);
        let replay_left = 9 + (digest[18] % 4);
        let replay_right = 9 + (digest[19] % 4);
        let ssti_primary_probe =
            SstiArithmeticProbe::new(lowercase_hex(&digest[..8]), primary_left, primary_right)
                .expect("bounded digest-derived primary SSTI operands are valid");
        let ssti_replay_probe =
            SstiArithmeticProbe::new(lowercase_hex(&digest[8..16]), replay_left, replay_right)
                .expect("bounded digest-derived replay SSTI operands are valid");
        Ok(Self {
            origin_identity: origin,
            cors_origin: format!("https://cors-{identity}.review.invalid"),
            external_url: format!("https://redirect-{identity}.review.invalid/venom-review"),
            reflection_identity: identity.clone(),
            sql_token: format!("venom-review-{identity}"),
            ssti_primary_probe,
            ssti_replay_probe,
        })
    }

    /// Returns the exact candidate Origin value for executor binding or matching.
    pub(crate) fn cors_origin(&self) -> &str {
        &self.cors_origin
    }

    /// Returns the exact external query value for executor binding or reflection matching.
    pub(crate) fn external_url(&self) -> &str {
        &self.external_url
    }

    pub(crate) fn reflection_identity(&self) -> &str {
        &self.reflection_identity
    }

    #[cfg(feature = "normalization-resilience")]
    pub(crate) fn normalization_candidate_identity(&self) -> String {
        self.normalization_identity("transformed-candidate")
    }

    #[cfg(feature = "normalization-resilience")]
    pub(crate) fn normalization_replay_identity(&self) -> String {
        self.normalization_identity("transformed-replay")
    }

    #[cfg(feature = "normalization-resilience")]
    fn normalization_identity(&self, role: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"venom.normalization-resilience.identity/v1\0");
        digest.update((self.origin_identity.len() as u64).to_be_bytes());
        digest.update(self.origin_identity.as_bytes());
        digest.update((role.len() as u64).to_be_bytes());
        digest.update(role.as_bytes());
        let digest = digest.finalize();
        lowercase_hex(&digest[..REVIEW_SEED_DIGEST_BYTES])
    }

    pub(crate) fn reflection_control_marker(&self) -> String {
        format!("venom-reflection-control-{}-end", self.reflection_identity)
    }

    pub(crate) fn reflection_candidate_marker(&self) -> String {
        format!(
            "venom-reflection-candidate-{}-end",
            self.reflection_identity
        )
    }

    /// Returns the bounded scanner-owned token used by the SQL mutation catalog.
    pub(crate) fn sql_token(&self) -> &str {
        &self.sql_token
    }

    pub(crate) fn ssti_primary_probe(&self) -> &SstiArithmeticProbe {
        &self.ssti_primary_probe
    }

    pub(crate) fn ssti_replay_probe(&self) -> &SstiArithmeticProbe {
        &self.ssti_replay_probe
    }

    fn matches_origin(&self, root: &Url) -> bool {
        self.origin_identity == root.origin().ascii_serialization()
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
#[path = "web_review_execution_tests.rs"]
mod tests;
