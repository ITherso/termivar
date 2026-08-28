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
    },
    payload_strategy::{
        PayloadSeed, PayloadStrategyError, PayloadStrategyLimits, PayloadStrategyRef,
    },
    web_actions::NativeWebReviewActionKind,
};

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
        redirect_query_parameter: Option<String>,
    ) -> Result<Self, NativeWebReviewExecutionError> {
        Self::build(
            requests,
            root,
            seeds,
            Some(observer),
            redirect_query_parameter,
        )
    }

    fn build(
        requests: HttpRequestBroker,
        root: Url,
        seeds: NativeWebReviewSeeds,
        observer: Option<Arc<dyn CompleteHttpResponseObserver>>,
        redirect_query_parameter: Option<String>,
    ) -> Result<Self, NativeWebReviewExecutionError> {
        validate_root(&requests, &root)?;
        if !seeds.matches_origin(&root) {
            return Err(NativeWebReviewExecutionError::SeedOriginMismatch);
        }
        let limits =
            PayloadStrategyLimits::new(REVIEW_PAYLOAD_MAX_BYTES, REVIEW_PAYLOAD_MAX_BYTES)?;
        let strategies = standard_payload_strategies()?;
        let provider = Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get));

        let cors_kind = NativeWebReviewActionKind::CorsPolicyPair;
        let cors_strategy = payload_strategy_reference(cors_kind)?;
        let cors_seed = PayloadSeed::new(seeds.cors_origin().as_bytes().to_vec(), limits)?;
        let cors_payload = HttpHeaderPayloadBinding::new(
            strategies.clone(),
            cors_strategy.clone(),
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
        let mut bindings = vec![NativeExecutorBinding {
            kind: cors_kind,
            executor: Arc::new(cors_executor),
        }];

        let redirect_query_configured = redirect_query_parameter.is_some();
        if let Some(parameter) = redirect_query_parameter {
            let redirect_kind = NativeWebReviewActionKind::RedirectReflectionQueryPair;
            let redirect_strategy = payload_strategy_reference(redirect_kind)?;
            let redirect_seed = PayloadSeed::new(seeds.external_url().as_bytes().to_vec(), limits)?;
            let redirect_payload = HttpQueryPayloadBinding::new(
                strategies,
                redirect_strategy.clone(),
                redirect_seed,
                limits,
                parameter,
            )?;
            let redirect_executor = configure_executor(
                HttpEvidenceExecutor::with_id_and_request_broker(
                    redirect_kind.executor_id(),
                    requests,
                    provider,
                )?
                .with_query_payload_binding(redirect_payload),
                observer.as_ref(),
            );
            bindings.push(NativeExecutorBinding {
                kind: redirect_kind,
                executor: Arc::new(redirect_executor),
            });
        }

        Ok(Self {
            bindings,
            redirect_query_configured,
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
        Self::build(requests, root, seeds, None, redirect_query_parameter)
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
}

impl fmt::Debug for NativeWebReviewSeeds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWebReviewSeeds")
            .field("origin", &"<redacted>")
            .field("cors_origin_bytes", &self.cors_origin.len())
            .field("external_url_bytes", &self.external_url.len())
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
        Ok(Self {
            origin_identity: origin,
            cors_origin: format!("https://cors-{identity}.review.invalid"),
            external_url: format!("https://redirect-{identity}.review.invalid/venom-review"),
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
