//! Bounded native web-review evidence and committed matched-pair replay.
//!
//! The HTTP executor lends this module only a fixed-vocabulary response
//! projection and, for reflection review, a complete bounded body. Raw
//! headers, payload bytes, and partial bodies never cross the retained evidence
//! boundary. Product projection must consume [`AssessmentReviewCandidate`]
//! values rather than interpreting action success as a vulnerability.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use thiserror::Error;
use url::Url;
use venom_core::{
    DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId, EvidenceKind,
    EvidenceOrigin, EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
    OutcomeStatus, VerificationStage,
};

use crate::web_review_execution::NativeWebReviewSeeds;
use crate::{
    http_evidence::{
        CompleteHttpResponseObservation, CompleteHttpResponseObserver,
        CorsAllowCredentialsRelation, CorsAllowOriginRelation, LocationRelation,
        VaryOriginRelation,
    },
    payload_strategies::{
        ExternalUrlQueryPairStrategy, CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION,
        EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION,
    },
    web_review_actions::{NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE, NATIVE_WEB_REVIEW_RESPONSE_MARKER},
    DecisionEvidenceReceipt, DecisionExecutionStage, DecisionOutcomeReport, HttpEvidenceError,
    HttpProbeMethod, KnowledgeBase, KnowledgeWrite, NativeWebReviewActionKind, PayloadSeed,
    PayloadStrategy, PayloadStrategyLimits, PayloadStrategyRef, PayloadVariantRole,
};

use super::web_assessment::{classify_exact_html_reflection, ExactHtmlReflectionContext};

const ASSESSMENT_REVIEW_CATEGORY: &str = "web-review-observation";
const ASSESSMENT_REVIEW_ALGORITHM: &str = "web.review.bounded-response-relations";
const ASSESSMENT_REVIEW_ALGORITHM_VERSION: u32 = 1;
const MAX_REVIEW_QUERY_PARAMETER_BYTES: usize = 64;
const MAX_REVIEW_CANDIDATE_BYTES: usize = 2_048;
const MAX_REVIEW_OBSERVATIONS: usize = 4;

const CORS_ALLOW_ORIGIN_RELATION: &str = "cors-allow-origin-relation";
const CORS_ALLOW_CREDENTIALS_RELATION: &str = "cors-allow-credentials-relation";
const CORS_VARY_ORIGIN_RELATION: &str = "cors-vary-origin-relation";
const CORS_HTTP_STATUS_CLASS: &str = "cors-http-status-class";
const REDIRECT_STATUS_RELATION: &str = "redirect-status-relation";
const REDIRECT_LOCATION_RELATION: &str = "redirect-location-relation";
const HTML_REFLECTION_CONTEXT: &str = "html-reflection-context";

const CORS_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.cors-policy-pair.pair-complete@1";
const REDIRECT_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.redirect-reflection-query-pair.pair-complete@1";

/// Returns the one verifier identity authorized to classify pair completion.
///
/// This verifier remains knowledge-only. Its `Success` is workflow truth, not
/// claim confirmation.
pub(crate) const fn native_review_active_verifier_rule_id(
    kind: NativeWebReviewActionKind,
) -> &'static str {
    match kind {
        NativeWebReviewActionKind::CorsPolicyPair => CORS_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::RedirectReflectionQueryPair => REDIRECT_ACTIVE_VERIFIER_RULE_ID,
    }
}

/// Invalid host composition for a sealed native-review observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum AssessmentReviewObserverError {
    #[error("native review requires one canonical query-free HTTP(S) root")]
    Root,
    #[error("native redirect review requires one bounded canonical query parameter name")]
    QueryParameter,
    #[error("native redirect review requires one bounded inert external candidate")]
    Candidate,
}

#[derive(Clone, PartialEq, Eq)]
struct RedirectReflectionContract {
    query_parameter: String,
    candidate_url: Url,
    candidate_value: String,
}

impl fmt::Debug for RedirectReflectionContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectReflectionContract")
            .field("query_parameter", &"<redacted>")
            .field("candidate_url", &"<redacted>")
            .field("candidate_value", &"<redacted>")
            .finish()
    }
}

/// Stateless composite complete-response observer for the enabled native actions.
///
/// A fresh instance is bound to the exact executor/strategy catalog, one root
/// subject, the shared non-secret seed plan, and (optionally) one discovered
/// redirect parameter. It retains no response.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AssessmentReviewObserverSet {
    root: Url,
    subject: EntityId,
    seeds: NativeWebReviewSeeds,
    redirect: Option<RedirectReflectionContract>,
}

impl fmt::Debug for AssessmentReviewObserverSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentReviewObserverSet")
            .field("root", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("seeds", &self.seeds)
            .field("redirect", &self.redirect.as_ref().map(|_| "<configured>"))
            .finish()
    }
}

impl AssessmentReviewObserverSet {
    /// Binds CORS and an optional redirect/reflection pair to one exact root.
    pub(crate) fn new(
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<&str>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let subject = review_root_subject(&root)?;
        let expected_seeds = NativeWebReviewSeeds::from_authorized_origin(&root)
            .map_err(|_| AssessmentReviewObserverError::Root)?;
        if seeds != expected_seeds {
            return Err(AssessmentReviewObserverError::Candidate);
        }
        validate_external_candidate(seeds.external_url())?;
        let redirect = redirect_query_parameter
            .map(|query_parameter| {
                if !valid_query_parameter(query_parameter) {
                    return Err(AssessmentReviewObserverError::QueryParameter);
                }
                let mut candidate_url = root.clone();
                candidate_url
                    .query_pairs_mut()
                    .append_pair(query_parameter, seeds.external_url());
                Ok(RedirectReflectionContract {
                    query_parameter: query_parameter.to_owned(),
                    candidate_url,
                    candidate_value: seeds.external_url().to_owned(),
                })
            })
            .transpose()?;
        Ok(Self {
            root,
            subject,
            seeds,
            redirect,
        })
    }

    fn expected_url(
        &self,
        kind: NativeWebReviewActionKind,
        stage: DecisionExecutionStage,
    ) -> Option<&Url> {
        match (kind, stage) {
            (NativeWebReviewActionKind::CorsPolicyPair, _)
            | (
                NativeWebReviewActionKind::RedirectReflectionQueryPair,
                DecisionExecutionStage::Passive,
            ) => Some(&self.root),
            (
                NativeWebReviewActionKind::RedirectReflectionQueryPair,
                DecisionExecutionStage::Active,
            ) => self
                .redirect
                .as_ref()
                .map(|contract| &contract.candidate_url),
        }
    }

    fn validate_recognized(
        &self,
        kind: NativeWebReviewActionKind,
        observation: &CompleteHttpResponseObservation<'_>,
    ) -> Result<(), HttpEvidenceError> {
        let expected_strategy = native_review_strategy_ref(kind);
        if observation.action_id() != kind.action_id()
            || observation.executor_id() != kind.executor_id()
            || observation.subject() != &self.subject
            || observation.method() != HttpProbeMethod::Get
            || observation.expected_url_mismatch(self.expected_url(kind, observation.stage()))
            || observation.case_id().is_empty()
            || observation.hypothesis_id().is_empty()
            || !observation.has_payload_strategy()
            || observation.payload_strategy() != Some(&expected_strategy)
            || observation.applies_hypothesis_transition()
        {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "native-review-action-contract",
            });
        }
        Ok(())
    }

    fn project(
        &self,
        kind: NativeWebReviewActionKind,
        observation: &CompleteHttpResponseObservation<'_>,
    ) -> Vec<(ReviewProperty, &'static str)> {
        let marker = match observation.stage() {
            DecisionExecutionStage::Passive => "passive-control",
            DecisionExecutionStage::Active => "active-candidate",
        };
        let projection = observation.review_response_projection();
        let mut records = vec![(ReviewProperty::ResponseMarker, marker)];
        match kind {
            NativeWebReviewActionKind::CorsPolicyPair => records.extend([
                (
                    ReviewProperty::CorsHttpStatusClass,
                    http_status_class_slug(classify_http_status(observation.status())),
                ),
                (
                    ReviewProperty::CorsAllowOrigin,
                    cors_allow_origin_slug(projection.access_control_allow_origin()),
                ),
                (
                    ReviewProperty::CorsAllowCredentials,
                    cors_allow_credentials_slug(projection.access_control_allow_credentials()),
                ),
                (
                    ReviewProperty::CorsVaryOrigin,
                    vary_origin_slug(projection.vary_origin()),
                ),
            ]),
            NativeWebReviewActionKind::RedirectReflectionQueryPair => records.extend([
                (
                    ReviewProperty::RedirectStatus,
                    if is_redirect_status(observation.status()) {
                        "redirect"
                    } else {
                        "other"
                    },
                ),
                (
                    ReviewProperty::RedirectLocation,
                    location_slug(projection.location()),
                ),
                (
                    ReviewProperty::HtmlReflection,
                    reflection_slug(classify_observation_reflection(
                        observation,
                        self.redirect
                            .as_ref()
                            .expect("enabled redirect observer retains its bounded contract")
                            .candidate_value
                            .as_str(),
                    )),
                ),
            ]),
        }
        records
    }
}

// This tiny extension avoids exposing requested-URL comparison outside the
// observer while keeping the validation expression readable.
trait ObservationUrlContract {
    fn expected_url_mismatch(&self, expected: Option<&Url>) -> bool;
}

impl ObservationUrlContract for CompleteHttpResponseObservation<'_> {
    fn expected_url_mismatch(&self, expected: Option<&Url>) -> bool {
        expected.is_none_or(|expected| self.requested_url() != expected)
    }
}

impl CompleteHttpResponseObserver for AssessmentReviewObserverSet {
    fn observe(
        &self,
        observation: CompleteHttpResponseObservation<'_>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let Some(kind) = NativeWebReviewActionKind::all()
            .into_iter()
            .find(|kind| observation.action_id() == kind.action_id())
        else {
            return Ok(Vec::new());
        };
        self.validate_recognized(kind, &observation)?;

        let parents = review_projection_parents(&observation, kind)?;
        let derivation = EvidenceDerivation::new(
            parents,
            DerivationAlgorithm::new(
                ASSESSMENT_REVIEW_ALGORITHM,
                ASSESSMENT_REVIEW_ALGORITHM_VERSION,
            )?,
        )?;
        let source = EvidenceSource::new(
            kind.executor_id(),
            review_source_method(kind, observation.stage()),
        )?
        .with_correlation_id(observation.case_id())?;
        self.project(kind, &observation)
            .into_iter()
            .map(|(property, value)| {
                Ok(Evidence::new(
                    observation.subject().clone(),
                    EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned()),
                    property.predicate(),
                    EvidenceValue::Text(value.to_owned()),
                    source.clone(),
                    observation.reliability(),
                )
                .derived_from(derivation.clone()))
            })
            .collect()
    }
}

fn review_root_subject(root: &Url) -> Result<EntityId, AssessmentReviewObserverError> {
    if !matches!(root.scheme(), "http" | "https")
        || root.query().is_some()
        || root.fragment().is_some()
        || !root.username().is_empty()
        || root.password().is_some()
        || root.host_str().is_none()
    {
        return Err(AssessmentReviewObserverError::Root);
    }
    EntityId::new(format!("endpoint:{root}")).map_err(|_| AssessmentReviewObserverError::Root)
}

fn valid_query_parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REVIEW_QUERY_PARAMETER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn validate_external_candidate(value: &str) -> Result<(), AssessmentReviewObserverError> {
    if value.is_empty() || value.len() > MAX_REVIEW_CANDIDATE_BYTES {
        return Err(AssessmentReviewObserverError::Candidate);
    }
    let limits = PayloadStrategyLimits::default();
    let seed = PayloadSeed::new(value.as_bytes().to_vec(), limits)
        .map_err(|_| AssessmentReviewObserverError::Candidate)?;
    ExternalUrlQueryPairStrategy::new()
        .derive_one(PayloadVariantRole::Candidate, &seed, limits)
        .map(|_| ())
        .map_err(|_| AssessmentReviewObserverError::Candidate)
}

fn native_review_strategy_ref(kind: NativeWebReviewActionKind) -> PayloadStrategyRef {
    let (id, revision) = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => {
            (CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            (EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
        },
    };
    PayloadStrategyRef::new(id, revision)
        .expect("native review strategies have valid static references")
}

fn review_projection_parents(
    observation: &CompleteHttpResponseObservation<'_>,
    kind: NativeWebReviewActionKind,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    let mut parents = [
        (
            observation.request_method_evidence_id(),
            "native-review-request-method-evidence",
        ),
        (
            observation.request_url_evidence_id(),
            "native-review-request-url-evidence",
        ),
        (
            observation.response_status_evidence_id(),
            "native-review-response-status-evidence",
        ),
        (
            observation.response_final_url_evidence_id(),
            "native-review-response-final-url-evidence",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect::<Result<Vec<_>, _>>()?;
    if kind == NativeWebReviewActionKind::RedirectReflectionQueryPair {
        if observation.media_type().is_some() {
            parents.push(
                observation
                    .response_media_type_evidence_id()
                    .cloned()
                    .ok_or(HttpEvidenceError::AssessmentObserverInvariant {
                        invariant: "native-review-response-media-type-evidence",
                    })?,
            );
        }
        parents.extend([
            observation
                .response_body_truncated_evidence_id()
                .cloned()
                .ok_or(HttpEvidenceError::AssessmentObserverInvariant {
                    invariant: "native-review-response-body-truncation-evidence",
                })?,
            observation
                .response_body_digest_evidence_id()
                .cloned()
                .ok_or(HttpEvidenceError::AssessmentObserverInvariant {
                    invariant: "native-review-response-body-digest-evidence",
                })?,
        ]);
    }
    Ok(parents)
}

fn classify_observation_reflection(
    observation: &CompleteHttpResponseObservation<'_>,
    candidate: &str,
) -> ExactHtmlReflectionContext {
    match observation.media_type() {
        Some("text/html") => {},
        Some(_) => return ExactHtmlReflectionContext::NotApplicable,
        None => return ExactHtmlReflectionContext::Incomplete,
    }
    let Some(body) = observation.complete_body() else {
        return ExactHtmlReflectionContext::Incomplete;
    };
    let Ok(html) = std::str::from_utf8(body) else {
        return ExactHtmlReflectionContext::Incomplete;
    };
    classify_exact_html_reflection(html, candidate)
}

fn review_source_method(
    kind: NativeWebReviewActionKind,
    stage: DecisionExecutionStage,
) -> &'static str {
    match (kind, stage) {
        (NativeWebReviewActionKind::CorsPolicyPair, DecisionExecutionStage::Passive) => {
            "cors-control-response"
        },
        (NativeWebReviewActionKind::CorsPolicyPair, DecisionExecutionStage::Active) => {
            "cors-candidate-response"
        },
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Passive,
        ) => "redirect-reflection-control-response",
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Active,
        ) => "redirect-reflection-candidate-response",
    }
}

fn cors_allow_origin_slug(relation: CorsAllowOriginRelation) -> &'static str {
    match relation {
        CorsAllowOriginRelation::Missing => "missing",
        CorsAllowOriginRelation::ExactRequestOrigin => "exact-request-origin",
        CorsAllowOriginRelation::Wildcard => "wildcard",
        CorsAllowOriginRelation::Other => "other",
        CorsAllowOriginRelation::InvalidOrMultiple => "invalid-or-multiple",
    }
}

fn cors_allow_credentials_slug(relation: CorsAllowCredentialsRelation) -> &'static str {
    match relation {
        CorsAllowCredentialsRelation::Missing => "missing",
        CorsAllowCredentialsRelation::True => "true",
        CorsAllowCredentialsRelation::Other => "other",
        CorsAllowCredentialsRelation::InvalidOrMultiple => "invalid-or-multiple",
    }
}

fn vary_origin_slug(relation: VaryOriginRelation) -> &'static str {
    match relation {
        VaryOriginRelation::Missing => "missing",
        VaryOriginRelation::ContainsOrigin => "contains-origin",
        VaryOriginRelation::Wildcard => "wildcard",
        VaryOriginRelation::Other => "other",
        VaryOriginRelation::Invalid => "invalid",
    }
}

const fn classify_http_status(status: u16) -> ReviewHttpStatusClass {
    match status {
        100..=199 => ReviewHttpStatusClass::Informational,
        200..=299 => ReviewHttpStatusClass::Successful,
        300..=399 => ReviewHttpStatusClass::Redirection,
        400..=499 => ReviewHttpStatusClass::ClientError,
        500..=599 => ReviewHttpStatusClass::ServerError,
        _ => ReviewHttpStatusClass::Other,
    }
}

const fn http_status_class_slug(status: ReviewHttpStatusClass) -> &'static str {
    match status {
        ReviewHttpStatusClass::Informational => "informational",
        ReviewHttpStatusClass::Successful => "successful",
        ReviewHttpStatusClass::Redirection => "redirection",
        ReviewHttpStatusClass::ClientError => "client-error",
        ReviewHttpStatusClass::ServerError => "server-error",
        ReviewHttpStatusClass::Other => "other",
    }
}

const fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn location_slug(relation: LocationRelation) -> &'static str {
    match relation {
        LocationRelation::Missing => "missing",
        LocationRelation::ExactExternalQueryValue => "exact-external-query-value",
        LocationRelation::Other => "other",
        LocationRelation::InvalidOrMultiple => "invalid-or-multiple",
    }
}

fn reflection_slug(context: ExactHtmlReflectionContext) -> &'static str {
    match context {
        ExactHtmlReflectionContext::Absent => "absent",
        ExactHtmlReflectionContext::Inert => "inert",
        ExactHtmlReflectionContext::Text => "text",
        ExactHtmlReflectionContext::Attribute => "attribute",
        ExactHtmlReflectionContext::Dangerous => "dangerous",
        ExactHtmlReflectionContext::NotApplicable => "not-applicable",
        ExactHtmlReflectionContext::Incomplete => "incomplete",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReviewProperty {
    ResponseMarker,
    CorsHttpStatusClass,
    CorsAllowOrigin,
    CorsAllowCredentials,
    CorsVaryOrigin,
    RedirectStatus,
    RedirectLocation,
    HtmlReflection,
}

impl ReviewProperty {
    const fn name(self) -> &'static str {
        match self {
            Self::ResponseMarker => NATIVE_WEB_REVIEW_RESPONSE_MARKER,
            Self::CorsHttpStatusClass => CORS_HTTP_STATUS_CLASS,
            Self::CorsAllowOrigin => CORS_ALLOW_ORIGIN_RELATION,
            Self::CorsAllowCredentials => CORS_ALLOW_CREDENTIALS_RELATION,
            Self::CorsVaryOrigin => CORS_VARY_ORIGIN_RELATION,
            Self::RedirectStatus => REDIRECT_STATUS_RELATION,
            Self::RedirectLocation => REDIRECT_LOCATION_RELATION,
            Self::HtmlReflection => HTML_REFLECTION_CONTEXT,
        }
    }

    fn predicate(self) -> KnowledgePredicate {
        KnowledgePredicate::new(NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE, self.name())
            .expect("native review properties have valid static identities")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewStatusRelation {
    Redirect,
    Other,
}

/// Fixed-vocabulary HTTP response class retained for CORS pair comparison.
///
/// Exact status values are deliberately not copied into native-review
/// evidence. Only two successful legs can establish the one product-facing
/// relationship; a generic error response never strengthens a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewHttpStatusClass {
    Informational,
    Successful,
    Redirection,
    ClientError,
    ServerError,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommittedReviewResponse {
    Cors {
        status: ReviewHttpStatusClass,
        allow_origin: CorsAllowOriginRelation,
        allow_credentials: CorsAllowCredentialsRelation,
        vary_origin: VaryOriginRelation,
    },
    RedirectReflection {
        status: ReviewStatusRelation,
        location: LocationRelation,
        reflection: ExactHtmlReflectionContext,
    },
}

/// One response reconstructed from exact committed value-free evidence.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentReviewObservation {
    kind: NativeWebReviewActionKind,
    subject: EntityId,
    case_id: String,
    hypothesis_id: String,
    stage: DecisionExecutionStage,
    response: CommittedReviewResponse,
    evidence_ids: Vec<EvidenceId>,
    property_evidence: BTreeMap<ReviewProperty, EvidenceId>,
    active_pair_success: bool,
}

impl fmt::Debug for CommittedAssessmentReviewObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAssessmentReviewObservation")
            .field("kind", &self.kind)
            .field("subject", &"<redacted>")
            .field("case_id", &"<redacted>")
            .field("hypothesis_id", &"<redacted>")
            .field("stage", &self.stage)
            .field("response", &self.response)
            .field("evidence_count", &self.evidence_ids.len())
            .field("active_pair_success", &self.active_pair_success)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReviewReceiptKey {
    kind: NativeWebReviewActionKind,
    case_id: String,
    stage: DecisionExecutionStage,
}

/// Fail-closed committed receipt replay reason. The variants intentionally
/// carry no response, URL, credential, or candidate text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum AssessmentReviewLedgerError {
    #[error("native review receipt authority was invalid")]
    ReceiptAuthority,
    #[error("native review receipt evidence was not committed exactly")]
    EvidenceCommit,
    #[error("native review evidence projection was malformed")]
    EvidenceProjection,
    #[error("native review verifier proof was invalid")]
    VerifierProof,
    #[error("native review ledger capacity was exhausted")]
    Capacity,
    #[error("native review receipt replay conflicted with an earlier record")]
    ReplayConflict,
}

/// Bounded assessment-owned ledger for the two native review pairs.
#[derive(PartialEq, Eq)]
pub(crate) struct CommittedAssessmentReviewLedger {
    root: Url,
    subject: EntityId,
    seeds: NativeWebReviewSeeds,
    redirect: Option<RedirectReflectionContract>,
    observations: BTreeMap<ReviewReceiptKey, CommittedAssessmentReviewObservation>,
}

impl fmt::Debug for CommittedAssessmentReviewLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAssessmentReviewLedger")
            .field("root", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("seeds", &self.seeds)
            .field("redirect", &self.redirect.as_ref().map(|_| "<configured>"))
            .field("observation_count", &self.observations.len())
            .finish()
    }
}

impl CommittedAssessmentReviewLedger {
    pub(crate) fn new(
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<&str>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let observer = AssessmentReviewObserverSet::new(root, seeds, redirect_query_parameter)?;
        Ok(Self {
            root: observer.root,
            subject: observer.subject,
            seeds: observer.seeds,
            redirect: observer.redirect,
            observations: BTreeMap::new(),
        })
    }

    pub(crate) fn observations(
        &self,
    ) -> impl ExactSizeIterator<Item = &CommittedAssessmentReviewObservation> {
        self.observations.values()
    }

    /// Returns whether an enabled HTML-reflection leg could not be classified
    /// within its complete-body, UTF-8, DOM, or occurrence boundary.
    pub(crate) fn has_incomplete_reflection_observation(&self) -> bool {
        self.observations.values().any(|observation| {
            matches!(
                observation.response,
                CommittedReviewResponse::RedirectReflection {
                    reflection: ExactHtmlReflectionContext::Incomplete,
                    ..
                }
            )
        })
    }

    /// Returns whether this ledger contains exactly one case-correlated,
    /// evidence-disjoint control/candidate pair for the requested capability.
    pub(crate) fn pair_is_complete(&self, kind: NativeWebReviewActionKind) -> bool {
        let mut controls = self.observations.values().filter(|observation| {
            observation.kind == kind && observation.stage == DecisionExecutionStage::Passive
        });
        let Some(control) = controls.next() else {
            return false;
        };
        if controls.next().is_some() {
            return false;
        }

        let mut candidates = self.observations.values().filter(|observation| {
            observation.kind == kind && observation.stage == DecisionExecutionStage::Active
        });
        let Some(candidate) = candidates.next() else {
            return false;
        };
        candidates.next().is_none() && observations_form_exact_pair(control, candidate)
    }

    /// Replays one outcome only after both its receipt batch and verifier audit
    /// are validated against the authoritative knowledge store.
    pub(crate) fn ingest_outcome(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        decision: &DecisionOutcomeReport,
        knowledge: &KnowledgeBase,
    ) -> Result<Option<&CommittedAssessmentReviewObservation>, AssessmentReviewLedgerError> {
        let kind = review_kind(receipt.case().action_id())
            .ok_or(AssessmentReviewLedgerError::ReceiptAuthority)?;
        validate_receipt_authority(
            receipt,
            decision,
            &self.root,
            &self.subject,
            self.redirect.as_ref(),
            kind,
        )?;
        validate_committed_batch(receipt, knowledge)?;
        let mut parsed = parse_review_receipt(receipt, &self.root, self.redirect.as_ref(), kind)?;
        parsed.active_pair_success =
            validate_verifier_proof(receipt, decision, knowledge, &parsed)?;
        let key = ReviewReceiptKey {
            kind,
            case_id: receipt.case().id().to_owned(),
            stage: receipt.stage(),
        };
        if let Some(existing) = self.observations.get(&key) {
            return if existing == &parsed {
                Ok(None)
            } else {
                Err(AssessmentReviewLedgerError::ReplayConflict)
            };
        }
        if self.observations.len() >= MAX_REVIEW_OBSERVATIONS {
            return Err(AssessmentReviewLedgerError::Capacity);
        }
        self.observations.insert(key.clone(), parsed);
        Ok(self.observations.get(&key))
    }

    /// Returns only matched pairs that satisfy their closed claim boundary.
    /// There is deliberately no `Confirmed` candidate variant.
    pub(crate) fn candidates(&self) -> Vec<AssessmentReviewCandidate> {
        let mut candidates = Vec::new();
        for kind in NativeWebReviewActionKind::all() {
            let passive = self
                .observations
                .values()
                .filter(|item| item.kind == kind && item.stage == DecisionExecutionStage::Passive);
            for control in passive {
                let Some(candidate) = self.observations.values().find(|item| {
                    item.kind == kind
                        && item.stage == DecisionExecutionStage::Active
                        && item.case_id == control.case_id
                        && item.hypothesis_id == control.hypothesis_id
                        && item.subject == control.subject
                }) else {
                    continue;
                };
                append_pair_candidates(
                    control,
                    candidate,
                    self.redirect
                        .as_ref()
                        .map(|contract| contract.query_parameter.as_str()),
                    &mut candidates,
                );
            }
        }
        candidates
    }
}

fn validate_receipt_authority(
    receipt: &DecisionEvidenceReceipt,
    decision: &DecisionOutcomeReport,
    root: &Url,
    subject: &EntityId,
    redirect: Option<&RedirectReflectionContract>,
    kind: NativeWebReviewActionKind,
) -> Result<(), AssessmentReviewLedgerError> {
    let case = receipt.case();
    let verification = decision.verification();
    let outcome = verification.outcome();
    if receipt.executor_id() != kind.executor_id()
        || case.subject() != subject
        || case.action_id() != kind.action_id()
        || case.payload_strategy() != Some(&native_review_strategy_ref(kind))
        || case.applies_hypothesis_transition()
        || case.id().is_empty()
        || case.hypothesis_id().is_empty()
        || verification.case() != case
        || outcome.case_id() != case.id()
        || outcome.subject() != case.subject()
        || outcome.action_id() != case.action_id()
        || outcome.hypothesis_id() != case.hypothesis_id()
        || decision.hypothesis_write().is_some()
        || receipt.evidence().len() != receipt.writes().len()
        || !execution_and_verification_stage_match(receipt.stage(), verification.stage())
        || verification.stage() != outcome.stage()
        || !receipt_url_matches_contract(receipt, root, redirect, kind)
    {
        return Err(AssessmentReviewLedgerError::ReceiptAuthority);
    }
    Ok(())
}

fn validate_committed_batch(
    receipt: &DecisionEvidenceReceipt,
    knowledge: &KnowledgeBase,
) -> Result<(), AssessmentReviewLedgerError> {
    for (evidence, write) in receipt.write_set() {
        if !matches!(write, KnowledgeWrite::Inserted | KnowledgeWrite::Unchanged)
            || evidence.subject() != receipt.case().subject()
            || evidence.source().component() != receipt.executor_id()
            || evidence.source().correlation_id() != Some(receipt.case().id())
            || knowledge.evidence(evidence.id()).as_ref() != Some(evidence)
        {
            return Err(AssessmentReviewLedgerError::EvidenceCommit);
        }
    }
    Ok(())
}

fn parse_review_receipt(
    receipt: &DecisionEvidenceReceipt,
    root: &Url,
    redirect: Option<&RedirectReflectionContract>,
    kind: NativeWebReviewActionKind,
) -> Result<CommittedAssessmentReviewObservation, AssessmentReviewLedgerError> {
    let expected = expected_properties(kind);
    let review = receipt
        .evidence()
        .iter()
        .filter(|item| item.predicate().namespace() == NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE)
        .collect::<Vec<_>>();
    if receipt.evidence().iter().any(|item| {
        item.predicate().namespace().starts_with("web.review")
            && item.predicate().namespace() != NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE
    }) || review.len() != expected.len()
    {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }

    let parents = expected_review_parent_ids(receipt, root, redirect, kind)?;
    let source_method = review_source_method(kind, receipt.stage());
    let mut property_evidence = BTreeMap::new();
    let mut values = BTreeMap::new();
    let mut evidence_ids = Vec::with_capacity(review.len());
    for (index, (item, property)) in review.iter().zip(expected.iter().copied()).enumerate() {
        if item.predicate().name() != property.name()
            || item.kind() != &EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned())
            || item.source().component() != kind.executor_id()
            || item.source().method() != source_method
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.subject() != receipt.case().subject()
            || property_evidence
                .insert(property, item.id().clone())
                .is_some()
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        let EvidenceOrigin::Derived(derivation) = item.origin() else {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        };
        if derivation.algorithm().name() != ASSESSMENT_REVIEW_ALGORITHM
            || derivation.algorithm().version() != ASSESSMENT_REVIEW_ALGORITHM_VERSION
            || derivation.parents() != parents
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        let EvidenceValue::Text(value) = item.value() else {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        };
        if index == 0 && value != stage_marker(receipt.stage()) {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        values.insert(property, value.as_str());
        evidence_ids.push(item.id().clone());
    }

    let response = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => CommittedReviewResponse::Cors {
            status: parse_http_status_class(value(&values, ReviewProperty::CorsHttpStatusClass)?)?,
            allow_origin: parse_cors_allow_origin(value(
                &values,
                ReviewProperty::CorsAllowOrigin,
            )?)?,
            allow_credentials: parse_cors_allow_credentials(value(
                &values,
                ReviewProperty::CorsAllowCredentials,
            )?)?,
            vary_origin: parse_vary_origin(value(&values, ReviewProperty::CorsVaryOrigin)?)?,
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            CommittedReviewResponse::RedirectReflection {
                status: parse_status_relation(value(&values, ReviewProperty::RedirectStatus)?)?,
                location: parse_location(value(&values, ReviewProperty::RedirectLocation)?)?,
                reflection: parse_reflection(value(&values, ReviewProperty::HtmlReflection)?)?,
            }
        },
    };
    Ok(CommittedAssessmentReviewObservation {
        kind,
        subject: receipt.case().subject().clone(),
        case_id: receipt.case().id().to_owned(),
        hypothesis_id: receipt.case().hypothesis_id().to_owned(),
        stage: receipt.stage(),
        response,
        evidence_ids,
        property_evidence,
        active_pair_success: false,
    })
}

fn validate_verifier_proof(
    receipt: &DecisionEvidenceReceipt,
    decision: &DecisionOutcomeReport,
    knowledge: &KnowledgeBase,
    parsed: &CommittedAssessmentReviewObservation,
) -> Result<bool, AssessmentReviewLedgerError> {
    let verification = decision.verification();
    let outcome = verification.outcome();
    match receipt.stage() {
        DecisionExecutionStage::Passive => {
            if outcome.status() != OutcomeStatus::Unknown
                || outcome.verifier_rule_id().is_some()
                || !outcome.evidence_ids().is_empty()
                || verification
                    .evaluations()
                    .iter()
                    .any(|evaluation| evaluation.selected())
            {
                return Err(AssessmentReviewLedgerError::VerifierProof);
            }
            Ok(false)
        },
        DecisionExecutionStage::Active => {
            let selected = verification
                .evaluations()
                .iter()
                .filter(|evaluation| evaluation.selected())
                .collect::<Vec<_>>();
            let marker = parsed
                .property_evidence
                .get(&ReviewProperty::ResponseMarker)
                .ok_or(AssessmentReviewLedgerError::VerifierProof)?;
            if outcome.status() != OutcomeStatus::Success
                || outcome.verifier_rule_id()
                    != Some(native_review_active_verifier_rule_id(parsed.kind))
                || selected.len() != 1
                || selected[0].rule_id() != native_review_active_verifier_rule_id(parsed.kind)
                || selected[0].stage() != VerificationStage::Active
                || !selected[0].action_matched()
                || !selected[0].eligible()
                || selected[0].condition().evidence_ids() != outcome.evidence_ids()
                || selected[0].fresh_evidence_ids().is_empty()
                || !selected[0].fresh_evidence_ids().contains(marker)
                || !selected[0]
                    .fresh_evidence_ids()
                    .is_subset(outcome.evidence_ids())
            {
                return Err(AssessmentReviewLedgerError::VerifierProof);
            }
            for id in outcome.evidence_ids() {
                let committed = knowledge
                    .evidence(id)
                    .ok_or(AssessmentReviewLedgerError::VerifierProof)?;
                if committed.subject() != receipt.case().subject()
                    || committed.source().correlation_id() != Some(receipt.case().id())
                {
                    return Err(AssessmentReviewLedgerError::VerifierProof);
                }
            }
            for id in selected[0].fresh_evidence_ids() {
                let receipt_item = receipt.evidence().iter().find(|item| item.id() == id);
                let committed = knowledge.evidence(id);
                if receipt_item.is_none()
                    || committed.as_ref() != receipt_item
                    || receipt_item.is_some_and(|item| {
                        item.subject() != receipt.case().subject()
                            || item.source().correlation_id() != Some(receipt.case().id())
                    })
                {
                    return Err(AssessmentReviewLedgerError::VerifierProof);
                }
            }
            Ok(true)
        },
    }
}

fn expected_review_parent_ids(
    receipt: &DecisionEvidenceReceipt,
    root: &Url,
    redirect: Option<&RedirectReflectionContract>,
    kind: NativeWebReviewActionKind,
) -> Result<Vec<EvidenceId>, AssessmentReviewLedgerError> {
    let method = unique_base(receipt, HttpEvidencePredicate::REQUEST_METHOD)?;
    let requested = unique_base(receipt, HttpEvidencePredicate::REQUEST_URL)?;
    let status = unique_base(receipt, HttpEvidencePredicate::RESPONSE_STATUS)?;
    let final_url = unique_base(receipt, HttpEvidencePredicate::RESPONSE_FINAL_URL)?;
    if method.value() != &EvidenceValue::Text("GET".to_owned())
        || !requested_url_value_matches(requested.value(), root, redirect, receipt.stage(), kind)
        || status_u16(status.value()).is_none()
        || requested.value() != final_url.value()
    {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }
    let mut items = vec![method, requested, status, final_url];
    if kind == NativeWebReviewActionKind::RedirectReflectionQueryPair {
        let media = optional_unique_base(receipt, HttpEvidencePredicate::RESPONSE_MEDIA_TYPE)?;
        if let Some(media) = media {
            if !matches!(media.value(), EvidenceValue::Text(value) if !value.is_empty()) {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            items.push(media);
        }
        let truncated = unique_base(receipt, HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED)?;
        let digest = unique_base(receipt, HttpEvidencePredicate::RESPONSE_BODY_SHA256)?;
        if !matches!(truncated.value(), EvidenceValue::Boolean(_))
            || !matches!(digest.value(), EvidenceValue::Text(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        items.extend([truncated, digest]);
    }
    let reliability = items[0].reliability();
    for item in &items {
        if item.kind() == &EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned())
            || item.subject() != receipt.case().subject()
            || item.source().component() != receipt.executor_id()
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.reliability() != reliability
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
    }
    let mut ids = items
        .into_iter()
        .map(|item| item.id().clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn unique_base(
    receipt: &DecisionEvidenceReceipt,
    predicate: venom_core::PredicateDescriptor,
) -> Result<&Evidence, AssessmentReviewLedgerError> {
    optional_unique_base(receipt, predicate)?.ok_or(AssessmentReviewLedgerError::EvidenceProjection)
}

fn optional_unique_base(
    receipt: &DecisionEvidenceReceipt,
    predicate: venom_core::PredicateDescriptor,
) -> Result<Option<&Evidence>, AssessmentReviewLedgerError> {
    let predicate = predicate.into_knowledge();
    let mut matches = receipt
        .evidence()
        .iter()
        .filter(|item| item.predicate() == &predicate);
    let first = matches.next();
    if matches.next().is_some() {
        Err(AssessmentReviewLedgerError::EvidenceProjection)
    } else {
        Ok(first)
    }
}

fn receipt_url_matches_contract(
    receipt: &DecisionEvidenceReceipt,
    root: &Url,
    redirect: Option<&RedirectReflectionContract>,
    kind: NativeWebReviewActionKind,
) -> bool {
    unique_base(receipt, HttpEvidencePredicate::REQUEST_URL)
        .ok()
        .is_some_and(|evidence| {
            requested_url_value_matches(evidence.value(), root, redirect, receipt.stage(), kind)
        })
}

fn requested_url_value_matches(
    value: &EvidenceValue,
    root: &Url,
    redirect: Option<&RedirectReflectionContract>,
    stage: DecisionExecutionStage,
    kind: NativeWebReviewActionKind,
) -> bool {
    let EvidenceValue::Text(value) = value else {
        return false;
    };
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    match (kind, stage) {
        (NativeWebReviewActionKind::CorsPolicyPair, _) => &url == root,
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Passive,
        ) => redirect.is_some() && &url == root,
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Active,
        ) => redirect.is_some_and(|contract| url == contract.candidate_url),
    }
}

fn execution_and_verification_stage_match(
    execution: DecisionExecutionStage,
    verification: VerificationStage,
) -> bool {
    matches!(
        (execution, verification),
        (DecisionExecutionStage::Passive, VerificationStage::Passive)
            | (DecisionExecutionStage::Active, VerificationStage::Active)
    )
}

fn review_kind(action_id: &str) -> Option<NativeWebReviewActionKind> {
    NativeWebReviewActionKind::all()
        .into_iter()
        .find(|kind| kind.action_id() == action_id)
}

const CORS_REVIEW_PROPERTIES: [ReviewProperty; 5] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::CorsHttpStatusClass,
    ReviewProperty::CorsAllowOrigin,
    ReviewProperty::CorsAllowCredentials,
    ReviewProperty::CorsVaryOrigin,
];

const REDIRECT_REVIEW_PROPERTIES: [ReviewProperty; 4] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::RedirectStatus,
    ReviewProperty::RedirectLocation,
    ReviewProperty::HtmlReflection,
];

fn expected_properties(kind: NativeWebReviewActionKind) -> &'static [ReviewProperty] {
    match kind {
        NativeWebReviewActionKind::CorsPolicyPair => &CORS_REVIEW_PROPERTIES,
        NativeWebReviewActionKind::RedirectReflectionQueryPair => &REDIRECT_REVIEW_PROPERTIES,
    }
}

fn value<'a>(
    values: &'a BTreeMap<ReviewProperty, &'a str>,
    property: ReviewProperty,
) -> Result<&'a str, AssessmentReviewLedgerError> {
    values
        .get(&property)
        .copied()
        .ok_or(AssessmentReviewLedgerError::EvidenceProjection)
}

fn stage_marker(stage: DecisionExecutionStage) -> &'static str {
    match stage {
        DecisionExecutionStage::Passive => "passive-control",
        DecisionExecutionStage::Active => "active-candidate",
    }
}

fn parse_cors_allow_origin(
    value: &str,
) -> Result<CorsAllowOriginRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(CorsAllowOriginRelation::Missing),
        "exact-request-origin" => Ok(CorsAllowOriginRelation::ExactRequestOrigin),
        "wildcard" => Ok(CorsAllowOriginRelation::Wildcard),
        "other" => Ok(CorsAllowOriginRelation::Other),
        "invalid-or-multiple" => Ok(CorsAllowOriginRelation::InvalidOrMultiple),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_cors_allow_credentials(
    value: &str,
) -> Result<CorsAllowCredentialsRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(CorsAllowCredentialsRelation::Missing),
        "true" => Ok(CorsAllowCredentialsRelation::True),
        "other" => Ok(CorsAllowCredentialsRelation::Other),
        "invalid-or-multiple" => Ok(CorsAllowCredentialsRelation::InvalidOrMultiple),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_vary_origin(value: &str) -> Result<VaryOriginRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(VaryOriginRelation::Missing),
        "contains-origin" => Ok(VaryOriginRelation::ContainsOrigin),
        "wildcard" => Ok(VaryOriginRelation::Wildcard),
        "other" => Ok(VaryOriginRelation::Other),
        "invalid" => Ok(VaryOriginRelation::Invalid),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_status_relation(value: &str) -> Result<ReviewStatusRelation, AssessmentReviewLedgerError> {
    match value {
        "redirect" => Ok(ReviewStatusRelation::Redirect),
        "other" => Ok(ReviewStatusRelation::Other),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_http_status_class(
    value: &str,
) -> Result<ReviewHttpStatusClass, AssessmentReviewLedgerError> {
    match value {
        "informational" => Ok(ReviewHttpStatusClass::Informational),
        "successful" => Ok(ReviewHttpStatusClass::Successful),
        "redirection" => Ok(ReviewHttpStatusClass::Redirection),
        "client-error" => Ok(ReviewHttpStatusClass::ClientError),
        "server-error" => Ok(ReviewHttpStatusClass::ServerError),
        "other" => Ok(ReviewHttpStatusClass::Other),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_location(value: &str) -> Result<LocationRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(LocationRelation::Missing),
        "exact-external-query-value" => Ok(LocationRelation::ExactExternalQueryValue),
        "other" => Ok(LocationRelation::Other),
        "invalid-or-multiple" => Ok(LocationRelation::InvalidOrMultiple),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_reflection(
    value: &str,
) -> Result<ExactHtmlReflectionContext, AssessmentReviewLedgerError> {
    match value {
        "absent" => Ok(ExactHtmlReflectionContext::Absent),
        "inert" => Ok(ExactHtmlReflectionContext::Inert),
        "text" => Ok(ExactHtmlReflectionContext::Text),
        "attribute" => Ok(ExactHtmlReflectionContext::Attribute),
        "dangerous" => Ok(ExactHtmlReflectionContext::Dangerous),
        "not-applicable" => Ok(ExactHtmlReflectionContext::NotApplicable),
        "incomplete" => Ok(ExactHtmlReflectionContext::Incomplete),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn status_u16(value: &EvidenceValue) -> Option<u16> {
    let EvidenceValue::Unsigned(value) = value else {
        return None;
    };
    u16::try_from(*value).ok()
}

/// Strongest product disposition a native review candidate can request.
/// Confirmation is intentionally not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeReviewDisposition {
    Informational,
    NeedsReview,
}

/// Closed CORS control/candidate status relationship admitted to projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorsStatusRelationship {
    MatchedSuccessful,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CorsReviewCandidate {
    subject: EntityId,
    case_id: String,
    status_relationship: CorsStatusRelationship,
    vary_origin: VaryOriginRelation,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RedirectReviewCandidate {
    subject: EntityId,
    case_id: String,
    query_parameter: String,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewReflectionContext {
    Inert,
    Text,
    Attribute,
    Dangerous,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReflectionReviewCandidate {
    subject: EntityId,
    case_id: String,
    query_parameter: String,
    context: ReviewReflectionContext,
    disposition: NativeReviewDisposition,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

/// Typed output from the matched-pair ledger. No variant can assert a
/// confirmed vulnerability.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AssessmentReviewCandidate {
    Cors(CorsReviewCandidate),
    Redirect(RedirectReviewCandidate),
    Reflection(ReflectionReviewCandidate),
}

macro_rules! redacted_candidate_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($name)
                    .field("subject", &"<redacted>")
                    .field("case_id", &"<redacted>")
                    .field("control_evidence_count", &self.control_evidence_ids.len())
                    .field(
                        "candidate_evidence_count",
                        &self.candidate_evidence_ids.len(),
                    )
                    .finish()
            }
        }
    };
}

redacted_candidate_debug!(CorsReviewCandidate, "CorsReviewCandidate");
redacted_candidate_debug!(RedirectReviewCandidate, "RedirectReviewCandidate");

impl fmt::Debug for ReflectionReviewCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReflectionReviewCandidate")
            .field("subject", &"<redacted>")
            .field("case_id", &"<redacted>")
            .field("context", &self.context)
            .field("disposition", &self.disposition)
            .field("control_evidence_count", &self.control_evidence_ids.len())
            .field(
                "candidate_evidence_count",
                &self.candidate_evidence_ids.len(),
            )
            .finish()
    }
}

impl fmt::Debug for AssessmentReviewCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cors(value) => value.fmt(formatter),
            Self::Redirect(value) => value.fmt(formatter),
            Self::Reflection(value) => value.fmt(formatter),
        }
    }
}

impl AssessmentReviewCandidate {
    pub(crate) const fn disposition(&self) -> NativeReviewDisposition {
        match self {
            Self::Cors(_) | Self::Redirect(_) => NativeReviewDisposition::NeedsReview,
            Self::Reflection(candidate) => candidate.disposition,
        }
    }

    pub(crate) fn subject(&self) -> &EntityId {
        match self {
            Self::Cors(candidate) => &candidate.subject,
            Self::Redirect(candidate) => &candidate.subject,
            Self::Reflection(candidate) => &candidate.subject,
        }
    }

    pub(crate) fn control_evidence_ids(&self) -> &[EvidenceId] {
        match self {
            Self::Cors(candidate) => &candidate.control_evidence_ids,
            Self::Redirect(candidate) => &candidate.control_evidence_ids,
            Self::Reflection(candidate) => &candidate.control_evidence_ids,
        }
    }

    pub(crate) fn candidate_evidence_ids(&self) -> &[EvidenceId] {
        match self {
            Self::Cors(candidate) => &candidate.candidate_evidence_ids,
            Self::Redirect(candidate) => &candidate.candidate_evidence_ids,
            Self::Reflection(candidate) => &candidate.candidate_evidence_ids,
        }
    }

    pub(crate) const fn reflection_context(&self) -> Option<ReviewReflectionContext> {
        match self {
            Self::Reflection(candidate) => Some(candidate.context),
            Self::Cors(_) | Self::Redirect(_) => None,
        }
    }

    /// Returns the only status relationship permitted for a CORS review item.
    pub(crate) const fn cors_status_relationship(&self) -> Option<CorsStatusRelationship> {
        match self {
            Self::Cors(candidate) => Some(candidate.status_relationship),
            Self::Redirect(_) | Self::Reflection(_) => None,
        }
    }

    pub(crate) fn query_parameter(&self) -> Option<&str> {
        match self {
            Self::Redirect(candidate) => Some(&candidate.query_parameter),
            Self::Reflection(candidate) => Some(&candidate.query_parameter),
            Self::Cors(_) => None,
        }
    }
}

fn append_pair_candidates(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
    redirect_query_parameter: Option<&str>,
    output: &mut Vec<AssessmentReviewCandidate>,
) {
    if !observations_form_exact_pair(control, candidate) {
        return;
    }
    match (control.response, candidate.response) {
        (
            CommittedReviewResponse::Cors {
                status: ReviewHttpStatusClass::Successful,
                allow_origin: CorsAllowOriginRelation::Missing,
                ..
            },
            CommittedReviewResponse::Cors {
                status: ReviewHttpStatusClass::Successful,
                allow_origin: CorsAllowOriginRelation::ExactRequestOrigin,
                allow_credentials: CorsAllowCredentialsRelation::True,
                vary_origin,
            },
        ) => output.push(AssessmentReviewCandidate::Cors(CorsReviewCandidate {
            subject: control.subject.clone(),
            case_id: control.case_id.clone(),
            status_relationship: CorsStatusRelationship::MatchedSuccessful,
            vary_origin,
            control_evidence_ids: ids_for(
                control,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::CorsHttpStatusClass,
                    ReviewProperty::CorsAllowOrigin,
                ],
            ),
            candidate_evidence_ids: ids_for(
                candidate,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::CorsHttpStatusClass,
                    ReviewProperty::CorsAllowOrigin,
                    ReviewProperty::CorsAllowCredentials,
                    ReviewProperty::CorsVaryOrigin,
                ],
            ),
        })),
        (
            CommittedReviewResponse::RedirectReflection {
                status: _,
                location: LocationRelation::Missing,
                reflection: control_reflection,
            },
            CommittedReviewResponse::RedirectReflection {
                status: ReviewStatusRelation::Redirect,
                location: LocationRelation::ExactExternalQueryValue,
                reflection: candidate_reflection,
            },
        ) => {
            let Some(query_parameter) = redirect_query_parameter else {
                return;
            };
            output.push(AssessmentReviewCandidate::Redirect(
                RedirectReviewCandidate {
                    subject: control.subject.clone(),
                    case_id: control.case_id.clone(),
                    query_parameter: query_parameter.to_owned(),
                    control_evidence_ids: ids_for(
                        control,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::RedirectStatus,
                            ReviewProperty::RedirectLocation,
                        ],
                    ),
                    candidate_evidence_ids: ids_for(
                        candidate,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::RedirectStatus,
                            ReviewProperty::RedirectLocation,
                        ],
                    ),
                },
            ));
            append_reflection_candidate(
                control,
                candidate,
                control_reflection,
                candidate_reflection,
                query_parameter,
                output,
            );
        },
        (
            CommittedReviewResponse::RedirectReflection {
                reflection: control_reflection,
                ..
            },
            CommittedReviewResponse::RedirectReflection {
                reflection: candidate_reflection,
                ..
            },
        ) => {
            let Some(query_parameter) = redirect_query_parameter else {
                return;
            };
            append_reflection_candidate(
                control,
                candidate,
                control_reflection,
                candidate_reflection,
                query_parameter,
                output,
            )
        },
        _ => {},
    }
}

fn observations_form_exact_pair(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
) -> bool {
    control.stage == DecisionExecutionStage::Passive
        && candidate.stage == DecisionExecutionStage::Active
        && !control.active_pair_success
        && candidate.active_pair_success
        && control.kind == candidate.kind
        && control.subject == candidate.subject
        && control.case_id == candidate.case_id
        && control.hypothesis_id == candidate.hypothesis_id
        && disjoint(&control.evidence_ids, &candidate.evidence_ids)
}

fn append_reflection_candidate(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
    control_context: ExactHtmlReflectionContext,
    candidate_context: ExactHtmlReflectionContext,
    query_parameter: &str,
    output: &mut Vec<AssessmentReviewCandidate>,
) {
    if control_context != ExactHtmlReflectionContext::Absent {
        return;
    }
    let (context, disposition) = match candidate_context {
        ExactHtmlReflectionContext::Inert => (
            ReviewReflectionContext::Inert,
            NativeReviewDisposition::Informational,
        ),
        ExactHtmlReflectionContext::Text => (
            ReviewReflectionContext::Text,
            NativeReviewDisposition::Informational,
        ),
        ExactHtmlReflectionContext::Attribute => (
            ReviewReflectionContext::Attribute,
            NativeReviewDisposition::Informational,
        ),
        ExactHtmlReflectionContext::Dangerous => (
            ReviewReflectionContext::Dangerous,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::Absent
        | ExactHtmlReflectionContext::NotApplicable
        | ExactHtmlReflectionContext::Incomplete => return,
    };
    output.push(AssessmentReviewCandidate::Reflection(
        ReflectionReviewCandidate {
            subject: control.subject.clone(),
            case_id: control.case_id.clone(),
            query_parameter: query_parameter.to_owned(),
            context,
            disposition,
            control_evidence_ids: ids_for(
                control,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::HtmlReflection,
                ],
            ),
            candidate_evidence_ids: ids_for(
                candidate,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::HtmlReflection,
                ],
            ),
        },
    ));
}

fn ids_for(
    observation: &CommittedAssessmentReviewObservation,
    properties: &[ReviewProperty],
) -> Vec<EvidenceId> {
    properties
        .iter()
        .filter_map(|property| observation.property_evidence.get(property).cloned())
        .collect()
}

fn disjoint(left: &[EvidenceId], right: &[EvidenceId]) -> bool {
    let left = left.iter().collect::<BTreeSet<_>>();
    right.iter().all(|id| !left.contains(id))
}

#[cfg(test)]
#[path = "assessment_review_tests.rs"]
mod tests;
