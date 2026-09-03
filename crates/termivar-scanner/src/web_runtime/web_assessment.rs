//! Bounded exact-origin orchestration over the standard web decision runtime.
//!
//! Discovery is names-only knowledge. It neither classifies vulnerabilities
//! nor authorizes another origin. Every subject shares one metered transport,
//! resource budget, knowledge base, cancellation token, and absolute deadline.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "reporting")]
use std::time::SystemTime;

use termivar_core::predicates::WebDiscoveryEvidencePredicate;
use termivar_core::{
    DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId, EvidenceKind,
    EvidenceOrigin, EvidenceSource, EvidenceValue, HttpEvidencePredicate, PredicateDescriptor,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

#[cfg(feature = "graphql-review")]
use crate::graphql_review::MAX_GRAPHQL_ACTIVE_VERIFICATIONS;
#[cfg(feature = "graphql-review")]
use crate::DefenseInteractionClass;

#[cfg(feature = "authorization-review")]
use super::authority::authenticated_transport_is_allowed;
#[cfg(feature = "authorization-review")]
use crate::authorization_review::{
    AuthorizationPrincipalPair, AuthorizationReviewOutcome, AuthorizationReviewPolicy,
};

#[cfg(feature = "graphql-review")]
use super::graphql_runtime::{
    execute_graphql_review, graphql_endpoint_hints, CommittedGraphqlReview, GraphqlRuntimeResult,
    GraphqlRuntimeStop,
};
#[cfg(feature = "openapi-review")]
use super::openapi_runtime::{
    select_openapi_candidate, CommittedOpenApiReview, OpenApiReviewConfig, OpenApiRuntimeOutcome,
    OpenApiRuntimeResult, WebAssessmentOpenApiAudit, MAX_OPENAPI_REVIEW_ACTIVE_VERIFICATIONS,
};
#[cfg(feature = "authorization-review")]
use super::resource_authorization_runtime::{
    CommittedResourceAuthorizationReview, ResourceAuthorizationReviewConfig,
    ResourceAuthorizationRuntimeResult, WebAssessmentAuthorizationAudit,
    MAX_AUTHORIZATION_REVIEW_ACTIVE_VERIFICATIONS,
};
#[cfg(feature = "rest-review")]
use super::rest_runtime::{
    CommittedRestReview, RestRuntimeOutcome, RestRuntimeResult, WebAssessmentRestAudit,
    MAX_REST_REVIEW_ACTIVE_VERIFICATIONS,
};
use super::{
    assessment_api_visibility::{
        build_root_api_visibility_runtime, CommittedAssessmentApiVisibility,
        RootApiVisibilityOutcome, RootApiVisibilityRuntime, WebAssessmentRootAuthorizationContext,
    },
    assessment_defense::{
        AssessmentDefenseBodyCoverage, AssessmentDefenseController, ASSESSMENT_DEFENSE_NAMESPACE,
    },
    assessment_item::{AssessmentItem, AssessmentItemSet},
    assessment_passive::{
        project_assessment_items, project_assessment_passive_response,
        AssessmentPassiveProjectionContext, AssessmentReviewProjectionSources,
        CommittedAssessmentPassiveLedger, PassiveAssessmentProjectionIncompleteness,
        ASSESSMENT_PASSIVE_NAMESPACE,
    },
    assessment_review::{AssessmentReviewObserverSet, CommittedAssessmentReviewLedger},
    web_review_execution::enabled_native_web_review_actions,
    NativeWebReviewSeeds, SharedWebRuntimeAuthority, StandardWebDecisionAssessmentFailureParts,
    StandardWebDecisionAssessmentParts, BOOTSTRAP_ACTION_ID, BOOTSTRAP_CASE_ID,
    BOOTSTRAP_HYPOTHESIS_ID,
};
#[cfg(feature = "reporting")]
use super::{
    assessment_report::{
        AssessmentRunReport, AssessmentRunReportError, AssessmentRuntimeLimits,
        CompletedWebAssessmentTruth,
    },
    scan_profile::ScanProfileV1,
};
use crate::{
    http_evidence::{CompleteHttpResponseObservation, CompleteHttpResponseObserver},
    web_actions::NativeWebReviewActionKind,
    AttackPlan, DecisionEvidenceReceipt, DecisionExecutionFailureReceipt, DecisionExecutionStage,
    DecisionLoopCommand, DecisionStopReason, DefensePosture, DefenseProduct, FingerprintConfidence,
    HttpEvidenceError, HttpEvidencePolicy, HttpProbe, HttpProbeMethod, KnowledgeBase, LimitsError,
    RuntimeApiVisibilityExecutionError, RuntimeBudget, RuntimeBudgetDimension,
    RuntimeLimitExceeded, SemanticExtractionLimits, SemanticExtractionResult, ShadowPlanDelta,
    StandardWebActionKind, StandardWebDecisionRuntime, StandardWebDecisionRuntimeError,
    StandardWebDecisionRuntimeTurn, TransportDispatchAudit, HTTP_EVIDENCE_EXECUTOR_ID,
    MAX_HTTP_BODY_LIMIT,
};

mod attribute_boundary_matcher;
mod attribute_source_context;
mod discovery;
mod javascript_source_context;
#[cfg(feature = "normalization-resilience")]
mod normalization_transform_catalog;
mod reflection_context;
mod semantic;
mod xss_probe_catalog;

pub(super) use attribute_boundary_matcher::{
    match_exact_xss_attribute_boundary_document, ExactXssAttributeBoundaryMatch,
};
pub(super) use attribute_source_context::{
    cross_validate_attribute_reflection_source, AttributeQuoteMode, AttributeSourceResult,
};
use discovery::{canonicalize_root, parse_document, ParsedDocument, ParsedForm, ParsedRoute};
pub(super) use javascript_source_context::{
    cross_validate_javascript_reflection_source, match_exact_xss_javascript_boundary_document,
    validate_exact_xss_javascript_boundary_candidate, ExactJavaScriptBoundaryMatch,
    JavaScriptScriptKind, JavaScriptSourceResult,
};
#[cfg(feature = "normalization-resilience")]
pub(super) use normalization_transform_catalog::{
    select_normalization_transform, NormalizationTransformRef, NormalizationTransformSelection,
};
#[cfg(all(feature = "normalization-resilience", test))]
pub(super) use normalization_transform_catalog::{
    NORMALIZATION_V1_MAX_CHILD_ACTIVE_VERIFICATIONS, NORMALIZATION_V1_MAX_CHILD_REQUESTS,
};
pub(super) use reflection_context::{
    classify_exact_html_reflection, match_exact_xss_html_boundary_document,
    validate_exact_xss_html_boundary_fragment, ExactHtmlReflectionContext, ExactXssBoundaryMatch,
};
use semantic::{assessment_semantic_limits, AssessmentSemanticEvidence};
pub(super) use xss_probe_catalog::{select_xss_probe_families, XssProbeFamily, XssProbeSelection};

/// Default maximum canonical subjects retained by one assessment.
pub const DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS: usize = 64;
/// Compiled maximum canonical subjects retained by one assessment.
pub const HARD_MAX_WEB_ASSESSMENT_SUBJECTS: usize = 1_024;
/// Default maximum discovery depth after the authorized root.
pub const DEFAULT_WEB_ASSESSMENT_MAX_DEPTH: u16 = 2;
/// Compiled maximum discovery depth after the authorized root.
pub const HARD_MAX_WEB_ASSESSMENT_DEPTH: u16 = 16;
/// Default maximum distinct route references retained from one document.
pub const DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT: usize = 128;
/// Compiled maximum distinct route references retained from one document.
pub const HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT: usize = 2_048;
/// Default maximum byte length of one canonical query-free URL.
pub const DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES: usize = 8_192;
/// Compiled maximum byte length of one canonical query-free URL.
pub const HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES: usize = 8_192;
/// Default maximum bytes charged once per distinct canonical URL identity.
pub const DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES: usize = 512 * 1024;
/// Compiled maximum bytes charged once per distinct canonical URL identity.
pub const HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES: usize = 8 * 1024 * 1024;
/// Default maximum number of forms retained by one assessment.
pub const DEFAULT_WEB_ASSESSMENT_MAX_FORMS: usize = 64;
/// Compiled maximum number of forms retained by one assessment.
pub const HARD_MAX_WEB_ASSESSMENT_FORMS: usize = 1_024;
/// Default maximum distinct control names retained for one form.
pub const DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM: usize = 64;
/// Compiled maximum distinct control names retained for one form.
pub const HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM: usize = 256;
/// Default maximum distinct query names retained for one route or form action.
pub const DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES: usize = 64;
/// Compiled maximum distinct query names retained for one route or form action.
pub const HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES: usize = 256;
/// Default maximum broker-owned dispatches for one assessment.
pub const DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS: u32 = 256;
/// Compiled request ceiling; this includes the later 10,000-request benchmark.
pub const HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS: u32 = 10_000;
/// Default per-response body retention ceiling.
pub const DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES: usize = 256 * 1024;
/// Compiled maximum retained bytes for one response body.
pub const HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES: usize = MAX_HTTP_BODY_LIMIT;
/// Default cumulative response-byte ceiling.
pub const DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
/// Compiled cumulative response-byte ceiling.
pub const HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;
/// Default complete-assessment wall-clock ceiling.
pub const DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME: Duration = Duration::from_secs(300);
/// Compiled complete-assessment wall-clock ceiling.
pub const HARD_MAX_WEB_ASSESSMENT_WALL_TIME: Duration = Duration::from_secs(3_600);
/// Default maximum active verification dispatches: seven for the initial
/// native review pass, one context-selected XSS structural family, and two for
/// one explicitly supplied authorization pair.
/// Callers may select a lower ceiling; exhaustion remains fail-closed.
pub const DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS: u16 = 10;
/// Compiled maximum active verification dispatches.
pub const HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS: u16 = 64;
/// Exact feature-local allowance reserved by an explicitly enabled GraphQL child.
#[cfg(feature = "graphql-review")]
pub(crate) const GRAPHQL_REVIEW_ACTIVE_VERIFICATION_ALLOWANCE: u16 =
    MAX_GRAPHQL_ACTIVE_VERIFICATIONS as u16;
/// Exact feature-local allowance reserved by one resource authorization child.
#[cfg(feature = "authorization-review")]
pub(crate) const AUTHORIZATION_REVIEW_ACTIVE_VERIFICATION_ALLOWANCE: u16 =
    MAX_AUTHORIZATION_REVIEW_ACTIVE_VERIFICATIONS as u16;
/// Assessment subjects execute sequentially under one shared authority.
pub const WEB_ASSESSMENT_CONCURRENCY: usize = 1;

/// Closed, non-secret parameter-name catalog eligible for the optional
/// external-destination differential. Discovery may observe other names, but
/// the review runtime never guesses that they carry navigation destinations.
const REDIRECT_REVIEW_QUERY_PARAMETER_ALLOWLIST: [&str; 11] = [
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "return",
    "return_to",
    "return_url",
    "url",
];

fn select_redirect_review_query_parameter(names: &[String]) -> Option<String> {
    names
        .iter()
        .find(|name| {
            REDIRECT_REVIEW_QUERY_PARAMETER_ALLOWLIST
                .binary_search(&name.as_str())
                .is_ok()
        })
        .cloned()
}

fn select_sql_review_query_parameter(names: &[String]) -> Option<String> {
    names
        .iter()
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 64
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
        })
        .min()
        .cloned()
}

fn select_ssti_review_query_parameter(names: &[String]) -> Option<String> {
    select_sql_review_query_parameter(names)
}

fn select_reflection_review_query_parameter(names: &[String]) -> Option<String> {
    select_sql_review_query_parameter(names)
}

pub(crate) const HARD_MAX_DISCOVERY_NAME_BYTES: usize =
    SemanticExtractionLimits::HARD_MAX_ASSESSMENT_PARAMETER_NAME_BYTES;
pub(crate) const HARD_MAX_DISCOVERY_NAMES_PER_REFERENCE: usize =
    SemanticExtractionLimits::HARD_MAX_ASSESSMENT_PARAMETER_NAMES_PER_REFERENCE;

/// Invalid configuration for a bounded web assessment.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum WebAssessmentLimitsError {
    /// A dimension required to retain the authorized root was configured as zero.
    #[error("web assessment limit {dimension} must be greater than zero")]
    ZeroRequired { dimension: &'static str },
    /// A selected limit exceeded its compiled ceiling.
    #[error("web assessment limit {dimension}={actual} exceeds compiled maximum {maximum}")]
    AboveHardMaximum {
        dimension: &'static str,
        actual: u64,
        maximum: u64,
    },
}

/// Checked resource and discovery envelope for one origin assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebAssessmentLimits {
    max_subjects: usize,
    max_discovery_depth: u16,
    max_references_per_document: usize,
    max_canonical_url_bytes: usize,
    max_retained_url_bytes: usize,
    max_forms: usize,
    max_controls_per_form: usize,
    max_query_parameter_names: usize,
    max_total_requests: u32,
    max_response_body_bytes: usize,
    max_total_response_bytes: u64,
    max_wall_time: Duration,
    max_active_verifications: u16,
}

impl WebAssessmentLimits {
    /// Replaces the subject ceiling.
    pub fn with_max_subjects(mut self, value: usize) -> Result<Self, WebAssessmentLimitsError> {
        check_nonzero("max_subjects", value)?;
        check_max("max_subjects", value, HARD_MAX_WEB_ASSESSMENT_SUBJECTS)?;
        self.max_subjects = value;
        Ok(self)
    }

    /// Replaces the maximum discovery depth. Zero permits only the root.
    pub fn with_max_discovery_depth(
        mut self,
        value: u16,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_max("max_discovery_depth", value, HARD_MAX_WEB_ASSESSMENT_DEPTH)?;
        self.max_discovery_depth = value;
        Ok(self)
    }

    /// Replaces the per-document route-reference ceiling. Zero retains none.
    pub fn with_max_references_per_document(
        mut self,
        value: usize,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_max(
            "max_references_per_document",
            value,
            HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT,
        )?;
        self.max_references_per_document = value;
        Ok(self)
    }

    /// Replaces the canonical URL byte ceiling.
    pub fn with_max_canonical_url_bytes(
        mut self,
        value: usize,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_nonzero("max_canonical_url_bytes", value)?;
        check_max(
            "max_canonical_url_bytes",
            value,
            HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES,
        )?;
        self.max_canonical_url_bytes = value;
        Ok(self)
    }

    /// Replaces the distinct canonical-URL identity byte ceiling.
    pub fn with_max_retained_url_bytes(
        mut self,
        value: usize,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_nonzero("max_retained_url_bytes", value)?;
        check_max(
            "max_retained_url_bytes",
            value,
            HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES,
        )?;
        self.max_retained_url_bytes = value;
        Ok(self)
    }

    /// Replaces the total form ceiling. Zero retains no forms.
    pub fn with_max_forms(mut self, value: usize) -> Result<Self, WebAssessmentLimitsError> {
        check_max("max_forms", value, HARD_MAX_WEB_ASSESSMENT_FORMS)?;
        self.max_forms = value;
        Ok(self)
    }

    /// Replaces the per-form control-name ceiling. Zero retains no names.
    pub fn with_max_controls_per_form(
        mut self,
        value: usize,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_max(
            "max_controls_per_form",
            value,
            HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM,
        )?;
        self.max_controls_per_form = value;
        Ok(self)
    }

    /// Replaces the query-name ceiling per route or form. Zero retains none.
    pub fn with_max_query_parameter_names(
        mut self,
        value: usize,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_max(
            "max_query_parameter_names",
            value,
            HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES,
        )?;
        self.max_query_parameter_names = value;
        Ok(self)
    }

    /// Replaces the authority-wide request ceiling. Zero denies all dispatches.
    pub fn with_max_total_requests(mut self, value: u32) -> Result<Self, WebAssessmentLimitsError> {
        check_max(
            "max_total_requests",
            value,
            HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS,
        )?;
        self.max_total_requests = value;
        Ok(self)
    }

    /// Replaces the per-response body ceiling.
    pub fn with_max_response_body_bytes(
        mut self,
        value: usize,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_nonzero("max_response_body_bytes", value)?;
        check_max("max_response_body_bytes", value, MAX_HTTP_BODY_LIMIT)?;
        self.max_response_body_bytes = value;
        Ok(self)
    }

    /// Replaces the authority-wide response-byte ceiling.
    pub fn with_max_total_response_bytes(
        mut self,
        value: u64,
    ) -> Result<Self, WebAssessmentLimitsError> {
        if value == 0 {
            return Err(WebAssessmentLimitsError::ZeroRequired {
                dimension: "max_total_response_bytes",
            });
        }
        check_max(
            "max_total_response_bytes",
            value,
            HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES,
        )?;
        self.max_total_response_bytes = value;
        Ok(self)
    }

    /// Replaces the authority-wide wall-clock ceiling. Zero denies execution.
    pub fn with_max_wall_time(mut self, value: Duration) -> Result<Self, WebAssessmentLimitsError> {
        if value > HARD_MAX_WEB_ASSESSMENT_WALL_TIME {
            return Err(WebAssessmentLimitsError::AboveHardMaximum {
                dimension: "max_wall_time_ms",
                actual: duration_ms(value),
                maximum: duration_ms(HARD_MAX_WEB_ASSESSMENT_WALL_TIME),
            });
        }
        self.max_wall_time = value;
        Ok(self)
    }

    /// Replaces the active-verification ceiling. Zero denies active requests.
    pub fn with_max_active_verifications(
        mut self,
        value: u16,
    ) -> Result<Self, WebAssessmentLimitsError> {
        check_max(
            "max_active_verifications",
            value,
            HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS,
        )?;
        self.max_active_verifications = value;
        Ok(self)
    }

    /// Returns the subject ceiling, including the root.
    pub const fn max_subjects(self) -> usize {
        self.max_subjects
    }
    /// Returns the maximum depth after the root.
    pub const fn max_discovery_depth(self) -> u16 {
        self.max_discovery_depth
    }
    /// Returns the route-reference ceiling per document.
    pub const fn max_references_per_document(self) -> usize {
        self.max_references_per_document
    }
    /// Returns the canonical URL byte ceiling.
    pub const fn max_canonical_url_bytes(self) -> usize {
        self.max_canonical_url_bytes
    }
    /// Returns the byte ceiling charged once per distinct canonical URL.
    pub const fn max_retained_url_bytes(self) -> usize {
        self.max_retained_url_bytes
    }
    /// Returns the assessment-wide form ceiling.
    pub const fn max_forms(self) -> usize {
        self.max_forms
    }
    /// Returns the control-name ceiling per form.
    pub const fn max_controls_per_form(self) -> usize {
        self.max_controls_per_form
    }
    /// Returns the query-name ceiling per reference.
    pub const fn max_query_parameter_names(self) -> usize {
        self.max_query_parameter_names
    }
    /// Returns the authority-wide request ceiling.
    pub const fn max_total_requests(self) -> u32 {
        self.max_total_requests
    }
    /// Returns the per-response body ceiling.
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }
    /// Returns the authority-wide response-byte ceiling.
    pub const fn max_total_response_bytes(self) -> u64 {
        self.max_total_response_bytes
    }
    /// Returns the authority-wide wall-clock ceiling.
    pub const fn max_wall_time(self) -> Duration {
        self.max_wall_time
    }
    /// Returns the authority-wide active-verification ceiling.
    pub const fn max_active_verifications(self) -> u16 {
        self.max_active_verifications
    }
    /// Returns the fixed concurrency boundary.
    pub const fn concurrency(self) -> usize {
        WEB_ASSESSMENT_CONCURRENCY
    }

    // GET/HEAD discovery sends no request body. The shared authority keeps the
    // existing RuntimeBudget defaults for request-body bytes (256 KiB),
    // same-action attempts (3), and consecutive no-progress turns (4); this
    // assessment contract narrows only the explicitly exposed dimensions.
    fn runtime_budget(self, optional_active_verifications: u16) -> RuntimeBudget {
        let active_verifications = self
            .max_active_verifications
            .checked_add(optional_active_verifications)
            .expect("compiled optional active-verification allowances fit u16");
        RuntimeBudget::default()
            .with_max_total_requests(self.max_total_requests)
            .with_max_response_bytes(self.max_total_response_bytes)
            .with_max_wall_time(self.max_wall_time)
            .with_max_active_verifications(active_verifications)
    }
}

impl Default for WebAssessmentLimits {
    fn default() -> Self {
        Self {
            max_subjects: DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS,
            max_discovery_depth: DEFAULT_WEB_ASSESSMENT_MAX_DEPTH,
            max_references_per_document: DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT,
            max_canonical_url_bytes: DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES,
            max_retained_url_bytes: DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES,
            max_forms: DEFAULT_WEB_ASSESSMENT_MAX_FORMS,
            max_controls_per_form: DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM,
            max_query_parameter_names: DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES,
            max_total_requests: DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS,
            max_response_body_bytes: DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES,
            max_total_response_bytes: DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES,
            max_wall_time: DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME,
            max_active_verifications: DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS,
        }
    }
}

fn check_nonzero(dimension: &'static str, value: usize) -> Result<(), WebAssessmentLimitsError> {
    if value == 0 {
        Err(WebAssessmentLimitsError::ZeroRequired { dimension })
    } else {
        Ok(())
    }
}

fn check_max<T>(
    dimension: &'static str,
    value: T,
    maximum: T,
) -> Result<(), WebAssessmentLimitsError>
where
    T: Copy + Ord + TryInto<u64>,
{
    if value > maximum {
        Err(WebAssessmentLimitsError::AboveHardMaximum {
            dimension,
            actual: value.try_into().unwrap_or(u64::MAX),
            maximum: maximum.try_into().unwrap_or(u64::MAX),
        })
    } else {
        Ok(())
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Safe method boundary retained for an assessment subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WebAssessmentMethod {
    /// Retrieve a complete bounded representation for semantic review.
    Get,
    /// Observe response metadata only.
    Head,
}

impl WebAssessmentMethod {
    const fn probe_method(self) -> HttpProbeMethod {
        match self {
            Self::Get => HttpProbeMethod::Get,
            Self::Head => HttpProbeMethod::Head,
        }
    }
}

/// HTML form method retained without dispatching POST or dialog actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WebAssessmentFormMethod {
    /// A safe GET action candidate.
    Get,
    /// A recorded POST boundary that discovery never dispatches.
    Post,
    /// A recorded dialog boundary that discovery never dispatches.
    Dialog,
}

/// Provenance class for one canonical subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WebAssessmentSubjectOrigin {
    /// Query-free root explicitly authorized by the host.
    AuthorizedRoot,
    /// Same-origin subject derived from committed HTML discovery evidence.
    Discovered,
}

/// One canonical query-free assessment subject.
#[derive(Clone, PartialEq, Eq)]
pub struct WebAssessmentSubject {
    url: Url,
    method: WebAssessmentMethod,
    depth: u16,
    origin: WebAssessmentSubjectOrigin,
    query_parameter_names: Vec<String>,
    evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for WebAssessmentSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentSubject")
            .field("url", &"<redacted>")
            .field("method", &self.method)
            .field("depth", &self.depth)
            .field("origin", &self.origin)
            .field("query_parameter_count", &self.query_parameter_names.len())
            .field("evidence_count", &self.evidence_ids.len())
            .finish()
    }
}

impl WebAssessmentSubject {
    /// Returns the canonical query-free URL.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Returns the safe method boundary.
    pub const fn method(&self) -> WebAssessmentMethod {
        self.method
    }
    /// Returns the stable BFS depth, with the root at zero.
    pub const fn depth(&self) -> u16 {
        self.depth
    }
    /// Returns whether the subject was host-authorized or discovered.
    pub const fn origin(&self) -> WebAssessmentSubjectOrigin {
        self.origin
    }
    /// Returns sorted, de-duplicated candidate query names. No values exist.
    pub fn query_parameter_names(&self) -> &[String] {
        &self.query_parameter_names
    }
    /// Returns committed discovery evidence identities for this subject.
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

/// One canonical same-origin form observation.
#[derive(Clone, PartialEq, Eq)]
pub struct WebAssessmentForm {
    document_url: Url,
    action: Url,
    method: WebAssessmentFormMethod,
    query_parameter_names: Vec<String>,
    control_names: Vec<String>,
    evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for WebAssessmentForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentForm")
            .field("document_url", &"<redacted>")
            .field("action", &"<redacted>")
            .field("method", &self.method)
            .field("query_parameter_count", &self.query_parameter_names.len())
            .field("control_count", &self.control_names.len())
            .field("evidence_count", &self.evidence_ids.len())
            .finish()
    }
}

impl WebAssessmentForm {
    /// Returns the query-free document that contained the form.
    pub fn document_url(&self) -> &Url {
        &self.document_url
    }
    /// Returns the canonical query-free action.
    pub fn action(&self) -> &Url {
        &self.action
    }
    /// Returns the observed form method.
    pub const fn method(&self) -> WebAssessmentFormMethod {
        self.method
    }
    /// Returns sorted candidate action query names. No values exist.
    pub fn query_parameter_names(&self) -> &[String] {
        &self.query_parameter_names
    }
    /// Returns sorted control names. No control values exist.
    pub fn control_names(&self) -> &[String] {
        &self.control_names
    }
    /// Returns committed discovery evidence identities for this form.
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

/// One subject's standard decision audit without duplicated global accounting.
pub struct WebAssessmentSubjectReport {
    subject: WebAssessmentSubject,
    executed: bool,
    bootstrap: Option<DecisionEvidenceReceipt>,
    turns: Vec<StandardWebDecisionRuntimeTurn>,
    unverified_evidence: Option<DecisionEvidenceReceipt>,
    terminal: Option<DecisionLoopCommand>,
    limit_exceeded: Option<RuntimeLimitExceeded>,
    execution_failure: Option<DecisionExecutionFailureReceipt>,
}

impl fmt::Debug for WebAssessmentSubjectReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentSubjectReport")
            .field("subject", &self.subject)
            .field("executed", &self.executed)
            .field("bootstrap_committed", &self.bootstrap.is_some())
            .field("turn_count", &self.turns.len())
            .field(
                "unverified_evidence_committed",
                &self.unverified_evidence.is_some(),
            )
            .field("terminal_present", &self.terminal.is_some())
            .field("limit_exceeded", &self.limit_exceeded.is_some())
            .field("execution_failed", &self.execution_failure.is_some())
            .finish()
    }
}

impl WebAssessmentSubjectReport {
    fn pending(subject: WebAssessmentSubject) -> Self {
        Self {
            subject,
            executed: false,
            bootstrap: None,
            turns: Vec::new(),
            unverified_evidence: None,
            terminal: None,
            limit_exceeded: None,
            execution_failure: None,
        }
    }

    fn complete(subject: WebAssessmentSubject, parts: StandardWebDecisionAssessmentParts) -> Self {
        Self {
            subject,
            executed: true,
            bootstrap: parts.bootstrap,
            turns: parts.turns,
            unverified_evidence: parts.unverified_evidence,
            terminal: Some(parts.terminal),
            limit_exceeded: parts.limit_exceeded,
            execution_failure: parts.execution_failure,
        }
    }

    fn failed(
        subject: WebAssessmentSubject,
        parts: StandardWebDecisionAssessmentFailureParts,
        executed: bool,
    ) -> Self {
        Self {
            subject,
            executed,
            bootstrap: parts.bootstrap,
            turns: parts.turns,
            unverified_evidence: None,
            terminal: None,
            limit_exceeded: None,
            execution_failure: None,
        }
    }

    /// Returns the canonical subject.
    pub fn subject(&self) -> &WebAssessmentSubject {
        &self.subject
    }
    /// Returns whether this retained subject reached the standard runtime.
    pub fn was_executed(&self) -> bool {
        self.executed
    }
    /// Returns the committed bootstrap evidence when execution started it.
    pub fn bootstrap(&self) -> Option<&DecisionEvidenceReceipt> {
        self.bootstrap.as_ref()
    }
    /// Returns planning and outcome turns without a nested transport snapshot.
    pub fn turns(&self) -> &[StandardWebDecisionRuntimeTurn] {
        &self.turns
    }
    /// Returns evidence committed before verification was skipped.
    pub fn unverified_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        self.unverified_evidence.as_ref()
    }
    /// Returns the subject terminal, or `None` when global limits prevented it.
    pub fn terminal(&self) -> Option<&DecisionLoopCommand> {
        self.terminal.as_ref()
    }
    /// Returns the subject-local view of a global runtime limit.
    pub fn limit_exceeded(&self) -> Option<&RuntimeLimitExceeded> {
        self.limit_exceeded.as_ref()
    }
    /// Returns the executor failure retained in a limit report.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        self.execution_failure.as_ref()
    }
}

/// Aggregate monotonic usage for one assessment authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebAssessmentUsage {
    retained_subjects: usize,
    executed_subjects: usize,
    retained_forms: usize,
    retained_unique_url_bytes: usize,
    total_requests: u32,
    active_verifications: u16,
    request_body_bytes: u64,
    response_bytes: u64,
    elapsed_ms: u64,
}

impl WebAssessmentUsage {
    pub const fn retained_subjects(self) -> usize {
        self.retained_subjects
    }
    pub const fn executed_subjects(self) -> usize {
        self.executed_subjects
    }
    pub const fn retained_forms(self) -> usize {
        self.retained_forms
    }
    /// Returns bytes charged once per distinct canonical URL identity.
    pub const fn retained_unique_url_bytes(self) -> usize {
        self.retained_unique_url_bytes
    }
    pub const fn total_requests(self) -> u32 {
        self.total_requests
    }
    pub const fn active_verifications(self) -> u16 {
        self.active_verifications
    }
    pub const fn request_body_bytes(self) -> u64 {
        self.request_body_bytes
    }
    pub const fn response_bytes(self) -> u64 {
        self.response_bytes
    }
    pub const fn elapsed_ms(self) -> u64 {
        self.elapsed_ms
    }
}

/// A bounded condition that prevented exhaustive assessment execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WebAssessmentIncompleteReason {
    SubjectLimit,
    DiscoveryDepthLimit,
    DocumentReferenceLimit,
    CanonicalUrlBytesLimit,
    RetainedUrlBytesLimit,
    FormLimit,
    FormControlLimit,
    QueryParameterNameLimit,
    ResponseBodyIncomplete,
    PartialRepresentation,
    InvalidUtf8,
    TotalRequestLimit,
    ResponseBytesLimit,
    RequestBodyBytesLimit,
    WallTimeLimit,
    ActiveVerificationLimit,
    SameActionAttemptLimit,
    ConsecutiveNoProgressLimit,
    ActionCycleLimit,
    AdaptationLimit,
    HumanReviewRequired,
    SubjectExecutionIncomplete,
    HostCancellation,
    SemanticExtractionLimit,
    PassiveResponseProjectionLimit,
    AssessmentSubjectIdentityUnavailable,
    /// The explicitly enabled matched review catalog did not commit every
    /// control/candidate observation required by its configured boundary.
    DifferentialReviewIncomplete,
    /// The explicitly supplied authorization-context pair did not produce one
    /// complete canonical comparison suitable for product projection.
    ApiVisibilityReviewIncomplete,
    /// The explicitly enabled anonymous GraphQL child did not complete its
    /// bounded correlated protocol review.
    #[cfg(feature = "graphql-review")]
    GraphqlReviewIncomplete,
    /// The explicitly enabled four-view resource authorization child did not
    /// complete its bounded comparison.
    #[cfg(feature = "authorization-review")]
    AuthorizationReviewIncomplete,
    /// The explicitly enabled OpenAPI document/replay pair did not complete.
    #[cfg(feature = "openapi-review")]
    OpenApiReviewIncomplete,
    /// The explicitly enabled OpenAPI-constrained REST candidate/replay pair
    /// did not complete its bounded anonymous comparison.
    #[cfg(feature = "rest-review")]
    RestReviewIncomplete,
}

/// Whether every retained subject and eligible document completed within bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebAssessmentCompletion {
    Complete,
    Incomplete {
        reasons: BTreeSet<WebAssessmentIncompleteReason>,
    },
}

impl WebAssessmentCompletion {
    /// Returns the typed incomplete reasons, or an empty set for a complete run.
    pub fn reasons(&self) -> BTreeSet<WebAssessmentIncompleteReason> {
        match self {
            Self::Complete => BTreeSet::new(),
            Self::Incomplete { reasons } => reasons.clone(),
        }
    }
}

/// Bounded body coverage used for a defense observation. This describes only
/// the detector input; it never claims exhaustive response-body analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAssessmentDefenseBodyCoverage {
    MetadataOnly,
    CompleteUtf8Prefix,
}

/// One committed confidence-graded defense observation. A fingerprint is a
/// product hint only, never a categorical WAF-presence claim.
#[derive(Clone, PartialEq, Eq)]
pub struct WebAssessmentDefenseObservation {
    subject: termivar_core::EntityId,
    case_id: String,
    stage: DecisionExecutionStage,
    status: u16,
    posture: Option<DefensePosture>,
    challenge_observed: bool,
    rate_limit_observed: bool,
    fingerprint_hint: Option<(DefenseProduct, FingerprintConfidence)>,
    body_coverage: WebAssessmentDefenseBodyCoverage,
    input_limit_reached: bool,
    evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for WebAssessmentDefenseObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentDefenseObservation")
            .field("subject", &"<redacted>")
            .field("case_id", &"<redacted>")
            .field("stage", &self.stage)
            .field("status", &self.status)
            .field("posture", &self.posture)
            .field("challenge_observed", &self.challenge_observed)
            .field("rate_limit_observed", &self.rate_limit_observed)
            .field("fingerprint_hint", &self.fingerprint_hint)
            .field("body_coverage", &self.body_coverage)
            .field("input_limit_reached", &self.input_limit_reached)
            .field("evidence_count", &self.evidence_ids.len())
            .finish()
    }
}

impl WebAssessmentDefenseObservation {
    pub fn subject(&self) -> &termivar_core::EntityId {
        &self.subject
    }
    pub fn case_id(&self) -> &str {
        &self.case_id
    }
    pub const fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }
    pub const fn status(&self) -> u16 {
        self.status
    }
    /// Returns the bounded detector posture. `Some(Open)` means only that the
    /// complete, uncapped UTF-8 detector prefix carried no positive signal; it
    /// never means that a WAF or other defense is absent. Metadata-only and
    /// capped Open observations return `None`.
    pub const fn posture(&self) -> Option<DefensePosture> {
        self.posture
    }
    pub const fn challenge_observed(&self) -> bool {
        self.challenge_observed
    }
    pub const fn rate_limit_observed(&self) -> bool {
        self.rate_limit_observed
    }
    pub const fn fingerprint_hint(&self) -> Option<(DefenseProduct, FingerprintConfidence)> {
        self.fingerprint_hint
    }
    pub const fn body_coverage(&self) -> WebAssessmentDefenseBodyCoverage {
        self.body_coverage
    }
    pub const fn input_limit_reached(&self) -> bool {
        self.input_limit_reached
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

/// Positive-only matched control/candidate defense delta.
#[derive(Clone, PartialEq, Eq)]
pub struct WebAssessmentDefenseTransition {
    case_id: String,
    candidate_block_status_appeared: bool,
    newly_rate_limited: bool,
    candidate_fingerprint_hint: Option<(DefenseProduct, FingerprintConfidence)>,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for WebAssessmentDefenseTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentDefenseTransition")
            .field("case_id", &"<redacted>")
            .field(
                "candidate_block_status_appeared",
                &self.candidate_block_status_appeared,
            )
            .field("newly_rate_limited", &self.newly_rate_limited)
            .field(
                "candidate_fingerprint_hint",
                &self.candidate_fingerprint_hint,
            )
            .field("control_evidence_count", &self.control_evidence_ids.len())
            .field(
                "candidate_evidence_count",
                &self.candidate_evidence_ids.len(),
            )
            .finish()
    }
}

impl WebAssessmentDefenseTransition {
    pub fn case_id(&self) -> &str {
        &self.case_id
    }
    pub const fn candidate_block_status_appeared(&self) -> bool {
        self.candidate_block_status_appeared
    }
    pub const fn newly_rate_limited(&self) -> bool {
        self.newly_rate_limited
    }
    pub const fn candidate_fingerprint_hint(
        &self,
    ) -> Option<(DefenseProduct, FingerprintConfidence)> {
        self.candidate_fingerprint_hint
    }
    pub fn control_evidence_ids(&self) -> &[EvidenceId] {
        &self.control_evidence_ids
    }
    pub fn candidate_evidence_ids(&self) -> &[EvidenceId] {
        &self.candidate_evidence_ids
    }
}

/// Exact policy-authorized plan and its read-only defense-aware subsequence.
#[derive(Clone)]
pub struct WebAssessmentDefenseShadowPlan {
    policy_authorized: AttackPlan,
    shadow: AttackPlan,
    delta: ShadowPlanDelta,
}

impl fmt::Debug for WebAssessmentDefenseShadowPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentDefenseShadowPlan")
            .field("policy_authorized", &"<redacted-plan>")
            .field("shadow", &"<redacted-plan>")
            .field("delta", &"<redacted-delta>")
            .finish()
    }
}

impl WebAssessmentDefenseShadowPlan {
    pub fn policy_authorized(&self) -> &AttackPlan {
        &self.policy_authorized
    }
    pub fn shadow(&self) -> &AttackPlan {
        &self.shadow
    }
    pub fn delta(&self) -> &ShadowPlanDelta {
        &self.delta
    }
}

/// Whether defense is observation-only or monotonically enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAssessmentDefenseMode {
    ObservationOnly,
    Enforced,
}

/// Bounded defense audit composed from exact committed subject receipts.
#[derive(Clone)]
pub struct WebAssessmentDefenseAudit {
    mode: WebAssessmentDefenseMode,
    observations: Vec<WebAssessmentDefenseObservation>,
    transitions: Vec<WebAssessmentDefenseTransition>,
    shadow_plans: Vec<WebAssessmentDefenseShadowPlan>,
}

impl fmt::Debug for WebAssessmentDefenseAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentDefenseAudit")
            .field("mode", &self.mode)
            .field("observation_count", &self.observations.len())
            .field("transition_count", &self.transitions.len())
            .field("shadow_plan_count", &self.shadow_plans.len())
            .finish()
    }
}

impl WebAssessmentDefenseAudit {
    fn new(mode: WebAssessmentDefenseMode) -> Self {
        Self {
            mode,
            observations: Vec::new(),
            transitions: Vec::new(),
            shadow_plans: Vec::new(),
        }
    }

    pub const fn mode(&self) -> WebAssessmentDefenseMode {
        self.mode
    }
    pub fn observations(&self) -> &[WebAssessmentDefenseObservation] {
        &self.observations
    }
    pub fn transitions(&self) -> &[WebAssessmentDefenseTransition] {
        &self.transitions
    }
    pub fn shadow_plans(&self) -> &[WebAssessmentDefenseShadowPlan] {
        &self.shadow_plans
    }

    fn append_controller(&mut self, controller: &AssessmentDefenseController) -> Result<(), ()> {
        let enforced = self.mode == WebAssessmentDefenseMode::Enforced;
        if controller.enforcement_enabled() != enforced {
            return Err(());
        }
        self.observations.extend(
            controller
                .ledger()
                .observations()
                .iter()
                .map(|observation| {
                    let hint = observation
                        .state()
                        .fingerprint()
                        .map(|hint| (hint.product(), hint.confidence()));
                    WebAssessmentDefenseObservation {
                        subject: observation.case().subject().clone(),
                        case_id: observation.case().id().to_owned(),
                        stage: observation.stage(),
                        status: observation.state().status(),
                        posture: if observation.state().posture() == DefensePosture::Open
                            && (observation.body_coverage()
                                != AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
                                || observation.input_limit_reached())
                        {
                            None
                        } else {
                            Some(observation.state().posture())
                        },
                        challenge_observed: observation.state().is_challenged(),
                        rate_limit_observed: observation.state().is_rate_limited(),
                        fingerprint_hint: hint,
                        body_coverage: match observation.body_coverage() {
                            AssessmentDefenseBodyCoverage::MetadataOnly => {
                                WebAssessmentDefenseBodyCoverage::MetadataOnly
                            },
                            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix => {
                                WebAssessmentDefenseBodyCoverage::CompleteUtf8Prefix
                            },
                        },
                        input_limit_reached: observation.input_limit_reached(),
                        evidence_ids: observation.evidence_ids().to_vec(),
                    }
                }),
        );
        self.transitions
            .extend(controller.ledger().transitions().iter().map(|transition| {
                let hint = transition
                    .candidate_fingerprint_hint()
                    .map(|hint| (hint.product(), hint.confidence()));
                WebAssessmentDefenseTransition {
                    case_id: transition.case().id().to_owned(),
                    candidate_block_status_appeared: transition.candidate_block_status_appeared(),
                    newly_rate_limited: transition.newly_rate_limited(),
                    candidate_fingerprint_hint: hint,
                    control_evidence_ids: transition.control_evidence_ids().to_vec(),
                    candidate_evidence_ids: transition.candidate_evidence_ids().to_vec(),
                }
            }));
        self.shadow_plans
            .extend(
                controller
                    .shadows()
                    .iter()
                    .map(|shadow| WebAssessmentDefenseShadowPlan {
                        policy_authorized: shadow.current().clone(),
                        shadow: shadow.shadow().clone(),
                        delta: shadow.delta().clone(),
                    }),
            );
        Ok(())
    }
}

/// Complete origin-assessment audit with exactly one global transport view.
pub struct WebAssessmentRunReport {
    #[cfg(feature = "reporting")]
    run_started_at: SystemTime,
    authorized_root: WebAssessmentSubject,
    limits: WebAssessmentLimits,
    runtime_active_verification_limit: u16,
    runtime_optional_active_verification_allowance: u16,
    subjects: Vec<WebAssessmentSubjectReport>,
    forms: Vec<WebAssessmentForm>,
    semantics: SemanticExtractionResult,
    defense: WebAssessmentDefenseAudit,
    #[cfg(feature = "authorization-review")]
    authorization_review: Option<WebAssessmentAuthorizationAudit>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<WebAssessmentOpenApiAudit>,
    #[cfg(feature = "rest-review")]
    rest_review: Option<WebAssessmentRestAudit>,
    assessment_items: AssessmentItemSet,
    assessment_projection_incompleteness: PassiveAssessmentProjectionIncompleteness,
    completion: WebAssessmentCompletion,
    usage: WebAssessmentUsage,
    transport: TransportDispatchAudit,
}

impl fmt::Debug for WebAssessmentRunReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("WebAssessmentRunReport");
        #[cfg(feature = "reporting")]
        debug.field("run_started_at", &"<runtime-owned>");
        debug
            .field("authorized_root", &"<redacted>")
            .field("limits", &self.limits)
            .field(
                "runtime_active_verification_limit",
                &self.runtime_active_verification_limit,
            )
            .field("subject_count", &self.subjects.len())
            .field("form_count", &self.forms.len())
            .field("semantics", &"<redacted>")
            .field("defense", &self.defense);
        #[cfg(feature = "authorization-review")]
        debug.field("authorization_review", &self.authorization_review);
        #[cfg(feature = "openapi-review")]
        debug.field("openapi_review", &self.openapi_review);
        #[cfg(feature = "rest-review")]
        debug.field("rest_review", &self.rest_review);
        debug
            .field("assessment_items", &self.assessment_items)
            .field(
                "unprojected_subject_count",
                &self
                    .assessment_projection_incompleteness
                    .non_root_observations(),
            )
            .field(
                "unprojected_condition_count",
                &self
                    .assessment_projection_incompleteness
                    .non_root_conditions(),
            )
            .field("completion", &self.completion)
            .field("usage", &self.usage)
            .field("transport", &"<redacted-audit>")
            .finish()
    }
}

impl WebAssessmentRunReport {
    /// Returns the exact query-free resource that started this assessment.
    ///
    /// Product adapters must bind any separately constructed run envelope to
    /// this identity instead of relying on same-origin equivalence.
    pub fn authorized_root(&self) -> &WebAssessmentSubject {
        &self.authorized_root
    }
    /// Returns the profile-owned base limits that governed this assessment.
    /// Feature-local additive authority, when present, is exposed separately.
    pub const fn limits(&self) -> WebAssessmentLimits {
        self.limits
    }
    /// Returns the actual shared active-verification ceiling used at startup.
    pub const fn runtime_active_verification_limit(&self) -> u16 {
        self.runtime_active_verification_limit
    }
    pub fn subjects(&self) -> &[WebAssessmentSubjectReport] {
        &self.subjects
    }
    pub fn forms(&self) -> &[WebAssessmentForm] {
        &self.forms
    }
    /// Returns bounded semantic entities derived only from exact committed
    /// assessment evidence.
    pub fn semantics(&self) -> &SemanticExtractionResult {
        &self.semantics
    }
    pub fn defense(&self) -> &WebAssessmentDefenseAudit {
        &self.defense
    }
    /// Returns the optional redaction-safe four-view authorization audit.
    #[cfg(feature = "authorization-review")]
    pub const fn authorization_review_audit(&self) -> Option<&WebAssessmentAuthorizationAudit> {
        self.authorization_review.as_ref()
    }
    #[cfg(feature = "openapi-review")]
    pub const fn openapi_review_audit(&self) -> Option<&WebAssessmentOpenApiAudit> {
        self.openapi_review.as_ref()
    }
    #[cfg(feature = "rest-review")]
    pub const fn rest_review_audit(&self) -> Option<&WebAssessmentRestAudit> {
        self.rest_review.as_ref()
    }
    /// Returns claim-safe items derived only from committed assessment truth.
    pub fn assessment_items(&self) -> &[AssessmentItem] {
        self.assessment_items.items()
    }
    /// Returns the number of discovered subjects whose reportable passive
    /// conditions lacked a host-approved stable product identity.
    pub const fn unprojected_assessment_subjects(&self) -> u16 {
        self.assessment_projection_incompleteness
            .non_root_observations()
    }
    /// Returns reportable passive conditions omitted at that identity boundary.
    pub const fn unprojected_assessment_conditions(&self) -> u16 {
        self.assessment_projection_incompleteness
            .non_root_conditions()
    }
    pub fn completion(&self) -> &WebAssessmentCompletion {
        &self.completion
    }
    pub const fn usage(&self) -> WebAssessmentUsage {
        self.usage
    }
    pub fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }

    /// Consumes the origin audit into the crate-owned typed product envelope.
    ///
    /// This remains crate-private so only the reporting layer can mint the run
    /// envelope from this report's runtime-owned timing and accounting. A
    /// public caller cannot pair this audit with an independently constructed
    /// generic [`termivar_core::RunReport`]. The existing `decision-scan/v1`
    /// report remains a separate contract.
    #[cfg(feature = "reporting")]
    pub(crate) fn into_assessment_report(
        self,
        profile: ScanProfileV1,
    ) -> Result<AssessmentRunReport, AssessmentRunReportError> {
        let truth = CompletedWebAssessmentTruth::new(
            self.run_started_at,
            &self.authorized_root,
            AssessmentRuntimeLimits::new(
                self.limits,
                self.runtime_active_verification_limit,
                self.runtime_optional_active_verification_allowance,
            ),
            self.usage,
            &self.completion,
            self.defense.mode(),
            profile,
        )?;
        AssessmentRunReport::from_completed_truth(
            self.assessment_items,
            truth,
            #[cfg(feature = "authorization-review")]
            self.authorization_review,
            #[cfg(feature = "openapi-review")]
            self.openapi_review,
            #[cfg(feature = "rest-review")]
            self.rest_review,
        )
    }
}

/// Durable outer audit retained when a started assessment fails.
pub struct WebAssessmentFailureReceipt {
    completed_subjects: Vec<WebAssessmentSubjectReport>,
    pending_subjects: Vec<WebAssessmentSubject>,
    forms: Vec<WebAssessmentForm>,
    semantics: SemanticExtractionResult,
    defense: WebAssessmentDefenseAudit,
    current_subject: WebAssessmentSubjectReport,
    incomplete_reasons: BTreeSet<WebAssessmentIncompleteReason>,
    inventory_consistent: bool,
    unrepresented_ledger_subjects: usize,
    committed_passive_observations: usize,
    usage: WebAssessmentUsage,
    transport: TransportDispatchAudit,
}

impl fmt::Debug for WebAssessmentFailureReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentFailureReceipt")
            .field("completed_subject_count", &self.completed_subjects.len())
            .field("pending_subject_count", &self.pending_subjects.len())
            .field("form_count", &self.forms.len())
            .field("semantics", &"<redacted>")
            .field("defense", &self.defense)
            .field("current_subject", &self.current_subject)
            .field("incomplete_reasons", &self.incomplete_reasons)
            .field("inventory_consistent", &self.inventory_consistent)
            .field(
                "unrepresented_ledger_subjects",
                &self.unrepresented_ledger_subjects,
            )
            .field(
                "committed_passive_observations",
                &self.committed_passive_observations,
            )
            .field("usage", &self.usage)
            .field("transport", &"<redacted-audit>")
            .finish()
    }
}

impl WebAssessmentFailureReceipt {
    pub fn completed_subjects(&self) -> &[WebAssessmentSubjectReport] {
        &self.completed_subjects
    }
    /// Returns committed discovered subjects that had not reached execution.
    pub fn pending_subjects(&self) -> &[WebAssessmentSubject] {
        &self.pending_subjects
    }
    pub fn forms(&self) -> &[WebAssessmentForm] {
        &self.forms
    }
    /// Returns semantic truth preserved from committed assessment evidence
    /// before the failing boundary.
    pub fn semantics(&self) -> &SemanticExtractionResult {
        &self.semantics
    }
    pub fn defense(&self) -> &WebAssessmentDefenseAudit {
        &self.defense
    }
    pub fn current_subject(&self) -> &WebAssessmentSubject {
        &self.current_subject.subject
    }
    /// Returns subject-local work at the failing boundary without a duplicate
    /// global transport or usage snapshot.
    pub fn current_subject_report(&self) -> &WebAssessmentSubjectReport {
        &self.current_subject
    }
    /// Returns every bounded or execution condition known at failure time.
    pub fn incomplete_reasons(&self) -> &BTreeSet<WebAssessmentIncompleteReason> {
        &self.incomplete_reasons
    }
    /// Returns whether typed subject/form inventory exactly matched the ledger.
    pub const fn inventory_consistent(&self) -> bool {
        self.inventory_consistent
    }
    /// Returns ledger subject identities absent from the typed known inventory.
    pub const fn unrepresented_ledger_subjects(&self) -> usize {
        self.unrepresented_ledger_subjects
    }
    /// Returns the bounded passive observations retained before failure.
    ///
    /// Started failures intentionally do not project user-facing assessment
    /// items: execution is incomplete, so callers receive this count and the
    /// typed failure inventory instead of a partial finding collection.
    pub const fn committed_passive_observations(&self) -> usize {
        self.committed_passive_observations
    }
    pub const fn usage(&self) -> WebAssessmentUsage {
        self.usage
    }
    pub fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }
}

/// Construction and execution failures for [`WebAssessmentRuntime`].
#[derive(Error)]
#[non_exhaustive]
pub enum WebAssessmentRuntimeError {
    #[error("web assessment runtime has already started")]
    AlreadyStarted,
    #[error(transparent)]
    Limits(#[from] WebAssessmentLimitsError),
    #[error(transparent)]
    SemanticLimits(#[from] LimitsError),
    #[error(transparent)]
    Http(#[from] HttpEvidenceError),
    #[error("authorized web assessment target cannot be retained safely")]
    InvalidCanonicalTarget,
    #[error("authorized root exceeds the total retained URL byte limit")]
    RootRetentionLimit,
    #[error("native low-risk web review could not be composed safely")]
    NativeReviewComposition,
    #[error("root authorization-context review requires an exact origin root target")]
    RootAuthorizationContextRequiresOriginRoot,
    #[error("root API authorization-context review could not be composed safely")]
    ApiVisibilityComposition,
    #[cfg(feature = "authorization-review")]
    #[error("resource authorization review could not be composed safely")]
    AuthorizationReviewComposition,
    #[cfg(feature = "authorization-review")]
    #[error("resource authorization review conflicts with root authorization context")]
    AuthorizationReviewConflict,
    #[cfg(feature = "authorization-review")]
    #[error("resource authorization review requires protected authenticated transport")]
    InsecureAuthorizationReviewTransport,
    #[cfg(feature = "rest-review")]
    #[error("REST review requires OpenAPI review in the same assessment")]
    RestReviewRequiresOpenApiReview,
    #[error(transparent)]
    Standard(#[from] StandardWebDecisionRuntimeError),
    #[error("web assessment failed after it started")]
    RunFailed {
        receipt: Box<WebAssessmentFailureReceipt>,
        #[source]
        source: Box<StandardWebDecisionRuntimeError>,
    },
    #[error("root API authorization-context review failed after it started")]
    ApiVisibilityRunFailed {
        receipt: Box<WebAssessmentFailureReceipt>,
        #[source]
        source: Box<RuntimeApiVisibilityExecutionError>,
    },
    #[error("committed web discovery evidence violated its typed projection contract")]
    ProjectionInvariant {
        receipt: Box<WebAssessmentFailureReceipt>,
    },
}

impl fmt::Debug for WebAssessmentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyStarted => {
                formatter.write_str("WebAssessmentRuntimeError::AlreadyStarted")
            },
            Self::Limits(_) => formatter.write_str("WebAssessmentRuntimeError::Limits(<redacted>)"),
            Self::SemanticLimits(_) => {
                formatter.write_str("WebAssessmentRuntimeError::SemanticLimits(<redacted>)")
            },
            Self::Http(_) => formatter.write_str("WebAssessmentRuntimeError::Http(<redacted>)"),
            Self::InvalidCanonicalTarget => {
                formatter.write_str("WebAssessmentRuntimeError::InvalidCanonicalTarget")
            },
            Self::RootRetentionLimit => {
                formatter.write_str("WebAssessmentRuntimeError::RootRetentionLimit")
            },
            Self::NativeReviewComposition => {
                formatter.write_str("WebAssessmentRuntimeError::NativeReviewComposition")
            },
            Self::RootAuthorizationContextRequiresOriginRoot => formatter
                .write_str("WebAssessmentRuntimeError::RootAuthorizationContextRequiresOriginRoot"),
            Self::ApiVisibilityComposition => {
                formatter.write_str("WebAssessmentRuntimeError::ApiVisibilityComposition")
            },
            #[cfg(feature = "authorization-review")]
            Self::AuthorizationReviewComposition => {
                formatter.write_str("WebAssessmentRuntimeError::AuthorizationReviewComposition")
            },
            #[cfg(feature = "authorization-review")]
            Self::AuthorizationReviewConflict => {
                formatter.write_str("WebAssessmentRuntimeError::AuthorizationReviewConflict")
            },
            #[cfg(feature = "authorization-review")]
            Self::InsecureAuthorizationReviewTransport => formatter
                .write_str("WebAssessmentRuntimeError::InsecureAuthorizationReviewTransport"),
            #[cfg(feature = "rest-review")]
            Self::RestReviewRequiresOpenApiReview => {
                formatter.write_str("WebAssessmentRuntimeError::RestReviewRequiresOpenApiReview")
            },
            Self::Standard(_) => {
                formatter.write_str("WebAssessmentRuntimeError::Standard(<redacted>)")
            },
            Self::RunFailed { receipt, .. } => formatter
                .debug_struct("WebAssessmentRuntimeError::RunFailed")
                .field("receipt", receipt)
                .field("source", &"<redacted>")
                .finish(),
            Self::ApiVisibilityRunFailed { receipt, .. } => formatter
                .debug_struct("WebAssessmentRuntimeError::ApiVisibilityRunFailed")
                .field("receipt", receipt)
                .field("source", &"<redacted>")
                .finish(),
            Self::ProjectionInvariant { receipt } => formatter
                .debug_struct("WebAssessmentRuntimeError::ProjectionInvariant")
                .field("receipt", receipt)
                .finish(),
        }
    }
}

impl WebAssessmentRuntimeError {
    pub fn failure_receipt(&self) -> Option<&WebAssessmentFailureReceipt> {
        match self {
            Self::RunFailed { receipt, .. }
            | Self::ApiVisibilityRunFailed { receipt, .. }
            | Self::ProjectionInvariant { receipt } => Some(receipt),
            _ => None,
        }
    }
}

/// Builder for one bounded exact-origin assessment.
pub struct WebAssessmentRuntimeBuilder {
    target: Url,
    limits: WebAssessmentLimits,
    http_policy: Option<HttpEvidencePolicy>,
    cancellation: CancellationToken,
    defense_enforcement: bool,
    low_risk_differential_review: bool,
    #[cfg(feature = "normalization-resilience")]
    normalization_resilience: bool,
    #[cfg(feature = "graphql-review")]
    graphql_review: bool,
    #[cfg(feature = "authorization-review")]
    resource_authorization_review: Option<(AuthorizationReviewPolicy, AuthorizationPrincipalPair)>,
    #[cfg(feature = "openapi-review")]
    openapi_review: bool,
    #[cfg(feature = "rest-review")]
    rest_review: bool,
    root_authorization_context: Option<WebAssessmentRootAuthorizationContext>,
}

impl WebAssessmentRuntimeBuilder {
    pub fn new(target: Url) -> Self {
        Self {
            target,
            limits: WebAssessmentLimits::default(),
            http_policy: None,
            cancellation: CancellationToken::new(),
            defense_enforcement: false,
            low_risk_differential_review: false,
            #[cfg(feature = "normalization-resilience")]
            normalization_resilience: false,
            #[cfg(feature = "graphql-review")]
            graphql_review: false,
            #[cfg(feature = "authorization-review")]
            resource_authorization_review: None,
            #[cfg(feature = "openapi-review")]
            openapi_review: false,
            #[cfg(feature = "rest-review")]
            rest_review: false,
            root_authorization_context: None,
        }
    }
    pub fn limits(mut self, limits: WebAssessmentLimits) -> Self {
        self.limits = limits;
        self
    }
    pub fn http_policy(mut self, policy: HttpEvidencePolicy) -> Self {
        self.http_policy = Some(policy);
        self
    }
    pub fn cancellation_token(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }
    /// Explicitly enables monotonic defense suppression. Default is observation-only.
    pub fn enable_defense_enforcement(mut self) -> Self {
        self.defense_enforcement = true;
        self
    }
    /// Enables the closed, low-risk matched review catalog after discovery.
    ///
    /// The default assessment remains discovery/passive only. Enabling this
    /// option cannot widen origin authority or create another request budget;
    /// every review leg is composed through the assessment's shared broker.
    pub fn enable_low_risk_differential_review(mut self) -> Self {
        self.low_risk_differential_review = true;
        self
    }
    /// Explicitly enables the bounded normalization-resilience child review.
    ///
    /// This policy is separate from the stable scan-profile wire contract. It
    /// can consume only an already-committed, candidate-specific defensive
    /// transition from an enabled structural review and shares that review's
    /// exact-origin broker, cancellation token, and runtime budget.
    #[cfg(feature = "normalization-resilience")]
    pub fn enable_normalization_resilience(mut self) -> Self {
        self.normalization_resilience = true;
        self
    }
    /// Explicitly enables one bounded, anonymous GraphQL surface review.
    ///
    /// The child is separate from the stable scan-profile wire contract. It
    /// uses only scanner-owned POST bodies, the existing exact-origin broker,
    /// and the assessment's shared request and active-verification budget.
    #[cfg(feature = "graphql-review")]
    pub fn enable_graphql_review(mut self) -> Self {
        self.graphql_review = true;
        self
    }
    /// Explicitly enables one exact-origin OpenAPI JSON document/replay review.
    #[cfg(feature = "openapi-review")]
    pub fn enable_openapi_review(mut self) -> Self {
        self.openapi_review = true;
        self
    }
    /// Explicitly enables one OpenAPI-constrained anonymous REST GET/replay.
    ///
    /// Build rejects this option unless OpenAPI review is enabled for the same
    /// assessment. Catalog knowledge constrains selection but grants no
    /// independent transport authority.
    #[cfg(feature = "rest-review")]
    pub fn enable_rest_review(mut self) -> Self {
        self.rest_review = true;
        self
    }
    /// Adds one explicitly selected, four-view resource authorization review.
    ///
    /// The policy and move-only principals are consumed by this builder. The
    /// child remains part of this assessment's exact-origin authority and
    /// cannot create a separately finalized report.
    #[cfg(feature = "authorization-review")]
    pub fn with_resource_authorization_review(
        mut self,
        policy: AuthorizationReviewPolicy,
        principals: AuthorizationPrincipalPair,
    ) -> Self {
        self.resource_authorization_review = Some((policy, principals));
        self
    }
    /// Adds one anonymous/authorized JSON comparison for the exact origin root.
    ///
    /// The context is consumed during build and can neither be cloned nor
    /// serialized. Both requests share the assessment's broker, cancellation,
    /// deadline, and global budget.
    pub fn with_root_authorization_context(
        mut self,
        context: WebAssessmentRootAuthorizationContext,
    ) -> Self {
        self.root_authorization_context = Some(context);
        self
    }
    pub fn build(self) -> Result<WebAssessmentRuntime, WebAssessmentRuntimeError> {
        #[cfg(feature = "rest-review")]
        if self.rest_review && !self.openapi_review {
            return Err(WebAssessmentRuntimeError::RestReviewRequiresOpenApiReview);
        }
        #[cfg(feature = "authorization-review")]
        if self.root_authorization_context.is_some() && self.resource_authorization_review.is_some()
        {
            return Err(WebAssessmentRuntimeError::AuthorizationReviewConflict);
        }
        if self.root_authorization_context.is_some()
            && (!self.target.username().is_empty()
                || self.target.password().is_some()
                || self.target.path() != "/"
                || self.target.query().is_some()
                || self.target.fragment().is_some())
        {
            return Err(WebAssessmentRuntimeError::RootAuthorizationContextRequiresOriginRoot);
        }
        let semantic_limits = assessment_semantic_limits(self.limits)?;
        // Validate credentials and the HTTP(S) scheme before removing query
        // values from the root. The query-free URL is the only representation
        // that is dispatched or retained by this opt-in runtime.
        HttpProbe::new(self.target.clone(), HttpProbeMethod::Get)?;
        let root = canonicalize_root(&self.target, self.limits)
            .ok_or(WebAssessmentRuntimeError::InvalidCanonicalTarget)?;
        #[cfg(feature = "authorization-review")]
        if self
            .resource_authorization_review
            .as_ref()
            .is_some_and(|(policy, _)| {
                !authenticated_transport_is_allowed(&root.url)
                    || !authenticated_transport_is_allowed(policy.execution_resource())
            })
        {
            return Err(WebAssessmentRuntimeError::InsecureAuthorizationReviewTransport);
        }
        if root.url.as_str().len() > self.limits.max_retained_url_bytes() {
            return Err(WebAssessmentRuntimeError::RootRetentionLimit);
        }
        let policy = match self.http_policy {
            Some(policy) => policy,
            None => HttpEvidencePolicy::for_origin(root.url.clone())?,
        }
        .restricted_for_web_assessment(&root.url, self.limits.max_response_body_bytes())?;
        let discovery_policy = policy.clone();
        let optional_active_verifications = {
            let allowance = 0_u16;
            #[cfg(feature = "graphql-review")]
            let allowance = allowance
                .checked_add(
                    u16::from(
                        self.graphql_review
                            && self.limits.max_active_verifications()
                                == DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS,
                    ) * GRAPHQL_REVIEW_ACTIVE_VERIFICATION_ALLOWANCE,
                )
                .expect("compiled GraphQL allowance fits u16");
            #[cfg(feature = "authorization-review")]
            let allowance = allowance
                .checked_add(
                    u16::from(
                        self.resource_authorization_review.is_some()
                            && self.limits.max_active_verifications()
                                == DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS,
                    ) * AUTHORIZATION_REVIEW_ACTIVE_VERIFICATION_ALLOWANCE,
                )
                .expect("compiled authorization allowance fits u16");
            #[cfg(feature = "openapi-review")]
            let allowance = allowance
                .checked_add(
                    u16::from(
                        self.openapi_review
                            && self.limits.max_active_verifications()
                                == DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS,
                    ) * u16::try_from(MAX_OPENAPI_REVIEW_ACTIVE_VERIFICATIONS)
                        .expect("OpenAPI active-verification allowance fits u16"),
                )
                .expect("compiled OpenAPI allowance fits u16");
            #[cfg(feature = "rest-review")]
            let allowance = allowance
                .checked_add(
                    u16::from(
                        self.rest_review
                            && self.limits.max_active_verifications()
                                == DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS,
                    ) * u16::try_from(MAX_REST_REVIEW_ACTIVE_VERIFICATIONS)
                        .expect("REST active-verification allowance fits u16"),
                )
                .expect("compiled REST allowance fits u16");
            allowance
        };
        let runtime_active_verification_limit = self
            .limits
            .max_active_verifications()
            .checked_add(optional_active_verifications)
            .expect("compiled optional active-verification allowances fit u16");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root.url,
            policy,
            self.limits.runtime_budget(optional_active_verifications),
            self.cancellation,
        )?;
        let root_subject = WebAssessmentSubject {
            url: root.url.clone(),
            method: WebAssessmentMethod::Get,
            depth: 0,
            origin: WebAssessmentSubjectOrigin::AuthorizedRoot,
            query_parameter_names: root.query_parameter_names,
            evidence_ids: Vec::new(),
        };
        let root_api_visibility = self
            .root_authorization_context
            .map(|context| {
                let resource_scope = EntityId::new(format!("endpoint:{}", root.url))
                    .map_err(|_| WebAssessmentRuntimeError::ApiVisibilityComposition)?;
                build_root_api_visibility_runtime(
                    &root.url,
                    resource_scope,
                    authority.clone(),
                    context,
                )
                .map_err(|_| WebAssessmentRuntimeError::ApiVisibilityComposition)
            })
            .transpose()?;
        #[cfg(feature = "authorization-review")]
        let resource_authorization_review = self
            .resource_authorization_review
            .map(|(policy, principals)| ResourceAuthorizationReviewConfig::new(policy, principals));
        let native_review = if self.low_risk_differential_review {
            let seeds = NativeWebReviewSeeds::from_authorized_origin(&root.url)?;
            let redirect_query_parameter =
                select_redirect_review_query_parameter(&root_subject.query_parameter_names);
            let sql_query_parameter =
                select_sql_review_query_parameter(&root_subject.query_parameter_names);
            let ssti_query_parameter =
                select_ssti_review_query_parameter(&root_subject.query_parameter_names);
            let reflection_query_parameter =
                select_reflection_review_query_parameter(&root_subject.query_parameter_names);
            let observer = Arc::new(
                AssessmentReviewObserverSet::new_with_sql(
                    root.url.clone(),
                    seeds.clone(),
                    redirect_query_parameter.as_deref(),
                    reflection_query_parameter.as_deref(),
                    sql_query_parameter.as_deref(),
                    ssti_query_parameter.as_deref(),
                )
                .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?,
            );
            let ledger = CommittedAssessmentReviewLedger::new_with_sql(
                root.url.clone(),
                seeds.clone(),
                redirect_query_parameter.as_deref(),
                reflection_query_parameter.as_deref(),
                sql_query_parameter.as_deref(),
                ssti_query_parameter.as_deref(),
            )
            .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
            Some(AssessmentNativeReviewRuntime {
                target: root.url.clone(),
                seeds,
                enabled_actions: enabled_native_web_review_actions(
                    true,
                    redirect_query_parameter.is_some(),
                    reflection_query_parameter.is_some(),
                    sql_query_parameter.is_some(),
                    ssti_query_parameter.is_some(),
                    None,
                ),
                redirect_query_parameter,
                reflection_query_parameter,
                sql_query_parameter,
                ssti_query_parameter,
                observer,
                ledger,
            })
        } else {
            None
        };
        let ledger = AssessmentLedger::new(&root_subject);
        let mut initial_reasons = BTreeSet::new();
        if root.query_name_limit_reached {
            initial_reasons.insert(WebAssessmentIncompleteReason::QueryParameterNameLimit);
        }
        Ok(WebAssessmentRuntime {
            limits: self.limits,
            runtime_active_verification_limit,
            runtime_optional_active_verification_allowance: optional_active_verifications,
            semantic_limits,
            semantic_evidence: AssessmentSemanticEvidence::default(),
            authority,
            discovery_policy,
            ledger,
            root: root_subject,
            initial_reasons,
            started: false,
            defense_enforcement: self.defense_enforcement,
            #[cfg(feature = "normalization-resilience")]
            normalization_resilience: self.normalization_resilience,
            #[cfg(feature = "graphql-review")]
            graphql_review: self.graphql_review,
            #[cfg(feature = "authorization-review")]
            resource_authorization_review,
            #[cfg(feature = "openapi-review")]
            openapi_review: self.openapi_review.then(|| {
                OpenApiReviewConfig::new(
                    select_openapi_candidate(&root.url, []).expect("fixed exact-origin fallback"),
                )
            }),
            #[cfg(feature = "rest-review")]
            rest_review: self.rest_review,
            native_review,
            non_root_structural_review: None,
            xss_structural_review: None,
            #[cfg(feature = "normalization-resilience")]
            normalization_review: None,
            root_api_visibility,
            committed_api_visibility: None,
            #[cfg(feature = "graphql-review")]
            committed_graphql_review: None,
            #[cfg(feature = "authorization-review")]
            committed_resource_authorization_review: None,
            #[cfg(feature = "authorization-review")]
            authorization_review_audit: None,
            #[cfg(feature = "openapi-review")]
            committed_openapi_review: None,
            #[cfg(feature = "openapi-review")]
            openapi_review_audit: None,
            #[cfg(feature = "rest-review")]
            committed_rest_review: None,
            #[cfg(feature = "rest-review")]
            rest_review_audit: None,
            #[cfg(feature = "graphql-review")]
            optional_child_parent_defense: None,
            defense_audit: WebAssessmentDefenseAudit::new(if self.defense_enforcement {
                WebAssessmentDefenseMode::Enforced
            } else {
                WebAssessmentDefenseMode::ObservationOnly
            }),
            passive_ledger: CommittedAssessmentPassiveLedger::default(),
        })
    }
}

/// Single-use deterministic assessment of one authorized exact origin.
pub struct WebAssessmentRuntime {
    limits: WebAssessmentLimits,
    runtime_active_verification_limit: u16,
    runtime_optional_active_verification_allowance: u16,
    semantic_limits: SemanticExtractionLimits,
    semantic_evidence: AssessmentSemanticEvidence,
    authority: SharedWebRuntimeAuthority,
    discovery_policy: HttpEvidencePolicy,
    ledger: AssessmentLedger,
    root: WebAssessmentSubject,
    initial_reasons: BTreeSet<WebAssessmentIncompleteReason>,
    started: bool,
    defense_enforcement: bool,
    #[cfg(feature = "normalization-resilience")]
    normalization_resilience: bool,
    #[cfg(feature = "graphql-review")]
    graphql_review: bool,
    #[cfg(feature = "authorization-review")]
    resource_authorization_review: Option<ResourceAuthorizationReviewConfig>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<OpenApiReviewConfig>,
    #[cfg(feature = "rest-review")]
    rest_review: bool,
    native_review: Option<AssessmentNativeReviewRuntime>,
    non_root_structural_review: Option<AssessmentNativeReviewRuntime>,
    xss_structural_review: Option<AssessmentNativeReviewRuntime>,
    #[cfg(feature = "normalization-resilience")]
    normalization_review: Option<AssessmentNativeReviewRuntime>,
    root_api_visibility: Option<RootApiVisibilityRuntime>,
    committed_api_visibility: Option<CommittedAssessmentApiVisibility>,
    #[cfg(feature = "graphql-review")]
    committed_graphql_review: Option<CommittedGraphqlReview>,
    #[cfg(feature = "authorization-review")]
    committed_resource_authorization_review: Option<CommittedResourceAuthorizationReview>,
    #[cfg(feature = "openapi-review")]
    committed_openapi_review: Option<CommittedOpenApiReview>,
    #[cfg(feature = "authorization-review")]
    authorization_review_audit: Option<WebAssessmentAuthorizationAudit>,
    #[cfg(feature = "openapi-review")]
    openapi_review_audit: Option<WebAssessmentOpenApiAudit>,
    #[cfg(feature = "rest-review")]
    committed_rest_review: Option<CommittedRestReview>,
    #[cfg(feature = "rest-review")]
    rest_review_audit: Option<WebAssessmentRestAudit>,
    #[cfg(feature = "graphql-review")]
    optional_child_parent_defense: Option<AssessmentDefenseController>,
    defense_audit: WebAssessmentDefenseAudit,
    passive_ledger: CommittedAssessmentPassiveLedger,
}

struct AssessmentNativeReviewRuntime {
    target: Url,
    seeds: NativeWebReviewSeeds,
    redirect_query_parameter: Option<String>,
    reflection_query_parameter: Option<String>,
    sql_query_parameter: Option<String>,
    ssti_query_parameter: Option<String>,
    observer: Arc<AssessmentReviewObserverSet>,
    ledger: CommittedAssessmentReviewLedger,
    enabled_actions: Vec<NativeWebReviewActionKind>,
}

struct FailedSubjectBoundary {
    subject: WebAssessmentSubject,
    envelope: AssessmentEnvelope,
    source: StandardWebDecisionRuntimeError,
    started: bool,
    defense: Option<AssessmentDefenseController>,
    planner: Option<crate::AttackPlanner>,
}

fn receipt_requires_defense_projection(receipt: &DecisionEvidenceReceipt) -> bool {
    receipt.case().action_id() != StandardWebActionKind::LaravelInputAnalysis.action_id()
}

fn replay_defense_parts(
    bootstrap: Option<&DecisionEvidenceReceipt>,
    turns: &[StandardWebDecisionRuntimeTurn],
    unverified: Option<&DecisionEvidenceReceipt>,
    planner: &crate::AttackPlanner,
    knowledge: &KnowledgeBase,
    enforcement_enabled: bool,
) -> Result<AssessmentDefenseController, ()> {
    let mut replay = AssessmentDefenseController::new(enforcement_enabled);
    if let Some(receipt) = bootstrap {
        replay.ingest_receipt(receipt, knowledge, true)?;
    }
    for turn in turns {
        match turn {
            StandardWebDecisionRuntimeTurn::Planning(report) => {
                replay.record_shadow(report, planner)?;
            },
            StandardWebDecisionRuntimeTurn::Outcome { evidence, .. } => {
                replay.ingest_receipt(
                    evidence,
                    knowledge,
                    receipt_requires_defense_projection(evidence),
                )?;
            },
        }
    }
    if let Some(receipt) = unverified {
        replay.ingest_receipt(
            receipt,
            knowledge,
            receipt_requires_defense_projection(receipt),
        )?;
    }
    Ok(replay)
}

fn replay_standard_defense(
    report: &crate::StandardWebDecisionRunReport,
    planner: &crate::AttackPlanner,
    knowledge: &KnowledgeBase,
    enforcement_enabled: bool,
) -> Result<AssessmentDefenseController, ()> {
    replay_defense_parts(
        report.bootstrap(),
        report.turns(),
        report.unverified_evidence(),
        planner,
        knowledge,
        enforcement_enabled,
    )
}

#[cfg(test)]
fn is_native_review_action(action_id: &str) -> bool {
    NativeWebReviewActionKind::all()
        .into_iter()
        .any(|kind| kind.action_id() == action_id)
}

fn replay_native_review(
    report: &crate::StandardWebDecisionRunReport,
    review: &mut AssessmentNativeReviewRuntime,
    knowledge: &KnowledgeBase,
) -> Result<bool, ()> {
    for turn in report.turns() {
        if let StandardWebDecisionRuntimeTurn::Outcome { evidence, decision } = turn {
            if review
                .enabled_actions
                .iter()
                .any(|kind| kind.action_id() == evidence.case().action_id())
            {
                review
                    .ledger
                    .ingest_outcome(evidence, decision, knowledge)
                    .map_err(|_| ())?;
            }
        }
    }

    let enabled_complete = review
        .enabled_actions
        .iter()
        .copied()
        .all(|kind| review.ledger.pair_is_complete(kind));
    let expected_observations = review.enabled_actions.len() * 2;
    Ok(enabled_complete
        && !review.ledger.has_incomplete_reflection_observation()
        && !review.ledger.has_incomplete_sql_observation()
        && !review.ledger.has_incomplete_ssti_observation()
        && review.ledger.observations().len() == expected_observations)
}

impl WebAssessmentRuntime {
    pub fn builder(target: Url) -> WebAssessmentRuntimeBuilder {
        WebAssessmentRuntimeBuilder::new(target)
    }
    pub fn limits(&self) -> WebAssessmentLimits {
        self.limits
    }
    pub fn authorized_root(&self) -> &WebAssessmentSubject {
        &self.root
    }
    pub fn knowledge(&self) -> &KnowledgeBase {
        self.authority.knowledge()
    }
    pub fn cancellation_token(&self) -> CancellationToken {
        self.authority.cancellation_token()
    }
    pub fn has_started(&self) -> bool {
        self.started
    }

    pub async fn analyze(&mut self) -> Result<WebAssessmentRunReport, WebAssessmentRuntimeError> {
        if self.started {
            return Err(WebAssessmentRuntimeError::AlreadyStarted);
        }
        self.started = true;
        let child_authority = self.authority.clone();
        let compose_child = |builder: super::StandardWebDecisionRuntimeBuilder| {
            builder.build_with_shared_authority(child_authority.clone())
        };
        #[cfg(feature = "reporting")]
        let run_started_at = SystemTime::now();
        let timing = self.authority.start();
        let started_at = timing.started_at();
        let mut reasons = self.initial_reasons.clone();
        let mut forms = Vec::new();
        let mut subject_reports = Vec::new();
        let mut known_subjects = BTreeMap::from([(self.root.url.to_string(), self.root.clone())]);
        let mut current_layer = vec![self.root.clone()];
        let mut stop = false;

        while !current_layer.is_empty() && !stop {
            current_layer.sort_by(|left, right| left.url.as_str().cmp(right.url.as_str()));
            let mut next_candidates = BTreeMap::<String, PendingRoute>::new();
            for queued_subject in current_layer.drain(..) {
                let subject = known_subjects
                    .get(queued_subject.url.as_str())
                    .cloned()
                    .unwrap_or(queued_subject);
                if self.authority.cancellation().is_cancelled() {
                    reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
                    stop = true;
                    break;
                }
                if started_at.elapsed() >= self.limits.max_wall_time() {
                    reasons.insert(WebAssessmentIncompleteReason::WallTimeLimit);
                    stop = true;
                    break;
                }

                let mut envelope = self.ledger.snapshot(self.limits, subject.depth);
                let Some(current_envelope_subject) =
                    envelope.subjects.get_mut(subject.url.as_str())
                else {
                    return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                        receipt: Box::new(self.failure_receipt(
                            &known_subjects,
                            subject_reports,
                            forms,
                            WebAssessmentSubjectReport::failed(
                                subject,
                                StandardWebDecisionAssessmentFailureParts::default(),
                                false,
                            ),
                            failed_reasons(&reasons),
                            started_at,
                        )),
                    });
                };
                current_envelope_subject.executed = true;
                if subject.origin == WebAssessmentSubjectOrigin::Discovered
                    && subject.method == WebAssessmentMethod::Get
                    && self.non_root_structural_review.is_none()
                    && self.native_review.as_ref().is_some_and(|review| {
                        review.sql_query_parameter.is_none()
                            && review.ssti_query_parameter.is_none()
                    })
                {
                    if let Some(parameter) =
                        select_sql_review_query_parameter(&subject.query_parameter_names)
                    {
                        let seeds = NativeWebReviewSeeds::from_authorized_origin(&subject.url)?;
                        let observer = Arc::new(
                            AssessmentReviewObserverSet::new_with_sql(
                                subject.url.clone(),
                                seeds.clone(),
                                None,
                                Some(&parameter),
                                Some(&parameter),
                                Some(&parameter),
                            )
                            .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?,
                        );
                        let ledger = CommittedAssessmentReviewLedger::new_with_sql(
                            subject.url.clone(),
                            seeds.clone(),
                            None,
                            Some(&parameter),
                            Some(&parameter),
                            Some(&parameter),
                        )
                        .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
                        self.non_root_structural_review = Some(AssessmentNativeReviewRuntime {
                            target: subject.url.clone(),
                            seeds,
                            enabled_actions: enabled_native_web_review_actions(
                                false, false, true, true, true, None,
                            ),
                            redirect_query_parameter: None,
                            reflection_query_parameter: Some(parameter.clone()),
                            sql_query_parameter: Some(parameter),
                            ssti_query_parameter: select_ssti_review_query_parameter(
                                &subject.query_parameter_names,
                            ),
                            observer,
                            ledger,
                        });
                    }
                }
                let subject_observer: Arc<dyn CompleteHttpResponseObserver> =
                    Arc::new(AssessmentDiscoveryObserver::new(
                        self.discovery_policy.clone(),
                        self.limits,
                        envelope.clone(),
                        &subject,
                        self.authority.cancellation_token(),
                        timing.deadline(),
                    ));
                let builder = StandardWebDecisionRuntime::builder(subject.url.clone())
                    .with_assessment_response_observer(
                        subject.method.probe_method(),
                        subject_observer,
                    )
                    .with_assessment_defense_enforcement(self.defense_enforcement);
                let builder = if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot {
                    match self.native_review.as_ref() {
                        Some(review) => {
                            let observer: Arc<dyn CompleteHttpResponseObserver> =
                                review.observer.clone();
                            builder.with_native_web_review(
                                review.seeds.clone(),
                                observer,
                                review.redirect_query_parameter.clone(),
                                review.reflection_query_parameter.clone(),
                                review.sql_query_parameter.clone(),
                                review.ssti_query_parameter.clone(),
                            )
                        },
                        None => builder,
                    }
                } else if let Some(review) = self
                    .non_root_structural_review
                    .as_ref()
                    .filter(|review| review.target == subject.url)
                {
                    let observer: Arc<dyn CompleteHttpResponseObserver> = review.observer.clone();
                    builder.with_native_structural_review(
                        review.seeds.clone(),
                        observer,
                        review.sql_query_parameter.clone(),
                        review.ssti_query_parameter.clone(),
                        review.reflection_query_parameter.clone(),
                    )
                } else {
                    builder
                };
                #[cfg(feature = "authorization-review")]
                let builder = if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot {
                    match self.resource_authorization_review.take() {
                        Some(config) => builder.with_resource_authorization_review(config),
                        None => builder,
                    }
                } else {
                    builder
                };
                #[cfg(feature = "openapi-review")]
                let builder = if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot {
                    match self.openapi_review.take() {
                        Some(config) => builder.with_openapi_review(config),
                        None => builder,
                    }
                } else {
                    builder
                };
                #[cfg(feature = "rest-review")]
                let builder = if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot
                    && self.rest_review
                {
                    builder.with_rest_review()
                } else {
                    builder
                };
                let mut runtime = match compose_child(builder) {
                    Ok(runtime) => runtime,
                    Err(source) => {
                        return Err(self.run_failed(
                            &mut known_subjects,
                            subject_reports,
                            forms,
                            FailedSubjectBoundary {
                                subject,
                                envelope,
                                source,
                                started: false,
                                defense: None,
                                planner: None,
                            },
                            &reasons,
                            started_at,
                        ));
                    },
                };
                if self.ledger.mark_executed(&subject).is_err() {
                    return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                        receipt: Box::new(self.failure_receipt(
                            &known_subjects,
                            subject_reports,
                            forms,
                            WebAssessmentSubjectReport::failed(
                                subject,
                                StandardWebDecisionAssessmentFailureParts::default(),
                                false,
                            ),
                            failed_reasons(&reasons),
                            started_at,
                        )),
                    });
                }
                let standard_result = runtime.analyze().await;
                #[cfg(feature = "authorization-review")]
                let resource_authorization_binding = runtime.take_resource_authorization_review();
                #[cfg(feature = "openapi-review")]
                let openapi_binding = runtime.take_openapi_review();
                #[cfg(feature = "rest-review")]
                let rest_binding = runtime.take_rest_review();
                let defense = runtime.assessment_defense_controller().cloned();
                let planner = runtime.assessment_planner().clone();
                let standard = match standard_result {
                    Ok(report) => report,
                    Err(source) => {
                        return Err(self.run_failed(
                            &mut known_subjects,
                            subject_reports,
                            forms,
                            FailedSubjectBoundary {
                                subject,
                                envelope,
                                source,
                                started: true,
                                defense,
                                planner: Some(planner),
                            },
                            &reasons,
                            started_at,
                        ));
                    },
                };
                let replay = replay_standard_defense(
                    &standard,
                    &planner,
                    self.authority.knowledge(),
                    self.defense_enforcement,
                );
                let defense_valid = match (defense.as_ref(), replay) {
                    (Some(expected), Ok(replayed)) if replayed.exact_audit_eq(expected) => {
                        #[cfg(feature = "graphql-review")]
                        if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot {
                            self.optional_child_parent_defense = Some(replayed.clone());
                        }
                        self.defense_audit.append_controller(&replayed).is_ok()
                    },
                    _ => false,
                };
                if !defense_valid {
                    let parts = standard.into_assessment_parts();
                    return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                        receipt: Box::new(self.failure_receipt(
                            &known_subjects,
                            subject_reports,
                            forms,
                            WebAssessmentSubjectReport::complete(subject, parts),
                            failed_reasons(&reasons),
                            started_at,
                        )),
                    });
                }
                #[cfg(feature = "authorization-review")]
                let mut authorization_hard_stop = false;
                #[cfg(feature = "authorization-review")]
                if let Some(binding) = resource_authorization_binding {
                    let forced_outcome = if self.authority.cancellation().is_cancelled() {
                        Some(AuthorizationReviewOutcome::Cancelled)
                    } else if standard.limit_exceeded().is_some() {
                        Some(AuthorizationReviewOutcome::BudgetExhausted)
                    } else {
                        None
                    };
                    let forced_runtime_limit = standard.limit_exceeded().cloned();
                    match binding.finalize(
                        self.authority.knowledge(),
                        standard.transport(),
                        forced_outcome,
                        forced_runtime_limit,
                    ) {
                        Ok(ResourceAuthorizationRuntimeResult::Complete(committed)) => {
                            let committed = *committed;
                            self.authorization_review_audit = Some(committed.audit().clone());
                            self.committed_resource_authorization_review = Some(committed);
                        },
                        Ok(ResourceAuthorizationRuntimeResult::Stopped {
                            audit,
                            runtime_limit,
                        }) => {
                            let outcome = audit.outcome();
                            self.authorization_review_audit = Some(audit);
                            authorization_hard_stop = true;
                            if let Some(limit) = runtime_limit {
                                reasons.insert(reason_for_runtime_dimension(limit.dimension()));
                            }
                            if outcome == AuthorizationReviewOutcome::Cancelled {
                                reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
                            }
                            reasons.insert(
                                WebAssessmentIncompleteReason::AuthorizationReviewIncomplete,
                            );
                        },
                        Err(_) => {
                            let parts = standard.into_assessment_parts();
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    subject_reports,
                                    forms,
                                    WebAssessmentSubjectReport::complete(subject, parts),
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        },
                    }
                }
                #[cfg(feature = "openapi-review")]
                if let Some(binding) = openapi_binding {
                    let forced_outcome = if self.authority.cancellation().is_cancelled() {
                        Some(OpenApiRuntimeOutcome::Cancelled)
                    } else if standard.limit_exceeded().is_some() {
                        Some(OpenApiRuntimeOutcome::BudgetExhausted)
                    } else {
                        None
                    };
                    let forced_runtime_limit = standard.limit_exceeded().cloned();
                    match binding.finalize(
                        self.authority.knowledge(),
                        standard.transport(),
                        forced_outcome,
                        forced_runtime_limit,
                    ) {
                        Ok(OpenApiRuntimeResult::Complete(committed)) => {
                            self.openapi_review_audit = Some(committed.audit().clone());
                            self.committed_openapi_review = Some(committed);
                        },
                        Ok(OpenApiRuntimeResult::Stopped {
                            audit,
                            runtime_limit,
                        }) => {
                            let outcome = audit.outcome();
                            self.openapi_review_audit = Some(audit);
                            if let Some(limit) = runtime_limit {
                                reasons.insert(reason_for_runtime_dimension(limit.dimension()));
                            }
                            if outcome == OpenApiRuntimeOutcome::Cancelled {
                                reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
                            }
                            reasons.insert(WebAssessmentIncompleteReason::OpenApiReviewIncomplete);
                        },
                        Err(_) => {
                            let parts = standard.into_assessment_parts();
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    subject_reports,
                                    forms,
                                    WebAssessmentSubjectReport::complete(subject, parts),
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        },
                    }
                }
                #[cfg(feature = "rest-review")]
                if let Some(binding) = rest_binding {
                    let forced_outcome = if self.authority.cancellation().is_cancelled() {
                        Some(RestRuntimeOutcome::Cancelled)
                    } else if standard.limit_exceeded().is_some() {
                        Some(RestRuntimeOutcome::BudgetExhausted)
                    } else {
                        None
                    };
                    let forced_runtime_limit = standard.limit_exceeded().cloned();
                    match binding.finalize(
                        self.authority.knowledge(),
                        standard.transport(),
                        forced_outcome,
                        forced_runtime_limit,
                    ) {
                        Ok(RestRuntimeResult::Complete(committed)) => {
                            self.rest_review_audit = Some(committed.audit().clone());
                            self.committed_rest_review = Some(committed);
                        },
                        Ok(RestRuntimeResult::Stopped {
                            audit,
                            runtime_limit,
                        }) => {
                            let outcome = audit.outcome();
                            self.rest_review_audit = Some(audit);
                            if let Some(limit) = runtime_limit {
                                reasons.insert(reason_for_runtime_dimension(limit.dimension()));
                            }
                            if outcome == RestRuntimeOutcome::Cancelled {
                                reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
                            }
                            reasons.insert(WebAssessmentIncompleteReason::RestReviewIncomplete);
                        },
                        Err(_) => {
                            let parts = standard.into_assessment_parts();
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    subject_reports,
                                    forms,
                                    WebAssessmentSubjectReport::complete(subject, parts),
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        },
                    }
                }
                let selected_review =
                    if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot {
                        self.native_review.as_mut()
                    } else {
                        self.non_root_structural_review
                            .as_mut()
                            .filter(|review| review.target == subject.url)
                    };
                #[cfg(feature = "authorization-review")]
                let allow_structural_followup = !authorization_hard_stop;
                #[cfg(not(feature = "authorization-review"))]
                let allow_structural_followup = true;
                let mut pending_xss_review = None;
                #[cfg(feature = "normalization-resilience")]
                let mut pending_normalization_review = None;
                if let Some(review) = selected_review {
                    let native_review_complete =
                        replay_native_review(&standard, review, self.authority.knowledge());
                    match native_review_complete {
                        Ok(true) => {
                            if allow_structural_followup && self.xss_structural_review.is_none() {
                                pending_xss_review = review
                                    .ledger
                                    .xss_selection_inputs()
                                    .into_iter()
                                    .find_map(|input| {
                                        select_xss_probe_families(
                                            input.context,
                                            &input.attribute_source,
                                            &input.javascript_source,
                                        )
                                        .into_iter()
                                        .next()
                                        .map(|selection| {
                                            (
                                                review.target.clone(),
                                                review.seeds.clone(),
                                                input.query_parameter,
                                                input.source_evidence_ids,
                                                selection,
                                            )
                                        })
                                    });
                            }
                        },
                        Ok(false) => {
                            reasons.insert(
                                WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                            );
                        },
                        Err(()) => {
                            let parts = standard.into_assessment_parts();
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    subject_reports,
                                    forms,
                                    WebAssessmentSubjectReport::complete(subject, parts),
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        },
                    }
                }
                if let Some((target, seeds, parameter, source_evidence_ids, selection)) =
                    pending_xss_review
                {
                    let xss_action = selection.action_kind();
                    let observer = Arc::new(
                        AssessmentReviewObserverSet::new_xss_with_source_evidence(
                            target.clone(),
                            seeds.clone(),
                            &parameter,
                            selection.clone(),
                            source_evidence_ids.clone(),
                        )
                        .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?,
                    );
                    let ledger = CommittedAssessmentReviewLedger::new_xss_with_source_evidence(
                        target.clone(),
                        seeds.clone(),
                        &parameter,
                        selection.clone(),
                        source_evidence_ids,
                    )
                    .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
                    let mut review = AssessmentNativeReviewRuntime {
                        target: target.clone(),
                        seeds: seeds.clone(),
                        redirect_query_parameter: None,
                        reflection_query_parameter: None,
                        sql_query_parameter: None,
                        ssti_query_parameter: None,
                        observer: observer.clone(),
                        ledger,
                        enabled_actions: vec![xss_action],
                    };
                    let response_observer: Arc<dyn CompleteHttpResponseObserver> = observer;
                    let xss_builder = StandardWebDecisionRuntime::builder(target)
                        .with_native_xss_structural_review(
                            seeds,
                            response_observer,
                            parameter,
                            selection,
                        )
                        .with_assessment_defense_enforcement(self.defense_enforcement);
                    let mut xss_runtime = compose_child(xss_builder)?;
                    let xss_result = xss_runtime.analyze().await;
                    let xss_defense = xss_runtime.assessment_defense_controller().cloned();
                    let xss_planner = xss_runtime.assessment_planner().clone();
                    match xss_result {
                        Ok(xss_report) => {
                            let replay = replay_standard_defense(
                                &xss_report,
                                &xss_planner,
                                self.authority.knowledge(),
                                self.defense_enforcement,
                            );
                            let replayed_defense = match (xss_defense.as_ref(), replay) {
                                (Some(expected), Ok(replayed))
                                    if replayed.exact_audit_eq(expected) =>
                                {
                                    replayed
                                },
                                _ => {
                                    return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                                },
                            };
                            if self
                                .defense_audit
                                .append_controller(&replayed_defense)
                                .is_err()
                            {
                                return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                            }
                            match replay_native_review(
                                &xss_report,
                                &mut review,
                                self.authority.knowledge(),
                            ) {
                                Ok(true) if !review.ledger.has_incomplete_xss_observation() =>
                                {
                                    #[cfg(feature = "normalization-resilience")]
                                    if self.normalization_resilience
                                        && self.normalization_review.is_none()
                                    {
                                        let parent = review
                                            .ledger
                                            .normalization_parent_evidence(
                                                replayed_defense.ledger(),
                                            )
                                            .map_err(|_| {
                                                WebAssessmentRuntimeError::NativeReviewComposition
                                            })?;
                                        if let Some(parent) = parent {
                                            if let Some(selection) = select_normalization_transform(
                                                parent.selection(),
                                                None,
                                            ) {
                                                pending_normalization_review = Some((
                                                    review.target.clone(),
                                                    review.seeds.clone(),
                                                    parent,
                                                    selection,
                                                ));
                                            }
                                        }
                                    }
                                },
                                Ok(_) => {
                                    reasons.insert(
                                        WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                                    );
                                },
                                Err(()) => {
                                    return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                                },
                            }
                        },
                        Err(_) => {
                            reasons.insert(
                                WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                            );
                        },
                    }
                    self.xss_structural_review = Some(review);
                }
                #[cfg(feature = "normalization-resilience")]
                if let Some((target, seeds, parent, selection)) = pending_normalization_review {
                    let observer = Arc::new(
                        AssessmentReviewObserverSet::new_normalization(
                            target.clone(),
                            seeds.clone(),
                            selection.clone(),
                            &parent,
                        )
                        .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?,
                    );
                    let ledger = CommittedAssessmentReviewLedger::new_normalization(
                        target.clone(),
                        seeds.clone(),
                        selection.clone(),
                        &parent,
                    )
                    .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
                    let mut review = AssessmentNativeReviewRuntime {
                        target: target.clone(),
                        seeds: seeds.clone(),
                        redirect_query_parameter: None,
                        reflection_query_parameter: None,
                        sql_query_parameter: None,
                        ssti_query_parameter: None,
                        observer: observer.clone(),
                        ledger,
                        enabled_actions: vec![
                            NativeWebReviewActionKind::NormalizationResilienceQueryPair,
                        ],
                    };
                    let response_observer: Arc<dyn CompleteHttpResponseObserver> = observer;
                    let normalization_builder = StandardWebDecisionRuntime::builder(target)
                        .with_native_normalization_resilience_review(
                            seeds,
                            response_observer,
                            parent.query_parameter().to_owned(),
                            selection,
                        )
                        .with_assessment_defense_enforcement(self.defense_enforcement);
                    let mut normalization_runtime = compose_child(normalization_builder)?;
                    let normalization_result = normalization_runtime.analyze().await;
                    let normalization_defense = normalization_runtime
                        .assessment_defense_controller()
                        .cloned();
                    let normalization_planner = normalization_runtime.assessment_planner().clone();
                    match normalization_result {
                        Ok(normalization_report) => {
                            let replayed_defense = match (
                                normalization_defense.as_ref(),
                                replay_standard_defense(
                                    &normalization_report,
                                    &normalization_planner,
                                    self.authority.knowledge(),
                                    self.defense_enforcement,
                                ),
                            ) {
                                (Some(expected), Ok(replayed))
                                    if replayed.exact_audit_eq(expected) =>
                                {
                                    replayed
                                },
                                _ => {
                                    return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                                },
                            };
                            if self
                                .defense_audit
                                .append_controller(&replayed_defense)
                                .is_err()
                            {
                                return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                            }
                            match replay_native_review(
                                &normalization_report,
                                &mut review,
                                self.authority.knowledge(),
                            ) {
                                Ok(true) => match review
                                    .ledger
                                    .finalize_normalization(replayed_defense.ledger())
                                    .map_err(|_| {
                                        WebAssessmentRuntimeError::NativeReviewComposition
                                    })? {
                                    super::assessment_review::NormalizationReviewOutcome::Incomplete => {
                                        reasons.insert(
                                            WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                                        );
                                    },
                                    super::assessment_review::NormalizationReviewOutcome::SemanticNormalizationGapObserved
                                    | super::assessment_review::NormalizationReviewOutcome::VariantStillBlocked
                                    | super::assessment_review::NormalizationReviewOutcome::VariantAcceptedSemanticsUnknown
                                    | super::assessment_review::NormalizationReviewOutcome::ReplayMismatch => {},
                                },
                                Ok(false) => {
                                    reasons.insert(
                                        WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                                    );
                                },
                                Err(()) => {
                                    return Err(
                                        WebAssessmentRuntimeError::NativeReviewComposition,
                                    );
                                },
                            }
                        },
                        Err(_) => {
                            reasons.insert(
                                WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                            );
                        },
                    }
                    self.normalization_review = Some(review);
                }
                classify_standard_completion(&standard, &mut reasons);
                #[cfg(feature = "authorization-review")]
                if authorization_hard_stop
                    && matches!(
                        standard.terminal(),
                        DecisionLoopCommand::Halt {
                            reason: DecisionStopReason::AdaptationLimit
                        }
                    )
                {
                    // The higher-priority authorization terminal rule uses a
                    // parent-owned Halt directive only to suppress later
                    // actions. Its typed audit already records the target or
                    // transport outcome, so the generic adaptation label would
                    // be synthetic. Real runtime limits remain classified.
                    reasons.remove(&WebAssessmentIncompleteReason::AdaptationLimit);
                }
                let cancelled_at_subject_boundary = self.authority.cancellation().is_cancelled();
                let wall_time_reached_at_subject_boundary =
                    started_at.elapsed() >= self.limits.max_wall_time();
                if cancelled_at_subject_boundary {
                    reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
                }
                if wall_time_reached_at_subject_boundary {
                    reasons.insert(WebAssessmentIncompleteReason::WallTimeLimit);
                }
                let mut should_stop = cancelled_at_subject_boundary
                    || wall_time_reached_at_subject_boundary
                    || standard.limit_exceeded().is_some()
                    || matches!(
                        standard.terminal(),
                        DecisionLoopCommand::Halt {
                            reason: DecisionStopReason::CancelledByHost
                                | DecisionStopReason::RuntimeBudgetLimit
                        }
                    );
                #[cfg(feature = "authorization-review")]
                {
                    should_stop |= authorization_hard_stop;
                }
                let projection = projection_from_committed_bootstrap(
                    standard.bootstrap(),
                    self.authority.knowledge(),
                    &subject,
                    &self.discovery_policy,
                    self.limits,
                    &envelope,
                );
                let parts = standard.into_assessment_parts();
                let subject_report = WebAssessmentSubjectReport::complete(subject.clone(), parts);
                let mut suppress_discovery_projection = false;

                match projection {
                    Ok(projection) => {
                        if self
                            .replay_passive_bootstrap(
                                subject_report.bootstrap(),
                                &subject,
                                &mut reasons,
                            )
                            .is_err()
                        {
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    subject_reports,
                                    forms,
                                    subject_report,
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        }
                        if self
                            .semantic_evidence
                            .commit_bootstrap(
                                subject_report.bootstrap(),
                                self.authority.knowledge(),
                                &subject,
                            )
                            .is_err()
                        {
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    subject_reports,
                                    forms,
                                    subject_report,
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        }
                        if subject.origin == WebAssessmentSubjectOrigin::AuthorizedRoot
                            && !should_stop
                        {
                            let api_visibility_result = match self.root_api_visibility.as_mut() {
                                Some(runtime) => Some(runtime.execute().await),
                                None => None,
                            };
                            if let Some(api_visibility_result) = api_visibility_result {
                                match api_visibility_result {
                                    Ok(RootApiVisibilityOutcome::NoDifference) => {},
                                    Ok(RootApiVisibilityOutcome::NeedsReview(committed)) => {
                                        self.committed_api_visibility = Some(*committed);
                                    },
                                    Ok(RootApiVisibilityOutcome::Incomplete) => {
                                        reasons.insert(
                                            WebAssessmentIncompleteReason::ApiVisibilityReviewIncomplete,
                                        );
                                        should_stop = true;
                                        suppress_discovery_projection = true;
                                    },
                                    Ok(RootApiVisibilityOutcome::Cancelled) => {
                                        reasons.insert(
                                            WebAssessmentIncompleteReason::HostCancellation,
                                        );
                                        should_stop = true;
                                        suppress_discovery_projection = true;
                                    },
                                    Ok(RootApiVisibilityOutcome::RuntimeLimit(dimension)) => {
                                        reasons.insert(reason_for_runtime_dimension(dimension));
                                        should_stop = true;
                                        suppress_discovery_projection = true;
                                    },
                                    Ok(RootApiVisibilityOutcome::ContractMismatch) => {
                                        return Err(
                                            WebAssessmentRuntimeError::ProjectionInvariant {
                                                receipt: Box::new(self.failure_receipt(
                                                    &known_subjects,
                                                    subject_reports,
                                                    forms,
                                                    subject_report,
                                                    failed_reasons(&reasons),
                                                    started_at,
                                                )),
                                            },
                                        );
                                    },
                                    Err(source) => {
                                        return Err(
                                            WebAssessmentRuntimeError::ApiVisibilityRunFailed {
                                                receipt: Box::new(self.failure_receipt(
                                                    &known_subjects,
                                                    subject_reports,
                                                    forms,
                                                    subject_report,
                                                    failed_reasons(&reasons),
                                                    started_at,
                                                )),
                                                source: Box::new(source),
                                            },
                                        );
                                    },
                                }
                            }
                        }
                        if let Some(projection) = projection {
                            projection.add_reasons(&mut reasons);
                            if !suppress_discovery_projection {
                                self.ledger.apply(&projection);
                                forms.extend(projection.forms);
                                for route in projection.routes {
                                    let route_is_pending = self
                                        .ledger
                                        .subject_admission(&route.url)
                                        .is_some_and(|entry| !entry.executed);
                                    if route_is_pending {
                                        if let Some(existing) =
                                            known_subjects.get_mut(route.url.as_str())
                                        {
                                            merge_subject_route(
                                                existing,
                                                &route,
                                                subject.depth + 1,
                                                self.limits.max_query_parameter_names(),
                                            );
                                        } else {
                                            known_subjects.insert(
                                                route.url.to_string(),
                                                WebAssessmentSubject {
                                                    url: route.url.clone(),
                                                    method: route.method,
                                                    depth: subject.depth.saturating_add(1),
                                                    origin: WebAssessmentSubjectOrigin::Discovered,
                                                    query_parameter_names: route
                                                        .query_parameter_names
                                                        .clone(),
                                                    evidence_ids: route.evidence_ids.clone(),
                                                },
                                            );
                                        }
                                    }
                                    merge_pending_route(
                                        &mut next_candidates,
                                        route,
                                        subject.depth + 1,
                                        self.limits.max_query_parameter_names(),
                                    );
                                }
                            }
                        }
                    },
                    Err(()) => {
                        return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                            receipt: Box::new(self.failure_receipt(
                                &known_subjects,
                                subject_reports,
                                forms,
                                subject_report,
                                failed_reasons(&reasons),
                                started_at,
                            )),
                        });
                    },
                }
                subject_reports.push(subject_report);
                if should_stop {
                    stop = true;
                    break;
                }
            }

            for (_, candidate) in next_candidates {
                if let Some(existing) = known_subjects.get_mut(candidate.url.as_str()) {
                    if self
                        .ledger
                        .subject_admission(&candidate.url)
                        .is_some_and(|entry| !entry.executed)
                    {
                        merge_subject_route(
                            existing,
                            &candidate,
                            candidate.depth,
                            self.limits.max_query_parameter_names(),
                        );
                    }
                } else {
                    known_subjects.insert(
                        candidate.url.to_string(),
                        WebAssessmentSubject {
                            url: candidate.url.clone(),
                            method: candidate.method,
                            depth: candidate.depth,
                            origin: WebAssessmentSubjectOrigin::Discovered,
                            query_parameter_names: candidate.query_parameter_names.clone(),
                            evidence_ids: candidate.evidence_ids.clone(),
                        },
                    );
                }
                if !stop
                    && self
                        .ledger
                        .subject_admission(&candidate.url)
                        .is_some_and(|entry| !entry.executed)
                {
                    if let Some(pending) = known_subjects.get(candidate.url.as_str()) {
                        current_layer.push(pending.clone());
                    } else {
                        reasons.insert(WebAssessmentIncompleteReason::SubjectExecutionIncomplete);
                        stop = true;
                    }
                }
            }
            if stop {
                break;
            }
        }

        // Preserve retained-but-unexecuted subjects after a global stop.
        let reported: BTreeSet<_> = subject_reports
            .iter()
            .map(|report| report.subject.url.to_string())
            .collect();
        for subject in known_subjects.values().cloned() {
            if !reported.contains(subject.url.as_str()) {
                subject_reports.push(WebAssessmentSubjectReport::pending(subject));
            }
        }
        subject_reports.sort_by(|left, right| {
            left.subject
                .depth
                .cmp(&right.subject.depth)
                .then_with(|| left.subject.url.as_str().cmp(right.subject.url.as_str()))
        });
        forms.sort_by(|left, right| {
            left.action
                .as_str()
                .cmp(right.action.as_str())
                .then_with(|| left.method.cmp(&right.method))
        });
        match self.reconcile_final_state(&subject_reports, &forms, &known_subjects) {
            Ok(true) => {
                reasons.insert(WebAssessmentIncompleteReason::SubjectExecutionIncomplete);
            },
            Ok(false) => {},
            Err(()) => {
                let current_subject = subject_reports
                    .pop()
                    .unwrap_or_else(|| WebAssessmentSubjectReport::pending(self.root.clone()));
                let completed_subjects = subject_reports
                    .into_iter()
                    .filter(WebAssessmentSubjectReport::was_executed)
                    .collect();
                return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                    receipt: Box::new(self.failure_receipt(
                        &known_subjects,
                        completed_subjects,
                        forms,
                        current_subject,
                        failed_reasons(&reasons),
                        started_at,
                    )),
                });
            },
        }
        #[cfg(feature = "graphql-review")]
        if self.graphql_review {
            if !reasons.is_empty() {
                reasons.insert(WebAssessmentIncompleteReason::GraphqlReviewIncomplete);
            } else {
                let root_subject = EntityId::new(format!("endpoint:{}", self.root.url()))
                    .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
                let parent_defense = self
                    .optional_child_parent_defense
                    .as_ref()
                    .ok_or(WebAssessmentRuntimeError::NativeReviewComposition)?;
                if !parent_defense.permits_optional_interaction(
                    &root_subject,
                    DefenseInteractionClass::DifferentialRead,
                ) {
                    // Enforced standing defense or rate limiting can only
                    // remove this optional child; it never creates a request.
                } else {
                    let hints = graphql_endpoint_hints(
                        self.root.url(),
                        self.authority.knowledge(),
                        subject_reports
                            .iter()
                            .filter(|report| report.was_executed())
                            .map(|report| report.subject().url().clone()),
                        forms.iter().map(|form| form.action().clone()),
                    );
                    match execute_graphql_review(
                        &self.authority,
                        self.root.url(),
                        hints,
                        self.limits.max_response_body_bytes(),
                        self.defense_enforcement,
                    )
                    .await
                    {
                        Ok(GraphqlRuntimeResult::NotEligible) => {},
                        Ok(GraphqlRuntimeResult::Complete(completed)) => {
                            let replayed = completed
                                .replay_defense(
                                    self.authority.knowledge(),
                                    self.defense_enforcement,
                                )
                                .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
                            if !completed.defense().exact_audit_eq(&replayed)
                                || self.defense_audit.append_controller(&replayed).is_err()
                            {
                                return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                            }
                            if completed.review().outcome()
                                == crate::graphql_review::GraphqlReviewOutcome::Incomplete
                            {
                                reasons
                                    .insert(WebAssessmentIncompleteReason::GraphqlReviewIncomplete);
                            } else {
                                self.committed_graphql_review = Some(completed.into_review());
                            }
                        },
                        Ok(GraphqlRuntimeResult::Stopped(stopped)) => {
                            let replayed = stopped
                                .replay_defense(
                                    self.authority.knowledge(),
                                    self.defense_enforcement,
                                )
                                .map_err(|_| WebAssessmentRuntimeError::NativeReviewComposition)?;
                            if !stopped.defense().exact_audit_eq(&replayed)
                                || self.defense_audit.append_controller(&replayed).is_err()
                            {
                                return Err(WebAssessmentRuntimeError::NativeReviewComposition);
                            }
                            match stopped.stop() {
                                GraphqlRuntimeStop::Cancelled => {
                                    reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
                                },
                                GraphqlRuntimeStop::RuntimeLimit(dimension) => {
                                    reasons.insert(reason_for_runtime_dimension(dimension));
                                },
                                GraphqlRuntimeStop::TransportIncomplete => {},
                            }
                            reasons.insert(WebAssessmentIncompleteReason::GraphqlReviewIncomplete);
                        },
                        Err(_) => {
                            let current_subject = subject_reports.pop().unwrap_or_else(|| {
                                WebAssessmentSubjectReport::pending(self.root.clone())
                            });
                            let completed_subjects = subject_reports
                                .into_iter()
                                .filter(WebAssessmentSubjectReport::was_executed)
                                .collect();
                            return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                                receipt: Box::new(self.failure_receipt(
                                    &known_subjects,
                                    completed_subjects,
                                    forms,
                                    current_subject,
                                    failed_reasons(&reasons),
                                    started_at,
                                )),
                            });
                        },
                    }
                }
            }
        }
        #[cfg(not(feature = "normalization-resilience"))]
        let review_ledgers = self
            .native_review
            .iter()
            .chain(self.non_root_structural_review.iter())
            .chain(self.xss_structural_review.iter())
            .map(|review| &review.ledger)
            .collect::<Vec<_>>();
        #[cfg(feature = "normalization-resilience")]
        let review_ledgers = self
            .native_review
            .iter()
            .chain(self.non_root_structural_review.iter())
            .chain(self.xss_structural_review.iter())
            .chain(self.normalization_review.iter())
            .map(|review| &review.ledger)
            .collect::<Vec<_>>();
        let assessment_projection = match project_assessment_items(
            &self.passive_ledger,
            AssessmentReviewProjectionSources {
                native: &review_ledgers,
                api_visibility: self.committed_api_visibility.as_ref(),
                #[cfg(feature = "graphql-review")]
                graphql: self.committed_graphql_review.as_ref(),
                #[cfg(feature = "authorization-review")]
                authorization: self.committed_resource_authorization_review.as_ref(),
                #[cfg(feature = "openapi-review")]
                openapi: self.committed_openapi_review.as_ref(),
                #[cfg(feature = "rest-review")]
                rest: self.committed_rest_review.as_ref(),
            },
            self.authority.knowledge(),
            &self.root,
            &subject_reports
                .iter()
                .map(|report| report.subject().clone())
                .collect::<Vec<_>>(),
        ) {
            Ok(projection) => projection,
            Err(_) => {
                let current_subject = subject_reports
                    .pop()
                    .unwrap_or_else(|| WebAssessmentSubjectReport::pending(self.root.clone()));
                let completed_subjects = subject_reports
                    .into_iter()
                    .filter(WebAssessmentSubjectReport::was_executed)
                    .collect();
                return Err(WebAssessmentRuntimeError::ProjectionInvariant {
                    receipt: Box::new(self.failure_receipt(
                        &known_subjects,
                        completed_subjects,
                        forms,
                        current_subject,
                        failed_reasons(&reasons),
                        started_at,
                    )),
                });
            },
        };
        let (assessment_items, assessment_projection_incompleteness) =
            assessment_projection.into_parts();
        if assessment_projection_incompleteness.is_incomplete() {
            reasons.insert(WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable);
        }
        let semantics = self.extract_semantics_and_refresh_limits(&mut reasons, started_at);
        let usage = self.usage(
            subject_reports.len(),
            subject_reports
                .iter()
                .filter(|report| report.was_executed())
                .count(),
            forms.len(),
            started_at,
        );
        let completion = if reasons.is_empty() {
            WebAssessmentCompletion::Complete
        } else {
            WebAssessmentCompletion::Incomplete { reasons }
        };
        Ok(WebAssessmentRunReport {
            #[cfg(feature = "reporting")]
            run_started_at,
            authorized_root: self.root.clone(),
            limits: self.limits,
            runtime_active_verification_limit: self.runtime_active_verification_limit,
            runtime_optional_active_verification_allowance: self
                .runtime_optional_active_verification_allowance,
            subjects: subject_reports,
            forms,
            semantics,
            defense: self.defense_audit.clone(),
            #[cfg(feature = "authorization-review")]
            authorization_review: self.authorization_review_audit.clone(),
            #[cfg(feature = "openapi-review")]
            openapi_review: self.openapi_review_audit.clone(),
            #[cfg(feature = "rest-review")]
            rest_review: self.rest_review_audit.clone(),
            assessment_items,
            assessment_projection_incompleteness,
            completion,
            usage,
            transport: self.authority.request_accounting().dispatch_audit(),
        })
    }

    fn reconcile_final_state(
        &self,
        subject_reports: &[WebAssessmentSubjectReport],
        forms: &[WebAssessmentForm],
        known_subjects: &BTreeMap<String, WebAssessmentSubject>,
    ) -> Result<bool, ()> {
        let report_subjects: BTreeMap<_, _> = subject_reports
            .iter()
            .map(|report| (report.subject.url.to_string(), report))
            .collect();
        if report_subjects.len() != subject_reports.len()
            || report_subjects.len() != known_subjects.len()
            || report_subjects.len() != self.ledger.subjects.len()
            || report_subjects.keys().ne(self.ledger.subjects.keys())
        {
            return Err(());
        }
        for (url, report) in &report_subjects {
            let admission = self.ledger.subjects.get(url).ok_or(())?;
            if report.was_executed() != admission.executed
                || report.subject.method != admission.method
                || report
                    .subject
                    .query_parameter_names
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    != admission.query_parameter_names
            {
                return Err(());
            }
        }
        let bootstrap_subjects: BTreeSet<_> = subject_reports
            .iter()
            .filter_map(|report| {
                report
                    .bootstrap()
                    .map(|receipt| receipt.case().subject().clone())
            })
            .collect();
        let passive_subjects: BTreeSet<_> = self
            .passive_ledger
            .observations()
            .iter()
            .map(|observation| observation.subject().clone())
            .collect();
        if bootstrap_subjects.len() != self.passive_ledger.observations().len()
            || bootstrap_subjects != passive_subjects
        {
            return Err(());
        }
        let form_identities: BTreeSet<_> = forms
            .iter()
            .map(|form| FormIdentity {
                action: form.action.to_string(),
                method: form.method,
            })
            .collect();
        if form_identities.len() != forms.len() || form_identities != self.ledger.form_identities {
            return Err(());
        }
        let retained_urls: BTreeSet<_> = subject_reports
            .iter()
            .map(|report| report.subject.url.to_string())
            .chain(forms.iter().map(|form| form.action.to_string()))
            .collect();
        let retained_unique_url_bytes = retained_urls.iter().map(String::len).sum::<usize>();
        if retained_urls != self.ledger.retained_urls
            || retained_unique_url_bytes != self.ledger.retained_unique_url_bytes
        {
            return Err(());
        }
        Ok(subject_reports.iter().any(|report| !report.was_executed()))
    }

    fn run_failed(
        &mut self,
        known_subjects: &mut BTreeMap<String, WebAssessmentSubject>,
        completed_subjects: Vec<WebAssessmentSubjectReport>,
        mut forms: Vec<WebAssessmentForm>,
        boundary: FailedSubjectBoundary,
        reasons: &BTreeSet<WebAssessmentIncompleteReason>,
        started_at: tokio::time::Instant,
    ) -> WebAssessmentRuntimeError {
        let FailedSubjectBoundary {
            subject: current_subject,
            envelope,
            source,
            started: subject_started,
            defense,
            planner,
        } = boundary;
        let (parts, source) = source.into_assessment_failure();
        if subject_started {
            let replay = planner.as_ref().and_then(|planner| {
                let mut replay = replay_defense_parts(
                    parts.bootstrap.as_ref(),
                    &parts.turns,
                    None,
                    planner,
                    self.authority.knowledge(),
                    self.defense_enforcement,
                )
                .ok()?;
                if let Some(committed) = source.committed_evidence() {
                    replay
                        .ingest_receipt(
                            committed,
                            self.authority.knowledge(),
                            receipt_requires_defense_projection(committed),
                        )
                        .ok()?;
                }
                Some(replay)
            });
            let defense_valid = match (defense.as_ref(), replay) {
                (Some(expected), Some(replayed)) if replayed.exact_audit_eq(expected) => {
                    self.defense_audit.append_controller(&replayed).is_ok()
                },
                _ => false,
            };
            if !defense_valid {
                let current_report =
                    WebAssessmentSubjectReport::failed(current_subject, parts, true);
                return WebAssessmentRuntimeError::ProjectionInvariant {
                    receipt: Box::new(self.failure_receipt(
                        known_subjects,
                        completed_subjects,
                        forms,
                        current_report,
                        failed_reasons(reasons),
                        started_at,
                    )),
                };
            }
        }
        let projection = projection_from_committed_bootstrap(
            parts.bootstrap.as_ref(),
            self.authority.knowledge(),
            &current_subject,
            &self.discovery_policy,
            self.limits,
            &envelope,
        );
        let current_report =
            WebAssessmentSubjectReport::failed(current_subject.clone(), parts, subject_started);
        let mut incomplete_reasons = failed_reasons(reasons);
        if self.authority.cancellation().is_cancelled() {
            incomplete_reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
        }
        if started_at.elapsed() >= self.limits.max_wall_time() {
            incomplete_reasons.insert(WebAssessmentIncompleteReason::WallTimeLimit);
        }
        match projection {
            Ok(projection) => {
                if self
                    .replay_passive_bootstrap(
                        current_report.bootstrap(),
                        &current_subject,
                        &mut incomplete_reasons,
                    )
                    .is_err()
                {
                    let receipt = self.failure_receipt(
                        known_subjects,
                        completed_subjects,
                        forms,
                        current_report,
                        incomplete_reasons,
                        started_at,
                    );
                    return WebAssessmentRuntimeError::ProjectionInvariant {
                        receipt: Box::new(receipt),
                    };
                }
                if self
                    .semantic_evidence
                    .commit_bootstrap(
                        current_report.bootstrap(),
                        self.authority.knowledge(),
                        &current_subject,
                    )
                    .is_err()
                {
                    let receipt = self.failure_receipt(
                        known_subjects,
                        completed_subjects,
                        forms,
                        current_report,
                        incomplete_reasons,
                        started_at,
                    );
                    return WebAssessmentRuntimeError::ProjectionInvariant {
                        receipt: Box::new(receipt),
                    };
                }
                if let Some(projection) = projection {
                    projection.add_reasons(&mut incomplete_reasons);
                    self.ledger.apply(&projection);
                    forms.extend(projection.forms);
                    for route in projection.routes {
                        if self
                            .ledger
                            .subject_admission(&route.url)
                            .is_some_and(|entry| !entry.executed)
                        {
                            if let Some(existing) = known_subjects.get_mut(route.url.as_str()) {
                                merge_subject_route(
                                    existing,
                                    &route,
                                    current_subject.depth.saturating_add(1),
                                    self.limits.max_query_parameter_names(),
                                );
                            } else {
                                known_subjects.insert(
                                    route.url.to_string(),
                                    WebAssessmentSubject {
                                        url: route.url,
                                        method: route.method,
                                        depth: current_subject.depth.saturating_add(1),
                                        origin: WebAssessmentSubjectOrigin::Discovered,
                                        query_parameter_names: route.query_parameter_names,
                                        evidence_ids: route.evidence_ids,
                                    },
                                );
                            }
                        }
                    }
                }
            },
            Err(()) => {
                let receipt = self.failure_receipt(
                    known_subjects,
                    completed_subjects,
                    forms,
                    current_report,
                    incomplete_reasons,
                    started_at,
                );
                return WebAssessmentRuntimeError::ProjectionInvariant {
                    receipt: Box::new(receipt),
                };
            },
        }
        let receipt = self.failure_receipt(
            known_subjects,
            completed_subjects,
            forms,
            current_report,
            incomplete_reasons,
            started_at,
        );
        if receipt.inventory_consistent() {
            WebAssessmentRuntimeError::RunFailed {
                receipt: Box::new(receipt),
                source: Box::new(source),
            }
        } else {
            WebAssessmentRuntimeError::ProjectionInvariant {
                receipt: Box::new(receipt),
            }
        }
    }

    fn failure_receipt(
        &self,
        known_subjects: &BTreeMap<String, WebAssessmentSubject>,
        completed_subjects: Vec<WebAssessmentSubjectReport>,
        forms: Vec<WebAssessmentForm>,
        current_subject: WebAssessmentSubjectReport,
        mut incomplete_reasons: BTreeSet<WebAssessmentIncompleteReason>,
        started_at: tokio::time::Instant,
    ) -> WebAssessmentFailureReceipt {
        let semantics =
            self.extract_semantics_and_refresh_limits(&mut incomplete_reasons, started_at);
        let completed_urls: BTreeSet<_> = completed_subjects
            .iter()
            .map(|report| report.subject.url.to_string())
            .collect();
        let mut pending_subjects: Vec<_> = known_subjects
            .values()
            .filter(|subject| {
                subject.url != current_subject.subject.url
                    && !completed_urls.contains(subject.url.as_str())
            })
            .cloned()
            .collect();
        pending_subjects.sort_by(|left, right| {
            left.depth
                .cmp(&right.depth)
                .then_with(|| left.url.as_str().cmp(right.url.as_str()))
        });
        let expected_executed: BTreeSet<_> = completed_subjects
            .iter()
            .filter(|report| report.was_executed())
            .map(|report| report.subject.url.to_string())
            .chain(
                current_subject
                    .was_executed()
                    .then(|| current_subject.subject.url.to_string()),
            )
            .collect();
        let unrepresented_ledger_subjects = self
            .ledger
            .subjects
            .keys()
            .filter(|url| !known_subjects.contains_key(url.as_str()))
            .count();
        let known_matches_ledger = known_subjects.len() == self.ledger.subjects.len()
            && known_subjects.iter().all(|(url, subject)| {
                self.ledger.subjects.get(url).is_some_and(|entry| {
                    entry.method == subject.method
                        && entry.query_parameter_names
                            == subject
                                .query_parameter_names
                                .iter()
                                .cloned()
                                .collect::<BTreeSet<_>>()
                        && entry.executed == expected_executed.contains(url)
                })
            });
        let retained_form_identities: BTreeSet<_> = forms
            .iter()
            .map(|form| FormIdentity {
                action: form.action.to_string(),
                method: form.method,
            })
            .collect();
        let inventory_consistent = known_matches_ledger
            && retained_form_identities.len() == forms.len()
            && retained_form_identities == self.ledger.form_identities;
        let executed_subjects = completed_subjects
            .iter()
            .filter(|report| report.was_executed())
            .count()
            .saturating_add(usize::from(current_subject.was_executed()));
        let mut usage = self.usage(
            completed_subjects
                .len()
                .saturating_add(1)
                .saturating_add(pending_subjects.len()),
            executed_subjects,
            forms.len(),
            started_at,
        );
        usage.retained_unique_url_bytes = completed_subjects
            .iter()
            .map(|report| report.subject.url.to_string())
            .chain(std::iter::once(current_subject.subject.url.to_string()))
            .chain(
                pending_subjects
                    .iter()
                    .map(|subject| subject.url.to_string()),
            )
            .chain(forms.iter().map(|form| form.action.to_string()))
            .collect::<BTreeSet<_>>()
            .iter()
            .map(String::len)
            .sum();
        WebAssessmentFailureReceipt {
            completed_subjects,
            pending_subjects,
            forms,
            semantics,
            defense: self.defense_audit.clone(),
            current_subject,
            incomplete_reasons,
            inventory_consistent,
            unrepresented_ledger_subjects,
            committed_passive_observations: self.passive_ledger.observations().len(),
            usage,
            transport: self.authority.request_accounting().dispatch_audit(),
        }
    }

    fn usage(
        &self,
        retained_subjects: usize,
        executed_subjects: usize,
        retained_forms: usize,
        started_at: tokio::time::Instant,
    ) -> WebAssessmentUsage {
        let accounting = self.authority.request_accounting().snapshot();
        WebAssessmentUsage {
            retained_subjects,
            executed_subjects,
            retained_forms,
            retained_unique_url_bytes: self.ledger.retained_unique_url_bytes,
            total_requests: accounting.total_requests(),
            active_verifications: accounting.active_verifications(),
            request_body_bytes: accounting.request_body_bytes(),
            response_bytes: accounting.response_bytes(),
            elapsed_ms: duration_ms(started_at.elapsed()),
        }
    }

    fn extract_semantics_and_refresh_limits(
        &self,
        reasons: &mut BTreeSet<WebAssessmentIncompleteReason>,
        started_at: tokio::time::Instant,
    ) -> SemanticExtractionResult {
        let semantics = self.semantic_evidence.extract(&self.semantic_limits);
        if semantics.truncated {
            reasons.insert(WebAssessmentIncompleteReason::SemanticExtractionLimit);
        }
        if self.authority.cancellation().is_cancelled() {
            reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
        }
        if started_at.elapsed() >= self.limits.max_wall_time() {
            reasons.insert(WebAssessmentIncompleteReason::WallTimeLimit);
        }
        semantics
    }

    fn replay_passive_bootstrap(
        &mut self,
        receipt: Option<&DecisionEvidenceReceipt>,
        expected_subject: &WebAssessmentSubject,
        reasons: &mut BTreeSet<WebAssessmentIncompleteReason>,
    ) -> Result<(), ()> {
        let Some(receipt) = receipt else {
            return Ok(());
        };
        let observation = self.passive_ledger.ingest_receipt(
            receipt,
            self.authority.knowledge(),
            expected_subject,
        )?;
        if observation.is_some_and(|observation| observation.projection_incomplete()) {
            reasons.insert(WebAssessmentIncompleteReason::PassiveResponseProjectionLimit);
        }
        Ok(())
    }
}

fn classify_standard_completion(
    report: &crate::StandardWebDecisionRunReport,
    reasons: &mut BTreeSet<WebAssessmentIncompleteReason>,
) {
    if let Some(limit) = report.limit_exceeded() {
        reasons.insert(reason_for_runtime_dimension(limit.dimension()));
    }
    match report.terminal() {
        DecisionLoopCommand::Complete { .. } => {},
        DecisionLoopCommand::AwaitHumanReview { .. } => {
            reasons.insert(WebAssessmentIncompleteReason::HumanReviewRequired);
        },
        DecisionLoopCommand::Halt { reason } => match reason {
            DecisionStopReason::ObjectiveComplete | DecisionStopReason::NoEligibleAction => {},
            DecisionStopReason::HumanReview => {
                reasons.insert(WebAssessmentIncompleteReason::HumanReviewRequired);
            },
            DecisionStopReason::ActionCycleLimit => {
                reasons.insert(WebAssessmentIncompleteReason::ActionCycleLimit);
            },
            DecisionStopReason::AdaptationLimit => {
                reasons.insert(WebAssessmentIncompleteReason::AdaptationLimit);
            },
            DecisionStopReason::CancelledByHost => {
                reasons.insert(WebAssessmentIncompleteReason::HostCancellation);
            },
            DecisionStopReason::RuntimeBudgetLimit => {
                if report.limit_exceeded().is_none() {
                    reasons.insert(WebAssessmentIncompleteReason::SubjectExecutionIncomplete);
                }
            },
        },
        DecisionLoopCommand::ExecuteAction { .. }
        | DecisionLoopCommand::CollectActiveEvidence { .. }
        | DecisionLoopCommand::Replan => {
            reasons.insert(WebAssessmentIncompleteReason::SubjectExecutionIncomplete);
        },
    }
}

fn failed_reasons(
    reasons: &BTreeSet<WebAssessmentIncompleteReason>,
) -> BTreeSet<WebAssessmentIncompleteReason> {
    let mut failed = reasons.clone();
    failed.insert(WebAssessmentIncompleteReason::SubjectExecutionIncomplete);
    failed
}

const fn reason_for_runtime_dimension(
    dimension: RuntimeBudgetDimension,
) -> WebAssessmentIncompleteReason {
    match dimension {
        RuntimeBudgetDimension::TotalRequests => WebAssessmentIncompleteReason::TotalRequestLimit,
        RuntimeBudgetDimension::WallTime => WebAssessmentIncompleteReason::WallTimeLimit,
        RuntimeBudgetDimension::ResponseBytes => WebAssessmentIncompleteReason::ResponseBytesLimit,
        RuntimeBudgetDimension::RequestBodyBytes => {
            WebAssessmentIncompleteReason::RequestBodyBytesLimit
        },
        RuntimeBudgetDimension::ActiveVerifications => {
            WebAssessmentIncompleteReason::ActiveVerificationLimit
        },
        RuntimeBudgetDimension::SameActionAttempts => {
            WebAssessmentIncompleteReason::SameActionAttemptLimit
        },
        RuntimeBudgetDimension::ConsecutiveNoProgressTurns => {
            WebAssessmentIncompleteReason::ConsecutiveNoProgressLimit
        },
    }
}

#[derive(Clone)]
struct PendingRoute {
    url: Url,
    method: WebAssessmentMethod,
    depth: u16,
    query_parameter_names: Vec<String>,
    evidence_ids: Vec<EvidenceId>,
}

fn merge_pending_route(
    routes: &mut BTreeMap<String, PendingRoute>,
    candidate: PendingRoute,
    depth: u16,
    query_name_limit: usize,
) {
    let key = candidate.url.to_string();
    match routes.get_mut(&key) {
        Some(existing) => {
            if candidate.method == WebAssessmentMethod::Get {
                existing.method = WebAssessmentMethod::Get;
            }
            existing.depth = existing.depth.min(depth);
            existing.query_parameter_names = existing
                .query_parameter_names
                .iter()
                .cloned()
                .chain(candidate.query_parameter_names)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(query_name_limit)
                .collect();
            existing.evidence_ids = existing
                .evidence_ids
                .iter()
                .cloned()
                .chain(candidate.evidence_ids)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        },
        None => {
            routes.insert(key, PendingRoute { depth, ..candidate });
        },
    }
}

fn merge_subject_route(
    subject: &mut WebAssessmentSubject,
    candidate: &PendingRoute,
    depth: u16,
    query_name_limit: usize,
) {
    if candidate.method == WebAssessmentMethod::Get {
        subject.method = WebAssessmentMethod::Get;
    }
    subject.depth = subject.depth.min(depth);
    subject.query_parameter_names = subject
        .query_parameter_names
        .iter()
        .cloned()
        .chain(candidate.query_parameter_names.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(query_name_limit)
        .collect();
    subject.evidence_ids = subject
        .evidence_ids
        .iter()
        .cloned()
        .chain(candidate.evidence_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
}

// Evidence-only observer and committed projection implementation.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FormIdentity {
    action: String,
    method: WebAssessmentFormMethod,
}

#[derive(Clone)]
struct SubjectAdmission {
    method: WebAssessmentMethod,
    query_parameter_names: BTreeSet<String>,
    executed: bool,
}

#[derive(Clone)]
struct AssessmentEnvelope {
    subjects: BTreeMap<String, SubjectAdmission>,
    form_identities: BTreeSet<FormIdentity>,
    retained_urls: BTreeSet<String>,
    remaining_subjects: usize,
    remaining_forms: usize,
    remaining_url_bytes: usize,
    allow_children: bool,
}

struct AssessmentLedger {
    subjects: BTreeMap<String, SubjectAdmission>,
    form_identities: BTreeSet<FormIdentity>,
    retained_urls: BTreeSet<String>,
    retained_unique_url_bytes: usize,
}

impl AssessmentLedger {
    fn new(root: &WebAssessmentSubject) -> Self {
        let root_url = root.url.to_string();
        Self {
            subjects: BTreeMap::from([(
                root_url.clone(),
                SubjectAdmission {
                    method: root.method,
                    query_parameter_names: root.query_parameter_names.iter().cloned().collect(),
                    executed: false,
                },
            )]),
            form_identities: BTreeSet::new(),
            retained_urls: BTreeSet::from([root_url.clone()]),
            retained_unique_url_bytes: root_url.len(),
        }
    }

    fn snapshot(&self, limits: WebAssessmentLimits, subject_depth: u16) -> AssessmentEnvelope {
        AssessmentEnvelope {
            subjects: self.subjects.clone(),
            form_identities: self.form_identities.clone(),
            retained_urls: self.retained_urls.clone(),
            remaining_subjects: limits.max_subjects().saturating_sub(self.subjects.len()),
            remaining_forms: limits
                .max_forms()
                .saturating_sub(self.form_identities.len()),
            remaining_url_bytes: limits
                .max_retained_url_bytes()
                .saturating_sub(self.retained_unique_url_bytes),
            allow_children: subject_depth < limits.max_discovery_depth(),
        }
    }

    fn mark_executed(&mut self, subject: &WebAssessmentSubject) -> Result<(), ()> {
        let entry = self.subjects.get_mut(subject.url.as_str()).ok_or(())?;
        entry.executed = true;
        entry.method = subject.method;
        entry.query_parameter_names = subject.query_parameter_names.iter().cloned().collect();
        Ok(())
    }

    fn subject_admission(&self, url: &Url) -> Option<&SubjectAdmission> {
        self.subjects.get(url.as_str())
    }

    fn apply(&mut self, projection: &DocumentProjection) {
        for route in &projection.routes {
            let key = route.url.to_string();
            match self.subjects.get_mut(&key) {
                Some(existing) if !existing.executed => {
                    if route.method == WebAssessmentMethod::Get {
                        existing.method = WebAssessmentMethod::Get;
                    }
                    existing
                        .query_parameter_names
                        .extend(route.query_parameter_names.iter().cloned());
                },
                Some(_) => {},
                None => {
                    self.subjects.insert(
                        key,
                        SubjectAdmission {
                            method: route.method,
                            query_parameter_names: route
                                .query_parameter_names
                                .iter()
                                .cloned()
                                .collect(),
                            executed: false,
                        },
                    );
                },
            }
            self.retain_url(&route.url);
        }
        for form in &projection.forms {
            self.form_identities.insert(FormIdentity {
                action: form.action.to_string(),
                method: form.method,
            });
            self.retain_url(&form.action);
        }
    }

    fn retain_url(&mut self, url: &Url) {
        let value = url.to_string();
        if self.retained_urls.insert(value.clone()) {
            self.retained_unique_url_bytes =
                self.retained_unique_url_bytes.saturating_add(value.len());
        }
    }
}

/// Exact allowlisted implementation of the sealed HTTP response observer.
///
/// The observer owns no mutable state. A fresh instance receives one immutable
/// runtime-ledger snapshot; only the decision runner can commit its output.
pub(crate) struct AssessmentDiscoveryObserver {
    policy: HttpEvidencePolicy,
    limits: WebAssessmentLimits,
    envelope: AssessmentEnvelope,
    expected_subject: String,
    expected_url: Url,
    expected_method: HttpProbeMethod,
    cancellation: CancellationToken,
    deadline: Option<tokio::time::Instant>,
}

impl AssessmentDiscoveryObserver {
    fn new(
        policy: HttpEvidencePolicy,
        limits: WebAssessmentLimits,
        envelope: AssessmentEnvelope,
        subject: &WebAssessmentSubject,
        cancellation: CancellationToken,
        deadline: Option<tokio::time::Instant>,
    ) -> Self {
        Self {
            policy,
            limits,
            envelope,
            expected_subject: format!("endpoint:{}", subject.url),
            expected_url: subject.url.clone(),
            expected_method: subject.method.probe_method(),
            cancellation,
            deadline,
        }
    }

    fn stopped(&self) -> bool {
        self.cancellation.is_cancelled()
            || self
                .deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    }

    fn admit_document(&self, parsed: ParsedDocument) -> AdmittedDocument {
        let mut admitted = AdmittedDocument {
            route_limit_reached: parsed.route_limit_reached,
            form_limit_reached: parsed.form_limit_reached,
            control_limit_reached: parsed.control_limit_reached,
            query_name_limit_reached: parsed.query_name_limit_reached,
            url_byte_limit_reached: parsed.url_byte_limit_reached,
            outside_origin_reference_count: parsed.outside_origin_reference_count,
            ..AdmittedDocument::default()
        };
        if !self.envelope.allow_children {
            admitted.depth_limit_reached = !parsed.routes.is_empty() || !parsed.forms.is_empty();
            return admitted;
        }

        let mut envelope = self.envelope.clone();
        // The parser has already merged GET form actions into the same
        // URL-first route prefix as anchors, areas, and link metadata routes.
        for route in parsed.routes {
            if self.policy.require_permitted_target(&route.url).is_err() {
                continue;
            }
            let key = route.url.to_string();
            if let Some(existing) = envelope.subjects.get_mut(&key) {
                if existing.executed {
                    continue;
                }
                let merged_method = if existing.method == WebAssessmentMethod::Get
                    || route.method == WebAssessmentMethod::Get
                {
                    WebAssessmentMethod::Get
                } else {
                    WebAssessmentMethod::Head
                };
                let method_changed = merged_method != existing.method;
                let mut admitted_names = Vec::new();
                for name in route.query_parameter_names {
                    if existing.query_parameter_names.contains(&name) {
                        continue;
                    }
                    if existing.query_parameter_names.len()
                        >= self.limits.max_query_parameter_names()
                    {
                        admitted.query_name_limit_reached = true;
                        continue;
                    }
                    existing.query_parameter_names.insert(name.clone());
                    admitted_names.push(name);
                }
                if !method_changed && admitted_names.is_empty() {
                    continue;
                }
                existing.method = merged_method;
                admitted.routes.push(ParsedRoute {
                    url: route.url,
                    method: route.method,
                    query_parameter_names: admitted_names,
                });
                continue;
            }
            if envelope.remaining_subjects == 0 {
                admitted.subject_limit_reached = true;
                break;
            }
            if !admit_unique_url(&mut envelope, &route.url) {
                admitted.retained_url_limit_reached = true;
                break;
            }
            envelope.remaining_subjects = envelope.remaining_subjects.saturating_sub(1);
            envelope.subjects.insert(
                key,
                SubjectAdmission {
                    method: route.method,
                    query_parameter_names: route.query_parameter_names.iter().cloned().collect(),
                    executed: false,
                },
            );
            admitted.routes.push(route);
        }

        for form in parsed.forms {
            if self.policy.require_permitted_target(&form.action).is_err() {
                continue;
            }
            let identity = FormIdentity {
                action: form.action.to_string(),
                method: form.method,
            };
            if envelope.form_identities.contains(&identity) {
                continue;
            }
            if envelope.remaining_forms == 0 {
                admitted.form_limit_reached = true;
                break;
            }
            if !admit_unique_url(&mut envelope, &form.action) {
                admitted.retained_url_limit_reached = true;
                break;
            }
            envelope.remaining_forms = envelope.remaining_forms.saturating_sub(1);
            envelope.form_identities.insert(identity);
            admitted.forms.push(form);
        }
        admitted
    }

    fn evidence_for_document(
        &self,
        observation: &CompleteHttpResponseObservation<'_>,
        admitted: AdmittedDocument,
        parents: Vec<EvidenceId>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let marker = derived_observation(
            observation,
            WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED,
            EvidenceValue::Boolean(true),
            "document-projected",
            parents,
        )?;
        let mut evidence = vec![marker.clone()];

        for (condition, predicate, method) in [
            (
                admitted.route_limit_reached,
                WebDiscoveryEvidencePredicate::DOCUMENT_ROUTE_LIMIT_REACHED,
                "document-route-limit-reached",
            ),
            (
                admitted.form_limit_reached,
                WebDiscoveryEvidencePredicate::DOCUMENT_FORM_LIMIT_REACHED,
                "document-form-limit-reached",
            ),
            (
                admitted.control_limit_reached,
                WebDiscoveryEvidencePredicate::DOCUMENT_CONTROL_LIMIT_REACHED,
                "document-control-limit-reached",
            ),
            (
                admitted.query_name_limit_reached,
                WebDiscoveryEvidencePredicate::DOCUMENT_QUERY_NAME_LIMIT_REACHED,
                "document-query-name-limit-reached",
            ),
            (
                admitted.url_byte_limit_reached,
                WebDiscoveryEvidencePredicate::DOCUMENT_URL_BYTE_LIMIT_REACHED,
                "document-url-byte-limit-reached",
            ),
            (
                admitted.subject_limit_reached,
                WebDiscoveryEvidencePredicate::ASSESSMENT_SUBJECT_LIMIT_REACHED,
                "assessment-subject-limit-reached",
            ),
            (
                admitted.depth_limit_reached,
                WebDiscoveryEvidencePredicate::ASSESSMENT_DEPTH_LIMIT_REACHED,
                "assessment-depth-limit-reached",
            ),
            (
                admitted.retained_url_limit_reached,
                WebDiscoveryEvidencePredicate::ASSESSMENT_RETAINED_URL_BYTE_LIMIT_REACHED,
                "assessment-retained-url-byte-limit-reached",
            ),
        ] {
            if condition {
                evidence.push(derived_observation(
                    observation,
                    predicate,
                    EvidenceValue::Boolean(true),
                    method,
                    [marker.id().clone()],
                )?);
            }
        }
        if admitted.outside_origin_reference_count > 0 {
            evidence.push(derived_observation(
                observation,
                WebDiscoveryEvidencePredicate::DOCUMENT_OUTSIDE_ORIGIN_REFERENCE_COUNT,
                EvidenceValue::Unsigned(admitted.outside_origin_reference_count),
                "document-outside-origin-reference-count",
                [marker.id().clone()],
            )?);
        }

        for route in admitted.routes {
            let predicate = match route.method {
                WebAssessmentMethod::Get => WebDiscoveryEvidencePredicate::GET_ROUTE,
                WebAssessmentMethod::Head => WebDiscoveryEvidencePredicate::HEAD_ROUTE,
            };
            let method = match route.method {
                WebAssessmentMethod::Get => "get-route",
                WebAssessmentMethod::Head => "head-route",
            };
            let parent = derived_observation(
                observation,
                predicate,
                EvidenceValue::Text(route.url.to_string()),
                method,
                [marker.id().clone()],
            )?;
            let parent_id = parent.id().clone();
            evidence.push(parent);
            if !route.query_parameter_names.is_empty() {
                evidence.push(derived_observation(
                    observation,
                    WebDiscoveryEvidencePredicate::ROUTE_QUERY_PARAMETER_NAMES,
                    EvidenceValue::TextList(route.query_parameter_names),
                    "route-query-parameter-names",
                    [parent_id],
                )?);
            }
        }

        for form in admitted.forms {
            let (predicate, method) = match form.method {
                WebAssessmentFormMethod::Get => (
                    WebDiscoveryEvidencePredicate::GET_FORM_ACTION,
                    "get-form-action",
                ),
                WebAssessmentFormMethod::Post => (
                    WebDiscoveryEvidencePredicate::POST_FORM_ACTION,
                    "post-form-action",
                ),
                WebAssessmentFormMethod::Dialog => (
                    WebDiscoveryEvidencePredicate::DIALOG_FORM_ACTION,
                    "dialog-form-action",
                ),
            };
            let parent = derived_observation(
                observation,
                predicate,
                EvidenceValue::Text(form.action.to_string()),
                method,
                [marker.id().clone()],
            )?;
            let parent_id = parent.id().clone();
            evidence.push(parent);
            if !form.query_parameter_names.is_empty() {
                evidence.push(derived_observation(
                    observation,
                    WebDiscoveryEvidencePredicate::FORM_QUERY_PARAMETER_NAMES,
                    EvidenceValue::TextList(form.query_parameter_names),
                    "form-query-parameter-names",
                    [parent_id.clone()],
                )?);
            }
            if !form.control_names.is_empty() {
                evidence.push(derived_observation(
                    observation,
                    WebDiscoveryEvidencePredicate::FORM_CONTROL_NAMES,
                    EvidenceValue::TextList(form.control_names),
                    "form-control-names",
                    [parent_id],
                )?);
            }
        }
        Ok(evidence)
    }
}

impl CompleteHttpResponseObserver for AssessmentDiscoveryObserver {
    fn observe(
        &self,
        observation: CompleteHttpResponseObservation<'_>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        if observation.case_id() != BOOTSTRAP_CASE_ID
            || observation.action_id() != BOOTSTRAP_ACTION_ID
            || observation.hypothesis_id() != BOOTSTRAP_HYPOTHESIS_ID
            || observation.has_payload_strategy()
            || !observation.applies_hypothesis_transition()
            || observation.stage() != DecisionExecutionStage::Passive
            || observation.subject().as_str() != self.expected_subject
            || observation.method() != self.expected_method
            || observation.requested_url() != &self.expected_url
            || observation.requested_url().query().is_some()
            || observation.requested_url().fragment().is_some()
            || self
                .policy
                .require_permitted_target(observation.requested_url())
                .is_err()
        {
            return Ok(Vec::new());
        }
        // Passive metadata is value-free and body-independent. Emit it before
        // every HEAD, incomplete-body, non-HTML, or discovery eligibility exit
        // so missing body evidence can never erase observed response metadata.
        let mut evidence = project_assessment_passive_response(
            observation.passive_response_projection(),
            AssessmentPassiveProjectionContext {
                subject: observation.subject(),
                case_id: observation.case_id(),
                executor_id: HTTP_EVIDENCE_EXECUTOR_ID,
                reliability: observation.reliability(),
                parents: passive_projection_parents(&observation)?,
            },
        )?;
        if self.expected_method == HttpProbeMethod::Head {
            return Ok(evidence);
        }
        let Some(body) = observation.complete_body() else {
            evidence.push(derived_observation(
                &observation,
                WebDiscoveryEvidencePredicate::DOCUMENT_BODY_INCOMPLETE,
                EvidenceValue::Boolean(true),
                "document-body-incomplete",
                incomplete_projection_parents(&observation)?,
            )?);
            return Ok(evidence);
        };
        if self.stopped() {
            return Ok(evidence);
        }
        if observation.media_type() != Some("text/html")
            || !matches!(observation.status(), 200 | 206)
        {
            return Ok(evidence);
        }
        let parents = complete_projection_parents(&observation)?;
        if observation.status() == 206 {
            evidence.push(derived_observation(
                &observation,
                WebDiscoveryEvidencePredicate::DOCUMENT_PARTIAL_REPRESENTATION,
                EvidenceValue::Boolean(true),
                "document-partial-representation",
                parents,
            )?);
            return Ok(evidence);
        }
        let Ok(html) = std::str::from_utf8(body) else {
            evidence.push(derived_observation(
                &observation,
                WebDiscoveryEvidencePredicate::DOCUMENT_INVALID_UTF8,
                EvidenceValue::Boolean(true),
                "document-invalid-utf8",
                parents,
            )?);
            return Ok(evidence);
        };
        let parsed = parse_document(observation.requested_url(), html, self.limits);
        if self.stopped() {
            return Ok(evidence);
        }
        let admitted = self.admit_document(parsed);
        evidence.extend(self.evidence_for_document(&observation, admitted, parents)?);
        if self.stopped() {
            evidence.retain(|item| item.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE);
        }
        Ok(evidence)
    }
}

#[derive(Default)]
struct AdmittedDocument {
    routes: Vec<ParsedRoute>,
    forms: Vec<ParsedForm>,
    route_limit_reached: bool,
    form_limit_reached: bool,
    control_limit_reached: bool,
    query_name_limit_reached: bool,
    url_byte_limit_reached: bool,
    subject_limit_reached: bool,
    depth_limit_reached: bool,
    retained_url_limit_reached: bool,
    outside_origin_reference_count: u64,
}

fn admit_unique_url(envelope: &mut AssessmentEnvelope, url: &Url) -> bool {
    let value = url.to_string();
    if envelope.retained_urls.contains(&value) {
        return true;
    }
    if value.len() > envelope.remaining_url_bytes {
        return false;
    }
    envelope.remaining_url_bytes -= value.len();
    envelope.retained_urls.insert(value);
    true
}

fn complete_projection_parents(
    observation: &CompleteHttpResponseObservation<'_>,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    [
        (
            observation.request_method_evidence_id(),
            "request-method-evidence",
        ),
        (
            observation.request_url_evidence_id(),
            "request-url-evidence",
        ),
        (
            observation.response_status_evidence_id(),
            "response-status-evidence",
        ),
        (
            observation.response_media_type_evidence_id(),
            "response-media-type-evidence",
        ),
        (
            observation.response_body_truncated_evidence_id(),
            "response-body-truncated-evidence",
        ),
        (
            observation.response_body_digest_evidence_id(),
            "response-body-digest-evidence",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect()
}

fn passive_projection_parents(
    observation: &CompleteHttpResponseObservation<'_>,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    [
        (
            observation.request_method_evidence_id(),
            "request-method-evidence",
        ),
        (
            observation.request_url_evidence_id(),
            "request-url-evidence",
        ),
        (
            observation.response_status_evidence_id(),
            "response-status-evidence",
        ),
        (
            observation.response_final_url_evidence_id(),
            "response-final-url-evidence",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect()
}

fn incomplete_projection_parents(
    observation: &CompleteHttpResponseObservation<'_>,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    let mut parents = [
        (
            observation.request_method_evidence_id(),
            "request-method-evidence",
        ),
        (
            observation.request_url_evidence_id(),
            "request-url-evidence",
        ),
        (
            observation.response_status_evidence_id(),
            "response-status-evidence",
        ),
        (
            observation.response_body_truncated_evidence_id(),
            "response-body-truncated-evidence",
        ),
        (
            observation.response_body_digest_evidence_id(),
            "response-body-digest-evidence",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect::<Result<Vec<_>, _>>()?;
    if let Some(media_id) = observation.response_media_type_evidence_id() {
        parents.push(media_id.clone());
    }
    Ok(parents)
}

fn derived_observation(
    observation: &CompleteHttpResponseObservation<'_>,
    predicate: PredicateDescriptor,
    value: EvidenceValue,
    method: &'static str,
    parents: impl IntoIterator<Item = EvidenceId>,
) -> Result<Evidence, HttpEvidenceError> {
    let source = EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, method)?
        .with_correlation_id(observation.case_id())?;
    let derivation = EvidenceDerivation::new(
        parents,
        DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1)?,
    )?;
    Ok(Evidence::new(
        observation.subject().clone(),
        EvidenceKind::Content,
        predicate.into(),
        value,
        source,
        observation.reliability(),
    )
    .derived_from(derivation))
}

#[derive(Default)]
struct DocumentProjection {
    routes: Vec<PendingRoute>,
    forms: Vec<WebAssessmentForm>,
    explicit_reason: Option<WebAssessmentIncompleteReason>,
    subject_limit_reached: bool,
    depth_limit_reached: bool,
    route_limit_reached: bool,
    form_limit_reached: bool,
    control_limit_reached: bool,
    query_name_limit_reached: bool,
    canonical_url_byte_limit_reached: bool,
    retained_url_byte_limit_reached: bool,
}

impl DocumentProjection {
    fn add_reasons(&self, reasons: &mut BTreeSet<WebAssessmentIncompleteReason>) {
        if let Some(reason) = self.explicit_reason {
            reasons.insert(reason);
        }
        for (condition, reason) in [
            (
                self.subject_limit_reached,
                WebAssessmentIncompleteReason::SubjectLimit,
            ),
            (
                self.depth_limit_reached,
                WebAssessmentIncompleteReason::DiscoveryDepthLimit,
            ),
            (
                self.route_limit_reached,
                WebAssessmentIncompleteReason::DocumentReferenceLimit,
            ),
            (
                self.form_limit_reached,
                WebAssessmentIncompleteReason::FormLimit,
            ),
            (
                self.control_limit_reached,
                WebAssessmentIncompleteReason::FormControlLimit,
            ),
            (
                self.query_name_limit_reached,
                WebAssessmentIncompleteReason::QueryParameterNameLimit,
            ),
            (
                self.canonical_url_byte_limit_reached,
                WebAssessmentIncompleteReason::CanonicalUrlBytesLimit,
            ),
            (
                self.retained_url_byte_limit_reached,
                WebAssessmentIncompleteReason::RetainedUrlBytesLimit,
            ),
        ] {
            if condition {
                reasons.insert(reason);
            }
        }
    }
}

struct ProjectionBase {
    parent_ids: Vec<EvidenceId>,
    status: u16,
    body_truncated: bool,
}

fn projection_from_committed_bootstrap(
    receipt: Option<&DecisionEvidenceReceipt>,
    knowledge: &KnowledgeBase,
    subject: &WebAssessmentSubject,
    policy: &HttpEvidencePolicy,
    limits: WebAssessmentLimits,
    envelope: &AssessmentEnvelope,
) -> Result<Option<DocumentProjection>, ()> {
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    if receipt.case().id() != BOOTSTRAP_CASE_ID
        || receipt.case().action_id() != BOOTSTRAP_ACTION_ID
        || receipt.case().subject().as_str() != format!("endpoint:{}", subject.url)
        || receipt.case().hypothesis_id() != BOOTSTRAP_HYPOTHESIS_ID
        || receipt.case().payload_strategy().is_some()
        || !receipt.case().applies_hypothesis_transition()
        || receipt.executor_id() != HTTP_EVIDENCE_EXECUTOR_ID
        || receipt.stage() != DecisionExecutionStage::Passive
        || receipt.evidence().len() != receipt.writes().len()
    {
        return Err(());
    }
    for evidence in receipt.evidence() {
        if knowledge.evidence(evidence.id()).as_ref() != Some(evidence) {
            return Err(());
        }
    }
    let bootstrap_envelope = validate_bootstrap_request_envelope(receipt, subject)?;

    let Some(first_discovery) = receipt
        .evidence()
        .iter()
        .position(|evidence| evidence.predicate().namespace() == "web.discovery")
    else {
        if subject.method == WebAssessmentMethod::Get && bootstrap_envelope.body_truncated {
            // A broker-truncated GET can only be represented by the sealed
            // observer's explicit incomplete-document evidence. Absence of
            // that marker is a committed-envelope invariant violation.
            return Err(());
        }
        return Ok(None);
    };
    if receipt.evidence()[..first_discovery]
        .iter()
        .any(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE)
    {
        return Err(());
    }
    let discovery_tail = &receipt.evidence()[first_discovery..];
    let discovery_len = discovery_tail
        .iter()
        .position(|evidence| evidence.predicate().namespace() != "web.discovery")
        .unwrap_or(discovery_tail.len());
    let (discovery, trailing) = discovery_tail.split_at(discovery_len);
    // The HTTP evidence executor appends assessment-defense records after the
    // discovery observer's closed batch. Keep discovery replay strict while
    // admitting only that separately replay-validated suffix; an unknown or
    // interleaved evidence namespace still fails closed.
    if trailing
        .iter()
        .any(|evidence| evidence.predicate().namespace() != ASSESSMENT_DEFENSE_NAMESPACE)
    {
        return Err(());
    }
    let first = discovery.first().ok_or(())?;

    if first.predicate()
        == &WebDiscoveryEvidencePredicate::DOCUMENT_BODY_INCOMPLETE.into_knowledge()
    {
        let base = projection_base(receipt, subject, false)?;
        if discovery.len() != 1 {
            return Err(());
        }
        validate_discovery_evidence(first, receipt, "document-body-incomplete", &base.parent_ids)?;
        require_true(first)?;
        return Ok(Some(DocumentProjection {
            explicit_reason: Some(WebAssessmentIncompleteReason::ResponseBodyIncomplete),
            ..DocumentProjection::default()
        }));
    }
    let base = projection_base(receipt, subject, true)?;
    if first.predicate()
        == &WebDiscoveryEvidencePredicate::DOCUMENT_PARTIAL_REPRESENTATION.into_knowledge()
    {
        if discovery.len() != 1 || base.status != 206 || base.body_truncated {
            return Err(());
        }
        validate_discovery_evidence(
            first,
            receipt,
            "document-partial-representation",
            &base.parent_ids,
        )?;
        require_true(first)?;
        return Ok(Some(DocumentProjection {
            explicit_reason: Some(WebAssessmentIncompleteReason::PartialRepresentation),
            ..DocumentProjection::default()
        }));
    }
    if first.predicate() == &WebDiscoveryEvidencePredicate::DOCUMENT_INVALID_UTF8.into_knowledge() {
        if discovery.len() != 1 || base.status != 200 || base.body_truncated {
            return Err(());
        }
        validate_discovery_evidence(first, receipt, "document-invalid-utf8", &base.parent_ids)?;
        require_true(first)?;
        return Ok(Some(DocumentProjection {
            explicit_reason: Some(WebAssessmentIncompleteReason::InvalidUtf8),
            ..DocumentProjection::default()
        }));
    }
    if base.status != 200
        || base.body_truncated
        || first.predicate() != &WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED.into_knowledge()
    {
        return Err(());
    }
    validate_discovery_evidence(first, receipt, "document-projected", &base.parent_ids)?;
    require_true(first)?;
    let marker_id = first.id().clone();
    let mut projection = DocumentProjection::default();
    let mut index = 1;
    let mut last_flag_rank = None;

    while let Some(evidence) = discovery.get(index) {
        let Some((rank, flag)) = projection_flag(evidence.predicate()) else {
            break;
        };
        if last_flag_rank.is_some_and(|previous| rank <= previous) {
            return Err(());
        }
        validate_discovery_evidence(
            evidence,
            receipt,
            discovery_method(evidence.predicate()).ok_or(())?,
            std::slice::from_ref(&marker_id),
        )?;
        match flag {
            ProjectionFlag::OutsideOriginCount => {
                if !matches!(evidence.value(), EvidenceValue::Unsigned(value) if *value > 0) {
                    return Err(());
                }
            },
            flag => {
                require_true(evidence)?;
                set_projection_flag(&mut projection, flag)?;
            },
        }
        last_flag_rank = Some(rank);
        index += 1;
    }

    let mut last_route_url: Option<String> = None;
    while let Some(evidence) = discovery.get(index) {
        let predicate = evidence.predicate();
        if predicate != &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge()
            && predicate != &WebDiscoveryEvidencePredicate::HEAD_ROUTE.into_knowledge()
        {
            break;
        }
        validate_discovery_evidence(
            evidence,
            receipt,
            discovery_method(predicate).ok_or(())?,
            std::slice::from_ref(&marker_id),
        )?;
        let url = canonical_evidence_url(evidence, policy, limits)?;
        let key = url.to_string();
        if last_route_url
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(());
        }
        last_route_url = Some(key);
        let method = if predicate == &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge() {
            WebAssessmentMethod::Get
        } else {
            WebAssessmentMethod::Head
        };
        let mut route = PendingRoute {
            url,
            method,
            depth: 0,
            query_parameter_names: Vec::new(),
            evidence_ids: vec![evidence.id().clone()],
        };
        let parent_id = evidence.id().clone();
        index += 1;
        if let Some(child) = discovery.get(index).filter(|child| {
            child.predicate()
                == &WebDiscoveryEvidencePredicate::ROUTE_QUERY_PARAMETER_NAMES.into_knowledge()
        }) {
            validate_discovery_evidence(
                child,
                receipt,
                "route-query-parameter-names",
                std::slice::from_ref(&parent_id),
            )?;
            route.query_parameter_names =
                valid_name_list(child.value(), limits.max_query_parameter_names())?;
            route.evidence_ids.push(child.id().clone());
            index += 1;
        }
        projection.routes.push(route);
    }

    let mut last_form: Option<FormIdentity> = None;
    while let Some(evidence) = discovery.get(index) {
        if !is_form_action_predicate(evidence.predicate()) {
            return Err(());
        }
        validate_discovery_evidence(
            evidence,
            receipt,
            discovery_method(evidence.predicate()).ok_or(())?,
            std::slice::from_ref(&marker_id),
        )?;
        let action = canonical_evidence_url(evidence, policy, limits)?;
        let method = form_method_for_predicate(evidence.predicate()).ok_or(())?;
        let identity = FormIdentity {
            action: action.to_string(),
            method,
        };
        if last_form
            .as_ref()
            .is_some_and(|previous| previous >= &identity)
        {
            return Err(());
        }
        last_form = Some(identity);
        let parent_id = evidence.id().clone();
        let mut form = WebAssessmentForm {
            document_url: subject.url.clone(),
            action,
            method,
            query_parameter_names: Vec::new(),
            control_names: Vec::new(),
            evidence_ids: vec![parent_id.clone()],
        };
        index += 1;
        if let Some(child) = discovery.get(index).filter(|child| {
            child.predicate()
                == &WebDiscoveryEvidencePredicate::FORM_QUERY_PARAMETER_NAMES.into_knowledge()
        }) {
            validate_discovery_evidence(
                child,
                receipt,
                "form-query-parameter-names",
                std::slice::from_ref(&parent_id),
            )?;
            form.query_parameter_names =
                valid_name_list(child.value(), limits.max_query_parameter_names())?;
            form.evidence_ids.push(child.id().clone());
            index += 1;
        }
        if let Some(child) = discovery.get(index).filter(|child| {
            child.predicate() == &WebDiscoveryEvidencePredicate::FORM_CONTROL_NAMES.into_knowledge()
        }) {
            validate_discovery_evidence(
                child,
                receipt,
                "form-control-names",
                std::slice::from_ref(&parent_id),
            )?;
            form.control_names = valid_name_list(child.value(), limits.max_controls_per_form())?;
            form.evidence_ids.push(child.id().clone());
            index += 1;
        }
        projection.forms.push(form);
    }

    validate_projection_envelope(&projection, envelope, limits)?;
    Ok(Some(projection))
}

struct BootstrapRequestEnvelope {
    body_truncated: bool,
}

fn validate_bootstrap_request_envelope(
    receipt: &DecisionEvidenceReceipt,
    subject: &WebAssessmentSubject,
) -> Result<BootstrapRequestEnvelope, ()> {
    let expected_method = match subject.method {
        WebAssessmentMethod::Get => "GET",
        WebAssessmentMethod::Head => "HEAD",
    };
    let mut body_truncated = None;
    for (descriptor, kind, source_method) in [
        (
            HttpEvidencePredicate::REQUEST_METHOD,
            EvidenceKind::Http,
            "request-method",
        ),
        (
            HttpEvidencePredicate::REQUEST_URL,
            EvidenceKind::Http,
            "request-url",
        ),
        (
            HttpEvidencePredicate::RESPONSE_STATUS,
            EvidenceKind::Http,
            "response-status",
        ),
        (
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
            EvidenceKind::Http,
            "response-final-url",
        ),
        (
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            EvidenceKind::Content,
            "response-body-truncation",
        ),
        (
            HttpEvidencePredicate::RESPONSE_BODY_SHA256,
            EvidenceKind::Content,
            "response-body-sha256",
        ),
    ] {
        let predicate = descriptor.into_knowledge();
        let mut matches = receipt
            .evidence()
            .iter()
            .filter(|evidence| evidence.predicate() == &predicate);
        let evidence = matches.next().ok_or(())?;
        if matches.next().is_some()
            || evidence.subject() != receipt.case().subject()
            || evidence.kind() != &kind
            || evidence.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
            || evidence.source().method() != source_method
            || evidence.source().correlation_id() != Some(BOOTSTRAP_CASE_ID)
            || !matches!(evidence.origin(), EvidenceOrigin::Direct)
        {
            return Err(());
        }
        match descriptor {
            HttpEvidencePredicate::REQUEST_METHOD => {
                if evidence.value() != &EvidenceValue::Text(expected_method.to_owned()) {
                    return Err(());
                }
            },
            HttpEvidencePredicate::REQUEST_URL => {
                if evidence.value() != &EvidenceValue::Text(subject.url.to_string()) {
                    return Err(());
                }
            },
            HttpEvidencePredicate::RESPONSE_STATUS => {
                if !matches!(evidence.value(), EvidenceValue::Unsigned(value) if u16::try_from(*value).is_ok())
                {
                    return Err(());
                }
            },
            HttpEvidencePredicate::RESPONSE_FINAL_URL => {
                if evidence.value() != &EvidenceValue::Text(subject.url.to_string()) {
                    return Err(());
                }
            },
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED => {
                let EvidenceValue::Boolean(value) = evidence.value() else {
                    return Err(());
                };
                body_truncated = Some(*value);
            },
            HttpEvidencePredicate::RESPONSE_BODY_SHA256 => {
                let EvidenceValue::Text(value) = evidence.value() else {
                    return Err(());
                };
                if !valid_sha256(value) {
                    return Err(());
                }
            },
            _ => return Err(()),
        }
    }
    let media_predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
    let mut media_matches = receipt
        .evidence()
        .iter()
        .filter(|evidence| evidence.predicate() == &media_predicate);
    if let Some(media) = media_matches.next() {
        let EvidenceValue::Text(value) = media.value() else {
            return Err(());
        };
        if media_matches.next().is_some()
            || media.subject() != receipt.case().subject()
            || media.kind() != &EvidenceKind::Http
            || media.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
            || media.source().method() != "response-media-type"
            || media.source().correlation_id() != Some(BOOTSTRAP_CASE_ID)
            || !matches!(media.origin(), EvidenceOrigin::Direct)
            || value.is_empty()
            || value != &value.to_ascii_lowercase()
            || value.contains(';')
            || value.chars().any(char::is_control)
        {
            return Err(());
        }
    }
    Ok(BootstrapRequestEnvelope {
        body_truncated: body_truncated.ok_or(())?,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn projection_base(
    receipt: &DecisionEvidenceReceipt,
    subject: &WebAssessmentSubject,
    require_html_media: bool,
) -> Result<ProjectionBase, ()> {
    let specs = [
        (
            HttpEvidencePredicate::REQUEST_METHOD,
            EvidenceKind::Http,
            "request-method",
        ),
        (
            HttpEvidencePredicate::REQUEST_URL,
            EvidenceKind::Http,
            "request-url",
        ),
        (
            HttpEvidencePredicate::RESPONSE_STATUS,
            EvidenceKind::Http,
            "response-status",
        ),
        (
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            EvidenceKind::Content,
            "response-body-truncation",
        ),
        (
            HttpEvidencePredicate::RESPONSE_BODY_SHA256,
            EvidenceKind::Content,
            "response-body-sha256",
        ),
    ];
    let mut ids = Vec::with_capacity(specs.len());
    let mut status = None;
    let mut body_truncated = None;
    for (descriptor, kind, method) in specs {
        let predicate = descriptor.into_knowledge();
        let mut matches = receipt
            .evidence()
            .iter()
            .filter(|evidence| evidence.predicate() == &predicate);
        let evidence = matches.next().ok_or(())?;
        if matches.next().is_some()
            || evidence.subject() != receipt.case().subject()
            || evidence.kind() != &kind
            || evidence.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
            || evidence.source().method() != method
            || evidence.source().correlation_id() != Some(BOOTSTRAP_CASE_ID)
            || !matches!(evidence.origin(), EvidenceOrigin::Direct)
        {
            return Err(());
        }
        match descriptor {
            HttpEvidencePredicate::REQUEST_METHOD => {
                if evidence.value() != &EvidenceValue::Text("GET".to_owned())
                    || subject.method != WebAssessmentMethod::Get
                {
                    return Err(());
                }
            },
            HttpEvidencePredicate::REQUEST_URL => {
                if evidence.value() != &EvidenceValue::Text(subject.url.to_string()) {
                    return Err(());
                }
            },
            HttpEvidencePredicate::RESPONSE_STATUS => {
                let EvidenceValue::Unsigned(value) = evidence.value() else {
                    return Err(());
                };
                status = Some(u16::try_from(*value).map_err(|_| ())?);
            },
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED => {
                let EvidenceValue::Boolean(value) = evidence.value() else {
                    return Err(());
                };
                body_truncated = Some(*value);
            },
            HttpEvidencePredicate::RESPONSE_BODY_SHA256 => {
                let EvidenceValue::Text(value) = evidence.value() else {
                    return Err(());
                };
                if !valid_sha256(value) {
                    return Err(());
                }
            },
            _ => return Err(()),
        }
        ids.push(evidence.id().clone());
    }
    let media_predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
    let mut media_matches = receipt
        .evidence()
        .iter()
        .filter(|evidence| evidence.predicate() == &media_predicate);
    let media = media_matches.next();
    if media_matches.next().is_some() || (require_html_media && media.is_none()) {
        return Err(());
    }
    if let Some(evidence) = media {
        let EvidenceValue::Text(value) = evidence.value() else {
            return Err(());
        };
        if evidence.subject() != receipt.case().subject()
            || evidence.kind() != &EvidenceKind::Http
            || evidence.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
            || evidence.source().method() != "response-media-type"
            || evidence.source().correlation_id() != Some(BOOTSTRAP_CASE_ID)
            || !matches!(evidence.origin(), EvidenceOrigin::Direct)
            || (require_html_media && value != "text/html")
        {
            return Err(());
        }
        ids.push(evidence.id().clone());
    }
    ids.sort();
    Ok(ProjectionBase {
        parent_ids: ids,
        status: status.ok_or(())?,
        body_truncated: body_truncated.ok_or(())?,
    })
}

fn validate_discovery_evidence(
    evidence: &Evidence,
    receipt: &DecisionEvidenceReceipt,
    method: &str,
    expected_parents: &[EvidenceId],
) -> Result<(), ()> {
    if evidence.subject() != receipt.case().subject()
        || evidence.kind() != &EvidenceKind::Content
        || evidence.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
        || evidence.source().method() != method
        || evidence.source().correlation_id() != Some(BOOTSTRAP_CASE_ID)
    {
        return Err(());
    }
    let derivation = evidence.origin().derivation().ok_or(())?;
    if derivation.algorithm().name() != "web.discovery.html5ever-names-only"
        || derivation.algorithm().version() != 1
        || derivation.parents() != expected_parents
    {
        return Err(());
    }
    Ok(())
}

fn canonical_evidence_url(
    evidence: &Evidence,
    policy: &HttpEvidencePolicy,
    limits: WebAssessmentLimits,
) -> Result<Url, ()> {
    let EvidenceValue::Text(value) = evidence.value() else {
        return Err(());
    };
    let url = Url::parse(value).map_err(|_| ())?;
    if url.to_string() != *value
        || url.query().is_some()
        || url.fragment().is_some()
        || value.len() > limits.max_canonical_url_bytes()
        || policy.require_permitted_target(&url).is_err()
    {
        return Err(());
    }
    Ok(url)
}

#[derive(Clone, Copy)]
enum ProjectionFlag {
    RouteLimit,
    FormLimit,
    ControlLimit,
    QueryNameLimit,
    CanonicalUrlByteLimit,
    SubjectLimit,
    DepthLimit,
    RetainedUrlByteLimit,
    OutsideOriginCount,
}

fn projection_flag(predicate: &termivar_core::KnowledgePredicate) -> Option<(u8, ProjectionFlag)> {
    let ordered = [
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_ROUTE_LIMIT_REACHED,
            ProjectionFlag::RouteLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_FORM_LIMIT_REACHED,
            ProjectionFlag::FormLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_CONTROL_LIMIT_REACHED,
            ProjectionFlag::ControlLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_QUERY_NAME_LIMIT_REACHED,
            ProjectionFlag::QueryNameLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_URL_BYTE_LIMIT_REACHED,
            ProjectionFlag::CanonicalUrlByteLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::ASSESSMENT_SUBJECT_LIMIT_REACHED,
            ProjectionFlag::SubjectLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::ASSESSMENT_DEPTH_LIMIT_REACHED,
            ProjectionFlag::DepthLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::ASSESSMENT_RETAINED_URL_BYTE_LIMIT_REACHED,
            ProjectionFlag::RetainedUrlByteLimit,
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_OUTSIDE_ORIGIN_REFERENCE_COUNT,
            ProjectionFlag::OutsideOriginCount,
        ),
    ];
    ordered
        .into_iter()
        .enumerate()
        .find_map(|(rank, (descriptor, flag))| {
            (predicate == &descriptor.into_knowledge()).then_some((rank as u8, flag))
        })
}

fn set_projection_flag(
    projection: &mut DocumentProjection,
    flag: ProjectionFlag,
) -> Result<(), ()> {
    let target = match flag {
        ProjectionFlag::RouteLimit => &mut projection.route_limit_reached,
        ProjectionFlag::FormLimit => &mut projection.form_limit_reached,
        ProjectionFlag::ControlLimit => &mut projection.control_limit_reached,
        ProjectionFlag::QueryNameLimit => &mut projection.query_name_limit_reached,
        ProjectionFlag::CanonicalUrlByteLimit => &mut projection.canonical_url_byte_limit_reached,
        ProjectionFlag::SubjectLimit => &mut projection.subject_limit_reached,
        ProjectionFlag::DepthLimit => &mut projection.depth_limit_reached,
        ProjectionFlag::RetainedUrlByteLimit => &mut projection.retained_url_byte_limit_reached,
        ProjectionFlag::OutsideOriginCount => return Err(()),
    };
    if *target {
        return Err(());
    }
    *target = true;
    Ok(())
}

fn require_true(evidence: &Evidence) -> Result<(), ()> {
    (evidence.value() == &EvidenceValue::Boolean(true))
        .then_some(())
        .ok_or(())
}

fn discovery_method(predicate: &termivar_core::KnowledgePredicate) -> Option<&'static str> {
    let methods = [
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED,
            "document-projected",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_BODY_INCOMPLETE,
            "document-body-incomplete",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_PARTIAL_REPRESENTATION,
            "document-partial-representation",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_INVALID_UTF8,
            "document-invalid-utf8",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_ROUTE_LIMIT_REACHED,
            "document-route-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_FORM_LIMIT_REACHED,
            "document-form-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_CONTROL_LIMIT_REACHED,
            "document-control-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_QUERY_NAME_LIMIT_REACHED,
            "document-query-name-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_URL_BYTE_LIMIT_REACHED,
            "document-url-byte-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::ASSESSMENT_SUBJECT_LIMIT_REACHED,
            "assessment-subject-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::ASSESSMENT_DEPTH_LIMIT_REACHED,
            "assessment-depth-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::ASSESSMENT_RETAINED_URL_BYTE_LIMIT_REACHED,
            "assessment-retained-url-byte-limit-reached",
        ),
        (
            WebDiscoveryEvidencePredicate::DOCUMENT_OUTSIDE_ORIGIN_REFERENCE_COUNT,
            "document-outside-origin-reference-count",
        ),
        (WebDiscoveryEvidencePredicate::GET_ROUTE, "get-route"),
        (WebDiscoveryEvidencePredicate::HEAD_ROUTE, "head-route"),
        (
            WebDiscoveryEvidencePredicate::ROUTE_QUERY_PARAMETER_NAMES,
            "route-query-parameter-names",
        ),
        (
            WebDiscoveryEvidencePredicate::GET_FORM_ACTION,
            "get-form-action",
        ),
        (
            WebDiscoveryEvidencePredicate::POST_FORM_ACTION,
            "post-form-action",
        ),
        (
            WebDiscoveryEvidencePredicate::DIALOG_FORM_ACTION,
            "dialog-form-action",
        ),
        (
            WebDiscoveryEvidencePredicate::FORM_QUERY_PARAMETER_NAMES,
            "form-query-parameter-names",
        ),
        (
            WebDiscoveryEvidencePredicate::FORM_CONTROL_NAMES,
            "form-control-names",
        ),
    ];
    methods.into_iter().find_map(|(descriptor, method)| {
        (predicate == &descriptor.into_knowledge()).then_some(method)
    })
}

fn validate_projection_envelope(
    projection: &DocumentProjection,
    envelope: &AssessmentEnvelope,
    limits: WebAssessmentLimits,
) -> Result<(), ()> {
    if projection.routes.len() > limits.max_references_per_document()
        || projection.forms.len() > limits.max_forms()
        || (!envelope.allow_children
            && (!projection.routes.is_empty() || !projection.forms.is_empty()))
    {
        return Err(());
    }
    let mut replay = envelope.clone();
    for route in &projection.routes {
        let key = route.url.to_string();
        if let Some(existing) = replay.subjects.get_mut(&key) {
            if existing.executed {
                return Err(());
            }
            let merged_method = if existing.method == WebAssessmentMethod::Get
                || route.method == WebAssessmentMethod::Get
            {
                WebAssessmentMethod::Get
            } else {
                WebAssessmentMethod::Head
            };
            let method_changed = merged_method != existing.method;
            if route
                .query_parameter_names
                .iter()
                .any(|name| existing.query_parameter_names.contains(name))
                || existing
                    .query_parameter_names
                    .len()
                    .saturating_add(route.query_parameter_names.len())
                    > limits.max_query_parameter_names()
            {
                return Err(());
            }
            if !method_changed && route.query_parameter_names.is_empty() {
                return Err(());
            }
            existing.method = merged_method;
            existing
                .query_parameter_names
                .extend(route.query_parameter_names.iter().cloned());
            continue;
        }
        if replay.remaining_subjects == 0 || !admit_unique_url(&mut replay, &route.url) {
            return Err(());
        }
        replay.remaining_subjects -= 1;
        replay.subjects.insert(
            key,
            SubjectAdmission {
                method: route.method,
                query_parameter_names: route.query_parameter_names.iter().cloned().collect(),
                executed: false,
            },
        );
    }
    for form in &projection.forms {
        let identity = FormIdentity {
            action: form.action.to_string(),
            method: form.method,
        };
        if replay.form_identities.contains(&identity)
            || replay.remaining_forms == 0
            || !admit_unique_url(&mut replay, &form.action)
        {
            return Err(());
        }
        replay.remaining_forms -= 1;
        replay.form_identities.insert(identity);
    }
    Ok(())
}

fn valid_name_list(value: &EvidenceValue, limit: usize) -> Result<Vec<String>, ()> {
    let EvidenceValue::TextList(names) = value else {
        return Err(());
    };
    if names.is_empty() || names.len() > limit {
        return Err(());
    }
    let canonical: BTreeSet<_> = names.iter().cloned().collect();
    if canonical.len() != names.len()
        || canonical.iter().ne(names)
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > HARD_MAX_DISCOVERY_NAME_BYTES
                || name.chars().any(char::is_control)
        })
    {
        return Err(());
    }
    Ok(names.clone())
}

fn is_form_action_predicate(predicate: &termivar_core::KnowledgePredicate) -> bool {
    [
        WebDiscoveryEvidencePredicate::GET_FORM_ACTION,
        WebDiscoveryEvidencePredicate::POST_FORM_ACTION,
        WebDiscoveryEvidencePredicate::DIALOG_FORM_ACTION,
    ]
    .into_iter()
    .any(|item| predicate == &item.into_knowledge())
}

fn form_method_for_predicate(
    predicate: &termivar_core::KnowledgePredicate,
) -> Option<WebAssessmentFormMethod> {
    if predicate == &WebDiscoveryEvidencePredicate::GET_FORM_ACTION.into_knowledge() {
        Some(WebAssessmentFormMethod::Get)
    } else if predicate == &WebDiscoveryEvidencePredicate::POST_FORM_ACTION.into_knowledge() {
        Some(WebAssessmentFormMethod::Post)
    } else if predicate == &WebDiscoveryEvidencePredicate::DIALOG_FORM_ACTION.into_knowledge() {
        Some(WebAssessmentFormMethod::Dialog)
    } else {
        None
    }
}

#[cfg(test)]
#[path = "web_assessment_tests.rs"]
mod tests;
