//! Bounded product report envelope for typed assessment items.
//!
//! This module owns no projection, verification, rendering, or persistence
//! authority. It mints the generic [`RunReport`] envelope only from consumed
//! runtime-owned completion truth, then binds the exact [`ScanProfileV1`] that
//! governed the run to assessment items minted by the closed claim boundary.
//! The public type deliberately has no Serde implementation; the reporting
//! adapter performs a separate explicit, redacted wire projection.

use std::{
    collections::BTreeSet,
    fmt,
    time::{Duration, SystemTime},
};

use sha2::{Digest, Sha256};
use termivar_core::{
    ResourceAccounting, RunAccounting, RunReport, RunReportInput, RunStatus, RunStepReport,
    RunStepStatus, RunStopCode, RunStopReason,
};
use thiserror::Error;
use url::Url;

#[cfg(feature = "openapi-review")]
use super::openapi_runtime::{
    OpenApiRuntimeOutcome, WebAssessmentOpenApiAudit, MAX_OPENAPI_REVIEW_REQUESTS,
    OPENAPI_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "authorization-review")]
use super::resource_authorization_runtime::{
    WebAssessmentAuthorizationAudit, MAX_AUTHORIZATION_REVIEW_REQUESTS,
    RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "rest-review")]
use super::rest_runtime::{
    RestRuntimeOutcome, WebAssessmentRestAudit, MAX_REST_REVIEW_ACTIVE_VERIFICATIONS,
    MAX_REST_REVIEW_REQUESTS, REST_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "ssrf-oast-review")]
use super::ssrf_oast_runtime::{
    SsrfOastRuntimeOutcome, WebAssessmentSsrfOastAudit, MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS,
    MAX_SSRF_OAST_REVIEW_PROVIDER_REQUESTS, MAX_SSRF_OAST_REVIEW_REQUESTS,
    SSRF_OAST_REVIEW_CAPABILITY_ID,
};
use super::{
    assessment_item::{
        AssessmentItem, AssessmentItemSet, AssessmentSubjectInventoryEntry,
        MAX_ASSESSMENT_ITEM_SET_ITEMS,
    },
    scan_profile::{BuiltInScanProfile, ScanProfileV1},
    web_assessment::{
        WebAssessmentCompletion, WebAssessmentDefenseMode, WebAssessmentLimits,
        WebAssessmentMethod, WebAssessmentSubject, WebAssessmentSubjectOrigin, WebAssessmentUsage,
    },
};
#[cfg(feature = "authorization-review")]
use crate::authorization_review::{
    AuthorizationReviewOutcome, HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS,
    HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS,
};
use crate::RuntimeBudget;

/// Stable schema for the typed assessment-run product envelope.
pub const ASSESSMENT_RUN_REPORT_SCHEMA: &str = "venom-assessment-run/v1";

/// Maximum number of typed assessment items retained by one run report.
pub const MAX_ASSESSMENT_RUN_ITEMS: usize = MAX_ASSESSMENT_ITEM_SET_ITEMS;

const ASSESSMENT_RUN_TARGET_DOMAIN: &[u8] = b"venom.assessment-run.target.v1\0";
const WEB_ASSESSMENT_RUN_STEP_ID: &str = "web-review";
const WEB_ASSESSMENT_STOP_DETAIL: &str = "bounded web assessment completed";

/// Runtime-only extension of the profile limits for explicitly enabled child work.
#[derive(Clone, Copy)]
pub(crate) struct AssessmentRuntimeLimits {
    profile: WebAssessmentLimits,
    active_verification_limit: u16,
    optional_active_verification_allowance: u16,
}

impl AssessmentRuntimeLimits {
    pub(super) const fn new(
        profile: WebAssessmentLimits,
        active_verification_limit: u16,
        optional_active_verification_allowance: u16,
    ) -> Self {
        Self {
            profile,
            active_verification_limit,
            optional_active_verification_allowance,
        }
    }
}

/// Checked bridge between one completed origin assessment and its product
/// report envelope.
///
/// The token owns the exact profile label and retains only a domain-separated
/// digest of the canonical starting resource. It can be minted only from the
/// runtime's typed completion, configured limits, defense mode, and accounting
/// snapshot. This prevents a caller from pairing a successful-looking generic
/// [`RunReport`] with an incomplete assessment or a profile that did not govern
/// the run.
pub(crate) struct CompletedWebAssessmentTruth {
    run_started_at: SystemTime,
    target: String,
    authorized_origin: String,
    target_identity: [u8; 32],
    expected_accounting: RunAccounting,
    expected_elapsed_ms: u64,
    profile: ScanProfileV1,
}

impl CompletedWebAssessmentTruth {
    pub(crate) fn new(
        run_started_at: SystemTime,
        authorized_root: &WebAssessmentSubject,
        runtime_limits: AssessmentRuntimeLimits,
        usage: WebAssessmentUsage,
        completion: &WebAssessmentCompletion,
        defense_mode: WebAssessmentDefenseMode,
        profile: ScanProfileV1,
    ) -> Result<Self, AssessmentRunReportError> {
        let limits = runtime_limits.profile;
        let runtime_active_verification_limit = runtime_limits.active_verification_limit;
        validate_completed_assessment_truth_with_active_limit(
            authorized_root,
            runtime_limits,
            AssessmentUsageTruth::from(usage),
            completion,
            defense_mode,
            &profile,
        )?;
        let usage = AssessmentUsageTruth::from(usage);
        let target = authorized_root.url().to_string();
        Ok(Self {
            run_started_at,
            authorized_origin: authorized_root.url().origin().ascii_serialization(),
            target_identity: assessment_target_identity(authorized_root.url()),
            target,
            expected_accounting: expected_run_accounting_with_active_limit(
                limits,
                runtime_active_verification_limit,
                usage,
            ),
            expected_elapsed_ms: usage.elapsed_ms,
            profile,
        })
    }
}

impl fmt::Debug for CompletedWebAssessmentTruth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedWebAssessmentTruth")
            .field("run_started_at", &"<runtime-owned>")
            .field("target", &"<redacted>")
            .field("authorized_origin", &"<redacted>")
            .field("target_identity", &"<stable-digest>")
            .field("accounting", &"<bounded>")
            .field("elapsed_ms", &self.expected_elapsed_ms)
            .field("profile", &self.profile.profile().id())
            .finish()
    }
}

/// A validated, bounded assessment-run product envelope.
///
/// Construction preserves the already validated runtime and profile contracts.
/// Items are sorted by their stable, non-secret fingerprint so the same set of
/// runtime truths has one deterministic report order. Duplicate fingerprints
/// fail closed instead of silently collapsing two projections.
///
/// This type intentionally does not implement `Serialize` or `Deserialize`.
/// Renderers must consume its read-only accessors through a separately reviewed
/// redacted wire projection.
#[derive(Clone, PartialEq, Eq)]
pub struct AssessmentRunReport {
    run_report: RunReport,
    profile: ScanProfileV1,
    subjects: Vec<AssessmentSubjectInventoryEntry>,
    items: Vec<AssessmentItem>,
    #[cfg(feature = "authorization-review")]
    authorization_review: Option<WebAssessmentAuthorizationAudit>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<WebAssessmentOpenApiAudit>,
    #[cfg(feature = "rest-review")]
    rest_review: Option<WebAssessmentRestAudit>,
    #[cfg(feature = "ssrf-oast-review")]
    ssrf_oast_review: Option<WebAssessmentSsrfOastAudit>,
}

impl AssessmentRunReport {
    /// Mints the canonical run envelope from runtime-owned completion truth
    /// and composes it with the closed typed-item set.
    pub(crate) fn from_completed_truth(
        items: AssessmentItemSet,
        truth: CompletedWebAssessmentTruth,
        #[cfg(feature = "authorization-review")] authorization_review: Option<
            WebAssessmentAuthorizationAudit,
        >,
        #[cfg(feature = "openapi-review")] openapi_review: Option<WebAssessmentOpenApiAudit>,
        #[cfg(feature = "rest-review")] rest_review: Option<WebAssessmentRestAudit>,
        #[cfg(feature = "ssrf-oast-review")] ssrf_oast_review: Option<WebAssessmentSsrfOastAudit>,
    ) -> Result<Self, AssessmentRunReportError> {
        let run_report = build_run_report(&truth)?;
        Self::new_validated(
            run_report,
            items,
            truth,
            #[cfg(feature = "authorization-review")]
            authorization_review,
            #[cfg(feature = "openapi-review")]
            openapi_review,
            #[cfg(feature = "rest-review")]
            rest_review,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast_review,
        )
    }

    #[cfg(test)]
    fn new(
        run_report: RunReport,
        items: AssessmentItemSet,
        truth: CompletedWebAssessmentTruth,
    ) -> Result<Self, AssessmentRunReportError> {
        Self::new_validated(
            run_report,
            items,
            truth,
            #[cfg(feature = "authorization-review")]
            None,
            #[cfg(feature = "openapi-review")]
            None,
            #[cfg(feature = "rest-review")]
            None,
            #[cfg(feature = "ssrf-oast-review")]
            None,
        )
    }

    fn new_validated(
        run_report: RunReport,
        items: AssessmentItemSet,
        truth: CompletedWebAssessmentTruth,
        #[cfg(feature = "authorization-review")] authorization_review: Option<
            WebAssessmentAuthorizationAudit,
        >,
        #[cfg(feature = "openapi-review")] openapi_review: Option<WebAssessmentOpenApiAudit>,
        #[cfg(feature = "rest-review")] rest_review: Option<WebAssessmentRestAudit>,
        #[cfg(feature = "ssrf-oast-review")] ssrf_oast_review: Option<WebAssessmentSsrfOastAudit>,
    ) -> Result<Self, AssessmentRunReportError> {
        validate_run_identity(&run_report, truth.target_identity)?;
        validate_run_completion(&run_report)?;
        validate_run_accounting(
            &run_report,
            &truth.expected_accounting,
            truth.expected_elapsed_ms,
        )?;
        if !items.matches_exact_origin(run_report.authorized_origin()) {
            return Err(AssessmentRunReportError::ScopeAuthorityMismatch);
        }
        if !items.contains_stable_subject("authorized-root@1") {
            return Err(AssessmentRunReportError::SubjectReferenceMismatch);
        }
        let (subjects, mut items) = items.into_parts();
        validate_subject_inventory(&subjects, &items)?;
        validate_and_canonicalize_items(truth.profile.profile(), &mut items)?;
        #[cfg(feature = "authorization-review")]
        validate_authorization_audit(authorization_review.as_ref(), &items)?;
        #[cfg(feature = "openapi-review")]
        validate_openapi_audit(openapi_review.as_ref(), &items)?;
        #[cfg(feature = "rest-review")]
        validate_rest_audit(rest_review.as_ref(), &items)?;
        #[cfg(feature = "ssrf-oast-review")]
        validate_ssrf_oast_audit(ssrf_oast_review.as_ref(), &items)?;

        Ok(Self {
            run_report,
            profile: truth.profile,
            subjects,
            items,
            #[cfg(feature = "authorization-review")]
            authorization_review,
            #[cfg(feature = "openapi-review")]
            openapi_review,
            #[cfg(feature = "rest-review")]
            rest_review,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast_review,
        })
    }

    /// Returns the stable assessment-run schema.
    pub const fn schema(&self) -> &'static str {
        ASSESSMENT_RUN_REPORT_SCHEMA
    }

    /// Returns the exact validated profile that governed the run.
    pub const fn profile(&self) -> &ScanProfileV1 {
        &self.profile
    }

    /// Returns assessment items in canonical fingerprint order.
    pub fn items(&self) -> &[AssessmentItem] {
        &self.items
    }

    pub(crate) const fn run_report(&self) -> &RunReport {
        &self.run_report
    }

    /// Returns subjects registered by the consumed projection authority.
    pub const fn subject_count(&self) -> usize {
        self.subjects.len()
    }

    /// Returns the bounded assessment-item count.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Returns the optional redaction-safe resource-authorization audit.
    #[cfg(feature = "authorization-review")]
    pub const fn authorization_review_audit(&self) -> Option<&WebAssessmentAuthorizationAudit> {
        self.authorization_review.as_ref()
    }
    #[cfg(feature = "openapi-review")]
    pub const fn openapi_review_audit(&self) -> Option<&WebAssessmentOpenApiAudit> {
        self.openapi_review.as_ref()
    }

    /// Returns the optional redaction-safe REST read-only review audit.
    #[cfg(feature = "rest-review")]
    pub const fn rest_review_audit(&self) -> Option<&WebAssessmentRestAudit> {
        self.rest_review.as_ref()
    }

    /// Returns the optional redaction-safe query-only SSRF/OAST review audit.
    #[cfg(feature = "ssrf-oast-review")]
    pub const fn ssrf_oast_review_audit(&self) -> Option<&WebAssessmentSsrfOastAudit> {
        self.ssrf_oast_review.as_ref()
    }
}

#[cfg(feature = "ssrf-oast-review")]
fn validate_ssrf_oast_audit(
    audit: Option<&WebAssessmentSsrfOastAudit>,
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    let projected = items
        .iter()
        .filter(|item| item.capability_id() == SSRF_OAST_REVIEW_CAPABILITY_ID)
        .count();
    if projected > 1 {
        return Err(AssessmentRunReportError::SsrfOastAuditMismatch);
    }
    let Some(audit) = audit else {
        return if projected == 0 {
            Ok(())
        } else {
            Err(AssessmentRunReportError::SsrfOastAuditMismatch)
        };
    };
    let positive = audit.outcome() == SsrfOastRuntimeOutcome::RepeatedCallbacksObserved;
    if usize::from(audit.target_request_count()) > MAX_SSRF_OAST_REVIEW_REQUESTS
        || usize::from(audit.provider_request_count()) > MAX_SSRF_OAST_REVIEW_PROVIDER_REQUESTS
        || usize::from(audit.active_verification_count())
            > MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS
        || audit.item_projected() != (projected == 1)
        || positive != audit.item_projected()
        || (positive
            && (usize::from(audit.target_request_count()) != MAX_SSRF_OAST_REVIEW_REQUESTS
                || usize::from(audit.active_verification_count())
                    != MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS
                || !audit.preflight_clean()
                || !audit.candidate_callback_observed()
                || !audit.replay_callback_observed()
                || !audit.cleanup_verified()))
    {
        return Err(AssessmentRunReportError::SsrfOastAuditMismatch);
    }
    Ok(())
}

#[cfg(feature = "openapi-review")]
fn validate_openapi_audit(
    audit: Option<&WebAssessmentOpenApiAudit>,
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    let projected = items
        .iter()
        .filter(|item| item.capability_id() == OPENAPI_REVIEW_CAPABILITY_ID)
        .count();
    if projected > 1 {
        return Err(AssessmentRunReportError::OpenApiAuditMismatch);
    }
    let Some(audit) = audit else {
        return if projected == 0 {
            Ok(())
        } else {
            Err(AssessmentRunReportError::OpenApiAuditMismatch)
        };
    };
    if usize::from(audit.request_count()) > MAX_OPENAPI_REVIEW_REQUESTS
        || audit.active_verification_count() > 1
        || audit.item_projected() != (projected == 1)
        || (audit.outcome() == OpenApiRuntimeOutcome::DocumentObserved) != (projected == 1)
    {
        return Err(AssessmentRunReportError::OpenApiAuditMismatch);
    }
    Ok(())
}

#[cfg(feature = "rest-review")]
fn validate_rest_audit(
    audit: Option<&WebAssessmentRestAudit>,
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    let projected = items
        .iter()
        .filter(|item| item.capability_id() == REST_REVIEW_CAPABILITY_ID)
        .count();
    if projected > 1 {
        return Err(AssessmentRunReportError::RestAuditMismatch);
    }
    let Some(audit) = audit else {
        return if projected == 0 {
            Ok(())
        } else {
            Err(AssessmentRunReportError::RestAuditMismatch)
        };
    };
    if !RestAuditFacts::from_audit(audit).is_valid(projected) {
        return Err(AssessmentRunReportError::RestAuditMismatch);
    }
    Ok(())
}

#[cfg(feature = "rest-review")]
#[derive(Clone, Copy)]
struct RestAuditFacts {
    outcome: RestRuntimeOutcome,
    request_count: usize,
    active_verification_count: usize,
    eligible_operation_count: u32,
    selected_operation_present: bool,
    replay_stable: bool,
    item_projected: bool,
}

#[cfg(feature = "rest-review")]
impl RestAuditFacts {
    fn from_audit(audit: &WebAssessmentRestAudit) -> Self {
        Self {
            outcome: audit.outcome(),
            request_count: usize::from(audit.request_count()),
            active_verification_count: usize::from(audit.active_verification_count()),
            eligible_operation_count: audit.eligible_operation_count(),
            selected_operation_present: audit.selected_operation_identity().is_some(),
            replay_stable: audit.replay_stable(),
            item_projected: audit.item_projected(),
        }
    }

    fn is_valid(self, projected: usize) -> bool {
        let positive = self.outcome == RestRuntimeOutcome::SurfaceObserved;
        self.request_count <= MAX_REST_REVIEW_REQUESTS
            && self.active_verification_count <= MAX_REST_REVIEW_ACTIVE_VERIFICATIONS
            && self.active_verification_count
                == usize::from(self.request_count == MAX_REST_REVIEW_REQUESTS)
            && self.item_projected == (projected == 1)
            && positive == self.item_projected
            && self.replay_stable == positive
            && (!positive
                || (self.request_count == MAX_REST_REVIEW_REQUESTS
                    && self.active_verification_count == MAX_REST_REVIEW_ACTIVE_VERIFICATIONS
                    && self.eligible_operation_count > 0
                    && self.selected_operation_present))
    }
}

impl fmt::Debug for AssessmentRunReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("AssessmentRunReport");
        debug
            .field("schema", &ASSESSMENT_RUN_REPORT_SCHEMA)
            .field("run_report", &"<redacted>")
            .field("profile", &self.profile.profile().id())
            .field("subject_count", &self.subjects.len())
            .field("item_count", &self.items.len());
        #[cfg(feature = "authorization-review")]
        debug.field(
            "authorization_review_audit_present",
            &self.authorization_review.is_some(),
        );
        #[cfg(feature = "openapi-review")]
        debug.field(
            "openapi_review_audit_present",
            &self.openapi_review.is_some(),
        );
        #[cfg(feature = "rest-review")]
        debug.field("rest_review_audit_present", &self.rest_review.is_some());
        #[cfg(feature = "ssrf-oast-review")]
        debug.field(
            "ssrf_oast_review_audit_present",
            &self.ssrf_oast_review.is_some(),
        );
        debug.finish()
    }
}

#[cfg(feature = "authorization-review")]
fn validate_authorization_audit(
    audit: Option<&WebAssessmentAuthorizationAudit>,
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    let projected_count = items
        .iter()
        .filter(|item| item.capability_id() == RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID)
        .count();
    if projected_count > 1 {
        return Err(AssessmentRunReportError::AuthorizationAuditMismatch);
    }
    let Some(audit) = audit else {
        return if projected_count == 0 {
            Ok(())
        } else {
            Err(AssessmentRunReportError::AuthorizationAuditMismatch)
        };
    };
    let positive = audit.outcome() == AuthorizationReviewOutcome::StableCrossPrincipalEquivalence;
    if audit.selected_path_count() == 0
        || usize::from(audit.selected_path_count()) > HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS
        || usize::from(audit.ignored_path_count()) > HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS
        || usize::from(audit.request_count()) > MAX_AUTHORIZATION_REVIEW_REQUESTS
        || audit.item_projected() != (projected_count == 1)
        || positive != audit.item_projected()
        || (positive && usize::from(audit.request_count()) != MAX_AUTHORIZATION_REVIEW_REQUESTS)
    {
        return Err(AssessmentRunReportError::AuthorizationAuditMismatch);
    }
    Ok(())
}

/// Invalid relationship in a typed assessment-run envelope.
///
/// Error variants retain only fixed classifications and bounded collection
/// counts. They never copy a target, subject, fingerprint, evidence identity,
/// credential, header, or diagnostic body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AssessmentRunReportError {
    /// Runtime-owned truth could not be represented by the canonical generic
    /// run envelope. The underlying error is intentionally not retained.
    #[error("runtime assessment truth could not produce a canonical run envelope")]
    RunEnvelopeInvalid,
    /// The item collection exceeded its compiled retention ceiling.
    #[error("assessment item count {actual} exceeds the limit of {limit}")]
    TooManyItems {
        /// Supplied collection length.
        actual: usize,
        /// Compiled collection ceiling.
        limit: usize,
    },
    /// Two items declared the same stable fingerprint.
    #[error("assessment item fingerprints must be unique")]
    DuplicateFingerprint,
    /// A single-resource baseline profile cannot label an origin assessment.
    #[error("the baseline scan profile cannot label an origin assessment")]
    BaselineItemsForbidden,
    /// The origin assessment retained one or more typed incomplete reasons.
    #[error("only a complete origin assessment can produce this report")]
    AssessmentIncomplete,
    /// The selected profile limits did not govern the origin assessment.
    #[error("the scan profile does not match the assessment runtime authority")]
    ProfileAuthorityMismatch,
    /// The selected defense mode did not match the governing profile.
    #[error("the scan profile does not match the assessment defense mode")]
    ProfileDefenseMismatch,
    /// Runtime usage was inconsistent with a completed bounded assessment.
    #[error("assessment usage is inconsistent with its runtime authority")]
    AssessmentUsageMismatch,
    /// The run envelope did not represent successful exhaustive completion.
    #[error("assessment run status must be complete with a completed stop reason")]
    RunNotComplete,
    /// The run envelope carried accounting other than the runtime's exact
    /// metered limits and usage.
    #[error("assessment run accounting does not match runtime usage")]
    RunAccountingMismatch,
    /// The run timestamps did not encode the runtime's exact elapsed duration.
    #[error("assessment run duration does not match runtime usage")]
    RunDurationMismatch,
    /// The run did not contain exactly the canonical assessment step receipt.
    #[error("assessment run step inventory is not canonical")]
    RunStepMismatch,
    /// Generic run outcomes cannot be injected alongside the closed item set.
    #[error("assessment run outcomes must be projected only as assessment items")]
    RunOutcomesForbidden,
    /// The run identity was not one canonical exact HTTP(S) origin.
    #[error("assessment run identity must match the canonical authorized resource")]
    RunIdentityNotExactOrigin,
    /// The item set was minted for another exact-origin authority.
    #[error("assessment item scope does not match the run authority")]
    ScopeAuthorityMismatch,
    /// An item reference did not belong to the consumed subject inventory.
    #[error("assessment item subject reference is outside its projection inventory")]
    SubjectReferenceMismatch,
    /// The optional authorization audit disagreed with projected item truth.
    #[cfg(feature = "authorization-review")]
    #[error("authorization review audit does not match projected item truth")]
    AuthorizationAuditMismatch,
    /// The optional OpenAPI audit disagreed with projected item truth.
    #[cfg(feature = "openapi-review")]
    #[error("OpenAPI review audit does not match projected item truth")]
    OpenApiAuditMismatch,
    /// The optional REST review audit disagreed with projected item truth.
    #[cfg(feature = "rest-review")]
    #[error("REST review audit does not match projected item truth")]
    RestAuditMismatch,
    /// The optional SSRF/OAST review audit disagreed with projected item truth.
    #[cfg(feature = "ssrf-oast-review")]
    #[error("SSRF OAST review audit does not match projected item truth")]
    SsrfOastAuditMismatch,
}

fn build_run_report(
    truth: &CompletedWebAssessmentTruth,
) -> Result<RunReport, AssessmentRunReportError> {
    let completed_at = truth
        .run_started_at
        .checked_add(Duration::from_millis(truth.expected_elapsed_ms))
        .ok_or(AssessmentRunReportError::RunEnvelopeInvalid)?;
    let stop_reason = RunStopReason::new(RunStopCode::Completed, WEB_ASSESSMENT_STOP_DETAIL)
        .map_err(|_| AssessmentRunReportError::RunEnvelopeInvalid)?;
    let step = RunStepReport::new(
        1,
        WEB_ASSESSMENT_RUN_STEP_ID,
        RunStepStatus::Succeeded,
        truth.expected_elapsed_ms,
        None,
    )
    .map_err(|_| AssessmentRunReportError::RunEnvelopeInvalid)?;
    let input = RunReportInput::new(
        RunStatus::Complete,
        stop_reason,
        truth.target.clone(),
        truth.authorized_origin.clone(),
        truth.run_started_at.into(),
        completed_at.into(),
    )
    .map_err(|_| AssessmentRunReportError::RunEnvelopeInvalid)?
    .with_accounting(truth.expected_accounting.clone())
    .with_steps(vec![step])
    .with_outcomes(Vec::new());
    RunReport::new(input).map_err(|_| AssessmentRunReportError::RunEnvelopeInvalid)
}

fn validate_run_identity(
    run_report: &RunReport,
    expected_target_identity: [u8; 32],
) -> Result<(), AssessmentRunReportError> {
    let authorized_origin = run_report.authorized_origin();
    let Ok(target) = Url::parse(run_report.target()) else {
        return Err(AssessmentRunReportError::RunIdentityNotExactOrigin);
    };
    if !is_canonical_http_origin(authorized_origin)
        || !matches!(target.scheme(), "http" | "https")
        || !target.username().is_empty()
        || target.password().is_some()
        || target.host().is_none()
        || target.query().is_some()
        || target.fragment().is_some()
        || target.origin().ascii_serialization() != authorized_origin
        || target.as_str() != run_report.target()
        || assessment_target_identity(&target) != expected_target_identity
    {
        return Err(AssessmentRunReportError::RunIdentityNotExactOrigin);
    }
    Ok(())
}

fn validate_run_completion(run_report: &RunReport) -> Result<(), AssessmentRunReportError> {
    if run_report.status() != RunStatus::Complete
        || run_report.stop_reason().code() != RunStopCode::Completed
    {
        return Err(AssessmentRunReportError::RunNotComplete);
    }
    if !run_report.outcomes().is_empty() {
        return Err(AssessmentRunReportError::RunOutcomesForbidden);
    }
    Ok(())
}

fn validate_run_accounting(
    run_report: &RunReport,
    expected: &RunAccounting,
    expected_elapsed_ms: u64,
) -> Result<(), AssessmentRunReportError> {
    if run_report.accounting() != expected {
        return Err(AssessmentRunReportError::RunAccountingMismatch);
    }

    let elapsed = run_report.completed_at() - run_report.started_at();
    if u64::try_from(elapsed.num_milliseconds()).ok() != Some(expected_elapsed_ms)
        || elapsed.subsec_nanos().rem_euclid(1_000_000) != 0
    {
        return Err(AssessmentRunReportError::RunDurationMismatch);
    }

    let [step] = run_report.steps() else {
        return Err(AssessmentRunReportError::RunStepMismatch);
    };
    if step.ordinal() != 1
        || step.action_id() != WEB_ASSESSMENT_RUN_STEP_ID
        || step.status() != RunStepStatus::Succeeded
        || step.duration_ms() != expected_elapsed_ms
        || step.detail().is_some()
    {
        return Err(AssessmentRunReportError::RunStepMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AssessmentUsageTruth {
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

impl From<WebAssessmentUsage> for AssessmentUsageTruth {
    fn from(usage: WebAssessmentUsage) -> Self {
        Self {
            retained_subjects: usage.retained_subjects(),
            executed_subjects: usage.executed_subjects(),
            retained_forms: usage.retained_forms(),
            retained_unique_url_bytes: usage.retained_unique_url_bytes(),
            total_requests: usage.total_requests(),
            active_verifications: usage.active_verifications(),
            request_body_bytes: usage.request_body_bytes(),
            response_bytes: usage.response_bytes(),
            elapsed_ms: usage.elapsed_ms(),
        }
    }
}

#[cfg(test)]
fn validate_completed_assessment_truth(
    authorized_root: &WebAssessmentSubject,
    limits: WebAssessmentLimits,
    usage: AssessmentUsageTruth,
    completion: &WebAssessmentCompletion,
    defense_mode: WebAssessmentDefenseMode,
    profile: &ScanProfileV1,
) -> Result<(), AssessmentRunReportError> {
    validate_completed_assessment_truth_with_active_limit(
        authorized_root,
        AssessmentRuntimeLimits::new(limits, limits.max_active_verifications(), 0),
        usage,
        completion,
        defense_mode,
        profile,
    )
}

fn validate_completed_assessment_truth_with_active_limit(
    authorized_root: &WebAssessmentSubject,
    runtime_limits: AssessmentRuntimeLimits,
    usage: AssessmentUsageTruth,
    completion: &WebAssessmentCompletion,
    defense_mode: WebAssessmentDefenseMode,
    profile: &ScanProfileV1,
) -> Result<(), AssessmentRunReportError> {
    let limits = runtime_limits.profile;
    let runtime_active_verification_limit = runtime_limits.active_verification_limit;
    let optional_active_verification_allowance =
        runtime_limits.optional_active_verification_allowance;
    if profile.profile() != BuiltInScanProfile::WebReview {
        return Err(AssessmentRunReportError::BaselineItemsForbidden);
    }
    if profile.web_assessment_limits() != limits {
        return Err(AssessmentRunReportError::ProfileAuthorityMismatch);
    }
    let expected_defense = if profile.defense_enforcement_enabled() {
        WebAssessmentDefenseMode::Enforced
    } else {
        WebAssessmentDefenseMode::ObservationOnly
    };
    if defense_mode != expected_defense {
        return Err(AssessmentRunReportError::ProfileDefenseMismatch);
    }
    if !matches!(completion, WebAssessmentCompletion::Complete) {
        return Err(AssessmentRunReportError::AssessmentIncomplete);
    }

    let root = authorized_root.url();
    if authorized_root.origin() != WebAssessmentSubjectOrigin::AuthorizedRoot
        || authorized_root.depth() != 0
        || authorized_root.method() != WebAssessmentMethod::Get
        || !matches!(root.scheme(), "http" | "https")
        || root.host().is_none()
        || !root.username().is_empty()
        || root.password().is_some()
        || root.query().is_some()
        || root.fragment().is_some()
        || root.path().is_empty()
        || root.as_str().len() > limits.max_canonical_url_bytes()
    {
        return Err(AssessmentRunReportError::RunIdentityNotExactOrigin);
    }

    let request_body_limit = RuntimeBudget::default().max_request_body_bytes();
    let compiled_optional_allowance = {
        let allowance = 0_u16;
        #[cfg(feature = "graphql-review")]
        let allowance = allowance.saturating_add(1);
        #[cfg(feature = "authorization-review")]
        let allowance = allowance.saturating_add(1);
        #[cfg(feature = "openapi-review")]
        let allowance = allowance.saturating_add(1);
        #[cfg(feature = "rest-review")]
        let allowance = allowance.saturating_add(1);
        allowance
    };
    let expected_active_limit = limits
        .max_active_verifications()
        .checked_add(optional_active_verification_allowance)
        .ok_or(AssessmentRunReportError::AssessmentUsageMismatch)?;
    if usage.retained_subjects == 0
        || usage.executed_subjects != usage.retained_subjects
        || usage.retained_subjects > limits.max_subjects()
        || usage.retained_forms > limits.max_forms()
        || usage.retained_unique_url_bytes < root.as_str().len()
        || usage.retained_unique_url_bytes > limits.max_retained_url_bytes()
        || usage.total_requests > limits.max_total_requests()
        || optional_active_verification_allowance > compiled_optional_allowance
        || runtime_active_verification_limit != expected_active_limit
        || usage.active_verifications > runtime_active_verification_limit
        || usage.request_body_bytes > request_body_limit
        || usage.response_bytes > limits.max_total_response_bytes()
        || usage.elapsed_ms > u64::try_from(limits.max_wall_time().as_millis()).unwrap_or(u64::MAX)
    {
        return Err(AssessmentRunReportError::AssessmentUsageMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn expected_run_accounting(
    limits: WebAssessmentLimits,
    usage: AssessmentUsageTruth,
) -> RunAccounting {
    expected_run_accounting_with_active_limit(limits, limits.max_active_verifications(), usage)
}

fn expected_run_accounting_with_active_limit(
    limits: WebAssessmentLimits,
    runtime_active_verification_limit: u16,
    usage: AssessmentUsageTruth,
) -> RunAccounting {
    let budget = RuntimeBudget::default()
        .with_max_total_requests(limits.max_total_requests())
        .with_max_response_bytes(limits.max_total_response_bytes())
        .with_max_wall_time(limits.max_wall_time())
        .with_max_active_verifications(runtime_active_verification_limit);
    RunAccounting::new(
        ResourceAccounting::metered(
            u64::from(budget.max_total_requests()),
            u64::from(usage.total_requests),
        ),
        ResourceAccounting::metered(budget.max_response_bytes(), usage.response_bytes),
        ResourceAccounting::metered(budget.max_request_body_bytes(), usage.request_body_bytes),
        ResourceAccounting::metered(budget.max_wall_time_ms(), usage.elapsed_ms),
    )
}

fn assessment_target_identity(target: &Url) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ASSESSMENT_RUN_TARGET_DOMAIN);
    digest.update((target.as_str().len() as u64).to_be_bytes());
    digest.update(target.as_str().as_bytes());
    digest.finalize().into()
}

fn is_canonical_http_origin(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == value
}

fn validate_item_count(item_count: usize) -> Result<(), AssessmentRunReportError> {
    if item_count > MAX_ASSESSMENT_RUN_ITEMS {
        return Err(AssessmentRunReportError::TooManyItems {
            actual: item_count,
            limit: MAX_ASSESSMENT_RUN_ITEMS,
        });
    }
    Ok(())
}

fn validate_profile_item_count(
    profile: BuiltInScanProfile,
    _item_count: usize,
) -> Result<(), AssessmentRunReportError> {
    if profile == BuiltInScanProfile::Baseline {
        return Err(AssessmentRunReportError::BaselineItemsForbidden);
    }
    Ok(())
}

fn validate_subject_inventory(
    subjects: &[AssessmentSubjectInventoryEntry],
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    if subjects.is_empty() {
        return Err(AssessmentRunReportError::SubjectReferenceMismatch);
    }
    let mut fingerprints = BTreeSet::new();
    for (ordinal, subject) in subjects.iter().enumerate() {
        if subject.reference().ordinal() != u32::try_from(ordinal).unwrap_or(u32::MAX)
            || !fingerprints.insert(subject.fingerprint())
        {
            return Err(AssessmentRunReportError::SubjectReferenceMismatch);
        }
    }
    if items.iter().any(|item| {
        usize::try_from(item.subject_reference().ordinal())
            .map_or(true, |ordinal| ordinal >= subjects.len())
    }) {
        return Err(AssessmentRunReportError::SubjectReferenceMismatch);
    }
    Ok(())
}

trait CanonicalFingerprint {
    fn canonical_fingerprint(&self) -> &str;
}

impl CanonicalFingerprint for AssessmentItem {
    fn canonical_fingerprint(&self) -> &str {
        self.fingerprint()
    }
}

fn validate_and_canonicalize_items<T>(
    profile: BuiltInScanProfile,
    items: &mut [T],
) -> Result<(), AssessmentRunReportError>
where
    T: CanonicalFingerprint,
{
    validate_item_count(items.len())?;
    validate_profile_item_count(profile, items.len())?;
    canonicalize_items(items)
}

fn canonicalize_items<T>(items: &mut [T]) -> Result<(), AssessmentRunReportError>
where
    T: CanonicalFingerprint,
{
    items.sort_unstable_by(|left, right| {
        left.canonical_fingerprint()
            .cmp(right.canonical_fingerprint())
    });
    if items
        .windows(2)
        .any(|pair| pair[0].canonical_fingerprint() == pair[1].canonical_fingerprint())
    {
        return Err(AssessmentRunReportError::DuplicateFingerprint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use termivar_core::{
        EntityId, RunOutcomeRecord, RunReportInput, RunStatus, RunStepReport, RunStepStatus,
        RunStopCode, RunStopReason,
    };

    use super::super::assessment_item::{
        AssessmentProjectionContext, StableAssessmentScopeId, StableAssessmentSubjectId,
    };
    use super::super::{WebAssessmentIncompleteReason, WebAssessmentRuntime};
    use super::*;
    use crate::KnowledgeBase;

    const PRIVATE_EXACT_ORIGIN: &str = "https://private-target-credential-sentinel.test";
    const PRIVATE_CANONICAL_TARGET: &str = "https://private-target-credential-sentinel.test/review";
    const PRIVATE_STOP_DETAIL: &str = "private-stop-diagnostic-sentinel";
    const TEST_ELAPSED_MS: u64 = 1_000;

    fn usage_truth(target: &str) -> AssessmentUsageTruth {
        AssessmentUsageTruth {
            retained_subjects: 1,
            executed_subjects: 1,
            retained_forms: 0,
            retained_unique_url_bytes: target.len(),
            total_requests: 1,
            active_verifications: 0,
            request_body_bytes: 0,
            response_bytes: 128,
            elapsed_ms: TEST_ELAPSED_MS,
        }
    }

    fn completed_truth(target: &str) -> CompletedWebAssessmentTruth {
        let target = Url::parse(target).unwrap();
        let limits = WebAssessmentLimits::default();
        let usage = usage_truth(target.as_str());
        CompletedWebAssessmentTruth {
            run_started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            authorized_origin: target.origin().ascii_serialization(),
            target_identity: assessment_target_identity(&target),
            target: target.to_string(),
            expected_accounting: expected_run_accounting(limits, usage),
            expected_elapsed_ms: usage.elapsed_ms,
            profile: ScanProfileV1::web_review().unwrap(),
        }
    }

    fn complete_run_report(target: &str, authorized_origin: &str) -> RunReport {
        run_report(
            RunStatus::Complete,
            RunStopCode::Completed,
            RunStepStatus::Succeeded,
            target,
            authorized_origin,
            "2026-08-28T10:00:01Z",
            WEB_ASSESSMENT_RUN_STEP_ID,
            None,
            expected_run_accounting(WebAssessmentLimits::default(), usage_truth(target)),
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_report(
        status: RunStatus,
        stop_code: RunStopCode,
        step_status: RunStepStatus,
        target: &str,
        authorized_origin: &str,
        completed_at: &str,
        step_action: &str,
        step_detail: Option<String>,
        accounting: RunAccounting,
        outcomes: Vec<RunOutcomeRecord>,
    ) -> RunReport {
        let input = RunReportInput::new(
            status,
            RunStopReason::new(stop_code, PRIVATE_STOP_DETAIL).unwrap(),
            target,
            authorized_origin,
            "2026-08-28T10:00:00Z".parse().unwrap(),
            completed_at.parse().unwrap(),
        )
        .unwrap()
        .with_accounting(accounting)
        .with_steps(vec![RunStepReport::new(
            1,
            step_action,
            step_status,
            TEST_ELAPSED_MS,
            step_detail,
        )
        .unwrap()])
        .with_outcomes(outcomes);
        RunReport::new(input).unwrap()
    }

    fn root_item_set(exact_origin: &str) -> AssessmentItemSet {
        let knowledge = KnowledgeBase::new();
        let mut context = AssessmentProjectionContext::new(
            &knowledge,
            StableAssessmentScopeId::from_exact_origin(exact_origin).unwrap(),
        );
        context
            .register_subject(
                EntityId::new(format!("endpoint:{exact_origin}/")).unwrap(),
                StableAssessmentSubjectId::new("authorized-root@1").unwrap(),
                Vec::new(),
            )
            .unwrap();
        context.finish()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TestItem(&'static str);

    impl CanonicalFingerprint for TestItem {
        fn canonical_fingerprint(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn empty_validated_reports_expose_only_read_only_components() {
        let report = AssessmentRunReport::new(
            complete_run_report(PRIVATE_CANONICAL_TARGET, PRIVATE_EXACT_ORIGIN),
            root_item_set(PRIVATE_EXACT_ORIGIN),
            completed_truth(PRIVATE_CANONICAL_TARGET),
        )
        .unwrap();

        assert_eq!(report.schema(), ASSESSMENT_RUN_REPORT_SCHEMA);
        assert_eq!(report.run_report.target(), PRIVATE_CANONICAL_TARGET);
        assert_eq!(report.profile().profile(), BuiltInScanProfile::WebReview);
        assert!(report.items().is_empty());
        assert_eq!(report.subject_count(), 1);
        assert_eq!(report.item_count(), 0);
    }

    #[test]
    fn run_identity_must_match_the_exact_canonical_assessment_root() {
        for (target, authorized_origin) in [
            (
                "https://example.test/private-path-credential-sentinel",
                "https://example.test",
            ),
            (
                "https://target-identity-sentinel.test/",
                "https://authority-identity-sentinel.test",
            ),
            (
                "https://user:credential-sentinel@example.test/",
                "https://example.test",
            ),
            (
                "https://example.test/?credential-sentinel=value",
                "https://example.test",
            ),
            ("HTTPS://EXAMPLE.TEST/", "https://example.test"),
            ("https://example.test/", "https://example.test/"),
            ("ftp://example.test/", "ftp://example.test"),
        ] {
            let error = AssessmentRunReport::new(
                complete_run_report(target, authorized_origin),
                root_item_set("https://example.test"),
                completed_truth("https://example.test/"),
            )
            .unwrap_err();
            assert_eq!(error, AssessmentRunReportError::RunIdentityNotExactOrigin);
            let display = error.to_string();
            assert!(!display.contains(target));
            assert!(!display.contains(authorized_origin));
            assert!(!display.contains("credential-sentinel"));
        }

        for (target, exact_origin) in [
            ("http://example.test/", "http://example.test"),
            ("https://example.test/", "https://example.test"),
            (
                "https://example.test:8443/review",
                "https://example.test:8443",
            ),
            ("http://127.0.0.1:8080/path", "http://127.0.0.1:8080"),
            ("http://[::1]:8080/root", "http://[::1]:8080"),
        ] {
            let report = AssessmentRunReport::new(
                complete_run_report(target, exact_origin),
                root_item_set(exact_origin),
                completed_truth(target),
            )
            .unwrap();
            assert_eq!(report.run_report.target(), target);
            assert_eq!(report.run_report.authorized_origin(), exact_origin);
        }
    }

    #[test]
    fn item_scope_must_match_the_run_exact_origin() {
        let error = AssessmentRunReport::new(
            complete_run_report("https://example.test/path", "https://example.test"),
            root_item_set("https://other.test"),
            completed_truth("https://example.test/path"),
        )
        .unwrap_err();

        assert_eq!(error, AssessmentRunReportError::ScopeAuthorityMismatch);
        assert!(!error.to_string().contains("example.test"));
        assert!(!error.to_string().contains("other.test"));
    }

    #[test]
    fn item_limit_accepts_the_boundary_and_rejects_one_more() {
        assert_eq!(validate_item_count(MAX_ASSESSMENT_RUN_ITEMS), Ok(()));
        assert_eq!(
            validate_item_count(MAX_ASSESSMENT_RUN_ITEMS + 1),
            Err(AssessmentRunReportError::TooManyItems {
                actual: MAX_ASSESSMENT_RUN_ITEMS + 1,
                limit: MAX_ASSESSMENT_RUN_ITEMS,
            })
        );
    }

    #[test]
    fn baseline_can_never_label_an_origin_assessment_even_when_items_are_empty() {
        assert_eq!(
            validate_profile_item_count(BuiltInScanProfile::Baseline, 0),
            Err(AssessmentRunReportError::BaselineItemsForbidden)
        );
        assert_eq!(
            validate_profile_item_count(BuiltInScanProfile::Baseline, 1),
            Err(AssessmentRunReportError::BaselineItemsForbidden)
        );
        assert_eq!(
            validate_profile_item_count(BuiltInScanProfile::WebReview, 1),
            Ok(())
        );

        let mut item = vec![TestItem("sha256:baseline-forbidden")];
        assert_eq!(
            validate_and_canonicalize_items(BuiltInScanProfile::Baseline, &mut item),
            Err(AssessmentRunReportError::BaselineItemsForbidden)
        );
    }

    #[test]
    fn truth_bridge_rejects_incomplete_profile_limit_defense_and_usage_mislabeling() {
        let runtime =
            WebAssessmentRuntime::builder(Url::parse("https://example.test/review").unwrap())
                .build()
                .unwrap();
        let root = runtime.authorized_root();
        let limits = WebAssessmentLimits::default();
        let usage = usage_truth(root.url().as_str());
        let web_review = ScanProfileV1::web_review().unwrap();

        assert_eq!(
            validate_completed_assessment_truth(
                root,
                limits,
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &web_review,
            ),
            Ok(())
        );

        let incomplete = WebAssessmentCompletion::Incomplete {
            reasons: BTreeSet::from([WebAssessmentIncompleteReason::HostCancellation]),
        };
        assert_eq!(
            validate_completed_assessment_truth(
                root,
                limits,
                usage,
                &incomplete,
                WebAssessmentDefenseMode::ObservationOnly,
                &web_review,
            ),
            Err(AssessmentRunReportError::AssessmentIncomplete)
        );
        assert_eq!(
            validate_completed_assessment_truth(
                root,
                limits,
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &ScanProfileV1::baseline().unwrap(),
            ),
            Err(AssessmentRunReportError::BaselineItemsForbidden)
        );

        let narrower = limits.with_max_subjects(2).unwrap();
        assert_eq!(
            validate_completed_assessment_truth(
                root,
                narrower,
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &web_review,
            ),
            Err(AssessmentRunReportError::ProfileAuthorityMismatch)
        );
        assert_eq!(
            validate_completed_assessment_truth(
                root,
                limits,
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::Enforced,
                &web_review,
            ),
            Err(AssessmentRunReportError::ProfileDefenseMismatch)
        );

        let excessive_usage = AssessmentUsageTruth {
            total_requests: limits.max_total_requests().saturating_add(1),
            ..usage
        };
        assert_eq!(
            validate_completed_assessment_truth(
                root,
                limits,
                excessive_usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &web_review,
            ),
            Err(AssessmentRunReportError::AssessmentUsageMismatch)
        );
    }

    #[cfg(all(
        feature = "graphql-review",
        feature = "authorization-review",
        feature = "openapi-review",
        feature = "rest-review"
    ))]
    #[test]
    fn independently_enabled_optional_children_have_an_exact_additive_active_allowance() {
        let runtime =
            WebAssessmentRuntime::builder(Url::parse("https://example.test/review").unwrap())
                .build()
                .unwrap();
        let root = runtime.authorized_root();
        let limits = WebAssessmentLimits::default();
        let expected = limits.max_active_verifications().checked_add(4).unwrap();
        let usage = AssessmentUsageTruth {
            active_verifications: 4,
            ..usage_truth(root.url().as_str())
        };
        let profile = ScanProfileV1::web_review().unwrap();

        assert_eq!(
            validate_completed_assessment_truth_with_active_limit(
                root,
                AssessmentRuntimeLimits::new(limits, expected, 4),
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &profile,
            ),
            Ok(())
        );
        assert_eq!(
            validate_completed_assessment_truth_with_active_limit(
                root,
                AssessmentRuntimeLimits::new(limits, expected - 1, 4),
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &profile,
            ),
            Err(AssessmentRunReportError::AssessmentUsageMismatch)
        );
        assert_eq!(
            validate_completed_assessment_truth_with_active_limit(
                root,
                AssessmentRuntimeLimits::new(limits, expected + 1, 5),
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &profile,
            ),
            Err(AssessmentRunReportError::AssessmentUsageMismatch)
        );
    }

    #[cfg(feature = "rest-review")]
    #[test]
    fn rest_audit_contract_requires_exact_positive_replay_and_item_truth() {
        let positive = RestAuditFacts {
            outcome: RestRuntimeOutcome::SurfaceObserved,
            request_count: MAX_REST_REVIEW_REQUESTS,
            active_verification_count: MAX_REST_REVIEW_ACTIVE_VERIFICATIONS,
            eligible_operation_count: 1,
            selected_operation_present: true,
            replay_stable: true,
            item_projected: true,
        };
        assert!(positive.is_valid(1));

        for invalid in [
            RestAuditFacts {
                request_count: MAX_REST_REVIEW_REQUESTS + 1,
                ..positive
            },
            RestAuditFacts {
                active_verification_count: MAX_REST_REVIEW_ACTIVE_VERIFICATIONS + 1,
                ..positive
            },
            RestAuditFacts {
                eligible_operation_count: 0,
                ..positive
            },
            RestAuditFacts {
                selected_operation_present: false,
                ..positive
            },
            RestAuditFacts {
                replay_stable: false,
                ..positive
            },
            RestAuditFacts {
                item_projected: false,
                ..positive
            },
        ] {
            assert!(!invalid.is_valid(1));
        }

        let negative = RestAuditFacts {
            outcome: RestRuntimeOutcome::NotEligible,
            request_count: 0,
            active_verification_count: 0,
            eligible_operation_count: 0,
            selected_operation_present: false,
            replay_stable: false,
            item_projected: false,
        };
        assert!(negative.is_valid(0));
        assert!(!negative.is_valid(1));
    }

    #[test]
    fn partial_cancelled_failed_and_no_eligible_runs_cannot_masquerade_as_complete() {
        for (status, stop, step) in [
            (
                RunStatus::Partial,
                RunStopCode::NoEligibleAction,
                RunStepStatus::Succeeded,
            ),
            (
                RunStatus::Cancelled,
                RunStopCode::Cancelled,
                RunStepStatus::Cancelled,
            ),
            (
                RunStatus::Failed,
                RunStopCode::StepFailed,
                RunStepStatus::Failed,
            ),
            (
                RunStatus::Complete,
                RunStopCode::NoEligibleAction,
                RunStepStatus::Succeeded,
            ),
        ] {
            let run = run_report(
                status,
                stop,
                step,
                PRIVATE_CANONICAL_TARGET,
                PRIVATE_EXACT_ORIGIN,
                "2026-08-28T10:00:01Z",
                WEB_ASSESSMENT_RUN_STEP_ID,
                None,
                expected_run_accounting(
                    WebAssessmentLimits::default(),
                    usage_truth(PRIVATE_CANONICAL_TARGET),
                ),
                Vec::new(),
            );
            assert_eq!(
                AssessmentRunReport::new(
                    run,
                    root_item_set(PRIVATE_EXACT_ORIGIN),
                    completed_truth(PRIVATE_CANONICAL_TARGET),
                )
                .unwrap_err(),
                AssessmentRunReportError::RunNotComplete
            );
        }
    }

    #[test]
    fn accounting_duration_step_and_outcome_injection_fail_closed() {
        let unmetered = run_report(
            RunStatus::Complete,
            RunStopCode::Completed,
            RunStepStatus::Succeeded,
            PRIVATE_CANONICAL_TARGET,
            PRIVATE_EXACT_ORIGIN,
            "2026-08-28T10:00:01Z",
            WEB_ASSESSMENT_RUN_STEP_ID,
            None,
            RunAccounting::unmetered(),
            Vec::new(),
        );
        assert_eq!(
            AssessmentRunReport::new(
                unmetered,
                root_item_set(PRIVATE_EXACT_ORIGIN),
                completed_truth(PRIVATE_CANONICAL_TARGET),
            )
            .unwrap_err(),
            AssessmentRunReportError::RunAccountingMismatch
        );

        let wrong_duration = run_report(
            RunStatus::Complete,
            RunStopCode::Completed,
            RunStepStatus::Succeeded,
            PRIVATE_CANONICAL_TARGET,
            PRIVATE_EXACT_ORIGIN,
            "2026-08-28T10:00:02Z",
            WEB_ASSESSMENT_RUN_STEP_ID,
            None,
            expected_run_accounting(
                WebAssessmentLimits::default(),
                usage_truth(PRIVATE_CANONICAL_TARGET),
            ),
            Vec::new(),
        );
        assert_eq!(
            AssessmentRunReport::new(
                wrong_duration,
                root_item_set(PRIVATE_EXACT_ORIGIN),
                completed_truth(PRIVATE_CANONICAL_TARGET),
            )
            .unwrap_err(),
            AssessmentRunReportError::RunDurationMismatch
        );

        let wrong_step = run_report(
            RunStatus::Complete,
            RunStopCode::Completed,
            RunStepStatus::Succeeded,
            PRIVATE_CANONICAL_TARGET,
            PRIVATE_EXACT_ORIGIN,
            "2026-08-28T10:00:01Z",
            "unrelated-step",
            None,
            expected_run_accounting(
                WebAssessmentLimits::default(),
                usage_truth(PRIVATE_CANONICAL_TARGET),
            ),
            Vec::new(),
        );
        assert_eq!(
            AssessmentRunReport::new(
                wrong_step,
                root_item_set(PRIVATE_EXACT_ORIGIN),
                completed_truth(PRIVATE_CANONICAL_TARGET),
            )
            .unwrap_err(),
            AssessmentRunReportError::RunStepMismatch
        );

        let injected = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test/").unwrap(),
            "legacy.outcome",
            "unverified",
            "redacted",
        )
        .unwrap();
        let with_outcome = run_report(
            RunStatus::Complete,
            RunStopCode::Completed,
            RunStepStatus::Succeeded,
            PRIVATE_CANONICAL_TARGET,
            PRIVATE_EXACT_ORIGIN,
            "2026-08-28T10:00:01Z",
            WEB_ASSESSMENT_RUN_STEP_ID,
            None,
            expected_run_accounting(
                WebAssessmentLimits::default(),
                usage_truth(PRIVATE_CANONICAL_TARGET),
            ),
            vec![injected],
        );
        assert_eq!(
            AssessmentRunReport::new(
                with_outcome,
                root_item_set(PRIVATE_EXACT_ORIGIN),
                completed_truth(PRIVATE_CANONICAL_TARGET),
            )
            .unwrap_err(),
            AssessmentRunReportError::RunOutcomesForbidden
        );
    }

    #[test]
    fn fingerprints_define_stable_order_and_duplicates_fail_closed() {
        let mut items = vec![
            TestItem("sha256:ccc"),
            TestItem("sha256:aaa"),
            TestItem("sha256:bbb"),
        ];
        validate_and_canonicalize_items(BuiltInScanProfile::WebReview, &mut items).unwrap();
        assert_eq!(
            items,
            vec![
                TestItem("sha256:aaa"),
                TestItem("sha256:bbb"),
                TestItem("sha256:ccc"),
            ]
        );

        let mut duplicates = vec![
            TestItem("sha256:other"),
            TestItem("sha256:duplicate"),
            TestItem("sha256:duplicate"),
        ];
        assert_eq!(
            validate_and_canonicalize_items(BuiltInScanProfile::WebReview, &mut duplicates,),
            Err(AssessmentRunReportError::DuplicateFingerprint)
        );
    }

    #[test]
    fn debug_and_errors_never_echo_private_report_or_item_identity() {
        let truth = completed_truth(PRIVATE_CANONICAL_TARGET);
        let truth_debug = format!("{truth:?}");
        assert!(truth_debug.contains("<stable-digest>"));
        assert!(!truth_debug.contains(PRIVATE_CANONICAL_TARGET));

        let report = AssessmentRunReport::new(
            complete_run_report(PRIVATE_CANONICAL_TARGET, PRIVATE_EXACT_ORIGIN),
            root_item_set(PRIVATE_EXACT_ORIGIN),
            truth,
        )
        .unwrap();
        let debug = format!("{report:?}");
        assert!(debug.contains(ASSESSMENT_RUN_REPORT_SCHEMA));
        assert!(debug.contains("item_count: 0"));
        for private in [
            PRIVATE_EXACT_ORIGIN,
            PRIVATE_CANONICAL_TARGET,
            PRIVATE_STOP_DETAIL,
        ] {
            assert!(!debug.contains(private));
        }

        let duplicate = AssessmentRunReportError::DuplicateFingerprint.to_string();
        let baseline = AssessmentRunReportError::BaselineItemsForbidden.to_string();
        for output in [duplicate, baseline] {
            assert!(!output.contains("sha256:"));
            assert!(!output.contains("evidence"));
            assert!(!output.contains("credential"));
            assert!(!output.contains(PRIVATE_EXACT_ORIGIN));
        }
    }
}
