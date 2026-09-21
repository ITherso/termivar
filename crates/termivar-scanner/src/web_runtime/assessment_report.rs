//! Bounded product report envelope for typed assessment items.
//!
//! This module owns no projection, verification, rendering, or persistence
//! authority. It mints the generic [`RunReport`] envelope only from consumed
//! runtime-owned completion truth, then binds the exact [`ScanProfileV1`] that
//! governed the run to assessment items minted by the closed claim boundary.
//! The public type deliberately has no Serde implementation; the reporting
//! adapter performs a separate explicit, redacted wire projection.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, SystemTime},
};

use sha2::{Digest, Sha256};
use termivar_core::{
    EvidenceId, ResourceAccounting, RunAccounting, RunReport, RunReportInput, RunStatus,
    RunStepReport, RunStepStatus, RunStopCode, RunStopReason,
};
use thiserror::Error;
use url::Url;

#[cfg(feature = "jwt-policy-review")]
use crate::jwt_policy_review::{
    JwtExternalOperationStatus, JwtLocalSignatureStatus, JwtParsingStatus, JwtPolicyReviewAudit,
    JwtPolicyStatus, JwtPolicyViolation, JwtTargetAcceptanceStatus, MAX_CLOCK_SKEW_SECONDS,
    MAX_REQUIRED_CLAIMS,
};
#[cfg(feature = "jwt-target-acceptance-review")]
use crate::jwt_target_acceptance::{
    JwtTargetAcceptanceAudit, JwtTargetAcceptanceConclusion, JwtTargetAcceptanceIncompleteReason,
    JwtTargetAcceptanceNotEligibleReason, JWT_TARGET_ACCEPTANCE_AUDIT_SCHEMA,
    JWT_TARGET_ACCEPTANCE_POLICY_ID, MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS,
    MAX_JWT_TARGET_ACCEPTANCE_REQUESTS,
};

#[cfg(feature = "secret-exposure-review")]
use super::assessment_item::AssessmentBasis;
#[cfg(feature = "openapi-review")]
use super::openapi_runtime::{
    OpenApiRuntimeOutcome, WebAssessmentOpenApiAudit, MAX_OPENAPI_REVIEW_REQUESTS,
    OPENAPI_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "recon-ct-provider")]
use super::recon_ct_runtime::WebAssessmentReconCtProviderAudit;
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
#[cfg(feature = "secret-exposure-review")]
use super::secret_exposure::{
    WebAssessmentSecretExposureAudit, MAX_SECRET_EXPOSURE_BODY_BYTES,
    MAX_SECRET_EXPOSURE_OCCURRENCES, MAX_SECRET_EXPOSURE_RESPONSES,
    MAX_SECRET_EXPOSURE_RETAINED_OBSERVATIONS, MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES,
};
#[cfg(feature = "ssrf-oast-review")]
use super::ssrf_oast_runtime::{
    SsrfOastRuntimeOutcome, WebAssessmentSsrfOastAudit, MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS,
    MAX_SSRF_OAST_REVIEW_PROVIDER_REQUESTS, MAX_SSRF_OAST_REVIEW_REQUESTS,
    SSRF_OAST_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "tls-observation")]
use super::tls_observation::{
    WebAssessmentTlsObservationAudit, TLS_OBSERVATION_AUDIT_SCHEMA, TLS_OBSERVATION_BACKEND_LIMIT,
    TLS_OBSERVATION_CLOCK_ASSURANCE, TLS_OBSERVATION_POLICY_ID, TLS_OBSERVATION_REVOCATION_STATUS,
    TLS_OBSERVATION_SOURCE_SCOPE, TLS_OBSERVATION_VALIDATION_SCOPE,
};
#[cfg(feature = "wordpress-review")]
use super::wordpress_fingerprint_runtime::{
    WordPressAssetFingerprintExecution, WordPressAssetFingerprintResourceReceipt,
};
#[cfg(feature = "wordpress-review")]
use super::wordpress_runtime::{
    WebAssessmentWordPressAudit, WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID,
    WORDPRESS_REVIEW_CAPABILITY_ID,
};
use super::{
    assessment_item::{
        AssessmentEvidenceReference, AssessmentItem, AssessmentItemSet,
        AssessmentSubjectInventoryEntry, MAX_ASSESSMENT_ITEM_SET_ITEMS,
    },
    assessment_passive::selected_application_stable_subject_identity,
    scan_profile::{BuiltInScanProfile, ScanProfileV1},
    web_assessment::{
        WebAssessmentCompletion, WebAssessmentDefenseMode, WebAssessmentLimits,
        WebAssessmentMethod, WebAssessmentSubject, WebAssessmentSubjectOrigin, WebAssessmentUsage,
    },
};
#[cfg(feature = "supplied-session-review")]
use super::{
    SuppliedSessionAuditOutcome, SuppliedSessionBodyState, SuppliedSessionHealthCheckpointPhase,
    SuppliedSessionHealthOutcome, SuppliedSessionLoginFormOutcome,
    SuppliedSessionLoginSubmitOutcome, SuppliedSessionResourceOutcome,
    WebAssessmentSuppliedSessionAudit, MAX_SUPPLIED_SESSION_CHECKPOINTS,
    MAX_SUPPLIED_SESSION_REQUESTS, MAX_SUPPLIED_SESSION_RESOURCES, SUPPLIED_SESSION_AUDIT_SCHEMA,
    SUPPLIED_SESSION_CAPABILITY_ID, SUPPLIED_SESSION_COOKIE_AUDIT_SCHEMA,
    SUPPLIED_SESSION_FORM_LOGIN_AUDIT_SCHEMA,
};
#[cfg(feature = "authorization-review")]
use crate::authorization_review::{
    AuthorizationReviewOutcome, HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS,
    HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS,
};
#[cfg(feature = "control-reference-mapping")]
use crate::control_reference_mapping::{map_control_references, ControlReferenceMappingAudit};
#[cfg(feature = "recon-snapshot-import")]
use crate::recon_snapshot::ReconSnapshot;
#[cfg(feature = "supplied-session-review")]
use crate::supplied_session_review::{
    SuppliedSessionCredentialAcquisition, SuppliedSessionCredentialMechanism,
    MAX_SUPPLIED_SESSION_COOKIES, MAX_SUPPLIED_SESSION_TOTAL_RESPONSE_BYTES,
};
#[cfg(feature = "wordpress-review")]
use crate::wordpress_review::{
    WordPressCatalogStatus, MAX_WORDPRESS_ADVISORY_RECORDS, MAX_WORDPRESS_RESULT_COMPONENTS,
    MAX_WORDPRESS_RESULT_VERSION_EVIDENCE, MAX_WORDPRESS_SIGNALS,
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
    evidence_references: BTreeMap<EvidenceId, AssessmentEvidenceReference>,
    #[cfg(feature = "supplied-session-review")]
    supplied_session: Option<WebAssessmentSuppliedSessionAudit>,
    #[cfg(feature = "authorization-review")]
    authorization_review: Option<WebAssessmentAuthorizationAudit>,
    #[cfg(feature = "jwt-target-acceptance-review")]
    jwt_target_acceptance: Option<JwtTargetAcceptanceAudit>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<WebAssessmentOpenApiAudit>,
    #[cfg(feature = "rest-review")]
    rest_review: Option<WebAssessmentRestAudit>,
    #[cfg(feature = "ssrf-oast-review")]
    ssrf_oast_review: Option<WebAssessmentSsrfOastAudit>,
    #[cfg(feature = "wordpress-review")]
    wordpress_review: Option<WebAssessmentWordPressAudit>,
    #[cfg(feature = "secret-exposure-review")]
    secret_exposure_review: Option<WebAssessmentSecretExposureAudit>,
    #[cfg(feature = "tls-observation")]
    tls_observation: Option<WebAssessmentTlsObservationAudit>,
    #[cfg(feature = "recon-ct-provider")]
    recon_ct_provider: Option<WebAssessmentReconCtProviderAudit>,
    #[cfg(feature = "jwt-policy-review")]
    jwt_policy_review: Option<JwtPolicyReviewAudit>,
    #[cfg(feature = "control-reference-mapping")]
    control_reference_mapping: Option<ControlReferenceMappingAudit>,
    #[cfg(feature = "recon-snapshot-import")]
    recon_snapshot: Option<ReconSnapshot>,
}

#[derive(Default)]
struct AssessmentReviewAudits {
    #[cfg(feature = "supplied-session-review")]
    supplied_session: Option<WebAssessmentSuppliedSessionAudit>,
    #[cfg(feature = "authorization-review")]
    authorization_review: Option<WebAssessmentAuthorizationAudit>,
    #[cfg(feature = "jwt-target-acceptance-review")]
    jwt_target_acceptance: Option<JwtTargetAcceptanceAudit>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<WebAssessmentOpenApiAudit>,
    #[cfg(feature = "rest-review")]
    rest_review: Option<WebAssessmentRestAudit>,
    #[cfg(feature = "ssrf-oast-review")]
    ssrf_oast_review: Option<WebAssessmentSsrfOastAudit>,
    #[cfg(feature = "wordpress-review")]
    wordpress_review: Option<WebAssessmentWordPressAudit>,
    #[cfg(feature = "secret-exposure-review")]
    secret_exposure_review: Option<WebAssessmentSecretExposureAudit>,
    #[cfg(feature = "tls-observation")]
    tls_observation: Option<WebAssessmentTlsObservationAudit>,
    #[cfg(feature = "recon-ct-provider")]
    recon_ct_provider: Option<WebAssessmentReconCtProviderAudit>,
}

impl AssessmentRunReport {
    /// Mints the canonical run envelope from runtime-owned completion truth
    /// and composes it with the closed typed-item set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_completed_truth(
        items: AssessmentItemSet,
        truth: CompletedWebAssessmentTruth,
        #[cfg(feature = "supplied-session-review")] supplied_session: Option<
            WebAssessmentSuppliedSessionAudit,
        >,
        #[cfg(feature = "authorization-review")] authorization_review: Option<
            WebAssessmentAuthorizationAudit,
        >,
        #[cfg(feature = "jwt-target-acceptance-review")] jwt_target_acceptance: Option<
            JwtTargetAcceptanceAudit,
        >,
        #[cfg(feature = "openapi-review")] openapi_review: Option<WebAssessmentOpenApiAudit>,
        #[cfg(feature = "rest-review")] rest_review: Option<WebAssessmentRestAudit>,
        #[cfg(feature = "ssrf-oast-review")] ssrf_oast_review: Option<WebAssessmentSsrfOastAudit>,
        #[cfg(feature = "wordpress-review")] wordpress_review: Option<WebAssessmentWordPressAudit>,
        #[cfg(feature = "secret-exposure-review")] secret_exposure_review: Option<
            WebAssessmentSecretExposureAudit,
        >,
        #[cfg(feature = "tls-observation")] tls_observation: Option<
            WebAssessmentTlsObservationAudit,
        >,
        #[cfg(feature = "recon-ct-provider")] recon_ct_provider: Option<
            WebAssessmentReconCtProviderAudit,
        >,
    ) -> Result<Self, AssessmentRunReportError> {
        let run_report = build_run_report(&truth)?;
        Self::new_validated(
            run_report,
            items,
            truth,
            AssessmentReviewAudits {
                #[cfg(feature = "supplied-session-review")]
                supplied_session,
                #[cfg(feature = "authorization-review")]
                authorization_review,
                #[cfg(feature = "jwt-target-acceptance-review")]
                jwt_target_acceptance,
                #[cfg(feature = "openapi-review")]
                openapi_review,
                #[cfg(feature = "rest-review")]
                rest_review,
                #[cfg(feature = "ssrf-oast-review")]
                ssrf_oast_review,
                #[cfg(feature = "wordpress-review")]
                wordpress_review,
                #[cfg(feature = "secret-exposure-review")]
                secret_exposure_review,
                #[cfg(feature = "tls-observation")]
                tls_observation,
                #[cfg(feature = "recon-ct-provider")]
                recon_ct_provider,
            },
        )
    }

    #[cfg(test)]
    fn new(
        run_report: RunReport,
        items: AssessmentItemSet,
        truth: CompletedWebAssessmentTruth,
    ) -> Result<Self, AssessmentRunReportError> {
        Self::new_validated(run_report, items, truth, AssessmentReviewAudits::default())
    }

    fn new_validated(
        run_report: RunReport,
        items: AssessmentItemSet,
        truth: CompletedWebAssessmentTruth,
        audits: AssessmentReviewAudits,
    ) -> Result<Self, AssessmentRunReportError> {
        let AssessmentReviewAudits {
            #[cfg(feature = "supplied-session-review")]
            supplied_session,
            #[cfg(feature = "authorization-review")]
            authorization_review,
            #[cfg(feature = "jwt-target-acceptance-review")]
            jwt_target_acceptance,
            #[cfg(feature = "openapi-review")]
            openapi_review,
            #[cfg(feature = "rest-review")]
            rest_review,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast_review,
            #[cfg(feature = "wordpress-review")]
            wordpress_review,
            #[cfg(feature = "secret-exposure-review")]
            secret_exposure_review,
            #[cfg(feature = "tls-observation")]
            tls_observation,
            #[cfg(feature = "recon-ct-provider")]
            recon_ct_provider,
        } = audits;
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
        #[cfg(feature = "supplied-session-review")]
        let supplied_session_application_reference = supplied_session
            .as_ref()
            .map(WebAssessmentSuppliedSessionAudit::application_reference);
        #[cfg(not(feature = "supplied-session-review"))]
        let supplied_session_application_reference: Option<&str> = None;
        let expected_root_subject =
            selected_application_stable_subject_identity(supplied_session_application_reference);
        if !items.contains_stable_subject(&expected_root_subject) {
            return Err(AssessmentRunReportError::SubjectReferenceMismatch);
        }
        let (subjects, mut items, evidence_references) = items.into_report_parts();
        validate_subject_inventory(&subjects, &items)?;
        validate_and_canonicalize_items(truth.profile.profile(), &mut items)?;
        #[cfg(feature = "supplied-session-review")]
        validate_supplied_session_audit(supplied_session.as_ref(), &items)?;
        #[cfg(feature = "authorization-review")]
        validate_authorization_audit(authorization_review.as_ref(), &items)?;
        #[cfg(feature = "jwt-target-acceptance-review")]
        validate_jwt_target_acceptance_audit(
            jwt_target_acceptance.as_ref(),
            truth.expected_accounting.requests().consumed(),
            truth.expected_accounting.response_body_bytes().consumed(),
        )?;
        #[cfg(feature = "openapi-review")]
        validate_openapi_audit(openapi_review.as_ref(), &items)?;
        #[cfg(feature = "rest-review")]
        validate_rest_audit(rest_review.as_ref(), &items)?;
        #[cfg(feature = "ssrf-oast-review")]
        validate_ssrf_oast_audit(ssrf_oast_review.as_ref(), &items)?;
        #[cfg(feature = "wordpress-review")]
        validate_wordpress_audit(wordpress_review.as_ref(), &items)?;
        #[cfg(feature = "secret-exposure-review")]
        validate_secret_exposure_audit(
            secret_exposure_review.as_ref(),
            &items,
            &evidence_references,
        )?;
        #[cfg(feature = "tls-observation")]
        validate_tls_observation_audit(
            tls_observation.as_ref(),
            &truth.target,
            truth.expected_accounting.requests().consumed(),
        )?;
        #[cfg(feature = "recon-ct-provider")]
        validate_recon_ct_provider_audit(
            recon_ct_provider.as_ref(),
            truth.expected_accounting.requests().consumed(),
            truth.expected_accounting.response_body_bytes().consumed(),
        )?;

        Ok(Self {
            run_report,
            profile: truth.profile,
            subjects,
            items,
            evidence_references,
            #[cfg(feature = "supplied-session-review")]
            supplied_session,
            #[cfg(feature = "authorization-review")]
            authorization_review,
            #[cfg(feature = "jwt-target-acceptance-review")]
            jwt_target_acceptance,
            #[cfg(feature = "openapi-review")]
            openapi_review,
            #[cfg(feature = "rest-review")]
            rest_review,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast_review,
            #[cfg(feature = "wordpress-review")]
            wordpress_review,
            #[cfg(feature = "secret-exposure-review")]
            secret_exposure_review,
            #[cfg(feature = "tls-observation")]
            tls_observation,
            #[cfg(feature = "recon-ct-provider")]
            recon_ct_provider,
            #[cfg(feature = "jwt-policy-review")]
            jwt_policy_review: None,
            #[cfg(feature = "control-reference-mapping")]
            control_reference_mapping: None,
            #[cfg(feature = "recon-snapshot-import")]
            recon_snapshot: None,
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

    /// Returns the optional redaction-safe supplied-session assessment audit.
    #[cfg(feature = "supplied-session-review")]
    pub const fn supplied_session_audit(&self) -> Option<&WebAssessmentSuppliedSessionAudit> {
        self.supplied_session.as_ref()
    }

    /// Returns subjects registered by the consumed projection authority.
    pub const fn subject_count(&self) -> usize {
        self.subjects.len()
    }

    /// Returns the bounded assessment-item count.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Resolves one runtime-owned evidence identity to the opaque reference
    /// minted by the same consumed projection authority. This mapping remains
    /// private to report composition and is never serialized as runtime state.
    #[cfg(any(feature = "wordpress-review", feature = "secret-exposure-review"))]
    pub(crate) fn evidence_reference_for(
        &self,
        evidence_id: &EvidenceId,
    ) -> Option<AssessmentEvidenceReference> {
        self.evidence_references.get(evidence_id).copied()
    }

    /// Returns the optional redaction-safe resource-authorization audit.
    #[cfg(feature = "authorization-review")]
    pub const fn authorization_review_audit(&self) -> Option<&WebAssessmentAuthorizationAudit> {
        self.authorization_review.as_ref()
    }
    /// Returns the optional value-free target-side JWT control audit.
    #[cfg(feature = "jwt-target-acceptance-review")]
    pub const fn jwt_target_acceptance_audit(&self) -> Option<&JwtTargetAcceptanceAudit> {
        self.jwt_target_acceptance.as_ref()
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

    /// Returns the optional redaction-safe, transport-free WordPress audit.
    #[cfg(feature = "wordpress-review")]
    pub const fn wordpress_review_audit(&self) -> Option<&WebAssessmentWordPressAudit> {
        self.wordpress_review.as_ref()
    }

    /// Returns the optional value-free passive secret-exposure audit.
    #[cfg(feature = "secret-exposure-review")]
    pub const fn secret_exposure_review_audit(&self) -> Option<&WebAssessmentSecretExposureAudit> {
        self.secret_exposure_review.as_ref()
    }

    /// Returns the optional passive existing-connection TLS audit.
    #[cfg(feature = "tls-observation")]
    pub const fn tls_observation_audit(&self) -> Option<&WebAssessmentTlsObservationAudit> {
        self.tls_observation.as_ref()
    }

    /// Returns the optional bounded certificate-transparency provider audit.
    #[cfg(feature = "recon-ct-provider")]
    pub const fn recon_ct_provider_audit(&self) -> Option<&WebAssessmentReconCtProviderAudit> {
        self.recon_ct_provider.as_ref()
    }

    /// Attaches one independently evaluated, transport-free local JWT audit
    /// after the ordinary web assessment has completed.
    #[cfg(feature = "jwt-policy-review")]
    pub(crate) fn with_jwt_policy_review_audit(
        mut self,
        audit: Option<JwtPolicyReviewAudit>,
    ) -> Result<Self, AssessmentRunReportError> {
        if self.jwt_policy_review.is_some() {
            return Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch);
        }
        #[cfg(feature = "jwt-target-acceptance-review")]
        if self.jwt_target_acceptance.is_some() && audit.is_none() {
            return Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch);
        }
        #[cfg(feature = "jwt-target-acceptance-review")]
        if self.jwt_target_acceptance.is_none()
            && audit
                .as_ref()
                .is_some_and(|audit| audit.target_preparation_binding().is_some())
        {
            return Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch);
        }
        if let Some(audit) = audit.as_ref() {
            validate_jwt_policy_review_audit(audit)?;
            #[cfg(feature = "jwt-target-acceptance-review")]
            if let Some(target) = self.jwt_target_acceptance.as_ref() {
                validate_jwt_target_local_link(audit, target)?;
            }
        }
        self.jwt_policy_review = audit;
        Ok(self)
    }

    /// Returns the optional value-free, transport-free local JWT audit.
    #[cfg(feature = "jwt-policy-review")]
    pub const fn jwt_policy_review_audit(&self) -> Option<&JwtPolicyReviewAudit> {
        self.jwt_policy_review.as_ref()
    }

    /// Attaches the one built-in, bounded, transport-free control-reference
    /// projection over this completed report's immutable assessment items.
    #[cfg(feature = "control-reference-mapping")]
    pub(crate) fn with_control_reference_mapping(
        mut self,
    ) -> Result<Self, AssessmentRunReportError> {
        if self.control_reference_mapping.is_some() {
            return Err(AssessmentRunReportError::ControlReferenceMappingAuditMismatch);
        }
        self.control_reference_mapping = Some(
            map_control_references(&self.items)
                .map_err(|_| AssessmentRunReportError::ControlReferenceMappingAuditMismatch)?,
        );
        Ok(self)
    }

    /// Returns the optional transport-free control-reference mapping audit.
    #[cfg(feature = "control-reference-mapping")]
    pub const fn control_reference_mapping_audit(&self) -> Option<&ControlReferenceMappingAudit> {
        self.control_reference_mapping.as_ref()
    }

    /// Attaches one previously bounded, transport-free local reconnaissance
    /// snapshot. The imported records remain inert source-qualified hypotheses
    /// and cannot mint assessment items, subjects, or network authority.
    #[cfg(feature = "recon-snapshot-import")]
    pub(crate) fn with_recon_snapshot(
        mut self,
        audit: ReconSnapshot,
    ) -> Result<Self, AssessmentRunReportError> {
        if self.recon_snapshot.is_some() {
            return Err(AssessmentRunReportError::ReconSnapshotAuditMismatch);
        }
        self.recon_snapshot = Some(audit);
        Ok(self)
    }

    /// Returns the optional transport-free reconnaissance snapshot audit.
    #[cfg(feature = "recon-snapshot-import")]
    pub const fn recon_snapshot_audit(&self) -> Option<&ReconSnapshot> {
        self.recon_snapshot.as_ref()
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn validate_jwt_target_local_link(
    local: &JwtPolicyReviewAudit,
    target: &JwtTargetAcceptanceAudit,
) -> Result<(), AssessmentRunReportError> {
    if local.target_preparation_binding().is_none()
        || local.target_preparation_binding() != target.preparation_binding()
    {
        return Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch);
    }
    let local_eligible = local.parsing_status() == JwtParsingStatus::Parsed
        && local.policy_status() == JwtPolicyStatus::Consistent
        && local.local_signature_status() == JwtLocalSignatureStatus::Verified;
    let linked = match target.conclusion() {
        JwtTargetAcceptanceConclusion::Incomplete(
            JwtTargetAcceptanceIncompleteReason::NotEligible(reason),
        ) if target.legs().is_empty() => match reason {
            JwtTargetAcceptanceNotEligibleReason::LocalParsingNotEstablished => {
                matches!(local.parsing_status(), JwtParsingStatus::Rejected(_))
            },
            JwtTargetAcceptanceNotEligibleReason::LocalPolicyNotEstablished => {
                local.parsing_status() == JwtParsingStatus::Parsed
                    && local.policy_status() == JwtPolicyStatus::Inconsistent
            },
            JwtTargetAcceptanceNotEligibleReason::LocalSignatureNotEstablished => {
                local.parsing_status() == JwtParsingStatus::Parsed
                    && local.policy_status() == JwtPolicyStatus::Consistent
                    && local.local_signature_status() == JwtLocalSignatureStatus::Invalid
            },
            JwtTargetAcceptanceNotEligibleReason::RuntimeAuthorityUnavailable
            | JwtTargetAcceptanceNotEligibleReason::RequestBudgetUnavailable => local_eligible,
        },
        _ => !target.legs().is_empty() && local_eligible,
    };
    if linked {
        Ok(())
    } else {
        Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch)
    }
}

#[cfg(feature = "jwt-policy-review")]
fn validate_jwt_policy_review_audit(
    audit: &JwtPolicyReviewAudit,
) -> Result<(), AssessmentRunReportError> {
    let methodology = audit.methodology();
    let external = audit.external_activity();
    let base_valid = audit.schema() == crate::jwt_policy_review::JWT_POLICY_REVIEW_AUDIT_SCHEMA
        && audit.policy() == crate::jwt_policy_review::JWT_POLICY_REVIEW_POLICY_ID
        && audit.selected()
        && valid_jwt_methodology_reference(methodology.operator_policy_reference())
        && valid_jwt_methodology_reference(methodology.operator_policy_revision())
        && valid_jwt_public_key_sha256(methodology.local_public_key_sha256())
        && methodology.expected_type_selected()
        && methodology.expected_issuer_selected()
        && methodology.expected_audience_selected()
        && methodology.required_claim_count() as usize <= MAX_REQUIRED_CLAIMS
        && methodology.allowed_clock_skew_seconds() <= MAX_CLOCK_SKEW_SECONDS
        && external.target_request_count() == 0
        && external.remote_key_retrieval() == JwtExternalOperationStatus::NotPerformed
        && external.token_forwarding() == JwtExternalOperationStatus::NotPerformed
        && audit.target_acceptance_status() == JwtTargetAcceptanceStatus::NotPerformed;
    if !base_valid {
        return Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch);
    }

    let state_valid = match audit.parsing_status() {
        JwtParsingStatus::Rejected(_) => {
            audit.policy_status() == JwtPolicyStatus::NotEvaluated
                && audit.local_signature_status() == JwtLocalSignatureStatus::NotEvaluated
                && audit.policy_violations().is_empty()
        },
        JwtParsingStatus::Parsed => {
            matches!(
                audit.local_signature_status(),
                JwtLocalSignatureStatus::Verified | JwtLocalSignatureStatus::Invalid
            ) && match audit.policy_status() {
                JwtPolicyStatus::Consistent => audit.policy_violations().is_empty(),
                JwtPolicyStatus::Inconsistent => !audit.policy_violations().is_empty(),
                JwtPolicyStatus::NotEvaluated => false,
            }
        },
    };
    let mut required_ordinals = BTreeSet::new();
    let ordinals_valid = audit.policy_violations().iter().all(|violation| {
        let JwtPolicyViolation::MissingRequiredClaim { ordinal } = violation else {
            return true;
        };
        *ordinal < methodology.required_claim_count() && required_ordinals.insert(*ordinal)
    });
    if state_valid && ordinals_valid {
        Ok(())
    } else {
        Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch)
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn validate_jwt_target_acceptance_audit(
    audit: Option<&JwtTargetAcceptanceAudit>,
    assessment_request_count: Option<u64>,
    assessment_response_bytes: Option<u64>,
) -> Result<(), AssessmentRunReportError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let accounting = audit.accounting();
    let dispatched = audit
        .legs()
        .iter()
        .filter(|leg| leg.was_dispatched())
        .count();
    let committed = audit
        .legs()
        .iter()
        .filter(|leg| leg.was_committed())
        .count();
    let active = audit
        .legs()
        .iter()
        .filter(|leg| leg.was_dispatched() && leg.role().is_active())
        .count();
    let passive = dispatched.saturating_sub(active);
    let accounted_bytes = audit.legs().iter().try_fold(0_u64, |sum, leg| {
        sum.checked_add(leg.accounted_response_bytes())
    });
    let retained_bytes = audit.legs().iter().try_fold(0_u64, |sum, leg| {
        sum.checked_add(leg.retained_response_bytes())
    });
    let zero_request_shape = audit.legs().is_empty()
        && accounting.dispatched_request_count() == 0
        && accounting.dispatched_passive_request_count() == 0
        && accounting.dispatched_active_request_count() == 0
        && accounting.committed_response_count() == 0
        && accounting.retained_response_bytes() == 0
        && accounting.accounted_response_bytes() == 0;
    let selected_shape = audit.legs().len() == usize::from(MAX_JWT_TARGET_ACCEPTANCE_REQUESTS)
        && dispatched == usize::from(accounting.dispatched_request_count())
        && passive == usize::from(accounting.dispatched_passive_request_count())
        && active == usize::from(accounting.dispatched_active_request_count())
        && committed == usize::from(accounting.committed_response_count())
        && retained_bytes == Some(accounting.retained_response_bytes())
        && accounted_bytes == Some(accounting.accounted_response_bytes());
    let valid = audit.schema() == JWT_TARGET_ACCEPTANCE_AUDIT_SCHEMA
        && audit.policy() == JWT_TARGET_ACCEPTANCE_POLICY_ID
        && valid_jwt_methodology_reference(audit.operator_policy_reference())
        && valid_jwt_methodology_reference(audit.operator_policy_revision())
        && valid_jwt_methodology_reference(audit.resource_reference())
        && audit.preparation_binding().is_some()
        && (zero_request_shape || selected_shape)
        && accounting.dispatched_request_count() <= MAX_JWT_TARGET_ACCEPTANCE_REQUESTS
        && accounting.dispatched_active_request_count()
            <= MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS
        && assessment_request_count
            .is_some_and(|count| u64::from(accounting.dispatched_request_count()) <= count)
        && assessment_response_bytes
            .is_some_and(|count| accounting.accounted_response_bytes() <= count);
    if valid {
        Ok(())
    } else {
        Err(AssessmentRunReportError::JwtTargetAcceptanceAuditMismatch)
    }
}

#[cfg(feature = "jwt-policy-review")]
fn valid_jwt_methodology_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
        })
}

#[cfg(feature = "jwt-policy-review")]
fn valid_jwt_public_key_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(feature = "tls-observation")]
fn validate_tls_observation_audit(
    audit: Option<&WebAssessmentTlsObservationAudit>,
    target: &str,
    assessment_request_count: Option<u64>,
) -> Result<(), AssessmentRunReportError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let target_scheme = Url::parse(target)
        .map_err(|_| AssessmentRunReportError::TlsObservationAuditMismatch)?
        .scheme()
        .to_owned();
    let observed_response_count = audit
        .successful_https_response_count()
        .checked_add(audit.plaintext_response_count())
        .ok_or(AssessmentRunReportError::TlsObservationAuditMismatch)?;
    let https_partition = audit
        .tls_info_unavailable_count()
        .checked_add(audit.malformed_certificate_count())
        .and_then(|count| count.checked_add(audit.certificate_limit_rejection_count()))
        .and_then(|count| count.checked_add(audit.unretained_leaf_response_count()))
        .and_then(|count| {
            audit
                .leaf_observations()
                .iter()
                .try_fold(count, |sum, row| {
                    sum.checked_add(row.response_occurrence_count())
                })
        })
        .ok_or(AssessmentRunReportError::TlsObservationAuditMismatch)?;
    let valid = audit.schema() == TLS_OBSERVATION_AUDIT_SCHEMA
        && audit.policy() == TLS_OBSERVATION_POLICY_ID
        && audit.selected()
        && audit.additional_request_count() == 0
        && audit.target_scheme().as_str() == target_scheme
        && audit.observation_source_scope() == TLS_OBSERVATION_SOURCE_SCOPE
        && audit.observation_clock_assurance() == TLS_OBSERVATION_CLOCK_ASSURANCE
        && audit.protocol() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.cipher_suite() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.alpn_protocol() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.full_chain() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.connection_reuse() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.session_resumption() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.handshake_kind() == TLS_OBSERVATION_BACKEND_LIMIT
        && audit.revocation() == TLS_OBSERVATION_REVOCATION_STATUS
        && audit.standard_transport_validation_scope() == TLS_OBSERVATION_VALIDATION_SCOPE
        && https_partition == audit.successful_https_response_count()
        && (target_scheme == "https" || audit.successful_https_response_count() == 0)
        && (target_scheme == "http" || audit.plaintext_response_count() == 0)
        && matches!(target_scheme.as_str(), "http" | "https")
        && assessment_request_count.is_some_and(|count| observed_response_count <= count);
    if valid {
        Ok(())
    } else {
        Err(AssessmentRunReportError::TlsObservationAuditMismatch)
    }
}

#[cfg(feature = "recon-ct-provider")]
fn validate_recon_ct_provider_audit(
    audit: Option<&WebAssessmentReconCtProviderAudit>,
    total_request_count: Option<u64>,
    total_response_bytes: Option<u64>,
) -> Result<(), AssessmentRunReportError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let admitted = u64::try_from(audit.request_admitted_count())
        .map_err(|_| AssessmentRunReportError::ReconCtProviderAuditMismatch)?;
    if !audit.is_consistent()
        || total_request_count.is_none_or(|total| admitted > total)
        || total_response_bytes.is_none_or(|total| audit.observed_response_bytes() > total)
    {
        return Err(AssessmentRunReportError::ReconCtProviderAuditMismatch);
    }
    Ok(())
}

#[cfg(feature = "secret-exposure-review")]
fn validate_secret_exposure_audit(
    audit: Option<&WebAssessmentSecretExposureAudit>,
    items: &[AssessmentItem],
    evidence_references: &BTreeMap<EvidenceId, AssessmentEvidenceReference>,
) -> Result<(), AssessmentRunReportError> {
    let is_secret_item = |item: &AssessmentItem| {
        matches!(
            item.capability_id(),
            "exposure.response-private-key-material@1"
                | "exposure.response-aws-access-key-pair@1"
                | "exposure.response-stripe-live-secret@1"
                | "exposure.response-bearer-authorization@1"
        )
    };
    let projected = items
        .iter()
        .filter(|item| is_secret_item(item))
        .collect::<Vec<_>>();
    let Some(audit) = audit else {
        return if projected.is_empty() {
            Ok(())
        } else {
            Err(AssessmentRunReportError::SecretExposureAuditMismatch)
        };
    };
    let outcome_sum = audit
        .outcomes()
        .iter()
        .try_fold(0_u32, |count, row| count.checked_add(row.count()));
    let evaluated = audit
        .outcomes()
        .iter()
        .find(|row| row.outcome().as_str() == "evaluated")
        .map_or(0, |row| row.count());
    let retained_occurrences = audit
        .observations()
        .iter()
        .try_fold(0_u64, |count, observation| {
            count.checked_add(u64::from(observation.occurrence_count()))
        });
    if usize::try_from(audit.response_count()).unwrap_or(usize::MAX) > MAX_SECRET_EXPOSURE_RESPONSES
        || audit.evaluated_response_count() != evaluated
        || audit.not_evaluated_response_count()
            != audit
                .response_count()
                .saturating_sub(audit.evaluated_response_count())
        || outcome_sum != Some(audit.response_count())
        || audit.interpreted_byte_count() > MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES
        || audit.interpreted_byte_count()
            > u64::from(audit.evaluated_response_count())
                .saturating_mul(MAX_SECRET_EXPOSURE_BODY_BYTES as u64)
        || audit.observations().len() > MAX_SECRET_EXPOSURE_RETAINED_OBSERVATIONS
        || projected.len() != audit.observations().len()
        || audit.match_occurrence_count()
            > u64::from(audit.response_count())
                .saturating_mul(u64::from(MAX_SECRET_EXPOSURE_OCCURRENCES))
        || retained_occurrences.is_none_or(|count| {
            if audit.omitted_observation_count() == 0 {
                count != audit.match_occurrence_count()
            } else {
                count >= audit.match_occurrence_count()
            }
        })
    {
        return Err(AssessmentRunReportError::SecretExposureAuditMismatch);
    }

    let mut paired_items = BTreeSet::new();
    let mut paired_evidence = BTreeSet::new();
    for observation in audit.observations() {
        if observation.occurrence_count() == 0
            || observation.occurrence_count() > MAX_SECRET_EXPOSURE_OCCURRENCES
            || observation.evidence_ids().len() != 1
        {
            return Err(AssessmentRunReportError::SecretExposureAuditMismatch);
        }
        let evidence_id = &observation.evidence_ids()[0];
        let evidence_reference = evidence_references
            .get(evidence_id)
            .copied()
            .ok_or(AssessmentRunReportError::SecretExposureAuditMismatch)?;
        if !paired_evidence.insert(evidence_reference) {
            return Err(AssessmentRunReportError::SecretExposureAuditMismatch);
        }
        let matches = projected
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                if item.capability_id() != observation.detector_class().capability_id() {
                    return false;
                }
                matches!(
                    item.basis(),
                    AssessmentBasis::Observation(basis)
                        if basis.evidence() == [evidence_reference]
                )
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 || !paired_items.insert(matches[0]) {
            return Err(AssessmentRunReportError::SecretExposureAuditMismatch);
        }
    }
    if paired_items.len() != projected.len() {
        return Err(AssessmentRunReportError::SecretExposureAuditMismatch);
    }
    Ok(())
}

#[cfg(feature = "wordpress-review")]
fn validate_wordpress_audit(
    audit: Option<&WebAssessmentWordPressAudit>,
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    let projected = items
        .iter()
        .filter(|item| item.capability_id() == WORDPRESS_REVIEW_CAPABILITY_ID)
        .count();
    if projected > 1 {
        return Err(AssessmentRunReportError::WordPressAuditMismatch);
    }
    let discovery_items = items
        .iter()
        .filter(|item| item.capability_id() == WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID)
        .collect::<Vec<_>>();
    if discovery_items.len() > 1 {
        return Err(AssessmentRunReportError::WordPressAuditMismatch);
    }
    let Some(audit) = audit else {
        return if projected == 0 && discovery_items.is_empty() {
            Ok(())
        } else {
            Err(AssessmentRunReportError::WordPressAuditMismatch)
        };
    };
    let result = audit.result();
    let fingerprint_attempted_request_count = audit.asset_fingerprints().map_or(
        0,
        WordPressAssetFingerprintExecution::attempted_request_count,
    );
    let fingerprint_evidence_reference_count = audit
        .asset_fingerprints()
        .into_iter()
        .flat_map(WordPressAssetFingerprintExecution::resources)
        .flat_map(WordPressAssetFingerprintResourceReceipt::evidence_ids)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let discovery_consistent = match audit.discovery() {
        Some(discovery) => {
            let page_attempted_request_count = discovery
                .page_scope()
                .map_or(0, |pages| pages.attempted_request_count());
            let page_committed_response_count = discovery
                .page_scope()
                .map_or(0, |pages| pages.committed_response_count());
            let supplied_session_page_evidence_count = discovery
                .supplied_session_pages()
                .into_iter()
                .flat_map(|pages| pages.pages())
                .flat_map(|page| page.evidence_ids())
                .try_fold(0_usize, |count, _| count.checked_add(1));
            let total_attempted_request_count = discovery
                .attempted_request_count()
                .checked_add(page_attempted_request_count)
                .and_then(|count| count.checked_add(fingerprint_attempted_request_count));
            let total_committed_evidence_count = usize::from(discovery.committed_response_count())
                .checked_add(usize::from(page_committed_response_count))
                .and_then(|count| {
                    supplied_session_page_evidence_count
                        .and_then(|session_pages| count.checked_add(session_pages))
                })
                .and_then(|count| count.checked_add(fingerprint_evidence_reference_count));
            let expected_item = total_committed_evidence_count.is_some_and(|count| count > 0);
            discovery.is_internally_consistent()
                && total_attempted_request_count == Some(audit.additional_request_count())
                && (discovery_items.len() == 1) == expected_item
                && discovery_items.first().is_none_or(|item| {
                    total_committed_evidence_count
                        .is_some_and(|count| item.evidence_count() == count)
                })
        },
        None => {
            audit.asset_fingerprints().is_none()
                && audit.additional_request_count() == 0
                && discovery_items.is_empty()
        },
    };
    let version_evidence_count = result
        .components()
        .iter()
        .try_fold(0_usize, |count, component| {
            count.checked_add(component.versions().len())
        });
    let catalog_consistent = matches!(
        (
            result.catalog_status(),
            result.catalog_metadata(),
            result.external_review(),
        ),
        (WordPressCatalogStatus::CatalogNotSupplied, None, None)
            | (WordPressCatalogStatus::Evaluated, Some(_), None)
            | (WordPressCatalogStatus::Evaluated, None, Some(_))
    );
    if usize::from(audit.signal_count()) > MAX_WORDPRESS_SIGNALS
        || result.components().len() > MAX_WORDPRESS_RESULT_COMPONENTS
        || version_evidence_count.is_none_or(|count| count > MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)
        || result.advisories().len() > MAX_WORDPRESS_ADVISORY_RECORDS
        || !discovery_consistent
        || audit.item_projected() != (projected == 1)
        || audit.item_projected() != (audit.signal_count() > 0)
        || !catalog_consistent
    {
        return Err(AssessmentRunReportError::WordPressAuditMismatch);
    }
    Ok(())
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
        #[cfg(feature = "supplied-session-review")]
        debug.field(
            "supplied_session_audit_present",
            &self.supplied_session.is_some(),
        );
        #[cfg(feature = "authorization-review")]
        debug.field(
            "authorization_review_audit_present",
            &self.authorization_review.is_some(),
        );
        #[cfg(feature = "jwt-target-acceptance-review")]
        debug.field(
            "jwt_target_acceptance_audit_present",
            &self.jwt_target_acceptance.is_some(),
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
        #[cfg(feature = "wordpress-review")]
        debug.field(
            "wordpress_review_audit_present",
            &self.wordpress_review.is_some(),
        );
        #[cfg(feature = "secret-exposure-review")]
        debug.field(
            "secret_exposure_review_audit_present",
            &self.secret_exposure_review.is_some(),
        );
        #[cfg(feature = "tls-observation")]
        debug.field(
            "tls_observation_audit_present",
            &self.tls_observation.is_some(),
        );
        #[cfg(feature = "recon-ct-provider")]
        debug.field(
            "recon_ct_provider_audit_present",
            &self.recon_ct_provider.is_some(),
        );
        #[cfg(feature = "jwt-policy-review")]
        debug.field(
            "jwt_policy_review_audit_present",
            &self.jwt_policy_review.is_some(),
        );
        #[cfg(feature = "control-reference-mapping")]
        debug.field(
            "control_reference_mapping_audit_present",
            &self.control_reference_mapping.is_some(),
        );
        #[cfg(feature = "recon-snapshot-import")]
        debug.field(
            "recon_snapshot_audit_present",
            &self.recon_snapshot.is_some(),
        );
        debug.finish()
    }
}

#[cfg(feature = "supplied-session-review")]
const fn valid_v1_supplied_session_outcome(outcome: SuppliedSessionAuditOutcome) -> bool {
    !matches!(
        outcome,
        SuppliedSessionAuditOutcome::CredentialUpdateRequired
            | SuppliedSessionAuditOutcome::CredentialUpdateUnusable
            | SuppliedSessionAuditOutcome::LoginFormUnavailable
            | SuppliedSessionAuditOutcome::LoginSubmitUnavailable
            | SuppliedSessionAuditOutcome::LoginCookieUnavailable
    )
}

#[cfg(feature = "supplied-session-review")]
const fn valid_v2_cookie_lifecycle_outcome(
    outcome: SuppliedSessionAuditOutcome,
    selected_update_response_count: u8,
    update_classification_failure_count: u8,
) -> bool {
    match outcome {
        SuppliedSessionAuditOutcome::CredentialUpdateRequired => {
            selected_update_response_count == 1 && update_classification_failure_count == 0
        },
        SuppliedSessionAuditOutcome::CredentialUpdateUnusable => {
            selected_update_response_count == 0 && update_classification_failure_count == 1
        },
        SuppliedSessionAuditOutcome::LoginFormUnavailable
        | SuppliedSessionAuditOutcome::LoginSubmitUnavailable
        | SuppliedSessionAuditOutcome::LoginCookieUnavailable => false,
        _ => selected_update_response_count == 0 && update_classification_failure_count == 0,
    }
}

#[cfg(feature = "supplied-session-review")]
const fn valid_v2_cookie_lifecycle_accounting(
    selected_update_response_count: u8,
    unselected_update_response_count: u8,
    update_classification_failure_count: u8,
    dispatched_request_count: u8,
) -> bool {
    selected_update_response_count <= dispatched_request_count
        && (unselected_update_response_count as u16 + update_classification_failure_count as u16)
            <= dispatched_request_count as u16
}

#[cfg(feature = "supplied-session-review")]
const fn valid_v3_cookie_lifecycle_accounting(
    selected_update_response_count: u8,
    unselected_update_response_count: u8,
    update_classification_failure_count: u8,
    dispatched_request_count: u8,
    login_request_count: u8,
) -> bool {
    let Some(update_eligible_request_count) =
        dispatched_request_count.checked_sub(login_request_count)
    else {
        return false;
    };
    valid_v2_cookie_lifecycle_accounting(
        selected_update_response_count,
        unselected_update_response_count,
        update_classification_failure_count,
        update_eligible_request_count,
    )
}

#[cfg(feature = "supplied-session-review")]
const fn valid_v3_cookie_lifecycle_outcome(
    outcome: SuppliedSessionAuditOutcome,
    selected_update_response_count: u8,
    update_classification_failure_count: u8,
) -> bool {
    match outcome {
        SuppliedSessionAuditOutcome::CredentialUpdateRequired => {
            selected_update_response_count == 1 && update_classification_failure_count == 0
        },
        SuppliedSessionAuditOutcome::CredentialUpdateUnusable => {
            selected_update_response_count == 0 && update_classification_failure_count == 1
        },
        _ => selected_update_response_count == 0 && update_classification_failure_count == 0,
    }
}

#[cfg(feature = "supplied-session-review")]
fn valid_v3_login_audit(
    audit: &WebAssessmentSuppliedSessionAudit,
    lifecycle_initial_epoch: u8,
    lifecycle_final_epoch: u8,
) -> bool {
    let Some(login) = audit.login() else {
        return false;
    };
    let page_contract = valid_v3_login_page_contract(
        login.form_outcome(),
        login.form_error_code(),
        login.page_dispatched(),
        login.page_status(),
        login.page_body_state(),
    );
    let submit_contract = valid_v3_login_submit_contract(
        login.submit_outcome(),
        login.submit_dispatched(),
        login.attempt_count(),
        login.submit_status(),
        login.submit_body_state(),
        login.acquired_cookie_count(),
    );
    let startup_authenticated = audit.checkpoints().first().is_some_and(|checkpoint| {
        checkpoint.phase() == SuppliedSessionHealthCheckpointPhase::Startup
            && checkpoint.outcome() == SuppliedSessionHealthOutcome::Healthy
    });
    let startup_cookie_update_stopped_transition = audit.checkpoints().len() == 1
        && audit
            .resources()
            .iter()
            .all(|resource| resource.outcome() == SuppliedSessionResourceOutcome::NotDispatched)
        && matches!(
            audit.outcome(),
            SuppliedSessionAuditOutcome::CredentialUpdateRequired
                | SuppliedSessionAuditOutcome::CredentialUpdateUnusable
        );
    let epoch_transition_is_valid = valid_v3_login_epoch_transition(
        login.final_epoch(),
        startup_authenticated,
        startup_cookie_update_stopped_transition,
    );
    let outcome_contract = valid_v3_login_outcome_contract(
        audit.outcome(),
        login.form_outcome(),
        login.submit_outcome(),
    );
    let dispatch_contract = valid_v3_login_dispatch_contract(
        login.form_outcome(),
        login.page_dispatched(),
        login.submit_dispatched(),
        login.response_bytes(),
    );
    let outcome_epoch_contract = match audit.outcome() {
        SuppliedSessionAuditOutcome::LoginFormUnavailable => login.final_epoch() == 0,
        SuppliedSessionAuditOutcome::LoginSubmitUnavailable => login.final_epoch() == 0,
        SuppliedSessionAuditOutcome::LoginCookieUnavailable => login.final_epoch() == 0,
        _ => true,
    };
    valid_supplied_session_reference(login.login_reference(), "supplied-session-login-sha256:")
        && login.max_attempts() == 1
        && login.attempt_count() <= login.max_attempts()
        && login.initial_epoch() == 0
        && epoch_transition_is_valid
        && lifecycle_initial_epoch == login.initial_epoch()
        && lifecycle_final_epoch == login.final_epoch()
        && !login.pre_session_cookie_applied()
        && page_contract
        && submit_contract
        && outcome_contract
        && dispatch_contract
        && outcome_epoch_contract
}

#[cfg(feature = "supplied-session-review")]
fn valid_v3_login_page_contract(
    form_outcome: SuppliedSessionLoginFormOutcome,
    form_error_code: Option<&str>,
    page_dispatched: bool,
    page_status: Option<u16>,
    page_body_state: SuppliedSessionBodyState,
) -> bool {
    if page_status.is_some_and(|status| !(100..=599).contains(&status)) {
        return false;
    }
    match form_outcome {
        SuppliedSessionLoginFormOutcome::Matched => {
            page_dispatched
                && page_status == Some(200)
                && page_body_state == SuppliedSessionBodyState::Complete
                && form_error_code.is_none()
        },
        SuppliedSessionLoginFormOutcome::IneligibleResponse => {
            page_dispatched
                && page_status.is_some()
                && matches!(
                    page_body_state,
                    SuppliedSessionBodyState::Complete | SuppliedSessionBodyState::Incomplete
                )
                && matches!(
                    form_error_code,
                    Some(
                        "ineligible_response"
                            | "pre_session_cookie_unsupported"
                            | "inexact_final_target"
                    )
                )
        },
        SuppliedSessionLoginFormOutcome::Missing => {
            page_dispatched
                && page_status == Some(200)
                && page_body_state == SuppliedSessionBodyState::Complete
                && matches!(form_error_code, Some("missing_form" | "missing_csrf"))
        },
        SuppliedSessionLoginFormOutcome::Ambiguous => {
            page_dispatched
                && page_status == Some(200)
                && page_body_state == SuppliedSessionBodyState::Complete
                && matches!(form_error_code, Some("ambiguous_form" | "ambiguous_csrf"))
        },
        SuppliedSessionLoginFormOutcome::Invalid
            if form_error_code == Some("invalid_descriptor") =>
        {
            !page_dispatched
                && page_status.is_none()
                && page_body_state == SuppliedSessionBodyState::Unavailable
        },
        SuppliedSessionLoginFormOutcome::Invalid => {
            page_dispatched
                && page_status == Some(200)
                && page_body_state == SuppliedSessionBodyState::Complete
                && matches!(
                    form_error_code,
                    Some("invalid_form_contract" | "invalid_csrf" | "invalid_form_body")
                )
        },
        SuppliedSessionLoginFormOutcome::TransportFailed => {
            page_status.is_none()
                && page_body_state == SuppliedSessionBodyState::Unavailable
                && form_error_code == Some("transport_failed")
        },
        SuppliedSessionLoginFormOutcome::RuntimeLimit => {
            page_status.is_none()
                && page_body_state == SuppliedSessionBodyState::Unavailable
                && form_error_code == Some("runtime_limit")
        },
        SuppliedSessionLoginFormOutcome::Cancelled => {
            page_status.is_none()
                && page_body_state == SuppliedSessionBodyState::Unavailable
                && form_error_code == Some("cancelled")
        },
        SuppliedSessionLoginFormOutcome::NotEvaluated => false,
    }
}

#[cfg(feature = "supplied-session-review")]
fn valid_v3_login_submit_contract(
    submit_outcome: SuppliedSessionLoginSubmitOutcome,
    submit_dispatched: bool,
    attempt_count: u8,
    submit_status: Option<u16>,
    submit_body_state: SuppliedSessionBodyState,
    acquired_cookie_count: u8,
) -> bool {
    if submit_status.is_some_and(|status| !(100..=599).contains(&status)) {
        return false;
    }
    match submit_outcome {
        SuppliedSessionLoginSubmitOutcome::CookieAcquired => {
            submit_dispatched
                && attempt_count == 1
                && submit_status == Some(200)
                && submit_body_state == SuppliedSessionBodyState::Complete
                && acquired_cookie_count > 0
        },
        SuppliedSessionLoginSubmitOutcome::CookieUnavailable => {
            submit_dispatched
                && attempt_count == 1
                && submit_status == Some(200)
                && submit_body_state == SuppliedSessionBodyState::Complete
                && acquired_cookie_count == 0
        },
        SuppliedSessionLoginSubmitOutcome::HttpError => {
            submit_dispatched
                && attempt_count == 1
                && submit_status
                    .is_some_and(|status| status != 200 && !(300..400).contains(&status))
                && submit_body_state == SuppliedSessionBodyState::Complete
                && acquired_cookie_count == 0
        },
        SuppliedSessionLoginSubmitOutcome::RedirectRefused => {
            submit_dispatched
                && attempt_count == 1
                && submit_status.is_some_and(|status| (300..400).contains(&status))
                && matches!(
                    submit_body_state,
                    SuppliedSessionBodyState::Complete | SuppliedSessionBodyState::Incomplete
                )
                && acquired_cookie_count == 0
        },
        SuppliedSessionLoginSubmitOutcome::Incomplete => {
            submit_dispatched
                && attempt_count == 1
                && submit_status.is_some_and(|status| !(300..400).contains(&status))
                && submit_body_state == SuppliedSessionBodyState::Incomplete
                && acquired_cookie_count == 0
        },
        SuppliedSessionLoginSubmitOutcome::TransportFailed
        | SuppliedSessionLoginSubmitOutcome::RuntimeLimit
        | SuppliedSessionLoginSubmitOutcome::Cancelled => {
            attempt_count == u8::from(submit_dispatched)
                && submit_status.is_none()
                && submit_body_state == SuppliedSessionBodyState::Unavailable
                && acquired_cookie_count == 0
        },
        SuppliedSessionLoginSubmitOutcome::NotDispatched => {
            !submit_dispatched
                && attempt_count == 0
                && submit_status.is_none()
                && submit_body_state == SuppliedSessionBodyState::Unavailable
                && acquired_cookie_count == 0
        },
    }
}

#[cfg(feature = "supplied-session-review")]
fn valid_v3_login_outcome_contract(
    audit_outcome: SuppliedSessionAuditOutcome,
    form_outcome: SuppliedSessionLoginFormOutcome,
    submit_outcome: SuppliedSessionLoginSubmitOutcome,
) -> bool {
    match audit_outcome {
        SuppliedSessionAuditOutcome::LoginFormUnavailable => {
            form_outcome != SuppliedSessionLoginFormOutcome::Matched
                && form_outcome != SuppliedSessionLoginFormOutcome::NotEvaluated
                && submit_outcome == SuppliedSessionLoginSubmitOutcome::NotDispatched
        },
        SuppliedSessionAuditOutcome::LoginSubmitUnavailable => {
            form_outcome == SuppliedSessionLoginFormOutcome::Matched
                && !matches!(
                    submit_outcome,
                    SuppliedSessionLoginSubmitOutcome::CookieAcquired
                        | SuppliedSessionLoginSubmitOutcome::CookieUnavailable
                )
        },
        SuppliedSessionAuditOutcome::LoginCookieUnavailable => {
            form_outcome == SuppliedSessionLoginFormOutcome::Matched
                && submit_outcome == SuppliedSessionLoginSubmitOutcome::CookieUnavailable
        },
        SuppliedSessionAuditOutcome::RuntimeLimit => {
            form_outcome == SuppliedSessionLoginFormOutcome::RuntimeLimit
                || submit_outcome == SuppliedSessionLoginSubmitOutcome::RuntimeLimit
                || submit_outcome == SuppliedSessionLoginSubmitOutcome::CookieAcquired
        },
        SuppliedSessionAuditOutcome::Cancelled => {
            form_outcome == SuppliedSessionLoginFormOutcome::Cancelled
                || submit_outcome == SuppliedSessionLoginSubmitOutcome::Cancelled
                || submit_outcome == SuppliedSessionLoginSubmitOutcome::CookieAcquired
        },
        _ => submit_outcome == SuppliedSessionLoginSubmitOutcome::CookieAcquired,
    }
}

#[cfg(feature = "supplied-session-review")]
fn valid_v3_form_cookie_count_contract(
    declared_count: u8,
    secure_count: u8,
    submit_outcome: SuppliedSessionLoginSubmitOutcome,
    acquired_cookie_count: u8,
) -> bool {
    (secure_count == 0 || secure_count == declared_count)
        && (submit_outcome != SuppliedSessionLoginSubmitOutcome::CookieAcquired
            || acquired_cookie_count == declared_count)
}

#[cfg(feature = "supplied-session-review")]
fn valid_v3_login_dispatch_contract(
    form_outcome: SuppliedSessionLoginFormOutcome,
    page_dispatched: bool,
    submit_dispatched: bool,
    response_bytes: u64,
) -> bool {
    (!submit_dispatched || form_outcome == SuppliedSessionLoginFormOutcome::Matched)
        && (page_dispatched || submit_dispatched || response_bytes == 0)
}

#[cfg(feature = "supplied-session-review")]
const fn valid_v3_login_epoch_transition(
    final_epoch: u8,
    startup_authenticated: bool,
    startup_cookie_update_stopped_transition: bool,
) -> bool {
    match final_epoch {
        1 => startup_authenticated,
        0 => !startup_authenticated || startup_cookie_update_stopped_transition,
        _ => false,
    }
}

#[cfg(feature = "supplied-session-review")]
fn validate_supplied_session_audit(
    audit: Option<&WebAssessmentSuppliedSessionAudit>,
    items: &[AssessmentItem],
) -> Result<(), AssessmentRunReportError> {
    let projected_count = items
        .iter()
        .filter(|item| item.capability_id() == SUPPLIED_SESSION_CAPABILITY_ID)
        .count();
    if projected_count != 0 {
        return Err(AssessmentRunReportError::SuppliedSessionAuditMismatch);
    }
    let Some(audit) = audit else {
        return Ok(());
    };
    let selected_resource_count = usize::from(audit.selected_resource_count());
    let dispatched_resource_count = usize::from(audit.dispatched_resource_count());
    let committed_resource_count = usize::from(audit.committed_resource_count());
    let dispatched_request_count = usize::from(audit.dispatched_request_count());
    let actual_dispatched_resource_count = audit
        .resources()
        .iter()
        .filter(|resource| resource.outcome() != SuppliedSessionResourceOutcome::NotDispatched)
        .count();
    let actual_committed_resource_count = audit
        .resources()
        .iter()
        .filter(|resource| resource.outcome() == SuppliedSessionResourceOutcome::Committed)
        .count();
    let child_response_bytes = audit
        .login()
        .map_or(0, |login| login.response_bytes())
        .checked_add(
            audit
                .checkpoints()
                .iter()
                .map(|checkpoint| checkpoint.response_bytes())
                .chain(
                    audit
                        .resources()
                        .iter()
                        .map(|resource| resource.response_bytes()),
                )
                .try_fold(0_u64, u64::checked_add)
                .ok_or(AssessmentRunReportError::SuppliedSessionAuditMismatch)?,
        );
    let login_request_count = audit.login().map_or(0_u8, |login| {
        u8::from(login.page_dispatched()).saturating_add(u8::from(login.submit_dispatched()))
    });
    let cookie_contract_is_valid = match (
        audit.schema(),
        audit.credential_mechanism(),
        audit.cookie_policy(),
        audit.cookie_lifecycle(),
    ) {
        (
            SUPPLIED_SESSION_AUDIT_SCHEMA,
            SuppliedSessionCredentialMechanism::AuthorizationHeader,
            None,
            None,
        ) => {
            audit.credential_acquisition()
                == SuppliedSessionCredentialAcquisition::SuppliedAuthorization
                && audit.login().is_none()
                && valid_v1_supplied_session_outcome(audit.outcome())
        },
        (
            SUPPLIED_SESSION_COOKIE_AUDIT_SCHEMA,
            SuppliedSessionCredentialMechanism::CookieJar,
            Some(policy),
            Some(lifecycle),
        ) => {
            let declared = usize::from(policy.declared_count());
            audit.credential_acquisition()
                == SuppliedSessionCredentialAcquisition::SuppliedCookieJar
                && audit.login().is_none()
                && (1..=MAX_SUPPLIED_SESSION_COOKIES).contains(&declared)
                && usize::from(policy.host_only_count())
                    .checked_add(usize::from(policy.domain_count()))
                    == Some(declared)
                && usize::from(policy.secure_count()) <= declared
                && usize::from(policy.same_site_none_count()) <= usize::from(policy.secure_count())
                && usize::from(policy.http_only_count()) <= declared
                && usize::from(policy.session_count())
                    .checked_add(usize::from(policy.persistent_count()))
                    == Some(declared)
                && usize::from(policy.same_site_missing_count())
                    .checked_add(usize::from(policy.same_site_strict_count()))
                    .and_then(|count| count.checked_add(usize::from(policy.same_site_lax_count())))
                    .and_then(|count| count.checked_add(usize::from(policy.same_site_none_count())))
                    == Some(declared)
                && policy.update_policy().as_str() == "stop_on_selected_cookie"
                && policy.browser_semantics() == "attributes_preserved_not_browser_csrf_emulation"
                && lifecycle.initial_epoch() == 1
                && lifecycle.final_epoch() == 1
                && valid_v2_cookie_lifecycle_accounting(
                    lifecycle.selected_update_response_count(),
                    lifecycle.unselected_update_response_count(),
                    lifecycle.update_classification_failure_count(),
                    audit.dispatched_request_count(),
                )
                && lifecycle.updates_applied() == 0
                && valid_v2_cookie_lifecycle_outcome(
                    audit.outcome(),
                    lifecycle.selected_update_response_count(),
                    lifecycle.update_classification_failure_count(),
                )
        },
        (
            SUPPLIED_SESSION_FORM_LOGIN_AUDIT_SCHEMA,
            SuppliedSessionCredentialMechanism::CookieJar,
            Some(policy),
            Some(lifecycle),
        ) => {
            let declared = usize::from(policy.declared_count());
            audit.credential_acquisition() == SuppliedSessionCredentialAcquisition::BoundedFormLogin
                && selected_resource_count <= MAX_SUPPLIED_SESSION_RESOURCES.saturating_sub(1)
                && (1..=MAX_SUPPLIED_SESSION_COOKIES).contains(&declared)
                && usize::from(policy.host_only_count()) == declared
                && policy.domain_count() == 0
                && audit.login().is_some_and(|login| {
                    valid_v3_form_cookie_count_contract(
                        policy.declared_count(),
                        policy.secure_count(),
                        login.submit_outcome(),
                        login.acquired_cookie_count(),
                    )
                })
                && usize::from(policy.http_only_count()) == declared
                && usize::from(policy.session_count()) == declared
                && policy.persistent_count() == 0
                && policy.same_site_missing_count() == 0
                && policy.same_site_none_count() == 0
                && usize::from(policy.same_site_strict_count())
                    .checked_add(usize::from(policy.same_site_lax_count()))
                    == Some(declared)
                && policy.update_policy().as_str() == "stop_on_selected_cookie"
                && policy.browser_semantics() == "attributes_preserved_not_browser_csrf_emulation"
                && valid_v3_cookie_lifecycle_accounting(
                    lifecycle.selected_update_response_count(),
                    lifecycle.unselected_update_response_count(),
                    lifecycle.update_classification_failure_count(),
                    audit.dispatched_request_count(),
                    login_request_count,
                )
                && lifecycle.updates_applied() == 0
                && valid_v3_cookie_lifecycle_outcome(
                    audit.outcome(),
                    lifecycle.selected_update_response_count(),
                    lifecycle.update_classification_failure_count(),
                )
                && valid_v3_login_audit(audit, lifecycle.initial_epoch(), lifecycle.final_epoch())
        },
        _ => false,
    };
    if !cookie_contract_is_valid
        || audit.capability_id() != SUPPLIED_SESSION_CAPABILITY_ID
        || !valid_supplied_session_principal_alias(audit.principal_alias())
        || audit.resources().is_empty()
        || audit.resources().len() > MAX_SUPPLIED_SESSION_RESOURCES
        || audit.checkpoints().len() > MAX_SUPPLIED_SESSION_CHECKPOINTS
        || selected_resource_count != audit.resources().len()
        || dispatched_resource_count != actual_dispatched_resource_count
        || committed_resource_count != actual_committed_resource_count
        || committed_resource_count > dispatched_resource_count
        || dispatched_resource_count > selected_resource_count
        || dispatched_request_count > usize::from(MAX_SUPPLIED_SESSION_REQUESTS)
        || dispatched_request_count
            != audit
                .checkpoints()
                .len()
                .checked_add(dispatched_resource_count)
                .and_then(|count| count.checked_add(usize::from(login_request_count)))
                .ok_or(AssessmentRunReportError::SuppliedSessionAuditMismatch)?
        || child_response_bytes != Some(audit.response_bytes())
        || !valid_supplied_session_response_limit(
            audit.response_bytes(),
            audit.response_byte_limit(),
            audit.response_byte_limit_exceeded(),
        )
        || audit
            .checkpoints()
            .iter()
            .enumerate()
            .any(|(index, checkpoint)| {
                let expected_phase = if index == 0 {
                    SuppliedSessionHealthCheckpointPhase::Startup
                } else if index == selected_resource_count {
                    SuppliedSessionHealthCheckpointPhase::Terminal
                } else {
                    SuppliedSessionHealthCheckpointPhase::SubjectBoundary
                };
                usize::from(checkpoint.sequence()) != index
                    || usize::from(checkpoint.after_subject_count()) != index
                    || checkpoint.phase() != expected_phase
            })
        || audit.checkpoints().iter().any(|checkpoint| {
            let evidence = checkpoint.evidence_reference();
            let evidence_is_valid = evidence.is_some_and(|reference| {
                valid_supplied_session_reference(
                    reference,
                    "supplied-session-checkpoint-evidence-sha256:",
                )
            });
            (evidence.is_some()
                || checkpoint.outcome() != SuppliedSessionHealthOutcome::Indeterminate)
                && !evidence_is_valid
        })
        || audit.resources().iter().any(|resource| {
            let evidence_is_valid = resource.evidence_reference().is_some_and(|reference| {
                valid_supplied_session_reference(
                    reference,
                    "supplied-session-resource-evidence-sha256:",
                )
            });
            supplied_session_resource_outcome_requires_evidence(resource.outcome())
                != evidence_is_valid
        })
        || audit
            .resources()
            .iter()
            .enumerate()
            .any(|(index, resource)| {
                usize::from(resource.sequence()) != index
                    || resource.epoch() != 1
                    || !valid_supplied_session_reference(
                        resource.resource_reference(),
                        "supplied-session-resource-sha256:",
                    )
            })
        || audit.refresh_performed()
        || audit.anonymous_fallback_performed()
        || audit.continuous_authentication_established()
        || (matches!(
            audit.outcome(),
            SuppliedSessionAuditOutcome::CredentialUpdateRequired
                | SuppliedSessionAuditOutcome::CredentialUpdateUnusable
        ) && audit.coverage() == super::SuppliedSessionCoverage::Complete)
        || audit.exploit_execution_performed()
        || audit.impact_validation_performed()
    {
        return Err(AssessmentRunReportError::SuppliedSessionAuditMismatch);
    }
    Ok(())
}

#[cfg(feature = "supplied-session-review")]
const fn valid_supplied_session_response_limit(
    response_bytes: u64,
    response_byte_limit: u64,
    response_byte_limit_exceeded: bool,
) -> bool {
    response_byte_limit > 0
        && response_byte_limit <= MAX_SUPPLIED_SESSION_TOTAL_RESPONSE_BYTES
        && response_byte_limit_exceeded == (response_bytes > response_byte_limit)
}

#[cfg(feature = "supplied-session-review")]
const fn supplied_session_resource_outcome_requires_evidence(
    outcome: SuppliedSessionResourceOutcome,
) -> bool {
    matches!(
        outcome,
        SuppliedSessionResourceOutcome::Committed
            | SuppliedSessionResourceOutcome::HealthUnqualified
    )
}

#[cfg(feature = "supplied-session-review")]
fn valid_supplied_session_reference(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(feature = "supplied-session-review")]
fn valid_supplied_session_principal_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
        })
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
        || (positive
            && (audit.primary_stable() != Some(true)
                || audit.peer_stable() != Some(true)
                || audit.cross_resources_equivalent() != Some(true)))
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
    /// The optional supplied-session audit disagreed with its audit-only runtime truth.
    #[cfg(feature = "supplied-session-review")]
    #[error("supplied-session review audit does not match runtime truth")]
    SuppliedSessionAuditMismatch,
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
    /// The optional WordPress audit disagreed with projected item truth.
    #[cfg(feature = "wordpress-review")]
    #[error("WordPress review audit does not match projected item truth")]
    WordPressAuditMismatch,
    /// The optional passive secret-exposure audit disagreed with projected item truth.
    #[cfg(feature = "secret-exposure-review")]
    #[error("secret-exposure review audit does not match committed item truth")]
    SecretExposureAuditMismatch,
    /// The optional passive TLS audit disagreed with its transport-owned truth.
    #[cfg(feature = "tls-observation")]
    #[error("TLS observation audit does not match transport truth")]
    TlsObservationAuditMismatch,
    /// The optional CT provider audit disagreed with runtime-owned request and byte truth.
    #[cfg(feature = "recon-ct-provider")]
    #[error("certificate-transparency provider audit does not match runtime truth")]
    ReconCtProviderAuditMismatch,
    /// The optional transport-free JWT audit violated its closed local contract.
    #[cfg(feature = "jwt-policy-review")]
    #[error("JWT policy review audit does not match its local evaluation contract")]
    JwtPolicyReviewAuditMismatch,
    /// The optional target-side JWT audit violated its closed six-leg contract.
    #[cfg(feature = "jwt-target-acceptance-review")]
    #[error("JWT target-acceptance audit does not match its runtime contract")]
    JwtTargetAcceptanceAuditMismatch,
    /// The optional offline control-reference mapping violated its closed bounds.
    #[cfg(feature = "control-reference-mapping")]
    #[error("control-reference mapping audit does not match completed assessment items")]
    ControlReferenceMappingAuditMismatch,
    /// The optional bounded local reconnaissance snapshot was attached more
    /// than once or otherwise violated the report composition contract.
    #[cfg(feature = "recon-snapshot-import")]
    #[error("reconnaissance snapshot audit does not match the report composition contract")]
    ReconSnapshotAuditMismatch,
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
        #[cfg(feature = "jwt-target-acceptance-review")]
        let allowance =
            allowance.saturating_add(u16::from(MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS));
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

    #[cfg(feature = "jwt-target-acceptance-review")]
    #[test]
    fn jwt_target_audit_is_bound_to_the_matching_local_prerequisite_state() {
        use crate::{
            jwt_policy_review::{
                review_and_prepare_target_acceptance, Es256LocalPublicKey, JwtEvaluationTime,
                JwtLocalPolicy, SecretCompactJwt,
            },
            jwt_target_acceptance::{
                JwtTargetAcceptanceAudit, JwtTargetAcceptanceNotEligibleReason,
                JwtTargetAcceptancePolicy,
            },
        };

        let key = Es256LocalPublicKey::from_jwk_json(
            br#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#
                .to_vec(),
        )
        .unwrap();
        let policy = JwtLocalPolicy::new(
            ("synthetic-policy", "synthetic-policy-v1"),
            "JWT",
            "owned-issuer",
            "owned-api",
            &["scope"],
            true,
            0,
        )
        .unwrap();
        let prepared = review_and_prepare_target_acceptance(
            SecretCompactJwt::new(b"not-a.compact.jwt".to_vec()).unwrap(),
            &key,
            &policy,
            JwtEvaluationTime {
                unix_seconds: 1_900_000_000,
            },
        )
        .unwrap();
        let (rejected, runtime_input) = prepared.into_parts();
        let (_, reason, preparation_binding) = runtime_input.into_parts();
        assert_eq!(
            reason,
            Some(JwtTargetAcceptanceNotEligibleReason::LocalParsingNotEstablished)
        );
        let target_policy = JwtTargetAcceptancePolicy::new(
            ("synthetic-target-policy", "synthetic-target-v1"),
            Url::parse("https://owned.invalid/app/").unwrap(),
            Url::parse("https://owned.invalid/app/canary").unwrap(),
            "protected-canary",
            "accepted",
        )
        .unwrap();

        let matching = JwtTargetAcceptanceAudit::not_eligible(
            &target_policy,
            JwtTargetAcceptanceNotEligibleReason::LocalParsingNotEstablished,
        )
        .bind_to_preparation(preparation_binding.clone());
        assert!(validate_jwt_target_local_link(&rejected, &matching).is_ok());

        let independently_prepared = review_and_prepare_target_acceptance(
            SecretCompactJwt::new(b"not-a.compact.jwt".to_vec()).unwrap(),
            &key,
            &policy,
            JwtEvaluationTime {
                unix_seconds: 1_900_000_000,
            },
        )
        .unwrap();
        let (independent_rejected, _) = independently_prepared.into_parts();
        assert_eq!(
            validate_jwt_target_local_link(&independent_rejected, &matching),
            Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch),
            "identical local states from another preparation must not pair with this target audit"
        );

        for reason in [
            JwtTargetAcceptanceNotEligibleReason::LocalPolicyNotEstablished,
            JwtTargetAcceptanceNotEligibleReason::LocalSignatureNotEstablished,
            JwtTargetAcceptanceNotEligibleReason::RuntimeAuthorityUnavailable,
            JwtTargetAcceptanceNotEligibleReason::RequestBudgetUnavailable,
        ] {
            let mismatched = JwtTargetAcceptanceAudit::not_eligible(&target_policy, reason)
                .bind_to_preparation(preparation_binding.clone());
            assert_eq!(
                validate_jwt_target_local_link(&rejected, &mismatched),
                Err(AssessmentRunReportError::JwtPolicyReviewAuditMismatch)
            );
        }
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    #[test]
    fn jwt_target_transport_bytes_are_bounded_by_parent_response_accounting() {
        use crate::jwt_target_acceptance::{
            JwtTargetAcceptanceAudit, JwtTargetAcceptanceBinding, JwtTargetAcceptanceCommitStatus,
            JwtTargetAcceptanceDispatchStatus, JwtTargetAcceptanceLegFact,
            JwtTargetAcceptanceLegRole, JwtTargetAcceptanceMarkerStatus, JwtTargetAcceptancePolicy,
            JwtTargetAcceptanceResponseStatus,
        };

        let policy = JwtTargetAcceptancePolicy::new(
            ("synthetic-target-policy", "synthetic-target-v1"),
            Url::parse("https://owned.invalid/app/").unwrap(),
            Url::parse("https://owned.invalid/app/canary").unwrap(),
            "protected-canary",
            "accepted",
        )
        .unwrap();
        let roles = JwtTargetAcceptanceLegRole::ORDERED;
        let mut legs = roles
            .into_iter()
            .map(JwtTargetAcceptanceLegFact::not_dispatched)
            .collect::<Vec<_>>();
        legs[0] = JwtTargetAcceptanceLegFact::new(
            roles[0],
            JwtTargetAcceptanceDispatchStatus::Dispatched,
            JwtTargetAcceptanceCommitStatus::NotCommitted,
            JwtTargetAcceptanceResponseStatus::Incomplete,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
            5,
            None,
        )
        .unwrap();
        let audit = JwtTargetAcceptanceAudit::from_legs(&policy, legs)
            .unwrap()
            .bind_to_preparation(JwtTargetAcceptanceBinding::synthetic_for_test(0x3C));

        assert!(validate_jwt_target_acceptance_audit(Some(&audit), Some(1), Some(5)).is_ok());
        assert_eq!(
            validate_jwt_target_acceptance_audit(Some(&audit), Some(1), Some(4)),
            Err(AssessmentRunReportError::JwtTargetAcceptanceAuditMismatch)
        );
        assert_eq!(
            validate_jwt_target_acceptance_audit(Some(&audit), Some(1), None),
            Err(AssessmentRunReportError::JwtTargetAcceptanceAuditMismatch)
        );
    }

    #[cfg(feature = "tls-observation")]
    #[test]
    fn tls_observation_response_count_is_bounded_by_run_request_accounting() {
        let collector = super::super::tls_observation::TlsObservationCollector::new("https");
        let empty = collector.audit();
        assert!(
            validate_tls_observation_audit(Some(&empty), "https://example.test/", Some(0),).is_ok()
        );

        collector.observe_https_response(None);
        let one_response = collector.audit();
        assert!(validate_tls_observation_audit(
            Some(&one_response),
            "https://example.test/",
            Some(1),
        )
        .is_ok());
        assert_eq!(
            validate_tls_observation_audit(Some(&one_response), "https://example.test/", Some(0),),
            Err(AssessmentRunReportError::TlsObservationAuditMismatch)
        );
        assert_eq!(
            validate_tls_observation_audit(Some(&one_response), "https://example.test/", None,),
            Err(AssessmentRunReportError::TlsObservationAuditMismatch)
        );
    }

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

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn supplied_session_report_preserves_overrun_accounting_and_qualification_state() {
        assert!(valid_supplied_session_response_limit(59, 65_536, false));
        assert!(valid_supplied_session_response_limit(65_537, 65_536, true));
        assert!(!valid_supplied_session_response_limit(
            65_537, 65_536, false
        ));
        assert!(!valid_supplied_session_response_limit(59, 0, true));
        assert!(!valid_supplied_session_response_limit(
            59,
            MAX_SUPPLIED_SESSION_TOTAL_RESPONSE_BYTES + 1,
            false
        ));

        assert!(supplied_session_resource_outcome_requires_evidence(
            SuppliedSessionResourceOutcome::Committed
        ));
        assert!(supplied_session_resource_outcome_requires_evidence(
            SuppliedSessionResourceOutcome::HealthUnqualified
        ));
        for outcome in [
            SuppliedSessionResourceOutcome::HttpError,
            SuppliedSessionResourceOutcome::RedirectRefused,
            SuppliedSessionResourceOutcome::Incomplete,
            SuppliedSessionResourceOutcome::TransportFailed,
            SuppliedSessionResourceOutcome::NotDispatched,
        ] {
            assert!(!supplied_session_resource_outcome_requires_evidence(
                outcome
            ));
        }
    }

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn supplied_session_versioned_outcomes_reject_v1_mutations_and_keep_v2_stops() {
        for outcome in [
            SuppliedSessionAuditOutcome::CredentialUpdateRequired,
            SuppliedSessionAuditOutcome::CredentialUpdateUnusable,
            SuppliedSessionAuditOutcome::LoginFormUnavailable,
            SuppliedSessionAuditOutcome::LoginSubmitUnavailable,
            SuppliedSessionAuditOutcome::LoginCookieUnavailable,
        ] {
            assert!(!valid_v1_supplied_session_outcome(outcome));
        }

        assert!(valid_v1_supplied_session_outcome(
            SuppliedSessionAuditOutcome::Complete
        ));
        assert!(valid_v2_cookie_lifecycle_outcome(
            SuppliedSessionAuditOutcome::CredentialUpdateRequired,
            1,
            0,
        ));
        assert!(valid_v2_cookie_lifecycle_outcome(
            SuppliedSessionAuditOutcome::CredentialUpdateUnusable,
            0,
            1,
        ));
        for outcome in [
            SuppliedSessionAuditOutcome::LoginFormUnavailable,
            SuppliedSessionAuditOutcome::LoginSubmitUnavailable,
            SuppliedSessionAuditOutcome::LoginCookieUnavailable,
        ] {
            assert!(!valid_v2_cookie_lifecycle_outcome(outcome, 0, 0));
        }
        assert!(valid_v3_cookie_lifecycle_outcome(
            SuppliedSessionAuditOutcome::LoginCookieUnavailable,
            0,
            0,
        ));
        assert!(!valid_v3_cookie_lifecycle_outcome(
            SuppliedSessionAuditOutcome::LoginCookieUnavailable,
            1,
            0,
        ));
        assert!(valid_v2_cookie_lifecycle_accounting(1, 1, 0, 1));
        assert!(!valid_v2_cookie_lifecycle_accounting(0, 1, 1, 1));
        assert!(valid_v3_cookie_lifecycle_accounting(0, 3, 0, 5, 2));
        assert!(!valid_v3_cookie_lifecycle_accounting(0, 4, 0, 5, 2));
        assert!(!valid_v3_cookie_lifecycle_accounting(0, 0, 0, 1, 2));

        assert!(valid_v3_login_outcome_contract(
            SuppliedSessionAuditOutcome::RuntimeLimit,
            SuppliedSessionLoginFormOutcome::RuntimeLimit,
            SuppliedSessionLoginSubmitOutcome::NotDispatched,
        ));
        assert!(valid_v3_login_outcome_contract(
            SuppliedSessionAuditOutcome::Cancelled,
            SuppliedSessionLoginFormOutcome::Matched,
            SuppliedSessionLoginSubmitOutcome::Cancelled,
        ));
        assert!(valid_v3_login_outcome_contract(
            SuppliedSessionAuditOutcome::RuntimeLimit,
            SuppliedSessionLoginFormOutcome::Matched,
            SuppliedSessionLoginSubmitOutcome::CookieAcquired,
        ));
        for outcome in [
            SuppliedSessionAuditOutcome::RuntimeLimit,
            SuppliedSessionAuditOutcome::Cancelled,
        ] {
            assert!(!valid_v3_login_outcome_contract(
                outcome,
                SuppliedSessionLoginFormOutcome::Missing,
                SuppliedSessionLoginSubmitOutcome::NotDispatched,
            ));
        }

        assert!(valid_v3_login_page_contract(
            SuppliedSessionLoginFormOutcome::Invalid,
            Some("invalid_descriptor"),
            false,
            None,
            SuppliedSessionBodyState::Unavailable,
        ));
        assert!(!valid_v3_login_page_contract(
            SuppliedSessionLoginFormOutcome::Invalid,
            Some("invalid_descriptor"),
            true,
            None,
            SuppliedSessionBodyState::Unavailable,
        ));
        assert!(valid_v3_login_page_contract(
            SuppliedSessionLoginFormOutcome::Missing,
            Some("missing_csrf"),
            true,
            Some(200),
            SuppliedSessionBodyState::Complete,
        ));
        assert!(!valid_v3_login_page_contract(
            SuppliedSessionLoginFormOutcome::Missing,
            Some("missing_csrf"),
            true,
            Some(404),
            SuppliedSessionBodyState::Unavailable,
        ));
        assert!(!valid_v3_login_page_contract(
            SuppliedSessionLoginFormOutcome::RuntimeLimit,
            Some("runtime_limit"),
            true,
            Some(200),
            SuppliedSessionBodyState::Complete,
        ));
        assert!(!valid_v3_login_page_contract(
            SuppliedSessionLoginFormOutcome::IneligibleResponse,
            Some("inexact_final_target"),
            true,
            Some(600),
            SuppliedSessionBodyState::Complete,
        ));
        assert!(valid_v3_login_submit_contract(
            SuppliedSessionLoginSubmitOutcome::RuntimeLimit,
            true,
            1,
            None,
            SuppliedSessionBodyState::Unavailable,
            0,
        ));
        assert!(!valid_v3_login_submit_contract(
            SuppliedSessionLoginSubmitOutcome::RuntimeLimit,
            true,
            1,
            Some(200),
            SuppliedSessionBodyState::Complete,
            0,
        ));
        assert!(!valid_v3_login_submit_contract(
            SuppliedSessionLoginSubmitOutcome::HttpError,
            true,
            1,
            Some(99),
            SuppliedSessionBodyState::Complete,
            0,
        ));
        assert!(valid_v3_form_cookie_count_contract(
            1,
            0,
            SuppliedSessionLoginSubmitOutcome::CookieAcquired,
            1,
        ));
        assert!(valid_v3_form_cookie_count_contract(
            2,
            2,
            SuppliedSessionLoginSubmitOutcome::CookieAcquired,
            2,
        ));
        assert!(!valid_v3_form_cookie_count_contract(
            2,
            1,
            SuppliedSessionLoginSubmitOutcome::CookieAcquired,
            2,
        ));
        assert!(!valid_v3_form_cookie_count_contract(
            2,
            2,
            SuppliedSessionLoginSubmitOutcome::CookieAcquired,
            1,
        ));
        assert!(valid_v3_login_dispatch_contract(
            SuppliedSessionLoginFormOutcome::Matched,
            true,
            true,
            32,
        ));
        assert!(!valid_v3_login_dispatch_contract(
            SuppliedSessionLoginFormOutcome::Missing,
            true,
            true,
            32,
        ));
        assert!(valid_v3_login_dispatch_contract(
            SuppliedSessionLoginFormOutcome::Invalid,
            false,
            false,
            0,
        ));
        assert!(!valid_v3_login_dispatch_contract(
            SuppliedSessionLoginFormOutcome::Invalid,
            false,
            false,
            1,
        ));
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

    #[cfg(feature = "recon-snapshot-import")]
    #[test]
    fn recon_snapshot_attachment_preserves_assessment_truth_and_is_single_use() {
        let bytes = br#"{
            "schema":"security.recon-snapshot/v1",
            "snapshot_id":"synthetic-empty-snapshot",
            "snapshot_revision":"revision-1",
            "sources":[{
                "source_id":"synthetic-source",
                "namespace":"owned.fixture",
                "revision":"source-r1",
                "provider_time":null,
                "observed_time":"2026-09-20T10:30:00Z",
                "collection_method":"owned-offline-fixture",
                "completeness":"unknown",
                "origin":"owned fixture",
                "rights":{"status":"permitted_as_declared","attribution":null,"notice":null}
            }],
            "records":[]
        }"#;
        let first = crate::recon_snapshot::parse_recon_snapshot(bytes).unwrap();
        let duplicate = crate::recon_snapshot::parse_recon_snapshot(bytes).unwrap();
        let report = AssessmentRunReport::new(
            complete_run_report(PRIVATE_CANONICAL_TARGET, PRIVATE_EXACT_ORIGIN),
            root_item_set(PRIVATE_EXACT_ORIGIN),
            completed_truth(PRIVATE_CANONICAL_TARGET),
        )
        .unwrap();
        let run_target = report.run_report().target().to_owned();
        let subject_count = report.subject_count();
        let item_count = report.item_count();

        let report = report.with_recon_snapshot(first).unwrap();
        assert_eq!(report.run_report().target(), run_target);
        assert_eq!(report.subject_count(), subject_count);
        assert_eq!(report.item_count(), item_count);
        assert_eq!(
            report
                .recon_snapshot_audit()
                .map(|audit| audit.record_count()),
            Some(0)
        );
        assert_eq!(
            report.with_recon_snapshot(duplicate).unwrap_err(),
            AssessmentRunReportError::ReconSnapshotAuditMismatch
        );
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
        feature = "jwt-target-acceptance-review",
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
        let expected = limits.max_active_verifications().checked_add(6).unwrap();
        let usage = AssessmentUsageTruth {
            active_verifications: 6,
            ..usage_truth(root.url().as_str())
        };
        let profile = ScanProfileV1::web_review().unwrap();

        assert_eq!(
            validate_completed_assessment_truth_with_active_limit(
                root,
                AssessmentRuntimeLimits::new(limits, expected, 6),
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
                AssessmentRuntimeLimits::new(limits, expected - 1, 6),
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
                AssessmentRuntimeLimits::new(limits, expected + 1, 7),
                usage,
                &WebAssessmentCompletion::Complete,
                WebAssessmentDefenseMode::ObservationOnly,
                &profile,
            ),
            Err(AssessmentRunReportError::AssessmentUsageMismatch)
        );
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    #[test]
    fn jwt_target_acceptance_has_exact_two_active_control_allowance() {
        let runtime =
            WebAssessmentRuntime::builder(Url::parse("https://example.test/review").unwrap())
                .build()
                .unwrap();
        let root = runtime.authorized_root();
        let limits = WebAssessmentLimits::default();
        let allowance = u16::from(MAX_JWT_TARGET_ACCEPTANCE_ACTIVE_REQUESTS);
        let expected = limits
            .max_active_verifications()
            .checked_add(allowance)
            .unwrap();
        let usage = AssessmentUsageTruth {
            active_verifications: allowance,
            ..usage_truth(root.url().as_str())
        };
        let profile = ScanProfileV1::web_review().unwrap();

        assert_eq!(
            validate_completed_assessment_truth_with_active_limit(
                root,
                AssessmentRuntimeLimits::new(limits, expected, allowance),
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
                AssessmentRuntimeLimits::new(limits, expected - 1, allowance),
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

    #[cfg(feature = "supplied-session-review")]
    #[test]
    fn form_login_epoch_requires_health_or_the_exact_pre_transition_cookie_stop() {
        assert!(valid_v3_login_epoch_transition(1, true, false));
        assert!(!valid_v3_login_epoch_transition(1, false, false));

        assert!(valid_v3_login_epoch_transition(0, false, false));
        assert!(valid_v3_login_epoch_transition(0, true, true));
        assert!(!valid_v3_login_epoch_transition(0, true, false));

        assert!(!valid_v3_login_epoch_transition(2, true, true));
    }
}
