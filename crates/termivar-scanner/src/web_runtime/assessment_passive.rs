//! Value-free passive response evidence and exact committed-receipt replay.
//!
//! Raw response headers are deliberately absent from this module. The HTTP
//! executor passes only a bounded [`PassiveResponseProjection`], and this
//! module turns that projection into a closed evidence vocabulary. The ledger
//! accepts the result only after the decision runner has committed the exact
//! batch to the authoritative knowledge base.

use std::{collections::BTreeMap, fmt};

use termivar_core::{
    ConfidenceScore, DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId,
    EvidenceKind, EvidenceOrigin, EvidenceSource, EvidenceValue, HttpEvidencePredicate,
    KnowledgePredicate,
};

use crate::{
    http_evidence::passive_review::{
        ContentSecurityPolicyMetadata, PassiveCookieMetadata, PassiveCookieSameSite,
        PassiveFieldProjection, PassiveProjectionIncompleteReason, PassiveProjectionState,
        PassiveResponseProjection, PermissionsPolicyMetadata, ReferrerPolicyValue,
        StrictTransportSecurityMetadata, MAX_PASSIVE_COOKIE_NAME_BYTES,
        MAX_PASSIVE_DERIVED_OBSERVATIONS, MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES,
        MAX_PASSIVE_PERMISSIONS_POLICY_MEMBERS, MAX_PASSIVE_SET_COOKIE_OCCURRENCES,
    },
    DecisionEvidenceReceipt, DecisionExecutionStage, HttpEvidenceError, KnowledgeBase,
    KnowledgeWrite, HTTP_EVIDENCE_EXECUTOR_ID,
};

#[cfg(feature = "graphql-review")]
use super::graphql_runtime::{
    project_graphql_items, register_graphql_subject, CommittedGraphqlReview,
};
#[cfg(feature = "openapi-review")]
use super::openapi_runtime::{project_openapi_item, CommittedOpenApiReview};
#[cfg(feature = "authorization-review")]
use super::resource_authorization_runtime::{
    project_resource_authorization_item, CommittedResourceAuthorizationReview,
};
#[cfg(feature = "rest-review")]
use super::rest_runtime::{project_rest_item, CommittedRestReview};
#[cfg(feature = "ssrf-oast-review")]
use super::ssrf_oast_runtime::{project_ssrf_oast_item, CommittedSsrfOastReview};
use super::{
    assessment_api_visibility::{project_api_visibility_item, CommittedAssessmentApiVisibility},
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemSet,
        AssessmentItemTarget, AssessmentProjectionContext, StableAssessmentScopeId,
        StableAssessmentSubjectId, MAX_ASSESSMENT_ITEM_SET_ITEMS,
    },
    assessment_review::CommittedAssessmentReviewLedger,
    assessment_review_projection::{
        project_assessment_review_ledgers, AssessmentReviewItemProjectionError,
    },
    web_assessment::{
        WebAssessmentMethod, WebAssessmentSubject, WebAssessmentSubjectOrigin,
        HARD_MAX_WEB_ASSESSMENT_SUBJECTS,
    },
    BOOTSTRAP_ACTION_ID, BOOTSTRAP_CASE_ID, BOOTSTRAP_HYPOTHESIS_ID,
};

pub(crate) const ASSESSMENT_PASSIVE_NAMESPACE: &str = "web.passive-review";
const ASSESSMENT_PASSIVE_CATEGORY: &str = "web-passive-review";
const ASSESSMENT_PASSIVE_SOURCE_METHOD: &str = "passive-response-projection";
const ASSESSMENT_PASSIVE_ALGORITHM: &str = "web.passive-review.value-free-response-metadata";
const ASSESSMENT_PASSIVE_ALGORITHM_VERSION: u32 = 1;

const HSTS_STATE: &str = "hsts_state";
const HSTS_MAX_AGE: &str = "hsts_max_age_seconds";
const HSTS_INCLUDE_SUBDOMAINS: &str = "hsts_include_subdomains";
const HSTS_PRELOAD: &str = "hsts_preload_requested";
const HSTS_UNRECOGNIZED: &str = "hsts_unrecognized_directive";

const CSP_STATE: &str = "csp_state";
const CSP_POLICY_COUNT: &str = "csp_policy_count";
const CSP_DIRECTIVE_COUNT: &str = "csp_directive_count";
const CSP_DEFAULT_SRC: &str = "csp_declares_default_src";
const CSP_SCRIPT_SRC: &str = "csp_declares_script_src";
const CSP_OBJECT_SRC: &str = "csp_declares_object_src";
const CSP_OBJECT_SRC_NONE: &str = "csp_declares_object_src_none";
const CSP_BASE_URI: &str = "csp_declares_base_uri";
const CSP_BASE_URI_NONE: &str = "csp_declares_base_uri_none";
const CSP_FRAME_ANCESTORS: &str = "csp_declares_frame_ancestors";
const CSP_UNSAFE_INLINE: &str = "csp_declares_unsafe_inline";
const CSP_UNSAFE_EVAL: &str = "csp_declares_unsafe_eval";
const CSP_NONCE: &str = "csp_declares_nonce";
const CSP_HASH: &str = "csp_declares_hash";

const XCTO_STATE: &str = "x_content_type_options_state";
const XCTO_NOSNIFF: &str = "x_content_type_options_nosniff";

const REFERRER_STATE: &str = "referrer_policy_state";
const REFERRER_EFFECTIVE: &str = "referrer_policy_effective";
const REFERRER_DECLARED_COUNT: &str = "referrer_policy_declared_count";

const PERMISSIONS_STATE: &str = "permissions_policy_state";
const PERMISSIONS_DIRECTIVE_COUNT: &str = "permissions_policy_directive_count";
const PERMISSIONS_MEMBER_COUNT: &str = "permissions_policy_member_count";
const PERMISSIONS_EMPTY: &str = "permissions_policy_empty_allowlist_count";
const PERMISSIONS_WILDCARD: &str = "permissions_policy_wildcard_member_count";
const PERMISSIONS_SELF: &str = "permissions_policy_self_member_count";
const PERMISSIONS_SRC: &str = "permissions_policy_src_member_count";
const PERMISSIONS_EXPLICIT: &str = "permissions_policy_explicit_member_count";
const PERMISSIONS_DUPLICATE: &str = "permissions_policy_duplicate_directive";

const COOKIE_STATE: &str = "cookie_state";
const COOKIE_NAME: &str = "cookie_name";
const COOKIE_SECURE: &str = "cookie_secure";
const COOKIE_HTTP_ONLY: &str = "cookie_http_only";
const COOKIE_SAME_SITE: &str = "cookie_same_site";
const COOKIE_DOMAIN_PRESENT: &str = "cookie_domain_attribute_present";
const COOKIE_PATH_PRESENT: &str = "cookie_path_attribute_present";

const AUTHORIZED_ROOT_STABLE_SUBJECT_ID: &str = "authorized-root@1";
const MAX_PASSIVE_ASSESSMENT_CONDITIONS: usize = 19;

const HSTS_MISSING_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.hsts.missing@1",
        "Strict-Transport-Security was not observed",
        "transport-security",
        "The eligible HTTPS response did not include a Strict-Transport-Security policy.",
        1_000_000,
        "web.remediation.hsts@1",
        "Define and validate an HTTPS Strict-Transport-Security policy appropriate for the origin.",
    );
const HSTS_ZERO_MAX_AGE_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.hsts.max-age-zero@1",
        "Strict-Transport-Security disables retention",
        "transport-security",
        "The eligible HTTPS response declared a zero Strict-Transport-Security max-age.",
        1_000_000,
        "web.remediation.hsts@1",
        "Define and validate an HTTPS Strict-Transport-Security policy appropriate for the origin.",
    );
const HSTS_NONCONFORMANT_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.hsts.nonconformant@1",
        "Strict-Transport-Security was nonconformant",
        "transport-security",
        "The eligible HTTPS response contained a nonconformant Strict-Transport-Security policy.",
        1_000_000,
        "web.remediation.hsts@1",
        "Define and validate an HTTPS Strict-Transport-Security policy appropriate for the origin.",
    );

const CSP_MISSING_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.csp.missing@1",
        "Content-Security-Policy was not observed",
        "content-policy",
        "The eligible HTML response did not include a Content-Security-Policy.",
        1_000_000,
        "web.remediation.csp@1",
        "Define and validate a Content-Security-Policy for the application document.",
    );
const CSP_NONCONFORMANT_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.csp.nonconformant@1",
        "Content-Security-Policy was nonconformant",
        "content-policy",
        "The eligible HTML response contained a nonconformant Content-Security-Policy.",
        1_000_000,
        "web.remediation.csp@1",
        "Define and validate a Content-Security-Policy for the application document.",
    );
const CSP_UNSAFE_INLINE_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.csp.unsafe-inline-declared@1",
        "Content-Security-Policy declares unsafe-inline",
        "content-policy",
        "The eligible HTML response declared the unsafe-inline source expression.",
        1_000_000,
        "web.remediation.csp-script@1",
        "Prefer nonce- or hash-based script authorization after application compatibility review.",
    );
const CSP_UNSAFE_EVAL_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.csp.unsafe-eval-declared@1",
        "Content-Security-Policy declares unsafe-eval",
        "content-policy",
        "The eligible HTML response declared the unsafe-eval source expression.",
        1_000_000,
        "web.remediation.csp-script@1",
        "Remove dynamic code evaluation where feasible and validate the resulting script policy.",
    );

const XCTO_MISSING_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.x-content-type-options.missing@1",
        "X-Content-Type-Options was not observed",
        "browser-defense",
        "The eligible document response did not include X-Content-Type-Options.",
        1_000_000,
        "web.remediation.nosniff@1",
        "Set X-Content-Type-Options to nosniff where compatible with served content.",
    );
const XCTO_NONCONFORMANT_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.x-content-type-options.not-nosniff@1",
        "X-Content-Type-Options was not nosniff",
        "browser-defense",
        "The eligible document response contained a nonconformant X-Content-Type-Options value.",
        1_000_000,
        "web.remediation.nosniff@1",
        "Set X-Content-Type-Options to nosniff where compatible with served content.",
    );

const REFERRER_MISSING_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.referrer-policy.missing@1",
        "Referrer-Policy was not observed",
        "browser-defense",
        "The eligible HTML response did not include a Referrer-Policy.",
        1_000_000,
        "web.remediation.referrer-policy@1",
        "Define a Referrer-Policy that matches the application's cross-origin disclosure needs.",
    );
const REFERRER_NONCONFORMANT_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.referrer-policy.nonconformant@1",
        "Referrer-Policy was nonconformant",
        "browser-defense",
        "The eligible HTML response contained a nonconformant Referrer-Policy.",
        1_000_000,
        "web.remediation.referrer-policy@1",
        "Define a Referrer-Policy that matches the application's cross-origin disclosure needs.",
    );
const REFERRER_UNSAFE_URL_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.referrer-policy.unsafe-url@1",
        "Referrer-Policy permits full referrer URLs",
        "browser-defense",
        "The eligible HTML response selected the unsafe-url referrer policy.",
        1_000_000,
        "web.remediation.referrer-policy@1",
        "Select a referrer policy that limits cross-origin URL disclosure.",
    );

const PERMISSIONS_MISSING_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.permissions-policy.missing@1",
        "Permissions-Policy was not observed",
        "browser-defense",
        "The eligible HTML response did not include a Permissions-Policy.",
        1_000_000,
        "web.remediation.permissions-policy@1",
        "Define a Permissions-Policy after reviewing the browser features the application needs.",
    );
const PERMISSIONS_NONCONFORMANT_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.permissions-policy.nonconformant@1",
        "Permissions-Policy was nonconformant",
        "browser-defense",
        "The eligible HTML response contained a nonconformant Permissions-Policy.",
        1_000_000,
        "web.remediation.permissions-policy@1",
        "Define a syntactically valid Permissions-Policy for the browser features the application needs.",
    );

const COOKIE_SECURE_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.cookie.secure-not-set@1",
        "A response cookie omitted Secure",
        "cookie-policy",
        "At least one cookie set by the eligible HTTPS response omitted the Secure attribute.",
        1_000_000,
        "web.remediation.cookie-secure@1",
        "Set Secure on cookies intended only for HTTPS transport.",
    );
const COOKIE_HTTP_ONLY_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.cookie.http-only-not-set@1",
        "A response cookie omitted HttpOnly",
        "cookie-policy",
        "At least one cookie set by the response omitted the HttpOnly attribute.",
        1_000_000,
        "web.remediation.cookie-http-only@1",
        "Set HttpOnly on cookies that do not require script access.",
    );
const COOKIE_SAME_SITE_MISSING_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.cookie.same-site-not-set@1",
        "A response cookie omitted SameSite",
        "cookie-policy",
        "At least one cookie set by the response omitted the SameSite attribute.",
        1_000_000,
        "web.remediation.cookie-same-site@1",
        "Choose an explicit SameSite policy based on the application's cross-site requirements.",
    );
const COOKIE_SAME_SITE_NONE_WITHOUT_SECURE_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.cookie.same-site-none-without-secure@1",
        "SameSite=None was declared without Secure",
        "cookie-policy",
        "At least one cookie set by the response declared SameSite=None without Secure.",
        1_000_000,
        "web.remediation.cookie-none-secure@1",
        "Pair SameSite=None with Secure after confirming that cross-site cookie use is required.",
    );
const COOKIE_NONCONFORMANT_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.passive.cookie.nonconformant@1",
        "Set-Cookie metadata was nonconformant",
        "cookie-policy",
        "The response contained nonconformant Set-Cookie metadata.",
        1_000_000,
        "web.remediation.cookie-syntax@1",
        "Emit syntactically valid Set-Cookie metadata with explicit security attributes.",
    );

/// Exact non-secret base identities from earlier in the same HTTP batch.
pub(crate) struct AssessmentPassiveProjectionContext<'a> {
    pub(crate) subject: &'a EntityId,
    pub(crate) case_id: &'a str,
    pub(crate) executor_id: &'a str,
    pub(crate) reliability: ConfidenceScore,
    pub(crate) parents: Vec<EvidenceId>,
}

/// Maps one already-bounded response projection into a closed evidence batch.
pub(crate) fn project_assessment_passive_response(
    projection: &PassiveResponseProjection,
    context: AssessmentPassiveProjectionContext<'_>,
) -> Result<Vec<Evidence>, HttpEvidenceError> {
    let records = canonical_records(projection)?;
    if records.len() > MAX_PASSIVE_DERIVED_OBSERVATIONS
        || records.len() != usize::from(projection.derived_observation_count())
    {
        return Err(HttpEvidenceError::AssessmentObserverInvariant {
            invariant: "passive-response-evidence-count",
        });
    }
    let derivation = EvidenceDerivation::new(
        context.parents,
        DerivationAlgorithm::new(
            ASSESSMENT_PASSIVE_ALGORITHM,
            ASSESSMENT_PASSIVE_ALGORITHM_VERSION,
        )?,
    )?;
    let source = EvidenceSource::new(context.executor_id, ASSESSMENT_PASSIVE_SOURCE_METHOD)?
        .with_correlation_id(context.case_id)?;
    let mut evidence = Vec::with_capacity(records.len());
    for (name, value) in records {
        if evidence.len() >= MAX_PASSIVE_DERIVED_OBSERVATIONS {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "passive-response-evidence-limit",
            });
        }
        evidence.push(
            Evidence::new(
                context.subject.clone(),
                EvidenceKind::Custom(ASSESSMENT_PASSIVE_CATEGORY.to_owned()),
                predicate(name)?,
                value,
                source.clone(),
                context.reliability,
            )
            .derived_from(derivation.clone()),
        );
    }
    Ok(evidence)
}

fn canonical_records(
    projection: &PassiveResponseProjection,
) -> Result<Vec<(&'static str, EvidenceValue)>, HttpEvidenceError> {
    let mut records = Vec::with_capacity(usize::from(projection.derived_observation_count()));
    push_field_state(
        &mut records,
        HSTS_STATE,
        projection.strict_transport_security(),
    )?;
    if let Some(metadata) = projection.strict_transport_security().metadata() {
        push_hsts(&mut records, metadata);
    }

    push_field_state(
        &mut records,
        CSP_STATE,
        projection.content_security_policy(),
    )?;
    if let Some(metadata) = projection.content_security_policy().metadata() {
        push_csp(&mut records, metadata);
    }

    push_field_state(
        &mut records,
        XCTO_STATE,
        projection.x_content_type_options(),
    )?;
    if let Some(metadata) = projection.x_content_type_options().metadata() {
        records.push((XCTO_NOSNIFF, EvidenceValue::Boolean(metadata.nosniff())));
    }

    push_field_state(&mut records, REFERRER_STATE, projection.referrer_policy())?;
    if let Some(metadata) = projection.referrer_policy().metadata() {
        records.push((
            REFERRER_EFFECTIVE,
            EvidenceValue::Text(
                metadata
                    .effective_policy()
                    .map(referrer_policy_slug)
                    .unwrap_or("unrecognized")
                    .to_owned(),
            ),
        ));
        records.push((
            REFERRER_DECLARED_COUNT,
            EvidenceValue::Unsigned(u64::from(metadata.declared_policy_count())),
        ));
    }

    push_field_state(
        &mut records,
        PERMISSIONS_STATE,
        projection.permissions_policy(),
    )?;
    if let Some(metadata) = projection.permissions_policy().metadata() {
        push_permissions(&mut records, metadata);
    }

    push_field_state(&mut records, COOKIE_STATE, projection.cookies())?;
    if let Some(cookies) = projection.cookies().metadata() {
        for cookie in cookies {
            push_cookie(&mut records, cookie);
        }
    }
    Ok(records)
}

fn push_field_state<T>(
    records: &mut Vec<(&'static str, EvidenceValue)>,
    name: &'static str,
    field: &PassiveFieldProjection<T>,
) -> Result<(), HttpEvidenceError> {
    let mut value = vec![projection_state_slug(field.state()).to_owned()];
    match (field.state(), field.incomplete_reason(), field.metadata()) {
        (PassiveProjectionState::ProjectionIncomplete, Some(reason), None) => {
            value.push(incomplete_reason_slug(reason).to_owned());
        },
        (PassiveProjectionState::Parsed, None, Some(_))
        | (PassiveProjectionState::Nonconformant, None, _)
        | (PassiveProjectionState::Missing, None, None)
        | (PassiveProjectionState::Malformed, None, None) => {},
        _ => {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "passive-response-field-shape",
            });
        },
    }
    records.push((name, EvidenceValue::TextList(value)));
    Ok(())
}

fn push_hsts(
    records: &mut Vec<(&'static str, EvidenceValue)>,
    metadata: &StrictTransportSecurityMetadata,
) {
    records.extend([
        (
            HSTS_MAX_AGE,
            EvidenceValue::Unsigned(metadata.max_age_seconds()),
        ),
        (
            HSTS_INCLUDE_SUBDOMAINS,
            EvidenceValue::Boolean(metadata.includes_subdomains()),
        ),
        (
            HSTS_PRELOAD,
            EvidenceValue::Boolean(metadata.requests_preload()),
        ),
        (
            HSTS_UNRECOGNIZED,
            EvidenceValue::Boolean(metadata.has_unrecognized_directive()),
        ),
    ]);
}

fn push_csp(
    records: &mut Vec<(&'static str, EvidenceValue)>,
    metadata: &ContentSecurityPolicyMetadata,
) {
    records.extend([
        (
            CSP_POLICY_COUNT,
            EvidenceValue::Unsigned(u64::from(metadata.policy_count())),
        ),
        (
            CSP_DIRECTIVE_COUNT,
            EvidenceValue::Unsigned(u64::from(metadata.directive_count())),
        ),
        (
            CSP_DEFAULT_SRC,
            EvidenceValue::Boolean(metadata.has_default_src()),
        ),
        (
            CSP_SCRIPT_SRC,
            EvidenceValue::Boolean(metadata.has_script_src()),
        ),
        (
            CSP_OBJECT_SRC,
            EvidenceValue::Boolean(metadata.has_object_src()),
        ),
        (
            CSP_OBJECT_SRC_NONE,
            EvidenceValue::Boolean(metadata.has_object_src_none()),
        ),
        (
            CSP_BASE_URI,
            EvidenceValue::Boolean(metadata.has_base_uri()),
        ),
        (
            CSP_BASE_URI_NONE,
            EvidenceValue::Boolean(metadata.has_base_uri_none()),
        ),
        (
            CSP_FRAME_ANCESTORS,
            EvidenceValue::Boolean(metadata.has_frame_ancestors()),
        ),
        (
            CSP_UNSAFE_INLINE,
            EvidenceValue::Boolean(metadata.declares_unsafe_inline()),
        ),
        (
            CSP_UNSAFE_EVAL,
            EvidenceValue::Boolean(metadata.declares_unsafe_eval()),
        ),
        (CSP_NONCE, EvidenceValue::Boolean(metadata.declares_nonce())),
        (CSP_HASH, EvidenceValue::Boolean(metadata.declares_hash())),
    ]);
}

fn push_permissions(
    records: &mut Vec<(&'static str, EvidenceValue)>,
    metadata: &PermissionsPolicyMetadata,
) {
    records.extend([
        (
            PERMISSIONS_DIRECTIVE_COUNT,
            EvidenceValue::Unsigned(u64::from(metadata.directive_count())),
        ),
        (
            PERMISSIONS_MEMBER_COUNT,
            EvidenceValue::Unsigned(u64::from(metadata.member_count())),
        ),
        (
            PERMISSIONS_EMPTY,
            EvidenceValue::Unsigned(u64::from(metadata.empty_allowlist_directives())),
        ),
        (
            PERMISSIONS_WILDCARD,
            EvidenceValue::Unsigned(u64::from(metadata.wildcard_members())),
        ),
        (
            PERMISSIONS_SELF,
            EvidenceValue::Unsigned(u64::from(metadata.self_members())),
        ),
        (
            PERMISSIONS_SRC,
            EvidenceValue::Unsigned(u64::from(metadata.src_members())),
        ),
        (
            PERMISSIONS_EXPLICIT,
            EvidenceValue::Unsigned(u64::from(metadata.explicit_members())),
        ),
        (
            PERMISSIONS_DUPLICATE,
            EvidenceValue::Boolean(metadata.duplicate_feature_directives()),
        ),
    ]);
}

fn push_cookie(records: &mut Vec<(&'static str, EvidenceValue)>, cookie: &PassiveCookieMetadata) {
    records.extend([
        (COOKIE_NAME, EvidenceValue::Text(cookie.name().to_owned())),
        (COOKIE_SECURE, EvidenceValue::Boolean(cookie.secure())),
        (COOKIE_HTTP_ONLY, EvidenceValue::Boolean(cookie.http_only())),
        (
            COOKIE_SAME_SITE,
            EvidenceValue::Text(cookie_same_site_slug(cookie.same_site()).to_owned()),
        ),
        (
            COOKIE_DOMAIN_PRESENT,
            EvidenceValue::Boolean(cookie.domain_attribute_present()),
        ),
        (
            COOKIE_PATH_PRESENT,
            EvidenceValue::Boolean(cookie.path_attribute_present()),
        ),
    ]);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedPassiveField<T> {
    state: PassiveProjectionState,
    incomplete_reason: Option<PassiveProjectionIncompleteReason>,
    metadata: Option<T>,
}

impl<T> CommittedPassiveField<T> {
    #[cfg(test)]
    pub(crate) const fn state(&self) -> PassiveProjectionState {
        self.state
    }

    #[cfg(test)]
    pub(crate) const fn incomplete_reason(&self) -> Option<PassiveProjectionIncompleteReason> {
        self.incomplete_reason
    }

    #[cfg(test)]
    pub(crate) const fn metadata(&self) -> Option<&T> {
        self.metadata.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommittedHstsMetadata {
    pub(crate) max_age_seconds: u64,
    pub(crate) includes_subdomains: bool,
    pub(crate) requests_preload: bool,
    pub(crate) has_unrecognized_directive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommittedCspMetadata {
    pub(crate) policy_count: u8,
    pub(crate) directive_count: u8,
    pub(crate) has_default_src: bool,
    pub(crate) has_script_src: bool,
    pub(crate) has_object_src: bool,
    pub(crate) has_object_src_none: bool,
    pub(crate) has_base_uri: bool,
    pub(crate) has_base_uri_none: bool,
    pub(crate) has_frame_ancestors: bool,
    pub(crate) declares_unsafe_inline: bool,
    pub(crate) declares_unsafe_eval: bool,
    pub(crate) declares_nonce: bool,
    pub(crate) declares_hash: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommittedXctoMetadata {
    pub(crate) nosniff: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommittedReferrerPolicyMetadata {
    pub(crate) effective_policy: Option<ReferrerPolicyValue>,
    pub(crate) declared_policy_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommittedPermissionsPolicyMetadata {
    pub(crate) directive_count: u8,
    pub(crate) member_count: u8,
    pub(crate) empty_allowlist_directives: u8,
    pub(crate) wildcard_members: u8,
    pub(crate) self_members: u8,
    pub(crate) src_members: u8,
    pub(crate) explicit_members: u8,
    pub(crate) duplicate_feature_directives: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CommittedCookieMetadata {
    pub(crate) name: String,
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) same_site: PassiveCookieSameSite,
    pub(crate) domain_attribute_present: bool,
    pub(crate) path_attribute_present: bool,
}

impl fmt::Debug for CommittedCookieMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedCookieMetadata")
            .field("name", &"<redacted>")
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("domain_attribute_present", &self.domain_attribute_present)
            .field("path_attribute_present", &self.path_attribute_present)
            .finish()
    }
}

/// Closed response media classification. The raw media value is not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommittedPassiveMediaClass {
    Missing,
    Html,
    JsonCompatible,
    Other,
}

#[derive(Clone, PartialEq, Eq)]
struct CommittedPassiveBaseEvidence {
    method: EvidenceId,
    request_url: EvidenceId,
    status: EvidenceId,
    final_url: EvidenceId,
    media_type: Option<EvidenceId>,
}

impl CommittedPassiveBaseEvidence {
    fn append_to(&self, evidence: &mut Vec<EvidenceId>) {
        evidence.extend([
            self.method.clone(),
            self.request_url.clone(),
            self.status.clone(),
            self.final_url.clone(),
        ]);
        evidence.extend(self.media_type.iter().cloned());
    }
}

impl fmt::Debug for CommittedPassiveBaseEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedPassiveBaseEvidence")
            .field("method", &"<opaque-evidence-id>")
            .field("request_url", &"<opaque-evidence-id>")
            .field("status", &"<opaque-evidence-id>")
            .field("final_url", &"<opaque-evidence-id>")
            .field(
                "media_type",
                &self.media_type.as_ref().map(|_| "<opaque-evidence-id>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PassiveEvidenceProperty(&'static str);

/// One typed passive response reconstructed exclusively from committed
/// evidence. It contains no raw header values or secret cookie values.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentPassiveObservation {
    subject: EntityId,
    case_id: String,
    stage: DecisionExecutionStage,
    method: WebAssessmentMethod,
    status: u16,
    media_class: CommittedPassiveMediaClass,
    hsts: CommittedPassiveField<CommittedHstsMetadata>,
    csp: CommittedPassiveField<CommittedCspMetadata>,
    xcto: CommittedPassiveField<CommittedXctoMetadata>,
    referrer_policy: CommittedPassiveField<CommittedReferrerPolicyMetadata>,
    permissions_policy: CommittedPassiveField<CommittedPermissionsPolicyMetadata>,
    cookies: CommittedPassiveField<Vec<CommittedCookieMetadata>>,
    base_evidence: CommittedPassiveBaseEvidence,
    parent_evidence_ids: Vec<EvidenceId>,
    evidence_ids: Vec<EvidenceId>,
    property_evidence: BTreeMap<PassiveEvidenceProperty, Vec<EvidenceId>>,
}

impl fmt::Debug for CommittedAssessmentPassiveObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAssessmentPassiveObservation")
            .field("subject", &"<redacted>")
            .field("case", &"<redacted>")
            .field("stage", &self.stage)
            .field("method", &self.method)
            .field("status", &self.status)
            .field("media_class", &self.media_class)
            .field("hsts_state", &self.hsts.state)
            .field("csp_state", &self.csp.state)
            .field("xcto_state", &self.xcto.state)
            .field("referrer_policy_state", &self.referrer_policy.state)
            .field("permissions_policy_state", &self.permissions_policy.state)
            .field("cookie_state", &self.cookies.state)
            .field(
                "cookie_count",
                &self.cookies.metadata.as_ref().map_or(0, Vec::len),
            )
            .field("parent_evidence_count", &self.parent_evidence_ids.len())
            .field("evidence_count", &self.evidence_ids.len())
            .field("property_count", &self.property_evidence.len())
            .finish()
    }
}

impl CommittedAssessmentPassiveObservation {
    pub(crate) fn subject(&self) -> &EntityId {
        &self.subject
    }

    #[cfg(test)]
    pub(crate) fn case_id(&self) -> &str {
        &self.case_id
    }

    #[cfg(test)]
    pub(crate) const fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }

    #[cfg(test)]
    pub(crate) const fn method(&self) -> WebAssessmentMethod {
        self.method
    }

    #[cfg(test)]
    pub(crate) const fn status(&self) -> u16 {
        self.status
    }

    #[cfg(test)]
    pub(crate) const fn media_class(&self) -> CommittedPassiveMediaClass {
        self.media_class
    }

    #[cfg(test)]
    pub(crate) fn hsts(&self) -> &CommittedPassiveField<CommittedHstsMetadata> {
        &self.hsts
    }

    #[cfg(test)]
    pub(crate) fn csp(&self) -> &CommittedPassiveField<CommittedCspMetadata> {
        &self.csp
    }

    #[cfg(test)]
    pub(crate) fn xcto(&self) -> &CommittedPassiveField<CommittedXctoMetadata> {
        &self.xcto
    }

    #[cfg(test)]
    pub(crate) fn referrer_policy(
        &self,
    ) -> &CommittedPassiveField<CommittedReferrerPolicyMetadata> {
        &self.referrer_policy
    }

    #[cfg(test)]
    pub(crate) fn permissions_policy(
        &self,
    ) -> &CommittedPassiveField<CommittedPermissionsPolicyMetadata> {
        &self.permissions_policy
    }

    #[cfg(test)]
    pub(crate) fn cookies(&self) -> &CommittedPassiveField<Vec<CommittedCookieMetadata>> {
        &self.cookies
    }

    #[cfg(test)]
    pub(crate) fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }

    #[cfg(test)]
    pub(crate) fn parent_evidence_ids(&self) -> &[EvidenceId] {
        &self.parent_evidence_ids
    }

    #[cfg(test)]
    pub(crate) fn evidence_ids_for_property(&self, property: &str) -> Option<&[EvidenceId]> {
        self.evidence_ids_for_property_internal(property)
    }

    fn evidence_ids_for_property_internal(&self, property: &str) -> Option<&[EvidenceId]> {
        let property = canonical_property(property)?;
        self.property_evidence.get(&property).map(Vec::as_slice)
    }

    pub(crate) fn projection_incomplete(&self) -> bool {
        [
            self.hsts.state,
            self.csp.state,
            self.xcto.state,
            self.referrer_policy.state,
            self.permissions_policy.state,
            self.cookies.state,
        ]
        .contains(&PassiveProjectionState::ProjectionIncomplete)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PassiveReceiptKey {
    subject: EntityId,
    case_id: String,
    stage: DecisionExecutionStage,
}

/// Idempotent assessment-owned replay ledger for passive response metadata.
#[derive(Default, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentPassiveLedger {
    observations: Vec<CommittedAssessmentPassiveObservation>,
    receipt_evidence: BTreeMap<PassiveReceiptKey, Vec<EvidenceId>>,
}

impl fmt::Debug for CommittedAssessmentPassiveLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAssessmentPassiveLedger")
            .field("observation_count", &self.observations.len())
            .finish()
    }
}

impl CommittedAssessmentPassiveLedger {
    pub(crate) fn observations(&self) -> &[CommittedAssessmentPassiveObservation] {
        &self.observations
    }

    #[cfg(test)]
    pub(crate) fn receipt_count(&self) -> usize {
        self.receipt_evidence.len()
    }

    /// Replays one already-committed receipt atomically.
    pub(crate) fn ingest_receipt(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        knowledge: &KnowledgeBase,
        expected_subject: &WebAssessmentSubject,
    ) -> Result<Option<&CommittedAssessmentPassiveObservation>, ()> {
        validate_receipt_storage(receipt, knowledge, expected_subject)?;
        let parsed = parse_receipt(receipt, expected_subject)?;
        let key = PassiveReceiptKey {
            subject: receipt.case().subject().clone(),
            case_id: receipt.case().id().to_owned(),
            stage: receipt.stage(),
        };
        if let Some(existing) = self.receipt_evidence.get(&key) {
            return if existing == &parsed.evidence_ids {
                Ok(None)
            } else {
                Err(())
            };
        }
        if self.observations.len() >= HARD_MAX_WEB_ASSESSMENT_SUBJECTS {
            return Err(());
        }
        // Parsing and authoritative storage validation completed above. Only
        // now mutate the two bounded ledger collections; no full-ledger clone
        // is needed for atomicity.
        self.receipt_evidence
            .insert(key, parsed.evidence_ids.clone());
        self.observations.push(parsed);
        Ok(self.observations.last())
    }
}

/// Typed accounting for passive conditions that could not be assigned a
/// host-approved stable subject identity. Raw discovered URLs are never used
/// as a fallback product identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PassiveAssessmentProjectionIncompleteness {
    root_subject_identity_unavailable: bool,
    non_root_observations: u16,
    non_root_conditions: u16,
}

impl PassiveAssessmentProjectionIncompleteness {
    pub(crate) const fn non_root_observations(self) -> u16 {
        self.non_root_observations
    }

    pub(crate) const fn non_root_conditions(self) -> u16 {
        self.non_root_conditions
    }

    pub(crate) const fn is_incomplete(self) -> bool {
        self.root_subject_identity_unavailable || self.non_root_conditions != 0
    }
}

/// Context-owned passive item set plus explicit identity-boundary accounting.
pub(crate) struct PassiveAssessmentItemProjection {
    items: AssessmentItemSet,
    incompleteness: PassiveAssessmentProjectionIncompleteness,
}

impl PassiveAssessmentItemProjection {
    pub(crate) fn into_parts(
        self,
    ) -> (AssessmentItemSet, PassiveAssessmentProjectionIncompleteness) {
        (self.items, self.incompleteness)
    }
}

impl fmt::Debug for PassiveAssessmentItemProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassiveAssessmentItemProjection")
            .field("items", &self.items)
            .field("incompleteness", &self.incompleteness)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PassiveAssessmentItemProjectionError {
    #[error("authorized assessment root is invalid")]
    InvalidAuthorizedRoot,
    #[error("committed passive observation violates the projection contract")]
    CommittedObservationInvariant,
    #[error("passive assessment condition count exceeds its compiled maximum")]
    ConditionLimit,
    #[error(transparent)]
    Item(#[from] AssessmentItemProjectionError),
    #[error(transparent)]
    Review(#[from] AssessmentReviewItemProjectionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassiveAssessmentCondition {
    HstsMissing,
    HstsMaxAgeZero,
    HstsNonconformant,
    CspMissing,
    CspNonconformant,
    CspUnsafeInlineDeclared,
    CspUnsafeEvalDeclared,
    XctoMissing,
    XctoNonconformant,
    ReferrerMissing,
    ReferrerNonconformant,
    ReferrerUnsafeUrl,
    PermissionsMissing,
    PermissionsNonconformant,
    CookieSecureNotSet,
    CookieHttpOnlyNotSet,
    CookieSameSiteNotSet,
    CookieSameSiteNoneWithoutSecure,
    CookieNonconformant,
}

impl PassiveAssessmentCondition {
    const fn capability(self) -> &'static AssessmentCapabilityDescriptor {
        match self {
            Self::HstsMissing => &HSTS_MISSING_CAPABILITY,
            Self::HstsMaxAgeZero => &HSTS_ZERO_MAX_AGE_CAPABILITY,
            Self::HstsNonconformant => &HSTS_NONCONFORMANT_CAPABILITY,
            Self::CspMissing => &CSP_MISSING_CAPABILITY,
            Self::CspNonconformant => &CSP_NONCONFORMANT_CAPABILITY,
            Self::CspUnsafeInlineDeclared => &CSP_UNSAFE_INLINE_CAPABILITY,
            Self::CspUnsafeEvalDeclared => &CSP_UNSAFE_EVAL_CAPABILITY,
            Self::XctoMissing => &XCTO_MISSING_CAPABILITY,
            Self::XctoNonconformant => &XCTO_NONCONFORMANT_CAPABILITY,
            Self::ReferrerMissing => &REFERRER_MISSING_CAPABILITY,
            Self::ReferrerNonconformant => &REFERRER_NONCONFORMANT_CAPABILITY,
            Self::ReferrerUnsafeUrl => &REFERRER_UNSAFE_URL_CAPABILITY,
            Self::PermissionsMissing => &PERMISSIONS_MISSING_CAPABILITY,
            Self::PermissionsNonconformant => &PERMISSIONS_NONCONFORMANT_CAPABILITY,
            Self::CookieSecureNotSet => &COOKIE_SECURE_CAPABILITY,
            Self::CookieHttpOnlyNotSet => &COOKIE_HTTP_ONLY_CAPABILITY,
            Self::CookieSameSiteNotSet => &COOKIE_SAME_SITE_MISSING_CAPABILITY,
            Self::CookieSameSiteNoneWithoutSecure => {
                &COOKIE_SAME_SITE_NONE_WITHOUT_SECURE_CAPABILITY
            },
            Self::CookieNonconformant => &COOKIE_NONCONFORMANT_CAPABILITY,
        }
    }
}

struct PlannedPassiveAssessmentItem {
    condition: PassiveAssessmentCondition,
    evidence_ids: Vec<EvidenceId>,
}

pub(crate) struct AssessmentReviewProjectionSources<'a> {
    pub(crate) native: &'a [&'a CommittedAssessmentReviewLedger],
    pub(crate) api_visibility: Option<&'a CommittedAssessmentApiVisibility>,
    #[cfg(feature = "graphql-review")]
    pub(crate) graphql: Option<&'a CommittedGraphqlReview>,
    #[cfg(feature = "authorization-review")]
    pub(crate) authorization: Option<&'a CommittedResourceAuthorizationReview>,
    #[cfg(feature = "openapi-review")]
    pub(crate) openapi: Option<&'a CommittedOpenApiReview>,
    #[cfg(feature = "rest-review")]
    pub(crate) rest: Option<&'a CommittedRestReview>,
    #[cfg(feature = "ssrf-oast-review")]
    pub(crate) ssrf_oast: Option<&'a CommittedSsrfOastReview>,
}

/// Test adapter that projects only the explicitly authorized root.
#[cfg(test)]
pub(crate) fn project_passive_assessment_items(
    ledger: &CommittedAssessmentPassiveLedger,
    knowledge: &KnowledgeBase,
    authorized_root: &WebAssessmentSubject,
) -> Result<PassiveAssessmentItemProjection, PassiveAssessmentItemProjectionError> {
    project_assessment_items(
        ledger,
        AssessmentReviewProjectionSources {
            native: &[],
            api_visibility: None,
            #[cfg(feature = "graphql-review")]
            graphql: None,
            #[cfg(feature = "authorization-review")]
            authorization: None,
            #[cfg(feature = "openapi-review")]
            openapi: None,
            #[cfg(feature = "rest-review")]
            rest: None,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast: None,
        },
        knowledge,
        authorized_root,
        std::slice::from_ref(authorized_root),
    )
}

/// Projects passive observations and optional matched review candidates into
/// one context-owned item/reference space.
pub(crate) fn project_assessment_items(
    ledger: &CommittedAssessmentPassiveLedger,
    reviews: AssessmentReviewProjectionSources<'_>,
    knowledge: &KnowledgeBase,
    authorized_root: &WebAssessmentSubject,
    assessment_subjects: &[WebAssessmentSubject],
) -> Result<PassiveAssessmentItemProjection, PassiveAssessmentItemProjectionError> {
    if authorized_root.origin() != WebAssessmentSubjectOrigin::AuthorizedRoot
        || authorized_root.depth() != 0
        || !matches!(authorized_root.url().scheme(), "http" | "https")
        || !authorized_root.url().username().is_empty()
        || authorized_root.url().password().is_some()
        || authorized_root.url().query().is_some()
        || authorized_root.url().fragment().is_some()
    {
        return Err(PassiveAssessmentItemProjectionError::InvalidAuthorizedRoot);
    }
    let exact_origin = authorized_root.url().origin().ascii_serialization();
    let scope = StableAssessmentScopeId::from_exact_origin(&exact_origin)?;
    // `authorized-root@1` remains reserved for the exact origin root. Eligible
    // discovered resources receive a separate opaque, versioned identity that
    // is derived only from their already-canonical structural subject.
    let root_subject = if authorized_root.url().path() == "/" {
        Some(
            EntityId::new(format!("endpoint:{}", authorized_root.url()))
                .map_err(|_| PassiveAssessmentItemProjectionError::InvalidAuthorizedRoot)?,
        )
    } else {
        None
    };
    let mut stable_subjects = Vec::new();
    if let Some(root_subject) = &root_subject {
        stable_subjects.push((
            root_subject.clone(),
            StableAssessmentSubjectId::new(AUTHORIZED_ROOT_STABLE_SUBJECT_ID)?,
            authorized_root.query_parameter_names().to_vec(),
        ));
    }
    let mut discovered = assessment_subjects
        .iter()
        .filter(|subject| subject.origin() == WebAssessmentSubjectOrigin::Discovered)
        .collect::<Vec<_>>();
    discovered.sort_unstable_by(|left, right| {
        left.depth()
            .cmp(&right.depth())
            .then_with(|| left.url().as_str().cmp(right.url().as_str()))
            .then_with(|| left.method().cmp(&right.method()))
    });
    for subject in discovered {
        if subject.depth() == 0
            || subject.url().origin() != authorized_root.url().origin()
            || subject.url().query().is_some()
            || subject.url().fragment().is_some()
        {
            continue;
        }
        let Ok(stable_id) = StableAssessmentSubjectId::from_discovered_resource(
            &scope,
            subject.method(),
            subject.url(),
            subject.query_parameter_names(),
        ) else {
            continue;
        };
        let Ok(runtime_subject) = EntityId::new(format!("endpoint:{}", subject.url())) else {
            continue;
        };
        stable_subjects.push((
            runtime_subject,
            stable_id,
            subject.query_parameter_names().to_vec(),
        ));
    }
    project_assessment_items_for_subjects(
        ledger,
        reviews,
        knowledge,
        root_subject,
        scope,
        stable_subjects,
        authorized_root.url().scheme() == "https",
    )
}

#[cfg(test)]
fn project_passive_assessment_items_for_root(
    ledger: &CommittedAssessmentPassiveLedger,
    knowledge: &KnowledgeBase,
    root_subject: Option<EntityId>,
    exact_origin: &str,
    root_query_parameter_names: &[String],
    https: bool,
) -> Result<PassiveAssessmentItemProjection, PassiveAssessmentItemProjectionError> {
    let scope = StableAssessmentScopeId::from_exact_origin(exact_origin)?;
    let stable_subjects = match root_subject.as_ref() {
        Some(subject) => vec![(
            subject.clone(),
            StableAssessmentSubjectId::new(AUTHORIZED_ROOT_STABLE_SUBJECT_ID)?,
            root_query_parameter_names.to_vec(),
        )],
        None => Vec::new(),
    };
    project_assessment_items_for_subjects(
        ledger,
        AssessmentReviewProjectionSources {
            native: &[],
            api_visibility: None,
            #[cfg(feature = "graphql-review")]
            graphql: None,
            #[cfg(feature = "authorization-review")]
            authorization: None,
            #[cfg(feature = "openapi-review")]
            openapi: None,
            #[cfg(feature = "rest-review")]
            rest: None,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast: None,
        },
        knowledge,
        root_subject,
        scope,
        stable_subjects,
        https,
    )
}

fn project_assessment_items_for_subjects(
    ledger: &CommittedAssessmentPassiveLedger,
    reviews: AssessmentReviewProjectionSources<'_>,
    knowledge: &KnowledgeBase,
    root_subject: Option<EntityId>,
    scope: StableAssessmentScopeId,
    stable_subjects: Vec<(EntityId, StableAssessmentSubjectId, Vec<String>)>,
    https: bool,
) -> Result<PassiveAssessmentItemProjection, PassiveAssessmentItemProjectionError> {
    #[cfg(feature = "graphql-review")]
    let graphql_scope = scope.clone();
    let mut context = AssessmentProjectionContext::new(knowledge, scope);
    let stable_subject_ids = stable_subjects
        .iter()
        .map(|(subject, _, _)| subject.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (subject, stable_id, query_parameter_names) in stable_subjects {
        context.register_subject(subject, stable_id, query_parameter_names)?;
    }
    #[cfg(feature = "graphql-review")]
    if let Some(graphql) = reviews.graphql {
        register_graphql_subject(&mut context, &graphql_scope, graphql)?;
    }
    let mut planned_items = Vec::new();
    let mut incompleteness = PassiveAssessmentProjectionIncompleteness {
        root_subject_identity_unavailable: root_subject.is_none(),
        ..PassiveAssessmentProjectionIncompleteness::default()
    };
    for observation in ledger.observations() {
        let planned = passive_conditions(observation, https)?;
        if !stable_subject_ids.contains(&observation.subject) {
            if !planned.is_empty() {
                incompleteness.non_root_observations = incompleteness
                    .non_root_observations
                    .checked_add(1)
                    .ok_or(PassiveAssessmentItemProjectionError::ConditionLimit)?;
                incompleteness.non_root_conditions = incompleteness
                    .non_root_conditions
                    .checked_add(
                        u16::try_from(planned.len())
                            .map_err(|_| PassiveAssessmentItemProjectionError::ConditionLimit)?,
                    )
                    .ok_or(PassiveAssessmentItemProjectionError::ConditionLimit)?;
            }
            continue;
        }
        planned_items.extend(
            planned
                .into_iter()
                .map(|item| (observation.subject.clone(), item)),
        );
        if planned_items.len() > MAX_ASSESSMENT_ITEM_SET_ITEMS {
            return Err(PassiveAssessmentItemProjectionError::ConditionLimit);
        }
    }

    let evidence_ids = planned_items
        .iter()
        .flat_map(|(_, item)| item.evidence_ids.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    for evidence_id in evidence_ids {
        context.register_evidence(knowledge, &evidence_id)?;
    }
    let target = AssessmentItemTarget::subject();
    for (subject, item) in planned_items {
        context.project_observation(
            item.condition.capability(),
            knowledge,
            &subject,
            &target,
            &item.evidence_ids,
        )?;
    }
    project_assessment_review_ledgers(&mut context, reviews.native, knowledge)?;
    if let (Some(api_visibility), Some(root_subject)) =
        (reviews.api_visibility, root_subject.as_ref())
    {
        project_api_visibility_item(&mut context, knowledge, root_subject, api_visibility)?;
    }
    #[cfg(feature = "graphql-review")]
    if let Some(graphql) = reviews.graphql {
        project_graphql_items(&mut context, knowledge, graphql)?;
    }
    #[cfg(feature = "authorization-review")]
    if let Some(authorization) = reviews.authorization {
        project_resource_authorization_item(&mut context, knowledge, authorization)?;
    }
    #[cfg(feature = "openapi-review")]
    if let Some(openapi) = reviews.openapi {
        project_openapi_item(&mut context, knowledge, openapi)?;
    }
    #[cfg(feature = "rest-review")]
    if let Some(rest) = reviews.rest {
        project_rest_item(&mut context, knowledge, rest)?;
    }
    #[cfg(feature = "ssrf-oast-review")]
    if let Some(ssrf_oast) = reviews.ssrf_oast {
        project_ssrf_oast_item(&mut context, knowledge, ssrf_oast)?;
    }
    Ok(PassiveAssessmentItemProjection {
        items: context.finish(),
        incompleteness,
    })
}

fn passive_conditions(
    observation: &CommittedAssessmentPassiveObservation,
    https: bool,
) -> Result<Vec<PlannedPassiveAssessmentItem>, PassiveAssessmentItemProjectionError> {
    let mut conditions = Vec::with_capacity(MAX_PASSIVE_ASSESSMENT_CONDITIONS);
    let hsts_eligible = https
        && matches!(
            observation.method,
            WebAssessmentMethod::Get | WebAssessmentMethod::Head
        )
        && (200..=399).contains(&observation.status)
        && observation.status != 304;
    if hsts_eligible {
        match observation.hsts.state {
            PassiveProjectionState::Missing => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::HstsMissing,
                &[HSTS_STATE],
                &[],
            )?,
            PassiveProjectionState::Parsed => {
                if observation
                    .hsts
                    .metadata
                    .is_some_and(|metadata| metadata.max_age_seconds == 0)
                {
                    push_condition(
                        &mut conditions,
                        observation,
                        PassiveAssessmentCondition::HstsMaxAgeZero,
                        &[HSTS_STATE, HSTS_MAX_AGE],
                        &[],
                    )?;
                }
            },
            PassiveProjectionState::Nonconformant | PassiveProjectionState::Malformed => {
                push_condition(
                    &mut conditions,
                    observation,
                    PassiveAssessmentCondition::HstsNonconformant,
                    &[HSTS_STATE],
                    &[],
                )?
            },
            PassiveProjectionState::ProjectionIncomplete => {},
        }
    }

    let html_eligible = observation.method == WebAssessmentMethod::Get
        && observation.status == 200
        && observation.media_class == CommittedPassiveMediaClass::Html;
    if html_eligible {
        match observation.csp.state {
            PassiveProjectionState::Missing => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::CspMissing,
                &[CSP_STATE],
                &[],
            )?,
            PassiveProjectionState::Parsed => {
                if observation
                    .csp
                    .metadata
                    .is_some_and(|metadata| metadata.declares_unsafe_inline)
                {
                    push_condition(
                        &mut conditions,
                        observation,
                        PassiveAssessmentCondition::CspUnsafeInlineDeclared,
                        &[CSP_STATE, CSP_UNSAFE_INLINE],
                        &[],
                    )?;
                }
                if observation
                    .csp
                    .metadata
                    .is_some_and(|metadata| metadata.declares_unsafe_eval)
                {
                    push_condition(
                        &mut conditions,
                        observation,
                        PassiveAssessmentCondition::CspUnsafeEvalDeclared,
                        &[CSP_STATE, CSP_UNSAFE_EVAL],
                        &[],
                    )?;
                }
            },
            PassiveProjectionState::Nonconformant | PassiveProjectionState::Malformed => {
                push_condition(
                    &mut conditions,
                    observation,
                    PassiveAssessmentCondition::CspNonconformant,
                    &[CSP_STATE],
                    &[],
                )?
            },
            PassiveProjectionState::ProjectionIncomplete => {},
        }

        match observation.xcto.state {
            PassiveProjectionState::Missing => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::XctoMissing,
                &[XCTO_STATE],
                &[],
            )?,
            PassiveProjectionState::Nonconformant => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::XctoNonconformant,
                &[XCTO_STATE, XCTO_NOSNIFF],
                &[],
            )?,
            PassiveProjectionState::Malformed => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::XctoNonconformant,
                &[XCTO_STATE],
                &[],
            )?,
            PassiveProjectionState::Parsed | PassiveProjectionState::ProjectionIncomplete => {},
        }

        match observation.referrer_policy.state {
            PassiveProjectionState::Missing => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::ReferrerMissing,
                &[REFERRER_STATE],
                &[],
            )?,
            PassiveProjectionState::Parsed => {
                if observation
                    .referrer_policy
                    .metadata
                    .is_some_and(|metadata| {
                        metadata.effective_policy == Some(ReferrerPolicyValue::UnsafeUrl)
                    })
                {
                    push_condition(
                        &mut conditions,
                        observation,
                        PassiveAssessmentCondition::ReferrerUnsafeUrl,
                        &[REFERRER_STATE, REFERRER_EFFECTIVE],
                        &[],
                    )?;
                }
            },
            PassiveProjectionState::Nonconformant | PassiveProjectionState::Malformed => {
                push_condition(
                    &mut conditions,
                    observation,
                    PassiveAssessmentCondition::ReferrerNonconformant,
                    &[REFERRER_STATE],
                    &[],
                )?
            },
            PassiveProjectionState::ProjectionIncomplete => {},
        }

        match observation.permissions_policy.state {
            PassiveProjectionState::Missing => push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::PermissionsMissing,
                &[PERMISSIONS_STATE],
                &[],
            )?,
            PassiveProjectionState::Nonconformant | PassiveProjectionState::Malformed => {
                push_condition(
                    &mut conditions,
                    observation,
                    PassiveAssessmentCondition::PermissionsNonconformant,
                    &[PERMISSIONS_STATE],
                    &[],
                )?
            },
            PassiveProjectionState::Parsed | PassiveProjectionState::ProjectionIncomplete => {},
        }
    }

    if matches!(
        observation.cookies.state,
        PassiveProjectionState::Parsed | PassiveProjectionState::Nonconformant
    ) {
        let cookies = observation
            .cookies
            .metadata
            .as_deref()
            .filter(|cookies| !cookies.is_empty())
            .ok_or(PassiveAssessmentItemProjectionError::CommittedObservationInvariant)?;
        let insecure = cookies
            .iter()
            .enumerate()
            .filter_map(|(index, cookie)| (!cookie.secure).then_some(index))
            .collect::<Vec<_>>();
        if https && !insecure.is_empty() {
            push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::CookieSecureNotSet,
                &[COOKIE_STATE],
                &[(COOKIE_SECURE, &insecure)],
            )?;
        }
        let script_readable = cookies
            .iter()
            .enumerate()
            .filter_map(|(index, cookie)| (!cookie.http_only).then_some(index))
            .collect::<Vec<_>>();
        if !script_readable.is_empty() {
            push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::CookieHttpOnlyNotSet,
                &[COOKIE_STATE],
                &[(COOKIE_HTTP_ONLY, &script_readable)],
            )?;
        }
        let unspecified_same_site = cookies
            .iter()
            .enumerate()
            .filter_map(|(index, cookie)| {
                (cookie.same_site == PassiveCookieSameSite::Missing).then_some(index)
            })
            .collect::<Vec<_>>();
        if !unspecified_same_site.is_empty() {
            push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::CookieSameSiteNotSet,
                &[COOKIE_STATE],
                &[(COOKIE_SAME_SITE, &unspecified_same_site)],
            )?;
        }
        let none_without_secure = cookies
            .iter()
            .enumerate()
            .filter_map(|(index, cookie)| {
                (cookie.same_site == PassiveCookieSameSite::None && !cookie.secure).then_some(index)
            })
            .collect::<Vec<_>>();
        if !none_without_secure.is_empty() {
            push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::CookieSameSiteNoneWithoutSecure,
                &[COOKIE_STATE],
                &[
                    (COOKIE_SECURE, &none_without_secure),
                    (COOKIE_SAME_SITE, &none_without_secure),
                ],
            )?;
        }
        if observation.cookies.state == PassiveProjectionState::Nonconformant {
            push_condition(
                &mut conditions,
                observation,
                PassiveAssessmentCondition::CookieNonconformant,
                &[COOKIE_STATE],
                &[],
            )?;
        }
    }
    if observation.cookies.state == PassiveProjectionState::Malformed {
        push_condition(
            &mut conditions,
            observation,
            PassiveAssessmentCondition::CookieNonconformant,
            &[COOKIE_STATE],
            &[],
        )?;
    }
    Ok(conditions)
}

fn push_condition(
    conditions: &mut Vec<PlannedPassiveAssessmentItem>,
    observation: &CommittedAssessmentPassiveObservation,
    condition: PassiveAssessmentCondition,
    singleton_properties: &[&str],
    indexed_properties: &[(&str, &[usize])],
) -> Result<(), PassiveAssessmentItemProjectionError> {
    if conditions.len() >= MAX_PASSIVE_ASSESSMENT_CONDITIONS {
        return Err(PassiveAssessmentItemProjectionError::ConditionLimit);
    }
    let mut evidence_ids = Vec::new();
    observation.base_evidence.append_to(&mut evidence_ids);
    for property in singleton_properties {
        let values = observation
            .evidence_ids_for_property_internal(property)
            .ok_or(PassiveAssessmentItemProjectionError::CommittedObservationInvariant)?;
        if values.len() != 1 {
            return Err(PassiveAssessmentItemProjectionError::CommittedObservationInvariant);
        }
        evidence_ids.push(values[0].clone());
    }
    for (property, indices) in indexed_properties {
        let values = observation
            .evidence_ids_for_property_internal(property)
            .ok_or(PassiveAssessmentItemProjectionError::CommittedObservationInvariant)?;
        for index in *indices {
            evidence_ids.push(
                values
                    .get(*index)
                    .ok_or(PassiveAssessmentItemProjectionError::CommittedObservationInvariant)?
                    .clone(),
            );
        }
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    conditions.push(PlannedPassiveAssessmentItem {
        condition,
        evidence_ids,
    });
    Ok(())
}

fn validate_receipt_storage(
    receipt: &DecisionEvidenceReceipt,
    knowledge: &KnowledgeBase,
    expected_subject: &WebAssessmentSubject,
) -> Result<(), ()> {
    if receipt.executor_id() != HTTP_EVIDENCE_EXECUTOR_ID
        || receipt.stage() != DecisionExecutionStage::Passive
        || receipt.case().id() != BOOTSTRAP_CASE_ID
        || receipt.case().action_id() != BOOTSTRAP_ACTION_ID
        || receipt.case().hypothesis_id() != BOOTSTRAP_HYPOTHESIS_ID
        || receipt.case().payload_strategy().is_some()
        || !receipt.case().applies_hypothesis_transition()
        || receipt.case().subject().as_str() != format!("endpoint:{}", expected_subject.url())
        || receipt.evidence().len() != receipt.writes().len()
    {
        return Err(());
    }
    for (evidence, write) in receipt.write_set() {
        if !matches!(write, KnowledgeWrite::Inserted | KnowledgeWrite::Unchanged)
            || evidence.subject() != receipt.case().subject()
            || evidence.source().correlation_id() != Some(receipt.case().id())
            || knowledge.evidence(evidence.id()).as_ref() != Some(evidence)
        {
            return Err(());
        }
    }
    Ok(())
}

fn parse_receipt(
    receipt: &DecisionEvidenceReceipt,
    expected_subject: &WebAssessmentSubject,
) -> Result<CommittedAssessmentPassiveObservation, ()> {
    for evidence in receipt.evidence() {
        let namespace = evidence.predicate().namespace();
        if namespace.starts_with("web.")
            && !matches!(
                namespace,
                ASSESSMENT_PASSIVE_NAMESPACE | "web.discovery" | "web.defense"
            )
        {
            return Err(());
        }
    }
    let first = receipt
        .evidence()
        .iter()
        .position(|item| item.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
        .ok_or(())?;
    let end = receipt.evidence()[first..]
        .iter()
        .position(|item| item.predicate().namespace() != ASSESSMENT_PASSIVE_NAMESPACE)
        .map(|offset| first + offset)
        .unwrap_or(receipt.evidence().len());
    let passive = &receipt.evidence()[first..end];
    if passive.is_empty() || passive.len() > MAX_PASSIVE_DERIVED_OBSERVATIONS {
        return Err(());
    }
    validate_trailing_namespaces(&receipt.evidence()[end..])?;
    if receipt.evidence()[..first].iter().any(|item| {
        matches!(
            item.predicate().namespace(),
            ASSESSMENT_PASSIVE_NAMESPACE | "web.discovery" | "web.defense"
        )
    }) {
        return Err(());
    }

    let base = passive_base(receipt, first, expected_subject)?;
    let mut canonical_parents = base.parent_ids.clone();
    canonical_parents.sort();
    if canonical_parents.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(());
    }
    for item in passive {
        if item.subject() != receipt.case().subject()
            || item.kind() != &EvidenceKind::Custom(ASSESSMENT_PASSIVE_CATEGORY.to_owned())
            || item.source().component() != receipt.executor_id()
            || item.source().method() != ASSESSMENT_PASSIVE_SOURCE_METHOD
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.reliability() != base.reliability
        {
            return Err(());
        }
        let EvidenceOrigin::Derived(derivation) = item.origin() else {
            return Err(());
        };
        if derivation.algorithm().name() != ASSESSMENT_PASSIVE_ALGORITHM
            || derivation.algorithm().version() != ASSESSMENT_PASSIVE_ALGORITHM_VERSION
            || derivation.parents() != canonical_parents
        {
            return Err(());
        }
    }

    let mut cursor = 0usize;
    let hsts_state = expect_state(passive, &mut cursor, PassiveFieldKind::Hsts, HSTS_STATE)?;
    let hsts = parse_optional_metadata(
        passive,
        &mut cursor,
        hsts_state,
        HSTS_MAX_AGE,
        |items, at| {
            Ok(CommittedHstsMetadata {
                max_age_seconds: expect_unsigned(items, at, HSTS_MAX_AGE)?,
                includes_subdomains: expect_boolean(items, at, HSTS_INCLUDE_SUBDOMAINS)?,
                requests_preload: expect_boolean(items, at, HSTS_PRELOAD)?,
                has_unrecognized_directive: expect_boolean(items, at, HSTS_UNRECOGNIZED)?,
            })
        },
    )?;

    let csp_state = expect_state(passive, &mut cursor, PassiveFieldKind::Csp, CSP_STATE)?;
    let csp = parse_optional_metadata(
        passive,
        &mut cursor,
        csp_state,
        CSP_POLICY_COUNT,
        |items, at| {
            let policy_count = bounded_u8(expect_unsigned(items, at, CSP_POLICY_COUNT)?, 1, 16)?;
            let directive_count =
                bounded_u8(expect_unsigned(items, at, CSP_DIRECTIVE_COUNT)?, 1, 64)?;
            Ok(CommittedCspMetadata {
                policy_count,
                directive_count,
                has_default_src: expect_boolean(items, at, CSP_DEFAULT_SRC)?,
                has_script_src: expect_boolean(items, at, CSP_SCRIPT_SRC)?,
                has_object_src: expect_boolean(items, at, CSP_OBJECT_SRC)?,
                has_object_src_none: expect_boolean(items, at, CSP_OBJECT_SRC_NONE)?,
                has_base_uri: expect_boolean(items, at, CSP_BASE_URI)?,
                has_base_uri_none: expect_boolean(items, at, CSP_BASE_URI_NONE)?,
                has_frame_ancestors: expect_boolean(items, at, CSP_FRAME_ANCESTORS)?,
                declares_unsafe_inline: expect_boolean(items, at, CSP_UNSAFE_INLINE)?,
                declares_unsafe_eval: expect_boolean(items, at, CSP_UNSAFE_EVAL)?,
                declares_nonce: expect_boolean(items, at, CSP_NONCE)?,
                declares_hash: expect_boolean(items, at, CSP_HASH)?,
            })
        },
    )?;

    if (csp.state == PassiveProjectionState::Nonconformant && csp.metadata.is_none())
        || csp.metadata.as_ref().is_some_and(|metadata| {
            (metadata.has_object_src_none && !metadata.has_object_src)
                || (metadata.has_base_uri_none && !metadata.has_base_uri)
        })
    {
        return Err(());
    }

    let xcto_state = expect_state(passive, &mut cursor, PassiveFieldKind::Xcto, XCTO_STATE)?;
    let xcto = parse_optional_metadata(
        passive,
        &mut cursor,
        xcto_state,
        XCTO_NOSNIFF,
        |items, at| {
            Ok(CommittedXctoMetadata {
                nosniff: expect_boolean(items, at, XCTO_NOSNIFF)?,
            })
        },
    )?;
    if (xcto.state == PassiveProjectionState::Parsed
        && xcto
            .metadata
            .as_ref()
            .is_none_or(|metadata| !metadata.nosniff))
        || (xcto.state == PassiveProjectionState::Nonconformant && xcto.metadata.is_none())
    {
        return Err(());
    }

    let referrer_state = expect_state(
        passive,
        &mut cursor,
        PassiveFieldKind::ReferrerPolicy,
        REFERRER_STATE,
    )?;
    let referrer_policy = parse_optional_metadata(
        passive,
        &mut cursor,
        referrer_state,
        REFERRER_EFFECTIVE,
        |items, at| {
            let effective_policy =
                parse_referrer_policy(expect_text(items, at, REFERRER_EFFECTIVE)?)?;
            let declared_policy_count =
                u16::try_from(expect_unsigned(items, at, REFERRER_DECLARED_COUNT)?)
                    .map_err(|_| ())?;
            if declared_policy_count == 0 {
                return Err(());
            }
            Ok(CommittedReferrerPolicyMetadata {
                effective_policy,
                declared_policy_count,
            })
        },
    )?;
    if (referrer_policy.state == PassiveProjectionState::Parsed
        && referrer_policy
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata.effective_policy.is_none()))
        || (referrer_policy.state == PassiveProjectionState::Nonconformant
            && referrer_policy.metadata.is_none())
    {
        return Err(());
    }

    let permissions_state = expect_state(
        passive,
        &mut cursor,
        PassiveFieldKind::PermissionsPolicy,
        PERMISSIONS_STATE,
    )?;
    let permissions_policy = parse_optional_metadata(
        passive,
        &mut cursor,
        permissions_state,
        PERMISSIONS_DIRECTIVE_COUNT,
        |items, at| {
            let directive_count = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_DIRECTIVE_COUNT)?,
                1,
                MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES,
            )?;
            let member_count = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_MEMBER_COUNT)?,
                0,
                MAX_PASSIVE_PERMISSIONS_POLICY_MEMBERS,
            )?;
            let empty_allowlist_directives = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_EMPTY)?,
                0,
                usize::from(directive_count),
            )?;
            let wildcard_members = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_WILDCARD)?,
                0,
                usize::from(member_count),
            )?;
            let self_members = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_SELF)?,
                0,
                usize::from(member_count),
            )?;
            let src_members = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_SRC)?,
                0,
                usize::from(member_count),
            )?;
            let explicit_members = bounded_u8(
                expect_unsigned(items, at, PERMISSIONS_EXPLICIT)?,
                0,
                usize::from(member_count),
            )?;
            if usize::from(wildcard_members)
                + usize::from(self_members)
                + usize::from(src_members)
                + usize::from(explicit_members)
                != usize::from(member_count)
            {
                return Err(());
            }
            Ok(CommittedPermissionsPolicyMetadata {
                directive_count,
                member_count,
                empty_allowlist_directives,
                wildcard_members,
                self_members,
                src_members,
                explicit_members,
                duplicate_feature_directives: expect_boolean(items, at, PERMISSIONS_DUPLICATE)?,
            })
        },
    )?;
    if (permissions_policy.state == PassiveProjectionState::Parsed
        && permissions_policy
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata.duplicate_feature_directives))
        || (permissions_policy.state == PassiveProjectionState::Nonconformant
            && permissions_policy.metadata.is_none())
    {
        return Err(());
    }

    let cookie_state = expect_state(
        passive,
        &mut cursor,
        PassiveFieldKind::Cookies,
        COOKIE_STATE,
    )?;
    let cookie_metadata_present = passive
        .get(cursor)
        .is_some_and(|item| item.predicate().name() == COOKIE_NAME);
    validate_metadata_presence(cookie_state.0, cookie_metadata_present)?;
    let mut cookies = Vec::new();
    if cookie_metadata_present {
        while cursor < passive.len() {
            if cookies.len() >= MAX_PASSIVE_SET_COOKIE_OCCURRENCES {
                return Err(());
            }
            let name = expect_text(passive, &mut cursor, COOKIE_NAME)?.to_owned();
            if name.len() > MAX_PASSIVE_COOKIE_NAME_BYTES || !valid_cookie_name(&name) {
                return Err(());
            }
            cookies.push(CommittedCookieMetadata {
                name,
                secure: expect_boolean(passive, &mut cursor, COOKIE_SECURE)?,
                http_only: expect_boolean(passive, &mut cursor, COOKIE_HTTP_ONLY)?,
                same_site: parse_same_site(expect_text(passive, &mut cursor, COOKIE_SAME_SITE)?)?,
                domain_attribute_present: expect_boolean(
                    passive,
                    &mut cursor,
                    COOKIE_DOMAIN_PRESENT,
                )?,
                path_attribute_present: expect_boolean(passive, &mut cursor, COOKIE_PATH_PRESENT)?,
            });
        }
        if cookies.is_empty() {
            return Err(());
        }
    }
    let cookies = CommittedPassiveField {
        state: cookie_state.0,
        incomplete_reason: cookie_state.1,
        metadata: cookie_metadata_present.then_some(cookies),
    };
    if cookies.state == PassiveProjectionState::Nonconformant && cookies.metadata.is_none() {
        return Err(());
    }
    if cursor != passive.len() {
        return Err(());
    }
    let mut property_evidence = BTreeMap::new();
    for item in passive {
        let property = canonical_property(item.predicate().name()).ok_or(())?;
        property_evidence
            .entry(property)
            .or_insert_with(Vec::new)
            .push(item.id().clone());
    }
    Ok(CommittedAssessmentPassiveObservation {
        subject: receipt.case().subject().clone(),
        case_id: receipt.case().id().to_owned(),
        stage: receipt.stage(),
        method: base.method,
        status: base.status,
        media_class: base.media_class,
        hsts,
        csp,
        xcto,
        referrer_policy,
        permissions_policy,
        cookies,
        base_evidence: base.evidence,
        parent_evidence_ids: canonical_parents,
        evidence_ids: passive.iter().map(|item| item.id().clone()).collect(),
        property_evidence,
    })
}

fn validate_trailing_namespaces(items: &[Evidence]) -> Result<(), ()> {
    let mut defense_started = false;
    for item in items {
        match item.predicate().namespace() {
            "web.discovery" if !defense_started => {},
            "web.defense" => defense_started = true,
            _ => return Err(()),
        }
    }
    Ok(())
}

struct PassiveBase {
    method: WebAssessmentMethod,
    status: u16,
    media_class: CommittedPassiveMediaClass,
    reliability: ConfidenceScore,
    parent_ids: Vec<EvidenceId>,
    evidence: CommittedPassiveBaseEvidence,
}

fn passive_base(
    receipt: &DecisionEvidenceReceipt,
    first_passive: usize,
    expected_subject: &WebAssessmentSubject,
) -> Result<PassiveBase, ()> {
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
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
            EvidenceKind::Http,
            "response-final-url",
        ),
    ];
    let mut parents = Vec::with_capacity(specs.len());
    let mut previous_index = None;
    let mut request_url = None;
    let mut final_url = None;
    let mut parsed_method = None;
    let mut status = None;
    let mut reliability = None;
    let mut method_evidence = None;
    let mut request_url_evidence = None;
    let mut status_evidence = None;
    let mut final_url_evidence = None;
    for (descriptor, kind, source_method) in specs {
        let expected = descriptor.into_knowledge();
        let matching: Vec<_> = receipt
            .evidence()
            .iter()
            .enumerate()
            .filter(|(_, item)| item.predicate() == &expected)
            .collect();
        if matching.len() != 1 {
            return Err(());
        }
        let (index, item) = matching[0];
        if index >= first_passive
            || previous_index.is_some_and(|previous| index <= previous)
            || item.subject() != receipt.case().subject()
            || item.kind() != &kind
            || item.source().component() != receipt.executor_id()
            || item.source().method() != source_method
            || item.source().correlation_id() != Some(receipt.case().id())
            || !item.origin().is_direct()
        {
            return Err(());
        }
        previous_index = Some(index);
        if reliability.is_some_and(|value| value != item.reliability()) {
            return Err(());
        }
        reliability = Some(item.reliability());
        match descriptor {
            HttpEvidencePredicate::REQUEST_METHOD => {
                let EvidenceValue::Text(value) = item.value() else {
                    return Err(());
                };
                parsed_method = Some(match value.as_str() {
                    "GET" if expected_subject.method() == WebAssessmentMethod::Get => {
                        WebAssessmentMethod::Get
                    },
                    "HEAD" if expected_subject.method() == WebAssessmentMethod::Head => {
                        WebAssessmentMethod::Head
                    },
                    _ => return Err(()),
                });
                method_evidence = Some(item.id().clone());
            },
            HttpEvidencePredicate::REQUEST_URL => {
                let EvidenceValue::Text(value) = item.value() else {
                    return Err(());
                };
                url::Url::parse(value).map_err(|_| ())?;
                if value != expected_subject.url().as_str() {
                    return Err(());
                }
                request_url = Some(value.as_str());
                request_url_evidence = Some(item.id().clone());
            },
            HttpEvidencePredicate::RESPONSE_STATUS => {
                let EvidenceValue::Unsigned(value) = item.value() else {
                    return Err(());
                };
                let value = u16::try_from(*value).map_err(|_| ())?;
                if !(100..=599).contains(&value) {
                    return Err(());
                }
                status = Some(value);
                status_evidence = Some(item.id().clone());
            },
            HttpEvidencePredicate::RESPONSE_FINAL_URL => {
                let EvidenceValue::Text(value) = item.value() else {
                    return Err(());
                };
                url::Url::parse(value).map_err(|_| ())?;
                if value != expected_subject.url().as_str() {
                    return Err(());
                }
                final_url = Some(value.as_str());
                final_url_evidence = Some(item.id().clone());
            },
            _ => return Err(()),
        }
        parents.push(item.id().clone());
    }
    if request_url.is_none() || request_url != final_url {
        return Err(());
    }
    let reliability = reliability.ok_or(())?;
    validate_rate_prefix(receipt, first_passive, reliability)?;
    let (media_class, media_type_evidence) =
        passive_media_class(receipt, first_passive, reliability)?;
    Ok(PassiveBase {
        method: parsed_method.ok_or(())?,
        status: status.ok_or(())?,
        media_class,
        reliability,
        parent_ids: parents,
        evidence: CommittedPassiveBaseEvidence {
            method: method_evidence.ok_or(())?,
            request_url: request_url_evidence.ok_or(())?,
            status: status_evidence.ok_or(())?,
            final_url: final_url_evidence.ok_or(())?,
            media_type: media_type_evidence,
        },
    })
}

fn validate_rate_prefix(
    receipt: &DecisionEvidenceReceipt,
    first_passive: usize,
    reliability: ConfidenceScore,
) -> Result<(), ()> {
    let mut previous = None;
    for (offset, (descriptor, method)) in [
        (
            HttpEvidencePredicate::RATE_LIMIT_DETECTED,
            "rate-limit-status",
        ),
        (
            HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
            "rate-limit-headers",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let predicate = descriptor.into_knowledge();
        let matching: Vec<_> = receipt
            .evidence()
            .iter()
            .enumerate()
            .filter(|(_, item)| item.predicate() == &predicate)
            .collect();
        if matching.len() != 1 {
            return Err(());
        }
        let (index, item) = matching[0];
        if index >= first_passive
            || index.checked_add(2 - offset) != Some(first_passive)
            || previous.is_some_and(|prior| index <= prior)
            || item.subject() != receipt.case().subject()
            || item.kind() != &EvidenceKind::RateLimit
            || item.source().component() != receipt.executor_id()
            || item.source().method() != method
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.reliability() != reliability
            || !item.origin().is_direct()
            || !matches!(item.value(), EvidenceValue::Boolean(_))
        {
            return Err(());
        }
        previous = Some(index);
    }
    Ok(())
}

fn passive_media_class(
    receipt: &DecisionEvidenceReceipt,
    first_passive: usize,
    reliability: ConfidenceScore,
) -> Result<(CommittedPassiveMediaClass, Option<EvidenceId>), ()> {
    let predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
    let matching: Vec<_> = receipt
        .evidence()
        .iter()
        .enumerate()
        .filter(|(_, item)| item.predicate() == &predicate)
        .collect();
    let Some((index, item)) = matching.first().copied() else {
        return Ok((CommittedPassiveMediaClass::Missing, None));
    };
    if matching.len() != 1
        || index >= first_passive
        || item.subject() != receipt.case().subject()
        || item.kind() != &EvidenceKind::Http
        || item.source().component() != receipt.executor_id()
        || item.source().method() != "response-media-type"
        || item.source().correlation_id() != Some(receipt.case().id())
        || item.reliability() != reliability
        || !item.origin().is_direct()
    {
        return Err(());
    }
    let EvidenceValue::Text(value) = item.value() else {
        return Err(());
    };
    if value.is_empty()
        || value != &value.to_ascii_lowercase()
        || value.contains(';')
        || value.chars().any(char::is_control)
        || value.matches('/').count() != 1
    {
        return Err(());
    }
    if value == "text/html" {
        Ok((CommittedPassiveMediaClass::Html, Some(item.id().clone())))
    } else if value
        .split_once('/')
        .is_some_and(|(_, subtype)| subtype == "json" || subtype.ends_with("+json"))
    {
        Ok((
            CommittedPassiveMediaClass::JsonCompatible,
            Some(item.id().clone()),
        ))
    } else {
        Ok((CommittedPassiveMediaClass::Other, Some(item.id().clone())))
    }
}

type ParsedState = (
    PassiveProjectionState,
    Option<PassiveProjectionIncompleteReason>,
);

#[derive(Clone, Copy)]
enum PassiveFieldKind {
    Hsts,
    Csp,
    Xcto,
    ReferrerPolicy,
    PermissionsPolicy,
    Cookies,
}

fn expect_state(
    items: &[Evidence],
    cursor: &mut usize,
    field: PassiveFieldKind,
    name: &str,
) -> Result<ParsedState, ()> {
    let values = expect_text_list(items, cursor, name)?;
    let state = values
        .first()
        .and_then(|value| parse_projection_state(value))
        .ok_or(())?;
    let reason = match state {
        PassiveProjectionState::ProjectionIncomplete => {
            if values.len() != 2 {
                return Err(());
            }
            let reason = parse_incomplete_reason(&values[1]).ok_or(())?;
            if !incomplete_reason_allowed(field, reason) {
                return Err(());
            }
            Some(reason)
        },
        _ => {
            if values.len() != 1 {
                return Err(());
            }
            None
        },
    };
    Ok((state, reason))
}

const fn incomplete_reason_allowed(
    field: PassiveFieldKind,
    reason: PassiveProjectionIncompleteReason,
) -> bool {
    if matches!(
        reason,
        PassiveProjectionIncompleteReason::TooManyDerivedObservations
    ) {
        return true;
    }
    match field {
        PassiveFieldKind::Hsts | PassiveFieldKind::Xcto | PassiveFieldKind::ReferrerPolicy => {
            matches!(
                reason,
                PassiveProjectionIncompleteReason::TooManyHeaderOccurrences
                    | PassiveProjectionIncompleteReason::OversizedHeaderValue
            )
        },
        PassiveFieldKind::Csp => matches!(
            reason,
            PassiveProjectionIncompleteReason::TooManyHeaderOccurrences
                | PassiveProjectionIncompleteReason::OversizedHeaderValue
                | PassiveProjectionIncompleteReason::TooManyCspPolicies
                | PassiveProjectionIncompleteReason::TooManyCspDirectives
        ),
        PassiveFieldKind::PermissionsPolicy => matches!(
            reason,
            PassiveProjectionIncompleteReason::TooManyHeaderOccurrences
                | PassiveProjectionIncompleteReason::OversizedHeaderValue
                | PassiveProjectionIncompleteReason::TooManyPermissionsPolicyDirectives
                | PassiveProjectionIncompleteReason::TooManyPermissionsPolicyMembers
        ),
        PassiveFieldKind::Cookies => matches!(
            reason,
            PassiveProjectionIncompleteReason::TooManySetCookieOccurrences
                | PassiveProjectionIncompleteReason::OversizedSetCookieValue
                | PassiveProjectionIncompleteReason::OversizedCookiePair
                | PassiveProjectionIncompleteReason::OversizedCookieName
                | PassiveProjectionIncompleteReason::TooManyCookieAttributes
                | PassiveProjectionIncompleteReason::OversizedCookieScopeValue
        ),
    }
}

fn parse_optional_metadata<T>(
    items: &[Evidence],
    cursor: &mut usize,
    state: ParsedState,
    first_name: &str,
    parser: impl FnOnce(&[Evidence], &mut usize) -> Result<T, ()>,
) -> Result<CommittedPassiveField<T>, ()> {
    let present = items
        .get(*cursor)
        .is_some_and(|item| item.predicate().name() == first_name);
    validate_metadata_presence(state.0, present)?;
    let metadata = if present {
        Some(parser(items, cursor)?)
    } else {
        None
    };
    Ok(CommittedPassiveField {
        state: state.0,
        incomplete_reason: state.1,
        metadata,
    })
}

fn validate_metadata_presence(state: PassiveProjectionState, present: bool) -> Result<(), ()> {
    match state {
        PassiveProjectionState::Parsed if present => Ok(()),
        PassiveProjectionState::Nonconformant => Ok(()),
        PassiveProjectionState::Missing
        | PassiveProjectionState::Malformed
        | PassiveProjectionState::ProjectionIncomplete
            if !present =>
        {
            Ok(())
        },
        _ => Err(()),
    }
}

fn expect_record<'a>(
    items: &'a [Evidence],
    cursor: &mut usize,
    name: &str,
) -> Result<&'a Evidence, ()> {
    let item = items.get(*cursor).ok_or(())?;
    if item.predicate().namespace() != ASSESSMENT_PASSIVE_NAMESPACE
        || item.predicate().name() != name
    {
        return Err(());
    }
    *cursor += 1;
    Ok(item)
}

fn expect_boolean(items: &[Evidence], cursor: &mut usize, name: &str) -> Result<bool, ()> {
    match expect_record(items, cursor, name)?.value() {
        EvidenceValue::Boolean(value) => Ok(*value),
        _ => Err(()),
    }
}

fn expect_unsigned(items: &[Evidence], cursor: &mut usize, name: &str) -> Result<u64, ()> {
    match expect_record(items, cursor, name)?.value() {
        EvidenceValue::Unsigned(value) => Ok(*value),
        _ => Err(()),
    }
}

fn expect_text<'a>(items: &'a [Evidence], cursor: &mut usize, name: &str) -> Result<&'a str, ()> {
    match expect_record(items, cursor, name)?.value() {
        EvidenceValue::Text(value) => Ok(value),
        _ => Err(()),
    }
}

fn expect_text_list<'a>(
    items: &'a [Evidence],
    cursor: &mut usize,
    name: &str,
) -> Result<&'a [String], ()> {
    match expect_record(items, cursor, name)?.value() {
        EvidenceValue::TextList(value) => Ok(value),
        _ => Err(()),
    }
}

fn bounded_u8(value: u64, minimum: usize, maximum: usize) -> Result<u8, ()> {
    let value = usize::try_from(value).map_err(|_| ())?;
    if !(minimum..=maximum).contains(&value) {
        return Err(());
    }
    u8::try_from(value).map_err(|_| ())
}

fn predicate(name: &'static str) -> Result<KnowledgePredicate, termivar_core::ReasoningModelError> {
    KnowledgePredicate::new(ASSESSMENT_PASSIVE_NAMESPACE, name)
}

fn canonical_property(name: &str) -> Option<PassiveEvidenceProperty> {
    match name {
        HSTS_STATE => Some(PassiveEvidenceProperty(HSTS_STATE)),
        HSTS_MAX_AGE => Some(PassiveEvidenceProperty(HSTS_MAX_AGE)),
        HSTS_INCLUDE_SUBDOMAINS => Some(PassiveEvidenceProperty(HSTS_INCLUDE_SUBDOMAINS)),
        HSTS_PRELOAD => Some(PassiveEvidenceProperty(HSTS_PRELOAD)),
        HSTS_UNRECOGNIZED => Some(PassiveEvidenceProperty(HSTS_UNRECOGNIZED)),
        CSP_STATE => Some(PassiveEvidenceProperty(CSP_STATE)),
        CSP_POLICY_COUNT => Some(PassiveEvidenceProperty(CSP_POLICY_COUNT)),
        CSP_DIRECTIVE_COUNT => Some(PassiveEvidenceProperty(CSP_DIRECTIVE_COUNT)),
        CSP_DEFAULT_SRC => Some(PassiveEvidenceProperty(CSP_DEFAULT_SRC)),
        CSP_SCRIPT_SRC => Some(PassiveEvidenceProperty(CSP_SCRIPT_SRC)),
        CSP_OBJECT_SRC => Some(PassiveEvidenceProperty(CSP_OBJECT_SRC)),
        CSP_OBJECT_SRC_NONE => Some(PassiveEvidenceProperty(CSP_OBJECT_SRC_NONE)),
        CSP_BASE_URI => Some(PassiveEvidenceProperty(CSP_BASE_URI)),
        CSP_BASE_URI_NONE => Some(PassiveEvidenceProperty(CSP_BASE_URI_NONE)),
        CSP_FRAME_ANCESTORS => Some(PassiveEvidenceProperty(CSP_FRAME_ANCESTORS)),
        CSP_UNSAFE_INLINE => Some(PassiveEvidenceProperty(CSP_UNSAFE_INLINE)),
        CSP_UNSAFE_EVAL => Some(PassiveEvidenceProperty(CSP_UNSAFE_EVAL)),
        CSP_NONCE => Some(PassiveEvidenceProperty(CSP_NONCE)),
        CSP_HASH => Some(PassiveEvidenceProperty(CSP_HASH)),
        XCTO_STATE => Some(PassiveEvidenceProperty(XCTO_STATE)),
        XCTO_NOSNIFF => Some(PassiveEvidenceProperty(XCTO_NOSNIFF)),
        REFERRER_STATE => Some(PassiveEvidenceProperty(REFERRER_STATE)),
        REFERRER_EFFECTIVE => Some(PassiveEvidenceProperty(REFERRER_EFFECTIVE)),
        REFERRER_DECLARED_COUNT => Some(PassiveEvidenceProperty(REFERRER_DECLARED_COUNT)),
        PERMISSIONS_STATE => Some(PassiveEvidenceProperty(PERMISSIONS_STATE)),
        PERMISSIONS_DIRECTIVE_COUNT => Some(PassiveEvidenceProperty(PERMISSIONS_DIRECTIVE_COUNT)),
        PERMISSIONS_MEMBER_COUNT => Some(PassiveEvidenceProperty(PERMISSIONS_MEMBER_COUNT)),
        PERMISSIONS_EMPTY => Some(PassiveEvidenceProperty(PERMISSIONS_EMPTY)),
        PERMISSIONS_WILDCARD => Some(PassiveEvidenceProperty(PERMISSIONS_WILDCARD)),
        PERMISSIONS_SELF => Some(PassiveEvidenceProperty(PERMISSIONS_SELF)),
        PERMISSIONS_SRC => Some(PassiveEvidenceProperty(PERMISSIONS_SRC)),
        PERMISSIONS_EXPLICIT => Some(PassiveEvidenceProperty(PERMISSIONS_EXPLICIT)),
        PERMISSIONS_DUPLICATE => Some(PassiveEvidenceProperty(PERMISSIONS_DUPLICATE)),
        COOKIE_STATE => Some(PassiveEvidenceProperty(COOKIE_STATE)),
        COOKIE_NAME => Some(PassiveEvidenceProperty(COOKIE_NAME)),
        COOKIE_SECURE => Some(PassiveEvidenceProperty(COOKIE_SECURE)),
        COOKIE_HTTP_ONLY => Some(PassiveEvidenceProperty(COOKIE_HTTP_ONLY)),
        COOKIE_SAME_SITE => Some(PassiveEvidenceProperty(COOKIE_SAME_SITE)),
        COOKIE_DOMAIN_PRESENT => Some(PassiveEvidenceProperty(COOKIE_DOMAIN_PRESENT)),
        COOKIE_PATH_PRESENT => Some(PassiveEvidenceProperty(COOKIE_PATH_PRESENT)),
        _ => None,
    }
}

const fn projection_state_slug(state: PassiveProjectionState) -> &'static str {
    match state {
        PassiveProjectionState::Missing => "missing",
        PassiveProjectionState::Parsed => "parsed",
        PassiveProjectionState::Nonconformant => "nonconformant",
        PassiveProjectionState::Malformed => "malformed",
        PassiveProjectionState::ProjectionIncomplete => "projection_incomplete",
    }
}

fn parse_projection_state(value: &str) -> Option<PassiveProjectionState> {
    match value {
        "missing" => Some(PassiveProjectionState::Missing),
        "parsed" => Some(PassiveProjectionState::Parsed),
        "nonconformant" => Some(PassiveProjectionState::Nonconformant),
        "malformed" => Some(PassiveProjectionState::Malformed),
        "projection_incomplete" => Some(PassiveProjectionState::ProjectionIncomplete),
        _ => None,
    }
}

const fn incomplete_reason_slug(reason: PassiveProjectionIncompleteReason) -> &'static str {
    match reason {
        PassiveProjectionIncompleteReason::TooManyHeaderOccurrences => {
            "too_many_header_occurrences"
        },
        PassiveProjectionIncompleteReason::OversizedHeaderValue => "oversized_header_value",
        PassiveProjectionIncompleteReason::TooManyCspPolicies => "too_many_csp_policies",
        PassiveProjectionIncompleteReason::TooManyCspDirectives => "too_many_csp_directives",
        PassiveProjectionIncompleteReason::TooManyPermissionsPolicyDirectives => {
            "too_many_permissions_policy_directives"
        },
        PassiveProjectionIncompleteReason::TooManyPermissionsPolicyMembers => {
            "too_many_permissions_policy_members"
        },
        PassiveProjectionIncompleteReason::TooManySetCookieOccurrences => {
            "too_many_set_cookie_occurrences"
        },
        PassiveProjectionIncompleteReason::OversizedSetCookieValue => "oversized_set_cookie_value",
        PassiveProjectionIncompleteReason::OversizedCookiePair => "oversized_cookie_pair",
        PassiveProjectionIncompleteReason::OversizedCookieName => "oversized_cookie_name",
        PassiveProjectionIncompleteReason::TooManyCookieAttributes => "too_many_cookie_attributes",
        PassiveProjectionIncompleteReason::OversizedCookieScopeValue => {
            "oversized_cookie_scope_value"
        },
        PassiveProjectionIncompleteReason::TooManyDerivedObservations => {
            "too_many_derived_observations"
        },
    }
}

fn parse_incomplete_reason(value: &str) -> Option<PassiveProjectionIncompleteReason> {
    match value {
        "too_many_header_occurrences" => {
            Some(PassiveProjectionIncompleteReason::TooManyHeaderOccurrences)
        },
        "oversized_header_value" => Some(PassiveProjectionIncompleteReason::OversizedHeaderValue),
        "too_many_csp_policies" => Some(PassiveProjectionIncompleteReason::TooManyCspPolicies),
        "too_many_csp_directives" => Some(PassiveProjectionIncompleteReason::TooManyCspDirectives),
        "too_many_permissions_policy_directives" => {
            Some(PassiveProjectionIncompleteReason::TooManyPermissionsPolicyDirectives)
        },
        "too_many_permissions_policy_members" => {
            Some(PassiveProjectionIncompleteReason::TooManyPermissionsPolicyMembers)
        },
        "too_many_set_cookie_occurrences" => {
            Some(PassiveProjectionIncompleteReason::TooManySetCookieOccurrences)
        },
        "oversized_set_cookie_value" => {
            Some(PassiveProjectionIncompleteReason::OversizedSetCookieValue)
        },
        "oversized_cookie_pair" => Some(PassiveProjectionIncompleteReason::OversizedCookiePair),
        "oversized_cookie_name" => Some(PassiveProjectionIncompleteReason::OversizedCookieName),
        "too_many_cookie_attributes" => {
            Some(PassiveProjectionIncompleteReason::TooManyCookieAttributes)
        },
        "oversized_cookie_scope_value" => {
            Some(PassiveProjectionIncompleteReason::OversizedCookieScopeValue)
        },
        "too_many_derived_observations" => {
            Some(PassiveProjectionIncompleteReason::TooManyDerivedObservations)
        },
        _ => None,
    }
}

const fn referrer_policy_slug(value: ReferrerPolicyValue) -> &'static str {
    match value {
        ReferrerPolicyValue::NoReferrer => "no-referrer",
        ReferrerPolicyValue::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
        ReferrerPolicyValue::Origin => "origin",
        ReferrerPolicyValue::OriginWhenCrossOrigin => "origin-when-cross-origin",
        ReferrerPolicyValue::SameOrigin => "same-origin",
        ReferrerPolicyValue::StrictOrigin => "strict-origin",
        ReferrerPolicyValue::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        ReferrerPolicyValue::UnsafeUrl => "unsafe-url",
    }
}

fn parse_referrer_policy(value: &str) -> Result<Option<ReferrerPolicyValue>, ()> {
    match value {
        "unrecognized" => Ok(None),
        "no-referrer" => Ok(Some(ReferrerPolicyValue::NoReferrer)),
        "no-referrer-when-downgrade" => Ok(Some(ReferrerPolicyValue::NoReferrerWhenDowngrade)),
        "origin" => Ok(Some(ReferrerPolicyValue::Origin)),
        "origin-when-cross-origin" => Ok(Some(ReferrerPolicyValue::OriginWhenCrossOrigin)),
        "same-origin" => Ok(Some(ReferrerPolicyValue::SameOrigin)),
        "strict-origin" => Ok(Some(ReferrerPolicyValue::StrictOrigin)),
        "strict-origin-when-cross-origin" => {
            Ok(Some(ReferrerPolicyValue::StrictOriginWhenCrossOrigin))
        },
        "unsafe-url" => Ok(Some(ReferrerPolicyValue::UnsafeUrl)),
        _ => Err(()),
    }
}

const fn cookie_same_site_slug(value: PassiveCookieSameSite) -> &'static str {
    match value {
        PassiveCookieSameSite::Missing => "missing",
        PassiveCookieSameSite::Strict => "strict",
        PassiveCookieSameSite::Lax => "lax",
        PassiveCookieSameSite::None => "none",
    }
}

fn parse_same_site(value: &str) -> Result<PassiveCookieSameSite, ()> {
    match value {
        "missing" => Ok(PassiveCookieSameSite::Missing),
        "strict" => Ok(PassiveCookieSameSite::Strict),
        "lax" => Ok(PassiveCookieSameSite::Lax),
        "none" => Ok(PassiveCookieSameSite::None),
        _ => Err(()),
    }
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod passive_item_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use termivar_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource,
        EvidenceValue, KnowledgePredicate,
    };

    use super::super::assessment_item::{AssessmentBasis, AssessmentDisposition};
    use super::super::WebAssessmentRuntime;
    use super::*;

    fn evidence_id(label: &str) -> EvidenceId {
        EvidenceId::parse(format!("evidence:passive-item:{label}")).unwrap()
    }

    fn property_evidence(
        cookie_count: usize,
    ) -> BTreeMap<PassiveEvidenceProperty, Vec<EvidenceId>> {
        let mut properties = BTreeMap::new();
        for name in [
            HSTS_STATE,
            HSTS_MAX_AGE,
            CSP_STATE,
            CSP_UNSAFE_INLINE,
            CSP_UNSAFE_EVAL,
            XCTO_STATE,
            XCTO_NOSNIFF,
            REFERRER_STATE,
            REFERRER_EFFECTIVE,
            PERMISSIONS_STATE,
            COOKIE_STATE,
        ] {
            properties.insert(canonical_property(name).unwrap(), vec![evidence_id(name)]);
        }
        for name in [
            COOKIE_NAME,
            COOKIE_SECURE,
            COOKIE_HTTP_ONLY,
            COOKIE_SAME_SITE,
        ] {
            properties.insert(
                canonical_property(name).unwrap(),
                (0..cookie_count)
                    .map(|index| evidence_id(&format!("{name}:{index}")))
                    .collect(),
            );
        }
        properties
    }

    fn parsed<T>(metadata: T) -> CommittedPassiveField<T> {
        CommittedPassiveField {
            state: PassiveProjectionState::Parsed,
            incomplete_reason: None,
            metadata: Some(metadata),
        }
    }

    fn absent<T>() -> CommittedPassiveField<T> {
        CommittedPassiveField {
            state: PassiveProjectionState::Missing,
            incomplete_reason: None,
            metadata: None,
        }
    }

    fn safe_observation(subject: &str) -> CommittedAssessmentPassiveObservation {
        CommittedAssessmentPassiveObservation {
            subject: EntityId::new(subject).unwrap(),
            case_id: "case:web.assessment.bootstrap".to_owned(),
            stage: DecisionExecutionStage::Passive,
            method: WebAssessmentMethod::Get,
            status: 200,
            media_class: CommittedPassiveMediaClass::Html,
            hsts: parsed(CommittedHstsMetadata {
                max_age_seconds: 31_536_000,
                includes_subdomains: true,
                requests_preload: false,
                has_unrecognized_directive: false,
            }),
            csp: parsed(CommittedCspMetadata {
                policy_count: 1,
                directive_count: 1,
                has_default_src: true,
                has_script_src: false,
                has_object_src: false,
                has_object_src_none: false,
                has_base_uri: false,
                has_base_uri_none: false,
                has_frame_ancestors: false,
                declares_unsafe_inline: false,
                declares_unsafe_eval: false,
                declares_nonce: false,
                declares_hash: false,
            }),
            xcto: parsed(CommittedXctoMetadata { nosniff: true }),
            referrer_policy: parsed(CommittedReferrerPolicyMetadata {
                effective_policy: Some(ReferrerPolicyValue::NoReferrer),
                declared_policy_count: 1,
            }),
            permissions_policy: parsed(CommittedPermissionsPolicyMetadata {
                directive_count: 1,
                member_count: 0,
                empty_allowlist_directives: 1,
                wildcard_members: 0,
                self_members: 0,
                src_members: 0,
                explicit_members: 0,
                duplicate_feature_directives: false,
            }),
            cookies: absent(),
            base_evidence: CommittedPassiveBaseEvidence {
                method: evidence_id("base:method"),
                request_url: evidence_id("base:request-url"),
                status: evidence_id("base:status"),
                final_url: evidence_id("base:final-url"),
                media_type: Some(evidence_id("base:media")),
            },
            parent_evidence_ids: vec![],
            evidence_ids: vec![],
            property_evidence: property_evidence(0),
        }
    }

    fn planned_conditions(
        observation: &CommittedAssessmentPassiveObservation,
        https: bool,
    ) -> Vec<PassiveAssessmentCondition> {
        passive_conditions(observation, https)
            .unwrap()
            .into_iter()
            .map(|planned| planned.condition)
            .collect()
    }

    #[test]
    fn passive_item_eligibility_is_method_status_media_and_scheme_bounded() {
        let mut observation = safe_observation("endpoint:https://fixture.test/");
        observation.hsts = absent();
        observation.csp = absent();

        assert_eq!(
            planned_conditions(&observation, true),
            vec![
                PassiveAssessmentCondition::HstsMissing,
                PassiveAssessmentCondition::CspMissing,
            ]
        );
        assert_eq!(
            planned_conditions(&observation, false),
            vec![PassiveAssessmentCondition::CspMissing]
        );

        observation.method = WebAssessmentMethod::Head;
        assert_eq!(
            planned_conditions(&observation, true),
            vec![PassiveAssessmentCondition::HstsMissing]
        );
        observation.method = WebAssessmentMethod::Get;
        observation.status = 201;
        assert_eq!(
            planned_conditions(&observation, true),
            vec![PassiveAssessmentCondition::HstsMissing]
        );
        observation.status = 304;
        assert!(planned_conditions(&observation, true).is_empty());
        observation.status = 200;
        observation.media_class = CommittedPassiveMediaClass::JsonCompatible;
        assert_eq!(
            planned_conditions(&observation, true),
            vec![PassiveAssessmentCondition::HstsMissing]
        );
    }

    #[test]
    fn passive_items_cite_only_base_and_predicate_specific_evidence() {
        let mut observation = safe_observation("endpoint:https://fixture.test/");
        observation.hsts = absent();
        let items = passive_conditions(&observation, true).unwrap();
        assert_eq!(items.len(), 1);
        let ids = &items[0].evidence_ids;
        for required in [
            "base:method",
            "base:request-url",
            "base:status",
            "base:final-url",
            "base:media",
            HSTS_STATE,
        ] {
            assert!(ids.contains(&evidence_id(required)), "missing {required}");
        }
        assert!(!ids.contains(&evidence_id(CSP_STATE)));
        assert!(!ids.contains(&evidence_id(HSTS_MAX_AGE)));
    }

    #[test]
    fn malformed_fields_are_nonconformant_and_incomplete_fields_never_imply_absence() {
        let mut observation = safe_observation("endpoint:https://fixture.test/");
        observation.hsts = CommittedPassiveField {
            state: PassiveProjectionState::Malformed,
            incomplete_reason: None,
            metadata: None,
        };
        observation.csp = CommittedPassiveField {
            state: PassiveProjectionState::Malformed,
            incomplete_reason: None,
            metadata: None,
        };
        observation.xcto = CommittedPassiveField {
            state: PassiveProjectionState::Malformed,
            incomplete_reason: None,
            metadata: None,
        };
        observation.referrer_policy = CommittedPassiveField {
            state: PassiveProjectionState::Malformed,
            incomplete_reason: None,
            metadata: None,
        };
        observation.permissions_policy = CommittedPassiveField {
            state: PassiveProjectionState::Malformed,
            incomplete_reason: None,
            metadata: None,
        };
        observation.cookies = CommittedPassiveField {
            state: PassiveProjectionState::ProjectionIncomplete,
            incomplete_reason: Some(PassiveProjectionIncompleteReason::TooManySetCookieOccurrences),
            metadata: None,
        };
        assert_eq!(
            planned_conditions(&observation, true),
            vec![
                PassiveAssessmentCondition::HstsNonconformant,
                PassiveAssessmentCondition::CspNonconformant,
                PassiveAssessmentCondition::XctoNonconformant,
                PassiveAssessmentCondition::ReferrerNonconformant,
                PassiveAssessmentCondition::PermissionsNonconformant,
            ]
        );

        observation.cookies = CommittedPassiveField {
            state: PassiveProjectionState::Malformed,
            incomplete_reason: None,
            metadata: None,
        };
        assert_eq!(
            planned_conditions(&observation, true),
            vec![
                PassiveAssessmentCondition::HstsNonconformant,
                PassiveAssessmentCondition::CspNonconformant,
                PassiveAssessmentCondition::XctoNonconformant,
                PassiveAssessmentCondition::ReferrerNonconformant,
                PassiveAssessmentCondition::PermissionsNonconformant,
                PassiveAssessmentCondition::CookieNonconformant,
            ]
        );

        let mut incomplete = safe_observation("endpoint:https://fixture.test/");
        incomplete.csp = CommittedPassiveField {
            state: PassiveProjectionState::ProjectionIncomplete,
            incomplete_reason: Some(PassiveProjectionIncompleteReason::TooManyHeaderOccurrences),
            metadata: None,
        };
        incomplete.referrer_policy = CommittedPassiveField {
            state: PassiveProjectionState::ProjectionIncomplete,
            incomplete_reason: Some(PassiveProjectionIncompleteReason::OversizedHeaderValue),
            metadata: None,
        };
        incomplete.cookies = CommittedPassiveField {
            state: PassiveProjectionState::ProjectionIncomplete,
            incomplete_reason: Some(PassiveProjectionIncompleteReason::TooManySetCookieOccurrences),
            metadata: None,
        };
        assert!(planned_conditions(&incomplete, true).is_empty());
    }

    #[test]
    fn cookie_secure_is_https_only_and_same_site_relationship_is_exact() {
        let mut observation = safe_observation("endpoint:https://fixture.test/");
        observation.cookies = CommittedPassiveField {
            state: PassiveProjectionState::Nonconformant,
            incomplete_reason: None,
            metadata: Some(vec![CommittedCookieMetadata {
                name: "private-session-cookie".to_owned(),
                secure: false,
                http_only: true,
                same_site: PassiveCookieSameSite::None,
                domain_attribute_present: false,
                path_attribute_present: true,
            }]),
        };
        observation.property_evidence = property_evidence(1);

        assert_eq!(
            planned_conditions(&observation, true),
            vec![
                PassiveAssessmentCondition::CookieSecureNotSet,
                PassiveAssessmentCondition::CookieSameSiteNoneWithoutSecure,
                PassiveAssessmentCondition::CookieNonconformant,
            ]
        );
        assert_eq!(
            planned_conditions(&observation, false),
            vec![
                PassiveAssessmentCondition::CookieSameSiteNoneWithoutSecure,
                PassiveAssessmentCondition::CookieNonconformant,
            ]
        );
        let relationship = passive_conditions(&observation, true)
            .unwrap()
            .into_iter()
            .find(|planned| {
                planned.condition == PassiveAssessmentCondition::CookieSameSiteNoneWithoutSecure
            })
            .unwrap();
        assert!(relationship
            .evidence_ids
            .contains(&evidence_id(&format!("{COOKIE_SECURE}:0"))));
        assert!(relationship
            .evidence_ids
            .contains(&evidence_id(&format!("{COOKIE_SAME_SITE}:0"))));
    }

    fn committed_fixture_evidence(id: EvidenceId, subject: &EntityId) -> Evidence {
        Evidence::with_id(
            id,
            subject.clone(),
            EvidenceKind::Http,
            KnowledgePredicate::new("test", "passive-item").unwrap(),
            EvidenceValue::Boolean(true),
            EvidenceSource::new("test.passive-item", "fixture")
                .unwrap()
                .with_correlation_id("case:web.assessment.bootstrap")
                .unwrap(),
            ConfidenceScore::MAX,
        )
    }

    fn commit_planned_evidence(
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        observation: &CommittedAssessmentPassiveObservation,
        https: bool,
    ) {
        let ids = passive_conditions(observation, https)
            .unwrap()
            .iter()
            .flat_map(|planned| planned.evidence_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        for id in ids {
            knowledge
                .insert_evidence(committed_fixture_evidence(id, subject))
                .unwrap();
        }
    }

    #[test]
    fn projector_emits_informational_item_without_severity_or_cwe() {
        let runtime = WebAssessmentRuntime::builder(
            url::Url::parse("https://fixture.test/").expect("root URL"),
        )
        .build()
        .expect("assessment runtime");
        let authorized_root = runtime.authorized_root().clone();
        let root = EntityId::new("endpoint:https://fixture.test/").unwrap();
        let mut observation = safe_observation(root.as_str());
        observation.hsts = absent();
        let ledger = CommittedAssessmentPassiveLedger {
            observations: vec![observation.clone()],
            receipt_evidence: BTreeMap::new(),
        };
        let knowledge = KnowledgeBase::new();
        commit_planned_evidence(&knowledge, &root, &observation, true);

        let projection =
            project_passive_assessment_items(&ledger, &knowledge, &authorized_root).unwrap();
        let repeated_projection =
            project_passive_assessment_items(&ledger, &knowledge, &authorized_root).unwrap();
        let (set, incomplete) = projection.into_parts();
        let (repeated_set, repeated_incomplete) = repeated_projection.into_parts();
        assert!(!incomplete.is_incomplete());
        assert!(!repeated_incomplete.is_incomplete());
        let (subjects, items) = set.into_parts();
        let (repeated_subjects, repeated_items) = repeated_set.into_parts();
        assert_eq!(subjects.len(), 1);
        assert_eq!(
            subjects[0].fingerprint(),
            repeated_subjects[0].fingerprint()
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].fingerprint(), repeated_items[0].fingerprint());
        assert_eq!(items[0].disposition(), AssessmentDisposition::Informational);
        assert_eq!(items[0].severity(), None);
        assert_eq!(items[0].cwe(), None);
        assert!(matches!(items[0].basis(), AssessmentBasis::Observation(_)));
        assert_eq!(items[0].capability_id(), "web.passive.hsts.missing@1");
    }

    #[test]
    fn non_root_conditions_are_typed_incompleteness_without_url_identity() {
        let root = EntityId::new("endpoint:https://fixture.test/").unwrap();
        let mut discovered = safe_observation("endpoint:https://fixture.test/private/path");
        discovered.hsts = absent();
        let ledger = CommittedAssessmentPassiveLedger {
            observations: vec![discovered],
            receipt_evidence: BTreeMap::new(),
        };
        let projection = project_passive_assessment_items_for_root(
            &ledger,
            &KnowledgeBase::new(),
            Some(root),
            "https://fixture.test",
            &[],
            true,
        )
        .unwrap();
        let (set, incomplete) = projection.into_parts();
        let (_, items) = set.into_parts();
        assert!(items.is_empty());
        assert_eq!(incomplete.non_root_observations(), 1);
        assert_eq!(incomplete.non_root_conditions(), 1);
        assert!(incomplete.is_incomplete());
        let debug = format!("{incomplete:?}");
        assert!(!debug.contains("private/path"));
    }

    #[test]
    fn non_origin_root_starting_paths_never_receive_the_implicit_root_identity() {
        let secret_paths = [
            "https://fixture.test/a/Bearer-SUPER-SECRET",
            "https://fixture.test/b/password=DO-NOT-RETAIN",
        ];

        for target in secret_paths {
            let runtime = WebAssessmentRuntime::builder(url::Url::parse(target).unwrap())
                .build()
                .expect("assessment runtime");
            let authorized_root = runtime.authorized_root().clone();
            let runtime_subject =
                EntityId::new(format!("endpoint:{}", authorized_root.url())).unwrap();
            let mut observation = safe_observation(runtime_subject.as_str());
            observation.hsts = absent();
            let ledger = CommittedAssessmentPassiveLedger {
                observations: vec![observation],
                receipt_evidence: BTreeMap::new(),
            };

            let projection =
                project_passive_assessment_items(&ledger, &KnowledgeBase::new(), &authorized_root)
                    .expect("non-root resources fail closed without a stable identity");
            let projection_debug = format!("{projection:?}");
            let (set, incomplete) = projection.into_parts();
            let set_debug = format!("{set:?}");
            let (subjects, items) = set.into_parts();

            assert!(subjects.is_empty(), "no subject fingerprint may be minted");
            assert!(items.is_empty(), "non-root observations are not projected");
            assert!(incomplete.is_incomplete());
            assert_eq!(incomplete.non_root_observations(), 1);
            assert_eq!(incomplete.non_root_conditions(), 1);
            for secret in ["Bearer-SUPER-SECRET", "password=DO-NOT-RETAIN"] {
                assert!(!projection_debug.contains(secret));
                assert!(!set_debug.contains(secret));
                assert!(!format!("{incomplete:?}").contains(secret));
            }
        }
    }

    #[test]
    fn passive_cookie_debug_and_items_never_expose_cookie_identity() {
        let mut observation = safe_observation("endpoint:https://fixture.test/");
        observation.cookies = parsed(vec![CommittedCookieMetadata {
            name: "do-not-display-session-name".to_owned(),
            secure: true,
            http_only: false,
            same_site: PassiveCookieSameSite::Strict,
            domain_attribute_present: false,
            path_attribute_present: true,
        }]);
        observation.property_evidence = property_evidence(1);
        let debug = format!("{observation:?}");
        assert!(!debug.contains("do-not-display-session-name"));
        let planned = passive_conditions(&observation, true).unwrap();
        assert_eq!(
            planned
                .iter()
                .map(|item| item.condition)
                .collect::<Vec<_>>(),
            vec![PassiveAssessmentCondition::CookieHttpOnlyNotSet]
        );
        let descriptor_debug = format!("{:?}", planned[0].condition.capability());
        assert!(!descriptor_debug.contains("do-not-display-session-name"));
    }
}
