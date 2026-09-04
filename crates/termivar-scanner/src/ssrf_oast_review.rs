//! Pure, bounded contracts for query-only repeated-callback SSRF review.
//!
//! This module performs no I/O. It validates the operator policy, reduces one
//! structurally eligible query position, prepares three exact request targets,
//! derives correlation material from caller-owned entropy, and evaluates
//! raw-free lifecycle facts. Transport authority remains with
//! `WebAssessmentRuntime`.

use std::{fmt, mem, str::FromStr};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use termivar_oast::{CallbackId, CallbackTarget, NativeOastRoute, PublicOrigin};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroize;

use crate::oast::{OastAuthorityEpoch, OastCorrelationToken, OastEventKey};
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
use crate::openapi_review::{
    OpenApiDocument, OpenApiFormatClass, OpenApiHttpMethod, OpenApiOperation,
    OpenApiParameterLocation, OpenApiServerKind,
};

/// Exact purpose-oriented policy schema implemented by V1.
pub const SSRF_OAST_REVIEW_POLICY_SCHEMA: &str = "security.ssrf-oast-review-policy/v1";
/// Semantic revision for policy, candidate, mutation, and result identities.
pub const SSRF_OAST_REVIEW_ALGORITHM: &str = "security.ssrf-oast-query-review/v1";
/// Hard policy-source ceiling.
pub const MAX_SSRF_OAST_REVIEW_POLICY_BYTES: usize = 64 * 1024;
/// V1 selects at most one resource.
pub const MAX_SSRF_OAST_REVIEW_RESOURCES: usize = 1;
/// V1 selects at most one query parameter.
pub const MAX_SSRF_OAST_REVIEW_PARAMETERS: usize = 1;
/// V1 executes one query mutation family.
pub const MAX_SSRF_OAST_REVIEW_FAMILIES: usize = 1;
/// Control, Candidate, and Replay are the exact target request plan.
pub const SSRF_OAST_TARGET_REQUESTS: usize = 3;
/// V1 owns one logical active verification.
pub const SSRF_OAST_ACTIVE_VERIFICATIONS: usize = 1;
/// Register, two allocations, preflight, at most seven post-dispatch polls, and cleanup.
pub const MAX_SSRF_OAST_PROVIDER_REQUESTS: usize = 12;
/// Minimum polls allowed for each dispatched callback leg.
pub const MIN_SSRF_OAST_POLLS_PER_LEG: u16 = 1;
/// Maximum polls allowed for each dispatched callback leg.
pub const MAX_SSRF_OAST_POLLS_PER_LEG: u16 = 4;
/// Minimum interval between bounded polls.
pub const MIN_SSRF_OAST_POLL_INTERVAL_MS: u64 = 250;
/// Maximum interval between bounded polls.
pub const MAX_SSRF_OAST_POLL_INTERVAL_MS: u64 = 2_000;
/// Minimum provider session lifetime.
pub const MIN_SSRF_OAST_LIFETIME_MS: u64 = 5_000;
/// Maximum provider session lifetime.
pub const MAX_SSRF_OAST_LIFETIME_MS: u64 = 30_000;
/// Minimum administrator bearer-token bytes.
pub const MIN_SSRF_OAST_ADMIN_TOKEN_BYTES: usize = 32;
/// Maximum administrator bearer-token bytes.
pub const MAX_SSRF_OAST_ADMIN_TOKEN_BYTES: usize = 4_096;

const MAX_TARGET_BYTES: usize = 8 * 1024;
const MAX_SUBJECT_IDENTITY_BYTES: usize = 512;
const MAX_PARAMETER_NAME_BYTES: usize = 256;
const POLICY_ID_DOMAIN: &[u8] = b"security.ssrf-oast-review-policy.identity.v1\0";
const RESOURCE_ID_DOMAIN: &[u8] = b"security.ssrf-oast-review-resource.v1\0";
const PARAMETER_ID_DOMAIN: &[u8] = b"security.ssrf-oast-review-parameter.v1\0";
const SELECTION_ID_DOMAIN: &[u8] = b"security.ssrf-oast-review-selection.v1\0";
const CONTROL_LABEL_DOMAIN: &[u8] = b"security.ssrf-oast-review-control-label.v1\0";
const EPOCH_DOMAIN: &[u8] = b"security.ssrf-oast-review-authority-epoch.v1\0";
const CANDIDATE_TOKEN_DOMAIN: &[u8] = b"security.ssrf-oast-review-candidate-token.v1\0";
const REPLAY_TOKEN_DOMAIN: &[u8] = b"security.ssrf-oast-review-replay-token.v1\0";
const CALLBACK_ID_DOMAIN: &[u8] = b"security.ssrf-oast-review-callback-id.v1\0";
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
const OPENAPI_PARAMETER_NAME_DOMAIN: &[u8] = b"openapi-parameter-name/v1";

/// Stable non-secret digest of one validated policy.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SsrfOastPolicyId([u8; 32]);

impl SsrfOastPolicyId {
    /// Returns a stable pseudonymous wire identity.
    pub fn to_wire(self) -> String {
        format!("ssrf-oast-policy-sha256:{}", hex(self.0))
    }

    /// Returns the domain-separated digest bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SsrfOastPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl fmt::Display for SsrfOastPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

/// Strict operator authorization for one target origin and one OAST provider.
pub struct SsrfOastReviewPolicy {
    target_origin: Url,
    provider_origin: PublicOrigin,
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
    policy_id: SsrfOastPolicyId,
}

impl SsrfOastReviewPolicy {
    /// Parses strict TOML and binds it to the assessment's exact origin.
    pub fn parse_toml(
        assessment_target: &Url,
        source: &[u8],
    ) -> Result<Self, SsrfOastReviewPolicyError> {
        if source.len() > MAX_SSRF_OAST_REVIEW_POLICY_BYTES {
            return Err(SsrfOastReviewPolicyError::PolicyTooLarge);
        }
        let source =
            std::str::from_utf8(source).map_err(|_| SsrfOastReviewPolicyError::MalformedPolicy)?;
        let wire: WirePolicy =
            toml::from_str(source).map_err(|_| SsrfOastReviewPolicyError::MalformedPolicy)?;
        if wire.schema != SSRF_OAST_REVIEW_POLICY_SCHEMA {
            return Err(SsrfOastReviewPolicyError::UnsupportedSchema);
        }
        if !wire.acknowledge_external_interaction {
            return Err(SsrfOastReviewPolicyError::AcknowledgementRequired);
        }
        if !(MIN_SSRF_OAST_POLLS_PER_LEG..=MAX_SSRF_OAST_POLLS_PER_LEG)
            .contains(&wire.polls_per_leg)
            || !(MIN_SSRF_OAST_POLL_INTERVAL_MS..=MAX_SSRF_OAST_POLL_INTERVAL_MS)
                .contains(&wire.poll_interval_ms)
            || !(MIN_SSRF_OAST_LIFETIME_MS..=MAX_SSRF_OAST_LIFETIME_MS).contains(&wire.lifetime_ms)
        {
            return Err(SsrfOastReviewPolicyError::InvalidLimits);
        }

        let assessment_origin = canonical_target_origin(assessment_target)
            .ok_or(SsrfOastReviewPolicyError::TargetOriginMismatch)?;
        let target_origin = parse_declared_target_origin(&wire.target_origin)?;
        if !same_origin(&assessment_origin, &target_origin) {
            return Err(SsrfOastReviewPolicyError::TargetOriginMismatch);
        }
        let provider_origin = PublicOrigin::from_str(&wire.provider_origin)
            .map_err(|_| SsrfOastReviewPolicyError::InvalidProviderOrigin)?;
        let provider_url = Url::parse(provider_origin.as_str())
            .map_err(|_| SsrfOastReviewPolicyError::InvalidProviderOrigin)?;
        if same_origin(&target_origin, &provider_url) {
            return Err(SsrfOastReviewPolicyError::ProviderOriginMatchesTarget);
        }

        let policy_id = policy_identity(
            &target_origin,
            &provider_url,
            wire.polls_per_leg,
            wire.poll_interval_ms,
            wire.lifetime_ms,
        );
        Ok(Self {
            target_origin,
            provider_origin,
            polls_per_leg: wire.polls_per_leg,
            poll_interval_ms: wire.poll_interval_ms,
            lifetime_ms: wire.lifetime_ms,
            policy_id,
        })
    }

    /// Constructs the same bounded policy around a repository-owned loopback
    /// provider fixture. Production callers cannot access this seam and still
    /// must pass the strict HTTPS/DNS TOML parser above.
    #[cfg(test)]
    pub(crate) fn for_loopback(
        target_origin: Url,
        provider_origin: PublicOrigin,
        polls_per_leg: u16,
        poll_interval_ms: u64,
        lifetime_ms: u64,
    ) -> Result<Self, SsrfOastReviewPolicyError> {
        if !(MIN_SSRF_OAST_POLLS_PER_LEG..=MAX_SSRF_OAST_POLLS_PER_LEG).contains(&polls_per_leg)
            || !(MIN_SSRF_OAST_POLL_INTERVAL_MS..=MAX_SSRF_OAST_POLL_INTERVAL_MS)
                .contains(&poll_interval_ms)
            || !(MIN_SSRF_OAST_LIFETIME_MS..=MAX_SSRF_OAST_LIFETIME_MS).contains(&lifetime_ms)
        {
            return Err(SsrfOastReviewPolicyError::InvalidLimits);
        }
        let target_origin = canonical_target_origin(&target_origin)
            .ok_or(SsrfOastReviewPolicyError::TargetOriginMismatch)?;
        let provider_url = Url::parse(provider_origin.as_str())
            .map_err(|_| SsrfOastReviewPolicyError::InvalidProviderOrigin)?;
        if same_origin(&target_origin, &provider_url) {
            return Err(SsrfOastReviewPolicyError::ProviderOriginMatchesTarget);
        }
        let policy_id = policy_identity(
            &target_origin,
            &provider_url,
            polls_per_leg,
            poll_interval_ms,
            lifetime_ms,
        );
        Ok(Self {
            target_origin,
            provider_origin,
            polls_per_leg,
            poll_interval_ms,
            lifetime_ms,
            policy_id,
        })
    }

    /// Returns the stable policy identity.
    pub const fn policy_id(&self) -> SsrfOastPolicyId {
        self.policy_id
    }

    /// Returns the exact bounded polls allowed for each callback leg.
    pub const fn polls_per_leg(&self) -> u16 {
        self.polls_per_leg
    }

    /// Returns the configured poll interval.
    pub const fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }

    /// Returns the configured provider session lifetime.
    pub const fn lifetime_ms(&self) -> u64 {
        self.lifetime_ms
    }

    /// Returns the validated target origin only to the in-crate runtime.
    pub(crate) const fn target_origin(&self) -> &Url {
        &self.target_origin
    }

    /// Returns the validated provider origin only to the in-crate runtime.
    pub(crate) const fn provider_origin(&self) -> &PublicOrigin {
        &self.provider_origin
    }
}

impl fmt::Debug for SsrfOastReviewPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SsrfOastReviewPolicy")
            .field("target_origin", &"<redacted>")
            .field("provider_origin", &"<redacted>")
            .field("polls_per_leg", &self.polls_per_leg)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("lifetime_ms", &self.lifetime_ms)
            .field("policy_id", &self.policy_id)
            .finish()
    }
}

/// Static, value-free policy validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SsrfOastReviewPolicyError {
    /// Input exceeded the compiled source ceiling.
    #[error("SSRF OAST review policy exceeds its compiled byte limit")]
    PolicyTooLarge,
    /// TOML, UTF-8, required fields, or scalar types were invalid.
    #[error("SSRF OAST review policy is malformed")]
    MalformedPolicy,
    /// The policy schema is not implemented.
    #[error("SSRF OAST review policy schema is unsupported")]
    UnsupportedSchema,
    /// Explicit external-interaction authorization was absent.
    #[error("SSRF OAST review requires explicit external-interaction acknowledgement")]
    AcknowledgementRequired,
    /// One of the fixed V1 scheduling limits was outside its range.
    #[error("SSRF OAST review scheduling limits are invalid")]
    InvalidLimits,
    /// The declared target was not the assessment's exact origin.
    #[error("SSRF OAST review target does not match exact-origin authority")]
    TargetOriginMismatch,
    /// The provider was not one exact public HTTPS DNS origin.
    #[error("SSRF OAST review provider origin is invalid")]
    InvalidProviderOrigin,
    /// Provider and target origins must be distinct.
    #[error("SSRF OAST review provider origin must differ from target origin")]
    ProviderOriginMatchesTarget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema: String,
    target_origin: String,
    provider_origin: String,
    acknowledge_external_interaction: bool,
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
}

/// Move-only administrator credential accepted only through the CLI secret boundary.
pub struct SsrfOastAdminToken {
    bytes: Vec<u8>,
}

impl SsrfOastAdminToken {
    /// Validates bounded visible ASCII suitable for one Bearer credential.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, SsrfOastAdminTokenError> {
        let valid = (MIN_SSRF_OAST_ADMIN_TOKEN_BYTES..=MAX_SSRF_OAST_ADMIN_TOKEN_BYTES)
            .contains(&bytes.len())
            && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte));
        if !valid {
            bytes.zeroize();
            return Err(SsrfOastAdminTokenError::Invalid);
        }
        Ok(Self { bytes })
    }

    /// Consumes the wrapper at the fixed native-provider request boundary.
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        mem::take(&mut self.bytes)
    }
}

impl fmt::Debug for SsrfOastAdminToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SsrfOastAdminToken(<redacted>)")
    }
}

impl Drop for SsrfOastAdminToken {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Static credential validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SsrfOastAdminTokenError {
    /// The supplied bytes were not one bounded visible-ASCII credential.
    #[error("SSRF OAST administrator token is invalid")]
    Invalid,
}

/// Structural evidence source used solely for deterministic ranking.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SsrfOastCandidateSource {
    /// A replay-stable exact-origin resource already carried an absolute URL value.
    ObservedUrlQuery,
    /// A replay-stable OpenAPI operation declared one optional URL/URI query.
    #[cfg(feature = "openapi-review")]
    OpenApiOptionalUrlQuery,
}

impl SsrfOastCandidateSource {
    #[cfg(feature = "openapi-review")]
    const fn rank(self) -> u8 {
        match self {
            Self::ObservedUrlQuery => 0,
            #[cfg(feature = "openapi-review")]
            Self::OpenApiOptionalUrlQuery => 1,
        }
    }

    /// Stable audit token without a parameter name or URL.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedUrlQuery => "observed_url_query",
            #[cfg(feature = "openapi-review")]
            Self::OpenApiOptionalUrlQuery => "openapi_optional_url_query",
        }
    }
}

/// Result of bounded structural candidate selection.
pub(crate) enum SsrfOastCandidateSelection {
    /// One deterministic query position was selected.
    Selected(Box<SsrfOastQueryCandidate>),
    /// No input proved the exact V1 structural contract.
    NotEligible,
}

impl fmt::Debug for SsrfOastCandidateSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(candidate) => {
                formatter.debug_tuple("Selected").field(candidate).finish()
            },
            Self::NotEligible => formatter.write_str("NotEligible"),
        }
    }
}

/// One private exact query position; all public identities are pseudonymous.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SsrfOastQueryCandidate {
    source: SsrfOastCandidateSource,
    execution_resource: Url,
    parameter_name: String,
    selected_pair_index: Option<usize>,
    parameter_id: String,
    selection_id: String,
    subject_identity: String,
}

impl SsrfOastQueryCandidate {
    /// Returns the structural source class.
    pub(crate) const fn source(&self) -> SsrfOastCandidateSource {
        self.source
    }

    /// Returns a pseudonymous selected-parameter identity.
    pub(crate) fn parameter_id(&self) -> &str {
        &self.parameter_id
    }

    /// Returns the stable selection identity used for exact case correlation.
    pub(crate) fn selection_id(&self) -> &str {
        &self.selection_id
    }

    /// Returns the already-authorized target only to the parent runtime.
    pub(crate) const fn execution_resource(&self) -> &Url {
        &self.execution_resource
    }

    /// Materializes the inert control target before any provider session exists.
    pub(crate) fn control_execution_url(
        &self,
        control_seed: [u8; 32],
    ) -> Result<Url, SsrfOastContractError> {
        if control_seed.iter().all(|byte| *byte == 0) {
            return Err(SsrfOastContractError::InvalidControlSeed);
        }
        let control_payload = inert_control_url(control_seed, self.selection_id())?;
        let control = materialize_query(self, control_payload.as_str())?;
        if !same_origin(&self.execution_resource, &control)
            || self.execution_resource.path() != control.path()
        {
            return Err(SsrfOastContractError::MutationInvariant);
        }
        Ok(control)
    }
}

impl fmt::Debug for SsrfOastQueryCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SsrfOastQueryCandidate")
            .field("source", &self.source)
            .field("execution_resource", &"<redacted>")
            .field("parameter_name", &"<redacted>")
            .field("parameter_id", &self.parameter_id)
            .field("selection_id", &self.selection_id)
            .finish()
    }
}

/// Selects one observed, replay-stable absolute URL-valued query position.
pub(crate) fn select_observed_query_candidate(
    assessment_origin: &Url,
    resource: &Url,
    subject_identity: &str,
    complete: bool,
    replay_stable: bool,
    defense_clear: bool,
) -> SsrfOastCandidateSelection {
    if !complete
        || !replay_stable
        || !defense_clear
        || !valid_subject_identity(subject_identity)
        || !safe_exact_origin_resource(assessment_origin, resource)
    {
        return SsrfOastCandidateSelection::NotEligible;
    }
    let Some(query) = resource.query() else {
        return SsrfOastCandidateSelection::NotEligible;
    };
    let Ok(pairs) = parse_query_pairs(query) else {
        return SsrfOastCandidateSelection::NotEligible;
    };
    let mut eligible = Vec::new();
    for (index, pair) in pairs.iter().enumerate() {
        if pairs
            .iter()
            .filter(|candidate| candidate.name == pair.name)
            .count()
            != 1
            || !valid_parameter_name(&pair.name)
            || !absolute_http_url_value(&pair.value)
        {
            continue;
        }
        eligible.push(build_candidate(
            SsrfOastCandidateSource::ObservedUrlQuery,
            resource.clone(),
            pair.name.clone(),
            Some(index),
            subject_identity,
            index,
        ));
    }
    if eligible.len() != MAX_SSRF_OAST_REVIEW_PARAMETERS {
        return SsrfOastCandidateSelection::NotEligible;
    }
    SsrfOastCandidateSelection::Selected(Box::new(eligible.remove(0)))
}

/// Validates a private OpenAPI name/execution bridge against reduced catalog metadata.
///
/// The OpenAPI catalog intentionally publishes only a name fingerprint. The
/// caller must obtain `parameter_name` from the same private parse boundary;
/// this function proves it matches the retained fingerprint before use.
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
pub(crate) fn select_openapi_query_candidate(
    assessment_origin: &Url,
    execution_url: &Url,
    operation: &OpenApiOperation,
    parameter_name: &str,
    document_complete: bool,
    replay_stable: bool,
    defense_clear: bool,
) -> SsrfOastCandidateSelection {
    if !document_complete
        || !replay_stable
        || !defense_clear
        || operation.method() != OpenApiHttpMethod::Get
        || operation.request_body_declared()
        || !operation.security().permits_anonymous()
        || operation
            .parameters()
            .iter()
            .any(|parameter| parameter.required())
        || operation.path().contains(['{', '}'])
        || operation.servers().iter().any(|server| {
            matches!(
                server.kind(),
                OpenApiServerKind::CrossOrigin
                    | OpenApiServerKind::Templated
                    | OpenApiServerKind::Unsupported
            )
        })
        || !valid_parameter_name(parameter_name)
        || !safe_exact_origin_resource(assessment_origin, execution_url)
        || execution_url.query().is_some()
        || !execution_url.path().ends_with(operation.path())
    {
        return SsrfOastCandidateSelection::NotEligible;
    }

    let url_parameters = operation
        .parameters()
        .iter()
        .enumerate()
        .filter(|(_, parameter)| {
            parameter.location() == OpenApiParameterLocation::Query
                && !parameter.required()
                && matches!(
                    parameter.format_class(),
                    OpenApiFormatClass::Uri | OpenApiFormatClass::Url
                )
        })
        .collect::<Vec<_>>();
    let [(position, metadata)] = url_parameters.as_slice() else {
        return SsrfOastCandidateSelection::NotEligible;
    };
    if digest_bytes(OPENAPI_PARAMETER_NAME_DOMAIN, parameter_name.as_bytes())
        != *metadata.name_fingerprint()
    {
        return SsrfOastCandidateSelection::NotEligible;
    }

    SsrfOastCandidateSelection::Selected(Box::new(build_candidate(
        SsrfOastCandidateSource::OpenApiOptionalUrlQuery,
        execution_url.clone(),
        parameter_name.to_owned(),
        None,
        operation.id().as_str(),
        *position,
    )))
}

/// Reduces one complete OpenAPI catalog to its deterministic SSRF OAST query candidate.
///
/// URL construction stays in this transport-neutral domain boundary. The OpenAPI
/// runtime only hands over the replay-validated document and cannot gain described-
/// operation execution authority from the catalog.
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
pub(crate) fn select_openapi_document_query_candidate(
    document: &OpenApiDocument,
    document_url: &Url,
) -> Option<SsrfOastQueryCandidate> {
    let mut selected = None;
    for operation in document.catalog().operations() {
        let Some(execution_url) = openapi_operation_target(document_url, operation) else {
            continue;
        };
        for parameter in operation.parameters() {
            let SsrfOastCandidateSelection::Selected(candidate) = select_openapi_query_candidate(
                document_url,
                &execution_url,
                operation,
                parameter.execution_name(),
                true,
                true,
                true,
            ) else {
                continue;
            };
            selected = match choose_ssrf_oast_query_candidate(selected, Some(*candidate)) {
                SsrfOastCandidateSelection::Selected(candidate) => Some(*candidate),
                SsrfOastCandidateSelection::NotEligible => None,
            };
        }
    }
    selected
}

#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
fn openapi_operation_target(document_url: &Url, operation: &OpenApiOperation) -> Option<Url> {
    let mut base = match operation.servers() {
        [] => {
            let mut root = document_url.clone();
            root.set_path("/");
            root.set_query(None);
            root.set_fragment(None);
            root
        },
        [server] => server.execution_base()?.clone(),
        _ => return None,
    };
    let base_path = base.path().trim_end_matches('/');
    let path = if base_path.is_empty() {
        operation.path().to_owned()
    } else {
        format!("{base_path}{}", operation.path())
    };
    if !path.starts_with('/')
        || path.contains(['?', '#', '%', '\\', '\r', '\n', '\0'])
        || path.contains("//")
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return None;
    }
    base.set_path(&path);
    base.set_query(None);
    base.set_fragment(None);
    (base.origin() == document_url.origin()).then_some(base)
}

/// Chooses at most one candidate with observed evidence ranked first.
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
pub(crate) fn choose_ssrf_oast_query_candidate(
    observed: Option<SsrfOastQueryCandidate>,
    openapi: Option<SsrfOastQueryCandidate>,
) -> SsrfOastCandidateSelection {
    let mut candidates = observed.into_iter().chain(openapi).collect::<Vec<_>>();
    candidates.sort_by(candidate_order);
    candidates.into_iter().next().map_or_else(
        || SsrfOastCandidateSelection::NotEligible,
        |candidate| SsrfOastCandidateSelection::Selected(Box::new(candidate)),
    )
}

#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
fn candidate_order(
    left: &SsrfOastQueryCandidate,
    right: &SsrfOastQueryCandidate,
) -> std::cmp::Ordering {
    left.source
        .rank()
        .cmp(&right.source.rank())
        .then(
            left.execution_resource
                .path()
                .len()
                .cmp(&right.execution_resource.path().len()),
        )
        .then(left.subject_identity.cmp(&right.subject_identity))
        .then(left.parameter_id.cmp(&right.parameter_id))
}

fn build_candidate(
    source: SsrfOastCandidateSource,
    execution_resource: Url,
    parameter_name: String,
    selected_pair_index: Option<usize>,
    subject_identity: &str,
    parameter_position: usize,
) -> SsrfOastQueryCandidate {
    let resource_id = prefixed_digest(
        "ssrf-oast-resource-sha256:",
        RESOURCE_ID_DOMAIN,
        &[
            canonical_origin_string(&execution_resource).as_bytes(),
            execution_resource.path().as_bytes(),
        ],
    );
    let position = u64::try_from(parameter_position)
        .unwrap_or(u64::MAX)
        .to_be_bytes();
    let parameter_id = prefixed_digest(
        "ssrf-oast-parameter-sha256:",
        PARAMETER_ID_DOMAIN,
        &[resource_id.as_bytes(), parameter_name.as_bytes(), &position],
    );
    let selection_id = prefixed_digest(
        "ssrf-oast-selection-sha256:",
        SELECTION_ID_DOMAIN,
        &[
            source.as_str().as_bytes(),
            subject_identity.as_bytes(),
            resource_id.as_bytes(),
            parameter_id.as_bytes(),
        ],
    );
    SsrfOastQueryCandidate {
        source,
        execution_resource,
        parameter_name,
        selected_pair_index,
        parameter_id,
        selection_id,
        subject_identity: subject_identity.to_owned(),
    }
}

/// Exact target leg for the single logical review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SsrfOastTargetLeg {
    /// First independently allocated provider callback.
    Candidate,
    /// Second independently allocated provider callback.
    Replay,
}

/// Three private bodyless GET targets with a redacted debug boundary.
pub(crate) struct SsrfOastMutationPlan {
    candidate: Url,
    replay: Url,
}

impl SsrfOastMutationPlan {
    /// Validates two native callback targets and materializes the exact plan.
    pub(crate) fn new(
        selected: SsrfOastQueryCandidate,
        control_seed: [u8; 32],
        candidate_target: &CallbackTarget,
        replay_target: &CallbackTarget,
        provider_origin: &PublicOrigin,
    ) -> Result<Self, SsrfOastContractError> {
        Self::from_callback_strings(
            selected,
            control_seed,
            candidate_target.as_str(),
            replay_target.as_str(),
            provider_origin,
        )
    }

    /// Test-only constructor for the repository-owned cleartext numeric
    /// loopback provider fixture. Production callback targets still pass only
    /// through [`Self::new`] and its exact public-HTTPS origin contract.
    #[cfg(test)]
    pub(crate) fn new_for_loopback(
        selected: SsrfOastQueryCandidate,
        control_seed: [u8; 32],
        candidate_target: &CallbackTarget,
        replay_target: &CallbackTarget,
        provider_origin: &PublicOrigin,
    ) -> Result<Self, SsrfOastContractError> {
        let provider = Url::parse(provider_origin.as_str())
            .map_err(|_| SsrfOastContractError::InvalidCallbackTarget)?;
        if !is_http_loopback_origin(&provider) {
            return Err(SsrfOastContractError::InvalidCallbackTarget);
        }
        Self::from_callback_strings_inner(
            selected,
            control_seed,
            candidate_target.as_str(),
            replay_target.as_str(),
            provider_origin,
            true,
        )
    }

    /// Crate-private pure seam for owned fuzz/property replay. Production
    /// execution uses [`Self::new`] with move-only provider targets.
    pub(crate) fn from_callback_strings(
        selected: SsrfOastQueryCandidate,
        control_seed: [u8; 32],
        candidate_target: &str,
        replay_target: &str,
        provider_origin: &PublicOrigin,
    ) -> Result<Self, SsrfOastContractError> {
        Self::from_callback_strings_inner(
            selected,
            control_seed,
            candidate_target,
            replay_target,
            provider_origin,
            false,
        )
    }

    fn from_callback_strings_inner(
        selected: SsrfOastQueryCandidate,
        control_seed: [u8; 32],
        candidate_target: &str,
        replay_target: &str,
        provider_origin: &PublicOrigin,
        allow_test_loopback: bool,
    ) -> Result<Self, SsrfOastContractError> {
        if candidate_target == replay_target {
            return Err(SsrfOastContractError::CallbackIdentityConflict);
        }
        let candidate_callback =
            validate_callback_target(candidate_target, provider_origin, allow_test_loopback)?;
        let replay_callback =
            validate_callback_target(replay_target, provider_origin, allow_test_loopback)?;
        let control = selected.control_execution_url(control_seed)?;
        let candidate = materialize_query(&selected, candidate_callback.as_str())?;
        let replay = materialize_query(&selected, replay_callback.as_str())?;
        if candidate == replay
            || !same_origin(&selected.execution_resource, &control)
            || !same_origin(&selected.execution_resource, &candidate)
            || !same_origin(&selected.execution_resource, &replay)
            || selected.execution_resource.path() != control.path()
            || selected.execution_resource.path() != candidate.path()
            || selected.execution_resource.path() != replay.path()
        {
            return Err(SsrfOastContractError::MutationInvariant);
        }
        Ok(Self { candidate, replay })
    }

    /// Returns one exact target only to the shared target broker.
    pub(crate) const fn execution_url(&self, leg: SsrfOastTargetLeg) -> &Url {
        match leg {
            SsrfOastTargetLeg::Candidate => &self.candidate,
            SsrfOastTargetLeg::Replay => &self.replay,
        }
    }
}

impl fmt::Debug for SsrfOastMutationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SsrfOastMutationPlan")
            .field("candidate", &"<redacted>")
            .field("replay", &"<redacted>")
            .finish()
    }
}

/// Three domain-separated correlation secrets derived from host entropy.
pub(crate) struct SsrfOastCorrelationMaterial {
    epoch: OastAuthorityEpoch,
    candidate: OastCorrelationToken,
    replay: OastCorrelationToken,
}

/// Exact non-secret runtime identities bound into all three correlation values.
pub(crate) struct SsrfOastCorrelationBinding<'a> {
    assessment_identity: &'a str,
    action_identity: &'a str,
    case_identity: &'a str,
}

impl<'a> SsrfOastCorrelationBinding<'a> {
    /// Creates one borrowed binding; [`SsrfOastCorrelationMaterial::derive`]
    /// performs the static bounded validation.
    pub(crate) const fn new(
        assessment_identity: &'a str,
        action_identity: &'a str,
        case_identity: &'a str,
    ) -> Self {
        Self {
            assessment_identity,
            action_identity,
            case_identity,
        }
    }
}

/// Three independent caller-owned entropy values.
pub(crate) struct SsrfOastCorrelationEntropy {
    epoch: [u8; 32],
    candidate: [u8; 32],
    replay: [u8; 32],
}

impl SsrfOastCorrelationEntropy {
    /// Wraps entropy minted by the host's cryptographically secure source.
    pub(crate) const fn new(epoch: [u8; 32], candidate: [u8; 32], replay: [u8; 32]) -> Self {
        Self {
            epoch,
            candidate,
            replay,
        }
    }
}

impl Drop for SsrfOastCorrelationEntropy {
    fn drop(&mut self) {
        self.epoch.zeroize();
        self.candidate.zeroize();
        self.replay.zeroize();
    }
}

impl SsrfOastCorrelationMaterial {
    /// Binds independent caller entropy to exact policy/action/case semantics.
    pub(crate) fn derive(
        policy: &SsrfOastReviewPolicy,
        candidate: &SsrfOastQueryCandidate,
        binding: SsrfOastCorrelationBinding<'_>,
        entropy: SsrfOastCorrelationEntropy,
    ) -> Result<Self, SsrfOastContractError> {
        if !valid_binding_identity(binding.assessment_identity)
            || !valid_binding_identity(binding.action_identity)
            || !valid_binding_identity(binding.case_identity)
            || entropy.epoch.iter().all(|byte| *byte == 0)
            || entropy.candidate.iter().all(|byte| *byte == 0)
            || entropy.replay.iter().all(|byte| *byte == 0)
            || entropy.candidate == entropy.replay
        {
            return Err(SsrfOastContractError::InvalidCorrelationMaterial);
        }
        let context = [
            policy.policy_id.to_wire(),
            candidate.selection_id.clone(),
            binding.assessment_identity.to_owned(),
            binding.action_identity.to_owned(),
            binding.case_identity.to_owned(),
        ];
        let context = context.iter().map(String::as_bytes).collect::<Vec<_>>();
        let mut epoch_bytes = digest_parts(EPOCH_DOMAIN, &context, &entropy.epoch);
        let mut candidate_bytes =
            digest_parts(CANDIDATE_TOKEN_DOMAIN, &context, &entropy.candidate);
        let mut replay_bytes = digest_parts(REPLAY_TOKEN_DOMAIN, &context, &entropy.replay);
        if candidate_bytes == replay_bytes {
            epoch_bytes.zeroize();
            candidate_bytes.zeroize();
            replay_bytes.zeroize();
            return Err(SsrfOastContractError::InvalidCorrelationMaterial);
        }
        let epoch_result = OastAuthorityEpoch::new(epoch_bytes);
        epoch_bytes.zeroize();
        let candidate_result = OastCorrelationToken::new(candidate_bytes);
        candidate_bytes.zeroize();
        let replay_result = OastCorrelationToken::new(replay_bytes);
        replay_bytes.zeroize();
        let epoch = epoch_result.map_err(|_| SsrfOastContractError::InvalidCorrelationMaterial)?;
        let candidate =
            candidate_result.map_err(|_| SsrfOastContractError::InvalidCorrelationMaterial)?;
        let replay =
            replay_result.map_err(|_| SsrfOastContractError::InvalidCorrelationMaterial)?;
        Ok(Self {
            epoch,
            candidate,
            replay,
        })
    }

    /// Consumes all move-only correlation material exactly once.
    pub(crate) fn into_parts(
        self,
    ) -> (
        OastAuthorityEpoch,
        OastCorrelationToken,
        OastCorrelationToken,
    ) {
        (self.epoch, self.candidate, self.replay)
    }
}

impl fmt::Debug for SsrfOastCorrelationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SsrfOastCorrelationMaterial(<redacted>)")
    }
}

/// Runtime terminal condition, separate from target callback observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SsrfOastTerminalState {
    DefensiveInterference,
    RateLimited,
    ProviderAuthenticationFailed,
    MalformedProviderResponse,
    PollExhausted,
    Expired,
    Cancelled,
    BudgetExhausted,
    Incomplete,
    /// A timeout after a proven dispatch does not erase exact callback evidence.
    TargetTimeoutAfterDispatch,
}

/// Raw-free identity of one expected allocated callback.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SsrfOastCallbackIdentity([u8; 32]);

impl SsrfOastCallbackIdentity {
    /// Reduces a native opaque ID before it enters comparison state.
    pub(crate) fn from_native(callback_id: &CallbackId) -> Self {
        Self(digest_bytes(
            CALLBACK_ID_DOMAIN,
            callback_id.as_str().as_bytes(),
        ))
    }
}

impl fmt::Debug for SsrfOastCallbackIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SsrfOastCallbackIdentity(<redacted>)")
    }
}

/// Raw-free reduced provider event used by the pure comparator.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SsrfOastObservedEvent {
    callback: SsrfOastCallbackIdentity,
    event: [u8; 32],
}

impl SsrfOastObservedEvent {
    /// Reduces an adapter-owned raw-free event key for runtime comparison.
    pub(crate) fn from_reduced(callback_id: &CallbackId, event_key: &OastEventKey) -> Self {
        Self {
            callback: SsrfOastCallbackIdentity::from_native(callback_id),
            event: *event_key.as_bytes(),
        }
    }
}

impl fmt::Debug for SsrfOastObservedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SsrfOastObservedEvent(<redacted>)")
    }
}

/// Complete raw-free facts supplied by the single parent execution lifecycle.
pub(crate) struct SsrfOastReviewFacts {
    pub(crate) control_complete: bool,
    pub(crate) provider_registered: bool,
    pub(crate) allocations_complete: bool,
    pub(crate) preflight_clean: bool,
    pub(crate) candidate_dispatched: bool,
    pub(crate) replay_dispatched: bool,
    pub(crate) expected_candidate: SsrfOastCallbackIdentity,
    pub(crate) expected_replay: SsrfOastCallbackIdentity,
    pub(crate) candidate_event: Option<SsrfOastObservedEvent>,
    pub(crate) replay_event: Option<SsrfOastObservedEvent>,
    pub(crate) correlations_distinct: bool,
    pub(crate) same_correlation_scope: bool,
    pub(crate) duplicate_only_substitution: bool,
    pub(crate) cleanup_verified: bool,
    pub(crate) target_accounting_complete: bool,
    pub(crate) provider_accounting_complete: bool,
    pub(crate) truncated: bool,
    pub(crate) terminal: Option<SsrfOastTerminalState>,
}

impl SsrfOastReviewFacts {
    /// Starts a fail-closed fact set for two independently allocated callbacks.
    pub(crate) fn new(candidate: &CallbackId, replay: &CallbackId) -> Self {
        Self {
            control_complete: false,
            provider_registered: false,
            allocations_complete: false,
            preflight_clean: false,
            candidate_dispatched: false,
            replay_dispatched: false,
            expected_candidate: SsrfOastCallbackIdentity::from_native(candidate),
            expected_replay: SsrfOastCallbackIdentity::from_native(replay),
            candidate_event: None,
            replay_event: None,
            correlations_distinct: false,
            same_correlation_scope: false,
            duplicate_only_substitution: false,
            cleanup_verified: false,
            target_accounting_complete: false,
            provider_accounting_complete: false,
            truncated: false,
            terminal: None,
        }
    }
}

impl fmt::Debug for SsrfOastReviewFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SsrfOastReviewFacts")
            .field("control_complete", &self.control_complete)
            .field("provider_registered", &self.provider_registered)
            .field("allocations_complete", &self.allocations_complete)
            .field("preflight_clean", &self.preflight_clean)
            .field("candidate_dispatched", &self.candidate_dispatched)
            .field("replay_dispatched", &self.replay_dispatched)
            .field("candidate_event", &self.candidate_event.is_some())
            .field("replay_event", &self.replay_event.is_some())
            .field("correlations_distinct", &self.correlations_distinct)
            .field("same_correlation_scope", &self.same_correlation_scope)
            .field(
                "duplicate_only_substitution",
                &self.duplicate_only_substitution,
            )
            .field("cleanup_verified", &self.cleanup_verified)
            .field(
                "target_accounting_complete",
                &self.target_accounting_complete,
            )
            .field(
                "provider_accounting_complete",
                &self.provider_accounting_complete,
            )
            .field("truncated", &self.truncated)
            .field("terminal", &self.terminal)
            .finish()
    }
}

/// Typed, non-boolean conclusion of the pure repeated-callback contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum SsrfOastReviewOutcome {
    NotEligible,
    ControlIncomplete,
    RegistrationIncomplete,
    AllocationIncomplete,
    PreflightContaminated,
    TargetNotDispatched,
    NoCallback,
    CandidateOnly,
    ReplayOnly,
    WrongCallback,
    EventIdentityConflict,
    CorrelationMismatch,
    DuplicateOnly,
    CleanupIncomplete,
    DefensiveInterference,
    RateLimited,
    ProviderAuthenticationFailed,
    MalformedProviderResponse,
    PollExhausted,
    Expired,
    Cancelled,
    BudgetExhausted,
    Truncated,
    Incomplete,
    RepeatedCallbacksObserved,
}

impl SsrfOastReviewOutcome {
    /// Only the full repeated-callback conclusion may project the V1 item.
    pub(crate) const fn projects_item(self) -> bool {
        matches!(self, Self::RepeatedCallbacksObserved)
    }
}

/// Evaluates complete raw-free lifecycle facts without transport or timing inference.
pub(crate) fn evaluate_ssrf_oast_review(
    facts: &SsrfOastReviewFacts,
) -> Result<SsrfOastReviewOutcome, SsrfOastContractError> {
    if facts.expected_candidate == facts.expected_replay {
        return Err(SsrfOastContractError::CallbackIdentityConflict);
    }
    if let Some(terminal) = facts.terminal {
        let outcome = match terminal {
            SsrfOastTerminalState::DefensiveInterference => {
                SsrfOastReviewOutcome::DefensiveInterference
            },
            SsrfOastTerminalState::RateLimited => SsrfOastReviewOutcome::RateLimited,
            SsrfOastTerminalState::ProviderAuthenticationFailed => {
                SsrfOastReviewOutcome::ProviderAuthenticationFailed
            },
            SsrfOastTerminalState::MalformedProviderResponse => {
                SsrfOastReviewOutcome::MalformedProviderResponse
            },
            SsrfOastTerminalState::PollExhausted => SsrfOastReviewOutcome::PollExhausted,
            SsrfOastTerminalState::Expired => SsrfOastReviewOutcome::Expired,
            SsrfOastTerminalState::Cancelled => SsrfOastReviewOutcome::Cancelled,
            SsrfOastTerminalState::BudgetExhausted => SsrfOastReviewOutcome::BudgetExhausted,
            SsrfOastTerminalState::Incomplete => SsrfOastReviewOutcome::Incomplete,
            SsrfOastTerminalState::TargetTimeoutAfterDispatch => {
                // Exact callbacks, not timing, decide the positive relation.
                SsrfOastReviewOutcome::NotEligible
            },
        };
        if !matches!(terminal, SsrfOastTerminalState::TargetTimeoutAfterDispatch) {
            return Ok(outcome);
        }
    }
    if !facts.control_complete {
        return Ok(SsrfOastReviewOutcome::ControlIncomplete);
    }
    if !facts.provider_registered {
        return Ok(SsrfOastReviewOutcome::RegistrationIncomplete);
    }
    if !facts.allocations_complete {
        return Ok(SsrfOastReviewOutcome::AllocationIncomplete);
    }
    if !facts.preflight_clean {
        return Ok(SsrfOastReviewOutcome::PreflightContaminated);
    }
    if !facts.candidate_dispatched || !facts.replay_dispatched {
        return Ok(SsrfOastReviewOutcome::TargetNotDispatched);
    }
    if facts.duplicate_only_substitution {
        return Ok(SsrfOastReviewOutcome::DuplicateOnly);
    }
    let candidate_exact = facts
        .candidate_event
        .as_ref()
        .is_some_and(|event| event.callback == facts.expected_candidate);
    let replay_exact = facts
        .replay_event
        .as_ref()
        .is_some_and(|event| event.callback == facts.expected_replay);
    if facts.candidate_event.is_some() && !candidate_exact
        || facts.replay_event.is_some() && !replay_exact
    {
        return Ok(SsrfOastReviewOutcome::WrongCallback);
    }
    match (candidate_exact, replay_exact) {
        (false, false) => return Ok(SsrfOastReviewOutcome::NoCallback),
        (true, false) => return Ok(SsrfOastReviewOutcome::CandidateOnly),
        (false, true) => return Ok(SsrfOastReviewOutcome::ReplayOnly),
        (true, true) => {},
    }
    if facts
        .candidate_event
        .as_ref()
        .zip(facts.replay_event.as_ref())
        .is_some_and(|(candidate, replay)| candidate.event == replay.event)
    {
        return Ok(SsrfOastReviewOutcome::EventIdentityConflict);
    }
    if !facts.correlations_distinct || !facts.same_correlation_scope {
        return Ok(SsrfOastReviewOutcome::CorrelationMismatch);
    }
    if !facts.cleanup_verified {
        return Ok(SsrfOastReviewOutcome::CleanupIncomplete);
    }
    if facts.truncated {
        return Ok(SsrfOastReviewOutcome::Truncated);
    }
    if !facts.target_accounting_complete || !facts.provider_accounting_complete {
        return Ok(SsrfOastReviewOutcome::Incomplete);
    }
    Ok(SsrfOastReviewOutcome::RepeatedCallbacksObserved)
}

/// Static internal contract failure, never target behavior.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SsrfOastContractError {
    #[error("SSRF OAST control seed is invalid")]
    InvalidControlSeed,
    #[error("SSRF OAST callback target is invalid")]
    InvalidCallbackTarget,
    #[error("SSRF OAST callback identities must be distinct")]
    CallbackIdentityConflict,
    #[error("SSRF OAST query mutation contract is invalid")]
    MutationInvariant,
    #[error("SSRF OAST correlation material is invalid")]
    InvalidCorrelationMaterial,
}

#[derive(Clone)]
struct ParsedQueryPair {
    name: String,
    value: String,
}

fn parse_query_pairs(query: &str) -> Result<Vec<ParsedQueryPair>, ()> {
    if query.is_empty() || !valid_percent_encoding(query.as_bytes()) {
        return Err(());
    }
    let raw_pairs = query.split('&').collect::<Vec<_>>();
    if raw_pairs.iter().any(|pair| pair.is_empty()) {
        return Err(());
    }
    let decoded = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if decoded.len() != raw_pairs.len() {
        return Err(());
    }
    decoded
        .into_iter()
        .map(|(name, value)| {
            if name.is_empty() {
                Err(())
            } else {
                Ok(ParsedQueryPair {
                    name: name.into_owned(),
                    value: value.into_owned(),
                })
            }
        })
        .collect()
}

fn valid_percent_encoding(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn absolute_http_url_value(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn safe_exact_origin_resource(origin: &Url, resource: &Url) -> bool {
    resource.as_str().len() <= MAX_TARGET_BYTES
        && matches!(resource.scheme(), "http" | "https")
        && resource.host().is_some()
        && resource.username().is_empty()
        && resource.password().is_none()
        && resource.fragment().is_none()
        && same_origin(origin, resource)
        && safe_path(resource.path())
}

fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['\\', '\r', '\n', '\0'])
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn valid_subject_identity(identity: &str) -> bool {
    !identity.is_empty()
        && identity.len() <= MAX_SUBJECT_IDENTITY_BYTES
        && identity.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_binding_identity(identity: &str) -> bool {
    valid_subject_identity(identity)
}

fn valid_parameter_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PARAMETER_NAME_BYTES
        && name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !name.contains(['&', '=', '#'])
}

fn validate_callback_target(
    source: &str,
    provider_origin: &PublicOrigin,
    allow_test_loopback: bool,
) -> Result<Url, SsrfOastContractError> {
    let parsed = Url::parse(source).map_err(|_| SsrfOastContractError::InvalidCallbackTarget)?;
    let provider = Url::parse(provider_origin.as_str())
        .map_err(|_| SsrfOastContractError::InvalidCallbackTarget)?;
    let scheme_allowed =
        parsed.scheme() == "https" || (allow_test_loopback && is_http_loopback_origin(&parsed));
    if !scheme_allowed
        || !same_origin(&parsed, &provider)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(
            NativeOastRoute::from_str(parsed.path()),
            Ok(NativeOastRoute::Callback { .. })
        )
    {
        return Err(SsrfOastContractError::InvalidCallbackTarget);
    }
    Ok(parsed)
}

fn is_http_loopback_origin(url: &Url) -> bool {
    url.scheme() == "http"
        && match url.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        }
}

fn inert_control_url(seed: [u8; 32], selection_id: &str) -> Result<Url, SsrfOastContractError> {
    let digest = digest_parts(CONTROL_LABEL_DOMAIN, &[selection_id.as_bytes()], &seed);
    // Keep `c-` plus the opaque digest prefix within DNS's 63-byte label
    // ceiling. The retained 240 bits remain far beyond the case-uniqueness
    // requirement while producing a structurally valid inert hostname.
    let mut label = hex(digest);
    label.truncate(60);
    Url::parse(&format!("https://c-{label}.invalid/"))
        .map_err(|_| SsrfOastContractError::MutationInvariant)
}

fn materialize_query(
    selected: &SsrfOastQueryCandidate,
    replacement: &str,
) -> Result<Url, SsrfOastContractError> {
    let encoded = encode_query_component(replacement.as_bytes());
    let query = match (
        selected.execution_resource.query(),
        selected.selected_pair_index,
    ) {
        (Some(original), Some(selected_index)) => {
            let mut pairs = original.split('&').map(str::to_owned).collect::<Vec<_>>();
            let pair = pairs
                .get_mut(selected_index)
                .ok_or(SsrfOastContractError::MutationInvariant)?;
            let raw_name = pair.split_once('=').map_or(pair.as_str(), |(name, _)| name);
            *pair = format!("{raw_name}={encoded}");
            pairs.join("&")
        },
        (None, None) => format!(
            "{}={encoded}",
            encode_query_component(selected.parameter_name.as_bytes())
        ),
        _ => return Err(SsrfOastContractError::MutationInvariant),
    };
    let mut target = selected.execution_resource.clone();
    target.set_query(Some(&query));
    if target.query() != Some(query.as_str()) || target.as_str().len() > MAX_TARGET_BYTES {
        return Err(SsrfOastContractError::MutationInvariant);
    }
    Ok(target)
}

fn encode_query_component(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(3));
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn parse_declared_target_origin(source: &str) -> Result<Url, SsrfOastReviewPolicyError> {
    if source.is_empty() || source.len() > MAX_TARGET_BYTES || !source.is_ascii() {
        return Err(SsrfOastReviewPolicyError::TargetOriginMismatch);
    }
    let parsed = Url::parse(source).map_err(|_| SsrfOastReviewPolicyError::TargetOriginMismatch)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SsrfOastReviewPolicyError::TargetOriginMismatch);
    }
    Ok(parsed)
}

fn canonical_target_origin(source: &Url) -> Option<Url> {
    if !matches!(source.scheme(), "http" | "https")
        || source.host().is_none()
        || !source.username().is_empty()
        || source.password().is_some()
    {
        return None;
    }
    let mut origin = source.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    Some(origin)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && normalized_host(left) == normalized_host(right)
        && left.port_or_known_default() == right.port_or_known_default()
}

fn normalized_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(value) => Some(value.to_ascii_lowercase()),
        Host::Ipv4(value) => Some(value.to_string()),
        Host::Ipv6(value) => Some(value.to_string()),
    }
}

fn canonical_origin_string(url: &Url) -> String {
    canonical_target_origin(url).map_or_else(String::new, |value| value.to_string())
}

fn policy_identity(
    target: &Url,
    provider: &Url,
    polls_per_leg: u16,
    poll_interval_ms: u64,
    lifetime_ms: u64,
) -> SsrfOastPolicyId {
    SsrfOastPolicyId(digest_many(
        POLICY_ID_DOMAIN,
        &[
            SSRF_OAST_REVIEW_POLICY_SCHEMA.as_bytes(),
            SSRF_OAST_REVIEW_ALGORITHM.as_bytes(),
            target.as_str().as_bytes(),
            provider.as_str().as_bytes(),
            &polls_per_leg.to_be_bytes(),
            &poll_interval_ms.to_be_bytes(),
            &lifetime_ms.to_be_bytes(),
        ],
    ))
}

fn prefixed_digest(prefix: &str, domain: &[u8], values: &[&[u8]]) -> String {
    format!("{prefix}{}", hex(digest_many(domain, values)))
}

fn digest_many(domain: &[u8], values: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_framed(&mut digest, domain);
    for value in values {
        update_framed(&mut digest, value);
    }
    digest.finalize().into()
}

fn digest_parts(domain: &[u8], context: &[&[u8]], entropy: &[u8; 32]) -> [u8; 32] {
    let mut values = context.to_vec();
    values.push(entropy);
    digest_many(domain, &values)
}

fn digest_bytes(domain: &[u8], value: &[u8]) -> [u8; 32] {
    digest_many(domain, &[value])
}

fn update_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "openapi-review")]
    use crate::openapi_review::{parse_openapi_document, OpenApiParseOutcome};
    #[cfg(feature = "openapi-review")]
    use serde_json::json;

    const TARGET: &str = "https://target.example.test/";
    const PROVIDER: &str = "https://oast.example.test/";
    const ADMIN_SENTINEL: &[u8] = b"SSRF-OAST-ADMIN-MUST-NOT-LEAK-71B4A9";

    fn policy_source() -> Vec<u8> {
        format!(
            "schema = \"{SSRF_OAST_REVIEW_POLICY_SCHEMA}\"\n\
             target_origin = \"{TARGET}\"\n\
             provider_origin = \"{PROVIDER}\"\n\
             acknowledge_external_interaction = true\n\
             polls_per_leg = 3\n\
             poll_interval_ms = 1000\n\
             lifetime_ms = 20000\n"
        )
        .into_bytes()
    }

    fn policy() -> SsrfOastReviewPolicy {
        SsrfOastReviewPolicy::parse_toml(&Url::parse(TARGET).unwrap(), &policy_source()).unwrap()
    }

    fn observed(url: &str) -> SsrfOastQueryCandidate {
        let SsrfOastCandidateSelection::Selected(candidate) = select_observed_query_candidate(
            &Url::parse(TARGET).unwrap(),
            &Url::parse(url).unwrap(),
            "subject-sha256:abc",
            true,
            true,
            true,
        ) else {
            panic!("expected candidate")
        };
        *candidate
    }

    fn callback(index: u8) -> String {
        let session = if index == 1 {
            "AQEBAQEBAQEBAQEBAQEBAQ"
        } else {
            "AgICAgICAgICAgICAgICAg"
        };
        let callback = if index == 1 {
            "AwMDAwMDAwMDAwMDAwMDAw"
        } else {
            "BAQEBAQEBAQEBAQEBAQEBA"
        };
        format!("{PROVIDER}c/{session}/{callback}")
    }

    #[test]
    fn strict_policy_parses_and_redacts_origins() {
        let policy = policy();
        assert_eq!(policy.polls_per_leg(), 3);
        assert_eq!(policy.poll_interval_ms(), 1_000);
        assert_eq!(policy.lifetime_ms(), 20_000);
        assert!(policy
            .policy_id()
            .to_wire()
            .starts_with("ssrf-oast-policy-sha256:"));
        let debug = format!("{policy:?}");
        assert!(!debug.contains("target.example"));
        assert!(!debug.contains("oast.example"));
    }

    #[test]
    fn policy_parser_rejects_unknown_schema_field_and_false_acknowledgement() {
        let target = Url::parse(TARGET).unwrap();
        let mut unknown = String::from_utf8(policy_source()).unwrap();
        unknown.push_str("payload = \"forbidden\"\n");
        assert_eq!(
            SsrfOastReviewPolicy::parse_toml(&target, unknown.as_bytes()).unwrap_err(),
            SsrfOastReviewPolicyError::MalformedPolicy
        );
        for (needle, replacement, expected) in [
            (
                SSRF_OAST_REVIEW_POLICY_SCHEMA,
                "security.ssrf-oast-review-policy/v2",
                SsrfOastReviewPolicyError::UnsupportedSchema,
            ),
            (
                "acknowledge_external_interaction = true",
                "acknowledge_external_interaction = false",
                SsrfOastReviewPolicyError::AcknowledgementRequired,
            ),
        ] {
            let changed = String::from_utf8(policy_source())
                .unwrap()
                .replace(needle, replacement);
            assert_eq!(
                SsrfOastReviewPolicy::parse_toml(&target, changed.as_bytes()).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn policy_limits_are_closed_and_inclusive() {
        let target = Url::parse(TARGET).unwrap();
        for (needle, values) in [
            (
                "polls_per_leg = 3",
                vec!["polls_per_leg = 0", "polls_per_leg = 5"],
            ),
            (
                "poll_interval_ms = 1000",
                vec!["poll_interval_ms = 249", "poll_interval_ms = 2001"],
            ),
            (
                "lifetime_ms = 20000",
                vec!["lifetime_ms = 4999", "lifetime_ms = 30001"],
            ),
        ] {
            for replacement in values {
                let changed = String::from_utf8(policy_source())
                    .unwrap()
                    .replace(needle, replacement);
                assert_eq!(
                    SsrfOastReviewPolicy::parse_toml(&target, changed.as_bytes()).unwrap_err(),
                    SsrfOastReviewPolicyError::InvalidLimits
                );
            }
        }
        for changed in [
            String::from_utf8(policy_source())
                .unwrap()
                .replace("polls_per_leg = 3", "polls_per_leg = 1"),
            String::from_utf8(policy_source())
                .unwrap()
                .replace("polls_per_leg = 3", "polls_per_leg = 4"),
        ] {
            SsrfOastReviewPolicy::parse_toml(&target, changed.as_bytes()).unwrap();
        }
    }

    #[test]
    fn policy_requires_exact_distinct_origins() {
        let target = Url::parse(TARGET).unwrap();
        let mismatched = String::from_utf8(policy_source())
            .unwrap()
            .replace(TARGET, "https://other.example.test/");
        assert_eq!(
            SsrfOastReviewPolicy::parse_toml(&target, mismatched.as_bytes()).unwrap_err(),
            SsrfOastReviewPolicyError::TargetOriginMismatch
        );
        let same = String::from_utf8(policy_source())
            .unwrap()
            .replace(PROVIDER, TARGET);
        assert_eq!(
            SsrfOastReviewPolicy::parse_toml(&target, same.as_bytes()).unwrap_err(),
            SsrfOastReviewPolicyError::ProviderOriginMatchesTarget
        );
        for invalid in [
            "http://oast.example.test/",
            "https://127.0.0.1/",
            "https://oast.example.test/path",
            "https://oast.example.test/?secret=yes",
        ] {
            let changed = String::from_utf8(policy_source())
                .unwrap()
                .replace(PROVIDER, invalid);
            assert_eq!(
                SsrfOastReviewPolicy::parse_toml(&target, changed.as_bytes()).unwrap_err(),
                SsrfOastReviewPolicyError::InvalidProviderOrigin
            );
        }
    }

    #[test]
    fn policy_is_bounded_and_identity_is_semantic() {
        let target = Url::parse(TARGET).unwrap();
        assert_eq!(
            SsrfOastReviewPolicy::parse_toml(
                &target,
                &vec![b'a'; MAX_SSRF_OAST_REVIEW_POLICY_BYTES + 1]
            )
            .unwrap_err(),
            SsrfOastReviewPolicyError::PolicyTooLarge
        );
        assert_eq!(
            SsrfOastReviewPolicy::parse_toml(&target, &[0xff]).unwrap_err(),
            SsrfOastReviewPolicyError::MalformedPolicy
        );
        let first = policy();
        let reordered = format!(
            "lifetime_ms=20000\npolls_per_leg=3\nschema=\"{SSRF_OAST_REVIEW_POLICY_SCHEMA}\"\n\
             provider_origin=\"{PROVIDER}\"\nacknowledge_external_interaction=true\n\
             target_origin=\"{TARGET}\"\npoll_interval_ms=1000\n"
        );
        let second = SsrfOastReviewPolicy::parse_toml(&target, reordered.as_bytes()).unwrap();
        assert_eq!(first.policy_id(), second.policy_id());
        let changed = String::from_utf8(policy_source())
            .unwrap()
            .replace("lifetime_ms = 20000", "lifetime_ms = 21000");
        assert_ne!(
            first.policy_id(),
            SsrfOastReviewPolicy::parse_toml(&target, changed.as_bytes())
                .unwrap()
                .policy_id()
        );
    }

    #[test]
    fn administrator_secret_is_move_only_bounded_and_redacted() {
        let token = SsrfOastAdminToken::new(ADMIN_SENTINEL.to_vec()).unwrap();
        assert_eq!(format!("{token:?}"), "SsrfOastAdminToken(<redacted>)");
        assert_eq!(token.into_bytes(), ADMIN_SENTINEL);
        for invalid in [
            vec![b'a'; MIN_SSRF_OAST_ADMIN_TOKEN_BYTES - 1],
            vec![b'a'; MAX_SSRF_OAST_ADMIN_TOKEN_BYTES + 1],
            [vec![b'a'; MIN_SSRF_OAST_ADMIN_TOKEN_BYTES], vec![b'\n']].concat(),
        ] {
            assert_eq!(
                SsrfOastAdminToken::new(invalid).unwrap_err(),
                SsrfOastAdminTokenError::Invalid
            );
        }
        assert!(!format!("{:?}", SsrfOastAdminTokenError::Invalid).contains("MUST-NOT-LEAK"));
    }

    #[test]
    fn observed_candidate_requires_one_absolute_url_occurrence() {
        let selected = observed(
            "https://target.example.test/fetch?keep=a%2Fb&url=https%3A%2F%2Fold.example%2Fx&tail=z",
        );
        assert_eq!(selected.source(), SsrfOastCandidateSource::ObservedUrlQuery);
        assert!(selected
            .parameter_id()
            .starts_with("ssrf-oast-parameter-sha256:"));
        assert!(selected
            .selection_id()
            .starts_with("ssrf-oast-selection-sha256:"));
        let debug = format!("{selected:?}");
        assert!(!debug.contains("old.example"));
        assert!(!debug.contains("/fetch"));
    }

    #[test]
    fn observed_candidate_rejects_ambiguity_and_unproven_inputs() {
        let origin = Url::parse(TARGET).unwrap();
        for value in [
            "https://target.example.test/no-query",
            "https://target.example.test/?next=relative/path",
            "https://target.example.test/?next=https%3A%2F%2Fx.test%2F%23fragment",
            "https://target.example.test/?next=https%3A%2F%2Fx.test%2F&next=https%3A%2F%2Fy.test%2F",
            "https://target.example.test/?next=https%3A%2F%2Fx.test%2F&return=https%3A%2F%2Fy.test%2F",
            "https://target.example.test/?ne%26xt=https%3A%2F%2Fx.test%2F",
            "https://target.example.test/?next=https%ZZ",
            "https://other.example.test/?next=https%3A%2F%2Fx.test%2F",
        ] {
            assert!(matches!(
                select_observed_query_candidate(
                    &origin,
                    &Url::parse(value).unwrap(),
                    "subject",
                    true,
                    true,
                    true,
                ),
                SsrfOastCandidateSelection::NotEligible
            ));
        }
        let resource =
            Url::parse("https://target.example.test/?next=https%3A%2F%2Fx.test%2F").unwrap();
        for flags in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(matches!(
                select_observed_query_candidate(
                    &origin, &resource, "subject", flags.0, flags.1, flags.2,
                ),
                SsrfOastCandidateSelection::NotEligible
            ));
        }
    }

    #[cfg(feature = "openapi-review")]
    #[test]
    fn observed_ranking_is_deterministic_and_prefers_observed() {
        let first = observed("https://target.example.test/x?b=https%3A%2F%2Fb.test%2F");
        let second = observed("https://target.example.test/x?b=https%3A%2F%2Fb.test%2F");
        assert_eq!(first.parameter_id(), second.parameter_id());
        let mut openapi = observed("https://target.example.test/y?u=https%3A%2F%2Fu.test%2F");
        openapi.source = SsrfOastCandidateSource::OpenApiOptionalUrlQuery;
        let SsrfOastCandidateSelection::Selected(chosen) =
            choose_ssrf_oast_query_candidate(Some(first), Some(openapi))
        else {
            panic!("expected candidate")
        };
        assert_eq!(chosen.source(), SsrfOastCandidateSource::ObservedUrlQuery);
    }

    #[cfg(feature = "openapi-review")]
    fn openapi_operation(value: serde_json::Value) -> OpenApiOperation {
        let document_url = Url::parse("https://target.example.test/openapi.json").unwrap();
        let OpenApiParseOutcome::Complete(document) =
            parse_openapi_document(&serde_json::to_vec(&value).unwrap(), &document_url)
        else {
            panic!("expected complete document")
        };
        document.catalog().operations()[0].clone()
    }

    #[cfg(feature = "openapi-review")]
    #[test]
    fn openapi_candidate_requires_exact_optional_url_query_proof() {
        let operation = openapi_operation(json!({
            "openapi": "3.1.0",
            "info": {"title": "fixture", "version": "1"},
            "paths": {"/fetch": {"get": {
                "parameters": [{"name":"destination","in":"query","required":false,
                    "schema":{"type":"string","format":"uri"}}],
                "responses":{"200":{"content":{"application/json":{"schema":{}}}}}
            }}}
        }));
        let result = select_openapi_query_candidate(
            &Url::parse(TARGET).unwrap(),
            &Url::parse("https://target.example.test/fetch").unwrap(),
            &operation,
            "destination",
            true,
            true,
            true,
        );
        let SsrfOastCandidateSelection::Selected(candidate) = result else {
            panic!("expected OpenAPI candidate")
        };
        assert_eq!(
            candidate.source(),
            SsrfOastCandidateSource::OpenApiOptionalUrlQuery
        );
        assert!(matches!(
            select_openapi_query_candidate(
                &Url::parse(TARGET).unwrap(),
                &Url::parse("https://target.example.test/fetch").unwrap(),
                &operation,
                "guessed-name",
                true,
                true,
                true,
            ),
            SsrfOastCandidateSelection::NotEligible
        ));
    }

    #[cfg(feature = "openapi-review")]
    #[test]
    fn openapi_rejects_required_body_auth_and_cross_origin_metadata() {
        let cases = [
            json!({"parameters":[{"name":"destination","in":"query","required":true,
                "schema":{"type":"string","format":"url"}}]}),
            json!({"requestBody":{"content":{"application/json":{}}},
                "parameters":[{"name":"destination","in":"query","required":false,
                "schema":{"type":"string","format":"url"}}]}),
            json!({"security":[{"bearer":[]}],
                "parameters":[{"name":"destination","in":"query","required":false,
                "schema":{"type":"string","format":"url"}}]}),
            json!({"servers":[{"url":"https://other.example.test"}],
                "parameters":[{"name":"destination","in":"query","required":false,
                "schema":{"type":"string","format":"url"}}]}),
        ];
        for mut body in cases {
            let mut root = json!({
                "openapi":"3.0.3",
                "info":{"title":"fixture","version":"1"},
                "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
                "paths":{"/fetch":{"get":{"responses":{"200":{"description":"ok"}}}}}
            });
            root["paths"]["/fetch"]["get"]
                .as_object_mut()
                .unwrap()
                .append(body.as_object_mut().unwrap());
            let operation = openapi_operation(root);
            assert!(matches!(
                select_openapi_query_candidate(
                    &Url::parse(TARGET).unwrap(),
                    &Url::parse("https://target.example.test/fetch").unwrap(),
                    &operation,
                    "destination",
                    true,
                    true,
                    true,
                ),
                SsrfOastCandidateSelection::NotEligible
            ));
        }
    }

    #[test]
    fn mutation_plan_preserves_unrelated_query_pairs_and_uses_invalid_control() {
        let selected = observed(
            "https://target.example.test/fetch?keep=a%2Fb&url=https%3A%2F%2Fold.example%2Fx&tail=z+q",
        );
        let provider = PublicOrigin::from_str(PROVIDER).unwrap();
        let control = selected.control_execution_url([7; 32]).unwrap();
        let plan = SsrfOastMutationPlan::from_callback_strings(
            selected,
            [7; 32],
            &callback(1),
            &callback(2),
            &provider,
        )
        .unwrap();
        let candidate = plan.execution_url(SsrfOastTargetLeg::Candidate);
        let replay = plan.execution_url(SsrfOastTargetLeg::Replay);
        assert!(control.query().unwrap().contains(".invalid%2F"));
        let control_value = control
            .query_pairs()
            .find(|(name, _)| name == "url")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        let control_url = Url::parse(&control_value).unwrap();
        assert!(control_url
            .domain()
            .unwrap()
            .split('.')
            .next()
            .is_some_and(|label| label.len() <= 63));
        assert!(control.query().unwrap().starts_with("keep=a%2Fb&url="));
        assert!(control.query().unwrap().ends_with("&tail=z+q"));
        assert_ne!(candidate, replay);
        assert!(candidate.query().unwrap().contains("oast.example.test"));
        assert_eq!(candidate.path(), "/fetch");
        let debug = format!("{plan:?}");
        assert!(!debug.contains("oast.example"));
        assert!(!debug.contains("target.example"));
    }

    #[cfg(feature = "openapi-review")]
    #[test]
    fn openapi_materialization_adds_only_the_proven_query() {
        let operation = openapi_operation(json!({
            "openapi":"3.0.3","info":{"title":"fixture","version":"1"},
            "paths":{"/fetch":{"get":{
                "parameters":[{"name":"destination","in":"query","required":false,
                    "schema":{"type":"string","format":"url"}}],
                "responses":{"200":{"description":"ok"}}
            }}}
        }));
        let SsrfOastCandidateSelection::Selected(selected) = select_openapi_query_candidate(
            &Url::parse(TARGET).unwrap(),
            &Url::parse("https://target.example.test/fetch").unwrap(),
            &operation,
            "destination",
            true,
            true,
            true,
        ) else {
            panic!("expected selection")
        };
        let provider = PublicOrigin::from_str(PROVIDER).unwrap();
        let plan = SsrfOastMutationPlan::from_callback_strings(
            *selected,
            [9; 32],
            &callback(1),
            &callback(2),
            &provider,
        )
        .unwrap();
        assert!(plan
            .execution_url(SsrfOastTargetLeg::Candidate)
            .query()
            .unwrap()
            .starts_with("destination=https%3A%2F%2F"));
    }

    #[test]
    fn mutation_plan_rejects_bad_or_reused_callback_targets() {
        let provider = PublicOrigin::from_str(PROVIDER).unwrap();
        assert_eq!(
            SsrfOastMutationPlan::from_callback_strings(
                observed("https://target.example.test/?url=https%3A%2F%2Fold.test%2F"),
                [1; 32],
                &callback(1),
                &callback(1),
                &provider,
            )
            .unwrap_err(),
            SsrfOastContractError::CallbackIdentityConflict
        );
        for invalid in [
            "http://oast.example.test/c/AQEBAQEBAQEBAQEBAQEBAQ/AwMDAwMDAwMDAwMDAwMDAw",
            "https://other.example.test/c/AQEBAQEBAQEBAQEBAQEBAQ/AwMDAwMDAwMDAwMDAwMDAw",
            "https://oast.example.test/not-a-callback",
            "https://oast.example.test/c/AQEBAQEBAQEBAQEBAQEBAQ/AwMDAwMDAwMDAwMDAwMDAw?x=1",
        ] {
            assert_eq!(
                SsrfOastMutationPlan::from_callback_strings(
                    observed("https://target.example.test/?url=https%3A%2F%2Fold.test%2F"),
                    [1; 32],
                    invalid,
                    &callback(2),
                    &provider,
                )
                .unwrap_err(),
                SsrfOastContractError::InvalidCallbackTarget
            );
        }
    }

    #[test]
    fn correlation_material_is_distinct_bound_and_redacted() {
        let candidate = observed("https://target.example.test/?url=https%3A%2F%2Fold.test%2F");
        let material = SsrfOastCorrelationMaterial::derive(
            &policy(),
            &candidate,
            SsrfOastCorrelationBinding::new("assessment-1", "web.review.ssrf-oast-query", "case-1"),
            SsrfOastCorrelationEntropy::new([1; 32], [2; 32], [3; 32]),
        )
        .unwrap();
        assert_eq!(
            format!("{material:?}"),
            "SsrfOastCorrelationMaterial(<redacted>)"
        );
        let (_epoch, candidate_token, replay_token) = material.into_parts();
        assert_eq!(
            format!("{candidate_token:?}"),
            "OastCorrelationToken(<redacted>)"
        );
        assert_eq!(
            format!("{replay_token:?}"),
            "OastCorrelationToken(<redacted>)"
        );
        assert_eq!(
            SsrfOastCorrelationMaterial::derive(
                &policy(),
                &candidate,
                SsrfOastCorrelationBinding::new("assessment-1", "action", "case"),
                SsrfOastCorrelationEntropy::new([1; 32], [2; 32], [2; 32]),
            )
            .unwrap_err(),
            SsrfOastContractError::InvalidCorrelationMaterial
        );
    }

    fn callback_identity(byte: u8) -> SsrfOastCallbackIdentity {
        SsrfOastCallbackIdentity([byte; 32])
    }

    fn event(callback: SsrfOastCallbackIdentity, byte: u8) -> SsrfOastObservedEvent {
        SsrfOastObservedEvent {
            callback,
            event: [byte; 32],
        }
    }

    fn positive_facts() -> SsrfOastReviewFacts {
        SsrfOastReviewFacts {
            control_complete: true,
            provider_registered: true,
            allocations_complete: true,
            preflight_clean: true,
            candidate_dispatched: true,
            replay_dispatched: true,
            expected_candidate: callback_identity(1),
            expected_replay: callback_identity(2),
            candidate_event: Some(event(callback_identity(1), 3)),
            replay_event: Some(event(callback_identity(2), 4)),
            correlations_distinct: true,
            same_correlation_scope: true,
            duplicate_only_substitution: false,
            cleanup_verified: true,
            target_accounting_complete: true,
            provider_accounting_complete: true,
            truncated: false,
            terminal: None,
        }
    }

    #[test]
    fn only_full_repeated_callback_contract_projects() {
        let outcome = evaluate_ssrf_oast_review(&positive_facts()).unwrap();
        assert_eq!(outcome, SsrfOastReviewOutcome::RepeatedCallbacksObserved);
        assert!(outcome.projects_item());
        let mut with_timeout = positive_facts();
        with_timeout.terminal = Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch);
        assert_eq!(
            evaluate_ssrf_oast_review(&with_timeout).unwrap(),
            SsrfOastReviewOutcome::RepeatedCallbacksObserved
        );
    }

    #[test]
    fn one_sided_wrong_and_duplicate_events_never_project() {
        let mut candidate_only = positive_facts();
        candidate_only.replay_event = None;
        let mut replay_only = positive_facts();
        replay_only.candidate_event = None;
        let mut wrong = positive_facts();
        wrong.replay_event = Some(event(callback_identity(9), 4));
        let mut duplicate = positive_facts();
        duplicate.duplicate_only_substitution = true;
        let mut same_event = positive_facts();
        same_event.replay_event = Some(event(callback_identity(2), 3));
        for (facts, expected) in [
            (candidate_only, SsrfOastReviewOutcome::CandidateOnly),
            (replay_only, SsrfOastReviewOutcome::ReplayOnly),
            (wrong, SsrfOastReviewOutcome::WrongCallback),
            (duplicate, SsrfOastReviewOutcome::DuplicateOnly),
            (same_event, SsrfOastReviewOutcome::EventIdentityConflict),
        ] {
            let outcome = evaluate_ssrf_oast_review(&facts).unwrap();
            assert_eq!(outcome, expected);
            assert!(!outcome.projects_item());
        }
    }

    #[test]
    fn lifecycle_incompleteness_and_interference_fail_closed() {
        type FactsMutationCase = (Box<dyn Fn(&mut SsrfOastReviewFacts)>, SsrfOastReviewOutcome);
        let mutations: Vec<FactsMutationCase> = vec![
            (
                Box::new(|facts| facts.control_complete = false),
                SsrfOastReviewOutcome::ControlIncomplete,
            ),
            (
                Box::new(|facts| facts.provider_registered = false),
                SsrfOastReviewOutcome::RegistrationIncomplete,
            ),
            (
                Box::new(|facts| facts.allocations_complete = false),
                SsrfOastReviewOutcome::AllocationIncomplete,
            ),
            (
                Box::new(|facts| facts.preflight_clean = false),
                SsrfOastReviewOutcome::PreflightContaminated,
            ),
            (
                Box::new(|facts| facts.replay_dispatched = false),
                SsrfOastReviewOutcome::TargetNotDispatched,
            ),
            (
                Box::new(|facts| facts.cleanup_verified = false),
                SsrfOastReviewOutcome::CleanupIncomplete,
            ),
            (
                Box::new(|facts| facts.truncated = true),
                SsrfOastReviewOutcome::Truncated,
            ),
            (
                Box::new(|facts| facts.provider_accounting_complete = false),
                SsrfOastReviewOutcome::Incomplete,
            ),
            (
                Box::new(|facts| facts.same_correlation_scope = false),
                SsrfOastReviewOutcome::CorrelationMismatch,
            ),
        ];
        for (mutate, expected) in mutations {
            let mut facts = positive_facts();
            mutate(&mut facts);
            let outcome = evaluate_ssrf_oast_review(&facts).unwrap();
            assert_eq!(outcome, expected);
            assert!(!outcome.projects_item());
        }
    }

    #[test]
    fn every_terminal_provider_state_is_typed_and_nonpositive() {
        for (terminal, expected) in [
            (
                SsrfOastTerminalState::DefensiveInterference,
                SsrfOastReviewOutcome::DefensiveInterference,
            ),
            (
                SsrfOastTerminalState::RateLimited,
                SsrfOastReviewOutcome::RateLimited,
            ),
            (
                SsrfOastTerminalState::ProviderAuthenticationFailed,
                SsrfOastReviewOutcome::ProviderAuthenticationFailed,
            ),
            (
                SsrfOastTerminalState::MalformedProviderResponse,
                SsrfOastReviewOutcome::MalformedProviderResponse,
            ),
            (
                SsrfOastTerminalState::PollExhausted,
                SsrfOastReviewOutcome::PollExhausted,
            ),
            (
                SsrfOastTerminalState::Expired,
                SsrfOastReviewOutcome::Expired,
            ),
            (
                SsrfOastTerminalState::Cancelled,
                SsrfOastReviewOutcome::Cancelled,
            ),
            (
                SsrfOastTerminalState::BudgetExhausted,
                SsrfOastReviewOutcome::BudgetExhausted,
            ),
            (
                SsrfOastTerminalState::Incomplete,
                SsrfOastReviewOutcome::Incomplete,
            ),
        ] {
            let mut facts = positive_facts();
            facts.terminal = Some(terminal);
            let outcome = evaluate_ssrf_oast_review(&facts).unwrap();
            assert_eq!(outcome, expected);
            assert!(!outcome.projects_item());
        }
    }

    #[test]
    fn callback_identity_conflict_is_an_internal_error() {
        let mut facts = positive_facts();
        facts.expected_replay = facts.expected_candidate.clone();
        assert_eq!(
            evaluate_ssrf_oast_review(&facts).unwrap_err(),
            SsrfOastContractError::CallbackIdentityConflict
        );
    }
}
