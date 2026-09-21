//! Bounded, transport-neutral core for Cert Spotter reconnaissance queries.
//!
//! This module validates explicit operator policy, constructs the one permitted
//! provider route, and reduces bounded provider pages to source-qualified DNS
//! name hypotheses. It owns no network transport, target authority, retry
//! policy, clock, or persistence. In particular, a successful query does not
//! establish ownership, currentness, source authenticity, or scan authority.

use std::{collections::BTreeSet, fmt, net::IpAddr, time::Duration};

use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Number, Value};
use thiserror::Error;
use url::{Host, Url};

/// The only accepted local policy schema.
pub const RECON_CT_PROVIDER_POLICY_SCHEMA: &str = "security.recon-certspotter-policy/v1";
/// Fixed provider origin used by production execution.
pub const CERT_SPOTTER_PRODUCTION_ORIGIN: &str = "https://api.certspotter.com";
/// Maximum exact local policy size.
pub const MAX_RECON_CT_PROVIDER_POLICY_BYTES: usize = 16 * 1024;
/// Maximum accepted bytes in one provider response page.
pub const MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES: usize = 256 * 1024;
/// Maximum provider pages in one bounded collection.
pub const MAX_CERT_SPOTTER_RESPONSE_PAGES: usize = 2;
/// Maximum accepted provider response bytes over the whole collection.
pub const MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES: usize = 512 * 1024;
/// Maximum wall-clock time transport integration may spend on collection.
pub const MAX_CERT_SPOTTER_ELAPSED: Duration = Duration::from_secs(10);
/// Maximum simultaneous provider requests permitted by this contract.
pub const MAX_CERT_SPOTTER_IN_FLIGHT_REQUESTS: usize = 1;
/// Maximum unique in-scope DNS name hypotheses retained in one result.
pub const MAX_CERT_SPOTTER_RETAINED_NAMES: usize = 256;

const MAX_POLICY_OPAQUE_BYTES: usize = 128;
const MAX_PROVIDER_ORIGIN_BYTES: usize = 256;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_ISSUANCE_ID_BYTES: usize = 128;
const MAX_ISSUANCES_PER_PAGE: usize = 4096;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_MEMBERS: usize = 16_384;
const MAX_JSON_ARRAY_ITEMS: usize = 16_384;
const MAX_JSON_KEY_BYTES: usize = 128;
const MAX_JSON_STRING_BYTES: usize = 4096;
const DUPLICATE_KEY_MARKER: &str = "termivar_cert_spotter_duplicate_json_key";
const JSON_LIMIT_MARKER: &str = "termivar_cert_spotter_json_limit";

/// Closed execution environment selected by local operator policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconCtProviderExecutionMode {
    /// Use the fixed HTTPS Cert Spotter production origin.
    Production,
    /// Use an explicitly owned, numeric-loopback HTTP fixture.
    OwnedLoopbackFixture,
}

impl ReconCtProviderExecutionMode {
    /// Returns the stable policy and reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::OwnedLoopbackFixture => "owned_loopback_fixture",
        }
    }
}

/// Concise provider-specific alias for the execution mode.
pub type CertSpotterExecutionMode = ReconCtProviderExecutionMode;

/// Validated local policy for one bounded Cert Spotter query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertSpotterPolicy {
    revision: String,
    query_domain: String,
    query_reference: String,
    execution_mode: ReconCtProviderExecutionMode,
    provider_origin: String,
}

/// Integration-facing policy name used by CLI and runtime code.
pub type ReconCtProviderPolicy = CertSpotterPolicy;

impl CertSpotterPolicy {
    /// Parses one exact, strict V1 JSON policy document.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, ReconCtProviderPolicyError> {
        parse_recon_ct_provider_policy(bytes)
    }

    /// Returns the accepted policy schema.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        RECON_CT_PROVIDER_POLICY_SCHEMA
    }

    /// Returns the bounded opaque operator revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the normalized lowercase ASCII DNS query.
    #[must_use]
    pub fn query_domain(&self) -> &str {
        &self.query_domain
    }

    /// Returns the bounded opaque operator query reference.
    #[must_use]
    pub fn query_reference(&self) -> &str {
        &self.query_reference
    }

    /// Returns the closed execution mode.
    #[must_use]
    pub const fn execution_mode(&self) -> ReconCtProviderExecutionMode {
        self.execution_mode
    }

    /// Returns the effective provider origin.
    ///
    /// Production always returns [`CERT_SPOTTER_PRODUCTION_ORIGIN`]. Fixture
    /// mode returns the canonical numeric-loopback origin declared by policy.
    #[must_use]
    pub fn provider_origin(&self) -> &str {
        &self.provider_origin
    }

    /// Returns the mandatory provider-use authorization acknowledgement.
    #[must_use]
    pub const fn provider_use_authorized(&self) -> bool {
        true
    }

    /// Returns the mandatory privacy-disclosure acknowledgement.
    #[must_use]
    pub const fn privacy_disclosure_acknowledged(&self) -> bool {
        true
    }

    /// Builds the exact permitted provider URL, optionally after one cursor.
    pub fn build_request_url(&self, after: Option<&str>) -> Result<Url, CertSpotterRequestError> {
        if after.is_some_and(|cursor| !valid_issuance_id(cursor)) {
            return Err(CertSpotterRequestError::InvalidAfterCursor);
        }

        let mut url = Url::parse(&self.provider_origin)
            .map_err(|_| CertSpotterRequestError::InvalidProviderOrigin)?;
        url.set_path("/v1/issuances");
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("domain", &self.query_domain);
            query.append_pair("expand", "dns_names");
            if let Some(cursor) = after {
                query.append_pair("after", cursor);
            }
        }
        Ok(url)
    }
}

/// Parses one exact, strict V1 policy document.
pub fn parse_recon_ct_provider_policy(
    bytes: &[u8],
) -> Result<ReconCtProviderPolicy, ReconCtProviderPolicyError> {
    if bytes.is_empty() {
        return Err(CertSpotterPolicyError::EmptyInput);
    }
    if bytes.len() > MAX_RECON_CT_PROVIDER_POLICY_BYTES {
        return Err(CertSpotterPolicyError::InputTooLarge);
    }

    let value = parse_strict_json(bytes).map_err(CertSpotterPolicyError::from)?;
    let provider_origin_present = value
        .as_object()
        .is_some_and(|object| object.contains_key("provider_origin"));
    let wire: PolicyWire =
        serde_json::from_value(value).map_err(|_| CertSpotterPolicyError::InvalidPolicy)?;
    if wire.schema != RECON_CT_PROVIDER_POLICY_SCHEMA {
        return Err(CertSpotterPolicyError::UnsupportedSchema);
    }
    if !valid_safe_opaque(&wire.revision) {
        return Err(CertSpotterPolicyError::InvalidRevision);
    }
    if !valid_query_domain(&wire.query_domain) {
        return Err(CertSpotterPolicyError::InvalidQueryDomain);
    }
    if !valid_safe_opaque(&wire.query_reference) {
        return Err(CertSpotterPolicyError::InvalidQueryReference);
    }
    if !wire.provider_use_authorized {
        return Err(CertSpotterPolicyError::ProviderUseNotAuthorized);
    }
    if !wire.privacy_disclosure_acknowledged {
        return Err(CertSpotterPolicyError::PrivacyDisclosureNotAcknowledged);
    }

    let (execution_mode, provider_origin) = match wire.execution_mode {
        ExecutionModeWire::Production => {
            if provider_origin_present {
                return Err(CertSpotterPolicyError::ProductionOriginMustBeAbsent);
            }
            (
                ReconCtProviderExecutionMode::Production,
                CERT_SPOTTER_PRODUCTION_ORIGIN.to_owned(),
            )
        },
        ExecutionModeWire::OwnedLoopbackFixture => {
            let declared = wire
                .provider_origin
                .as_deref()
                .ok_or(CertSpotterPolicyError::FixtureOriginRequired)?;
            let provider_origin = canonical_owned_loopback_origin(declared)
                .ok_or(CertSpotterPolicyError::InvalidFixtureOrigin)?;
            (
                ReconCtProviderExecutionMode::OwnedLoopbackFixture,
                provider_origin,
            )
        },
    };

    Ok(CertSpotterPolicy {
        revision: tight_string(wire.revision),
        query_domain: tight_string(wire.query_domain.to_ascii_lowercase()),
        query_reference: tight_string(wire.query_reference),
        execution_mode,
        provider_origin: tight_string(provider_origin),
    })
}

/// Builds the exact permitted provider URL from validated policy.
pub fn build_cert_spotter_request_url(
    policy: &CertSpotterPolicy,
    after: Option<&str>,
) -> Result<Url, CertSpotterRequestError> {
    policy.build_request_url(after)
}

/// Static, redaction-safe policy rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CertSpotterPolicyError {
    /// No exact policy bytes were supplied.
    #[error("Cert Spotter policy input is empty")]
    EmptyInput,
    /// Exact policy bytes exceeded the 16-KiB ceiling.
    #[error("Cert Spotter policy exceeds its byte limit")]
    InputTooLarge,
    /// The input was not one complete JSON value.
    #[error("Cert Spotter policy is malformed JSON")]
    MalformedJson,
    /// A JSON object contained a duplicate decoded key.
    #[error("Cert Spotter policy contains a duplicate JSON key")]
    DuplicateJsonKey,
    /// A JSON structural bound was exceeded.
    #[error("Cert Spotter policy exceeds a JSON structural limit")]
    StructuralLimitExceeded,
    /// A required field, type, closed token, or unknown field was invalid.
    #[error("Cert Spotter policy contains an invalid or unsupported value")]
    InvalidPolicy,
    /// The policy did not select the exact supported schema.
    #[error("Cert Spotter policy schema is unsupported")]
    UnsupportedSchema,
    /// The opaque policy revision violated its safe bounded syntax.
    #[error("Cert Spotter policy revision is invalid")]
    InvalidRevision,
    /// The query was not a multi-label, non-wildcard ASCII DNS name.
    #[error("Cert Spotter policy query domain is invalid")]
    InvalidQueryDomain,
    /// The opaque query reference violated its safe bounded syntax.
    #[error("Cert Spotter policy query reference is invalid")]
    InvalidQueryReference,
    /// Provider use was not affirmatively authorized.
    #[error("Cert Spotter provider use is not authorized by policy")]
    ProviderUseNotAuthorized,
    /// The privacy disclosure was not affirmatively acknowledged.
    #[error("Cert Spotter privacy disclosure is not acknowledged by policy")]
    PrivacyDisclosureNotAcknowledged,
    /// Production policy attempted to override the fixed provider origin.
    #[error("Cert Spotter production policy must not declare provider_origin")]
    ProductionOriginMustBeAbsent,
    /// Fixture mode omitted its explicitly owned loopback origin.
    #[error("Cert Spotter loopback fixture policy requires provider_origin")]
    FixtureOriginRequired,
    /// Fixture origin was not root-only HTTP on a numeric loopback and explicit port.
    #[error("Cert Spotter fixture origin is not an owned numeric-loopback HTTP origin")]
    InvalidFixtureOrigin,
}

/// Integration-facing alias for strict policy failures.
pub type ReconCtProviderPolicyError = CertSpotterPolicyError;

impl From<StrictJsonError> for CertSpotterPolicyError {
    fn from(value: StrictJsonError) -> Self {
        match value {
            StrictJsonError::Malformed => Self::MalformedJson,
            StrictJsonError::DuplicateKey => Self::DuplicateJsonKey,
            StrictJsonError::LimitExceeded => Self::StructuralLimitExceeded,
        }
    }
}

/// Static request-URL construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CertSpotterRequestError {
    /// The optional opaque cursor was empty, oversized, or contained controls.
    #[error("Cert Spotter after cursor is invalid")]
    InvalidAfterCursor,
    /// Validated policy unexpectedly did not contain a usable provider origin.
    #[error("Cert Spotter provider origin cannot form a request URL")]
    InvalidProviderOrigin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    schema: String,
    revision: String,
    query_domain: String,
    query_reference: String,
    execution_mode: ExecutionModeWire,
    provider_origin: Option<String>,
    provider_use_authorized: bool,
    privacy_disclosure_acknowledged: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionModeWire {
    Production,
    OwnedLoopbackFixture,
}

/// Fixed interpretation limits attached to every provider-derived name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertSpotterClaimLimit {
    /// Returned names are hypotheses, not findings or verified assets.
    HypothesesOnly,
    /// Provider output cannot grant target scan authority.
    ScanAuthorityNotGranted,
    /// Domain or certificate ownership was not established.
    OwnershipNotEstablished,
    /// Currentness at report consumption time was not established.
    CurrentnessNotEstablished,
    /// TLS transport, if any, is not provider-source authentication evidence.
    SourceAuthenticationNotEstablished,
}

impl CertSpotterClaimLimit {
    /// Returns the stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HypothesesOnly => "hypotheses_only",
            Self::ScanAuthorityNotGranted => "scan_authority_not_granted",
            Self::OwnershipNotEstablished => "ownership_not_established",
            Self::CurrentnessNotEstablished => "currentness_not_established",
            Self::SourceAuthenticationNotEstablished => "source_authentication_not_established",
        }
    }
}

const CERT_SPOTTER_CLAIM_LIMITS: [CertSpotterClaimLimit; 5] = [
    CertSpotterClaimLimit::HypothesesOnly,
    CertSpotterClaimLimit::ScanAuthorityNotGranted,
    CertSpotterClaimLimit::OwnershipNotEstablished,
    CertSpotterClaimLimit::CurrentnessNotEstablished,
    CertSpotterClaimLimit::SourceAuthenticationNotEstablished,
];

/// Why a bounded collection stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertSpotterTerminal {
    /// The provider returned an empty page at the observed cursor.
    ProviderExhausted,
    /// The unique retained-name ceiling was reached.
    HypothesisLimitReached,
    /// The two-page ceiling was reached before an empty page.
    PageLimitReached,
    /// The ten-second integration deadline was reached.
    DeadlineReached,
    /// Parent request accounting did not permit another provider request.
    ParentAuthorityUnavailable,
    /// Provider transport failed within the authorized operation.
    TransportFailed,
    /// The host cancelled collection.
    Cancelled,
}

impl CertSpotterTerminal {
    /// Returns the stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderExhausted => "provider_exhausted",
            Self::HypothesisLimitReached => "hypothesis_limit_reached",
            Self::PageLimitReached => "page_limit_reached",
            Self::DeadlineReached => "deadline_reached",
            Self::ParentAuthorityUnavailable => "parent_authority_unavailable",
            Self::TransportFailed => "transport_failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Returns the conservative completeness implied by this terminal state.
    #[must_use]
    pub const fn completeness(self) -> CertSpotterCompleteness {
        match self {
            Self::ProviderExhausted => CertSpotterCompleteness::ProviderExhaustedAsObserved,
            Self::HypothesisLimitReached | Self::PageLimitReached => {
                CertSpotterCompleteness::BoundedPartial
            },
            Self::DeadlineReached
            | Self::ParentAuthorityUnavailable
            | Self::TransportFailed
            | Self::Cancelled => CertSpotterCompleteness::Unknown,
        }
    }

    const fn is_external(self) -> bool {
        matches!(
            self,
            Self::DeadlineReached
                | Self::ParentAuthorityUnavailable
                | Self::TransportFailed
                | Self::Cancelled
        )
    }
}

/// Conservative collection completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertSpotterCompleteness {
    /// An empty provider page was observed within this bounded run.
    ///
    /// This is not a currentness or global CT completeness claim.
    ProviderExhaustedAsObserved,
    /// A compiled page or hypothesis ceiling stopped collection.
    BoundedPartial,
    /// Transport, authority, deadline, or cancellation prevented exhaustion.
    Unknown,
}

impl CertSpotterCompleteness {
    /// Returns the stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderExhaustedAsObserved => "provider_exhausted_as_observed",
            Self::BoundedPartial => "bounded_partial",
            Self::Unknown => "unknown",
        }
    }
}

/// One unique, source-qualified provider DNS name hypothesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertSpotterNameHypothesis {
    name: String,
    first_issuance_id: String,
}

impl CertSpotterNameHypothesis {
    /// Returns the normalized lowercase ASCII DNS name.
    ///
    /// A leading `*.` is retained when the provider supplied a syntactically
    /// valid wildcard subordinate to the policy query.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the first bounded provider issuance ID associated with the name.
    #[must_use]
    pub fn first_issuance_id(&self) -> &str {
        &self.first_issuance_id
    }

    /// Returns all fixed interpretation boundaries for this hypothesis.
    #[must_use]
    pub const fn claim_limits(&self) -> &'static [CertSpotterClaimLimit] {
        &CERT_SPOTTER_CLAIM_LIMITS
    }
}

/// Outcome after accepting one complete provider response page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertSpotterPageOutcome {
    /// Another page is allowed using this opaque provider cursor.
    Continue {
        /// Last issuance ID from the accepted page.
        after: String,
    },
    /// Collection reached one terminal condition.
    Terminal(CertSpotterTerminal),
}

/// Stateful, transactional parser for at most two provider response pages.
///
/// Failed page parsing does not mutate accumulated state. Transport code owns
/// request execution and calls [`Self::into_result`] with an external terminal
/// when collection ends before a parser-selected terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertSpotterResponseAccumulator {
    policy_revision: String,
    query_domain: String,
    query_reference: String,
    execution_mode: ReconCtProviderExecutionMode,
    provider_origin: String,
    initial_after: Option<String>,
    next_after: Option<String>,
    page_count: usize,
    response_bytes: usize,
    issuance_count: usize,
    seen_issuance_ids: BTreeSet<String>,
    seen_names: BTreeSet<String>,
    hypotheses: Vec<CertSpotterNameHypothesis>,
    foreign_name_count: usize,
    duplicate_name_count: usize,
    omitted_name_count: usize,
    terminal: Option<CertSpotterTerminal>,
}

impl CertSpotterResponseAccumulator {
    /// Creates an empty first-page accumulator from validated policy.
    #[must_use]
    pub fn for_policy(policy: &CertSpotterPolicy) -> Self {
        Self::from_policy_and_after(policy, None)
    }

    /// Creates an accumulator for an optional validated starting cursor.
    pub fn with_after(
        policy: &CertSpotterPolicy,
        after: Option<&str>,
    ) -> Result<Self, CertSpotterRequestError> {
        if after.is_some_and(|cursor| !valid_issuance_id(cursor)) {
            return Err(CertSpotterRequestError::InvalidAfterCursor);
        }
        Ok(Self::from_policy_and_after(policy, after))
    }

    fn from_policy_and_after(policy: &CertSpotterPolicy, after: Option<&str>) -> Self {
        Self {
            policy_revision: policy.revision.clone(),
            query_domain: policy.query_domain.clone(),
            query_reference: policy.query_reference.clone(),
            execution_mode: policy.execution_mode,
            provider_origin: policy.provider_origin.clone(),
            initial_after: after.map(ToOwned::to_owned),
            next_after: after.map(ToOwned::to_owned),
            page_count: 0,
            response_bytes: 0,
            issuance_count: 0,
            seen_issuance_ids: BTreeSet::new(),
            seen_names: BTreeSet::new(),
            hypotheses: Vec::new(),
            foreign_name_count: 0,
            duplicate_name_count: 0,
            omitted_name_count: 0,
            terminal: None,
        }
    }

    /// Returns the cursor for the next request, if one exists.
    #[must_use]
    pub fn next_after(&self) -> Option<&str> {
        self.next_after.as_deref()
    }

    /// Returns accepted provider page count.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.page_count
    }

    /// Returns accepted provider bytes over all pages.
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    /// Returns unique retained hypotheses accumulated so far.
    #[must_use]
    pub fn hypotheses(&self) -> &[CertSpotterNameHypothesis] {
        &self.hypotheses
    }

    /// Parses and transactionally accepts one complete provider JSON page.
    pub fn ingest_page(
        &mut self,
        bytes: &[u8],
    ) -> Result<CertSpotterPageOutcome, CertSpotterResponseError> {
        if self.terminal.is_some() {
            return Err(CertSpotterResponseError::CollectionAlreadyTerminal);
        }
        if self.page_count >= MAX_CERT_SPOTTER_RESPONSE_PAGES {
            return Err(CertSpotterResponseError::TooManyPages);
        }
        if bytes.len() > MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES {
            return Err(CertSpotterResponseError::PageTooLarge);
        }
        let total_response_bytes = self
            .response_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES)
            .ok_or(CertSpotterResponseError::TotalTooLarge)?;

        let value = parse_strict_json(bytes).map_err(CertSpotterResponseError::from)?;
        let Value::Array(issuances) = value else {
            return Err(CertSpotterResponseError::InvalidRoot);
        };
        if issuances.len() > MAX_ISSUANCES_PER_PAGE {
            return Err(CertSpotterResponseError::TooManyIssuances);
        }

        let mut seen_issuance_ids = self.seen_issuance_ids.clone();
        let mut seen_names = self.seen_names.clone();
        let mut hypotheses = self.hypotheses.clone();
        let mut foreign_name_count = self.foreign_name_count;
        let mut duplicate_name_count = self.duplicate_name_count;
        let mut omitted_name_count = self.omitted_name_count;
        let mut page_cursor = self.next_after.clone();

        for issuance in &issuances {
            let object = issuance
                .as_object()
                .ok_or(CertSpotterResponseError::InvalidIssuance)?;
            let issuance_id = object
                .get("id")
                .and_then(Value::as_str)
                .ok_or(CertSpotterResponseError::InvalidIssuanceId)?;
            if !valid_issuance_id(issuance_id) {
                return Err(CertSpotterResponseError::InvalidIssuanceId);
            }
            if seen_issuance_ids.contains(issuance_id) {
                return Err(CertSpotterResponseError::DuplicateIssuanceId);
            }
            // The provider contract calls this ID opaque. Equality with the
            // active cursor is therefore the only ordering statement we can
            // make independently; cross-page reuse is rejected by the seen set.
            if page_cursor.as_deref() == Some(issuance_id) {
                return Err(CertSpotterResponseError::NonProgressingIssuanceId);
            }
            let dns_names = object
                .get("dns_names")
                .and_then(Value::as_array)
                .ok_or(CertSpotterResponseError::InvalidDnsNames)?;

            for dns_name in dns_names {
                let Some(dns_name) = dns_name.as_str() else {
                    return Err(CertSpotterResponseError::InvalidDnsNames);
                };
                match classify_provider_name(dns_name, &self.query_domain) {
                    ProviderName::InScope(normalized) => {
                        if !seen_names.insert(normalized.clone()) {
                            duplicate_name_count = checked_increment(duplicate_name_count)?;
                        } else if hypotheses.len() < MAX_CERT_SPOTTER_RETAINED_NAMES {
                            hypotheses.push(CertSpotterNameHypothesis {
                                name: tight_string(normalized),
                                first_issuance_id: issuance_id.to_owned(),
                            });
                        } else {
                            omitted_name_count = checked_increment(omitted_name_count)?;
                        }
                    },
                    ProviderName::Foreign => {
                        foreign_name_count = checked_increment(foreign_name_count)?;
                    },
                    ProviderName::Invalid => {
                        omitted_name_count = checked_increment(omitted_name_count)?;
                    },
                }
            }

            seen_issuance_ids.insert(issuance_id.to_owned());
            page_cursor = Some(issuance_id.to_owned());
        }

        let page_count = checked_increment(self.page_count)?;
        let issuance_count = self
            .issuance_count
            .checked_add(issuances.len())
            .ok_or(CertSpotterResponseError::StructuralLimitExceeded)?;

        self.page_count = page_count;
        self.response_bytes = total_response_bytes;
        self.issuance_count = issuance_count;
        self.seen_issuance_ids = seen_issuance_ids;
        self.seen_names = seen_names;
        self.hypotheses = hypotheses;
        self.foreign_name_count = foreign_name_count;
        self.duplicate_name_count = duplicate_name_count;
        self.omitted_name_count = omitted_name_count;
        self.next_after = page_cursor;

        let outcome = if issuances.is_empty() {
            CertSpotterPageOutcome::Terminal(CertSpotterTerminal::ProviderExhausted)
        } else if self.hypotheses.len() >= MAX_CERT_SPOTTER_RETAINED_NAMES {
            CertSpotterPageOutcome::Terminal(CertSpotterTerminal::HypothesisLimitReached)
        } else if self.page_count >= MAX_CERT_SPOTTER_RESPONSE_PAGES {
            CertSpotterPageOutcome::Terminal(CertSpotterTerminal::PageLimitReached)
        } else {
            CertSpotterPageOutcome::Continue {
                after: self
                    .next_after
                    .clone()
                    .ok_or(CertSpotterResponseError::InvalidIssuance)?,
            }
        };
        if let CertSpotterPageOutcome::Terminal(terminal) = outcome {
            self.terminal = Some(terminal);
        }
        Ok(outcome)
    }

    /// Finalizes accumulated hypotheses with one terminal transport outcome.
    ///
    /// A parser-selected terminal must be passed back unchanged. Before such a
    /// terminal, only deadline, parent-authority, transport, or cancellation
    /// outcomes may be supplied by integration code.
    pub fn into_result(
        self,
        terminal: CertSpotterTerminal,
    ) -> Result<CertSpotterResult, CertSpotterResponseError> {
        match self.terminal {
            Some(selected) if selected != terminal => {
                return Err(CertSpotterResponseError::TerminalMismatch);
            },
            None if !terminal.is_external() => {
                return Err(CertSpotterResponseError::TerminalMismatch);
            },
            _ => {},
        }

        let audit = CertSpotterAudit {
            policy_revision: self.policy_revision,
            query_domain: self.query_domain,
            query_reference: self.query_reference,
            execution_mode: self.execution_mode,
            provider_origin: self.provider_origin,
            initial_after: self.initial_after,
            last_cursor: self.next_after,
            page_count: self.page_count,
            response_bytes: self.response_bytes,
            issuance_count: self.issuance_count,
            retained_name_count: self.hypotheses.len(),
            foreign_name_count: self.foreign_name_count,
            duplicate_name_count: self.duplicate_name_count,
            omitted_name_count: self.omitted_name_count,
            terminal,
            completeness: terminal.completeness(),
        };
        Ok(CertSpotterResult {
            hypotheses: self.hypotheses,
            audit,
        })
    }
}

/// Final bounded, source-qualified provider result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertSpotterResult {
    hypotheses: Vec<CertSpotterNameHypothesis>,
    audit: CertSpotterAudit,
}

impl CertSpotterResult {
    /// Returns unique hypotheses in first-observed provider order.
    #[must_use]
    pub fn hypotheses(&self) -> &[CertSpotterNameHypothesis] {
        &self.hypotheses
    }

    /// Returns the value-free collection audit and counters.
    #[must_use]
    pub const fn audit(&self) -> &CertSpotterAudit {
        &self.audit
    }

    /// Returns all fixed interpretation boundaries for the result.
    #[must_use]
    pub const fn claim_limits(&self) -> &'static [CertSpotterClaimLimit] {
        &CERT_SPOTTER_CLAIM_LIMITS
    }
}

/// Typed audit for one finalized bounded provider collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertSpotterAudit {
    policy_revision: String,
    query_domain: String,
    query_reference: String,
    execution_mode: ReconCtProviderExecutionMode,
    provider_origin: String,
    initial_after: Option<String>,
    last_cursor: Option<String>,
    page_count: usize,
    response_bytes: usize,
    issuance_count: usize,
    retained_name_count: usize,
    foreign_name_count: usize,
    duplicate_name_count: usize,
    omitted_name_count: usize,
    terminal: CertSpotterTerminal,
    completeness: CertSpotterCompleteness,
}

impl CertSpotterAudit {
    /// Returns the policy schema governing this collection.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        RECON_CT_PROVIDER_POLICY_SCHEMA
    }

    /// Returns the opaque local policy revision.
    #[must_use]
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    /// Returns the normalized query domain.
    #[must_use]
    pub fn query_domain(&self) -> &str {
        &self.query_domain
    }

    /// Returns the opaque local query reference.
    #[must_use]
    pub fn query_reference(&self) -> &str {
        &self.query_reference
    }

    /// Returns the selected execution mode.
    #[must_use]
    pub const fn execution_mode(&self) -> ReconCtProviderExecutionMode {
        self.execution_mode
    }

    /// Returns the effective provider origin used for request construction.
    #[must_use]
    pub fn provider_origin(&self) -> &str {
        &self.provider_origin
    }

    /// Returns the optional starting cursor supplied by integration code.
    #[must_use]
    pub fn initial_after(&self) -> Option<&str> {
        self.initial_after.as_deref()
    }

    /// Returns the last accepted cursor, if any.
    #[must_use]
    pub fn last_cursor(&self) -> Option<&str> {
        self.last_cursor.as_deref()
    }

    /// Returns the number of accepted response pages/provider requests.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.page_count
    }

    /// Returns exact accepted response bytes across pages.
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    /// Returns the number of accepted issuance objects.
    #[must_use]
    pub const fn issuance_count(&self) -> usize {
        self.issuance_count
    }

    /// Returns unique in-scope names retained as hypotheses.
    #[must_use]
    pub const fn retained_name_count(&self) -> usize {
        self.retained_name_count
    }

    /// Returns syntactically valid names outside the query domain.
    #[must_use]
    pub const fn foreign_name_count(&self) -> usize {
        self.foreign_name_count
    }

    /// Returns repeated normalized in-scope names.
    #[must_use]
    pub const fn duplicate_name_count(&self) -> usize {
        self.duplicate_name_count
    }

    /// Returns invalid names plus unique in-scope names over the retain limit.
    #[must_use]
    pub const fn omitted_name_count(&self) -> usize {
        self.omitted_name_count
    }

    /// Returns the terminal collection condition.
    #[must_use]
    pub const fn terminal(&self) -> CertSpotterTerminal {
        self.terminal
    }

    /// Returns conservative completeness implied by the terminal condition.
    #[must_use]
    pub const fn completeness(&self) -> CertSpotterCompleteness {
        self.completeness
    }

    /// Returns all fixed interpretation boundaries for reporting.
    #[must_use]
    pub const fn claim_limits(&self) -> &'static [CertSpotterClaimLimit] {
        &CERT_SPOTTER_CLAIM_LIMITS
    }

    /// Returns the compiled page ceiling.
    #[must_use]
    pub const fn maximum_pages(&self) -> usize {
        MAX_CERT_SPOTTER_RESPONSE_PAGES
    }

    /// Returns the compiled total provider-byte ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> usize {
        MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES
    }

    /// Returns the compiled provider deadline.
    #[must_use]
    pub const fn maximum_elapsed(&self) -> Duration {
        MAX_CERT_SPOTTER_ELAPSED
    }

    /// Returns the compiled in-flight request ceiling.
    #[must_use]
    pub const fn maximum_in_flight_requests(&self) -> usize {
        MAX_CERT_SPOTTER_IN_FLIGHT_REQUESTS
    }
}

/// Static, redaction-safe response parsing or finalization failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CertSpotterResponseError {
    /// One page exceeded 256 KiB.
    #[error("Cert Spotter response page exceeds its byte limit")]
    PageTooLarge,
    /// Accepted page bytes exceeded the 512-KiB collection ceiling.
    #[error("Cert Spotter response collection exceeds its byte limit")]
    TotalTooLarge,
    /// More than two pages were presented.
    #[error("Cert Spotter response exceeds its page limit")]
    TooManyPages,
    /// A page was supplied after a terminal parser outcome.
    #[error("Cert Spotter response collection is already terminal")]
    CollectionAlreadyTerminal,
    /// The input was not one complete JSON value.
    #[error("Cert Spotter response is malformed JSON")]
    MalformedJson,
    /// A JSON object contained a duplicate decoded key.
    #[error("Cert Spotter response contains a duplicate JSON key")]
    DuplicateJsonKey,
    /// A JSON structural bound or counter bound was exceeded.
    #[error("Cert Spotter response exceeds a JSON structural limit")]
    StructuralLimitExceeded,
    /// The response root was not an array.
    #[error("Cert Spotter response root must be an array")]
    InvalidRoot,
    /// A page contained more issuance objects than permitted.
    #[error("Cert Spotter response contains too many issuances")]
    TooManyIssuances,
    /// An array element was not an issuance object.
    #[error("Cert Spotter response contains an invalid issuance object")]
    InvalidIssuance,
    /// An issuance lacked a canonical bounded string ID.
    #[error("Cert Spotter response contains an invalid issuance ID")]
    InvalidIssuanceId,
    /// An issuance ID repeated within or across accepted pages.
    #[error("Cert Spotter response contains a duplicate issuance ID")]
    DuplicateIssuanceId,
    /// The response repeated the exact opaque cursor used to request it.
    #[error("Cert Spotter response repeats the active issuance cursor")]
    NonProgressingIssuanceId,
    /// An issuance lacked a string-only `dns_names` array.
    #[error("Cert Spotter response contains invalid dns_names")]
    InvalidDnsNames,
    /// Finalization did not preserve the selected terminal condition.
    #[error("Cert Spotter result terminal condition does not match parser state")]
    TerminalMismatch,
}

impl From<StrictJsonError> for CertSpotterResponseError {
    fn from(value: StrictJsonError) -> Self {
        match value {
            StrictJsonError::Malformed => Self::MalformedJson,
            StrictJsonError::DuplicateKey => Self::DuplicateJsonKey,
            StrictJsonError::LimitExceeded => Self::StructuralLimitExceeded,
        }
    }
}

fn checked_increment(value: usize) -> Result<usize, CertSpotterResponseError> {
    value
        .checked_add(1)
        .ok_or(CertSpotterResponseError::StructuralLimitExceeded)
}

fn valid_safe_opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_POLICY_OPAQUE_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn valid_query_domain(value: &str) -> bool {
    value.contains('.')
        && !value.starts_with("*.")
        && value.parse::<IpAddr>().is_err()
        && valid_dns_name(value)
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_DNS_NAME_BYTES
        || !value.is_ascii()
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn canonical_owned_loopback_origin(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_PROVIDER_ORIGIN_BYTES || !value.is_ascii() {
        return None;
    }
    let parsed = Url::parse(value).ok()?;
    if parsed.scheme() != "http"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_none()
        || parsed.port() == Some(0)
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let is_loopback = match parsed.host()? {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(_) => false,
    };
    if !is_loopback {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn valid_issuance_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ISSUANCE_ID_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{7f}')
}

enum ProviderName {
    InScope(String),
    Foreign,
    Invalid,
}

fn classify_provider_name(value: &str, query_domain: &str) -> ProviderName {
    if value.is_empty() || value.len() > MAX_DNS_NAME_BYTES || !value.is_ascii() {
        return ProviderName::Invalid;
    }
    let (wildcard, bare_name) = match value.strip_prefix("*.") {
        Some(name) => (true, name),
        None => (false, value),
    };
    if !valid_dns_name(bare_name) || bare_name.parse::<IpAddr>().is_ok() {
        return ProviderName::Invalid;
    }
    let bare_name = bare_name.to_ascii_lowercase();
    let in_scope = bare_name == query_domain
        || bare_name
            .strip_suffix(query_domain)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
    if !in_scope {
        return ProviderName::Foreign;
    }
    if wildcard {
        ProviderName::InScope(format!("*.{bare_name}"))
    } else {
        ProviderName::InScope(bare_name)
    }
}

fn tight_string(mut value: String) -> String {
    value.shrink_to_fit();
    value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictJsonError {
    Malformed,
    DuplicateKey,
    LimitExceeded,
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
    members: usize,
    array_items: usize,
}

impl JsonBudget {
    fn enter<E: de::Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > MAX_JSON_DEPTH || self.nodes >= MAX_JSON_NODES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        self.nodes += 1;
        Ok(())
    }

    fn member<E: de::Error>(&mut self) -> Result<(), E> {
        if self.members >= MAX_JSON_MEMBERS {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        self.members += 1;
        Ok(())
    }

    fn array_item<E: de::Error>(&mut self) -> Result<(), E> {
        if self.array_items >= MAX_JSON_ARRAY_ITEMS {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        self.array_items += 1;
        Ok(())
    }
}

struct StrictJsonSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.budget.enter::<D::Error>(self.depth)?;
        deserializer.deserialize_any(StrictJsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct StrictJsonVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded Cert Spotter JSON")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.visit_str(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            budget: &mut *self.budget,
            depth: self.depth + 1,
        })? {
            self.budget.array_item::<A::Error>()?;
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key_seed(StrictKeySeed)? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            self.budget.member::<A::Error>()?;
            let value = map.next_value_seed(StrictJsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct StrictKeySeed;

impl<'de> DeserializeSeed<'de> for StrictKeySeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictKeyVisitor)
    }
}

struct StrictKeyVisitor;

impl Visitor<'_> for StrictKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Cert Spotter object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_str(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_KEY_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_KEY_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(value)
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, StrictJsonError> {
    let mut budget = JsonBudget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

fn classify_json_error(error: serde_json::Error) -> StrictJsonError {
    let message = error.to_string();
    if message.contains(DUPLICATE_KEY_MARKER) {
        StrictJsonError::DuplicateKey
    } else if message.contains(JSON_LIMIT_MARKER) {
        StrictJsonError::LimitExceeded
    } else {
        StrictJsonError::Malformed
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn production_policy_value() -> Value {
        json!({
            "schema": RECON_CT_PROVIDER_POLICY_SCHEMA,
            "revision": "rev-2026.09",
            "query_domain": "Example.COM",
            "query_reference": "scope-reference-1",
            "execution_mode": "production",
            "provider_use_authorized": true,
            "privacy_disclosure_acknowledged": true
        })
    }

    fn production_policy() -> CertSpotterPolicy {
        parse_recon_ct_provider_policy(&serde_json::to_vec(&production_policy_value()).unwrap())
            .unwrap()
    }

    fn accumulator() -> CertSpotterResponseAccumulator {
        CertSpotterResponseAccumulator::for_policy(&production_policy())
    }

    #[test]
    fn parses_production_policy_and_builds_exact_urls() {
        let policy = production_policy();
        assert_eq!(policy.schema(), RECON_CT_PROVIDER_POLICY_SCHEMA);
        assert_eq!(policy.revision(), "rev-2026.09");
        assert_eq!(policy.query_domain(), "example.com");
        assert_eq!(policy.query_reference(), "scope-reference-1");
        assert_eq!(
            policy.execution_mode(),
            ReconCtProviderExecutionMode::Production
        );
        assert_eq!(policy.provider_origin(), CERT_SPOTTER_PRODUCTION_ORIGIN);
        assert!(policy.provider_use_authorized());
        assert!(policy.privacy_disclosure_acknowledged());
        assert_eq!(
            policy.build_request_url(None).unwrap().as_str(),
            "https://api.certspotter.com/v1/issuances?domain=example.com&expand=dns_names"
        );
        assert_eq!(
            build_cert_spotter_request_url(&policy, Some("42"))
                .unwrap()
                .as_str(),
            "https://api.certspotter.com/v1/issuances?domain=example.com&expand=dns_names&after=42"
        );
    }

    #[test]
    fn enforces_production_and_owned_loopback_origins() {
        let mut production = production_policy_value();
        production["provider_origin"] = json!("https://api.certspotter.com");
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&production).unwrap()),
            Err(CertSpotterPolicyError::ProductionOriginMustBeAbsent)
        );
        production["provider_origin"] = Value::Null;
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&production).unwrap()),
            Err(CertSpotterPolicyError::ProductionOriginMustBeAbsent)
        );

        let mut fixture = production_policy_value();
        fixture["execution_mode"] = json!("owned_loopback_fixture");
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&fixture).unwrap()),
            Err(CertSpotterPolicyError::FixtureOriginRequired)
        );

        for origin in [
            "https://127.0.0.1:43123",
            "http://localhost:43123",
            "http://192.0.2.10:43123",
            "http://127.0.0.1",
            "http://127.0.0.1:43123/path",
            "http://user@127.0.0.1:43123",
            "http://127.0.0.1:43123?query",
        ] {
            fixture["provider_origin"] = json!(origin);
            assert_eq!(
                parse_recon_ct_provider_policy(&serde_json::to_vec(&fixture).unwrap()),
                Err(CertSpotterPolicyError::InvalidFixtureOrigin),
                "origin {origin} unexpectedly passed"
            );
        }

        fixture["provider_origin"] = json!("http://127.0.0.1:43123/");
        let policy =
            parse_recon_ct_provider_policy(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(
            policy.execution_mode(),
            ReconCtProviderExecutionMode::OwnedLoopbackFixture
        );
        assert_eq!(policy.provider_origin(), "http://127.0.0.1:43123");
        assert_eq!(
            policy.build_request_url(None).unwrap().as_str(),
            "http://127.0.0.1:43123/v1/issuances?domain=example.com&expand=dns_names"
        );
    }

    #[test]
    fn rejects_invalid_policy_acknowledgements_and_closed_fields() {
        let mut value = production_policy_value();
        value["provider_use_authorized"] = json!(false);
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&value).unwrap()),
            Err(CertSpotterPolicyError::ProviderUseNotAuthorized)
        );
        value = production_policy_value();
        value["privacy_disclosure_acknowledged"] = json!(false);
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&value).unwrap()),
            Err(CertSpotterPolicyError::PrivacyDisclosureNotAcknowledged)
        );
        value = production_policy_value();
        value["future"] = json!(true);
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&value).unwrap()),
            Err(CertSpotterPolicyError::InvalidPolicy)
        );
    }

    #[test]
    fn rejects_invalid_query_domains_and_opaque_values() {
        for domain in [
            "localhost",
            "*.example.com",
            "127.0.0.1",
            "2001:db8::1",
            "example.com.",
            "-bad.example",
            "bad-.example",
            "münich.example",
        ] {
            let mut value = production_policy_value();
            value["query_domain"] = json!(domain);
            assert_eq!(
                parse_recon_ct_provider_policy(&serde_json::to_vec(&value).unwrap()),
                Err(CertSpotterPolicyError::InvalidQueryDomain),
                "domain {domain} unexpectedly passed"
            );
        }

        let mut value = production_policy_value();
        value["revision"] = json!(" revision");
        assert_eq!(
            parse_recon_ct_provider_policy(&serde_json::to_vec(&value).unwrap()),
            Err(CertSpotterPolicyError::InvalidRevision)
        );
        for reference in [
            "scope?secret=1",
            "C:/Users/name/private",
            "name@example.com",
        ] {
            value = production_policy_value();
            value["query_reference"] = json!(reference);
            assert_eq!(
                parse_recon_ct_provider_policy(&serde_json::to_vec(&value).unwrap()),
                Err(CertSpotterPolicyError::InvalidQueryReference),
                "reference {reference} unexpectedly passed"
            );
        }
    }

    #[test]
    fn policy_parser_rejects_duplicate_keys_and_size_limit() {
        let duplicate = br#"{
            "schema":"security.recon-certspotter-policy/v1",
            "revision":"one",
            "\u0072evision":"two",
            "query_domain":"example.com",
            "query_reference":"scope-1",
            "execution_mode":"production",
            "provider_use_authorized":true,
            "privacy_disclosure_acknowledged":true
        }"#;
        assert_eq!(
            parse_recon_ct_provider_policy(duplicate),
            Err(CertSpotterPolicyError::DuplicateJsonKey)
        );
        assert_eq!(
            parse_recon_ct_provider_policy(&vec![b' '; MAX_RECON_CT_PROVIDER_POLICY_BYTES + 1]),
            Err(CertSpotterPolicyError::InputTooLarge)
        );
        assert_eq!(
            parse_recon_ct_provider_policy(b"{"),
            Err(CertSpotterPolicyError::MalformedJson)
        );
    }

    #[test]
    fn validates_opaque_after_cursor_without_query_interpolation() {
        let policy = production_policy();
        for cursor in ["", "line\nbreak", "null\0byte"] {
            assert_eq!(
                policy.build_request_url(Some(cursor)),
                Err(CertSpotterRequestError::InvalidAfterCursor),
                "cursor {cursor} unexpectedly passed"
            );
            assert_eq!(
                CertSpotterResponseAccumulator::with_after(&policy, Some(cursor)),
                Err(CertSpotterRequestError::InvalidAfterCursor)
            );
        }
        for cursor in ["01", "-1", "1&expand=cert", "opaque/雪 ?"] {
            let url = policy.build_request_url(Some(cursor)).unwrap();
            let pairs = url.query_pairs().collect::<Vec<_>>();
            assert_eq!(
                pairs,
                vec![
                    ("domain".into(), "example.com".into()),
                    ("expand".into(), "dns_names".into()),
                    ("after".into(), cursor.into())
                ]
            );
        }
        let oversized = "a".repeat(MAX_ISSUANCE_ID_BYTES + 1);
        assert_eq!(
            policy.build_request_url(Some(&oversized)),
            Err(CertSpotterRequestError::InvalidAfterCursor)
        );
    }

    #[test]
    fn retains_only_unique_equal_or_subordinate_ascii_names() {
        let mut accumulator = accumulator();
        let page = json!([{
            "id": "10",
            "dns_names": [
                "example.com",
                "WWW.Example.COM",
                "*.example.com",
                "evil.test",
                "münich.example.com",
                "192.0.2.1",
                "www.example.com"
            ],
            "future": {"nested": [true, null, 7]}
        }]);
        assert_eq!(
            accumulator
                .ingest_page(&serde_json::to_vec(&page).unwrap())
                .unwrap(),
            CertSpotterPageOutcome::Continue {
                after: "10".to_owned()
            }
        );
        assert_eq!(accumulator.next_after(), Some("10"));
        assert_eq!(
            accumulator
                .hypotheses()
                .iter()
                .map(CertSpotterNameHypothesis::name)
                .collect::<Vec<_>>(),
            vec!["example.com", "www.example.com", "*.example.com"]
        );

        assert_eq!(
            accumulator.ingest_page(b"[]").unwrap(),
            CertSpotterPageOutcome::Terminal(CertSpotterTerminal::ProviderExhausted)
        );
        let result = accumulator
            .into_result(CertSpotterTerminal::ProviderExhausted)
            .unwrap();
        let audit = result.audit();
        assert_eq!(audit.page_count(), 2);
        assert_eq!(audit.issuance_count(), 1);
        assert_eq!(audit.retained_name_count(), 3);
        assert_eq!(audit.foreign_name_count(), 1);
        assert_eq!(audit.duplicate_name_count(), 1);
        assert_eq!(audit.omitted_name_count(), 2);
        assert_eq!(audit.last_cursor(), Some("10"));
        assert_eq!(
            audit.completeness(),
            CertSpotterCompleteness::ProviderExhaustedAsObserved
        );
        assert_eq!(
            audit
                .claim_limits()
                .iter()
                .map(|limit| limit.as_str())
                .collect::<Vec<_>>(),
            vec![
                "hypotheses_only",
                "scan_authority_not_granted",
                "ownership_not_established",
                "currentness_not_established",
                "source_authentication_not_established"
            ]
        );
    }

    #[test]
    fn opaque_cursor_rejects_repetition_without_inventing_ordering() {
        let policy = production_policy();
        let mut repeated =
            CertSpotterResponseAccumulator::with_after(&policy, Some("opaque-z")).unwrap();
        assert_eq!(
            repeated.ingest_page(br#"[{"id":"opaque-z","dns_names":[]}]"#),
            Err(CertSpotterResponseError::NonProgressingIssuanceId)
        );

        let mut resumed =
            CertSpotterResponseAccumulator::with_after(&policy, Some("opaque-z")).unwrap();
        assert_eq!(
            resumed
                .ingest_page(br#"[{"id":"opaque-a","dns_names":[]}]"#)
                .unwrap(),
            CertSpotterPageOutcome::Continue {
                after: "opaque-a".to_owned()
            }
        );
        assert_eq!(
            resumed.ingest_page(br#"[{"id":"opaque-a","dns_names":[]}]"#),
            Err(CertSpotterResponseError::DuplicateIssuanceId)
        );
        assert_eq!(resumed.page_count(), 1);
        assert_eq!(resumed.next_after(), Some("opaque-a"));

        let mut accumulator = accumulator();
        assert_eq!(
            accumulator
                .ingest_page(
                    br#"[{"id":"opaque-z","dns_names":[]},{"id":"opaque-a","dns_names":[]}]"#
                )
                .unwrap(),
            CertSpotterPageOutcome::Continue {
                after: "opaque-a".to_owned()
            }
        );
        assert_eq!(accumulator.page_count(), 1);
        assert_eq!(accumulator.next_after(), Some("opaque-a"));
    }

    #[test]
    fn rejects_duplicate_keys_at_any_response_depth() {
        let mut accumulator = accumulator();
        assert_eq!(
            accumulator.ingest_page(br#"[{"id":"1","\u0069d":"2","dns_names":[]}]"#),
            Err(CertSpotterResponseError::DuplicateJsonKey)
        );
        assert_eq!(
            accumulator.ingest_page(br#"[{"id":"1","dns_names":[],"future":{"a":1,"a":2}}]"#),
            Err(CertSpotterResponseError::DuplicateJsonKey)
        );
    }

    #[test]
    fn rejects_malformed_roots_and_required_field_types() {
        let cases: &[(&[u8], CertSpotterResponseError)] = &[
            (b"{", CertSpotterResponseError::MalformedJson),
            (b"{}", CertSpotterResponseError::InvalidRoot),
            (b"[null]", CertSpotterResponseError::InvalidIssuance),
            (
                br#"[{"dns_names":[]}]"#,
                CertSpotterResponseError::InvalidIssuanceId,
            ),
            (
                br#"[{"id":1,"dns_names":[]}]"#,
                CertSpotterResponseError::InvalidIssuanceId,
            ),
            (
                br#"[{"id":"\u0000","dns_names":[]}]"#,
                CertSpotterResponseError::InvalidIssuanceId,
            ),
            (
                br#"[{"id":"1"}]"#,
                CertSpotterResponseError::InvalidDnsNames,
            ),
            (
                br#"[{"id":"1","dns_names":"example.com"}]"#,
                CertSpotterResponseError::InvalidDnsNames,
            ),
            (
                br#"[{"id":"1","dns_names":[7]}]"#,
                CertSpotterResponseError::InvalidDnsNames,
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(accumulator().ingest_page(bytes), Err(*expected));
        }
    }

    #[test]
    fn rejects_page_and_json_structure_bounds() {
        assert_eq!(
            accumulator().ingest_page(&vec![b' '; MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES + 1]),
            Err(CertSpotterResponseError::PageTooLarge)
        );

        let oversized_string = "x".repeat(MAX_JSON_STRING_BYTES + 1);
        let page = json!([{"id":"1", "dns_names":[], "future":oversized_string}]);
        assert_eq!(
            accumulator().ingest_page(&serde_json::to_vec(&page).unwrap()),
            Err(CertSpotterResponseError::StructuralLimitExceeded)
        );

        let oversized_key = "k".repeat(MAX_JSON_KEY_BYTES + 1);
        let page = format!(r#"[{{"id":"1","dns_names":[],"{oversized_key}":true}}]"#);
        assert_eq!(
            accumulator().ingest_page(page.as_bytes()),
            Err(CertSpotterResponseError::StructuralLimitExceeded)
        );

        let mut nested = json!(null);
        for _ in 0..=MAX_JSON_DEPTH {
            nested = json!([nested]);
        }
        assert_eq!(
            accumulator().ingest_page(&serde_json::to_vec(&nested).unwrap()),
            Err(CertSpotterResponseError::StructuralLimitExceeded)
        );
    }

    #[test]
    fn caps_unique_names_and_counts_omissions() {
        let mut names = Vec::new();
        for index in 0..(MAX_CERT_SPOTTER_RETAINED_NAMES + 2) {
            names.push(format!("host-{index}.example.com"));
        }
        let page = json!([{"id":"1", "dns_names":names}]);
        let mut accumulator = accumulator();
        assert_eq!(
            accumulator
                .ingest_page(&serde_json::to_vec(&page).unwrap())
                .unwrap(),
            CertSpotterPageOutcome::Terminal(CertSpotterTerminal::HypothesisLimitReached)
        );
        let result = accumulator
            .into_result(CertSpotterTerminal::HypothesisLimitReached)
            .unwrap();
        assert_eq!(result.hypotheses().len(), MAX_CERT_SPOTTER_RETAINED_NAMES);
        assert_eq!(result.audit().omitted_name_count(), 2);
        assert_eq!(
            result.audit().completeness(),
            CertSpotterCompleteness::BoundedPartial
        );
    }

    #[test]
    fn page_limit_is_terminal_and_finalization_is_consistent() {
        let mut accumulator = accumulator();
        assert!(matches!(
            accumulator
                .ingest_page(br#"[{"id":"1","dns_names":[]}]"#)
                .unwrap(),
            CertSpotterPageOutcome::Continue { .. }
        ));
        assert_eq!(
            accumulator
                .ingest_page(br#"[{"id":"2","dns_names":[]}]"#)
                .unwrap(),
            CertSpotterPageOutcome::Terminal(CertSpotterTerminal::PageLimitReached)
        );
        assert_eq!(
            accumulator.ingest_page(b"[]"),
            Err(CertSpotterResponseError::CollectionAlreadyTerminal)
        );
        assert_eq!(
            accumulator
                .clone()
                .into_result(CertSpotterTerminal::ProviderExhausted),
            Err(CertSpotterResponseError::TerminalMismatch)
        );
        let result = accumulator
            .into_result(CertSpotterTerminal::PageLimitReached)
            .unwrap();
        assert_eq!(result.audit().page_count(), MAX_CERT_SPOTTER_RESPONSE_PAGES);
    }

    #[test]
    fn external_terminal_can_finalize_partial_or_empty_state() {
        let result = accumulator()
            .into_result(CertSpotterTerminal::TransportFailed)
            .unwrap();
        assert_eq!(result.audit().page_count(), 0);
        assert_eq!(
            result.audit().completeness(),
            CertSpotterCompleteness::Unknown
        );
        assert_eq!(
            accumulator().into_result(CertSpotterTerminal::ProviderExhausted),
            Err(CertSpotterResponseError::TerminalMismatch)
        );
    }
}
