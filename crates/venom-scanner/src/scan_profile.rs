//! Strict, versioned product profiles for the deterministic web scanner.
//!
//! This contract deliberately exposes only reviewed product choices. It has
//! no URL, credential, header, raw transport, concurrency, or arbitrary
//! option fields. A profile therefore cannot expand exact-origin authority or
//! bypass the host-owned request broker and [`WebAssessmentLimits`].

use std::{fmt, str::FromStr, time::Duration};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{
    WebAssessmentLimits, WebAssessmentLimitsError, DEFAULT_MAX_ACTIVE_VERIFICATIONS,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_TOTAL_REQUESTS, DEFAULT_MAX_WALL_TIME_MS,
};

/// Exact schema identifier for the first deterministic scan-profile contract.
pub const SCAN_PROFILE_V1_SCHEMA: &str = "venom.scan-profile/v1";
/// Exact built-in identifier for conservative single-resource behavior.
pub const BASELINE_SCAN_PROFILE_ID: &str = "baseline";
/// Exact built-in identifier for bounded exact-origin review.
pub const WEB_REVIEW_SCAN_PROFILE_ID: &str = "web-review";
/// Request ceiling used by the unchanged default single-resource runtime.
pub const BASELINE_SCAN_PROFILE_MAX_TOTAL_REQUESTS: u32 = DEFAULT_MAX_TOTAL_REQUESTS;
/// Wall-clock ceiling used by the unchanged default single-resource runtime.
pub const BASELINE_SCAN_PROFILE_MAX_WALL_TIME_MS: u64 = DEFAULT_MAX_WALL_TIME_MS;
/// Cumulative response-byte ceiling used by the unchanged default runtime.
pub const BASELINE_SCAN_PROFILE_MAX_TOTAL_RESPONSE_BYTES: u64 = DEFAULT_MAX_RESPONSE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum ScanProfileSchemaV1 {
    #[serde(rename = "venom.scan-profile/v1")]
    V1,
}

impl<'de> Deserialize<'de> for ScanProfileSchemaV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            SCAN_PROFILE_V1_SCHEMA => Ok(Self::V1),
            _ => Err(D::Error::custom("unknown scan-profile schema version")),
        }
    }
}

/// One of the two product profiles implemented by the deterministic runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum BuiltInScanProfile {
    /// Conservative single-resource behavior used by the default CLI path.
    #[serde(rename = "baseline")]
    Baseline,
    /// Bounded exact-origin discovery and evidence review.
    #[serde(rename = "web-review")]
    WebReview,
}

impl<'de> Deserialize<'de> for BuiltInScanProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_id(&value).map_err(D::Error::custom)
    }
}

impl BuiltInScanProfile {
    /// Parses an exact, case-sensitive built-in identifier without trimming.
    pub fn parse_id(value: &str) -> Result<Self, BuiltInScanProfileParseError> {
        match value {
            BASELINE_SCAN_PROFILE_ID => Ok(Self::Baseline),
            WEB_REVIEW_SCAN_PROFILE_ID => Ok(Self::WebReview),
            _ => Err(BuiltInScanProfileParseError),
        }
    }

    /// Returns the stable wire identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Baseline => BASELINE_SCAN_PROFILE_ID,
            Self::WebReview => WEB_REVIEW_SCAN_PROFILE_ID,
        }
    }

    const fn required_scope(self) -> ScanProfileScope {
        match self {
            Self::Baseline => ScanProfileScope::SingleResource,
            Self::WebReview => ScanProfileScope::ExactOrigin,
        }
    }

    const fn required_capabilities(self) -> ScanProfileCapabilitiesV1 {
        match self {
            Self::Baseline => ScanProfileCapabilitiesV1::BASELINE,
            Self::WebReview => ScanProfileCapabilitiesV1::WEB_REVIEW,
        }
    }
}

impl fmt::Display for BuiltInScanProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

impl FromStr for BuiltInScanProfile {
    type Err = BuiltInScanProfileParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_id(value)
    }
}

/// An input was not one of the exact built-in profile identifiers.
///
/// The rejected value is intentionally not retained or echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown built-in scan profile identifier")]
pub struct BuiltInScanProfileParseError;

/// Network scope selected by a versioned scan profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ScanProfileScope {
    /// Preserve the conservative single-resource decision runtime.
    #[serde(rename = "single-resource")]
    SingleResource,
    /// Assess a bounded set of subjects under one exact-origin authority.
    #[serde(rename = "exact-origin")]
    ExactOrigin,
}

impl<'de> Deserialize<'de> for ScanProfileScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "single-resource" => Ok(Self::SingleResource),
            "exact-origin" => Ok(Self::ExactOrigin),
            _ => Err(D::Error::custom("unknown scan-profile scope")),
        }
    }
}

impl ScanProfileScope {
    /// Returns the stable wire identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::SingleResource => "single-resource",
            Self::ExactOrigin => "exact-origin",
        }
    }
}

impl fmt::Display for ScanProfileScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

/// Closed capability manifest for a v1 profile.
///
/// These flags describe executable behavior, not roadmap intent. They are
/// validated as an exact built-in matrix and cannot be independently toggled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanProfileCapabilitiesV1 {
    standard_web_decision: bool,
    origin_discovery: bool,
    semantic_extraction: bool,
    defense_observation: bool,
    defense_shadow_planning: bool,
    low_risk_differential_review: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScanProfileCapabilitiesV1 {
    standard_web_decision: bool,
    origin_discovery: bool,
    semantic_extraction: bool,
    defense_observation: bool,
    defense_shadow_planning: bool,
    low_risk_differential_review: bool,
}

impl WireScanProfileCapabilitiesV1 {
    const fn into_capabilities(self) -> ScanProfileCapabilitiesV1 {
        ScanProfileCapabilitiesV1 {
            standard_web_decision: self.standard_web_decision,
            origin_discovery: self.origin_discovery,
            semantic_extraction: self.semantic_extraction,
            defense_observation: self.defense_observation,
            defense_shadow_planning: self.defense_shadow_planning,
            low_risk_differential_review: self.low_risk_differential_review,
        }
    }
}

impl ScanProfileCapabilitiesV1 {
    const BASELINE: Self = Self {
        standard_web_decision: true,
        origin_discovery: false,
        semantic_extraction: false,
        defense_observation: false,
        defense_shadow_planning: false,
        low_risk_differential_review: false,
    };

    // PR B exposes only capabilities that execute on this branch. PR C may
    // deliberately enable low-risk differential review only after its native
    // capabilities and boundary tests land; roadmap intent is not runtime
    // truth and must not be advertised here.
    const WEB_REVIEW: Self = Self {
        standard_web_decision: true,
        origin_discovery: true,
        semantic_extraction: true,
        defense_observation: true,
        defense_shadow_planning: true,
        low_risk_differential_review: false,
    };

    /// Whether the standard single-subject decision primitive executes.
    pub const fn standard_web_decision(self) -> bool {
        self.standard_web_decision
    }

    /// Whether bounded exact-origin discovery executes.
    pub const fn origin_discovery(self) -> bool {
        self.origin_discovery
    }

    /// Whether committed assessment evidence is semantically projected.
    pub const fn semantic_extraction(self) -> bool {
        self.semantic_extraction
    }

    /// Whether response evidence is projected into defense state.
    pub const fn defense_observation(self) -> bool {
        self.defense_observation
    }

    /// Whether defense-aware planning is recorded without enforcement.
    pub const fn defense_shadow_planning(self) -> bool {
        self.defense_shadow_planning
    }

    /// Whether the native low-risk differential review set executes.
    pub const fn low_risk_differential_review(self) -> bool {
        self.low_risk_differential_review
    }
}

/// Complete serialized resource envelope for a v1 assessment profile.
///
/// Construction and deserialization route every value through the checked
/// [`WebAssessmentLimits`] setters. The fixed concurrency of that authority is
/// intentionally not configurable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanProfileLimitsV1 {
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
    max_wall_time_ms: u64,
    max_active_verifications: u16,
    #[serde(skip)]
    checked: WebAssessmentLimits,
}

impl ScanProfileLimitsV1 {
    fn from_checked(checked: WebAssessmentLimits) -> Result<Self, ScanProfileV1Error> {
        if checked.max_wall_time().subsec_nanos() % 1_000_000 != 0 {
            return Err(ScanProfileV1Error::SubMillisecondWallTime);
        }
        Ok(Self {
            max_subjects: checked.max_subjects(),
            max_discovery_depth: checked.max_discovery_depth(),
            max_references_per_document: checked.max_references_per_document(),
            max_canonical_url_bytes: checked.max_canonical_url_bytes(),
            max_retained_url_bytes: checked.max_retained_url_bytes(),
            max_forms: checked.max_forms(),
            max_controls_per_form: checked.max_controls_per_form(),
            max_query_parameter_names: checked.max_query_parameter_names(),
            max_total_requests: checked.max_total_requests(),
            max_response_body_bytes: checked.max_response_body_bytes(),
            max_total_response_bytes: checked.max_total_response_bytes(),
            max_wall_time_ms: duration_millis(checked.max_wall_time()),
            max_active_verifications: checked.max_active_verifications(),
            checked,
        })
    }

    /// Creates a wire envelope from an already checked assessment envelope.
    ///
    /// The assessment limit must use whole-millisecond wall-time precision so
    /// serialization cannot silently change the effective runtime authority.
    pub fn from_web_assessment_limits(
        limits: WebAssessmentLimits,
    ) -> Result<Self, ScanProfileV1Error> {
        Self::from_checked(limits)
    }

    /// Returns the checked assessment envelope.
    pub const fn web_assessment_limits(&self) -> WebAssessmentLimits {
        self.checked
    }

    /// Returns the subject ceiling, including the authorized root.
    pub const fn max_subjects(&self) -> usize {
        self.max_subjects
    }

    /// Returns the discovery depth after the root.
    pub const fn max_discovery_depth(&self) -> u16 {
        self.max_discovery_depth
    }

    /// Returns the reference ceiling per document.
    pub const fn max_references_per_document(&self) -> usize {
        self.max_references_per_document
    }

    /// Returns the canonical URL byte ceiling.
    pub const fn max_canonical_url_bytes(&self) -> usize {
        self.max_canonical_url_bytes
    }

    /// Returns the retained canonical-URL byte ceiling.
    pub const fn max_retained_url_bytes(&self) -> usize {
        self.max_retained_url_bytes
    }

    /// Returns the assessment-wide form ceiling.
    pub const fn max_forms(&self) -> usize {
        self.max_forms
    }

    /// Returns the control-name ceiling per form.
    pub const fn max_controls_per_form(&self) -> usize {
        self.max_controls_per_form
    }

    /// Returns the query-name ceiling per reference.
    pub const fn max_query_parameter_names(&self) -> usize {
        self.max_query_parameter_names
    }

    /// Returns the authority-wide request ceiling.
    pub const fn max_total_requests(&self) -> u32 {
        self.max_total_requests
    }

    /// Returns the per-response body ceiling.
    pub const fn max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes
    }

    /// Returns the authority-wide response-byte ceiling.
    pub const fn max_total_response_bytes(&self) -> u64 {
        self.max_total_response_bytes
    }

    /// Returns the authority-wide wall-clock ceiling in milliseconds.
    pub const fn max_wall_time_ms(&self) -> u64 {
        self.max_wall_time_ms
    }

    /// Returns the active-verification request ceiling.
    pub const fn max_active_verifications(&self) -> u16 {
        self.max_active_verifications
    }

    /// Returns the non-configurable assessment concurrency.
    pub const fn concurrency(&self) -> usize {
        self.checked.concurrency()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScanProfileLimitsV1 {
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
    max_wall_time_ms: u64,
    max_active_verifications: u16,
}

impl WireScanProfileLimitsV1 {
    fn into_checked(self) -> Result<WebAssessmentLimits, WebAssessmentLimitsError> {
        WebAssessmentLimits::default()
            .with_max_subjects(self.max_subjects)?
            .with_max_discovery_depth(self.max_discovery_depth)?
            .with_max_references_per_document(self.max_references_per_document)?
            .with_max_canonical_url_bytes(self.max_canonical_url_bytes)?
            .with_max_retained_url_bytes(self.max_retained_url_bytes)?
            .with_max_forms(self.max_forms)?
            .with_max_controls_per_form(self.max_controls_per_form)?
            .with_max_query_parameter_names(self.max_query_parameter_names)?
            .with_max_total_requests(self.max_total_requests)?
            .with_max_response_body_bytes(self.max_response_body_bytes)?
            .with_max_total_response_bytes(self.max_total_response_bytes)?
            .with_max_wall_time(Duration::from_millis(self.max_wall_time_ms))?
            .with_max_active_verifications(self.max_active_verifications)
    }
}

impl<'de> Deserialize<'de> for ScanProfileLimitsV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireScanProfileLimitsV1::deserialize(deserializer)?;
        let checked = wire.into_checked().map_err(D::Error::custom)?;
        Self::from_checked(checked).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanProfileDefenseV1 {
    enforcement_enabled: bool,
}

fn baseline_web_assessment_limits() -> Result<WebAssessmentLimits, WebAssessmentLimitsError> {
    let defaults = WebAssessmentLimits::default();
    defaults
        .with_max_subjects(1)?
        .with_max_discovery_depth(0)?
        .with_max_references_per_document(0)?
        .with_max_canonical_url_bytes(defaults.max_canonical_url_bytes())?
        .with_max_retained_url_bytes(defaults.max_canonical_url_bytes())?
        .with_max_forms(0)?
        .with_max_controls_per_form(0)?
        .with_max_query_parameter_names(0)?
        .with_max_total_requests(BASELINE_SCAN_PROFILE_MAX_TOTAL_REQUESTS)?
        .with_max_response_body_bytes(defaults.max_response_body_bytes())?
        .with_max_total_response_bytes(BASELINE_SCAN_PROFILE_MAX_TOTAL_RESPONSE_BYTES)?
        .with_max_wall_time(Duration::from_millis(
            BASELINE_SCAN_PROFILE_MAX_WALL_TIME_MS,
        ))?
        .with_max_active_verifications(DEFAULT_MAX_ACTIVE_VERIFICATIONS)
}

/// A validated `venom.scan-profile/v1` product profile.
///
/// The type has no [`Default`] implementation: callers must deliberately
/// choose `baseline` or `web-review`. Deserialization is fail-closed and
/// rejects every unknown field, identifier, schema version, invalid limit, or
/// capability/scope mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanProfileV1 {
    schema: ScanProfileSchemaV1,
    profile: BuiltInScanProfile,
    scope: ScanProfileScope,
    capabilities: ScanProfileCapabilitiesV1,
    limits: ScanProfileLimitsV1,
    defense: ScanProfileDefenseV1,
}

impl ScanProfileV1 {
    /// Constructs the conservative, single-resource built-in profile.
    pub fn baseline() -> Result<Self, ScanProfileV1Error> {
        let limits = baseline_web_assessment_limits()?;
        Self::from_parts(
            BuiltInScanProfile::Baseline,
            ScanProfileScope::SingleResource,
            ScanProfileCapabilitiesV1::BASELINE,
            ScanProfileLimitsV1::from_checked(limits)?,
            false,
        )
    }

    /// Constructs bounded exact-origin review with enforcement disabled.
    pub fn web_review() -> Result<Self, ScanProfileV1Error> {
        Self::from_parts(
            BuiltInScanProfile::WebReview,
            ScanProfileScope::ExactOrigin,
            ScanProfileCapabilitiesV1::WEB_REVIEW,
            ScanProfileLimitsV1::from_checked(WebAssessmentLimits::default())?,
            false,
        )
    }

    /// Constructs one of the exact built-in profiles.
    pub fn for_builtin(profile: BuiltInScanProfile) -> Result<Self, ScanProfileV1Error> {
        match profile {
            BuiltInScanProfile::Baseline => Self::baseline(),
            BuiltInScanProfile::WebReview => Self::web_review(),
        }
    }

    /// Parses an exact built-in identifier and constructs its profile.
    pub fn for_builtin_id(value: &str) -> Result<Self, ScanProfileSelectionError> {
        let profile = BuiltInScanProfile::parse_id(value)?;
        Self::for_builtin(profile).map_err(ScanProfileSelectionError::InvalidProfile)
    }

    fn from_parts(
        profile: BuiltInScanProfile,
        scope: ScanProfileScope,
        capabilities: ScanProfileCapabilitiesV1,
        limits: ScanProfileLimitsV1,
        defense_enforcement_enabled: bool,
    ) -> Result<Self, ScanProfileV1Error> {
        let candidate = Self {
            schema: ScanProfileSchemaV1::V1,
            profile,
            scope,
            capabilities,
            limits,
            defense: ScanProfileDefenseV1 {
                enforcement_enabled: defense_enforcement_enabled,
            },
        };
        candidate.validate()?;
        Ok(candidate)
    }

    fn validate(&self) -> Result<(), ScanProfileV1Error> {
        let expected_scope = self.profile.required_scope();
        if self.scope != expected_scope {
            return Err(ScanProfileV1Error::ScopeMismatch {
                profile: self.profile,
                expected: expected_scope,
                actual: self.scope,
            });
        }
        if self.capabilities != self.profile.required_capabilities() {
            return Err(ScanProfileV1Error::CapabilityManifestMismatch {
                profile: self.profile,
            });
        }
        if self.defense.enforcement_enabled && self.profile != BuiltInScanProfile::WebReview {
            return Err(ScanProfileV1Error::DefenseEnforcementNotAllowed {
                profile: self.profile,
            });
        }
        if self.profile == BuiltInScanProfile::Baseline {
            self.validate_baseline_limits()?;
        }
        Ok(())
    }

    fn validate_baseline_limits(&self) -> Result<(), ScanProfileV1Error> {
        let limits = &self.limits;
        let expected = baseline_web_assessment_limits()?;
        let invalid_dimension = if limits.max_subjects() != expected.max_subjects() {
            Some("max_subjects")
        } else if limits.max_discovery_depth() != expected.max_discovery_depth() {
            Some("max_discovery_depth")
        } else if limits.max_references_per_document() != expected.max_references_per_document() {
            Some("max_references_per_document")
        } else if limits.max_canonical_url_bytes() != expected.max_canonical_url_bytes() {
            Some("max_canonical_url_bytes")
        } else if limits.max_retained_url_bytes() != expected.max_retained_url_bytes() {
            Some("max_retained_url_bytes")
        } else if limits.max_forms() != expected.max_forms() {
            Some("max_forms")
        } else if limits.max_controls_per_form() != expected.max_controls_per_form() {
            Some("max_controls_per_form")
        } else if limits.max_query_parameter_names() != expected.max_query_parameter_names() {
            Some("max_query_parameter_names")
        } else if limits.max_total_requests() != expected.max_total_requests() {
            Some("max_total_requests")
        } else if limits.max_response_body_bytes() != expected.max_response_body_bytes() {
            Some("max_response_body_bytes")
        } else if limits.max_total_response_bytes() != expected.max_total_response_bytes() {
            Some("max_total_response_bytes")
        } else if limits.max_wall_time_ms() != duration_millis(expected.max_wall_time()) {
            Some("max_wall_time_ms")
        } else if limits.max_active_verifications() != expected.max_active_verifications() {
            Some("max_active_verifications")
        } else {
            None
        };
        match invalid_dimension {
            Some(dimension) => Err(ScanProfileV1Error::BaselineLimitMismatch { dimension }),
            None => Ok(()),
        }
    }

    /// Returns the exact schema identifier.
    pub const fn schema(&self) -> &'static str {
        match self.schema {
            ScanProfileSchemaV1::V1 => SCAN_PROFILE_V1_SCHEMA,
        }
    }

    /// Returns the selected built-in profile.
    pub const fn profile(&self) -> BuiltInScanProfile {
        self.profile
    }

    /// Returns the profile's fixed network scope.
    pub const fn scope(&self) -> ScanProfileScope {
        self.scope
    }

    /// Returns the exact executable capability manifest.
    pub const fn capabilities(&self) -> ScanProfileCapabilitiesV1 {
        self.capabilities
    }

    /// Returns the complete serialized limits contract.
    pub const fn limits(&self) -> &ScanProfileLimitsV1 {
        &self.limits
    }

    /// Returns the checked limits consumed by the assessment runtime.
    pub const fn web_assessment_limits(&self) -> WebAssessmentLimits {
        self.limits.web_assessment_limits()
    }

    /// Returns whether defense enforcement was explicitly enabled.
    pub const fn defense_enforcement_enabled(&self) -> bool {
        self.defense.enforcement_enabled
    }

    /// Replaces the complete checked limit envelope.
    ///
    /// Every baseline dimension remains fixed to the current conservative CLI
    /// envelope. `web-review` may use any checked, whole-millisecond envelope.
    pub fn with_limits(mut self, limits: WebAssessmentLimits) -> Result<Self, ScanProfileV1Error> {
        self.limits = ScanProfileLimitsV1::from_checked(limits)?;
        self.validate()?;
        Ok(self)
    }

    /// Explicitly enables or disables monotonic defense enforcement.
    ///
    /// Enforcement is disabled in both built-in constructors. Baseline rejects
    /// an attempt to enable it; only `web-review` can opt in.
    pub fn with_defense_enforcement_enabled(
        mut self,
        enabled: bool,
    ) -> Result<Self, ScanProfileV1Error> {
        self.defense.enforcement_enabled = enabled;
        self.validate()?;
        Ok(self)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScanProfileV1 {
    schema: ScanProfileSchemaV1,
    profile: BuiltInScanProfile,
    scope: ScanProfileScope,
    capabilities: WireScanProfileCapabilitiesV1,
    limits: ScanProfileLimitsV1,
    defense: ScanProfileDefenseV1,
}

impl<'de> Deserialize<'de> for ScanProfileV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireScanProfileV1::deserialize(deserializer)?;
        let ScanProfileSchemaV1::V1 = wire.schema;
        Self::from_parts(
            wire.profile,
            wire.scope,
            wire.capabilities.into_capabilities(),
            wire.limits,
            wire.defense.enforcement_enabled,
        )
        .map_err(D::Error::custom)
    }
}

/// Invalid relationship inside a v1 profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ScanProfileV1Error {
    /// A complete limit envelope violated a compiled assessment ceiling.
    #[error(transparent)]
    Limits(#[from] WebAssessmentLimitsError),
    /// The built-in profile was paired with a different network scope.
    #[error(
        "scan profile {profile} requires scope {expected}, but the document selected {actual}"
    )]
    ScopeMismatch {
        /// Selected built-in profile.
        profile: BuiltInScanProfile,
        /// Only permitted scope for that profile.
        expected: ScanProfileScope,
        /// Scope present in the rejected document.
        actual: ScanProfileScope,
    },
    /// Capability flags did not exactly match executable built-in behavior.
    #[error(
        "scan profile {profile} has a capability manifest that does not match executable behavior"
    )]
    CapabilityManifestMismatch {
        /// Selected built-in profile.
        profile: BuiltInScanProfile,
    },
    /// A baseline limit differed from the exact conservative CLI envelope.
    #[error("baseline scan profile limit {dimension} does not match the built-in envelope")]
    BaselineLimitMismatch {
        /// Mismatched, non-secret limit field.
        dimension: &'static str,
    },
    /// A checked wall-time limit could not be represented losslessly on the v1 wire.
    #[error("scan-profile wall-time limits must use whole-millisecond precision")]
    SubMillisecondWallTime,
    /// Defense enforcement was requested for a profile that cannot enforce it.
    #[error("scan profile {profile} does not permit defense enforcement")]
    DefenseEnforcementNotAllowed {
        /// Selected built-in profile.
        profile: BuiltInScanProfile,
    },
}

/// Failure to select or construct a built-in v1 profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ScanProfileSelectionError {
    /// The supplied profile identifier was not exact.
    #[error(transparent)]
    UnknownProfile(#[from] BuiltInScanProfileParseError),
    /// The selected built-in configuration failed its invariant checks.
    #[error(transparent)]
    InvalidProfile(#[from] ScanProfileV1Error),
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS, HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES,
        HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM, HARD_MAX_WEB_ASSESSMENT_DEPTH,
        HARD_MAX_WEB_ASSESSMENT_FORMS, HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES,
        HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT,
        HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES, HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES,
        HARD_MAX_WEB_ASSESSMENT_SUBJECTS, HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS,
        HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES, HARD_MAX_WEB_ASSESSMENT_WALL_TIME,
        WEB_ASSESSMENT_CONCURRENCY,
    };

    fn profile_value(profile: ScanProfileV1) -> Value {
        serde_json::to_value(profile).unwrap()
    }

    fn web_review_value() -> Value {
        profile_value(ScanProfileV1::web_review().unwrap())
    }

    fn parse(value: &Value) -> Result<ScanProfileV1, serde_json::Error> {
        serde_json::from_value(value.clone())
    }

    fn set_limit(value: &mut Value, name: &str, replacement: Value) {
        value["limits"][name] = replacement;
    }

    #[test]
    fn exact_profile_id_parsing_rejects_case_whitespace_and_historical_names() {
        assert_eq!(
            BuiltInScanProfile::parse_id("baseline").unwrap(),
            BuiltInScanProfile::Baseline
        );
        assert_eq!(
            BuiltInScanProfile::parse_id("web-review").unwrap(),
            BuiltInScanProfile::WebReview
        );
        for rejected in [
            "Baseline",
            "BASELINE",
            " baseline",
            "baseline ",
            "web_review",
            "WEB-REVIEW",
            "enterprise",
            "cloud",
            "aggressive",
            "stealth",
            "",
        ] {
            assert!(
                BuiltInScanProfile::parse_id(rejected).is_err(),
                "{rejected:?}"
            );
            assert!(
                ScanProfileV1::for_builtin_id(rejected).is_err(),
                "{rejected:?}"
            );
        }
    }

    #[test]
    fn built_in_profiles_pin_executable_capability_truth() {
        let baseline = ScanProfileV1::baseline().unwrap();
        assert_eq!(baseline.schema(), SCAN_PROFILE_V1_SCHEMA);
        assert_eq!(baseline.profile(), BuiltInScanProfile::Baseline);
        assert_eq!(baseline.scope(), ScanProfileScope::SingleResource);
        assert!(baseline.capabilities().standard_web_decision());
        assert!(!baseline.capabilities().origin_discovery());
        assert!(!baseline.capabilities().semantic_extraction());
        assert!(!baseline.capabilities().defense_observation());
        assert!(!baseline.capabilities().defense_shadow_planning());
        assert!(!baseline.capabilities().low_risk_differential_review());
        assert!(!baseline.defense_enforcement_enabled());

        let web_review = ScanProfileV1::web_review().unwrap();
        assert_eq!(web_review.schema(), SCAN_PROFILE_V1_SCHEMA);
        assert_eq!(web_review.profile(), BuiltInScanProfile::WebReview);
        assert_eq!(web_review.scope(), ScanProfileScope::ExactOrigin);
        assert!(web_review.capabilities().standard_web_decision());
        assert!(web_review.capabilities().origin_discovery());
        assert!(web_review.capabilities().semantic_extraction());
        assert!(web_review.capabilities().defense_observation());
        assert!(web_review.capabilities().defense_shadow_planning());
        assert!(!web_review.capabilities().low_risk_differential_review());
        assert!(!web_review.defense_enforcement_enabled());
    }

    #[test]
    fn built_in_limits_are_exact_and_share_fixed_concurrency() {
        assert_eq!(
            BASELINE_SCAN_PROFILE_MAX_TOTAL_REQUESTS,
            DEFAULT_MAX_TOTAL_REQUESTS
        );
        assert_eq!(
            BASELINE_SCAN_PROFILE_MAX_WALL_TIME_MS,
            DEFAULT_MAX_WALL_TIME_MS
        );
        assert_eq!(
            BASELINE_SCAN_PROFILE_MAX_TOTAL_RESPONSE_BYTES,
            DEFAULT_MAX_RESPONSE_BYTES
        );

        let baseline = ScanProfileV1::baseline().unwrap();
        let limits = baseline.limits();
        assert_eq!(limits.max_subjects(), 1);
        assert_eq!(limits.max_discovery_depth(), 0);
        assert_eq!(limits.max_references_per_document(), 0);
        assert_eq!(
            limits.max_retained_url_bytes(),
            limits.max_canonical_url_bytes()
        );
        assert_eq!(limits.max_forms(), 0);
        assert_eq!(limits.max_controls_per_form(), 0);
        assert_eq!(limits.max_query_parameter_names(), 0);
        assert_eq!(
            limits.max_total_requests(),
            BASELINE_SCAN_PROFILE_MAX_TOTAL_REQUESTS
        );
        assert_eq!(
            limits.max_total_response_bytes(),
            BASELINE_SCAN_PROFILE_MAX_TOTAL_RESPONSE_BYTES
        );
        assert_eq!(
            limits.max_wall_time_ms(),
            BASELINE_SCAN_PROFILE_MAX_WALL_TIME_MS
        );
        assert_eq!(
            limits.max_active_verifications(),
            DEFAULT_MAX_ACTIVE_VERIFICATIONS
        );
        assert_eq!(limits.concurrency(), WEB_ASSESSMENT_CONCURRENCY);

        let expected = WebAssessmentLimits::default();
        let web_review = ScanProfileV1::web_review().unwrap();
        assert_eq!(web_review.web_assessment_limits(), expected);
        assert_eq!(
            web_review.limits().max_total_requests(),
            expected.max_total_requests()
        );
        assert_eq!(
            web_review.limits().max_wall_time_ms(),
            duration_millis(expected.max_wall_time())
        );
        assert_eq!(
            web_review.limits().concurrency(),
            WEB_ASSESSMENT_CONCURRENCY
        );
    }

    #[test]
    fn both_built_ins_round_trip_without_defaults_or_hidden_fields() {
        for profile in [
            ScanProfileV1::baseline().unwrap(),
            ScanProfileV1::web_review().unwrap(),
        ] {
            let encoded = serde_json::to_string(&profile).unwrap();
            assert!(!encoded.contains("checked"));
            assert!(!encoded.contains("concurrency"));
            let decoded: ScanProfileV1 = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, profile);
        }
    }

    #[test]
    fn unknown_schema_versions_and_version_field_fail_closed() {
        let mut value = web_review_value();
        value["schema"] = json!("venom.scan-profile/v2");
        assert!(parse(&value).is_err());

        let mut value = web_review_value();
        value["schema"] = json!("venom.scan-profile/V1");
        assert!(parse(&value).is_err());

        let mut value = web_review_value();
        value["version"] = json!(1);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn unknown_profile_scope_and_case_fail_closed_on_wire() {
        for replacement in ["enterprise", "WEB-REVIEW", " web-review"] {
            let mut value = web_review_value();
            value["profile"] = json!(replacement);
            assert!(parse(&value).is_err(), "{replacement:?}");
        }
        for replacement in ["origin", "ExactOrigin", "exact-origin "] {
            let mut value = web_review_value();
            value["scope"] = json!(replacement);
            assert!(parse(&value).is_err(), "{replacement:?}");
        }
    }

    #[test]
    fn invalid_wire_scalars_never_echo_rejected_secret_shaped_text() {
        const REJECTED: &str = "Bearer profile-secret-that-must-not-be-echoed";

        for field in ["schema", "profile", "scope"] {
            let mut value = web_review_value();
            value[field] = json!(REJECTED);
            let error = parse(&value).unwrap_err();
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains(REJECTED), "{field}: {rendered}");
            }
        }
    }

    #[test]
    fn every_object_level_rejects_unknown_fields() {
        for (field, replacement) in [
            ("target", json!("https://outside.invalid/")),
            ("headers", json!({"authorization": "not-accepted"})),
            ("transport", json!({"redirects": true})),
            ("concurrency", json!(2)),
            ("secret", json!("not-accepted")),
            ("unexpected", json!(true)),
        ] {
            let mut top = web_review_value();
            top[field] = replacement;
            assert!(parse(&top).is_err(), "{field}");
        }

        let mut capabilities = web_review_value();
        capabilities["capabilities"]["unexpected"] = json!(true);
        assert!(parse(&capabilities).is_err());

        let mut limits = web_review_value();
        limits["limits"]["concurrency"] = json!(2);
        assert!(parse(&limits).is_err());

        let mut defense = web_review_value();
        defense["defense"]["strategy"] = json!("evasion");
        assert!(parse(&defense).is_err());
    }

    #[test]
    fn every_required_top_level_and_nested_field_must_be_present() {
        for field in [
            "schema",
            "profile",
            "scope",
            "capabilities",
            "limits",
            "defense",
        ] {
            let mut value = web_review_value();
            value.as_object_mut().unwrap().remove(field);
            assert!(parse(&value).is_err(), "{field}");
        }

        for field in [
            "standard_web_decision",
            "origin_discovery",
            "semantic_extraction",
            "defense_observation",
            "defense_shadow_planning",
            "low_risk_differential_review",
        ] {
            let mut value = web_review_value();
            value["capabilities"].as_object_mut().unwrap().remove(field);
            assert!(parse(&value).is_err(), "{field}");
        }

        let mut value = web_review_value();
        value["defense"]
            .as_object_mut()
            .unwrap()
            .remove("enforcement_enabled");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn complete_limit_object_has_no_implicit_defaults() {
        for field in [
            "max_subjects",
            "max_discovery_depth",
            "max_references_per_document",
            "max_canonical_url_bytes",
            "max_retained_url_bytes",
            "max_forms",
            "max_controls_per_form",
            "max_query_parameter_names",
            "max_total_requests",
            "max_response_body_bytes",
            "max_total_response_bytes",
            "max_wall_time_ms",
            "max_active_verifications",
        ] {
            let mut value = web_review_value();
            value["limits"].as_object_mut().unwrap().remove(field);
            assert!(parse(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn every_compiled_limit_rejects_hard_maximum_plus_one() {
        let cases = [
            ("max_subjects", json!(HARD_MAX_WEB_ASSESSMENT_SUBJECTS + 1)),
            (
                "max_discovery_depth",
                json!(u32::from(HARD_MAX_WEB_ASSESSMENT_DEPTH) + 1),
            ),
            (
                "max_references_per_document",
                json!(HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT + 1),
            ),
            (
                "max_canonical_url_bytes",
                json!(HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES + 1),
            ),
            (
                "max_retained_url_bytes",
                json!(HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES + 1),
            ),
            ("max_forms", json!(HARD_MAX_WEB_ASSESSMENT_FORMS + 1)),
            (
                "max_controls_per_form",
                json!(HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM + 1),
            ),
            (
                "max_query_parameter_names",
                json!(HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES + 1),
            ),
            (
                "max_total_requests",
                json!(u64::from(HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS) + 1),
            ),
            (
                "max_response_body_bytes",
                json!(HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES + 1),
            ),
            (
                "max_total_response_bytes",
                json!(HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES + 1),
            ),
            (
                "max_wall_time_ms",
                json!(duration_millis(HARD_MAX_WEB_ASSESSMENT_WALL_TIME) + 1),
            ),
            (
                "max_active_verifications",
                json!(u32::from(HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS) + 1),
            ),
        ];

        for (field, replacement) in cases {
            let mut value = web_review_value();
            set_limit(&mut value, field, replacement);
            assert!(parse(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn runtime_required_nonzero_limits_reject_zero() {
        for field in [
            "max_subjects",
            "max_canonical_url_bytes",
            "max_retained_url_bytes",
            "max_response_body_bytes",
            "max_total_response_bytes",
        ] {
            let mut value = web_review_value();
            set_limit(&mut value, field, json!(0));
            assert!(parse(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn fail_closed_zero_limits_remain_valid_where_runtime_contract_allows_them() {
        let mut value = web_review_value();
        for field in [
            "max_discovery_depth",
            "max_references_per_document",
            "max_forms",
            "max_controls_per_form",
            "max_query_parameter_names",
            "max_total_requests",
            "max_wall_time_ms",
            "max_active_verifications",
        ] {
            set_limit(&mut value, field, json!(0));
        }
        let profile = parse(&value).unwrap();
        assert_eq!(profile.limits().max_discovery_depth(), 0);
        assert_eq!(profile.limits().max_total_requests(), 0);
        assert_eq!(profile.limits().max_wall_time_ms(), 0);
        assert_eq!(profile.limits().max_active_verifications(), 0);
    }

    #[test]
    fn baseline_rejects_any_limit_that_differs_from_its_exact_cli_envelope() {
        for (field, replacement) in [
            ("max_subjects", json!(2)),
            ("max_discovery_depth", json!(1)),
            ("max_references_per_document", json!(1)),
            ("max_canonical_url_bytes", json!(1)),
            ("max_retained_url_bytes", json!(1)),
            ("max_forms", json!(1)),
            ("max_controls_per_form", json!(1)),
            ("max_query_parameter_names", json!(1)),
            ("max_total_requests", json!(0)),
            ("max_response_body_bytes", json!(1)),
            ("max_total_response_bytes", json!(1)),
            ("max_wall_time_ms", json!(0)),
            ("max_active_verifications", json!(0)),
        ] {
            let mut value = profile_value(ScanProfileV1::baseline().unwrap());
            set_limit(&mut value, field, replacement);
            assert!(parse(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn profile_scope_and_capability_combinations_are_not_user_selectable() {
        let mut baseline_scope = profile_value(ScanProfileV1::baseline().unwrap());
        baseline_scope["scope"] = json!("exact-origin");
        assert!(parse(&baseline_scope).is_err());

        let mut web_scope = web_review_value();
        web_scope["scope"] = json!("single-resource");
        assert!(parse(&web_scope).is_err());

        for built_in in [
            ScanProfileV1::baseline().unwrap(),
            ScanProfileV1::web_review().unwrap(),
        ] {
            for capability in [
                "standard_web_decision",
                "origin_discovery",
                "semantic_extraction",
                "defense_observation",
                "defense_shadow_planning",
                "low_risk_differential_review",
            ] {
                let mut value = profile_value(built_in.clone());
                let current = value["capabilities"][capability].as_bool().unwrap();
                value["capabilities"][capability] = json!(!current);
                assert!(parse(&value).is_err(), "{capability}");
            }
        }
    }

    #[test]
    fn defense_enforcement_is_default_off_and_requires_explicit_web_review_opt_in() {
        let baseline = ScanProfileV1::baseline().unwrap();
        assert!(baseline.with_defense_enforcement_enabled(true).is_err());

        let web_review = ScanProfileV1::web_review().unwrap();
        assert!(!web_review.defense_enforcement_enabled());
        let enabled = web_review.with_defense_enforcement_enabled(true).unwrap();
        assert!(enabled.defense_enforcement_enabled());
        let round_trip: ScanProfileV1 =
            serde_json::from_value(profile_value(enabled.clone())).unwrap();
        assert_eq!(round_trip, enabled);

        let mut baseline_wire = profile_value(ScanProfileV1::baseline().unwrap());
        baseline_wire["defense"]["enforcement_enabled"] = json!(true);
        assert!(parse(&baseline_wire).is_err());
    }

    #[test]
    fn checked_limit_replacement_preserves_profile_invariants() {
        let web_review = ScanProfileV1::web_review().unwrap();
        let narrowed = WebAssessmentLimits::default()
            .with_max_subjects(2)
            .unwrap()
            .with_max_total_requests(3)
            .unwrap();
        let web_review = web_review.with_limits(narrowed).unwrap();
        assert_eq!(web_review.limits().max_subjects(), 2);
        assert_eq!(web_review.limits().max_total_requests(), 3);

        let baseline = ScanProfileV1::baseline().unwrap();
        assert!(baseline.with_limits(narrowed).is_err());
    }

    #[test]
    fn checked_limit_conversion_requires_lossless_millisecond_precision() {
        let sub_millisecond = WebAssessmentLimits::default()
            .with_max_wall_time(Duration::from_nanos(1))
            .unwrap();
        assert!(matches!(
            ScanProfileLimitsV1::from_web_assessment_limits(sub_millisecond),
            Err(ScanProfileV1Error::SubMillisecondWallTime)
        ));
        assert!(matches!(
            ScanProfileV1::web_review()
                .unwrap()
                .with_limits(sub_millisecond),
            Err(ScanProfileV1Error::SubMillisecondWallTime)
        ));

        let exact_milliseconds = WebAssessmentLimits::default()
            .with_max_wall_time(Duration::from_millis(1_234))
            .unwrap();
        let profile = ScanProfileV1::web_review()
            .unwrap()
            .with_limits(exact_milliseconds)
            .unwrap();
        let encoded = serde_json::to_string(&profile).unwrap();
        let decoded: ScanProfileV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, profile);
        assert_eq!(decoded.web_assessment_limits(), exact_milliseconds);
    }
}
