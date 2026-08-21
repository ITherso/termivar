//! Transport-neutral run completion and audit records.
//!
//! These records describe whether work completed and which verifier outcomes or
//! unresolved observations were retained. They do not turn an observation into
//! a vulnerability finding and they do not grant execution authority.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    marker::PhantomData,
};

use chrono::{DateTime, Utc};
use serde::{
    de::{DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{EntityId, EvidenceId, Outcome, OutcomeStatus, Probability, VerificationStage};

/// Stable schema name for a typed Venom run report.
pub const RUN_REPORT_SCHEMA: &str = "venom-run/v1";
/// Maximum bytes retained in a single human-readable report field.
pub const MAX_RUN_REPORT_TEXT_BYTES: usize = 1_024;
/// Maximum steps retained in one report.
pub const MAX_RUN_REPORT_STEPS: usize = 4_096;
/// Maximum outcome projections retained in one report.
pub const MAX_RUN_REPORT_OUTCOMES: usize = 4_096;
/// Maximum evidence references retained by one projected outcome.
pub const MAX_RUN_REPORT_EVIDENCE_IDS: usize = 256;

/// Validation errors for typed run reports.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RunReportError {
    /// A required field was blank.
    #[error("{field} must not be blank")]
    Blank { field: &'static str },
    /// A bounded string exceeded its limit.
    #[error("{field} exceeds {limit} bytes")]
    TextTooLong { field: &'static str, limit: usize },
    /// A collection exceeded its retention ceiling.
    #[error("{field} contains {actual} records; limit is {limit}")]
    TooMany {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    /// Completion predates the recorded start.
    #[error("completed_at must not precede started_at")]
    InvalidTimeRange,
    /// A resource accounting record mixed metered and unmetered semantics.
    #[error("invalid resource accounting: {reason}")]
    InvalidAccounting { reason: &'static str },
    /// A step ordinal was duplicated or out of order.
    #[error("step ordinals must be strictly increasing")]
    InvalidStepOrder,
    /// Two executable steps declared the same host-visible identity.
    #[error("registered step identities must be unique")]
    DuplicateStepIdentity,
    /// A mutable host view no longer matched the immutable authority captured
    /// for this run before execution.
    #[error("run authority no longer matches its captured execution scope")]
    RunAuthorityMismatch,
    /// An outcome fingerprint was malformed or duplicated.
    #[error("invalid or duplicate outcome fingerprint")]
    InvalidFingerprint,
    /// An outcome projection contradicted the existing outcome contract.
    #[error("invalid {status:?} outcome projection: {reason}")]
    InvalidOutcome {
        /// Existing verifier disposition being projected.
        status: OutcomeStatus,
        /// Stable explanation of the violated invariant.
        reason: &'static str,
    },
    /// The run schema was not the supported version.
    #[error("unsupported run report schema: {0}")]
    UnsupportedSchema(String),
    /// The overall status contradicted the typed stop classification.
    #[error("run status {status:?} is incompatible with stop code {code:?}")]
    IncompatibleStatusStop {
        /// Overall completion state.
        status: RunStatus,
        /// Stop classification supplied with that state.
        code: RunStopCode,
    },
    /// Step-level states contradicted the aggregate run state.
    #[error("run status {status:?} with stop code {code:?} contradicts its steps: {reason}")]
    InconsistentSteps {
        /// Overall completion state.
        status: RunStatus,
        /// Stop classification supplied with that state.
        code: RunStopCode,
        /// Stable explanation of the mismatch.
        reason: &'static str,
    },
}

fn bounded(value: impl Into<String>, field: &'static str) -> Result<String, RunReportError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(RunReportError::Blank { field });
    }
    if value.len() > MAX_RUN_REPORT_TEXT_BYTES {
        return Err(RunReportError::TextTooLong {
            field,
            limit: MAX_RUN_REPORT_TEXT_BYTES,
        });
    }
    Ok(value)
}

fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedStringSeed::new("run report text").deserialize(deserializer)
}

fn deserialize_optional_bounded_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(BoundedOptionalStringVisitor::new("run report text"))
}

fn deserialize_bounded_entity_id<'de, D>(deserializer: D) -> Result<EntityId, D::Error>
where
    D: Deserializer<'de>,
{
    let value = BoundedStringSeed::new("run report entity id").deserialize(deserializer)?;
    EntityId::new(value).map_err(serde::de::Error::custom)
}

struct BoundedStringSeed {
    field: &'static str,
}

impl BoundedStringSeed {
    const fn new(field: &'static str) -> Self {
        Self { field }
    }
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BoundedStringVisitor::new(self.field))
    }
}

struct BoundedStringVisitor {
    field: &'static str,
}

impl BoundedStringVisitor {
    const fn new(field: &'static str) -> Self {
        Self { field }
    }

    fn check<E>(&self, value: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_RUN_REPORT_TEXT_BYTES {
            return Err(E::custom(format_args!(
                "{} exceeds the byte limit of {MAX_RUN_REPORT_TEXT_BYTES}",
                self.field
            )));
        }
        Ok(())
    }
}

impl<'de> Visitor<'de> for BoundedStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} no longer than {MAX_RUN_REPORT_TEXT_BYTES} bytes",
            self.field
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.check(value)?;
        Ok(value.to_owned())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.check(&value)?;
        Ok(value)
    }
}

struct BoundedOptionalStringVisitor {
    field: &'static str,
}

impl BoundedOptionalStringVisitor {
    const fn new(field: &'static str) -> Self {
        Self { field }
    }
}

impl<'de> Visitor<'de> for BoundedOptionalStringVisitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "null or {} no longer than {MAX_RUN_REPORT_TEXT_BYTES} bytes",
            self.field
        )
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        BoundedStringSeed::new(self.field)
            .deserialize(deserializer)
            .map(Some)
    }
}

/// Overall completion state for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunStatus {
    /// Every scheduled step reached its intended completion boundary.
    Complete,
    /// Some useful state was retained, but one or more steps did not complete.
    Partial,
    /// Host cancellation stopped the run.
    Cancelled,
    /// The run failed before it could produce a useful partial result.
    Failed,
}

/// Stable classification for why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunStopCode {
    /// The configured work completed.
    Completed,
    /// No action remained eligible.
    NoEligibleAction,
    /// A resource envelope stopped further work.
    BudgetExhausted,
    /// A report retention ceiling was reached after useful work completed.
    ReportLimitExceeded,
    /// The host cancelled the run.
    Cancelled,
    /// A phase returned an error.
    StepFailed,
    /// A phase exceeded its deadline.
    StepTimedOut,
    /// A task panicked or otherwise failed to join.
    TaskJoinFailed,
    /// Runtime orchestration failed.
    RuntimeFailed,
}

/// Structured, bounded reason that ended a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RunStopReasonWire")]
pub struct RunStopReason {
    code: RunStopCode,
    detail: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunStopReasonWire {
    code: RunStopCode,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    detail: String,
}

impl RunStopReason {
    /// Creates a bounded stop reason.
    pub fn new(code: RunStopCode, detail: impl Into<String>) -> Result<Self, RunReportError> {
        Ok(Self {
            code,
            detail: bounded(detail, "stop reason")?,
        })
    }

    /// Returns the stable stop classification.
    pub const fn code(&self) -> RunStopCode {
        self.code
    }

    /// Returns the bounded explanatory detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl TryFrom<RunStopReasonWire> for RunStopReason {
    type Error = RunReportError;

    fn try_from(value: RunStopReasonWire) -> Result<Self, Self::Error> {
        Self::new(value.code, value.detail)
    }
}

/// Completion state for one phase or semantic action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunStepStatus {
    /// The step completed its objective.
    Succeeded,
    /// The step returned an error.
    Failed,
    /// The step exceeded its deadline.
    TimedOut,
    /// Host cancellation interrupted the step.
    Cancelled,
    /// Policy prevented the step from running.
    Skipped,
    /// Resource policy denied the step.
    BudgetExhausted,
}

/// Typed severity attached to a projected outcome or unresolved observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecuritySeverity {
    /// Informational observation with no security impact claim.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

/// Whether a resource dimension was enforced by a shared meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceAccountingMode {
    /// The runtime measured and enforced this dimension.
    Metered,
    /// The runtime observed consumption but did not enforce a limit.
    Observed,
    /// The runtime cannot truthfully report this dimension.
    Unmetered,
}

/// Accounting for one resource dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResourceAccountingWire")]
pub struct ResourceAccounting {
    mode: ResourceAccountingMode,
    limit: Option<u64>,
    consumed: Option<u64>,
    remaining: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceAccountingWire {
    mode: ResourceAccountingMode,
    limit: Option<u64>,
    consumed: Option<u64>,
    remaining: Option<u64>,
}

impl ResourceAccounting {
    /// Records a metered resource. `consumed` may exceed `limit` by the single
    /// observation that revealed a boundary crossing.
    pub const fn metered(limit: u64, consumed: u64) -> Self {
        Self {
            mode: ResourceAccountingMode::Metered,
            limit: Some(limit),
            consumed: Some(consumed),
            remaining: Some(limit.saturating_sub(consumed)),
        }
    }

    /// Records observed consumption for a dimension without claiming that the
    /// runtime enforced a limit.
    pub const fn observed(consumed: u64) -> Self {
        Self {
            mode: ResourceAccountingMode::Observed,
            limit: None,
            consumed: Some(consumed),
            remaining: None,
        }
    }

    /// Records that the runtime did not meter this dimension.
    pub const fn unmetered() -> Self {
        Self {
            mode: ResourceAccountingMode::Unmetered,
            limit: None,
            consumed: None,
            remaining: None,
        }
    }

    /// Returns the accounting mode.
    pub const fn mode(&self) -> ResourceAccountingMode {
        self.mode
    }

    /// Returns the enforced limit when metered.
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Returns measured consumption when metered.
    pub const fn consumed(&self) -> Option<u64> {
        self.consumed
    }

    /// Returns remaining capacity when metered.
    pub const fn remaining(&self) -> Option<u64> {
        self.remaining
    }
}

impl TryFrom<ResourceAccountingWire> for ResourceAccounting {
    type Error = RunReportError;

    fn try_from(value: ResourceAccountingWire) -> Result<Self, Self::Error> {
        match (value.mode, value.limit, value.consumed, value.remaining) {
            (ResourceAccountingMode::Unmetered, None, None, None) => Ok(Self::unmetered()),
            (ResourceAccountingMode::Observed, None, Some(consumed), None) => {
                Ok(Self::observed(consumed))
            },
            (ResourceAccountingMode::Metered, Some(limit), Some(consumed), Some(remaining))
                if remaining == limit.saturating_sub(consumed) =>
            {
                Ok(Self::metered(limit, consumed))
            },
            _ => Err(RunReportError::InvalidAccounting {
                reason: "mode and values are inconsistent",
            }),
        }
    }
}

/// Run-level resource accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAccounting {
    requests: ResourceAccounting,
    response_body_bytes: ResourceAccounting,
    request_body_bytes: ResourceAccounting,
    wall_time_ms: ResourceAccounting,
}

impl RunAccounting {
    /// Creates accounting for all required resource dimensions.
    pub const fn new(
        requests: ResourceAccounting,
        response_body_bytes: ResourceAccounting,
        request_body_bytes: ResourceAccounting,
        wall_time_ms: ResourceAccounting,
    ) -> Self {
        Self {
            requests,
            response_body_bytes,
            request_body_bytes,
            wall_time_ms,
        }
    }

    /// Returns fully explicit unmetered accounting.
    pub const fn unmetered() -> Self {
        Self::new(
            ResourceAccounting::unmetered(),
            ResourceAccounting::unmetered(),
            ResourceAccounting::unmetered(),
            ResourceAccounting::unmetered(),
        )
    }

    /// Returns request accounting.
    pub const fn requests(&self) -> &ResourceAccounting {
        &self.requests
    }

    /// Returns response-body accounting.
    pub const fn response_body_bytes(&self) -> &ResourceAccounting {
        &self.response_body_bytes
    }

    /// Returns request-body accounting.
    pub const fn request_body_bytes(&self) -> &ResourceAccounting {
        &self.request_body_bytes
    }

    /// Returns wall-time accounting.
    pub const fn wall_time_ms(&self) -> &ResourceAccounting {
        &self.wall_time_ms
    }
}

/// One attempted phase or semantic action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RunStepReportWire")]
pub struct RunStepReport {
    ordinal: u32,
    action_id: String,
    status: RunStepStatus,
    duration_ms: u64,
    detail: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunStepReportWire {
    ordinal: u32,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    action_id: String,
    status: RunStepStatus,
    duration_ms: u64,
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string")]
    detail: Option<String>,
}

impl RunStepReport {
    /// Creates a bounded step report.
    pub fn new(
        ordinal: u32,
        action_id: impl Into<String>,
        status: RunStepStatus,
        duration_ms: u64,
        detail: Option<String>,
    ) -> Result<Self, RunReportError> {
        Ok(Self {
            ordinal,
            action_id: bounded(action_id, "step action id")?,
            status,
            duration_ms,
            detail: detail
                .map(|value| bounded(value, "step detail"))
                .transpose()?,
        })
    }

    /// Returns the stable step ordinal.
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the phase or action identity.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the completion state.
    pub const fn status(&self) -> RunStepStatus {
        self.status
    }

    /// Returns the observed duration.
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    /// Returns bounded diagnostic detail.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl TryFrom<RunStepReportWire> for RunStepReport {
    type Error = RunReportError;

    fn try_from(value: RunStepReportWire) -> Result<Self, Self::Error> {
        Self::new(
            value.ordinal,
            value.action_id,
            value.status,
            value.duration_ms,
            value.detail,
        )
    }
}

/// A verifier outcome or unresolved observation projected into a run report.
///
/// Non-unknown records can only be created from an already validated
/// [`Outcome`]. The flattened fields make reports convenient to consume while
/// the embedded outcome preserves the verifier rule, case, hypothesis, stage,
/// and evidence provenance needed to revalidate a serialized record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RunOutcomeRecordWire")]
pub struct RunOutcomeRecord {
    fingerprint: String,
    subject: EntityId,
    action_id: String,
    severity: SecuritySeverity,
    disposition: OutcomeStatus,
    confidence: Probability,
    evidence_ids: BTreeSet<EvidenceId>,
    rationale: String,
    redacted_summary: String,
    verification: Option<Outcome>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunOutcomeRecordWire {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    fingerprint: String,
    #[serde(deserialize_with = "deserialize_bounded_entity_id")]
    subject: EntityId,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    action_id: String,
    severity: SecuritySeverity,
    disposition: OutcomeStatus,
    confidence: Probability,
    #[serde(deserialize_with = "deserialize_evidence_ids")]
    evidence_ids: BTreeSet<EvidenceId>,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    rationale: String,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    redacted_summary: String,
    verification: Option<VerificationOutcomeWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationOutcomeWire {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    case_id: String,
    #[serde(deserialize_with = "deserialize_bounded_entity_id")]
    subject: EntityId,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    action_id: String,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    hypothesis_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string")]
    verifier_rule_id: Option<String>,
    stage: VerificationStage,
    status: OutcomeStatus,
    confidence: Probability,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    rationale: String,
    #[serde(deserialize_with = "deserialize_evidence_ids")]
    evidence_ids: BTreeSet<EvidenceId>,
}

fn deserialize_evidence_ids<'de, D>(deserializer: D) -> Result<BTreeSet<EvidenceId>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedEvidenceIdsVisitor)
}

struct BoundedEvidenceIdsVisitor;

struct BoundedEvidenceIdSeed;

struct BoundedEvidenceIdVisitor;

impl<'de> DeserializeSeed<'de> for BoundedEvidenceIdSeed {
    type Value = EvidenceId;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BoundedEvidenceIdVisitor)
    }
}

impl<'de> Visitor<'de> for BoundedEvidenceIdVisitor {
    type Value = EvidenceId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "an evidence identifier no longer than {MAX_RUN_REPORT_TEXT_BYTES} bytes"
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_RUN_REPORT_TEXT_BYTES {
            return Err(E::custom(format_args!(
                "outcome evidence id exceeds the byte limit of {MAX_RUN_REPORT_TEXT_BYTES}"
            )));
        }
        EvidenceId::parse(value).map_err(E::custom)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Visitor<'de> for BoundedEvidenceIdsVisitor {
    type Value = BTreeSet<EvidenceId>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_RUN_REPORT_EVIDENCE_IDS} encoded evidence identifiers"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > MAX_RUN_REPORT_EVIDENCE_IDS)
        {
            return Err(serde::de::Error::custom(format_args!(
                "outcome evidence ids exceed the encoded-entry limit of {MAX_RUN_REPORT_EVIDENCE_IDS}"
            )));
        }

        let mut evidence_ids = BTreeSet::new();
        let mut encoded_entries = 0_usize;
        while let Some(evidence_id) = sequence.next_element_seed(BoundedEvidenceIdSeed)? {
            encoded_entries += 1;
            if encoded_entries > MAX_RUN_REPORT_EVIDENCE_IDS {
                return Err(serde::de::Error::custom(format_args!(
                    "outcome evidence ids exceed the encoded-entry limit of {MAX_RUN_REPORT_EVIDENCE_IDS}"
                )));
            }
            evidence_ids.insert(evidence_id);
        }
        Ok(evidence_ids)
    }
}

impl VerificationOutcomeWire {
    fn into_outcome(self) -> Result<Outcome, RunReportError> {
        if self.status == OutcomeStatus::Unknown {
            if self.verifier_rule_id.is_some()
                || self.confidence != Probability::ZERO
                || !self.evidence_ids.is_empty()
            {
                return Err(RunReportError::InvalidOutcome {
                    status: self.status,
                    reason: "unknown verifier outcome has non-canonical provenance",
                });
            }
            return Outcome::unknown(
                self.case_id,
                self.subject,
                self.action_id,
                self.hypothesis_id,
                self.stage,
                self.rationale,
            )
            .map_err(|_| RunReportError::InvalidOutcome {
                status: self.status,
                reason: "embedded verifier outcome is invalid",
            });
        }

        let verifier_rule_id = self
            .verifier_rule_id
            .ok_or(RunReportError::InvalidOutcome {
                status: self.status,
                reason: "verified outcome is missing verifier rule provenance",
            })?;
        Outcome::verified(
            self.case_id,
            self.subject,
            self.action_id,
            self.hypothesis_id,
            verifier_rule_id,
            self.stage,
            self.status,
            self.confidence,
            self.rationale,
            self.evidence_ids,
        )
        .map_err(|_| RunReportError::InvalidOutcome {
            status: self.status,
            reason: "embedded verifier outcome is invalid",
        })
    }
}

impl RunOutcomeRecord {
    /// Creates the canonical projection for an unresolved observation that did
    /// not pass through a verifier case.
    pub fn unresolved(
        subject: EntityId,
        action_id: impl Into<String>,
        rationale: impl Into<String>,
        redacted_summary: impl Into<String>,
    ) -> Result<Self, RunReportError> {
        let mut record = Self {
            fingerprint: String::new(),
            subject,
            action_id: bounded(action_id, "outcome action id")?,
            severity: SecuritySeverity::Info,
            disposition: OutcomeStatus::Unknown,
            confidence: Probability::ZERO,
            evidence_ids: BTreeSet::new(),
            rationale: bounded(rationale, "outcome rationale")?,
            redacted_summary: bounded(redacted_summary, "redacted evidence summary")?,
            verification: None,
        };
        validate_record_bounds(&record)?;
        record.fingerprint = outcome_fingerprint(&record);
        Ok(record)
    }

    /// Projects an existing verifier-owned outcome without weakening its case,
    /// rule, confidence, or immutable evidence requirements.
    ///
    /// Projection remains informational because verifier success does not by
    /// itself establish security impact or finding severity. [`Outcome`] also
    /// does not carry the orchestration-level `VerificationCase` transition
    /// permission: a knowledge-only `Success` is therefore not promoted into a
    /// finding or confirmed claim here. A future impact policy may add a
    /// narrower constructor without weakening this boundary.
    pub fn from_outcome(
        outcome: Outcome,
        redacted_summary: impl Into<String>,
    ) -> Result<Self, RunReportError> {
        let mut record = Self {
            fingerprint: String::new(),
            subject: outcome.subject().clone(),
            action_id: outcome.action_id().to_string(),
            severity: SecuritySeverity::Info,
            disposition: outcome.status(),
            confidence: outcome.confidence(),
            evidence_ids: outcome.evidence_ids().clone(),
            rationale: bounded(outcome.rationale(), "outcome rationale")?,
            redacted_summary: bounded(redacted_summary, "redacted evidence summary")?,
            verification: Some(outcome),
        };
        validate_record_bounds(&record)?;
        record.fingerprint = outcome_fingerprint(&record);
        Ok(record)
    }

    /// Returns the verifier-owned outcome when this is a verification
    /// projection. Unresolved compatibility observations return `None`.
    pub const fn verification_outcome(&self) -> Option<&Outcome> {
        self.verification.as_ref()
    }

    /// Returns the stable deterministic fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the target subject.
    pub const fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the producer action or module identity.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns typed severity.
    pub const fn severity(&self) -> SecuritySeverity {
        self.severity
    }

    /// Returns the existing verifier disposition vocabulary.
    pub const fn disposition(&self) -> OutcomeStatus {
        self.disposition
    }

    /// Returns confidence in the projected record.
    pub const fn confidence(&self) -> Probability {
        self.confidence
    }

    /// Returns correlated immutable evidence identifiers.
    pub const fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence_ids
    }

    /// Returns the bounded rationale.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns the bounded, redacted evidence summary.
    pub fn redacted_summary(&self) -> &str {
        &self.redacted_summary
    }
}

fn validate_record_bounds(record: &RunOutcomeRecord) -> Result<(), RunReportError> {
    if record.action_id.len() > MAX_RUN_REPORT_TEXT_BYTES {
        return Err(RunReportError::TextTooLong {
            field: "outcome action id",
            limit: MAX_RUN_REPORT_TEXT_BYTES,
        });
    }
    if record.evidence_ids.len() > MAX_RUN_REPORT_EVIDENCE_IDS {
        return Err(RunReportError::TooMany {
            field: "outcome evidence ids",
            actual: record.evidence_ids.len(),
            limit: MAX_RUN_REPORT_EVIDENCE_IDS,
        });
    }
    if record
        .evidence_ids
        .iter()
        .any(|evidence_id| evidence_id.as_str().len() > MAX_RUN_REPORT_TEXT_BYTES)
    {
        return Err(RunReportError::TextTooLong {
            field: "outcome evidence id",
            limit: MAX_RUN_REPORT_TEXT_BYTES,
        });
    }
    if record.subject.as_str().len() > MAX_RUN_REPORT_TEXT_BYTES {
        return Err(RunReportError::TextTooLong {
            field: "outcome subject",
            limit: MAX_RUN_REPORT_TEXT_BYTES,
        });
    }
    if let Some(outcome) = &record.verification {
        for (field, value) in [
            ("verification case id", outcome.case_id()),
            ("verification hypothesis id", outcome.hypothesis_id()),
        ] {
            if value.len() > MAX_RUN_REPORT_TEXT_BYTES {
                return Err(RunReportError::TextTooLong {
                    field,
                    limit: MAX_RUN_REPORT_TEXT_BYTES,
                });
            }
        }
        if outcome
            .verifier_rule_id()
            .is_some_and(|value| value.len() > MAX_RUN_REPORT_TEXT_BYTES)
        {
            return Err(RunReportError::TextTooLong {
                field: "verifier rule id",
                limit: MAX_RUN_REPORT_TEXT_BYTES,
            });
        }
    }
    Ok(())
}

impl TryFrom<RunOutcomeRecordWire> for RunOutcomeRecord {
    type Error = RunReportError;

    fn try_from(value: RunOutcomeRecordWire) -> Result<Self, Self::Error> {
        let rebuilt = match value.verification {
            Some(outcome) => Self::from_outcome(outcome.into_outcome()?, value.redacted_summary)?,
            None => Self::unresolved(
                value.subject.clone(),
                value.action_id.clone(),
                value.rationale.clone(),
                value.redacted_summary,
            )?,
        };
        if rebuilt.fingerprint != value.fingerprint
            || rebuilt.subject != value.subject
            || rebuilt.action_id != value.action_id
            || rebuilt.severity != value.severity
            || rebuilt.disposition != value.disposition
            || rebuilt.confidence != value.confidence
            || rebuilt.evidence_ids != value.evidence_ids
            || rebuilt.rationale != value.rationale
        {
            return Err(RunReportError::InvalidFingerprint);
        }
        Ok(rebuilt)
    }
}

fn outcome_fingerprint(record: &RunOutcomeRecord) -> String {
    let mut digest = Sha256::new();
    digest.update(b"venom.run-outcome.v1\0");
    digest_field(
        &mut digest,
        if record.verification.is_some() {
            "verified"
        } else {
            "unresolved"
        },
    );
    digest_field(&mut digest, record.subject.as_str());
    digest_field(&mut digest, &record.action_id);
    digest_field(&mut digest, outcome_code(record.disposition));
    digest.update(record.confidence.parts_per_million().to_be_bytes());
    for evidence_id in &record.evidence_ids {
        digest_field(&mut digest, evidence_id.as_str());
    }
    if let Some(outcome) = &record.verification {
        for field in [
            outcome.case_id(),
            outcome.hypothesis_id(),
            outcome.verifier_rule_id().unwrap_or(""),
            outcome.stage().as_str(),
        ] {
            digest_field(&mut digest, field);
        }
    }
    format!("sha256:{:x}", digest.finalize())
}

fn digest_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn outcome_code(value: OutcomeStatus) -> &'static str {
    match value {
        OutcomeStatus::Success => "success",
        OutcomeStatus::Blocked => "blocked",
        OutcomeStatus::Unknown => "unknown",
        OutcomeStatus::FalsePositive => "false_positive",
        OutcomeStatus::NeedsReview => "needs_review",
        OutcomeStatus::ConfirmedNegative => "confirmed_negative",
    }
}

/// Complete transport-neutral report for one authorized run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RunReportWire")]
pub struct RunReport {
    schema: String,
    status: RunStatus,
    stop_reason: RunStopReason,
    target: String,
    authorized_origin: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    accounting: RunAccounting,
    steps: Vec<RunStepReport>,
    outcomes: Vec<RunOutcomeRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunReportWire {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    schema: String,
    status: RunStatus,
    stop_reason: RunStopReason,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    target: String,
    #[serde(deserialize_with = "deserialize_bounded_string")]
    authorized_origin: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    accounting: RunAccounting,
    #[serde(deserialize_with = "deserialize_run_steps")]
    steps: Vec<RunStepReport>,
    #[serde(deserialize_with = "deserialize_run_outcomes")]
    outcomes: Vec<RunOutcomeRecord>,
}

fn deserialize_run_steps<'de, D>(deserializer: D) -> Result<Vec<RunStepReport>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::<RunStepReport>::new(
        "run steps",
        MAX_RUN_REPORT_STEPS,
    ))
}

fn deserialize_run_outcomes<'de, D>(deserializer: D) -> Result<Vec<RunOutcomeRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::<RunOutcomeRecord>::new(
        "run outcomes",
        MAX_RUN_REPORT_OUTCOMES,
    ))
}

struct BoundedVecVisitor<T> {
    field: &'static str,
    limit: usize,
    marker: PhantomData<T>,
}

impl<T> BoundedVecVisitor<T> {
    const fn new(field: &'static str, limit: usize) -> Self {
        Self {
            field,
            limit,
            marker: PhantomData,
        }
    }
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} {}", self.limit, self.field)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > self.limit) {
            return Err(serde::de::Error::custom(format_args!(
                "{} exceeds the limit of {}",
                self.field, self.limit
            )));
        }
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.limit));
        while let Some(value) = sequence.next_element()? {
            if values.len() == self.limit {
                return Err(serde::de::Error::custom(format_args!(
                    "{} exceeds the limit of {}",
                    self.field, self.limit
                )));
            }
            values.push(value);
        }
        Ok(values)
    }
}

/// Construction input for a validated [`RunReport`].
#[derive(Debug, Clone)]
pub struct RunReportInput {
    status: RunStatus,
    stop_reason: RunStopReason,
    target: String,
    authorized_origin: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    accounting: RunAccounting,
    steps: Vec<RunStepReport>,
    outcomes: Vec<RunOutcomeRecord>,
}

impl RunReportInput {
    /// Creates the required run envelope with explicit unmetered accounting.
    pub fn new(
        status: RunStatus,
        stop_reason: RunStopReason,
        target: impl Into<String>,
        authorized_origin: impl Into<String>,
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self, RunReportError> {
        Ok(Self {
            status,
            stop_reason,
            target: bounded(target, "run target")?,
            authorized_origin: bounded(authorized_origin, "authorized origin")?,
            started_at,
            completed_at,
            accounting: RunAccounting::unmetered(),
            steps: Vec::new(),
            outcomes: Vec::new(),
        })
    }

    /// Replaces resource accounting with the host's explicit measurements.
    pub fn with_accounting(mut self, accounting: RunAccounting) -> Self {
        self.accounting = accounting;
        self
    }

    /// Attaches attempted steps in execution order.
    pub fn with_steps(mut self, steps: Vec<RunStepReport>) -> Self {
        self.steps = steps;
        self
    }

    /// Attaches projected outcomes and unresolved observations.
    pub fn with_outcomes(mut self, outcomes: Vec<RunOutcomeRecord>) -> Self {
        self.outcomes = outcomes;
        self
    }
}

impl RunReport {
    /// Creates and validates a complete run report.
    pub fn new(input: RunReportInput) -> Result<Self, RunReportError> {
        if input.completed_at < input.started_at {
            return Err(RunReportError::InvalidTimeRange);
        }
        if !status_matches_stop(input.status, input.stop_reason.code()) {
            return Err(RunReportError::IncompatibleStatusStop {
                status: input.status,
                code: input.stop_reason.code(),
            });
        }
        if input.steps.len() > MAX_RUN_REPORT_STEPS {
            return Err(RunReportError::TooMany {
                field: "run steps",
                actual: input.steps.len(),
                limit: MAX_RUN_REPORT_STEPS,
            });
        }
        if input.outcomes.len() > MAX_RUN_REPORT_OUTCOMES {
            return Err(RunReportError::TooMany {
                field: "run outcomes",
                actual: input.outcomes.len(),
                limit: MAX_RUN_REPORT_OUTCOMES,
            });
        }
        if input
            .steps
            .windows(2)
            .any(|pair| pair[0].ordinal() >= pair[1].ordinal())
        {
            return Err(RunReportError::InvalidStepOrder);
        }
        validate_aggregate_consistency(
            input.status,
            input.stop_reason.code(),
            &input.steps,
            &input.outcomes,
        )?;
        let mut fingerprints = HashSet::with_capacity(input.outcomes.len());
        if input
            .outcomes
            .iter()
            .any(|record| !fingerprints.insert(record.fingerprint()))
        {
            return Err(RunReportError::InvalidFingerprint);
        }
        Ok(Self {
            schema: RUN_REPORT_SCHEMA.to_string(),
            status: input.status,
            stop_reason: input.stop_reason,
            target: input.target,
            authorized_origin: input.authorized_origin,
            started_at: input.started_at,
            completed_at: input.completed_at,
            accounting: input.accounting,
            steps: input.steps,
            outcomes: input.outcomes,
        })
    }

    /// Returns the stable schema name.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns overall completion status.
    pub const fn status(&self) -> RunStatus {
        self.status
    }

    /// Returns the structured stop reason.
    pub const fn stop_reason(&self) -> &RunStopReason {
        &self.stop_reason
    }

    /// Returns the sanitized target representation.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the authorized origin.
    pub fn authorized_origin(&self) -> &str {
        &self.authorized_origin
    }

    /// Returns the UTC start instant.
    pub const fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Returns the UTC completion instant.
    pub const fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }

    /// Returns resource accounting.
    pub const fn accounting(&self) -> &RunAccounting {
        &self.accounting
    }

    /// Returns attempted steps in execution order.
    pub fn steps(&self) -> &[RunStepReport] {
        &self.steps
    }

    /// Returns outcome/observation projections.
    pub fn outcomes(&self) -> &[RunOutcomeRecord] {
        &self.outcomes
    }
}

impl TryFrom<RunReportWire> for RunReport {
    type Error = RunReportError;

    fn try_from(value: RunReportWire) -> Result<Self, Self::Error> {
        if value.schema != RUN_REPORT_SCHEMA {
            return Err(RunReportError::UnsupportedSchema(value.schema));
        }
        let input = RunReportInput::new(
            value.status,
            value.stop_reason,
            value.target,
            value.authorized_origin,
            value.started_at,
            value.completed_at,
        )?
        .with_accounting(value.accounting)
        .with_steps(value.steps)
        .with_outcomes(value.outcomes);
        Self::new(input)
    }
}

fn status_matches_stop(status: RunStatus, code: RunStopCode) -> bool {
    match status {
        RunStatus::Complete => {
            matches!(code, RunStopCode::Completed | RunStopCode::NoEligibleAction)
        },
        RunStatus::Partial => matches!(
            code,
            RunStopCode::NoEligibleAction
                | RunStopCode::BudgetExhausted
                | RunStopCode::ReportLimitExceeded
                | RunStopCode::StepFailed
                | RunStopCode::StepTimedOut
                | RunStopCode::TaskJoinFailed
                | RunStopCode::RuntimeFailed
        ),
        RunStatus::Cancelled => code == RunStopCode::Cancelled,
        RunStatus::Failed => matches!(
            code,
            RunStopCode::BudgetExhausted
                | RunStopCode::StepFailed
                | RunStopCode::StepTimedOut
                | RunStopCode::TaskJoinFailed
                | RunStopCode::RuntimeFailed
        ),
    }
}

fn validate_aggregate_consistency(
    status: RunStatus,
    code: RunStopCode,
    steps: &[RunStepReport],
    outcomes: &[RunOutcomeRecord],
) -> Result<(), RunReportError> {
    let has = |wanted| steps.iter().any(|step| step.status() == wanted);
    let has_success = has(RunStepStatus::Succeeded);
    let has_failure = has(RunStepStatus::Failed);
    let has_timeout = has(RunStepStatus::TimedOut);
    let has_cancelled = has(RunStepStatus::Cancelled);
    let has_skipped = has(RunStepStatus::Skipped);
    let has_budget_exhausted = has(RunStepStatus::BudgetExhausted);
    let useful_state = has_success || !outcomes.is_empty();

    let inconsistent = |reason| {
        Err(RunReportError::InconsistentSteps {
            status,
            code,
            reason,
        })
    };

    match status {
        RunStatus::Complete
            if steps
                .iter()
                .any(|step| step.status() != RunStepStatus::Succeeded) =>
        {
            return inconsistent("complete runs may contain only succeeded steps");
        },
        RunStatus::Complete if code == RunStopCode::Completed && steps.is_empty() => {
            return inconsistent("completed runs require at least one succeeded step");
        },
        RunStatus::Partial if !useful_state => {
            return inconsistent("partial runs must retain a successful step or outcome");
        },
        RunStatus::Partial if has_cancelled => {
            return inconsistent("a cancelled step requires cancelled aggregate status");
        },
        RunStatus::Failed if useful_state => {
            return inconsistent("failed runs cannot retain successful work as if it were absent");
        },
        RunStatus::Cancelled if !steps.is_empty() && !has_cancelled && !has_skipped => {
            return inconsistent("cancelled runs with steps require a cancelled or skipped step");
        },
        _ => {},
    }

    match code {
        RunStopCode::StepFailed if !has_failure => {
            inconsistent("step_failed requires a failed step")
        },
        RunStopCode::StepTimedOut if !has_timeout => {
            inconsistent("step_timed_out requires a timed-out step")
        },
        RunStopCode::TaskJoinFailed if !has_failure => {
            inconsistent("task_join_failed requires a failed step receipt")
        },
        RunStopCode::BudgetExhausted
            if status == RunStatus::Partial && !has_budget_exhausted && !has_success =>
        {
            inconsistent("partial budget exhaustion requires completed or denied step evidence")
        },
        RunStopCode::ReportLimitExceeded if outcomes.is_empty() => {
            inconsistent("report retention exhaustion requires retained outcomes")
        },
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_REPORT_JSON: &str = r#"{
  "schema": "venom-run/v1",
  "status": "complete",
  "stop_reason": {
    "code": "completed",
    "detail": "all configured steps completed"
  },
  "target": "https://example.test/",
  "authorized_origin": "https://example.test",
  "started_at": "2026-08-13T10:00:00Z",
  "completed_at": "2026-08-13T10:00:01Z",
  "accounting": {
    "requests": {
      "mode": "unmetered",
      "limit": null,
      "consumed": null,
      "remaining": null
    },
    "response_body_bytes": {
      "mode": "unmetered",
      "limit": null,
      "consumed": null,
      "remaining": null
    },
    "request_body_bytes": {
      "mode": "unmetered",
      "limit": null,
      "consumed": null,
      "remaining": null
    },
    "wall_time_ms": {
      "mode": "unmetered",
      "limit": null,
      "consumed": null,
      "remaining": null
    }
  },
  "steps": [
    {
      "ordinal": 1,
      "action_id": "legacy.recon",
      "status": "succeeded",
      "duration_ms": 1,
      "detail": null
    }
  ],
  "outcomes": [
    {
      "fingerprint": "sha256:bf121d89e97f83f2103ab3f97f9439e6b8485df96177ec8911b30ae38c0f9250",
      "subject": "endpoint:https://example.test",
      "action_id": "legacy.recon",
      "severity": "info",
      "disposition": "unknown",
      "confidence": 0,
      "evidence_ids": [],
      "rationale": "unverified legacy observation",
      "redacted_summary": "details redacted",
      "verification": null
    }
  ]
}"#;

    fn time(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }

    #[test]
    fn report_round_trip_and_golden_are_stable() {
        let outcome = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.recon",
            "unverified legacy observation",
            "details redacted",
        )
        .unwrap();
        let input = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "all configured steps completed").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_accounting(RunAccounting::unmetered())
        .with_steps(vec![RunStepReport::new(
            1,
            "legacy.recon",
            RunStepStatus::Succeeded,
            1,
            None,
        )
        .unwrap()])
        .with_outcomes(vec![outcome]);
        let report = RunReport::new(input).unwrap();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let decoded: RunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, report);
        assert_eq!(decoded.schema(), RUN_REPORT_SCHEMA);
        assert_eq!(json, GOLDEN_REPORT_JSON);
    }

    #[test]
    fn malformed_wire_fails_closed() {
        let invalid_accounting = r#"{
          "mode":"unmetered","limit":1,"consumed":0,"remaining":1
        }"#;
        assert!(serde_json::from_str::<ResourceAccounting>(invalid_accounting).is_err());

        let reason = RunStopReason::new(RunStopCode::NoEligibleAction, "done").unwrap();
        let input = RunReportInput::new(
            RunStatus::Complete,
            reason,
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap();
        let mut report = serde_json::to_value(RunReport::new(input).unwrap()).unwrap();
        report["schema"] = serde_json::json!("venom-run/v999");
        assert!(serde_json::from_value::<RunReport>(report).is_err());
    }

    #[test]
    fn accounting_distinguishes_enforced_observed_and_unknown_dimensions() {
        let metered = ResourceAccounting::metered(10, 4);
        assert_eq!(metered.mode(), ResourceAccountingMode::Metered);
        assert_eq!(metered.limit(), Some(10));
        assert_eq!(metered.consumed(), Some(4));
        assert_eq!(metered.remaining(), Some(6));

        let observed = ResourceAccounting::observed(7);
        assert_eq!(observed.mode(), ResourceAccountingMode::Observed);
        assert_eq!(observed.limit(), None);
        assert_eq!(observed.consumed(), Some(7));
        assert_eq!(observed.remaining(), None);
        assert_eq!(
            serde_json::from_value::<ResourceAccounting>(serde_json::to_value(&observed).unwrap())
                .unwrap(),
            observed
        );

        let unmetered = ResourceAccounting::unmetered();
        assert_eq!(unmetered.mode(), ResourceAccountingMode::Unmetered);
        assert_eq!(unmetered.consumed(), None);
    }

    #[test]
    fn report_retention_limit_is_distinct_from_runtime_budget_exhaustion() {
        let outcome = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.recon",
            "unresolved",
            "redacted",
        )
        .unwrap();
        let input = RunReportInput::new(
            RunStatus::Partial,
            RunStopReason::new(RunStopCode::ReportLimitExceeded, "retention limit").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_steps(vec![RunStepReport::new(
            1,
            "legacy.recon",
            RunStepStatus::Succeeded,
            1,
            None,
        )
        .unwrap()])
        .with_outcomes(vec![outcome]);
        let report = RunReport::new(input).unwrap();
        assert_eq!(
            report.stop_reason().code(),
            RunStopCode::ReportLimitExceeded
        );
        assert_eq!(report.status(), RunStatus::Partial);
    }

    #[test]
    fn report_rejects_unknown_fields_and_forged_fingerprints() {
        let outcome = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.recon",
            "unresolved",
            "redacted",
        )
        .unwrap();
        let mut forged = serde_json::to_value(&outcome).unwrap();
        forged["fingerprint"] = serde_json::json!("sha256:forged");
        assert!(serde_json::from_value::<RunOutcomeRecord>(forged).is_err());

        let input = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::NoEligibleAction, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap();
        let mut wire = serde_json::to_value(RunReport::new(input).unwrap()).unwrap();
        wire["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RunReport>(wire).is_err());

        let mut nested =
            serde_json::to_value(RunStopReason::new(RunStopCode::Completed, "done").unwrap())
                .unwrap();
        nested["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RunStopReason>(nested).is_err());

        let duplicate = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::NoEligibleAction, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_outcomes(vec![outcome.clone(), outcome]);
        assert_eq!(
            RunReport::new(duplicate),
            Err(RunReportError::InvalidFingerprint)
        );
    }

    #[test]
    fn report_rejects_incompatible_status_time_and_step_order() {
        let cancelled = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Cancelled, "host cancelled").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap();
        assert!(matches!(
            RunReport::new(cancelled),
            Err(RunReportError::IncompatibleStatusStop { .. })
        ));

        let reversed = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:01Z"),
            time("2026-08-13T10:00:00Z"),
        )
        .unwrap();
        assert_eq!(
            RunReport::new(reversed),
            Err(RunReportError::InvalidTimeRange)
        );

        let duplicate_steps = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_steps(vec![
            RunStepReport::new(1, "one", RunStepStatus::Succeeded, 1, None).unwrap(),
            RunStepReport::new(1, "two", RunStepStatus::Succeeded, 1, None).unwrap(),
        ]);
        assert_eq!(
            RunReport::new(duplicate_steps),
            Err(RunReportError::InvalidStepOrder)
        );

        let complete_with_skipped = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_steps(vec![RunStepReport::new(
            1,
            "skipped",
            RunStepStatus::Skipped,
            0,
            None,
        )
        .unwrap()]);
        assert!(matches!(
            RunReport::new(complete_with_skipped),
            Err(RunReportError::InconsistentSteps { .. })
        ));

        let complete = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_steps(vec![RunStepReport::new(
            1,
            "complete",
            RunStepStatus::Succeeded,
            1,
            None,
        )
        .unwrap()]);
        let mut complete_wire = serde_json::to_value(RunReport::new(complete).unwrap()).unwrap();
        complete_wire["steps"][0]["status"] = serde_json::json!("skipped");
        assert!(serde_json::from_value::<RunReport>(complete_wire).is_err());

        let cancelled_with_success = RunReportInput::new(
            RunStatus::Cancelled,
            RunStopReason::new(RunStopCode::Cancelled, "host cancelled").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_steps(vec![RunStepReport::new(
            1,
            "complete",
            RunStepStatus::Succeeded,
            1,
            None,
        )
        .unwrap()]);
        assert!(matches!(
            RunReport::new(cancelled_with_success),
            Err(RunReportError::InconsistentSteps { .. })
        ));

        let cancelled = RunReportInput::new(
            RunStatus::Cancelled,
            RunStopReason::new(RunStopCode::Cancelled, "host cancelled").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap()
        .with_steps(vec![RunStepReport::new(
            1,
            "skipped",
            RunStepStatus::Skipped,
            0,
            None,
        )
        .unwrap()]);
        let mut cancelled_wire = serde_json::to_value(RunReport::new(cancelled).unwrap()).unwrap();
        cancelled_wire["steps"][0]["status"] = serde_json::json!("succeeded");
        assert!(serde_json::from_value::<RunReport>(cancelled_wire).is_err());
    }

    #[test]
    fn unknown_projection_cannot_be_escalated_on_the_wire() {
        let record = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.detector",
            "legacy heuristic is unresolved",
            "redacted",
        )
        .unwrap();
        let mut severity = serde_json::to_value(&record).unwrap();
        severity["severity"] = serde_json::json!("critical");
        assert!(serde_json::from_value::<RunOutcomeRecord>(severity).is_err());

        let mut confidence = serde_json::to_value(&record).unwrap();
        confidence["confidence"] = serde_json::json!(900_000);
        assert!(serde_json::from_value::<RunOutcomeRecord>(confidence).is_err());

        let mut evidence = serde_json::to_value(record).unwrap();
        evidence["evidence_ids"] = serde_json::json!(["evidence:legacy"]);
        assert!(serde_json::from_value::<RunOutcomeRecord>(evidence).is_err());
    }

    #[test]
    fn verified_projection_preserves_provenance_and_ignores_presentation_wording_in_identity() {
        let verified = Outcome::verified(
            "case:nginx",
            EntityId::new("endpoint:https://example.test").unwrap(),
            "web.action.nginx.verify",
            "hypothesis:nginx",
            "verify.nginx.version",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(95).unwrap(),
            "version token matched",
            BTreeSet::from([EvidenceId::parse("evidence:server-header").unwrap()]),
        )
        .unwrap();
        let first =
            RunOutcomeRecord::from_outcome(verified.clone(), "server header redacted").unwrap();

        let mut wording = serde_json::to_value(&first).unwrap();
        wording["rationale"] = serde_json::json!("different explanation");
        wording["redacted_summary"] = serde_json::json!("different safe presentation");
        wording["verification"]["rationale"] = serde_json::json!("different explanation");
        let second: RunOutcomeRecord = serde_json::from_value(wording).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(second.severity(), SecuritySeverity::Info);
        let preserved = second.verification_outcome().unwrap();
        assert_eq!(preserved.case_id(), "case:nginx");
        assert_eq!(preserved.hypothesis_id(), "hypothesis:nginx");
        assert_eq!(preserved.verifier_rule_id(), Some("verify.nginx.version"));
        assert_eq!(preserved.stage(), VerificationStage::Passive);

        let mut forged = serde_json::to_value(first).unwrap();
        forged["verification"]["verifier_rule_id"] = serde_json::json!("verify.forged");
        assert!(serde_json::from_value::<RunOutcomeRecord>(forged).is_err());

        let projected = RunOutcomeRecord::from_outcome(verified, "redacted").unwrap();
        let mut severity = serde_json::to_value(projected).unwrap();
        severity["severity"] = serde_json::json!("high");
        assert!(serde_json::from_value::<RunOutcomeRecord>(severity).is_err());
    }

    #[test]
    fn wire_rejects_oversized_scalar_text_before_conversion() {
        let oversized = "x".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1);

        let stop_reason = serde_json::json!({
            "code": "completed",
            "detail": oversized,
        });
        assert!(serde_json::from_value::<RunStopReasonWire>(stop_reason).is_err());

        let step = RunStepReport::new(
            1,
            "legacy.recon",
            RunStepStatus::Succeeded,
            1,
            Some("complete".to_string()),
        )
        .unwrap();
        for field in ["action_id", "detail"] {
            let mut wire = serde_json::to_value(&step).unwrap();
            wire[field] = serde_json::json!(oversized);
            assert!(
                serde_json::from_value::<RunStepReportWire>(wire).is_err(),
                "oversized step {field} was accepted"
            );
        }
        let mut step_without_detail = serde_json::to_value(&step).unwrap();
        step_without_detail
            .as_object_mut()
            .unwrap()
            .remove("detail");
        assert!(serde_json::from_value::<RunStepReportWire>(step_without_detail).is_ok());

        let unresolved = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.detector",
            "unresolved",
            "redacted",
        )
        .unwrap();
        for field in [
            "fingerprint",
            "subject",
            "action_id",
            "rationale",
            "redacted_summary",
        ] {
            let mut wire = serde_json::to_value(&unresolved).unwrap();
            wire[field] = serde_json::json!(oversized);
            assert!(
                serde_json::from_value::<RunOutcomeRecordWire>(wire).is_err(),
                "oversized outcome {field} was accepted"
            );
        }

        let verified = Outcome::verified(
            "case:bounded-scalars",
            EntityId::new("endpoint:https://example.test").unwrap(),
            "verified.action",
            "hypothesis:bounded-scalars",
            "verify.bounded-scalars",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(90).unwrap(),
            "verified",
            BTreeSet::from([EvidenceId::parse("evidence:one").unwrap()]),
        )
        .unwrap();
        let projection = RunOutcomeRecord::from_outcome(verified, "redacted").unwrap();
        let projection_wire = serde_json::to_value(&projection).unwrap();
        for field in [
            "case_id",
            "subject",
            "action_id",
            "hypothesis_id",
            "verifier_rule_id",
            "rationale",
        ] {
            let mut wire = projection_wire["verification"].clone();
            wire[field] = serde_json::json!(oversized);
            assert!(
                serde_json::from_value::<VerificationOutcomeWire>(wire).is_err(),
                "oversized verification {field} was accepted"
            );
        }
        let mut verification_without_rule = projection_wire["verification"].clone();
        verification_without_rule
            .as_object_mut()
            .unwrap()
            .remove("verifier_rule_id");
        assert!(
            serde_json::from_value::<VerificationOutcomeWire>(verification_without_rule).is_ok()
        );

        let input = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::NoEligibleAction, "no eligible action").unwrap(),
            "https://example.test/",
            "https://example.test",
            time("2026-08-13T10:00:00Z"),
            time("2026-08-13T10:00:01Z"),
        )
        .unwrap();
        let report = RunReport::new(input).unwrap();
        for field in ["schema", "target", "authorized_origin"] {
            let mut wire = serde_json::to_value(&report).unwrap();
            wire[field] = serde_json::json!(oversized);
            assert!(
                serde_json::from_value::<RunReportWire>(wire.clone()).is_err(),
                "oversized report {field} was accepted by the private wire"
            );
            assert!(
                serde_json::from_value::<RunReport>(wire).is_err(),
                "oversized report {field} was accepted by the public contract"
            );
        }

        let escaped = "\\u0078".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1);
        let escaped_reason = format!(r#"{{"code":"completed","detail":"{escaped}"}}"#);
        assert!(serde_json::from_str::<RunStopReasonWire>(&escaped_reason).is_err());
    }

    #[test]
    fn bounded_fields_and_collections_fail_closed() {
        let oversized = "x".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1);
        assert!(RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.detector",
            oversized,
            "redacted",
        )
        .is_err());

        let evidence_ids = (0..=MAX_RUN_REPORT_EVIDENCE_IDS)
            .map(|index| EvidenceId::parse(format!("evidence:{index}")))
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        let outcome = Outcome::verified(
            "case:bounded",
            EntityId::new("endpoint:https://example.test").unwrap(),
            "verified.action",
            "hypothesis:bounded",
            "verify.bounded",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(90).unwrap(),
            "verified",
            evidence_ids,
        )
        .unwrap();
        assert!(matches!(
            RunOutcomeRecord::from_outcome(outcome, "redacted"),
            Err(RunReportError::TooMany { .. })
        ));
    }

    #[test]
    fn wire_counts_duplicate_and_unique_evidence_entries_before_insertion() {
        fn encoded_ids(unique: bool) -> serde_json::Value {
            serde_json::Value::Array(
                (0..=MAX_RUN_REPORT_EVIDENCE_IDS)
                    .map(|index| {
                        serde_json::Value::String(if unique {
                            format!("evidence:{index}")
                        } else {
                            "evidence:duplicate".to_string()
                        })
                    })
                    .collect(),
            )
        }

        let unresolved = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.detector",
            "unresolved",
            "redacted",
        )
        .unwrap();
        for unique in [true, false] {
            let mut outer = serde_json::to_value(&unresolved).unwrap();
            outer["evidence_ids"] = encoded_ids(unique);
            assert!(serde_json::from_value::<RunOutcomeRecordWire>(outer.clone()).is_err());
            assert!(serde_json::from_value::<RunOutcomeRecord>(outer).is_err());
        }

        let verified = Outcome::verified(
            "case:evidence-bound",
            EntityId::new("endpoint:https://example.test").unwrap(),
            "verified.action",
            "hypothesis:evidence-bound",
            "verify.evidence-bound",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(90).unwrap(),
            "verified",
            BTreeSet::from([EvidenceId::parse("evidence:one").unwrap()]),
        )
        .unwrap();
        let projection = RunOutcomeRecord::from_outcome(verified, "redacted").unwrap();
        for unique in [true, false] {
            let mut embedded = serde_json::to_value(&projection).unwrap();
            embedded["verification"]["evidence_ids"] = encoded_ids(unique);
            assert!(serde_json::from_value::<VerificationOutcomeWire>(
                embedded["verification"].clone()
            )
            .is_err());
            assert!(serde_json::from_value::<RunOutcomeRecord>(embedded).is_err());
        }
    }

    #[test]
    fn wire_rejects_oversized_evidence_ids_during_outer_and_embedded_decode() {
        let oversized = "x".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1);
        let unresolved = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.detector",
            "unresolved",
            "redacted",
        )
        .unwrap();
        let mut outer = serde_json::to_value(unresolved).unwrap();
        outer["evidence_ids"] = serde_json::json!([oversized]);
        assert!(serde_json::from_value::<RunOutcomeRecordWire>(outer).is_err());

        let verified = Outcome::verified(
            "case:evidence-id-bound",
            EntityId::new("endpoint:https://example.test").unwrap(),
            "verified.action",
            "hypothesis:evidence-id-bound",
            "verify.evidence-id-bound",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(90).unwrap(),
            "verified",
            BTreeSet::from([EvidenceId::parse("evidence:one").unwrap()]),
        )
        .unwrap();
        let projection = RunOutcomeRecord::from_outcome(verified, "redacted").unwrap();
        let mut embedded = serde_json::to_value(projection).unwrap();
        embedded["verification"]["evidence_ids"] =
            serde_json::json!(["x".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1)]);
        assert!(serde_json::from_value::<VerificationOutcomeWire>(
            embedded["verification"].clone()
        )
        .is_err());
    }

    #[test]
    fn validation_helpers_reject_every_bounded_projection_dimension() {
        assert_eq!(
            RunStopReason::new(RunStopCode::Completed, " "),
            Err(RunReportError::Blank {
                field: "stop reason"
            })
        );
        let reason = RunStopReason::new(RunStopCode::Completed, "done").unwrap();
        assert_eq!(reason.detail(), "done");

        let metered: ResourceAccounting = serde_json::from_value(serde_json::json!({
            "mode": "metered",
            "limit": 10,
            "consumed": 4,
            "remaining": 6
        }))
        .unwrap();
        assert_eq!(metered, ResourceAccounting::metered(10, 4));

        let step: RunStepReport = serde_json::from_value(serde_json::json!({
            "ordinal": 7,
            "action_id": "wire.step",
            "status": "succeeded",
            "duration_ms": 3,
            "detail": null
        }))
        .unwrap();
        assert_eq!(step.ordinal(), 7);
        assert_eq!(step.action_id(), "wire.step");
        assert_eq!(step.duration_ms(), 3);
        assert_eq!(step.detail(), None);

        let subject = EntityId::new("endpoint:https://example.test").unwrap();
        let canonical_unknown = VerificationOutcomeWire {
            case_id: "case:unknown".to_string(),
            subject: subject.clone(),
            action_id: "verify.unknown".to_string(),
            hypothesis_id: "hypothesis:unknown".to_string(),
            verifier_rule_id: None,
            stage: VerificationStage::Passive,
            status: OutcomeStatus::Unknown,
            confidence: Probability::ZERO,
            rationale: "no eligible verifier".to_string(),
            evidence_ids: BTreeSet::new(),
        }
        .into_outcome()
        .unwrap();
        assert_eq!(canonical_unknown.status(), OutcomeStatus::Unknown);

        let noncanonical_unknown = VerificationOutcomeWire {
            case_id: "case:unknown".to_string(),
            subject: subject.clone(),
            action_id: "verify.unknown".to_string(),
            hypothesis_id: "hypothesis:unknown".to_string(),
            verifier_rule_id: Some("verify.forged".to_string()),
            stage: VerificationStage::Passive,
            status: OutcomeStatus::Unknown,
            confidence: Probability::ZERO,
            rationale: "forged".to_string(),
            evidence_ids: BTreeSet::new(),
        };
        assert!(matches!(
            noncanonical_unknown.into_outcome(),
            Err(RunReportError::InvalidOutcome {
                status: OutcomeStatus::Unknown,
                ..
            })
        ));

        let malformed_unknown = VerificationOutcomeWire {
            case_id: " ".to_string(),
            subject: subject.clone(),
            action_id: "verify.unknown".to_string(),
            hypothesis_id: "hypothesis:unknown".to_string(),
            verifier_rule_id: None,
            stage: VerificationStage::Passive,
            status: OutcomeStatus::Unknown,
            confidence: Probability::ZERO,
            rationale: "invalid identity".to_string(),
            evidence_ids: BTreeSet::new(),
        };
        assert!(matches!(
            malformed_unknown.into_outcome(),
            Err(RunReportError::InvalidOutcome {
                status: OutcomeStatus::Unknown,
                ..
            })
        ));

        let missing_rule = VerificationOutcomeWire {
            case_id: "case:blocked".to_string(),
            subject: subject.clone(),
            action_id: "verify.blocked".to_string(),
            hypothesis_id: "hypothesis:blocked".to_string(),
            verifier_rule_id: None,
            stage: VerificationStage::Passive,
            status: OutcomeStatus::Blocked,
            confidence: Probability::from_percent(50).unwrap(),
            rationale: "blocked".to_string(),
            evidence_ids: BTreeSet::from([EvidenceId::parse("evidence:blocked").unwrap()]),
        };
        assert!(matches!(
            missing_rule.into_outcome(),
            Err(RunReportError::InvalidOutcome {
                status: OutcomeStatus::Blocked,
                ..
            })
        ));

        let base_record = || {
            RunOutcomeRecord::unresolved(
                subject.clone(),
                "legacy.detector",
                "unresolved",
                "redacted",
            )
            .unwrap()
        };

        let mut invalid = base_record();
        invalid.action_id = "a".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1);
        assert!(matches!(
            validate_record_bounds(&invalid),
            Err(RunReportError::TextTooLong {
                field: "outcome action id",
                ..
            })
        ));

        let mut invalid = base_record();
        invalid.evidence_ids =
            BTreeSet::from([EvidenceId::parse("e".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1)).unwrap()]);
        assert!(matches!(
            validate_record_bounds(&invalid),
            Err(RunReportError::TextTooLong {
                field: "outcome evidence id",
                ..
            })
        ));

        let mut invalid = base_record();
        invalid.subject = EntityId::new("s".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1)).unwrap();
        assert!(matches!(
            validate_record_bounds(&invalid),
            Err(RunReportError::TextTooLong {
                field: "outcome subject",
                ..
            })
        ));

        for (field, case_id, hypothesis_id) in [
            (
                "verification case id",
                "c".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1),
                "hypothesis:bounded".to_string(),
            ),
            (
                "verification hypothesis id",
                "case:bounded".to_string(),
                "h".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1),
            ),
        ] {
            let mut invalid = base_record();
            invalid.verification = Some(
                Outcome::unknown(
                    case_id,
                    subject.clone(),
                    "verify.unknown",
                    hypothesis_id,
                    VerificationStage::Passive,
                    "bounded",
                )
                .unwrap(),
            );
            assert!(matches!(
                validate_record_bounds(&invalid),
                Err(RunReportError::TextTooLong {
                    field: actual,
                    ..
                }) if actual == field
            ));
        }

        let mut invalid = base_record();
        invalid.verification = Some(
            Outcome::verified(
                "case:bounded",
                subject,
                "verify.bounded",
                "hypothesis:bounded",
                "r".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1),
                VerificationStage::Passive,
                OutcomeStatus::Success,
                Probability::from_percent(90).unwrap(),
                "bounded",
                BTreeSet::from([EvidenceId::parse("evidence:bounded").unwrap()]),
            )
            .unwrap(),
        );
        assert!(matches!(
            validate_record_bounds(&invalid),
            Err(RunReportError::TextTooLong {
                field: "verifier rule id",
                ..
            })
        ));

        for (status, token) in [
            (OutcomeStatus::Success, "success"),
            (OutcomeStatus::Blocked, "blocked"),
            (OutcomeStatus::Unknown, "unknown"),
            (OutcomeStatus::FalsePositive, "false_positive"),
            (OutcomeStatus::NeedsReview, "needs_review"),
            (OutcomeStatus::ConfirmedNegative, "confirmed_negative"),
        ] {
            assert_eq!(outcome_code(status), token);
        }
    }

    #[test]
    fn report_limits_and_aggregate_failure_proofs_are_exercised() {
        let start = time("2026-08-13T10:00:00Z");
        let end = time("2026-08-13T10:00:01Z");
        let completed = || RunStopReason::new(RunStopCode::Completed, "done").unwrap();
        let step =
            RunStepReport::new(1, "bounded.step", RunStepStatus::Succeeded, 1, None).unwrap();
        let too_many_steps = RunReportInput::new(
            RunStatus::Complete,
            completed(),
            "https://example.test/",
            "https://example.test",
            start,
            end,
        )
        .unwrap()
        .with_steps(vec![step.clone(); MAX_RUN_REPORT_STEPS + 1]);
        assert!(matches!(
            RunReport::new(too_many_steps),
            Err(RunReportError::TooMany {
                field: "run steps",
                ..
            })
        ));

        let outcome = RunOutcomeRecord::unresolved(
            EntityId::new("endpoint:https://example.test").unwrap(),
            "legacy.detector",
            "unresolved",
            "redacted",
        )
        .unwrap();
        let too_many_outcomes = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::NoEligibleAction, "done").unwrap(),
            "https://example.test/",
            "https://example.test",
            start,
            end,
        )
        .unwrap()
        .with_outcomes(vec![outcome.clone(); MAX_RUN_REPORT_OUTCOMES + 1]);
        assert!(matches!(
            RunReport::new(too_many_outcomes),
            Err(RunReportError::TooMany {
                field: "run outcomes",
                ..
            })
        ));

        for code in [
            RunStopCode::NoEligibleAction,
            RunStopCode::BudgetExhausted,
            RunStopCode::ReportLimitExceeded,
            RunStopCode::StepFailed,
            RunStopCode::StepTimedOut,
            RunStopCode::TaskJoinFailed,
            RunStopCode::RuntimeFailed,
        ] {
            assert!(status_matches_stop(RunStatus::Partial, code));
            assert_eq!(
                status_matches_stop(RunStatus::Failed, code),
                code != RunStopCode::NoEligibleAction && code != RunStopCode::ReportLimitExceeded
            );
        }

        let failed = RunStepReport::new(1, "failed", RunStepStatus::Failed, 1, None).unwrap();
        let timed_out = RunStepReport::new(1, "timed", RunStepStatus::TimedOut, 1, None).unwrap();
        let cancelled =
            RunStepReport::new(1, "cancelled", RunStepStatus::Cancelled, 1, None).unwrap();
        let budget =
            RunStepReport::new(1, "budget", RunStepStatus::BudgetExhausted, 1, None).unwrap();

        assert!(validate_aggregate_consistency(
            RunStatus::Complete,
            RunStopCode::Completed,
            &[],
            &[]
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Partial,
            RunStopCode::RuntimeFailed,
            &[],
            &[]
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Partial,
            RunStopCode::RuntimeFailed,
            std::slice::from_ref(&cancelled),
            std::slice::from_ref(&outcome)
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Failed,
            RunStopCode::RuntimeFailed,
            std::slice::from_ref(&step),
            &[]
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Failed,
            RunStopCode::StepFailed,
            &[],
            &[]
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Failed,
            RunStopCode::StepTimedOut,
            std::slice::from_ref(&failed),
            &[]
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Failed,
            RunStopCode::TaskJoinFailed,
            std::slice::from_ref(&timed_out),
            &[]
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Partial,
            RunStopCode::BudgetExhausted,
            &[],
            std::slice::from_ref(&outcome)
        )
        .is_err());
        assert!(validate_aggregate_consistency(
            RunStatus::Partial,
            RunStopCode::ReportLimitExceeded,
            std::slice::from_ref(&step),
            &[]
        )
        .is_err());

        assert!(validate_aggregate_consistency(
            RunStatus::Failed,
            RunStopCode::StepFailed,
            std::slice::from_ref(&failed),
            &[]
        )
        .is_ok());
        assert!(validate_aggregate_consistency(
            RunStatus::Failed,
            RunStopCode::StepTimedOut,
            std::slice::from_ref(&timed_out),
            &[]
        )
        .is_ok());
        assert!(validate_aggregate_consistency(
            RunStatus::Partial,
            RunStopCode::BudgetExhausted,
            std::slice::from_ref(&budget),
            &[]
        )
        .is_err());
    }
}
