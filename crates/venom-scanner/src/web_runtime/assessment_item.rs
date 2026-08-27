//! Claim-safe, read-only product projection for deterministic assessment truth.
//!
//! This module owns no detector, transport, verifier, renderer, or persistence
//! authority. It can only reduce already committed runtime truth into bounded,
//! opaque references. In particular, action success alone is never sufficient
//! for [`AssessmentDisposition::Confirmed`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use venom_core::{
    EntityId, EvidenceId, EvidenceValue, HypothesisState, KnowledgePredicate, Outcome,
    OutcomeStatus, Probability, SecuritySeverity, VerificationStage,
};

use crate::knowledge::KnowledgeAuthority;
use crate::{
    DecisionEvidenceReceipt, DecisionExecutionStage, DecisionOutcomeReport, KnowledgeBase,
};

/// Stable schema carried by every assessment item.
pub const ASSESSMENT_ITEM_SCHEMA: &str = "venom-assessment-item/v1";
/// Maximum retained evidence references for one assessment item.
pub const MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES: usize = 256;
/// Maximum bytes in one static capability identifier.
pub const MAX_ASSESSMENT_CAPABILITY_ID_BYTES: usize = 128;
/// Maximum bytes in one static display field.
pub const MAX_ASSESSMENT_DISPLAY_BYTES: usize = 1_024;

const FINGERPRINT_DOMAIN: &[u8] = b"venom.assessment-item.fingerprint.v1\0";
const MAX_STABLE_SUBJECT_ID_BYTES: usize = 256;
const MAX_QUERY_PARAMETER_NAME_BYTES: usize = 256;
const MAX_PROJECTION_SUBJECTS: usize = 1_024;
const MAX_PROJECTION_QUERY_NAMES_PER_SUBJECT: usize = 256;
const MAX_PROJECTION_CASES: usize = 10_000;
const MAX_PROJECTION_OUTCOMES: usize = 10_000;
const MAX_PROJECTION_EVIDENCE: usize = 262_144;

/// Product-facing claim disposition.
///
/// This vocabulary is intentionally distinct from verifier outcome status.
/// `Success` is an action result; `Confirmed` is a separately authorized
/// security-claim projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AssessmentDisposition {
    /// A bounded observation with no vulnerability claim.
    Informational,
    /// A typed relationship warrants authorized human review.
    NeedsReview,
    /// A verifier-authorized vulnerability hypothesis transition was committed.
    Confirmed,
}

impl AssessmentDisposition {
    /// Returns the stable product token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::NeedsReview => "needs_review",
            Self::Confirmed => "confirmed",
        }
    }
}

/// Opaque deterministic reference to one canonical assessment subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssessmentSubjectReference(u32);

impl AssessmentSubjectReference {
    pub(crate) const fn new(ordinal: u32) -> Self {
        Self(ordinal)
    }

    /// Returns the deterministic document-local ordinal.
    pub const fn ordinal(self) -> u32 {
        self.0
    }
}

impl fmt::Display for AssessmentSubjectReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "subject-{:04}", self.0)
    }
}

/// Opaque deterministic reference to one retained evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssessmentEvidenceReference(u32);

impl AssessmentEvidenceReference {
    pub(crate) const fn new(ordinal: u32) -> Self {
        Self(ordinal)
    }

    /// Returns the deterministic document-local ordinal.
    pub const fn ordinal(self) -> u32 {
        self.0
    }
}

impl fmt::Display for AssessmentEvidenceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "evidence-{:04}", self.0)
    }
}

/// Opaque deterministic reference to one verification case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssessmentCaseReference(u32);

impl AssessmentCaseReference {
    pub(crate) const fn new(ordinal: u32) -> Self {
        Self(ordinal)
    }

    /// Returns the deterministic document-local ordinal.
    pub const fn ordinal(self) -> u32 {
        self.0
    }
}

impl fmt::Display for AssessmentCaseReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "case-{:04}", self.0)
    }
}

/// Opaque deterministic reference to one verifier outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssessmentOutcomeReference(u32);

impl AssessmentOutcomeReference {
    pub(crate) const fn new(ordinal: u32) -> Self {
        Self(ordinal)
    }

    /// Returns the deterministic document-local ordinal.
    pub const fn ordinal(self) -> u32 {
        self.0
    }
}

impl fmt::Display for AssessmentOutcomeReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "outcome-{:04}", self.0)
    }
}

/// Host-approved, stable, non-secret subject identity used only for product
/// identity. This is not a redaction primitive: callers must never construct it
/// from a credential, raw URL, URL path, query value, cookie value, or other
/// secret and then assume the digest makes that input confidential.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct StableAssessmentSubjectId(String);

impl StableAssessmentSubjectId {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, AssessmentItemProjectionError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_STABLE_SUBJECT_ID_BYTES
            || value.trim() != value
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
            })
        {
            return Err(AssessmentItemProjectionError::InvalidStableSubjectIdentity);
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StableAssessmentSubjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableAssessmentSubjectId(<host-approved>)")
    }
}

/// Closed, non-secret discriminator for one item within a canonical subject.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AssessmentItemTarget {
    Subject,
    QueryParameter(String),
}

impl AssessmentItemTarget {
    pub(crate) const fn subject() -> Self {
        Self::Subject
    }

    pub(crate) fn query_parameter(
        name: impl Into<String>,
    ) -> Result<Self, AssessmentItemProjectionError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_QUERY_PARAMETER_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(AssessmentItemProjectionError::InvalidQueryParameterTarget);
        }
        Ok(Self::QueryParameter(name))
    }
}

impl fmt::Debug for AssessmentItemTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject => formatter.write_str("AssessmentItemTarget::Subject"),
            Self::QueryParameter(_) => {
                formatter.write_str("AssessmentItemTarget::QueryParameter(<name-only>)")
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuntimeOutcomeIdentity {
    subject: EntityId,
    case_id: String,
    action_id: String,
    hypothesis_id: String,
    verifier_rule_id: Option<String>,
    stage: &'static str,
}

impl RuntimeOutcomeIdentity {
    fn from_outcome(outcome: &Outcome) -> Self {
        Self {
            subject: outcome.subject().clone(),
            case_id: outcome.case_id().to_owned(),
            action_id: outcome.action_id().to_owned(),
            hypothesis_id: outcome.hypothesis_id().to_owned(),
            verifier_rule_id: outcome.verifier_rule_id().map(str::to_owned),
            stage: outcome.stage().as_str(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SubjectProjection {
    reference: AssessmentSubjectReference,
    stable_id: StableAssessmentSubjectId,
    query_parameter_names: BTreeSet<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct EvidenceProjection {
    reference: AssessmentEvidenceReference,
    subject: EntityId,
}

/// Crate-owned mapping authority from exact runtime identities to opaque
/// document-local references. Callers never select references directly.
#[derive(Clone)]
pub(crate) struct AssessmentProjectionContext {
    knowledge_authority: KnowledgeAuthority,
    subjects: BTreeMap<EntityId, SubjectProjection>,
    stable_subject_ids: BTreeSet<StableAssessmentSubjectId>,
    cases: BTreeMap<(EntityId, String), AssessmentCaseReference>,
    outcomes: BTreeMap<RuntimeOutcomeIdentity, AssessmentOutcomeReference>,
    evidence: BTreeMap<EvidenceId, EvidenceProjection>,
}

impl fmt::Debug for AssessmentProjectionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentProjectionContext")
            .field("subject_count", &self.subjects.len())
            .field("case_count", &self.cases.len())
            .field("outcome_count", &self.outcomes.len())
            .field("evidence_count", &self.evidence.len())
            .finish()
    }
}

impl AssessmentProjectionContext {
    pub(crate) fn new(knowledge: &KnowledgeBase, subject: &EntityId) -> Self {
        Self {
            knowledge_authority: knowledge.snapshot_for_subject(subject).authority().clone(),
            subjects: BTreeMap::new(),
            stable_subject_ids: BTreeSet::new(),
            cases: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            evidence: BTreeMap::new(),
        }
    }

    pub(crate) fn register_subject(
        &mut self,
        subject: EntityId,
        stable_id: StableAssessmentSubjectId,
        query_parameter_names: impl IntoIterator<Item = String>,
    ) -> Result<AssessmentSubjectReference, AssessmentItemProjectionError> {
        check_projection_limit("subjects", self.subjects.len(), MAX_PROJECTION_SUBJECTS)?;
        if self.subjects.contains_key(&subject) {
            return Err(AssessmentItemProjectionError::DuplicateSubjectMapping);
        }
        if self.stable_subject_ids.contains(&stable_id) {
            return Err(AssessmentItemProjectionError::DuplicateStableSubjectIdentity);
        }
        let mut names = BTreeSet::new();
        for name in query_parameter_names {
            check_projection_limit(
                "query_parameter_names",
                names.len(),
                MAX_PROJECTION_QUERY_NAMES_PER_SUBJECT,
            )?;
            let AssessmentItemTarget::QueryParameter(name) =
                AssessmentItemTarget::query_parameter(name)?
            else {
                unreachable!("query-parameter constructor returned another target")
            };
            if !names.insert(name) {
                return Err(AssessmentItemProjectionError::DuplicateQueryParameterTarget);
            }
        }
        let reference =
            AssessmentSubjectReference::new(next_ordinal(self.subjects.len(), "subject")?);
        self.stable_subject_ids.insert(stable_id.clone());
        self.subjects.insert(
            subject,
            SubjectProjection {
                reference,
                stable_id,
                query_parameter_names: names,
            },
        );
        Ok(reference)
    }

    pub(crate) fn register_case(
        &mut self,
        subject: &EntityId,
        case_id: impl Into<String>,
    ) -> Result<AssessmentCaseReference, AssessmentItemProjectionError> {
        check_projection_limit("cases", self.cases.len(), MAX_PROJECTION_CASES)?;
        if !self.subjects.contains_key(subject) {
            return Err(AssessmentItemProjectionError::UnknownSubjectMapping);
        }
        let case_id = case_id.into();
        if case_id.is_empty() {
            return Err(AssessmentItemProjectionError::InvalidRuntimeIdentity);
        }
        let identity = (subject.clone(), case_id);
        if self.cases.contains_key(&identity) {
            return Err(AssessmentItemProjectionError::DuplicateCaseMapping);
        }
        let reference = AssessmentCaseReference::new(next_ordinal(self.cases.len(), "case")?);
        self.cases.insert(identity, reference);
        Ok(reference)
    }

    pub(crate) fn register_outcome(
        &mut self,
        outcome: &Outcome,
    ) -> Result<AssessmentOutcomeReference, AssessmentItemProjectionError> {
        check_projection_limit("outcomes", self.outcomes.len(), MAX_PROJECTION_OUTCOMES)?;
        if !self.subjects.contains_key(outcome.subject()) {
            return Err(AssessmentItemProjectionError::UnknownSubjectMapping);
        }
        if !self
            .cases
            .contains_key(&(outcome.subject().clone(), outcome.case_id().to_owned()))
        {
            return Err(AssessmentItemProjectionError::UnknownCaseMapping);
        }
        let identity = RuntimeOutcomeIdentity::from_outcome(outcome);
        if self.outcomes.contains_key(&identity) {
            return Err(AssessmentItemProjectionError::DuplicateOutcomeMapping);
        }
        let reference =
            AssessmentOutcomeReference::new(next_ordinal(self.outcomes.len(), "outcome")?);
        self.outcomes.insert(identity, reference);
        Ok(reference)
    }

    pub(crate) fn register_evidence(
        &mut self,
        knowledge: &KnowledgeBase,
        evidence_id: &EvidenceId,
    ) -> Result<AssessmentEvidenceReference, AssessmentItemProjectionError> {
        check_projection_limit("evidence", self.evidence.len(), MAX_PROJECTION_EVIDENCE)?;
        let evidence = knowledge
            .evidence(evidence_id)
            .ok_or(AssessmentItemProjectionError::EvidenceNotCommitted)?;
        self.validate_knowledge_authority(knowledge, evidence.subject())?;
        if !self.subjects.contains_key(evidence.subject()) {
            return Err(AssessmentItemProjectionError::UnknownSubjectMapping);
        }
        if self.evidence.contains_key(evidence.id()) {
            return Err(AssessmentItemProjectionError::DuplicateEvidenceMapping);
        }
        let reference =
            AssessmentEvidenceReference::new(next_ordinal(self.evidence.len(), "evidence")?);
        self.evidence.insert(
            evidence.id().clone(),
            EvidenceProjection {
                reference,
                subject: evidence.subject().clone(),
            },
        );
        Ok(reference)
    }

    fn subject(
        &self,
        subject: &EntityId,
        target: &AssessmentItemTarget,
    ) -> Result<&SubjectProjection, AssessmentItemProjectionError> {
        let projection = self
            .subjects
            .get(subject)
            .ok_or(AssessmentItemProjectionError::UnknownSubjectMapping)?;
        if let AssessmentItemTarget::QueryParameter(name) = target {
            if !projection.query_parameter_names.contains(name) {
                return Err(AssessmentItemProjectionError::UnknownQueryParameterTarget);
            }
        }
        Ok(projection)
    }

    fn case_reference(
        &self,
        subject: &EntityId,
        case_id: &str,
    ) -> Result<AssessmentCaseReference, AssessmentItemProjectionError> {
        self.cases
            .get(&(subject.clone(), case_id.to_owned()))
            .copied()
            .ok_or(AssessmentItemProjectionError::UnknownCaseMapping)
    }

    fn outcome_reference(
        &self,
        outcome: &Outcome,
    ) -> Result<AssessmentOutcomeReference, AssessmentItemProjectionError> {
        self.outcomes
            .get(&RuntimeOutcomeIdentity::from_outcome(outcome))
            .copied()
            .ok_or(AssessmentItemProjectionError::UnknownOutcomeMapping)
    }

    fn evidence_references(
        &self,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        evidence_ids: impl IntoIterator<Item = EvidenceId>,
    ) -> Result<Vec<AssessmentEvidenceReference>, AssessmentItemProjectionError> {
        self.validate_knowledge_authority(knowledge, subject)?;
        evidence_ids
            .into_iter()
            .map(|evidence_id| {
                let projection = self
                    .evidence
                    .get(&evidence_id)
                    .ok_or(AssessmentItemProjectionError::UnknownEvidenceMapping)?;
                if &projection.subject != subject {
                    return Err(AssessmentItemProjectionError::EvidenceSubjectMappingMismatch);
                }
                let committed = knowledge
                    .evidence(&evidence_id)
                    .ok_or(AssessmentItemProjectionError::EvidenceNotCommitted)?;
                if committed.subject() != subject {
                    return Err(AssessmentItemProjectionError::EvidenceMappingMismatch);
                }
                Ok(projection.reference)
            })
            .collect()
    }

    fn validate_knowledge_authority(
        &self,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
    ) -> Result<(), AssessmentItemProjectionError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        if snapshot.authority().is_same_as(&self.knowledge_authority) {
            Ok(())
        } else {
            Err(AssessmentItemProjectionError::KnowledgeAuthorityMismatch)
        }
    }
}

fn next_ordinal(
    current_len: usize,
    kind: &'static str,
) -> Result<u32, AssessmentItemProjectionError> {
    u32::try_from(current_len)
        .map_err(|_| AssessmentItemProjectionError::ReferenceSpaceExhausted { kind })
}

fn check_projection_limit(
    dimension: &'static str,
    current_len: usize,
    maximum: usize,
) -> Result<(), AssessmentItemProjectionError> {
    if current_len >= maximum {
        Err(AssessmentItemProjectionError::ProjectionContextLimit { dimension, maximum })
    } else {
        Ok(())
    }
}

/// Static remediation metadata owned by a native capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssessmentRemediation {
    id: &'static str,
    summary: &'static str,
}

impl AssessmentRemediation {
    /// Returns the stable remediation policy identifier.
    pub const fn id(self) -> &'static str {
        self.id
    }

    /// Returns the bounded static remediation summary.
    pub const fn summary(self) -> &'static str {
        self.summary
    }
}

/// Evidence basis for an informational observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentObservationBasis {
    evidence: Vec<AssessmentEvidenceReference>,
}

impl AssessmentObservationBasis {
    /// Returns opaque evidence references in ascending ordinal order.
    pub fn evidence(&self) -> &[AssessmentEvidenceReference] {
        &self.evidence
    }
}

/// Matched control/candidate basis for a review item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentDifferentialBasis {
    control: Vec<AssessmentEvidenceReference>,
    candidate: Vec<AssessmentEvidenceReference>,
}

impl AssessmentDifferentialBasis {
    /// Returns opaque negative/control evidence references.
    pub fn control(&self) -> &[AssessmentEvidenceReference] {
        &self.control
    }

    /// Returns opaque candidate evidence references.
    pub fn candidate(&self) -> &[AssessmentEvidenceReference] {
        &self.candidate
    }
}

/// Verifier-owned basis for a confirmed item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentVerifierBasis {
    case_reference: AssessmentCaseReference,
    outcome_reference: AssessmentOutcomeReference,
    verifier_rule_id: &'static str,
    stage: VerificationStage,
    evidence: Vec<AssessmentEvidenceReference>,
}

impl AssessmentVerifierBasis {
    /// Returns the opaque case reference.
    pub const fn case_reference(&self) -> AssessmentCaseReference {
        self.case_reference
    }

    /// Returns the opaque outcome reference.
    pub const fn outcome_reference(&self) -> AssessmentOutcomeReference {
        self.outcome_reference
    }

    /// Returns the native verifier rule identity declared by the capability.
    pub const fn verifier_rule_id(&self) -> &'static str {
        self.verifier_rule_id
    }

    /// Returns the evidence collection stage.
    pub const fn stage(&self) -> VerificationStage {
        self.stage
    }

    /// Returns opaque contributing evidence references.
    pub fn evidence(&self) -> &[AssessmentEvidenceReference] {
        &self.evidence
    }
}

/// Typed authority that produced an assessment item.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssessmentBasis {
    /// One or more bounded observations; never a confirmation basis.
    Observation(AssessmentObservationBasis),
    /// A matched control/candidate relationship; review only.
    Differential(AssessmentDifferentialBasis),
    /// A case-correlated verifier transition.
    Verifier(AssessmentVerifierBasis),
}

impl AssessmentBasis {
    const fn disposition(&self) -> AssessmentDisposition {
        match self {
            Self::Observation(_) => AssessmentDisposition::Informational,
            Self::Differential(_) => AssessmentDisposition::NeedsReview,
            Self::Verifier(_) => AssessmentDisposition::Confirmed,
        }
    }

    /// Returns the total number of opaque evidence references.
    pub fn evidence_count(&self) -> usize {
        match self {
            Self::Observation(basis) => basis.evidence.len(),
            Self::Differential(basis) => basis.control.len() + basis.candidate.len(),
            Self::Verifier(basis) => basis.evidence.len(),
        }
    }

    /// Returns a verifier case reference only for verifier-owned items.
    pub const fn case_reference(&self) -> Option<AssessmentCaseReference> {
        match self {
            Self::Verifier(basis) => Some(basis.case_reference),
            Self::Observation(_) | Self::Differential(_) => None,
        }
    }
}

/// Read-only product projection from deterministic runtime truth.
///
/// The type deliberately has no general serialization implementation and no
/// public constructor. It is reserved for the later bounded report projection;
/// plugins and arbitrary callers cannot select a disposition or severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentItem {
    capability: &'static AssessmentCapabilityDescriptor,
    subject_reference: AssessmentSubjectReference,
    confidence: Probability,
    fingerprint: String,
    basis: AssessmentBasis,
}

impl AssessmentItem {
    /// Returns the stable item schema.
    pub const fn schema(&self) -> &'static str {
        ASSESSMENT_ITEM_SCHEMA
    }

    /// Returns the native capability identity.
    pub const fn capability_id(&self) -> &'static str {
        self.capability.id
    }

    /// Returns the bounded static title.
    pub const fn title(&self) -> &'static str {
        self.capability.title
    }

    /// Returns the opaque canonical-subject reference.
    pub const fn subject_reference(&self) -> AssessmentSubjectReference {
        self.subject_reference
    }

    /// Returns the product disposition.
    pub const fn disposition(&self) -> AssessmentDisposition {
        self.basis.disposition()
    }

    /// Returns capability-owned optional severity.
    pub const fn severity(&self) -> Option<SecuritySeverity> {
        self.capability.severity
    }

    /// Returns fixed-point confidence without interpreting it as CVSS.
    pub const fn confidence(&self) -> Probability {
        self.confidence
    }

    /// Returns the versioned stable fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the typed observation/differential/verifier basis.
    pub const fn basis(&self) -> &AssessmentBasis {
        &self.basis
    }

    /// Returns the bounded number of opaque evidence references.
    pub fn evidence_count(&self) -> usize {
        self.basis.evidence_count()
    }

    /// Returns the already-redacted static summary.
    pub const fn redacted_summary(&self) -> &'static str {
        self.capability.redacted_summary
    }

    /// Returns static capability category metadata.
    pub const fn category(&self) -> &'static str {
        self.capability.category
    }

    /// Returns a CWE only when the native capability maps cleanly to one.
    pub const fn cwe(&self) -> Option<&'static str> {
        self.capability.cwe
    }

    /// Returns capability-owned remediation metadata.
    pub const fn remediation(&self) -> AssessmentRemediation {
        self.capability.remediation
    }

    pub(crate) fn from_observation(
        capability: &'static AssessmentCapabilityDescriptor,
        context: &AssessmentProjectionContext,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        target: &AssessmentItemTarget,
        evidence_ids: &[EvidenceId],
    ) -> Result<Self, AssessmentItemProjectionError> {
        let subject_projection = context.subject(subject, target)?;
        let evidence =
            context.evidence_references(knowledge, subject, evidence_ids.iter().cloned())?;
        let evidence = validate_reference_set("observation", evidence)?;
        Ok(Self::build(
            capability,
            subject_projection,
            target,
            capability.confidence()?,
            AssessmentBasis::Observation(AssessmentObservationBasis { evidence }),
        ))
    }

    // Deliberately private until a capability-specific matched-pair validator
    // can mint a sealed differential proof. Arbitrary crate callers cannot
    // turn two evidence identifiers into `NeedsReview`.
    fn from_differential(
        capability: &'static AssessmentCapabilityDescriptor,
        context: &AssessmentProjectionContext,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        target: &AssessmentItemTarget,
        control_ids: &[EvidenceId],
        candidate_ids: &[EvidenceId],
    ) -> Result<Self, AssessmentItemProjectionError> {
        if !capability.allows_differential_review() {
            return Err(AssessmentItemProjectionError::DispositionDenied {
                requested: AssessmentDisposition::NeedsReview,
            });
        }
        let subject_projection = context.subject(subject, target)?;
        let control =
            context.evidence_references(knowledge, subject, control_ids.iter().cloned())?;
        let candidate =
            context.evidence_references(knowledge, subject, candidate_ids.iter().cloned())?;
        let control = validate_reference_set("differential control", control)?;
        let candidate = validate_reference_set("differential candidate", candidate)?;
        if control.len().saturating_add(candidate.len()) > MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES {
            return Err(AssessmentItemProjectionError::TooManyEvidenceReferences);
        }
        if control
            .iter()
            .any(|reference| candidate.contains(reference))
        {
            return Err(AssessmentItemProjectionError::OverlappingDifferentialEvidence);
        }
        Ok(Self::build(
            capability,
            subject_projection,
            target,
            capability.confidence()?,
            AssessmentBasis::Differential(AssessmentDifferentialBasis { control, candidate }),
        ))
    }

    pub(crate) fn from_verifier_projection(
        capability: &'static AssessmentCapabilityDescriptor,
        context: &AssessmentProjectionContext,
        target: &AssessmentItemTarget,
        receipt: &DecisionEvidenceReceipt,
        decision: &DecisionOutcomeReport,
        knowledge: &KnowledgeBase,
    ) -> Result<Self, AssessmentItemProjectionError> {
        let extraction = extract_confirmation_proof(capability, receipt, decision, knowledge);
        extraction.proof.authorize()?;

        let outcome = decision.verification().outcome();
        let subject_projection = context.subject(outcome.subject(), target)?;
        let case_reference = context.case_reference(outcome.subject(), outcome.case_id())?;
        let outcome_reference = context.outcome_reference(outcome)?;
        let projected = context.evidence_references(
            knowledge,
            outcome.subject(),
            extraction.evidence_ids.iter().cloned(),
        )?;
        let evidence = validate_reference_set("verifier", projected)?;
        let policy = capability.verifier_policy().ok_or(
            AssessmentItemProjectionError::ConfirmationDenied(
                AssessmentConfirmationDenial::CapabilityPolicy,
            ),
        )?;
        Ok(Self::build(
            capability,
            subject_projection,
            target,
            outcome.confidence(),
            AssessmentBasis::Verifier(AssessmentVerifierBasis {
                case_reference,
                outcome_reference,
                verifier_rule_id: policy.verifier_rule_id,
                stage: policy.stage,
                evidence,
            }),
        ))
    }

    fn build(
        capability: &'static AssessmentCapabilityDescriptor,
        subject: &SubjectProjection,
        target: &AssessmentItemTarget,
        confidence: Probability,
        basis: AssessmentBasis,
    ) -> Self {
        Self {
            capability,
            subject_reference: subject.reference,
            confidence,
            fingerprint: assessment_fingerprint(capability.id, &subject.stable_id, target),
            basis,
        }
    }
}

/// Stable reason a verifier outcome was denied confirmation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssessmentConfirmationDenial {
    CapabilityPolicy,
    ActionMismatch,
    HypothesisClaimMismatch,
    OutcomeNotSuccess,
    KnowledgeOnly,
    MissingHypothesisWrite,
    FinalHypothesisNotConfirmed,
    CaseMismatch,
    SelectedVerifierMismatch,
    MissingEvidence,
    EvidenceUnavailable,
    EvidenceSubjectMismatch,
    EvidenceCaseMismatch,
    ReceiptCaseMismatch,
    ReceiptStageMismatch,
    ReceiptDidNotContribute,
    ReceiptEvidenceMismatch,
}

impl fmt::Display for AssessmentConfirmationDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CapabilityPolicy => "capability policy does not authorize confirmation",
            Self::ActionMismatch => "action identity does not match capability claim policy",
            Self::HypothesisClaimMismatch => {
                "hypothesis predicate or value does not match capability claim policy"
            },
            Self::OutcomeNotSuccess => "verifier outcome is not success",
            Self::KnowledgeOnly => "verification case is knowledge-only",
            Self::MissingHypothesisWrite => "verifier transition write is absent",
            Self::FinalHypothesisNotConfirmed => "final hypothesis state is not confirmed",
            Self::CaseMismatch => "case and outcome identities do not agree",
            Self::SelectedVerifierMismatch => "selected verifier does not match capability policy",
            Self::MissingEvidence => "verifier outcome has no evidence",
            Self::EvidenceUnavailable => "verifier evidence is absent from committed knowledge",
            Self::EvidenceSubjectMismatch => "verifier evidence belongs to another subject",
            Self::EvidenceCaseMismatch => "verifier evidence belongs to another case",
            Self::ReceiptCaseMismatch => "execution receipt belongs to another case",
            Self::ReceiptStageMismatch => "execution receipt stage does not match verification",
            Self::ReceiptDidNotContribute => {
                "execution receipt does not contain the required contributing evidence"
            },
            Self::ReceiptEvidenceMismatch => {
                "execution receipt evidence differs from the committed knowledge record"
            },
        })
    }
}

/// Fail-closed projection errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AssessmentItemProjectionError {
    #[error("assessment capability does not authorize {requested:?}")]
    DispositionDenied { requested: AssessmentDisposition },
    #[error("assessment item requires at least one evidence reference")]
    MissingEvidence,
    #[error("assessment item exceeds its evidence-reference limit")]
    TooManyEvidenceReferences,
    #[error("assessment item contains a duplicate evidence reference")]
    DuplicateEvidenceReference,
    #[error("differential control and candidate evidence overlap")]
    OverlappingDifferentialEvidence,
    #[error("assessment confirmation denied: {0}")]
    ConfirmationDenied(AssessmentConfirmationDenial),
    #[error("static capability confidence is outside the fixed-point range")]
    InvalidCapabilityConfidence,
    #[error("host-approved stable subject identity is invalid")]
    InvalidStableSubjectIdentity,
    #[error("query-parameter target identity is invalid")]
    InvalidQueryParameterTarget,
    #[error("query-parameter target is not registered for the runtime subject")]
    UnknownQueryParameterTarget,
    #[error("query-parameter target is duplicated in one subject mapping")]
    DuplicateQueryParameterTarget,
    #[error("runtime identity is invalid")]
    InvalidRuntimeIdentity,
    #[error("runtime subject has no projection mapping")]
    UnknownSubjectMapping,
    #[error("runtime verification case has no projection mapping")]
    UnknownCaseMapping,
    #[error("runtime verifier outcome has no projection mapping")]
    UnknownOutcomeMapping,
    #[error("runtime evidence has no projection mapping")]
    UnknownEvidenceMapping,
    #[error("runtime evidence was not committed to knowledge")]
    EvidenceNotCommitted,
    #[error("runtime evidence mapping differs from committed knowledge")]
    EvidenceMappingMismatch,
    #[error("projection context belongs to another knowledge authority")]
    KnowledgeAuthorityMismatch,
    #[error("runtime subject already has a projection mapping")]
    DuplicateSubjectMapping,
    #[error("stable subject identity is already bound to another runtime subject")]
    DuplicateStableSubjectIdentity,
    #[error("runtime verification case already has a projection mapping")]
    DuplicateCaseMapping,
    #[error("runtime verifier outcome already has a projection mapping")]
    DuplicateOutcomeMapping,
    #[error("runtime evidence already has a projection mapping")]
    DuplicateEvidenceMapping,
    #[error("runtime evidence projection belongs to another subject")]
    EvidenceSubjectMappingMismatch,
    #[error("assessment {kind} reference space is exhausted")]
    ReferenceSpaceExhausted { kind: &'static str },
    #[error("assessment projection {dimension} exceeds compiled maximum {maximum}")]
    ProjectionContextLimit {
        dimension: &'static str,
        maximum: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssessmentClaimPolicy {
    ObservationOnly,
    DifferentialReview,
    VerifierTransition(VerifierClaimPolicy),
}

impl AssessmentClaimPolicy {
    const fn maximum_disposition(self) -> AssessmentDisposition {
        match self {
            Self::ObservationOnly => AssessmentDisposition::Informational,
            Self::DifferentialReview => AssessmentDisposition::NeedsReview,
            Self::VerifierTransition(_) => AssessmentDisposition::Confirmed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifierClaimPolicy {
    action_id: &'static str,
    hypothesis_namespace: &'static str,
    hypothesis_name: &'static str,
    hypothesis_value: StaticEvidenceValue,
    verifier_rule_id: &'static str,
    stage: VerificationStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticEvidenceValue {
    Boolean(bool),
    Unsigned(u64),
    Text(&'static str),
}

impl StaticEvidenceValue {
    fn matches(self, value: &EvidenceValue) -> bool {
        match (self, value) {
            (Self::Boolean(expected), EvidenceValue::Boolean(actual)) => expected == *actual,
            (Self::Unsigned(expected), EvidenceValue::Unsigned(actual)) => expected == *actual,
            (Self::Text(expected), EvidenceValue::Text(actual)) => expected == actual.as_str(),
            _ => false,
        }
    }
}

/// Native static metadata. This remains crate-private so plugins and arbitrary
/// callers cannot mint capability identities, severities, or claim policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssessmentCapabilityDescriptor {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    redacted_summary: &'static str,
    severity: Option<SecuritySeverity>,
    confidence_ppm: u32,
    cwe: Option<&'static str>,
    remediation: AssessmentRemediation,
    claim_policy: AssessmentClaimPolicy,
}

impl AssessmentCapabilityDescriptor {
    #[allow(clippy::too_many_arguments)]
    const fn new(
        id: &'static str,
        title: &'static str,
        category: &'static str,
        redacted_summary: &'static str,
        severity: Option<SecuritySeverity>,
        confidence_ppm: u32,
        cwe: Option<&'static str>,
        remediation: AssessmentRemediation,
        claim_policy: AssessmentClaimPolicy,
    ) -> Self {
        assert!(!id.is_empty() && id.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES);
        assert!(!title.is_empty() && title.len() <= MAX_ASSESSMENT_DISPLAY_BYTES);
        assert!(!category.is_empty() && category.len() <= MAX_ASSESSMENT_DISPLAY_BYTES);
        assert!(
            !redacted_summary.is_empty() && redacted_summary.len() <= MAX_ASSESSMENT_DISPLAY_BYTES
        );
        assert!(
            !remediation.id.is_empty()
                && remediation.id.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES
        );
        assert!(
            !remediation.summary.is_empty()
                && remediation.summary.len() <= MAX_ASSESSMENT_DISPLAY_BYTES
        );
        assert!(confidence_ppm <= 1_000_000);
        if let Some(cwe) = cwe {
            assert!(!cwe.is_empty() && cwe.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES);
        }
        match claim_policy {
            AssessmentClaimPolicy::ObservationOnly | AssessmentClaimPolicy::DifferentialReview => {
            },
            AssessmentClaimPolicy::VerifierTransition(policy) => {
                assert!(
                    !policy.action_id.is_empty()
                        && policy.action_id.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES
                );
                assert!(
                    !policy.hypothesis_namespace.is_empty()
                        && policy.hypothesis_namespace.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES
                );
                assert!(
                    !policy.hypothesis_name.is_empty()
                        && policy.hypothesis_name.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES
                );
                assert!(
                    !policy.verifier_rule_id.is_empty()
                        && policy.verifier_rule_id.len() <= MAX_ASSESSMENT_CAPABILITY_ID_BYTES
                );
                if let StaticEvidenceValue::Text(value) = policy.hypothesis_value {
                    assert!(!value.is_empty() && value.len() <= MAX_ASSESSMENT_DISPLAY_BYTES);
                }
            },
        }
        Self {
            id,
            title,
            category,
            redacted_summary,
            severity,
            confidence_ppm,
            cwe,
            remediation,
            claim_policy,
        }
    }

    fn confidence(self) -> Result<Probability, AssessmentItemProjectionError> {
        Probability::from_parts_per_million(self.confidence_ppm)
            .map_err(|_| AssessmentItemProjectionError::InvalidCapabilityConfidence)
    }

    const fn maximum_disposition(self) -> AssessmentDisposition {
        self.claim_policy.maximum_disposition()
    }

    const fn allows_differential_review(self) -> bool {
        matches!(
            self.claim_policy,
            AssessmentClaimPolicy::DifferentialReview
                | AssessmentClaimPolicy::VerifierTransition(_)
        )
    }

    const fn verifier_policy(self) -> Option<VerifierClaimPolicy> {
        match self.claim_policy {
            AssessmentClaimPolicy::VerifierTransition(policy) => Some(policy),
            AssessmentClaimPolicy::ObservationOnly | AssessmentClaimPolicy::DifferentialReview => {
                None
            },
        }
    }
}

fn validate_reference_set(
    _kind: &'static str,
    mut references: Vec<AssessmentEvidenceReference>,
) -> Result<Vec<AssessmentEvidenceReference>, AssessmentItemProjectionError> {
    if references.is_empty() {
        return Err(AssessmentItemProjectionError::MissingEvidence);
    }
    if references.len() > MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES {
        return Err(AssessmentItemProjectionError::TooManyEvidenceReferences);
    }
    references.sort_unstable();
    if references.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AssessmentItemProjectionError::DuplicateEvidenceReference);
    }
    Ok(references)
}

fn assessment_fingerprint(
    capability_id: &str,
    stable_subject_id: &StableAssessmentSubjectId,
    target: &AssessmentItemTarget,
) -> String {
    let mut digest = Sha256::new();
    digest.update(FINGERPRINT_DOMAIN);
    digest_field(&mut digest, ASSESSMENT_ITEM_SCHEMA);
    digest_field(&mut digest, capability_id);
    digest_field(&mut digest, stable_subject_id.as_str());
    match target {
        AssessmentItemTarget::Subject => digest_field(&mut digest, "subject"),
        AssessmentItemTarget::QueryParameter(name) => {
            digest_field(&mut digest, "query_parameter");
            digest_field(&mut digest, name);
        },
    }
    format!("sha256:{:x}", digest.finalize())
}

fn digest_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

#[derive(Debug, Clone, Copy)]
struct ConfirmationProof {
    capability_policy: bool,
    action_matches: bool,
    hypothesis_claim_matches: bool,
    outcome_success: bool,
    transition_authorized: bool,
    hypothesis_write: bool,
    final_hypothesis_confirmed: bool,
    case_matches: bool,
    selected_verifier_matches: bool,
    evidence_nonempty: bool,
    evidence_resolved: bool,
    evidence_subject_matches: bool,
    evidence_case_matches: bool,
    receipt_case_matches: bool,
    receipt_stage_matches: bool,
    receipt_contributed: bool,
    receipt_evidence_matches: bool,
}

impl ConfirmationProof {
    fn authorize(self) -> Result<(), AssessmentItemProjectionError> {
        let denied = if !self.capability_policy {
            Some(AssessmentConfirmationDenial::CapabilityPolicy)
        } else if !self.action_matches {
            Some(AssessmentConfirmationDenial::ActionMismatch)
        } else if !self.hypothesis_claim_matches {
            Some(AssessmentConfirmationDenial::HypothesisClaimMismatch)
        } else if !self.outcome_success {
            Some(AssessmentConfirmationDenial::OutcomeNotSuccess)
        } else if !self.transition_authorized {
            Some(AssessmentConfirmationDenial::KnowledgeOnly)
        } else if !self.hypothesis_write {
            Some(AssessmentConfirmationDenial::MissingHypothesisWrite)
        } else if !self.final_hypothesis_confirmed {
            Some(AssessmentConfirmationDenial::FinalHypothesisNotConfirmed)
        } else if !self.case_matches {
            Some(AssessmentConfirmationDenial::CaseMismatch)
        } else if !self.selected_verifier_matches {
            Some(AssessmentConfirmationDenial::SelectedVerifierMismatch)
        } else if !self.evidence_nonempty {
            Some(AssessmentConfirmationDenial::MissingEvidence)
        } else if !self.evidence_resolved {
            Some(AssessmentConfirmationDenial::EvidenceUnavailable)
        } else if !self.evidence_subject_matches {
            Some(AssessmentConfirmationDenial::EvidenceSubjectMismatch)
        } else if !self.evidence_case_matches {
            Some(AssessmentConfirmationDenial::EvidenceCaseMismatch)
        } else if !self.receipt_case_matches {
            Some(AssessmentConfirmationDenial::ReceiptCaseMismatch)
        } else if !self.receipt_stage_matches {
            Some(AssessmentConfirmationDenial::ReceiptStageMismatch)
        } else if !self.receipt_contributed {
            Some(AssessmentConfirmationDenial::ReceiptDidNotContribute)
        } else if !self.receipt_evidence_matches {
            Some(AssessmentConfirmationDenial::ReceiptEvidenceMismatch)
        } else {
            None
        };
        denied.map_or(Ok(()), |reason| {
            Err(AssessmentItemProjectionError::ConfirmationDenied(reason))
        })
    }
}

struct ConfirmationExtraction<'a> {
    proof: ConfirmationProof,
    evidence_ids: &'a BTreeSet<EvidenceId>,
}

fn extract_confirmation_proof<'a>(
    capability: &'static AssessmentCapabilityDescriptor,
    receipt: &DecisionEvidenceReceipt,
    decision: &'a DecisionOutcomeReport,
    knowledge: &KnowledgeBase,
) -> ConfirmationExtraction<'a> {
    let verification = decision.verification();
    let case = verification.case();
    let outcome = verification.outcome();
    let policy = capability.verifier_policy();
    let selected = verification
        .evaluations()
        .iter()
        .filter(|evaluation| evaluation.selected())
        .collect::<Vec<_>>();
    let selected_verifier_matches = policy.is_some_and(|policy| {
        selected.len() == 1
            && selected[0].rule_id() == policy.verifier_rule_id
            && selected[0].stage() == policy.stage
            && selected[0].action_matched()
            && selected[0].eligible()
            && selected[0].condition().evidence_ids() == outcome.evidence_ids()
            && outcome.verifier_rule_id() == Some(policy.verifier_rule_id)
            && outcome.stage() == policy.stage
            && verification.stage() == policy.stage
    });

    let final_hypothesis = knowledge.hypothesis(outcome.hypothesis_id());
    let hypothesis_claim_matches = policy.is_some_and(|policy| {
        final_hypothesis.as_ref().is_some_and(|hypothesis| {
            hypothesis.subject() == case.subject()
                && predicate_matches(
                    hypothesis.predicate(),
                    policy.hypothesis_namespace,
                    policy.hypothesis_name,
                )
                && policy.hypothesis_value.matches(hypothesis.value())
        })
    });
    let final_hypothesis_confirmed = final_hypothesis
        .as_ref()
        .is_some_and(|hypothesis| hypothesis.state() == HypothesisState::Confirmed);
    let case_matches = outcome.case_id() == case.id()
        && outcome.subject() == case.subject()
        && outcome.action_id() == case.action_id()
        && outcome.hypothesis_id() == case.hypothesis_id();
    let action_matches = policy.is_some_and(|policy| {
        case.action_id() == policy.action_id && outcome.action_id() == policy.action_id
    });
    let (evidence_resolved, evidence_subject_matches, evidence_case_matches) =
        validate_correlated_evidence(knowledge, outcome.evidence_ids(), case.subject(), case.id());
    let receipt_case_matches = receipt.case() == case;
    let receipt_stage_matches = execution_stage_matches(receipt.stage(), outcome.stage());
    let receipt_contributed = selected.first().is_some_and(|evaluation| {
        receipt_contributed_evidence(
            receipt,
            outcome.stage(),
            outcome.evidence_ids(),
            evaluation.fresh_evidence_ids(),
        )
    });
    let receipt_evidence_matches = selected.first().is_some_and(|evaluation| {
        receipt_evidence_matches_knowledge(
            receipt,
            knowledge,
            outcome.stage(),
            outcome.evidence_ids(),
            evaluation.fresh_evidence_ids(),
        )
    });

    ConfirmationExtraction {
        proof: ConfirmationProof {
            capability_policy: policy.is_some(),
            action_matches,
            hypothesis_claim_matches,
            outcome_success: is_confirmation_outcome(outcome.status()),
            transition_authorized: case.applies_hypothesis_transition(),
            hypothesis_write: decision.hypothesis_write().is_some(),
            final_hypothesis_confirmed,
            case_matches,
            selected_verifier_matches,
            evidence_nonempty: !outcome.evidence_ids().is_empty(),
            evidence_resolved,
            evidence_subject_matches,
            evidence_case_matches,
            receipt_case_matches,
            receipt_stage_matches,
            receipt_contributed,
            receipt_evidence_matches,
        },
        evidence_ids: outcome.evidence_ids(),
    }
}

const fn is_confirmation_outcome(status: OutcomeStatus) -> bool {
    matches!(status, OutcomeStatus::Success)
}

fn predicate_matches(predicate: &KnowledgePredicate, namespace: &str, name: &str) -> bool {
    predicate.namespace() == namespace && predicate.name() == name
}

fn validate_correlated_evidence(
    knowledge: &KnowledgeBase,
    evidence_ids: &BTreeSet<EvidenceId>,
    subject: &venom_core::EntityId,
    case_id: &str,
) -> (bool, bool, bool) {
    let mut resolved = true;
    let mut subject_matches = true;
    let mut case_matches = true;
    for evidence_id in evidence_ids {
        match knowledge.evidence(evidence_id) {
            Some(evidence) => {
                subject_matches &= evidence.subject() == subject;
                case_matches &= evidence.source().correlation_id() == Some(case_id);
            },
            None => {
                resolved = false;
                subject_matches = false;
                case_matches = false;
            },
        }
    }
    (resolved, subject_matches, case_matches)
}

fn execution_stage_matches(stage: DecisionExecutionStage, verification: VerificationStage) -> bool {
    matches!(
        (stage, verification),
        (DecisionExecutionStage::Passive, VerificationStage::Passive)
            | (DecisionExecutionStage::Active, VerificationStage::Active)
    )
}

fn receipt_contributed_evidence(
    receipt: &DecisionEvidenceReceipt,
    stage: VerificationStage,
    outcome_evidence: &BTreeSet<EvidenceId>,
    fresh_evidence: &BTreeSet<EvidenceId>,
) -> bool {
    let receipt_contains = |wanted: &EvidenceId| {
        receipt
            .evidence()
            .iter()
            .any(|evidence| evidence.id() == wanted)
    };
    match stage {
        VerificationStage::Passive => {
            !outcome_evidence.is_empty() && outcome_evidence.iter().all(&receipt_contains)
        },
        VerificationStage::Active => {
            !fresh_evidence.is_empty()
                && fresh_evidence.is_subset(outcome_evidence)
                && fresh_evidence.iter().all(receipt_contains)
        },
        _ => false,
    }
}

fn receipt_evidence_matches_knowledge(
    receipt: &DecisionEvidenceReceipt,
    knowledge: &KnowledgeBase,
    stage: VerificationStage,
    outcome_evidence: &BTreeSet<EvidenceId>,
    fresh_evidence: &BTreeSet<EvidenceId>,
) -> bool {
    let required = match stage {
        VerificationStage::Passive => outcome_evidence,
        VerificationStage::Active => fresh_evidence,
        _ => return false,
    };
    !required.is_empty()
        && required.iter().all(|evidence_id| {
            let receipt_evidence = receipt
                .evidence()
                .iter()
                .find(|evidence| evidence.id() == evidence_id);
            let committed_evidence = knowledge.evidence(evidence_id);
            receipt_evidence.is_some_and(|receipt_evidence| {
                committed_evidence
                    .as_ref()
                    .is_some_and(|committed| committed == receipt_evidence)
            })
        })
}

#[cfg(test)]
#[path = "assessment_item_tests.rs"]
mod tests;
