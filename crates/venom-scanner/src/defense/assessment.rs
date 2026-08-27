//! Assessment-owned defense evidence and exact committed-receipt replay.
//!
//! This module is crate-private until the outer assessment audit is composed.
//! It accepts only already-bounded, typed response signals from the HTTP
//! executor. Raw response headers, cookie values, and body bytes never enter
//! these types.

use std::collections::{BTreeMap, BTreeSet};

use venom_core::{
    ConfidenceScore, DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId,
    EvidenceKind, EvidenceOrigin, EvidenceSource, EvidenceValue, HttpEvidencePredicate,
    KnowledgePredicate, PredicateDescriptor, ReasoningModelError,
};

use crate::{
    planner::{AttackPlan, AttackPlanner},
    StandardWebActionKind, STANDARD_WEB_ACTION_COUNT,
};
use crate::{DecisionEvidenceReceipt, DecisionExecutionStage, KnowledgeBase, VerificationCase};

use super::{
    decide, shadow_planning::defense_aware_shadow_plan_from_current, DefenseAwareShadowPlan,
    DefenseFingerprint, DefenseInteractionClass, DefensePosture, DefenseProduct, DefenseState,
    DefenseTransition, FingerprintConfidence, InteractionDecision, ResourceDefenseObservation,
    ResourceDefenseSignal, MAX_FINGERPRINT_BODY_SCAN_BYTES,
};

pub(crate) const ASSESSMENT_DEFENSE_NAMESPACE: &str = "web.defense";
const ASSESSMENT_DEFENSE_CATEGORY: &str = "assessment-defense";
const ASSESSMENT_DEFENSE_METHOD: &str = "assessment-defense-projection";
const ASSESSMENT_DEFENSE_ALGORITHM: &str = "web-assessment-defense-observation";
const ASSESSMENT_DEFENSE_ALGORITHM_VERSION: u32 = 1;

const OBSERVATION_V1: &str = "observation_v1";
const BODY_COVERAGE: &str = "body_coverage";
const INPUT_LIMIT_REACHED: &str = "input_limit_reached";
const POSTURE: &str = "posture";
const CHALLENGE: &str = "challenge";
const RATE_LIMIT: &str = "rate_limit";
const RATE_LIMIT_HEADERS: &str = "rate_limit_headers";
const FINGERPRINT_HINT: &str = "fingerprint_hint";

const COVERAGE_METADATA_ONLY: &str = "metadata_only";
const COVERAGE_COMPLETE: &str = "complete_utf8_prefix";

/// Whether broker EOF and the detector's bounded UTF-8 prefix were available.
/// This never claims exhaustive whole-body analysis or defense absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssessmentDefenseBodyCoverage {
    MetadataOnly,
    CompleteUtf8Prefix,
}

impl AssessmentDefenseBodyCoverage {
    const fn slug(self) -> &'static str {
        match self {
            Self::MetadataOnly => COVERAGE_METADATA_ONLY,
            Self::CompleteUtf8Prefix => COVERAGE_COMPLETE,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            COVERAGE_METADATA_ONLY => Some(Self::MetadataOnly),
            COVERAGE_COMPLETE => Some(Self::CompleteUtf8Prefix),
            _ => None,
        }
    }
}

/// Bounded response signals passed from the executor into the evidence
/// projection. This owns no raw transport material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssessmentDefenseSignal {
    state: DefenseState,
    body_coverage: AssessmentDefenseBodyCoverage,
    input_limit_reached: bool,
}

impl AssessmentDefenseSignal {
    pub(crate) fn new(
        state: DefenseState,
        body_coverage: AssessmentDefenseBodyCoverage,
        input_limit_reached: bool,
    ) -> Self {
        Self {
            state,
            body_coverage,
            input_limit_reached,
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> &DefenseState {
        &self.state
    }

    #[cfg(test)]
    pub(crate) const fn body_coverage(&self) -> AssessmentDefenseBodyCoverage {
        self.body_coverage
    }

    #[cfg(test)]
    pub(crate) const fn input_limit_reached(&self) -> bool {
        self.input_limit_reached
    }

    #[cfg(test)]
    pub(crate) fn has_positive_metadata_signal(&self) -> bool {
        self.state.status_signal().is_block()
            || self.state.is_rate_limited()
            || self.state.has_rate_limit_headers()
            || self.state.fingerprint().is_some()
    }
}

/// Exact base evidence identities already present earlier in the same executor
/// batch. Every assessment-defense record derives from this closed set.
pub(crate) struct AssessmentDefenseProjectionContext<'a> {
    pub(crate) subject: &'a EntityId,
    pub(crate) case_id: &'a str,
    pub(crate) executor_id: &'a str,
    pub(crate) reliability: ConfidenceScore,
    pub(crate) parents: Vec<EvidenceId>,
}

/// Projects safe response signals into the same atomic HTTP evidence batch.
pub(crate) fn project_assessment_defense_signal(
    signal: &AssessmentDefenseSignal,
    context: AssessmentDefenseProjectionContext<'_>,
) -> Result<Vec<Evidence>, ReasoningModelError> {
    let derivation = EvidenceDerivation::new(
        context.parents,
        DerivationAlgorithm::new(
            ASSESSMENT_DEFENSE_ALGORITHM,
            ASSESSMENT_DEFENSE_ALGORITHM_VERSION,
        )?,
    )?;
    let source = EvidenceSource::new(context.executor_id, ASSESSMENT_DEFENSE_METHOD)?
        .with_correlation_id(context.case_id)?;
    let mut evidence = Vec::with_capacity(8);

    let mut push = |name: &'static str, value: EvidenceValue| -> Result<(), ReasoningModelError> {
        evidence.push(
            Evidence::new(
                context.subject.clone(),
                EvidenceKind::Custom(ASSESSMENT_DEFENSE_CATEGORY.to_owned()),
                predicate(name)?,
                value,
                source.clone(),
                context.reliability,
            )
            .derived_from(derivation.clone()),
        );
        Ok(())
    };

    push(
        OBSERVATION_V1,
        EvidenceValue::TextList(signal_summary(signal)),
    )?;
    push(
        BODY_COVERAGE,
        EvidenceValue::Text(signal.body_coverage.slug().to_owned()),
    )?;
    if signal.input_limit_reached {
        push(INPUT_LIMIT_REACHED, EvidenceValue::Boolean(true))?;
    }

    let posture_is_positive = signal.state.posture() != DefensePosture::Open;
    let complete_open = signal.body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
        && !signal.input_limit_reached;
    if posture_is_positive || complete_open {
        push(
            POSTURE,
            EvidenceValue::Text(posture_slug(signal.state.posture()).to_owned()),
        )?;
    }
    if signal.state.is_challenged() {
        push(CHALLENGE, EvidenceValue::Boolean(true))?;
    }
    if signal.state.is_rate_limited() {
        push(RATE_LIMIT, EvidenceValue::Boolean(true))?;
    }
    if signal.state.has_rate_limit_headers() {
        push(RATE_LIMIT_HEADERS, EvidenceValue::Boolean(true))?;
    }
    if let Some(hint) = signal.state.fingerprint() {
        push(
            FINGERPRINT_HINT,
            EvidenceValue::TextList(vec![
                product_slug(hint.product()).to_owned(),
                confidence_slug(hint.confidence()).to_owned(),
            ]),
        )?;
    }
    Ok(evidence)
}

/// One exactly replayed response observation. It contains only typed, bounded
/// state and immutable provenance identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentDefenseObservation {
    case: VerificationCase,
    stage: DecisionExecutionStage,
    state: DefenseState,
    body_coverage: AssessmentDefenseBodyCoverage,
    input_limit_reached: bool,
    evidence_ids: Vec<EvidenceId>,
}

impl CommittedAssessmentDefenseObservation {
    pub(crate) fn case(&self) -> &VerificationCase {
        &self.case
    }

    pub(crate) const fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }

    pub(crate) fn state(&self) -> &DefenseState {
        &self.state
    }

    pub(crate) const fn body_coverage(&self) -> AssessmentDefenseBodyCoverage {
        self.body_coverage
    }

    pub(crate) const fn input_limit_reached(&self) -> bool {
        self.input_limit_reached
    }

    pub(crate) fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }

    pub(crate) fn is_signal_eligible(&self) -> bool {
        (self.body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            && !self.input_limit_reached)
            || self.state.status_signal().is_block()
            || self.state.is_rate_limited()
            || self.state.fingerprint().is_some()
    }
}

/// One authoritative, idempotent receipt replay ledger used by both dynamic
/// enforcement and the outer assessment report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentDefenseLedger {
    observations: Vec<CommittedAssessmentDefenseObservation>,
    transitions: Vec<CommittedAssessmentDefenseTransition>,
    receipt_keys: BTreeSet<AssessmentDefenseReceiptKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentDefenseTransition {
    case: VerificationCase,
    candidate_block_status_appeared: bool,
    suppression_newly_blocking: bool,
    newly_rate_limited: bool,
    candidate_fingerprint_hint: Option<DefenseFingerprint>,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

impl CommittedAssessmentDefenseTransition {
    pub(crate) fn case(&self) -> &VerificationCase {
        &self.case
    }

    pub(crate) const fn candidate_block_status_appeared(&self) -> bool {
        self.candidate_block_status_appeared
    }

    pub(crate) const fn newly_rate_limited(&self) -> bool {
        self.newly_rate_limited
    }

    pub(crate) fn candidate_fingerprint_hint(&self) -> Option<&DefenseFingerprint> {
        self.candidate_fingerprint_hint.as_ref()
    }

    pub(crate) fn control_evidence_ids(&self) -> &[EvidenceId] {
        &self.control_evidence_ids
    }

    pub(crate) fn candidate_evidence_ids(&self) -> &[EvidenceId] {
        &self.candidate_evidence_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AssessmentDefenseReceiptKey {
    case_id: String,
    stage: DecisionExecutionStage,
    executor_id: String,
    evidence_ids: Vec<EvidenceId>,
}

impl CommittedAssessmentDefenseLedger {
    pub(crate) fn observations(&self) -> &[CommittedAssessmentDefenseObservation] {
        &self.observations
    }

    pub(crate) fn transitions(&self) -> &[CommittedAssessmentDefenseTransition] {
        &self.transitions
    }

    /// Replays one receipt atomically. `require_projection` is true for every
    /// assessment-owned transport executor and false for local-knowledge work.
    pub(crate) fn ingest_receipt(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        knowledge: &KnowledgeBase,
        require_projection: bool,
    ) -> Result<Option<&CommittedAssessmentDefenseObservation>, ()> {
        validate_receipt_storage(receipt, knowledge)?;
        let parsed = parse_receipt(receipt)?;
        if require_projection && parsed.is_none() {
            return Err(());
        }
        let receipt_key = receipt_key(receipt);
        if self.receipt_keys.contains(&receipt_key) {
            return Ok(None);
        }
        let Some(parsed) = parsed else {
            self.receipt_keys.insert(receipt_key);
            return Ok(None);
        };

        let mut prospective = self.clone();
        prospective.receipt_keys.insert(receipt_key);
        if let Some(transition) = prospective.positive_transition_for(&parsed) {
            prospective.transitions.push(transition);
        }
        prospective.observations.push(parsed);
        *self = prospective;
        Ok(self.observations.last())
    }

    fn positive_transition_for(
        &self,
        candidate: &CommittedAssessmentDefenseObservation,
    ) -> Option<CommittedAssessmentDefenseTransition> {
        if candidate.stage != DecisionExecutionStage::Active {
            return None;
        }
        let control = self.observations.iter().rev().find(|observation| {
            observation.stage == DecisionExecutionStage::Passive
                && observation.case == candidate.case
                && observation.case.subject() == candidate.case.subject()
        })?;
        let newly_blocking_status =
            candidate.state.status_signal().is_block() && !control.state.status_signal().is_block();
        let newly_rate_limited = candidate.state.is_rate_limited()
            && !control.state.is_rate_limited()
            && !control.input_limit_reached;
        let suppression_newly_blocking = newly_blocking_status
            && control.body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            && !control.input_limit_reached
            && control.state.posture() != DefensePosture::Blocking;
        let candidate_product = candidate.state.fingerprint().map(|hint| hint.product());
        let control_product = control.state.fingerprint().map(|hint| hint.product());
        let candidate_fingerprint_hint = is_candidate_fingerprint_hint(
            control_product,
            candidate_product,
            control.body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
                && !control.input_limit_reached,
        );
        if !(newly_blocking_status || newly_rate_limited || candidate_fingerprint_hint) {
            return None;
        }
        Some(CommittedAssessmentDefenseTransition {
            case: candidate.case.clone(),
            candidate_block_status_appeared: newly_blocking_status,
            suppression_newly_blocking,
            newly_rate_limited,
            candidate_fingerprint_hint: candidate
                .state
                .fingerprint()
                .cloned()
                .filter(|_| candidate_fingerprint_hint),
            control_evidence_ids: control.evidence_ids.clone(),
            candidate_evidence_ids: candidate.evidence_ids.clone(),
        })
    }

    pub(crate) fn signal_for_subject(&self, subject: &EntityId) -> ResourceDefenseSignal {
        let positive_transitions: BTreeMap<_, _> = self
            .transitions
            .iter()
            .filter(|transition| transition.case.subject() == subject)
            .filter_map(|transition| {
                if !transition.suppression_newly_blocking {
                    return None;
                }
                let control = self.observations.iter().find(|observation| {
                    observation.evidence_ids == transition.control_evidence_ids
                })?;
                let candidate = self.observations.iter().find(|observation| {
                    observation.evidence_ids == transition.candidate_evidence_ids
                })?;
                transition.candidate_evidence_ids.first().map(|id| {
                    (
                        id.clone(),
                        DefenseTransition::between(&control.state, &candidate.state),
                    )
                })
            })
            .collect();
        let observations: Vec<_> = self
            .observations
            .iter()
            .filter(|observation| observation.case.subject() == subject)
            .filter(|observation| observation.is_signal_eligible())
            .map(|observation| {
                let transition = observation
                    .evidence_ids
                    .first()
                    .and_then(|id| positive_transitions.get(id));
                ResourceDefenseObservation::new(
                    &observation.state,
                    transition,
                    observation.evidence_ids.clone(),
                )
            })
            .collect();
        ResourceDefenseSignal::aggregate(subject.clone(), &observations)
    }
}

fn is_candidate_fingerprint_hint(
    control: Option<DefenseProduct>,
    candidate: Option<DefenseProduct>,
    control_complete: bool,
) -> bool {
    match (control, candidate) {
        (Some(control), Some(candidate)) => control != candidate,
        (None, Some(_)) => control_complete,
        _ => false,
    }
}

/// Assessment-only dynamic controller. The outer report reuses the exact same
/// ledger implementation and requires replay equality before exposing audit.
#[derive(Debug, Clone)]
pub(crate) struct AssessmentDefenseController {
    ledger: CommittedAssessmentDefenseLedger,
    enforcement_enabled: bool,
    shadows: Vec<DefenseAwareShadowPlan>,
}

impl AssessmentDefenseController {
    pub(crate) fn new(enforcement_enabled: bool) -> Self {
        Self {
            ledger: CommittedAssessmentDefenseLedger::default(),
            enforcement_enabled,
            shadows: Vec::new(),
        }
    }

    pub(crate) fn ledger(&self) -> &CommittedAssessmentDefenseLedger {
        &self.ledger
    }

    pub(crate) const fn enforcement_enabled(&self) -> bool {
        self.enforcement_enabled
    }

    pub(crate) fn shadows(&self) -> &[DefenseAwareShadowPlan] {
        &self.shadows
    }

    pub(crate) fn exact_audit_eq(&self, other: &Self) -> bool {
        self.enforcement_enabled == other.enforcement_enabled
            && self.ledger == other.ledger
            && self.shadows.len() == other.shadows.len()
            && self
                .shadows
                .iter()
                .zip(&other.shadows)
                .all(|(left, right)| {
                    left.current() == right.current()
                        && left.shadow() == right.shadow()
                        && left.delta() == right.delta()
                })
    }

    pub(crate) fn record_shadow(
        &mut self,
        report: &crate::DecisionPlanningReport,
        planner: &AttackPlanner,
    ) -> Result<(), ()> {
        let shadow =
            self.shadow_from_policy_baseline(report.policy_authorized_plan().clone(), planner)?;
        if (self.enforcement_enabled && shadow.shadow() != report.plan())
            || (!self.enforcement_enabled && report.policy_authorized_plan() != report.plan())
        {
            return Err(());
        }
        self.shadows.push(shadow);
        Ok(())
    }

    pub(crate) fn ingest_receipt(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        knowledge: &KnowledgeBase,
        require_projection: bool,
    ) -> Result<(), ()> {
        self.ledger
            .ingest_receipt(receipt, knowledge, require_projection)
            .map(|_| ())
    }

    pub(crate) fn defense_suppressed_actions(
        &self,
        subject: &EntityId,
        planner: &AttackPlanner,
    ) -> Result<BTreeSet<String>, ()> {
        if !self.enforcement_enabled {
            return Ok(BTreeSet::new());
        }
        validate_standard_planner(planner)?;
        let signal = self.ledger.signal_for_subject(subject);
        let mut suppressed = BTreeSet::new();
        for kind in StandardWebActionKind::all() {
            let class = interaction_class(kind);
            if decide(signal.response(), class) == InteractionDecision::Suppress {
                suppressed.insert(kind.action_id().to_owned());
            }
        }
        Ok(suppressed)
    }

    pub(crate) fn shadow_from_policy_baseline(
        &self,
        baseline: AttackPlan,
        planner: &AttackPlanner,
    ) -> Result<DefenseAwareShadowPlan, ()> {
        validate_standard_planner(planner)?;
        let mut classes = BTreeMap::new();
        for step in baseline.steps() {
            let kind = StandardWebActionKind::all()
                .into_iter()
                .find(|kind| kind.action_id() == step.action_id())
                .ok_or(())?;
            if planner.action(step.action_id()).is_none() {
                return Err(());
            }
            classes.insert(step.action_id().to_owned(), interaction_class(kind));
        }
        let signal = self.ledger.signal_for_subject(baseline.subject());
        Ok(defense_aware_shadow_plan_from_current(
            baseline,
            planner,
            &signal,
            |action| {
                *classes
                    .get(action.id())
                    .expect("all policy-baseline actions were prevalidated")
            },
        ))
    }
}

fn validate_standard_planner(planner: &AttackPlanner) -> Result<(), ()> {
    if planner.len() != STANDARD_WEB_ACTION_COUNT
        || StandardWebActionKind::all()
            .into_iter()
            .any(|kind| planner.action(kind.action_id()).is_none())
    {
        return Err(());
    }
    Ok(())
}

const fn interaction_class(kind: StandardWebActionKind) -> DefenseInteractionClass {
    match kind {
        StandardWebActionKind::LaravelInputAnalysis => DefenseInteractionClass::LocalOnly,
        StandardWebActionKind::LaravelRouteDiscovery => DefenseInteractionClass::Behavioral,
        StandardWebActionKind::NginxConfiguration
        | StandardWebActionKind::ApacheConfiguration
        | StandardWebActionKind::PhpInputDiscovery
        | StandardWebActionKind::LivewireComponentDiscovery
        | StandardWebActionKind::SanctumAuthBoundary
        | StandardWebActionKind::HttpBasicAuthBoundary
        | StandardWebActionKind::HttpBearerAuthBoundary => DefenseInteractionClass::Passive,
    }
}

fn validate_receipt_storage(
    receipt: &DecisionEvidenceReceipt,
    knowledge: &KnowledgeBase,
) -> Result<(), ()> {
    if receipt.evidence().len() != receipt.writes().len() {
        return Err(());
    }
    for (evidence, write) in receipt.write_set() {
        if !matches!(
            write,
            crate::KnowledgeWrite::Inserted | crate::KnowledgeWrite::Unchanged
        ) {
            return Err(());
        }
        if evidence.subject() != receipt.case().subject()
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
) -> Result<Option<CommittedAssessmentDefenseObservation>, ()> {
    let Some(first_defense) = receipt
        .evidence()
        .iter()
        .position(|item| item.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE)
    else {
        return Ok(None);
    };
    if receipt.evidence()[first_defense..]
        .iter()
        .any(|item| item.predicate().namespace() != ASSESSMENT_DEFENSE_NAMESPACE)
    {
        return Err(());
    }
    let defense: Vec<_> = receipt.evidence()[first_defense..].iter().collect();
    let base = BaseEvidence::parse(receipt, first_defense)?;
    let mut canonical_parents = base.parent_ids.clone();
    canonical_parents.sort();
    if canonical_parents.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(());
    }
    for item in &defense {
        if item.kind() != &EvidenceKind::Custom(ASSESSMENT_DEFENSE_CATEGORY.to_owned())
            || item.source().component() != receipt.executor_id()
            || item.source().method() != ASSESSMENT_DEFENSE_METHOD
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.subject() != receipt.case().subject()
        {
            return Err(());
        }
        let EvidenceOrigin::Derived(derivation) = item.origin() else {
            return Err(());
        };
        if derivation.algorithm().name() != ASSESSMENT_DEFENSE_ALGORITHM
            || derivation.algorithm().version() != ASSESSMENT_DEFENSE_ALGORITHM_VERSION
            || derivation.parents() != canonical_parents
        {
            return Err(());
        }
    }

    let mut cursor = 0;
    let summary = expect_text_list_record(&defense, &mut cursor, OBSERVATION_V1)?;
    let coverage_value = expect_text_record(&defense, &mut cursor, BODY_COVERAGE)?;
    let body_coverage = AssessmentDefenseBodyCoverage::parse(coverage_value).ok_or(())?;
    let input_limit_reached = take_boolean_true(&defense, &mut cursor, INPUT_LIMIT_REACHED)?;
    let posture_record = take_text(&defense, &mut cursor, POSTURE)?;
    let posture = posture_record
        .map(parse_posture)
        .transpose()?
        .unwrap_or(DefensePosture::Open);
    let challenged = take_boolean_true(&defense, &mut cursor, CHALLENGE)?;
    let rate_limited = take_boolean_true(&defense, &mut cursor, RATE_LIMIT)?;
    let rate_limit_headers = take_boolean_true(&defense, &mut cursor, RATE_LIMIT_HEADERS)?;
    let fingerprint = take_fingerprint_hint(&defense, &mut cursor)?;
    if cursor != defense.len() {
        return Err(());
    }

    let state = DefenseState::from_assessment_projection(
        base.status,
        challenged,
        rate_limited,
        rate_limit_headers,
        fingerprint,
    );
    let signal = AssessmentDefenseSignal::new(state.clone(), body_coverage, input_limit_reached);
    let expected_summary = signal_summary(&signal);
    let expected_posture_record = state.posture() != DefensePosture::Open
        || (body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            && !input_limit_reached);
    if summary != expected_summary
        || posture_record.is_some() != expected_posture_record
        || state.posture() != posture
        || challenged != state.is_challenged()
        || rate_limited != state.is_rate_limited()
        || rate_limit_headers != state.has_rate_limit_headers()
        || base.rate_detected != (base.status == 429)
        || rate_limited != (base.rate_detected || base.rate_advertised)
        || rate_limit_headers != base.rate_advertised
        || (base.request_method == "HEAD"
            && body_coverage != AssessmentDefenseBodyCoverage::MetadataOnly)
        || (body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            && base.body_truncated)
        || (base.body_bytes > MAX_FINGERPRINT_BODY_SCAN_BYTES as u64 && !input_limit_reached)
    {
        return Err(());
    }

    Ok(Some(CommittedAssessmentDefenseObservation {
        case: receipt.case().clone(),
        stage: receipt.stage(),
        state,
        body_coverage,
        input_limit_reached,
        evidence_ids: defense.iter().map(|item| item.id().clone()).collect(),
    }))
}

struct BaseEvidence {
    request_method: String,
    status: u16,
    body_bytes: u64,
    body_truncated: bool,
    rate_detected: bool,
    rate_advertised: bool,
    parent_ids: Vec<EvidenceId>,
}

impl BaseEvidence {
    fn parse(receipt: &DecisionEvidenceReceipt, first_defense: usize) -> Result<Self, ()> {
        let required = [
            HttpEvidencePredicate::REQUEST_METHOD,
            HttpEvidencePredicate::REQUEST_URL,
            HttpEvidencePredicate::RESPONSE_STATUS,
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            HttpEvidencePredicate::RESPONSE_BODY_SHA256,
            HttpEvidencePredicate::RATE_LIMIT_DETECTED,
            HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
        ];
        let mut parents = Vec::with_capacity(required.len());
        let mut status = None;
        let mut rate_detected = None;
        let mut rate_advertised = None;
        let mut request_method = None;
        let mut body_bytes = None;
        let mut body_truncated = None;
        let mut request_url = None;
        let mut final_url = None;
        let mut previous_index = None;
        for descriptor in required {
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
            if index >= first_defense || previous_index.is_some_and(|previous| index <= previous) {
                return Err(());
            }
            previous_index = Some(index);
            if item.origin().is_direct()
                && item.source().component() == receipt.executor_id()
                && item.source().correlation_id() == Some(receipt.case().id())
                && base_record_shape(descriptor, item)
            {
                parents.push(item.id().clone());
            } else {
                return Err(());
            }
            if descriptor == HttpEvidencePredicate::REQUEST_METHOD {
                let EvidenceValue::Text(value) = item.value() else {
                    return Err(());
                };
                request_method = Some(value.clone());
            } else if descriptor == HttpEvidencePredicate::REQUEST_URL {
                let EvidenceValue::Text(value) = item.value() else {
                    return Err(());
                };
                request_url = Some(value.as_str());
            } else if descriptor == HttpEvidencePredicate::RESPONSE_FINAL_URL {
                let EvidenceValue::Text(value) = item.value() else {
                    return Err(());
                };
                final_url = Some(value.as_str());
            } else if descriptor == HttpEvidencePredicate::RESPONSE_STATUS {
                let EvidenceValue::Unsigned(value) = item.value() else {
                    return Err(());
                };
                status = u16::try_from(*value).ok();
            } else if descriptor == HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED {
                let EvidenceValue::Unsigned(value) = item.value() else {
                    return Err(());
                };
                body_bytes = Some(*value);
            } else if descriptor == HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED {
                let EvidenceValue::Boolean(value) = item.value() else {
                    return Err(());
                };
                body_truncated = Some(*value);
            } else if descriptor == HttpEvidencePredicate::RATE_LIMIT_DETECTED {
                let EvidenceValue::Boolean(value) = item.value() else {
                    return Err(());
                };
                rate_detected = Some(*value);
            } else if descriptor == HttpEvidencePredicate::RATE_LIMIT_ADVERTISED {
                let EvidenceValue::Boolean(value) = item.value() else {
                    return Err(());
                };
                rate_advertised = Some(*value);
            }
        }
        let status = status
            .filter(|value| (100..=599).contains(value))
            .ok_or(())?;
        if request_url.is_none() || request_url != final_url {
            return Err(());
        }
        Ok(Self {
            request_method: request_method.ok_or(())?,
            status,
            body_bytes: body_bytes.ok_or(())?,
            body_truncated: body_truncated.ok_or(())?,
            rate_detected: rate_detected.ok_or(())?,
            rate_advertised: rate_advertised.ok_or(())?,
            parent_ids: parents,
        })
    }
}

fn base_record_shape(descriptor: PredicateDescriptor, item: &Evidence) -> bool {
    let (kind, method) = match descriptor {
        HttpEvidencePredicate::REQUEST_METHOD => (EvidenceKind::Http, "request-method"),
        HttpEvidencePredicate::REQUEST_URL => (EvidenceKind::Http, "request-url"),
        HttpEvidencePredicate::RESPONSE_STATUS => (EvidenceKind::Http, "response-status"),
        HttpEvidencePredicate::RESPONSE_FINAL_URL => (EvidenceKind::Http, "response-final-url"),
        HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED => {
            (EvidenceKind::Content, "response-body-size")
        },
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED => {
            (EvidenceKind::Content, "response-body-truncation")
        },
        HttpEvidencePredicate::RESPONSE_BODY_SHA256 => {
            (EvidenceKind::Content, "response-body-sha256")
        },
        HttpEvidencePredicate::RATE_LIMIT_DETECTED => {
            (EvidenceKind::RateLimit, "rate-limit-status")
        },
        HttpEvidencePredicate::RATE_LIMIT_ADVERTISED => {
            (EvidenceKind::RateLimit, "rate-limit-headers")
        },
        _ => return false,
    };
    if item.kind() != &kind || item.source().method() != method {
        return false;
    }
    match descriptor {
        HttpEvidencePredicate::REQUEST_METHOD => matches!(
            item.value(),
            EvidenceValue::Text(value) if matches!(value.as_str(), "GET" | "HEAD" | "OPTIONS")
        ),
        HttpEvidencePredicate::REQUEST_URL | HttpEvidencePredicate::RESPONSE_FINAL_URL => {
            matches!(item.value(), EvidenceValue::Text(value) if url::Url::parse(value).is_ok())
        },
        HttpEvidencePredicate::RESPONSE_STATUS
        | HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED => {
            matches!(item.value(), EvidenceValue::Unsigned(_))
        },
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED
        | HttpEvidencePredicate::RATE_LIMIT_DETECTED
        | HttpEvidencePredicate::RATE_LIMIT_ADVERTISED => {
            matches!(item.value(), EvidenceValue::Boolean(_))
        },
        HttpEvidencePredicate::RESPONSE_BODY_SHA256 => matches!(
            item.value(),
            EvidenceValue::Text(value)
                if value.len() == 64
                    && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        ),
        _ => false,
    }
}

fn receipt_key(receipt: &DecisionEvidenceReceipt) -> AssessmentDefenseReceiptKey {
    let evidence_ids: Vec<_> = receipt
        .evidence()
        .iter()
        .map(|item| item.id().clone())
        .collect();
    AssessmentDefenseReceiptKey {
        case_id: receipt.case().id().to_owned(),
        stage: receipt.stage(),
        executor_id: receipt.executor_id().to_owned(),
        evidence_ids,
    }
}

fn predicate(name: &'static str) -> Result<KnowledgePredicate, ReasoningModelError> {
    KnowledgePredicate::new(ASSESSMENT_DEFENSE_NAMESPACE, name)
}

fn signal_summary(signal: &AssessmentDefenseSignal) -> Vec<String> {
    let mut summary = Vec::with_capacity(5);
    let posture_is_positive = signal.state.posture() != DefensePosture::Open;
    let complete_open = signal.body_coverage == AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
        && !signal.input_limit_reached;
    if posture_is_positive || complete_open {
        summary.push(format!("posture:{}", posture_slug(signal.state.posture())));
    }
    if signal.state.is_challenged() {
        summary.push("challenge:present".to_owned());
    }
    if signal.state.is_rate_limited() {
        summary.push("rate_limit:observed".to_owned());
    }
    if signal.state.has_rate_limit_headers() {
        summary.push("rate_limit_headers:present".to_owned());
    }
    if let Some(hint) = signal.state.fingerprint() {
        summary.push(format!(
            "fingerprint_hint:{}:{}",
            product_slug(hint.product()),
            confidence_slug(hint.confidence())
        ));
    }
    summary
}

fn expect_record(
    records: &[&Evidence],
    cursor: &mut usize,
    name: &str,
    value: &EvidenceValue,
) -> Result<(), ()> {
    let Some(record) = records.get(*cursor) else {
        return Err(());
    };
    if record.predicate().name() != name || record.value() != value {
        return Err(());
    }
    *cursor += 1;
    Ok(())
}

fn expect_text_record<'a>(
    records: &'a [&Evidence],
    cursor: &mut usize,
    name: &str,
) -> Result<&'a str, ()> {
    let Some(record) = records.get(*cursor) else {
        return Err(());
    };
    let EvidenceValue::Text(value) = record.value() else {
        return Err(());
    };
    if record.predicate().name() != name {
        return Err(());
    }
    *cursor += 1;
    Ok(value)
}

fn expect_text_list_record<'a>(
    records: &'a [&Evidence],
    cursor: &mut usize,
    name: &str,
) -> Result<&'a [String], ()> {
    let Some(record) = records.get(*cursor) else {
        return Err(());
    };
    let EvidenceValue::TextList(value) = record.value() else {
        return Err(());
    };
    if record.predicate().name() != name {
        return Err(());
    }
    *cursor += 1;
    Ok(value)
}

fn take_boolean_true(records: &[&Evidence], cursor: &mut usize, name: &str) -> Result<bool, ()> {
    if records
        .get(*cursor)
        .is_none_or(|record| record.predicate().name() != name)
    {
        return Ok(false);
    }
    expect_record(records, cursor, name, &EvidenceValue::Boolean(true))?;
    Ok(true)
}

fn take_text<'a>(
    records: &'a [&Evidence],
    cursor: &mut usize,
    name: &str,
) -> Result<Option<&'a str>, ()> {
    if records
        .get(*cursor)
        .is_none_or(|record| record.predicate().name() != name)
    {
        return Ok(None);
    }
    expect_text_record(records, cursor, name).map(Some)
}

fn take_fingerprint_hint(
    records: &[&Evidence],
    cursor: &mut usize,
) -> Result<Option<DefenseFingerprint>, ()> {
    if records
        .get(*cursor)
        .is_none_or(|record| record.predicate().name() != FINGERPRINT_HINT)
    {
        return Ok(None);
    }
    let record = records[*cursor];
    let EvidenceValue::TextList(values) = record.value() else {
        return Err(());
    };
    if values.len() != 2 {
        return Err(());
    }
    let product = parse_product(&values[0])?;
    let confidence = parse_confidence(&values[1])?;
    *cursor += 1;
    Ok(Some(DefenseFingerprint::from_assessment_hint(
        product, confidence,
    )))
}

const fn posture_slug(posture: DefensePosture) -> &'static str {
    match posture {
        DefensePosture::Open => "open",
        DefensePosture::Suspected => "suspected",
        DefensePosture::Blocking => "blocking",
    }
}

fn parse_posture(value: &str) -> Result<DefensePosture, ()> {
    match value {
        "open" => Ok(DefensePosture::Open),
        "suspected" => Ok(DefensePosture::Suspected),
        "blocking" => Ok(DefensePosture::Blocking),
        _ => Err(()),
    }
}

const fn confidence_slug(confidence: FingerprintConfidence) -> &'static str {
    match confidence {
        FingerprintConfidence::Weak => "weak",
        FingerprintConfidence::Probable => "probable",
        FingerprintConfidence::Strong => "strong",
    }
}

fn parse_confidence(value: &str) -> Result<FingerprintConfidence, ()> {
    match value {
        "weak" => Ok(FingerprintConfidence::Weak),
        "probable" => Ok(FingerprintConfidence::Probable),
        "strong" => Ok(FingerprintConfidence::Strong),
        _ => Err(()),
    }
}

const fn product_slug(product: DefenseProduct) -> &'static str {
    match product {
        DefenseProduct::Cloudflare => "cloudflare",
        DefenseProduct::AwsWaf => "aws_waf",
        DefenseProduct::ModSecurity => "mod_security",
        DefenseProduct::Akamai => "akamai",
        DefenseProduct::Imperva => "imperva",
        DefenseProduct::F5BigIp => "f5_big_ip",
        DefenseProduct::Barracuda => "barracuda",
        DefenseProduct::Fortinet => "fortinet",
        DefenseProduct::Sucuri => "sucuri",
        DefenseProduct::Wordfence => "wordfence",
    }
}

fn parse_product(value: &str) -> Result<DefenseProduct, ()> {
    match value {
        "cloudflare" => Ok(DefenseProduct::Cloudflare),
        "aws_waf" => Ok(DefenseProduct::AwsWaf),
        "mod_security" => Ok(DefenseProduct::ModSecurity),
        "akamai" => Ok(DefenseProduct::Akamai),
        "imperva" => Ok(DefenseProduct::Imperva),
        "f5_big_ip" => Ok(DefenseProduct::F5BigIp),
        "barracuda" => Ok(DefenseProduct::Barracuda),
        "fortinet" => Ok(DefenseProduct::Fortinet),
        "sucuri" => Ok(DefenseProduct::Sucuri),
        "wordfence" => Ok(DefenseProduct::Wordfence),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_case(id: &str, subject: &EntityId) -> VerificationCase {
        VerificationCase::new(
            id,
            subject.clone(),
            "action:test:defense",
            "hypothesis:test:defense",
        )
        .unwrap()
    }

    fn test_observation(
        case: VerificationCase,
        stage: DecisionExecutionStage,
        state: DefenseState,
        body_coverage: AssessmentDefenseBodyCoverage,
        input_limit_reached: bool,
        evidence_id: &str,
    ) -> CommittedAssessmentDefenseObservation {
        CommittedAssessmentDefenseObservation {
            case,
            stage,
            state,
            body_coverage,
            input_limit_reached,
            evidence_ids: vec![EvidenceId::parse(evidence_id).unwrap()],
        }
    }

    fn transition_for(
        control: CommittedAssessmentDefenseObservation,
        candidate: CommittedAssessmentDefenseObservation,
    ) -> Option<CommittedAssessmentDefenseTransition> {
        let ledger = CommittedAssessmentDefenseLedger {
            observations: vec![control],
            ..CommittedAssessmentDefenseLedger::default()
        };
        ledger.positive_transition_for(&candidate)
    }

    fn projected_state(
        status: u16,
        rate_limited: bool,
        fingerprint: Option<DefenseFingerprint>,
    ) -> DefenseState {
        DefenseState::from_assessment_projection(
            status,
            false,
            rate_limited,
            rate_limited,
            fingerprint,
        )
    }

    fn hint(product: DefenseProduct) -> DefenseFingerprint {
        DefenseFingerprint::from_assessment_hint(product, FingerprintConfidence::Weak)
    }

    fn projection_context<'a>(
        subject: &'a EntityId,
        parents: Vec<EvidenceId>,
    ) -> AssessmentDefenseProjectionContext<'a> {
        AssessmentDefenseProjectionContext {
            subject,
            case_id: "case:test:defense",
            executor_id: "executor:test:defense",
            reliability: ConfidenceScore::MAX,
            parents,
        }
    }

    #[test]
    fn metadata_only_projection_never_emits_open_posture() {
        let subject = EntityId::new("endpoint:https://example.test/").unwrap();
        let signal = AssessmentDefenseSignal::new(
            DefenseState::from_assessment_projection(200, false, false, false, None),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            false,
        );
        let parent = EvidenceId::parse("defense/parent-1").unwrap();
        let evidence = project_assessment_defense_signal(
            &signal,
            projection_context(&subject, vec![parent.clone()]),
        )
        .unwrap();
        assert!(evidence
            .iter()
            .all(|item| item.predicate().name() != POSTURE));
        assert!(evidence.iter().all(|item| matches!(
            item.origin(),
            EvidenceOrigin::Derived(derivation) if derivation.parents() == [parent.clone()]
        )));
    }

    #[test]
    fn incomplete_standard_planner_is_rejected() {
        let controller = AssessmentDefenseController::new(true);
        let subject = EntityId::new("endpoint:https://example.test/").unwrap();
        assert!(controller
            .defense_suppressed_actions(&subject, &AttackPlanner::new())
            .is_err());
    }

    #[test]
    fn candidate_fingerprint_hint_is_positive_only() {
        assert!(is_candidate_fingerprint_hint(
            None,
            Some(DefenseProduct::Cloudflare),
            true,
        ));
        assert!(!is_candidate_fingerprint_hint(
            None,
            Some(DefenseProduct::Cloudflare),
            false,
        ));
        assert!(is_candidate_fingerprint_hint(
            Some(DefenseProduct::Cloudflare),
            Some(DefenseProduct::Akamai),
            false,
        ));
        assert!(!is_candidate_fingerprint_hint(
            Some(DefenseProduct::Cloudflare),
            None,
            true,
        ));
        assert!(!is_candidate_fingerprint_hint(
            Some(DefenseProduct::Cloudflare),
            Some(DefenseProduct::Cloudflare),
            true,
        ));
    }

    #[test]
    fn transitions_are_same_case_passive_to_active_and_positive_only() {
        let subject = EntityId::new("endpoint:https://example.test/").unwrap();
        let case = test_case("case:test:defense:one", &subject);
        let control = test_observation(
            case.clone(),
            DecisionExecutionStage::Passive,
            projected_state(200, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/control-open",
        );
        let blocked = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(403, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-blocked",
        );
        let transition = transition_for(control.clone(), blocked.clone()).unwrap();
        assert!(transition.candidate_block_status_appeared());
        assert!(transition.suppression_newly_blocking);

        let rate_limited = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, true, None),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            false,
            "defense/candidate-rate-limited",
        );
        assert!(transition_for(control.clone(), rate_limited)
            .unwrap()
            .newly_rate_limited());

        let new_hint = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, false, Some(hint(DefenseProduct::AwsWaf))),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            false,
            "defense/candidate-new-hint",
        );
        assert!(transition_for(control.clone(), new_hint).is_some());

        let incomplete_control = test_observation(
            case.clone(),
            DecisionExecutionStage::Passive,
            projected_state(200, false, None),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            true,
            "defense/control-incomplete",
        );
        let incomplete_new_hint = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, false, Some(hint(DefenseProduct::AwsWaf))),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            false,
            "defense/candidate-incomplete-new-hint",
        );
        assert!(transition_for(incomplete_control.clone(), incomplete_new_hint).is_none());

        let incomplete_block = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(403, false, None),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            false,
            "defense/candidate-incomplete-block",
        );
        let transition = transition_for(incomplete_control, incomplete_block).unwrap();
        assert!(transition.candidate_block_status_appeared());
        assert!(!transition.suppression_newly_blocking);

        let changed_hint_control = test_observation(
            case.clone(),
            DecisionExecutionStage::Passive,
            projected_state(200, false, Some(hint(DefenseProduct::AwsWaf))),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            true,
            "defense/control-hint-a",
        );
        let changed_hint_candidate = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, false, Some(hint(DefenseProduct::Cloudflare))),
            AssessmentDefenseBodyCoverage::MetadataOnly,
            true,
            "defense/candidate-hint-b",
        );
        assert!(transition_for(changed_hint_control.clone(), changed_hint_candidate).is_some());

        let disappeared_hint = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-hint-disappeared",
        );
        assert!(transition_for(changed_hint_control.clone(), disappeared_hint).is_none());

        let unchanged_hint = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, false, Some(hint(DefenseProduct::AwsWaf))),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-hint-unchanged",
        );
        assert!(transition_for(changed_hint_control, unchanged_hint).is_none());

        let unchanged = test_observation(
            case.clone(),
            DecisionExecutionStage::Active,
            projected_state(200, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-open",
        );
        assert!(transition_for(control.clone(), unchanged).is_none());

        let other_case = test_observation(
            test_case("case:test:defense:other", &subject),
            DecisionExecutionStage::Active,
            projected_state(403, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-other-case",
        );
        assert!(transition_for(control.clone(), other_case).is_none());

        let other_subject = EntityId::new("endpoint:https://other.example.test/").unwrap();
        let cross_subject = test_observation(
            test_case("case:test:defense:one", &other_subject),
            DecisionExecutionStage::Active,
            projected_state(403, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-other-subject",
        );
        assert!(transition_for(control.clone(), cross_subject).is_none());

        let passive_candidate = test_observation(
            case.clone(),
            DecisionExecutionStage::Passive,
            projected_state(403, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/candidate-passive",
        );
        assert!(transition_for(control.clone(), passive_candidate).is_none());

        let active_control = test_observation(
            case,
            DecisionExecutionStage::Active,
            projected_state(200, false, None),
            AssessmentDefenseBodyCoverage::CompleteUtf8Prefix,
            false,
            "defense/control-active",
        );
        assert!(transition_for(active_control, blocked).is_none());
    }
}
