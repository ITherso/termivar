//! Projection of observed defense state into provenance-carrying evidence.
//!
//! This adapter reuses the existing observation contracts — [`DefenseState`],
//! [`DefenseTransition`], and the fingerprint types — and projects them into
//! immutable [`venom_core::Evidence`] records that a knowledge store can retain
//! with full provenance. It is deliberately projection-only:
//!
//! - it produces **evidence** (observations), never a [`venom_core::Fact`] or
//!   hypothesis, so a single block never becomes a "confirmed WAF" claim;
//! - it derives from an actual response only — a timeout or connection failure
//!   has no [`DefenseState`], so it is never learned as a defense signal;
//! - it selects no payload, issues no request, and reads no clock or randomness:
//!   identity and timestamp come from the caller's context, so the projection is
//!   a pure, deterministic, idempotent function of its inputs.
//!
//! Callers ingest the result through the existing
//! `KnowledgeBase::insert_evidence_batch`; this module does not touch the store,
//! the planner, the executor, or any runtime configuration.

use venom_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate, ReasoningModelError,
};

use super::fingerprint::{DefenseProduct, FingerprintConfidence};
use super::state::{DefensePosture, DefenseState};
use super::transition::{DefenseTransition, DefenseTransitionKind};

/// Broad category recorded for every projected defense observation.
const DEFENSE_EVIDENCE_CATEGORY: &str = "defense";

/// Reliability of a direct, unambiguous response observation (status, challenge,
/// rate limit, posture, transition). This is the reliability of the observation
/// itself, not a claim that a WAF exists.
const DIRECT_OBSERVATION_PERCENT: u8 = 90;

/// The outcome of one execution turn, from the projection's point of view.
///
/// Only an actual response carries a [`DefenseState`]. Transport failures,
/// timeouts, and connection errors are [`ObservedOutcome::NoResponse`] and yield
/// no defense evidence, so they can never be learned as a defensive signal.
#[derive(Debug, Clone, Copy)]
pub enum ObservedOutcome<'state> {
    /// A response was received and observed into a defense state.
    Response(&'state DefenseState),
    /// No response was received (timeout, connection failure, not applicable).
    NoResponse,
}

/// Immutable provenance a projected defense observation is stamped with.
///
/// Every emitted evidence record carries the producer, the resource it concerns,
/// the action/case correlation, and — folded into a deterministic evidence id —
/// the observation sequence and the supporting response receipt. Supplying the
/// timestamp keeps the projection deterministic and idempotent.
#[derive(Debug, Clone)]
pub struct DefenseObservationContext {
    producer_id: String,
    resource: EntityId,
    correlation_id: String,
    sequence: u64,
    response_receipt: String,
    observed_at_ms: u64,
}

impl DefenseObservationContext {
    /// Creates a validated observation context.
    ///
    /// `producer_id`, `correlation_id`, and `response_receipt` must be non-empty.
    pub fn new(
        producer_id: impl Into<String>,
        resource: EntityId,
        correlation_id: impl Into<String>,
        sequence: u64,
        response_receipt: impl Into<String>,
        observed_at_ms: u64,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            producer_id: non_empty(producer_id, "defense producer id")?,
            resource,
            correlation_id: non_empty(correlation_id, "defense correlation id")?,
            sequence,
            response_receipt: non_empty(response_receipt, "defense response receipt")?,
            observed_at_ms,
        })
    }

    /// Returns the producing component identity.
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    /// Returns the resource this observation concerns.
    pub fn resource(&self) -> &EntityId {
        &self.resource
    }

    /// Returns the action/case correlation identity.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Returns the monotonic observation sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the supporting response receipt reference.
    pub fn response_receipt(&self) -> &str {
        &self.response_receipt
    }

    /// Returns the observation timestamp in Unix milliseconds.
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
}

/// Projects one execution outcome into defense evidence.
///
/// A [`ObservedOutcome::NoResponse`] yields an empty vector: a non-response is
/// never learned as a defensive signal.
pub fn project_outcome(
    outcome: ObservedOutcome<'_>,
    ctx: &DefenseObservationContext,
) -> Vec<Evidence> {
    match outcome {
        ObservedOutcome::Response(state) => project_defense_state(state, ctx),
        ObservedOutcome::NoResponse => Vec::new(),
    }
}

/// Projects one observed defense state into provenance-carrying evidence.
///
/// Always records the posture. Records specific signals (block, challenge, rate
/// limit) only when observed, and a product fingerprint only when one matched —
/// so a bare block never yields a product claim. Every record is an observation;
/// none is a confirmed fact.
pub fn project_defense_state(
    state: &DefenseState,
    ctx: &DefenseObservationContext,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    evidence.push(observation(
        ctx,
        "defense.posture",
        posture_slug(state.posture()),
        "defense-posture",
        direct_reliability(),
    ));

    if state.status_signal().is_block() {
        evidence.push(observation(
            ctx,
            "defense.status",
            "blocked",
            "defense-status",
            direct_reliability(),
        ));
    }

    if state.is_challenged() {
        evidence.push(observation(
            ctx,
            "defense.challenge",
            "present",
            "defense-challenge",
            direct_reliability(),
        ));
    }

    if state.is_rate_limited() {
        evidence.push(observation(
            ctx,
            "defense.rate_limit",
            "observed",
            "defense-rate-limit",
            direct_reliability(),
        ));
    }

    if let Some(print) = state.fingerprint() {
        evidence.push(observation(
            ctx,
            "defense.fingerprint",
            product_slug(print.product()),
            "defense-fingerprint",
            fingerprint_reliability(print.confidence()),
        ));
    }

    evidence
}

/// Projects one control-to-candidate transition into defense evidence.
pub fn project_defense_transition(
    transition: &DefenseTransition,
    ctx: &DefenseObservationContext,
) -> Vec<Evidence> {
    let mut evidence = vec![observation(
        ctx,
        "defense.transition",
        transition_kind_slug(transition.kind()),
        "defense-transition",
        direct_reliability(),
    )];

    if transition.is_newly_blocking() {
        evidence.push(observation(
            ctx,
            "defense.transition",
            "newly_blocking",
            "defense-transition",
            direct_reliability(),
        ));
    }
    if transition.is_newly_rate_limited() {
        evidence.push(observation(
            ctx,
            "defense.transition",
            "newly_rate_limited",
            "defense-transition",
            direct_reliability(),
        ));
    }
    if transition.fingerprint_changed() {
        evidence.push(observation(
            ctx,
            "defense.transition",
            "fingerprint_changed",
            "defense-transition",
            direct_reliability(),
        ));
    }

    evidence
}

fn observation(
    ctx: &DefenseObservationContext,
    namespace: &str,
    name: &str,
    method: &str,
    reliability: ConfidenceScore,
) -> Evidence {
    let predicate = KnowledgePredicate::new(namespace, name)
        .expect("defense predicate components are non-empty");
    let source = EvidenceSource::new(ctx.producer_id.clone(), method)
        .expect("defense producer id and method are non-empty")
        .with_correlation_id(ctx.correlation_id.clone())
        .expect("defense correlation id is non-empty");
    let id = EvidenceId::parse(format!(
        "{DEFENSE_EVIDENCE_CATEGORY}/{}/{}/{}.{}/{}/{}",
        ctx.producer_id,
        ctx.resource.as_str(),
        namespace,
        name,
        ctx.sequence,
        ctx.response_receipt,
    ))
    .expect("defense evidence id is non-empty");

    Evidence::with_id_at(
        id,
        ctx.resource.clone(),
        EvidenceKind::Custom(DEFENSE_EVIDENCE_CATEGORY.to_owned()),
        predicate,
        EvidenceValue::Boolean(true),
        source,
        reliability,
        ctx.observed_at_ms,
    )
}

fn direct_reliability() -> ConfidenceScore {
    ConfidenceScore::from_percent(DIRECT_OBSERVATION_PERCENT)
        .expect("direct observation reliability is in range")
}

fn fingerprint_reliability(confidence: FingerprintConfidence) -> ConfidenceScore {
    let percent = match confidence {
        FingerprintConfidence::Weak => 30,
        FingerprintConfidence::Probable => 60,
        FingerprintConfidence::Strong => 90,
    };
    ConfidenceScore::from_percent(percent).expect("fingerprint reliability is in range")
}

const fn posture_slug(posture: DefensePosture) -> &'static str {
    match posture {
        DefensePosture::Open => "open",
        DefensePosture::Suspected => "suspected",
        DefensePosture::Blocking => "blocking",
    }
}

const fn transition_kind_slug(kind: DefenseTransitionKind) -> &'static str {
    match kind {
        DefenseTransitionKind::NoChange => "unchanged",
        DefenseTransitionKind::DefenseEngaged => "engaged",
        DefenseTransitionKind::DefenseRelaxed => "relaxed",
        DefenseTransitionKind::DefenseReconfigured => "reconfigured",
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

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, ReasoningModelError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(ReasoningModelError::EmptyValue { field });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> EntityId {
        EntityId::new("endpoint:https://example.test/app").unwrap()
    }

    fn context(sequence: u64) -> DefenseObservationContext {
        DefenseObservationContext::new(
            "runtime.defense-projection",
            resource(),
            "case:web:1",
            sequence,
            "receipt:sha256:abc",
            1_700_000_000_000,
        )
        .unwrap()
    }

    fn dotted(evidence: &[Evidence]) -> Vec<String> {
        evidence
            .iter()
            .map(|item| item.predicate().dotted())
            .collect()
    }

    #[test]
    fn every_projected_record_carries_full_provenance() {
        let state = DefenseState::observe(403, &[("CF-RAY", "abc")], "access denied");
        let ctx = context(7);
        let evidence = project_defense_state(&state, &ctx);

        assert!(!evidence.is_empty());
        for item in &evidence {
            assert_eq!(item.source().component(), "runtime.defense-projection");
            assert_eq!(item.subject(), &resource());
            assert_eq!(item.source().correlation_id(), Some("case:web:1"));
            assert_eq!(item.observed_at_ms(), 1_700_000_000_000);
            assert_eq!(item.kind(), &EvidenceKind::Custom("defense".to_owned()));
            // The observation sequence and response receipt are folded into the
            // deterministic evidence id for traceability.
            assert!(item.id().as_str().contains("/7/receipt:sha256:abc"));
        }
    }

    #[test]
    fn a_fingerprinted_block_projects_status_posture_and_product() {
        let state = DefenseState::observe(
            403,
            &[("Server", "cloudflare"), ("CF-RAY", "x")],
            "Attention Required!",
        );
        let names = dotted(&project_defense_state(&state, &context(1)));
        assert!(names.contains(&"defense.posture.blocking".to_owned()));
        assert!(names.contains(&"defense.status.blocked".to_owned()));
        assert!(names.contains(&"defense.challenge.present".to_owned()));
        assert!(names.contains(&"defense.fingerprint.cloudflare".to_owned()));
    }

    #[test]
    fn single_403_does_not_create_a_confirmed_waf_fact() {
        // A bare 403 with no product tells: no fingerprint is claimed, and the
        // projection only ever produces observations (Evidence), never a Fact.
        let state = DefenseState::observe(403, &[], "forbidden");
        let evidence = project_defense_state(&state, &context(1));
        let names = dotted(&evidence);

        assert!(names.contains(&"defense.status.blocked".to_owned()));
        assert!(
            !evidence
                .iter()
                .any(|item| item.predicate().namespace() == "defense.fingerprint"),
            "a bare 403 must not fingerprint a product"
        );
        // No record asserts a WAF exists; every record is a status/posture
        // observation, and the block reliability is not maximal certainty.
        assert!(evidence
            .iter()
            .all(|item| item.reliability() < ConfidenceScore::MAX));
    }

    #[test]
    fn timeouts_and_connection_failures_are_not_learned_as_defense() {
        // A non-response has no defense state, so nothing is projected.
        assert!(project_outcome(ObservedOutcome::NoResponse, &context(1)).is_empty());
    }

    #[test]
    fn an_open_response_still_records_a_posture_observation() {
        let state = DefenseState::observe(200, &[("Server", "nginx")], "ok");
        let names = dotted(&project_defense_state(&state, &context(1)));
        assert_eq!(names, vec!["defense.posture.open".to_owned()]);
    }

    #[test]
    fn a_rate_limit_projects_observed_without_a_block() {
        let state = DefenseState::observe(429, &[], "slow down");
        let names = dotted(&project_defense_state(&state, &context(1)));
        assert!(names.contains(&"defense.rate_limit.observed".to_owned()));
        assert!(!names.contains(&"defense.status.blocked".to_owned()));
    }

    #[test]
    fn fingerprint_confidence_is_carried_as_reliability() {
        // A weak Amazon request-id signal keeps a low reliability.
        let state = DefenseState::observe(200, &[("x-amzn-requestid", "id")], "ok");
        let evidence = project_defense_state(&state, &context(1));
        let fingerprint = evidence
            .iter()
            .find(|item| item.predicate().namespace() == "defense.fingerprint")
            .expect("aws fingerprint present");
        assert_eq!(
            fingerprint.reliability(),
            ConfidenceScore::from_percent(30).unwrap()
        );
    }

    #[test]
    fn projection_is_deterministic_and_idempotent() {
        let state = DefenseState::observe(403, &[("CF-RAY", "x")], "access denied");
        let ctx = context(3);
        assert_eq!(
            project_defense_state(&state, &ctx),
            project_defense_state(&state, &ctx)
        );
    }

    #[test]
    fn transition_projects_typed_kind_and_flags() {
        let control = DefenseState::observe(200, &[], "ok");
        let candidate = DefenseState::observe(403, &[("CF-RAY", "x")], "access denied");
        let transition = DefenseTransition::between(&control, &candidate);
        let names = dotted(&project_defense_transition(&transition, &context(2)));
        assert!(names.contains(&"defense.transition.engaged".to_owned()));
        assert!(names.contains(&"defense.transition.newly_blocking".to_owned()));
    }

    #[test]
    fn context_rejects_empty_provenance() {
        assert!(DefenseObservationContext::new("", resource(), "case:1", 1, "receipt", 0).is_err());
    }
}
