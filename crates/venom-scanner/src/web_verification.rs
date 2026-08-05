//! Deterministic outcomes for standard web discovery evidence.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Rules are scoped to both a semantic action and the current verification
//! case correlation. This prevents historical responses or another executor's
//! observations from being combined into a new outcome.

use serde::Serialize;
use thiserror::Error;
use venom_core::{
    EvidenceValue, HttpEvidencePredicate, OutcomeStatus, Probability, ReasoningModelError,
    VerificationStage,
};

use crate::{
    rules::{Expression, KnowledgeLayer, RuleEngineError},
    verification::{VerificationError, VerificationPipeline, VerificationRule, VerifierWrite},
    web_actions::{StandardWebActionKind, STANDARD_WEB_DISCOVERY_ACTIONS},
};

/// Number of passive and active rules installed by the standard profile.
pub const STANDARD_WEB_VERIFICATION_RULE_COUNT: usize = 20;

/// Failures while constructing or atomically installing standard web rules.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebVerificationError {
    /// A semantic action has no built-in verification rule mapping.
    #[error("standard web action {action:?} has no built-in verification rules")]
    UnsupportedAction {
        /// Action rejected while the profile was being constructed.
        action: StandardWebActionKind,
    },

    /// A rule used a stage unsupported by this two-stage profile.
    #[error("verification stage {stage:?} is unsupported by the standard web profile")]
    UnsupportedStage {
        /// Stage rejected before the prospective pipeline was committed.
        stage: VerificationStage,
    },

    /// A predicate or probability was invalid.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),

    /// An evidence expression was invalid.
    #[error(transparent)]
    Rule(#[from] RuleEngineError),

    /// A verifier rule or identity conflicted.
    #[error(transparent)]
    Verification(#[from] VerificationError),
}

/// Counts of rules added by an idempotent profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StandardWebVerificationInstallReport {
    passive_rules_inserted: usize,
    active_rules_inserted: usize,
}

impl StandardWebVerificationInstallReport {
    /// Returns the number of newly registered passive rules.
    pub fn passive_rules_inserted(self) -> usize {
        self.passive_rules_inserted
    }

    /// Returns the number of newly registered active rules.
    pub fn active_rules_inserted(self) -> usize {
        self.active_rules_inserted
    }

    /// Returns the total number of newly registered rules.
    pub fn total_rules_inserted(self) -> usize {
        self.passive_rules_inserted + self.active_rules_inserted
    }
}

/// Action- and case-scoped verification rules for standard discovery probes.
///
/// The profile is intentionally conservative: explicit framework/auth markers
/// can succeed, blocking status codes can report `Blocked`, and a Laravel
/// `Allow` header remains `NeedsReview`. Absence alone never creates a false
/// positive outcome.
///
/// # Examples
///
/// ```rust
/// use venom_scanner::{
///     StandardWebVerificationProfile, VerificationPipeline,
///     STANDARD_WEB_VERIFICATION_RULE_COUNT,
/// };
///
/// let profile = StandardWebVerificationProfile::new()?;
/// let mut pipeline = VerificationPipeline::default();
/// let report = profile.install(&mut pipeline)?;
///
/// assert_eq!(report.total_rules_inserted(), STANDARD_WEB_VERIFICATION_RULE_COUNT);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct StandardWebVerificationProfile {
    rules: Vec<VerificationRule>,
}

impl StandardWebVerificationProfile {
    /// Constructs the complete passive/active rule set.
    pub fn new() -> Result<Self, StandardWebVerificationError> {
        let mut rules = Vec::with_capacity(STANDARD_WEB_VERIFICATION_RULE_COUNT);
        for kind in STANDARD_WEB_DISCOVERY_ACTIONS {
            for stage in [VerificationStage::Passive, VerificationStage::Active] {
                rules.push(blocked_rule(kind, stage)?);
                rules.push(signal_rule(kind, stage)?);
            }
        }
        debug_assert_eq!(rules.len(), STANDARD_WEB_VERIFICATION_RULE_COUNT);
        Ok(Self { rules })
    }

    /// Installs all rules atomically and idempotently.
    pub fn install(
        &self,
        pipeline: &mut VerificationPipeline,
    ) -> Result<StandardWebVerificationInstallReport, StandardWebVerificationError> {
        let mut prospective = pipeline.clone();
        let mut report = StandardWebVerificationInstallReport::default();

        for rule in &self.rules {
            let write = match rule.stage() {
                VerificationStage::Passive => prospective.passive_mut().register(rule.clone())?,
                VerificationStage::Active => prospective.active_mut().register(rule.clone())?,
                stage => return Err(StandardWebVerificationError::UnsupportedStage { stage }),
            };
            if matches!(write, VerifierWrite::Inserted) {
                match rule.stage() {
                    VerificationStage::Passive => report.passive_rules_inserted += 1,
                    VerificationStage::Active => report.active_rules_inserted += 1,
                    stage => {
                        return Err(StandardWebVerificationError::UnsupportedStage { stage });
                    },
                }
            }
        }

        *pipeline = prospective;
        Ok(report)
    }

    /// Returns rules in stable action, stage, and purpose order.
    pub fn rules(&self) -> &[VerificationRule] {
        &self.rules
    }
}

fn blocked_rule(
    kind: StandardWebActionKind,
    stage: VerificationStage,
) -> Result<VerificationRule, StandardWebVerificationError> {
    let status = HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge();
    let condition = Expression::any(
        [401_u64, 403, 429]
            .into_iter()
            .map(|value| {
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    status.clone(),
                    EvidenceValue::Unsigned(value),
                )
            })
            .collect(),
    )?;
    scoped_rule(
        format!("web.verify.{}.{}.blocked", stage.as_str(), kind.slug()),
        kind,
        stage,
        800,
        condition,
        OutcomeStatus::Blocked,
        90,
        "The current discovery request was denied or rate limited",
    )
}

fn signal_rule(
    kind: StandardWebActionKind,
    stage: VerificationStage,
) -> Result<VerificationRule, StandardWebVerificationError> {
    let (condition, outcome, priority, confidence, rationale) = match kind {
        StandardWebActionKind::LaravelRouteDiscovery => (
            Expression::exists(
                KnowledgeLayer::Evidence,
                HttpEvidencePredicate::HEADER_ALLOW.into(),
            ),
            OutcomeStatus::NeedsReview,
            600,
            70,
            "The endpoint advertised methods, but this does not independently confirm Laravel",
        ),
        StandardWebActionKind::LivewireComponentDiscovery => (
            Expression::any(
                ["wire:id=", "wire:snapshot="]
                    .into_iter()
                    .map(|marker| {
                        Expression::text_contains_ascii_case_insensitive(
                            KnowledgeLayer::Evidence,
                            HttpEvidencePredicate::RESPONSE_BODY_SAMPLE.into(),
                            marker,
                        )
                    })
                    .collect::<Result<Vec<_>, RuleEngineError>>()?,
            )?,
            OutcomeStatus::Success,
            900,
            97,
            "The bounded response sample contains an explicit Livewire DOM marker",
        ),
        StandardWebActionKind::SanctumAuthBoundary => (
            Expression::all(vec![
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    HttpEvidencePredicate::COOKIE_NAME.into(),
                    EvidenceValue::Text("laravel_session".to_owned()),
                ),
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    HttpEvidencePredicate::COOKIE_NAME.into(),
                    EvidenceValue::Text("XSRF-TOKEN".to_owned()),
                ),
            ])?,
            OutcomeStatus::Success,
            900,
            92,
            "The current response issued both Laravel session and XSRF cookie names",
        ),
        StandardWebActionKind::HttpBasicAuthBoundary => (
            auth_header_condition("Basic")?,
            OutcomeStatus::Success,
            950,
            99,
            "WWW-Authenticate explicitly advertises HTTP Basic for this request",
        ),
        StandardWebActionKind::HttpBearerAuthBoundary => (
            auth_header_condition("Bearer")?,
            OutcomeStatus::Success,
            950,
            99,
            "WWW-Authenticate explicitly advertises HTTP Bearer for this request",
        ),
        StandardWebActionKind::NginxConfiguration
        | StandardWebActionKind::ApacheConfiguration
        | StandardWebActionKind::PhpInputDiscovery
        | StandardWebActionKind::LaravelInputAnalysis => {
            return Err(StandardWebVerificationError::UnsupportedAction { action: kind });
        },
    };
    scoped_rule(
        format!("web.verify.{}.{}.signal", stage.as_str(), kind.slug()),
        kind,
        stage,
        priority,
        condition,
        outcome,
        confidence,
        rationale,
    )
}

fn auth_header_condition(token: &str) -> Result<Expression, RuleEngineError> {
    Expression::text_contains_ascii_case_insensitive(
        KnowledgeLayer::Evidence,
        HttpEvidencePredicate::HEADER_WWW_AUTHENTICATE.into(),
        token,
    )
}

#[allow(clippy::too_many_arguments)]
fn scoped_rule(
    id: String,
    kind: StandardWebActionKind,
    stage: VerificationStage,
    priority: u16,
    condition: Expression,
    outcome: OutcomeStatus,
    confidence: u8,
    rationale: &str,
) -> Result<VerificationRule, StandardWebVerificationError> {
    Ok(VerificationRule::new(
        id,
        stage,
        priority,
        condition,
        outcome,
        Probability::from_percent(confidence)?,
        rationale,
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()?)
}

#[cfg(test)]
mod tests {
    use venom_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, Hypothesis,
        HypothesisState, HypothesisStrength, KnowledgePredicate,
    };

    use super::*;
    use crate::{KnowledgeBase, VerificationCase};

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test/app").unwrap()
    }

    fn case(id: &str, kind: StandardWebActionKind) -> VerificationCase {
        VerificationCase::new(id, subject(), kind.action_id(), "hypothesis:web").unwrap()
    }

    fn knowledge() -> KnowledgeBase {
        let knowledge = KnowledgeBase::new();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:web",
            subject(),
            KnowledgePredicate::new("technology", "candidate").unwrap(),
            EvidenceValue::Text("web".to_owned()),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        hypothesis.set_strength(HypothesisStrength::Weak);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        knowledge
    }

    fn evidence(
        case: &VerificationCase,
        namespace: &str,
        name: &str,
        value: EvidenceValue,
    ) -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new(namespace, name).unwrap(),
            value,
            EvidenceSource::new(
                StandardWebActionKind::HttpBasicAuthBoundary.executor_id(),
                "test-observation",
            )
            .unwrap()
            .with_correlation_id(case.id())
            .unwrap(),
            ConfidenceScore::MAX,
        )
    }

    fn pipeline() -> VerificationPipeline {
        let mut pipeline = VerificationPipeline::default();
        StandardWebVerificationProfile::new()
            .unwrap()
            .install(&mut pipeline)
            .unwrap();
        pipeline
    }

    #[test]
    fn profile_installs_atomically_and_idempotently() {
        let profile = StandardWebVerificationProfile::new().unwrap();
        let mut pipeline = VerificationPipeline::default();

        let first = profile.install(&mut pipeline).unwrap();
        let second = profile.install(&mut pipeline).unwrap();

        assert_eq!(first.passive_rules_inserted(), 10);
        assert_eq!(first.active_rules_inserted(), 10);
        assert_eq!(
            first.total_rules_inserted(),
            STANDARD_WEB_VERIFICATION_RULE_COUNT
        );
        assert_eq!(second, StandardWebVerificationInstallReport::default());
        assert_eq!(pipeline.passive().len(), 10);
        assert_eq!(pipeline.active().len(), 10);
    }

    #[test]
    fn every_discovery_action_has_passive_and_active_verifier_mappings() {
        for kind in STANDARD_WEB_DISCOVERY_ACTIONS {
            for stage in [VerificationStage::Passive, VerificationStage::Active] {
                assert!(
                    blocked_rule(kind, stage).is_ok(),
                    "missing blocked rule for {kind:?}"
                );
                assert!(
                    signal_rule(kind, stage).is_ok(),
                    "missing signal rule for {kind:?}"
                );
            }
        }
    }

    #[test]
    fn actions_without_verifier_mappings_fail_during_construction() {
        for kind in StandardWebActionKind::all()
            .into_iter()
            .filter(|kind| !STANDARD_WEB_DISCOVERY_ACTIONS.contains(kind))
        {
            assert!(matches!(
                signal_rule(kind, VerificationStage::Passive),
                Err(StandardWebVerificationError::UnsupportedAction { action }) if action == kind
            ));
        }
    }

    #[test]
    fn matching_basic_challenge_outranks_the_blocked_status() {
        let kind = StandardWebActionKind::HttpBasicAuthBoundary;
        let case = case("case:basic", kind);
        let knowledge = knowledge();
        knowledge
            .insert_evidence_batch(vec![
                evidence(
                    &case,
                    "http.response",
                    "status",
                    EvidenceValue::Unsigned(401),
                ),
                evidence(
                    &case,
                    "http.header",
                    "www-authenticate",
                    EvidenceValue::Text("Basic realm=\"admin\"".to_owned()),
                ),
            ])
            .unwrap();

        let report = pipeline().passive().verify(&knowledge, &case).unwrap();

        assert_eq!(report.outcome().status(), OutcomeStatus::Success);
        assert_eq!(
            report.outcome().verifier_rule_id(),
            Some("web.verify.passive.http-basic-auth.signal")
        );
    }

    #[test]
    fn action_scope_prevents_basic_evidence_from_confirming_bearer() {
        let basic = case("case:bearer", StandardWebActionKind::HttpBearerAuthBoundary);
        let knowledge = knowledge();
        knowledge
            .insert_evidence_batch(vec![
                evidence(
                    &basic,
                    "http.response",
                    "status",
                    EvidenceValue::Unsigned(401),
                ),
                evidence(
                    &basic,
                    "http.header",
                    "www-authenticate",
                    EvidenceValue::Text("Basic realm=\"admin\"".to_owned()),
                ),
            ])
            .unwrap();

        let report = pipeline().passive().verify(&knowledge, &basic).unwrap();
        let basic_signal = report
            .evaluations()
            .iter()
            .find(|evaluation| evaluation.rule_id().ends_with("http-basic-auth.signal"))
            .unwrap();

        assert!(basic_signal.condition().matched());
        assert!(!basic_signal.action_matched());
        assert!(!basic_signal.eligible());
        assert_eq!(report.outcome().status(), OutcomeStatus::Blocked);
    }

    #[test]
    fn stale_challenge_from_another_case_is_ignored() {
        let kind = StandardWebActionKind::HttpBasicAuthBoundary;
        let current = case("case:current", kind);
        let stale = case("case:stale", kind);
        let knowledge = knowledge();
        knowledge
            .insert_evidence_batch(vec![
                evidence(
                    &current,
                    "http.response",
                    "status",
                    EvidenceValue::Unsigned(200),
                ),
                evidence(
                    &stale,
                    "http.header",
                    "www-authenticate",
                    EvidenceValue::Text("Basic realm=\"old\"".to_owned()),
                ),
            ])
            .unwrap();

        let report = pipeline().passive().verify(&knowledge, &current).unwrap();

        assert_eq!(report.outcome().status(), OutcomeStatus::Unknown);
        assert!(report.outcome().evidence_ids().is_empty());
    }

    #[test]
    fn active_success_requires_a_fresh_livewire_marker() {
        let kind = StandardWebActionKind::LivewireComponentDiscovery;
        let case = case("case:livewire", kind);
        let knowledge = knowledge();
        knowledge
            .insert_evidence(evidence(
                &case,
                "http.response",
                "body-sample",
                EvidenceValue::Text("<div wire:id=\"old\">".to_owned()),
            ))
            .unwrap();
        let baseline = knowledge.snapshot_for_subject(&subject());
        let pipeline = pipeline();

        let stale = pipeline
            .active()
            .verify_snapshots(&case, &baseline, &baseline)
            .unwrap();
        assert_eq!(stale.outcome().status(), OutcomeStatus::Unknown);

        knowledge
            .insert_evidence(evidence(
                &case,
                "http.response",
                "body-sample",
                EvidenceValue::Text("<div wire:snapshot=\"fresh\">".to_owned()),
            ))
            .unwrap();
        let after = knowledge.snapshot_for_subject(&subject());
        let verified = pipeline
            .active()
            .verify_snapshots(&case, &baseline, &after)
            .unwrap();

        assert_eq!(verified.outcome().status(), OutcomeStatus::Success);
        assert_eq!(
            verified
                .evaluations()
                .iter()
                .find(|evaluation| evaluation.selected())
                .unwrap()
                .fresh_evidence_ids()
                .len(),
            1
        );
    }

    #[test]
    fn allow_header_remains_needs_review_and_rate_limit_is_blocked() {
        let route = case("case:route", StandardWebActionKind::LaravelRouteDiscovery);
        let knowledge = knowledge();
        knowledge
            .insert_evidence(evidence(
                &route,
                "http.header",
                "allow",
                EvidenceValue::Text("GET, HEAD, OPTIONS".to_owned()),
            ))
            .unwrap();
        let pipeline = pipeline();
        assert_eq!(
            pipeline
                .passive()
                .verify(&knowledge, &route)
                .unwrap()
                .outcome()
                .status(),
            OutcomeStatus::NeedsReview
        );

        let limited = case(
            "case:limited",
            StandardWebActionKind::LivewireComponentDiscovery,
        );
        knowledge
            .insert_evidence(evidence(
                &limited,
                "http.response",
                "status",
                EvidenceValue::Unsigned(429),
            ))
            .unwrap();
        assert_eq!(
            pipeline
                .passive()
                .verify(&knowledge, &limited)
                .unwrap()
                .outcome()
                .status(),
            OutcomeStatus::Blocked
        );
    }
}
