//! Immutable reasoning, planning, and outcome audit receipts.

use super::*;

/// Reasoning applications committed before a later planning-stage failure.
///
/// This receipt describes one successful in-memory [`RuleEngine::apply`]
/// transaction and its exact [`KnowledgeWrite`] statuses. It does not imply
/// durable persistence. A rule evaluation remains the pre-commit candidate;
/// hosts must query the knowledge base when verifier-owned terminal-state
/// preservation makes the stored hypothesis relevant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionReasoningCommitReceipt {
    pub(super) subject: EntityId,
    pub(super) planner_subject_revision: u64,
    pub(super) planner_ontology_revision: u64,
    pub(super) rule_applications: Vec<RuleApplication>,
}

impl DecisionReasoningCommitReceipt {
    /// Returns the subject whose hypotheses were evaluated and committed.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the subject revision captured by the attempted planner snapshot.
    pub fn planner_subject_revision(&self) -> u64 {
        self.planner_subject_revision
    }

    /// Returns the ontology revision captured by the attempted planner snapshot.
    pub fn planner_ontology_revision(&self) -> u64 {
        self.planner_ontology_revision
    }

    /// Returns deterministic applications and their exact write results.
    pub fn rule_applications(&self) -> &[RuleApplication] {
        &self.rule_applications
    }
}

/// Audit record produced by a reasoning and planning turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionPlanningReport {
    pub(super) rule_applications: Vec<RuleApplication>,
    pub(super) plan: AttackPlan,
    #[serde(skip_serializing)]
    pub(super) policy_authorized_plan: AttackPlan,
    pub(super) suppressed_actions: BTreeSet<String>,
    #[serde(skip_serializing)]
    pub(super) session_transition: DecisionSessionTransition,
    pub(super) command: DecisionLoopCommand,
}

impl DecisionPlanningReport {
    /// Returns deterministic reasoning applications in rule-ID order.
    pub fn rule_applications(&self) -> &[RuleApplication] {
        &self.rule_applications
    }

    /// Returns the complete planner audit record.
    pub fn plan(&self) -> &AttackPlan {
        &self.plan
    }

    pub(crate) fn policy_authorized_plan(&self) -> &AttackPlan {
        &self.policy_authorized_plan
    }

    /// Returns suppressions applied to this planning cycle.
    pub fn suppressed_actions(&self) -> &BTreeSet<String> {
        &self.suppressed_actions
    }

    /// Returns the session transition committed by this successful planning turn.
    ///
    /// This audit summary is intentionally excluded from the existing serialized
    /// planning-report shape.
    pub fn session_transition(&self) -> &DecisionSessionTransition {
        &self.session_transition
    }

    /// Returns the runner command selected for this turn.
    pub fn command(&self) -> &DecisionLoopCommand {
        &self.command
    }
}

/// Audit record produced by a passive or active verification turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionOutcomeReport {
    pub(super) verification: VerificationReport,
    pub(super) adaptive: AdaptiveDecision,
    pub(super) experience_write: ExperienceWrite,
    pub(super) hypothesis_write: Option<KnowledgeWrite>,
    #[serde(skip_serializing)]
    pub(super) session_transition: DecisionSessionTransition,
    pub(super) command: DecisionLoopCommand,
}

impl DecisionOutcomeReport {
    /// Returns the verifier outcome and rule trace.
    pub fn verification(&self) -> &VerificationReport {
        &self.verification
    }

    /// Returns the adaptive policy decision.
    pub fn adaptive(&self) -> &AdaptiveDecision {
        &self.adaptive
    }

    /// Returns whether experience inserted or already knew the outcome.
    pub fn experience_write(&self) -> ExperienceWrite {
        self.experience_write
    }

    /// Returns the verifier-owned hypothesis state write when the outcome is
    /// conclusive and its case authorizes a transition.
    pub fn hypothesis_write(&self) -> Option<KnowledgeWrite> {
        self.hypothesis_write
    }

    /// Returns the session transition applied during successful outcome processing.
    ///
    /// Candidate state makes normal returned-error paths error-atomic. This is
    /// not a cross-store or crash-atomic persistence guarantee.
    pub fn session_transition(&self) -> &DecisionSessionTransition {
        &self.session_transition
    }

    /// Returns the next runner command.
    pub fn command(&self) -> &DecisionLoopCommand {
        &self.command
    }
}
