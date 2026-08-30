use std::collections::BTreeMap;

use crate::knowledge::{KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot};

use crate::rules::{
    evaluation::{evaluate_rule, RuleApplication, RuleEvaluation},
    registry::{ReasoningRule, RuleWrite},
    RuleEngineError,
};

const MAX_STALE_SNAPSHOT_RETRIES: u8 = 3;
pub(super) const MAX_REASONING_APPLY_ATTEMPTS: u8 = MAX_STALE_SNAPSHOT_RETRIES + 1;

/// Deterministic registry and evaluator for declarative reasoning rules.
///
/// Rules are always evaluated in stable rule-ID order against one shared
/// snapshot. Conclusions are written only after every rule has been evaluated,
/// preventing earlier rules from changing later conditions in the same cycle.
#[derive(Debug, Clone, Default)]
pub struct RuleEngine {
    rules: BTreeMap<String, ReasoningRule>,
}

impl RuleEngine {
    /// Creates an empty engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an idempotent rule definition.
    pub fn register(&mut self, rule: ReasoningRule) -> Result<RuleWrite, RuleEngineError> {
        if let Some(existing) = self.rules.get(rule.id()) {
            return if existing == &rule {
                Ok(RuleWrite::Unchanged)
            } else {
                Err(RuleEngineError::RuleIdentityConflict {
                    id: rule.id().to_owned(),
                })
            };
        }
        self.rules.insert(rule.id().to_owned(), rule);
        Ok(RuleWrite::Inserted)
    }

    /// Returns the number of registered rule identities.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether no rules are registered.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluates all rules without mutating the knowledge base.
    pub fn evaluate(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
    ) -> Result<Vec<RuleEvaluation>, RuleEngineError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        self.evaluate_snapshot(&snapshot)
    }

    /// Evaluates all rules against one immutable snapshot.
    pub fn evaluate_snapshot(
        &self,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<Vec<RuleEvaluation>, RuleEngineError> {
        self.rules
            .values()
            .map(|rule| evaluate_rule(rule, snapshot))
            .collect()
    }

    /// Evaluates one decision cycle and atomically writes matched hypotheses.
    ///
    /// All rules first evaluate in stable rule-ID order against one immutable
    /// snapshot. Every matched hypothesis is then preflighted and committed in
    /// one knowledge-base write transaction, so one late identity conflict
    /// cannot leave earlier conclusions stored. Existing verifier-owned
    /// `Confirmed` and `Rejected` states are preserved under that same write
    /// lock, so a concurrent reasoning pass cannot reverse a verification result.
    pub fn apply(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
    ) -> Result<Vec<RuleApplication>, RuleEngineError> {
        self.apply_with_before_commit(knowledge, subject, |_, _| {})
    }

    pub(super) fn apply_with_before_commit<F>(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
        mut before_commit: F,
    ) -> Result<Vec<RuleApplication>, RuleEngineError>
    where
        F: FnMut(u8, &KnowledgeSnapshot),
    {
        for attempt in 1..=MAX_REASONING_APPLY_ATTEMPTS {
            let snapshot = knowledge.snapshot_for_subject(subject);
            let evaluations = self.evaluate_snapshot(&snapshot)?;
            let hypotheses = evaluations
                .iter()
                .filter_map(|evaluation| evaluation.hypothesis().cloned())
                .collect();
            before_commit(attempt, &snapshot);

            let writes = match knowledge.upsert_reasoning_hypothesis_batch(&snapshot, hypotheses) {
                Ok(writes) => writes,
                Err(KnowledgeBaseError::StaleSnapshot { .. })
                    if attempt < MAX_REASONING_APPLY_ATTEMPTS =>
                {
                    continue;
                },
                Err(KnowledgeBaseError::StaleSnapshot { .. }) => {
                    return Err(RuleEngineError::StaleSnapshotRetriesExhausted {
                        attempts: attempt,
                    });
                },
                Err(error) => return Err(error.into()),
            };

            let mut writes = writes.into_iter().peekable();
            let applications = evaluations
                .into_iter()
                .map(|evaluation| {
                    let write = evaluation.hypothesis().map(|_| {
                        writes
                            .next()
                            .expect("matched hypotheses and writes stay aligned")
                    });
                    RuleApplication { evaluation, write }
                })
                .collect();
            debug_assert!(writes.peek().is_none());
            return Ok(applications);
        }

        unreachable!("bounded reasoning attempts always return or retry")
    }
}
