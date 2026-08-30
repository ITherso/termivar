//! Deterministic executor registration and action routing.

use super::*;

/// Deterministic executor lookup used by the decision runner.
#[derive(Clone, Default)]
pub struct DecisionExecutorRegistry {
    executors: BTreeMap<String, Arc<dyn DecisionActionExecutor>>,
    routes: BTreeMap<(DecisionExecutionStage, String), String>,
}

impl DecisionExecutorRegistry {
    /// Creates an empty executor registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one executor identity.
    pub fn register(
        &mut self,
        executor: Arc<dyn DecisionActionExecutor>,
    ) -> Result<(), DecisionRunnerError> {
        let id = non_empty(executor.id(), "executor id")?;
        if self.executors.contains_key(&id) {
            return Err(DecisionRunnerError::ExecutorIdentityConflict { executor_id: id });
        }
        self.executors.insert(id, executor);
        Ok(())
    }

    /// Routes an action to an executor when the command does not name one.
    ///
    /// Active probes and explicitly host-owned low-level commands may carry
    /// only an action ID. Separate stage routes allow the explicit probe to use
    /// a stricter executor than the original passive action; high-level
    /// adaptive and retry commands pin the planner-authorized executor.
    pub fn route_action(
        &mut self,
        stage: DecisionExecutionStage,
        action_id: impl Into<String>,
        executor_id: impl Into<String>,
    ) -> Result<(), DecisionRunnerError> {
        let action_id = non_empty(action_id, "action id")?;
        let executor_id = non_empty(executor_id, "executor id")?;
        if !self.executors.contains_key(&executor_id) {
            return Err(DecisionRunnerError::UnknownExecutor { executor_id });
        }

        let key = (stage, action_id.clone());
        if let Some(existing) = self.routes.get(&key) {
            return if existing == &executor_id {
                Ok(())
            } else {
                Err(DecisionRunnerError::ActionRouteConflict { stage, action_id })
            };
        }
        self.routes.insert(key, executor_id);
        Ok(())
    }

    /// Returns whether an executor identity is registered.
    pub fn contains(&self, executor_id: &str) -> bool {
        self.executors.contains_key(executor_id)
    }

    /// Returns the number of registered executors.
    pub fn len(&self) -> usize {
        self.executors.len()
    }

    /// Returns whether the registry contains no executors.
    pub fn is_empty(&self) -> bool {
        self.executors.is_empty()
    }

    pub(super) fn resolve(
        &self,
        stage: DecisionExecutionStage,
        action_id: &str,
        requested_executor: Option<&str>,
    ) -> Result<(String, Arc<dyn DecisionActionExecutor>), DecisionRunnerError> {
        let executor_id = if let Some(requested) = requested_executor {
            non_empty(requested, "executor id")?
        } else {
            self.routes
                .get(&(stage, action_id.to_owned()))
                .cloned()
                .ok_or_else(|| DecisionRunnerError::MissingActionRoute {
                    stage,
                    action_id: action_id.to_owned(),
                })?
        };
        let executor = self.executors.get(&executor_id).cloned().ok_or_else(|| {
            DecisionRunnerError::UnknownExecutor {
                executor_id: executor_id.clone(),
            }
        })?;
        Ok((executor_id, executor))
    }
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, DecisionRunnerError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(DecisionRunnerError::EmptyValue { field });
    }
    Ok(value)
}
