//! Resource envelope for host-facing decision runtimes.
//!
//! These contracts deliberately live above planning, reasoning, verification,
//! and experience. Domain layers describe what should happen; the runtime owns
//! whether another side effect is still permitted.

use std::{collections::BTreeMap, fmt, time::Duration};

use serde::{Deserialize, Serialize};

/// Default maximum number of HTTP requests in one runtime session.
pub const DEFAULT_MAX_TOTAL_REQUESTS: u32 = 32;
/// Default wall-clock deadline in milliseconds.
pub const DEFAULT_MAX_WALL_TIME_MS: u64 = 120_000;
/// Default cumulative number of buffered response-body bytes.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
/// Default maximum number of active verification requests.
pub const DEFAULT_MAX_ACTIVE_VERIFICATIONS: u16 = 4;
/// Default maximum attempts for one semantic action.
pub const DEFAULT_MAX_SAME_ACTION_ATTEMPTS: u16 = 3;
/// Default maximum consecutive completed turns without semantic progress.
pub const DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS: u16 = 4;

/// Multi-dimensional resource envelope for one runtime session.
///
/// Zero is a valid fail-closed value for every dimension. For example,
/// `max_total_requests == 0` prevents even bootstrap I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeBudget {
    max_total_requests: u32,
    max_wall_time_ms: u64,
    max_response_bytes: u64,
    max_active_verifications: u16,
    max_same_action_attempts: u16,
    max_consecutive_no_progress_turns: u16,
}

impl RuntimeBudget {
    /// Creates an explicit resource envelope.
    pub const fn new(
        max_total_requests: u32,
        max_wall_time_ms: u64,
        max_response_bytes: u64,
        max_active_verifications: u16,
        max_same_action_attempts: u16,
        max_consecutive_no_progress_turns: u16,
    ) -> Self {
        Self {
            max_total_requests,
            max_wall_time_ms,
            max_response_bytes,
            max_active_verifications,
            max_same_action_attempts,
            max_consecutive_no_progress_turns,
        }
    }

    /// Returns the maximum number of requests, including bootstrap and retries.
    pub const fn max_total_requests(self) -> u32 {
        self.max_total_requests
    }

    /// Returns the monotonic wall-clock limit.
    pub const fn max_wall_time(self) -> Duration {
        Duration::from_millis(self.max_wall_time_ms)
    }

    /// Returns the serialized wall-clock limit in milliseconds.
    pub const fn max_wall_time_ms(self) -> u64 {
        self.max_wall_time_ms
    }

    /// Returns the cumulative buffered response-body byte limit.
    pub const fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }

    /// Returns the maximum number of active verification requests.
    pub const fn max_active_verifications(self) -> u16 {
        self.max_active_verifications
    }

    /// Returns the maximum number of attempts for one semantic action.
    pub const fn max_same_action_attempts(self) -> u16 {
        self.max_same_action_attempts
    }

    /// Returns the maximum consecutive completed no-progress turns.
    pub const fn max_consecutive_no_progress_turns(self) -> u16 {
        self.max_consecutive_no_progress_turns
    }

    /// Replaces the total-request limit.
    pub const fn with_max_total_requests(mut self, limit: u32) -> Self {
        self.max_total_requests = limit;
        self
    }

    /// Replaces the wall-clock limit, saturating at the wire representation.
    pub fn with_max_wall_time(mut self, limit: Duration) -> Self {
        let millis = limit.as_millis();
        let rounded = if limit.is_zero() { 0 } else { millis.max(1) };
        self.max_wall_time_ms = u64::try_from(rounded).unwrap_or(u64::MAX);
        self
    }

    /// Replaces the cumulative buffered response-body byte limit.
    pub const fn with_max_response_bytes(mut self, limit: u64) -> Self {
        self.max_response_bytes = limit;
        self
    }

    /// Replaces the active-verification request limit.
    pub const fn with_max_active_verifications(mut self, limit: u16) -> Self {
        self.max_active_verifications = limit;
        self
    }

    /// Replaces the per-action attempt limit.
    pub const fn with_max_same_action_attempts(mut self, limit: u16) -> Self {
        self.max_same_action_attempts = limit;
        self
    }

    /// Replaces the consecutive no-progress turn limit.
    pub const fn with_max_consecutive_no_progress_turns(mut self, limit: u16) -> Self {
        self.max_consecutive_no_progress_turns = limit;
        self
    }
}

impl Default for RuntimeBudget {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_TOTAL_REQUESTS,
            DEFAULT_MAX_WALL_TIME_MS,
            DEFAULT_MAX_RESPONSE_BYTES,
            DEFAULT_MAX_ACTIVE_VERIFICATIONS,
            DEFAULT_MAX_SAME_ACTION_ATTEMPTS,
            DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS,
        )
    }
}

/// Resource dimension that stopped a runtime before its next side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuntimeBudgetDimension {
    /// Total bootstrap, passive, active, adaptive, and retry requests.
    TotalRequests,
    /// Monotonic time spent by the complete runtime.
    WallTime,
    /// Cumulative response-body bytes buffered into evidence.
    ResponseBytes,
    /// Total explicit active-verification requests.
    ActiveVerifications,
    /// Attempts made for one semantic action identity.
    SameActionAttempts,
    /// Consecutive completed execution turns without semantic progress.
    ConsecutiveNoProgressTurns,
}

impl fmt::Display for RuntimeBudgetDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TotalRequests => "total_requests",
            Self::WallTime => "wall_time_ms",
            Self::ResponseBytes => "response_bytes",
            Self::ActiveVerifications => "active_verifications",
            Self::SameActionAttempts => "same_action_attempts",
            Self::ConsecutiveNoProgressTurns => "consecutive_no_progress_turns",
        })
    }
}

/// Structured explanation of a fail-closed runtime stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeLimitExceeded {
    dimension: RuntimeBudgetDimension,
    limit: u64,
    observed: u64,
    action_id: Option<String>,
}

impl RuntimeLimitExceeded {
    /// Creates a limit record for the attempted operation.
    pub(crate) fn new(
        dimension: RuntimeBudgetDimension,
        limit: u64,
        observed: u64,
        action_id: Option<String>,
    ) -> Self {
        Self {
            dimension,
            limit,
            observed,
            action_id,
        }
    }

    /// Returns the exhausted resource dimension.
    pub const fn dimension(&self) -> RuntimeBudgetDimension {
        self.dimension
    }

    /// Returns the configured maximum.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns the measured or next-attempt value that reached the guard.
    pub const fn observed(&self) -> u64 {
        self.observed
    }

    /// Returns the affected semantic action for an action-scoped limit.
    pub fn action_id(&self) -> Option<&str> {
        self.action_id.as_deref()
    }
}

impl fmt::Display for RuntimeLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runtime {} limit {} reached by {}",
            self.dimension, self.limit, self.observed
        )?;
        if let Some(action_id) = &self.action_id {
            write!(formatter, " for action {action_id}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RuntimeLimitExceeded {}

/// Monotonic, output-only resource accounting for a runtime session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RuntimeUsage {
    total_requests: u32,
    passive_requests: u32,
    active_verifications: u16,
    bootstrap_requests: u32,
    planned_requests: u32,
    adaptive_requests: u32,
    retry_requests: u32,
    response_bytes: u64,
    completed_execution_turns: u32,
    consecutive_no_progress_turns: u16,
    same_action_attempts: BTreeMap<String, u16>,
    elapsed_ms: u64,
}

impl RuntimeUsage {
    /// Returns all reserved HTTP request attempts.
    ///
    /// Reservation happens before an optional scheduler delay, so a wall-time
    /// cancellation during that delay still consumes the attempt.
    pub const fn total_requests(&self) -> u32 {
        self.total_requests
    }

    /// Returns passive requests, including bootstrap, planned, adaptive, and retries.
    pub const fn passive_requests(&self) -> u32 {
        self.passive_requests
    }

    /// Returns explicit active-verification requests.
    pub const fn active_verifications(&self) -> u16 {
        self.active_verifications
    }

    /// Returns bootstrap request attempts.
    pub const fn bootstrap_requests(&self) -> u32 {
        self.bootstrap_requests
    }

    /// Returns planner-originated request attempts.
    pub const fn planned_requests(&self) -> u32 {
        self.planned_requests
    }

    /// Returns adaptation-originated request attempts.
    pub const fn adaptive_requests(&self) -> u32 {
        self.adaptive_requests
    }

    /// Returns retry request attempts.
    pub const fn retry_requests(&self) -> u32 {
        self.retry_requests
    }

    /// Returns cumulative response-body bytes committed as evidence.
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    /// Returns completed passive or active execution turns.
    pub const fn completed_execution_turns(&self) -> u32 {
        self.completed_execution_turns
    }

    /// Returns the current consecutive no-progress count.
    pub const fn consecutive_no_progress_turns(&self) -> u16 {
        self.consecutive_no_progress_turns
    }

    /// Returns attempts for one semantic action identity.
    pub fn same_action_attempts(&self, action_id: &str) -> u16 {
        self.same_action_attempts
            .get(action_id)
            .copied()
            .unwrap_or(0)
    }

    /// Returns all action attempt counters in stable action-ID order.
    pub fn action_attempts(&self) -> &BTreeMap<String, u16> {
        &self.same_action_attempts
    }

    /// Returns elapsed runtime wall time.
    pub const fn elapsed(&self) -> Duration {
        Duration::from_millis(self.elapsed_ms)
    }

    /// Returns elapsed runtime wall time in milliseconds.
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    pub(crate) fn reserve_request(
        &mut self,
        action_id: &str,
        stage: crate::DecisionExecutionStage,
        origin: Option<crate::DecisionActionOrigin>,
    ) {
        self.total_requests = self.total_requests.saturating_add(1);
        match stage {
            crate::DecisionExecutionStage::Passive => {
                self.passive_requests = self.passive_requests.saturating_add(1);
                match origin {
                    Some(crate::DecisionActionOrigin::Bootstrap) => {
                        self.bootstrap_requests = self.bootstrap_requests.saturating_add(1);
                    },
                    Some(crate::DecisionActionOrigin::Planned) => {
                        self.planned_requests = self.planned_requests.saturating_add(1);
                    },
                    Some(crate::DecisionActionOrigin::Adaptive) => {
                        self.adaptive_requests = self.adaptive_requests.saturating_add(1);
                    },
                    Some(crate::DecisionActionOrigin::Retry) => {
                        self.retry_requests = self.retry_requests.saturating_add(1);
                    },
                    None => {},
                }
            },
            crate::DecisionExecutionStage::Active => {
                self.active_verifications = self.active_verifications.saturating_add(1);
            },
        }
        let attempts = self
            .same_action_attempts
            .entry(action_id.to_owned())
            .or_default();
        *attempts = attempts.saturating_add(1);
    }

    pub(crate) fn record_response_bytes(&mut self, bytes: u64) {
        self.response_bytes = self.response_bytes.saturating_add(bytes);
    }

    pub(crate) fn record_execution_progress(&mut self, progressed: bool) {
        self.completed_execution_turns = self.completed_execution_turns.saturating_add(1);
        if progressed {
            self.consecutive_no_progress_turns = 0;
        } else {
            self.consecutive_no_progress_turns =
                self.consecutive_no_progress_turns.saturating_add(1);
        }
    }

    pub(crate) fn set_elapsed(&mut self, elapsed: Duration) {
        self.elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_accepts_fail_closed_zero_values_and_round_trips() {
        let budget = RuntimeBudget::default()
            .with_max_total_requests(0)
            .with_max_wall_time(Duration::ZERO)
            .with_max_response_bytes(0)
            .with_max_active_verifications(0)
            .with_max_same_action_attempts(0)
            .with_max_consecutive_no_progress_turns(0);

        let encoded = serde_json::to_string(&budget).unwrap();
        assert_eq!(
            serde_json::from_str::<RuntimeBudget>(&encoded).unwrap(),
            budget
        );
        assert_eq!(budget.max_wall_time(), Duration::ZERO);

        let sub_millisecond =
            RuntimeBudget::default().with_max_wall_time(Duration::from_micros(999));
        assert_eq!(sub_millisecond.max_wall_time(), Duration::from_millis(1));

        let partial: RuntimeBudget = serde_json::from_value(serde_json::json!({
            "max_total_requests": 7
        }))
        .unwrap();
        assert_eq!(partial.max_total_requests(), 7);
        assert_eq!(partial.max_response_bytes(), DEFAULT_MAX_RESPONSE_BYTES);
        assert!(serde_json::from_value::<RuntimeBudget>(serde_json::json!({
            "max_total_requets": 7
        }))
        .is_err());
    }
}
