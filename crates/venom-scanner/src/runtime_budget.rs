//! Resource envelope for host-facing decision runtimes.
//!
//! These contracts deliberately live above planning, reasoning, verification,
//! and experience. Domain layers describe what should happen; the runtime owns
//! whether another side effect is still permitted.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

/// Default maximum number of HTTP requests in one runtime session.
pub const DEFAULT_MAX_TOTAL_REQUESTS: u32 = 32;
/// Default wall-clock deadline in milliseconds.
pub const DEFAULT_MAX_WALL_TIME_MS: u64 = 120_000;
/// Default cumulative transport-delivered response-body threshold.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
/// Default cumulative number of request-body bytes dispatched by the broker.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 256 * 1024;
/// Default maximum number of active verification requests.
pub const DEFAULT_MAX_ACTIVE_VERIFICATIONS: u16 = 4;
/// Default maximum attempts for one semantic action.
pub const DEFAULT_MAX_SAME_ACTION_ATTEMPTS: u16 = 3;
/// Default maximum consecutive completed turns without semantic progress.
pub const DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS: u16 = 4;
/// Maximum dispatch receipts retained by one broker audit.
pub const HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS: usize = 4_096;

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
    max_request_body_bytes: u64,
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
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
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

    /// Returns the cumulative transport-delivered response-body threshold.
    ///
    /// The chunk that crosses this threshold is charged in full and surfaced
    /// as a typed limit; the broker starts no later body read.
    pub const fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }

    /// Returns the cumulative request-body byte limit.
    ///
    /// Headers and transport framing are not included. A body is charged
    /// atomically immediately before its request is dispatched.
    pub const fn max_request_body_bytes(self) -> u64 {
        self.max_request_body_bytes
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

    /// Replaces the cumulative transport-delivered response-body threshold.
    pub const fn with_max_response_bytes(mut self, limit: u64) -> Self {
        self.max_response_bytes = limit;
        self
    }

    /// Replaces the cumulative request-body byte limit.
    pub const fn with_max_request_body_bytes(mut self, limit: u64) -> Self {
        self.max_request_body_bytes = limit;
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
    /// Cumulative response-body bytes delivered by transport, including the
    /// single serialized chunk that can cross the configured threshold.
    ResponseBytes,
    /// Cumulative request-body bytes accepted for transport dispatch.
    RequestBodyBytes,
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
            Self::RequestBodyBytes => "request_body_bytes",
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

/// Terminal transport state for one broker-owned wire dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransportDispatchOutcome {
    /// The response completed within transport and accounting policy.
    Completed,
    /// Request dispatch or response streaming failed at the transport layer.
    TransportFailure,
    /// The broker-owned per-request deadline elapsed.
    RequestTimeout,
    /// A delivered response chunk crossed the session byte boundary.
    ResponseBudgetReached,
    /// The caller dropped the in-flight broker future before classification.
    Cancelled,
}

/// Raw-target-free audit receipt for one broker-owned wire dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransportDispatchReceipt {
    sequence: u64,
    action_id: String,
    stage: crate::DecisionExecutionStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<crate::DecisionActionOrigin>,
    request_body_bytes: u64,
    response_bytes: u64,
    elapsed_ms: u64,
    outcome: TransportDispatchOutcome,
}

impl TransportDispatchReceipt {
    /// Returns the zero-based dispatch order within this broker authority.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the semantic action charged for this dispatch.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns whether this was passive collection or active verification.
    pub const fn stage(&self) -> crate::DecisionExecutionStage {
        self.stage
    }

    /// Returns the passive action origin, when applicable.
    pub const fn origin(&self) -> Option<crate::DecisionActionOrigin> {
        self.origin
    }

    /// Returns buffered request-body bytes charged before dispatch.
    pub const fn request_body_bytes(&self) -> u64 {
        self.request_body_bytes
    }

    /// Returns complete response-body bytes delivered to the collector.
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    /// Returns monotonic elapsed time from lease acquisition to classification.
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    /// Returns the broker-owned terminal transport classification.
    pub const fn outcome(&self) -> TransportDispatchOutcome {
        self.outcome
    }
}

/// Bounded, dispatch-ordered transport audit for one accounting authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TransportDispatchAudit {
    receipts: Vec<TransportDispatchReceipt>,
    omitted_receipt_count: u64,
}

impl TransportDispatchAudit {
    /// Returns retained receipts in original dispatch order.
    pub fn receipts(&self) -> &[TransportDispatchReceipt] {
        &self.receipts
    }

    /// Returns completed dispatch receipts excluded by the hard audit ceiling.
    pub const fn omitted_receipt_count(&self) -> u64 {
        self.omitted_receipt_count
    }

    /// Returns whether no dispatch was recorded or omitted.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty() && self.omitted_receipt_count == 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RequestAccountingSnapshot {
    total_requests: u32,
    passive_requests: u32,
    active_verifications: u16,
    bootstrap_requests: u32,
    planned_requests: u32,
    adaptive_requests: u32,
    retry_requests: u32,
    request_body_bytes: u64,
    response_bytes: u64,
}

impl RequestAccountingSnapshot {
    pub(crate) const fn total_requests(self) -> u32 {
        self.total_requests
    }

    pub(crate) const fn passive_requests(self) -> u32 {
        self.passive_requests
    }

    pub(crate) const fn active_verifications(self) -> u16 {
        self.active_verifications
    }

    pub(crate) const fn bootstrap_requests(self) -> u32 {
        self.bootstrap_requests
    }

    pub(crate) const fn planned_requests(self) -> u32 {
        self.planned_requests
    }

    pub(crate) const fn adaptive_requests(self) -> u32 {
        self.adaptive_requests
    }

    pub(crate) const fn retry_requests(self) -> u32 {
        self.retry_requests
    }

    pub(crate) const fn request_body_bytes(self) -> u64 {
        self.request_body_bytes
    }

    pub(crate) const fn response_bytes(self) -> u64 {
        self.response_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestAccountingPreflight {
    remaining_response_bytes: u64,
}

impl RequestAccountingPreflight {
    pub(crate) const fn remaining_response_bytes(self) -> u64 {
        self.remaining_response_bytes
    }
}

#[derive(Debug, Default)]
struct RequestAccountingState {
    snapshot: RequestAccountingSnapshot,
    next_dispatch_sequence: u64,
    dispatch_receipts: Vec<TransportDispatchReceipt>,
    omitted_dispatch_receipts: u64,
}

/// Shared host-owned authority for logical transport dispatch accounting.
///
/// Clones share one monotonic state. Preflight is advisory and side-effect
/// free; [`Self::try_begin`] repeats every guard under the same state lock that
/// records the dispatch.
#[derive(Debug, Clone)]
pub(crate) struct RequestAccountingBroker {
    budget: RuntimeBudget,
    state: Arc<Mutex<RequestAccountingState>>,
    response_read_gate: Arc<tokio::sync::Mutex<()>>,
}

impl RequestAccountingBroker {
    pub(crate) fn new(budget: RuntimeBudget) -> Self {
        Self {
            budget,
            state: Arc::new(Mutex::new(RequestAccountingState::default())),
            response_read_gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[cfg(test)]
    pub(crate) const fn budget(&self) -> RuntimeBudget {
        self.budget
    }

    pub(crate) fn snapshot(&self) -> RequestAccountingSnapshot {
        self.lock_state().snapshot
    }

    pub(crate) fn dispatch_audit(&self) -> TransportDispatchAudit {
        let state = self.lock_state();
        let mut receipts = state.dispatch_receipts.clone();
        receipts.sort_by_key(TransportDispatchReceipt::sequence);
        TransportDispatchAudit {
            receipts,
            omitted_receipt_count: state.omitted_dispatch_receipts,
        }
    }

    pub(crate) fn preflight(
        &self,
        action_id: &str,
        stage: crate::DecisionExecutionStage,
    ) -> Result<RequestAccountingPreflight, RuntimeLimitExceeded> {
        self.preflight_with_request_body_bytes(action_id, stage, 0)
    }

    pub(crate) fn preflight_with_request_body_bytes(
        &self,
        action_id: &str,
        stage: crate::DecisionExecutionStage,
        request_body_bytes: u64,
    ) -> Result<RequestAccountingPreflight, RuntimeLimitExceeded> {
        check_request_limits(
            &self.lock_state().snapshot,
            self.budget,
            action_id,
            stage,
            request_body_bytes,
        )
    }

    #[cfg(test)]
    pub(crate) fn try_begin(
        &self,
        action_id: &str,
        stage: crate::DecisionExecutionStage,
        origin: Option<crate::DecisionActionOrigin>,
    ) -> Result<RequestAccountingLease, RuntimeLimitExceeded> {
        self.try_begin_with_request_body_bytes(action_id, stage, origin, 0)
    }

    pub(crate) fn try_begin_with_request_body_bytes(
        &self,
        action_id: &str,
        stage: crate::DecisionExecutionStage,
        origin: Option<crate::DecisionActionOrigin>,
        request_body_bytes: u64,
    ) -> Result<RequestAccountingLease, RuntimeLimitExceeded> {
        let mut state = self.lock_state();
        check_request_limits(
            &state.snapshot,
            self.budget,
            action_id,
            stage,
            request_body_bytes,
        )?;
        record_dispatch(&mut state.snapshot, stage, origin, request_body_bytes);
        let sequence = state.next_dispatch_sequence;
        state.next_dispatch_sequence = state.next_dispatch_sequence.saturating_add(1);
        drop(state);

        Ok(RequestAccountingLease {
            broker: self.clone(),
            sequence,
            action_id: action_id.to_owned(),
            stage,
            origin,
            request_body_bytes,
            response_bytes: 0,
            response_budget_reached: false,
            started_at: Instant::now(),
            outcome: None,
        })
    }

    fn record_dispatch_receipt(&self, receipt: TransportDispatchReceipt) {
        let mut state = self.lock_state();
        if state.dispatch_receipts.len() < HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS {
            state.dispatch_receipts.push(receipt);
        } else {
            state.omitted_dispatch_receipts = state.omitted_dispatch_receipts.saturating_add(1);
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, RequestAccountingState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Non-clone proof that one logical transport dispatch was recorded.
///
/// Observed response bytes are recorded globally immediately. The returned
/// retention allowance can be smaller than the received chunk, but every byte
/// already delivered by transport remains charged. Dropping the lease never
/// rolls back either the request or byte counters.
#[derive(Debug)]
pub(crate) struct RequestAccountingLease {
    broker: RequestAccountingBroker,
    sequence: u64,
    action_id: String,
    stage: crate::DecisionExecutionStage,
    origin: Option<crate::DecisionActionOrigin>,
    request_body_bytes: u64,
    response_bytes: u64,
    response_budget_reached: bool,
    started_at: Instant,
    outcome: Option<TransportDispatchOutcome>,
}

impl RequestAccountingLease {
    pub(crate) async fn acquire_response_read(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.broker.response_read_gate)
            .lock_owned()
            .await
    }

    pub(crate) fn observe_response_bytes(&mut self, bytes: u64) -> u64 {
        self.response_bytes = self.response_bytes.saturating_add(bytes);
        let mut state = self.broker.lock_state();
        let remaining = self
            .broker
            .budget
            .max_response_bytes()
            .saturating_sub(state.snapshot.response_bytes);
        if bytes > 0 && bytes >= remaining {
            self.response_budget_reached = true;
        }
        let retained = bytes.min(remaining);
        state.snapshot.response_bytes = state.snapshot.response_bytes.saturating_add(bytes);
        retained
    }

    pub(crate) fn remaining_response_bytes(&self) -> u64 {
        let response_bytes = self.broker.snapshot().response_bytes;
        self.broker
            .budget
            .max_response_bytes()
            .saturating_sub(response_bytes)
    }

    pub(crate) const fn response_budget_reached(&self) -> bool {
        self.response_budget_reached
    }

    pub(crate) fn finish(&mut self, outcome: TransportDispatchOutcome) {
        debug_assert!(self.outcome.is_none(), "dispatch outcome classified twice");
        self.outcome = Some(outcome);
    }
}

impl Drop for RequestAccountingLease {
    fn drop(&mut self) {
        let receipt = TransportDispatchReceipt {
            sequence: self.sequence,
            action_id: self.action_id.clone(),
            stage: self.stage,
            origin: self.origin,
            request_body_bytes: self.request_body_bytes,
            response_bytes: self.response_bytes,
            elapsed_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome: self.outcome.unwrap_or(TransportDispatchOutcome::Cancelled),
        };
        self.broker.record_dispatch_receipt(receipt);
    }
}

fn check_request_limits(
    snapshot: &RequestAccountingSnapshot,
    budget: RuntimeBudget,
    action_id: &str,
    stage: crate::DecisionExecutionStage,
    request_body_bytes: u64,
) -> Result<RequestAccountingPreflight, RuntimeLimitExceeded> {
    if snapshot.total_requests >= budget.max_total_requests() {
        return Err(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::TotalRequests,
            u64::from(budget.max_total_requests()),
            u64::from(snapshot.total_requests).saturating_add(1),
            Some(action_id.to_owned()),
        ));
    }
    if snapshot.response_bytes >= budget.max_response_bytes() {
        return Err(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::ResponseBytes,
            budget.max_response_bytes(),
            snapshot.response_bytes,
            Some(action_id.to_owned()),
        ));
    }
    let Some(next_request_body_bytes) = snapshot.request_body_bytes.checked_add(request_body_bytes)
    else {
        return Err(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::RequestBodyBytes,
            budget.max_request_body_bytes(),
            u64::MAX,
            Some(action_id.to_owned()),
        ));
    };
    if next_request_body_bytes > budget.max_request_body_bytes() {
        return Err(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::RequestBodyBytes,
            budget.max_request_body_bytes(),
            next_request_body_bytes,
            Some(action_id.to_owned()),
        ));
    }
    if stage == crate::DecisionExecutionStage::Active
        && snapshot.active_verifications >= budget.max_active_verifications()
    {
        return Err(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::ActiveVerifications,
            u64::from(budget.max_active_verifications()),
            u64::from(snapshot.active_verifications).saturating_add(1),
            Some(action_id.to_owned()),
        ));
    }

    Ok(RequestAccountingPreflight {
        remaining_response_bytes: budget
            .max_response_bytes()
            .saturating_sub(snapshot.response_bytes),
    })
}

fn record_dispatch(
    snapshot: &mut RequestAccountingSnapshot,
    stage: crate::DecisionExecutionStage,
    origin: Option<crate::DecisionActionOrigin>,
    request_body_bytes: u64,
) {
    snapshot.total_requests = snapshot.total_requests.saturating_add(1);
    snapshot.request_body_bytes = snapshot
        .request_body_bytes
        .saturating_add(request_body_bytes);
    match stage {
        crate::DecisionExecutionStage::Passive => {
            snapshot.passive_requests = snapshot.passive_requests.saturating_add(1);
            match origin {
                Some(crate::DecisionActionOrigin::Bootstrap) => {
                    snapshot.bootstrap_requests = snapshot.bootstrap_requests.saturating_add(1);
                },
                Some(crate::DecisionActionOrigin::Planned) => {
                    snapshot.planned_requests = snapshot.planned_requests.saturating_add(1);
                },
                Some(crate::DecisionActionOrigin::Adaptive) => {
                    snapshot.adaptive_requests = snapshot.adaptive_requests.saturating_add(1);
                },
                Some(crate::DecisionActionOrigin::Retry) => {
                    snapshot.retry_requests = snapshot.retry_requests.saturating_add(1);
                },
                None => {},
            }
        },
        crate::DecisionExecutionStage::Active => {
            snapshot.active_verifications = snapshot.active_verifications.saturating_add(1);
        },
    }
}

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
    request_body_bytes: u64,
    response_bytes: u64,
    completed_execution_turns: u32,
    consecutive_no_progress_turns: u16,
    same_action_attempts: BTreeMap<String, u16>,
    elapsed_ms: u64,
}

impl RuntimeUsage {
    /// Returns logical transport dispatches that acquired an accounting lease.
    pub const fn total_requests(&self) -> u32 {
        self.total_requests
    }

    /// Returns passive transport dispatches, including bootstrap, planned,
    /// adaptive, and retry origins.
    pub const fn passive_requests(&self) -> u32 {
        self.passive_requests
    }

    /// Returns explicit active-verification transport dispatches.
    pub const fn active_verifications(&self) -> u16 {
        self.active_verifications
    }

    /// Returns bootstrap-originated transport dispatches.
    pub const fn bootstrap_requests(&self) -> u32 {
        self.bootstrap_requests
    }

    /// Returns planner-originated transport dispatches.
    pub const fn planned_requests(&self) -> u32 {
        self.planned_requests
    }

    /// Returns adaptation-originated transport dispatches.
    pub const fn adaptive_requests(&self) -> u32 {
        self.adaptive_requests
    }

    /// Returns retry-originated transport dispatches.
    pub const fn retry_requests(&self) -> u32 {
        self.retry_requests
    }

    /// Returns cumulative request-body bytes charged before dispatch.
    ///
    /// Bytes remain charged when transport or verification later fails.
    pub const fn request_body_bytes(&self) -> u64 {
        self.request_body_bytes
    }

    /// Returns cumulative response-body bytes delivered to transport leases.
    ///
    /// This can exceed the configured threshold by the single serialized chunk
    /// that revealed the crossing. The runtime reports that crossing as a
    /// typed limit and starts no later body read. Bytes remain charged when
    /// execution later fails or is cancelled.
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

    /// Returns all semantic action attempts without adding another wire field.
    pub fn total_action_attempts(&self) -> u64 {
        self.same_action_attempts
            .values()
            .map(|attempts| u64::from(*attempts))
            .sum()
    }

    /// Returns elapsed runtime wall time.
    pub const fn elapsed(&self) -> Duration {
        Duration::from_millis(self.elapsed_ms)
    }

    /// Returns elapsed runtime wall time in milliseconds.
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    pub(crate) fn reserve_action_attempt(&mut self, action_id: &str) {
        let attempts = self
            .same_action_attempts
            .entry(action_id.to_owned())
            .or_default();
        *attempts = attempts.saturating_add(1);
    }

    pub(crate) fn sync_request_accounting(&mut self, snapshot: RequestAccountingSnapshot) {
        // Broker state is monotonic. Merge rather than replace so a stale
        // snapshot observed by a concurrent reporter cannot make usage appear
        // to move backwards.
        self.total_requests = self.total_requests.max(snapshot.total_requests());
        self.passive_requests = self.passive_requests.max(snapshot.passive_requests());
        self.active_verifications = self
            .active_verifications
            .max(snapshot.active_verifications());
        self.bootstrap_requests = self.bootstrap_requests.max(snapshot.bootstrap_requests());
        self.planned_requests = self.planned_requests.max(snapshot.planned_requests());
        self.adaptive_requests = self.adaptive_requests.max(snapshot.adaptive_requests());
        self.retry_requests = self.retry_requests.max(snapshot.retry_requests());
        self.request_body_bytes = self.request_body_bytes.max(snapshot.request_body_bytes());
        self.response_bytes = self.response_bytes.max(snapshot.response_bytes());
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
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    #[test]
    fn budget_accepts_fail_closed_zero_values_and_round_trips() {
        let budget = RuntimeBudget::default()
            .with_max_total_requests(0)
            .with_max_wall_time(Duration::ZERO)
            .with_max_response_bytes(0)
            .with_max_request_body_bytes(0)
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
        assert_eq!(
            partial.max_request_body_bytes(),
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert!(serde_json::from_value::<RuntimeBudget>(serde_json::json!({
            "max_total_requets": 7
        }))
        .is_err());

        assert_eq!(
            serde_json::to_value(RuntimeBudget::default()).unwrap(),
            serde_json::json!({
                "max_total_requests": DEFAULT_MAX_TOTAL_REQUESTS,
                "max_wall_time_ms": DEFAULT_MAX_WALL_TIME_MS,
                "max_response_bytes": DEFAULT_MAX_RESPONSE_BYTES,
                "max_request_body_bytes": DEFAULT_MAX_REQUEST_BODY_BYTES,
                "max_active_verifications": DEFAULT_MAX_ACTIVE_VERIFICATIONS,
                "max_same_action_attempts": DEFAULT_MAX_SAME_ACTION_ATTEMPTS,
                "max_consecutive_no_progress_turns": DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS
            })
        );
    }

    #[test]
    fn zero_limits_fail_preflight_without_mutating_accounting() {
        let no_requests =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(0));
        let request_error = no_requests
            .preflight("http.bootstrap", crate::DecisionExecutionStage::Passive)
            .unwrap_err();
        assert_eq!(
            request_error.dimension(),
            RuntimeBudgetDimension::TotalRequests
        );
        assert_eq!(no_requests.snapshot(), RequestAccountingSnapshot::default());

        let no_bytes =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_response_bytes(0));
        let bytes_error = no_bytes
            .preflight("http.bootstrap", crate::DecisionExecutionStage::Passive)
            .unwrap_err();
        assert_eq!(
            bytes_error.dimension(),
            RuntimeBudgetDimension::ResponseBytes
        );
        assert_eq!(no_bytes.snapshot(), RequestAccountingSnapshot::default());

        let no_request_body =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_request_body_bytes(0));
        let request_body_error = no_request_body
            .preflight_with_request_body_bytes(
                "http.bootstrap",
                crate::DecisionExecutionStage::Passive,
                1,
            )
            .unwrap_err();
        assert_eq!(
            request_body_error.dimension(),
            RuntimeBudgetDimension::RequestBodyBytes
        );
        assert_eq!(
            no_request_body.snapshot(),
            RequestAccountingSnapshot::default()
        );

        let no_active =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_active_verifications(0));
        let active_error = no_active
            .preflight("http.verify", crate::DecisionExecutionStage::Active)
            .unwrap_err();
        assert_eq!(
            active_error.dimension(),
            RuntimeBudgetDimension::ActiveVerifications
        );
        assert_eq!(no_active.snapshot(), RequestAccountingSnapshot::default());
    }

    #[test]
    fn preflight_reports_remaining_bytes_without_reserving_a_dispatch() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(1)
                .with_max_response_bytes(7),
        );

        let first = broker
            .preflight("http.bootstrap", crate::DecisionExecutionStage::Passive)
            .unwrap();
        let second = broker
            .preflight("http.bootstrap", crate::DecisionExecutionStage::Passive)
            .unwrap();

        assert_eq!(first.remaining_response_bytes(), 7);
        assert_eq!(second, first);
        assert_eq!(broker.snapshot(), RequestAccountingSnapshot::default());
        assert_eq!(broker.budget().max_total_requests(), 1);
    }

    #[test]
    fn dropped_lease_never_refunds_a_dispatch() {
        let broker =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(1));
        let lease = broker
            .try_begin(
                "http.bootstrap",
                crate::DecisionExecutionStage::Passive,
                Some(crate::DecisionActionOrigin::Bootstrap),
            )
            .unwrap();

        drop(lease);

        let error = broker
            .try_begin(
                "http.bootstrap",
                crate::DecisionExecutionStage::Passive,
                Some(crate::DecisionActionOrigin::Bootstrap),
            )
            .unwrap_err();
        assert_eq!(error.dimension(), RuntimeBudgetDimension::TotalRequests);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.total_requests(), 1);
        assert_eq!(snapshot.passive_requests(), 1);
        assert_eq!(snapshot.bootstrap_requests(), 1);
    }

    #[test]
    fn dispatch_audit_preserves_order_and_completed_lease_metadata() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_request_body_bytes(8)
                .with_max_response_bytes(8),
        );
        let mut first = broker
            .try_begin_with_request_body_bytes(
                "http.control",
                crate::DecisionExecutionStage::Passive,
                Some(crate::DecisionActionOrigin::Bootstrap),
                3,
            )
            .unwrap();
        let mut second = broker
            .try_begin_with_request_body_bytes(
                "http.candidate",
                crate::DecisionExecutionStage::Active,
                None,
                5,
            )
            .unwrap();

        assert_eq!(first.observe_response_bytes(2), 2);
        assert_eq!(second.observe_response_bytes(4), 4);
        first.finish(TransportDispatchOutcome::Completed);
        second.finish(TransportDispatchOutcome::Completed);

        // Completion order must not change the original wire-dispatch order.
        drop(second);
        drop(first);

        let audit = broker.dispatch_audit();
        assert_eq!(audit.omitted_receipt_count(), 0);
        assert!(!audit.is_empty());
        let receipts = audit.receipts();
        assert_eq!(receipts.len(), 2);

        assert_eq!(receipts[0].sequence(), 0);
        assert_eq!(receipts[0].action_id(), "http.control");
        assert_eq!(receipts[0].stage(), crate::DecisionExecutionStage::Passive);
        assert_eq!(
            receipts[0].origin(),
            Some(crate::DecisionActionOrigin::Bootstrap)
        );
        assert_eq!(receipts[0].request_body_bytes(), 3);
        assert_eq!(receipts[0].response_bytes(), 2);
        assert_eq!(receipts[0].outcome(), TransportDispatchOutcome::Completed);

        assert_eq!(receipts[1].sequence(), 1);
        assert_eq!(receipts[1].action_id(), "http.candidate");
        assert_eq!(receipts[1].stage(), crate::DecisionExecutionStage::Active);
        assert_eq!(receipts[1].origin(), None);
        assert_eq!(receipts[1].request_body_bytes(), 5);
        assert_eq!(receipts[1].response_bytes(), 4);
        assert_eq!(receipts[1].outcome(), TransportDispatchOutcome::Completed);
    }

    #[test]
    fn unclassified_dispatch_is_audited_as_cancelled() {
        let broker =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(1));
        let mut lease = broker
            .try_begin(
                "http.cancelled",
                crate::DecisionExecutionStage::Passive,
                Some(crate::DecisionActionOrigin::Adaptive),
            )
            .unwrap();
        assert_eq!(lease.observe_response_bytes(7), 7);

        drop(lease);

        let audit = broker.dispatch_audit();
        let receipt = audit.receipts().first().unwrap();
        assert_eq!(audit.receipts().len(), 1);
        assert_eq!(receipt.action_id(), "http.cancelled");
        assert_eq!(receipt.response_bytes(), 7);
        assert_eq!(receipt.outcome(), TransportDispatchOutcome::Cancelled);
    }

    #[test]
    fn dispatch_audit_retention_is_bounded_and_counts_omissions() {
        let dispatch_count = HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS + 1;
        let broker =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(
                u32::try_from(dispatch_count).expect("test dispatch count fits in u32"),
            ));

        for index in 0..dispatch_count {
            let mut lease = broker
                .try_begin(
                    &format!("http.dispatch.{index}"),
                    crate::DecisionExecutionStage::Passive,
                    Some(crate::DecisionActionOrigin::Planned),
                )
                .unwrap();
            lease.finish(TransportDispatchOutcome::Completed);
        }

        let audit = broker.dispatch_audit();
        assert_eq!(audit.receipts().len(), HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS);
        assert_eq!(audit.omitted_receipt_count(), 1);
        assert_eq!(audit.receipts().first().unwrap().sequence(), 0);
        assert_eq!(
            audit.receipts().last().unwrap().sequence(),
            u64::try_from(HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS - 1).unwrap()
        );
    }

    #[test]
    fn denied_dispatch_does_not_create_an_audit_receipt() {
        let broker =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(0));

        let denied = broker
            .try_begin(
                "http.denied",
                crate::DecisionExecutionStage::Passive,
                Some(crate::DecisionActionOrigin::Planned),
            )
            .unwrap_err();

        assert_eq!(denied.dimension(), RuntimeBudgetDimension::TotalRequests);
        assert_eq!(broker.snapshot(), RequestAccountingSnapshot::default());
        assert!(broker.dispatch_audit().is_empty());
    }

    #[test]
    fn remaining_one_dispatch_is_acquired_atomically() {
        let broker =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(1));
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for action_id in ["http.a", "http.b"] {
            let broker = broker.clone();
            let barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                broker
                    .try_begin(
                        action_id,
                        crate::DecisionExecutionStage::Passive,
                        Some(crate::DecisionActionOrigin::Planned),
                    )
                    .map(drop)
                    .map_err(|error| error.dimension())
            }));
        }
        barrier.wait();

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { matches!(result, Err(RuntimeBudgetDimension::TotalRequests)) })
                .count(),
            1
        );
        assert_eq!(broker.snapshot().total_requests(), 1);
    }

    #[test]
    fn preflight_is_advisory_but_try_begin_is_atomic() {
        let broker =
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(1));
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for action_id in ["http.a", "http.b"] {
            let broker = broker.clone();
            let barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                broker
                    .preflight(action_id, crate::DecisionExecutionStage::Passive)
                    .unwrap();
                barrier.wait();
                broker
                    .try_begin(
                        action_id,
                        crate::DecisionExecutionStage::Passive,
                        Some(crate::DecisionActionOrigin::Planned),
                    )
                    .map(drop)
            }));
        }
        barrier.wait();

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let denied = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .unwrap();
        assert_eq!(denied.dimension(), RuntimeBudgetDimension::TotalRequests);
        assert_eq!(broker.snapshot().total_requests(), 1);
    }

    #[test]
    fn active_limit_is_atomic_without_blocking_passive_dispatch() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(3)
                .with_max_active_verifications(1),
        );
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = ["verify.a", "verify.b"]
            .into_iter()
            .map(|action_id| {
                let broker = broker.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    broker
                        .try_begin(action_id, crate::DecisionExecutionStage::Active, None)
                        .map(drop)
                })
            })
            .collect();
        barrier.wait();

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let denied = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .unwrap();
        assert_eq!(
            denied.dimension(),
            RuntimeBudgetDimension::ActiveVerifications
        );
        drop(
            broker
                .try_begin(
                    "http.passive",
                    crate::DecisionExecutionStage::Passive,
                    Some(crate::DecisionActionOrigin::Planned),
                )
                .unwrap(),
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.total_requests(), 2);
        assert_eq!(snapshot.active_verifications(), 1);
        assert_eq!(snapshot.passive_requests(), 1);
    }

    #[test]
    fn response_byte_observations_bound_retention_and_survive_lease_drop() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_response_bytes(5),
        );
        let mut lease = broker
            .try_begin(
                "http.bootstrap",
                crate::DecisionExecutionStage::Passive,
                Some(crate::DecisionActionOrigin::Bootstrap),
            )
            .unwrap();

        assert_eq!(lease.observe_response_bytes(3), 3);
        assert_eq!(lease.remaining_response_bytes(), 2);
        assert_eq!(lease.observe_response_bytes(4), 2);
        assert_eq!(lease.observe_response_bytes(1), 0);
        drop(lease);

        assert_eq!(broker.snapshot().response_bytes(), 8);
        assert_eq!(broker.dispatch_audit().receipts()[0].response_bytes(), 8);
        let error = broker
            .preflight("http.next", crate::DecisionExecutionStage::Passive)
            .unwrap_err();
        assert_eq!(error.dimension(), RuntimeBudgetDimension::ResponseBytes);
    }

    #[test]
    fn request_body_bytes_are_checked_and_charged_atomically_before_dispatch() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_request_body_bytes(5),
        );
        drop(
            broker
                .try_begin_with_request_body_bytes(
                    "http.control",
                    crate::DecisionExecutionStage::Passive,
                    Some(crate::DecisionActionOrigin::Planned),
                    3,
                )
                .unwrap(),
        );

        let denied = broker
            .try_begin_with_request_body_bytes(
                "http.candidate",
                crate::DecisionExecutionStage::Active,
                None,
                3,
            )
            .unwrap_err();
        assert_eq!(denied.dimension(), RuntimeBudgetDimension::RequestBodyBytes);
        assert_eq!(denied.limit(), 5);
        assert_eq!(denied.observed(), 6);

        let snapshot = broker.snapshot();
        assert_eq!(snapshot.total_requests(), 1);
        assert_eq!(snapshot.request_body_bytes(), 3);
        assert_eq!(snapshot.active_verifications(), 0);
    }

    #[test]
    fn request_body_accounting_overflow_fails_closed() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_request_body_bytes(u64::MAX),
        );
        drop(
            broker
                .try_begin_with_request_body_bytes(
                    "http.max-body",
                    crate::DecisionExecutionStage::Passive,
                    None,
                    u64::MAX,
                )
                .unwrap(),
        );

        let error = broker
            .try_begin_with_request_body_bytes(
                "http.overflow",
                crate::DecisionExecutionStage::Passive,
                None,
                1,
            )
            .unwrap_err();
        assert_eq!(error.dimension(), RuntimeBudgetDimension::RequestBodyBytes);
        assert_eq!(error.limit(), u64::MAX);
        assert_eq!(error.observed(), u64::MAX);
        assert_eq!(broker.snapshot().total_requests(), 1);
        assert_eq!(broker.snapshot().request_body_bytes(), u64::MAX);
    }

    #[test]
    fn concurrent_request_bodies_cannot_exceed_the_session_limit() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_request_body_bytes(5),
        );
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = ["http.a", "http.b"]
            .into_iter()
            .map(|action_id| {
                let broker = broker.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    broker
                        .try_begin_with_request_body_bytes(
                            action_id,
                            crate::DecisionExecutionStage::Passive,
                            Some(crate::DecisionActionOrigin::Planned),
                            4,
                        )
                        .map(drop)
                })
            })
            .collect();
        barrier.wait();

        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let denied = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .unwrap();
        assert_eq!(denied.dimension(), RuntimeBudgetDimension::RequestBodyBytes);
        assert_eq!(broker.snapshot().total_requests(), 1);
        assert_eq!(broker.snapshot().request_body_bytes(), 4);
    }

    #[tokio::test]
    async fn response_read_gate_limits_concurrent_collectors_to_one_crossing_chunk() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(3)
                .with_max_response_bytes(5),
        );
        let leases = ["http.a", "http.b", "http.c"].map(|action_id| {
            broker
                .try_begin(
                    action_id,
                    crate::DecisionExecutionStage::Passive,
                    Some(crate::DecisionActionOrigin::Planned),
                )
                .unwrap()
        });
        async fn read_one(mut lease: RequestAccountingLease) -> u64 {
            let _guard = lease.acquire_response_read().await;
            if lease.remaining_response_bytes() == 0 {
                return 0;
            }
            lease.observe_response_bytes(4)
        }
        let [first, second, third] = leases;
        let (first, second, third) =
            tokio::join!(read_one(first), read_one(second), read_one(third));

        let retained = first + second + third;
        assert_eq!(retained, 5);
        assert_eq!(broker.snapshot().response_bytes(), 8);
    }

    #[test]
    fn usage_sync_preserves_wire_shape_and_separates_action_attempts() {
        let broker = RequestAccountingBroker::new(
            RuntimeBudget::default()
                .with_max_total_requests(5)
                .with_max_active_verifications(1),
        );
        for origin in [
            crate::DecisionActionOrigin::Bootstrap,
            crate::DecisionActionOrigin::Planned,
            crate::DecisionActionOrigin::Adaptive,
            crate::DecisionActionOrigin::Retry,
        ] {
            drop(
                broker
                    .try_begin(
                        "http.probe",
                        crate::DecisionExecutionStage::Passive,
                        Some(origin),
                    )
                    .unwrap(),
            );
        }
        drop(
            broker
                .try_begin("http.probe", crate::DecisionExecutionStage::Active, None)
                .unwrap(),
        );

        let mut usage = RuntimeUsage::default();
        usage.reserve_action_attempt("http.probe");
        usage.reserve_action_attempt("http.probe");
        usage.sync_request_accounting(broker.snapshot());

        assert_eq!(usage.total_requests(), 5);
        assert_eq!(usage.passive_requests(), 4);
        assert_eq!(usage.active_verifications(), 1);
        assert_eq!(usage.bootstrap_requests(), 1);
        assert_eq!(usage.planned_requests(), 1);
        assert_eq!(usage.adaptive_requests(), 1);
        assert_eq!(usage.retry_requests(), 1);
        assert_eq!(usage.request_body_bytes(), 0);
        assert_eq!(usage.same_action_attempts("http.probe"), 2);
        assert_eq!(usage.total_action_attempts(), 2);
        assert_eq!(
            serde_json::to_value(&usage).unwrap(),
            serde_json::json!({
                "total_requests": 5,
                "passive_requests": 4,
                "active_verifications": 1,
                "bootstrap_requests": 1,
                "planned_requests": 1,
                "adaptive_requests": 1,
                "retry_requests": 1,
                "request_body_bytes": 0,
                "response_bytes": 0,
                "completed_execution_turns": 0,
                "consecutive_no_progress_turns": 0,
                "same_action_attempts": {"http.probe": 2},
                "elapsed_ms": 0
            })
        );
    }

    #[test]
    fn stale_snapshot_cannot_regress_runtime_usage() {
        let old = RequestAccountingSnapshot {
            total_requests: 1,
            passive_requests: 1,
            bootstrap_requests: 1,
            ..RequestAccountingSnapshot::default()
        };
        let new = RequestAccountingSnapshot {
            total_requests: 2,
            passive_requests: 1,
            active_verifications: 1,
            bootstrap_requests: 1,
            request_body_bytes: 4,
            response_bytes: 4,
            ..RequestAccountingSnapshot::default()
        };
        let mut usage = RuntimeUsage::default();

        usage.sync_request_accounting(new);
        usage.sync_request_accounting(old);

        assert_eq!(usage.total_requests(), 2);
        assert_eq!(usage.passive_requests(), 1);
        assert_eq!(usage.active_verifications(), 1);
        assert_eq!(usage.bootstrap_requests(), 1);
        assert_eq!(usage.request_body_bytes(), 4);
        assert_eq!(usage.response_bytes(), 4);
    }
}
