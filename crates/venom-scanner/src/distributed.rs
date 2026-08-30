//! Bounded deterministic in-process scan coordination.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `distributed`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental.
//!
//! This module is one revisioned, in-memory state machine. It provides no
//! transport, authentication, durability, process recovery, or multi-node
//! consensus. Callers supply a monotonic logical time and explicitly drive
//! lease expiry and worker-loss recovery.
//! Every command, including an idempotent terminal replay, must name the
//! coordinator's current revision. Ownership tokens make a current-revision
//! replay semantically idempotent; they do not bypass revision ordering.
//! Tokens and receipts are deterministic logical CAS/idempotency fences within
//! one caller-enforced coordinator epoch. They are not authentication material
//! and are not cross-instance replay-resistant.
//! Bounds cover retained data per instance; caller allocations, returned clones,
//! instance count, and allocator exhaustion remain host-budgeted.

mod coordinator;
mod lease;
mod limits;
mod model;
mod queue;
mod recovery;
mod results;
mod worker;

pub use coordinator::WorkerPool;
pub use lease::{
    CancellationOutcome, CompletionOutcome, CompletionReceipt, FailureOutcome, QueuedTaskFence,
    ScanTask, StartOutcome, TaskLease, TaskOwnership,
};
pub use limits::{
    DistributedLimits, MAX_ACTIVE_TASKS, MAX_AGGREGATE_ITEMS, MAX_HEARTBEAT_TIMEOUT_SECS,
    MAX_IDENTIFIER_BYTES, MAX_LEASE_TTL_SECS, MAX_RESULTS, MAX_RESULT_BYTES, MAX_RETRIES,
    MAX_TARGET_REF_BYTES, MAX_TASK_PHASES, MAX_TASK_RECORDS, MAX_TASK_TTL_SECS,
    MAX_TOTAL_RESULT_BYTES, MAX_WORKERS, MAX_WORKER_CAPACITY, MAX_WORKER_TAGS,
    UTILIZATION_BASIS_POINTS,
};
pub use model::{StateSnapshot, TaskPriority, TaskSpec, TaskStatus, Transition};
pub use queue::TaskQueue;
pub use recovery::RecoverySummary;
pub use results::{AggregatedResult, ResultAggregator, ResultLimits, StoreResultOutcome};
pub use worker::{WorkerNode, WorkerObservation, WorkerSpec, WorkerStatus, WorkerTag};

#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
use coordinator::{next_counter, next_u32};
#[cfg(test)]
use queue::QueueKey;
use thiserror::Error;

/// Typed state-machine failures. Every failure leaves state unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DistributedError {
    #[error("invalid zero limit: {name}")]
    InvalidLimit { name: &'static str },
    #[error("invalid limit relationship: {reason}")]
    InvalidLimitRelationship { reason: &'static str },
    #[error("count limit {name}={actual} exceeds absolute maximum {maximum}")]
    CountLimitExceedsMaximum {
        name: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("time limit {name}={actual} exceeds absolute maximum {maximum}")]
    TimeLimitExceedsMaximum {
        name: &'static str,
        actual: u64,
        maximum: u64,
    },
    #[error("retry limit {actual} exceeds absolute maximum {maximum}")]
    RetryLimitExceedsMaximum { actual: u32, maximum: u32 },
    #[error("invalid task: {reason}")]
    InvalidTask { reason: &'static str },
    #[error("invalid worker: {reason}")]
    InvalidWorker { reason: &'static str },
    #[error("revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("logical time regressed from {current} to {proposed}")]
    LogicalTimeRegression { current: u64, proposed: u64 },
    #[error("monotonic counter exhausted: {counter}")]
    CounterExhausted { counter: &'static str },
    #[error("task already exists: {task_id}")]
    TaskAlreadyExists { task_id: String },
    #[error("task not found: {task_id}")]
    TaskNotFound { task_id: String },
    #[error("worker already exists: {worker_id}")]
    WorkerAlreadyExists { worker_id: String },
    #[error("worker not found: {worker_id}")]
    WorkerNotFound { worker_id: String },
    #[error("worker generation conflict: expected {expected}, actual {actual}")]
    WorkerGenerationConflict { expected: u64, actual: u64 },
    #[error("task record capacity reached: {limit}")]
    TaskRecordCapacityReached { limit: usize },
    #[error("active task capacity reached: {limit}")]
    ActiveTaskCapacityReached { limit: usize },
    #[error("queued task capacity reached: {limit}")]
    QueuedTaskCapacityReached { limit: usize },
    #[error("terminal reservation capacity reached: {limit}")]
    TerminalCapacityReserved { limit: usize },
    #[error("worker capacity reached: {limit}")]
    WorkerCapacityReached { limit: usize },
    #[error("no queued task is available")]
    NoQueuedTask,
    #[error("no eligible worker is available")]
    NoAvailableWorker,
    #[error("worker is not eligible: {worker_id}")]
    WorkerUnavailable { worker_id: String },
    #[error("worker is at capacity: {worker_id}")]
    WorkerAtCapacity { worker_id: String },
    #[error("task {task_id} is not queued (status: {status:?})")]
    TaskNotQueued { task_id: String, status: TaskStatus },
    #[error("invalid {operation} transition for task {task_id} from {status:?}")]
    InvalidTransition {
        task_id: String,
        status: TaskStatus,
        operation: &'static str,
    },
    #[error("stale or mismatched task ownership token: {task_id}")]
    StaleOwnership { task_id: String },
    #[error("lease expired for task {task_id}")]
    LeaseExpired { task_id: String },
    #[error("result already exists with different bytes: {task_id}")]
    ConflictingResult { task_id: String },
    #[error("result receipt does not match the occupied task ID: {task_id}")]
    MismatchedResultReceipt { task_id: String },
    #[error("result capacity reached: {limit}")]
    ResultCapacityReached { limit: usize },
    #[error("result size {actual} exceeds limit {limit}")]
    ResultTooLarge { actual: usize, limit: usize },
    #[error("retained result bytes {actual} exceed limit {limit}")]
    TotalResultBytesExceeded { actual: usize, limit: usize },
    #[error("aggregate request has {actual} items, limit is {limit}")]
    AggregateItemLimitExceeded { actual: usize, limit: usize },
    #[error("aggregate request repeats task {task_id}")]
    DuplicateAggregateTask { task_id: String },
    #[error("aggregate result is missing task {task_id}")]
    MissingResult { task_id: String },
    #[error("aggregate bytes {actual} exceed limit {limit}")]
    AggregateBytesExceeded { actual: usize, limit: usize },
    #[error("state invariant failed: {reason}")]
    StateInvariant { reason: &'static str },
    #[error("state lock is poisoned")]
    StatePoisoned,
}

fn lock_state<T>(state: &Arc<Mutex<T>>) -> Result<MutexGuard<'_, T>, DistributedError> {
    state.lock().map_err(|_| DistributedError::StatePoisoned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_capacity_is_exact_at_basis_point_edges() {
        let mut worker = WorkerNode {
            worker_id: "worker".to_owned(),
            generation: 1,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 0,
            cpu_basis_points: 5_000,
            memory_basis_points: 0,
            network_basis_points: 0,
            tags: BTreeSet::new(),
        };
        assert_eq!(worker.effective_capacity(), 5);
        worker.cpu_basis_points = 9_999;
        assert_eq!(worker.effective_capacity(), 1);
        worker.cpu_basis_points = 10_000;
        assert_eq!(worker.effective_capacity(), 0);
    }

    #[test]
    fn counter_overflow_is_typed() {
        assert_eq!(
            next_counter(u64::MAX, "test"),
            Err(DistributedError::CounterExhausted { counter: "test" })
        );
        assert_eq!(
            next_u32(u32::MAX, "test32"),
            Err(DistributedError::CounterExhausted { counter: "test32" })
        );
    }

    #[test]
    fn invalid_limit_relationships_are_rejected() {
        let limits = DistributedLimits {
            max_task_records: 4,
            max_active_tasks: 2,
            max_queued_tasks: 3,
            max_terminal_tasks: 2,
            ..DistributedLimits::default()
        };
        assert_eq!(
            WorkerPool::with_limits(limits).err(),
            Some(DistributedError::InvalidLimitRelationship {
                reason: "max_queued_tasks exceeds max_active_tasks"
            })
        );
    }

    #[test]
    fn queue_key_orders_priority_then_ordinal_then_id() {
        let mut keys = BTreeSet::new();
        keys.insert(QueueKey::new(TaskPriority::Normal, 1, "z".to_owned()));
        keys.insert(QueueKey::new(TaskPriority::Critical, 2, "b".to_owned()));
        keys.insert(QueueKey::new(TaskPriority::Critical, 2, "a".to_owned()));
        let ordered: Vec<String> = keys.into_iter().map(|key| key.task_id).collect();
        assert_eq!(ordered, ["a", "b", "z"]);
    }
}
