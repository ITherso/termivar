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

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

/// Maximum task, scan, or worker identifier length in bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 256;
/// Maximum opaque target reference length in bytes.
pub const MAX_TARGET_REF_BYTES: usize = 1_024;
/// Maximum phases carried by one task.
pub const MAX_TASK_PHASES: usize = 256;
/// Maximum observational worker metadata tags.
pub const MAX_WORKER_TAGS: usize = 5;
/// Integer utilization scale: 10,000 is 100%.
pub const UTILIZATION_BASIS_POINTS: u16 = 10_000;
/// Absolute ceiling for retained task records and terminal reservations.
pub const MAX_TASK_RECORDS: usize = 65_536;
/// Absolute ceiling for active and queued tasks.
pub const MAX_ACTIVE_TASKS: usize = 16_384;
/// Absolute ceiling for retained worker records.
pub const MAX_WORKERS: usize = 4_096;
/// Absolute ceiling for configured retries after the first attempt.
pub const MAX_RETRIES: u32 = 32;
/// Absolute ceiling for one worker's configured concurrency.
pub const MAX_WORKER_CAPACITY: u32 = 4_096;
/// Absolute ceiling for a lease TTL.
pub const MAX_LEASE_TTL_SECS: u64 = 86_400;
/// Absolute ceiling for task TTL policy.
pub const MAX_TASK_TTL_SECS: u64 = 31 * 86_400;
/// Absolute ceiling for heartbeat timeout policy.
pub const MAX_HEARTBEAT_TIMEOUT_SECS: u64 = 86_400;
/// Absolute ceiling for retained result records.
pub const MAX_RESULTS: usize = 65_536;
/// Absolute ceiling for one result.
pub const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
/// Absolute ceiling for retained or aggregated result bytes.
pub const MAX_TOTAL_RESULT_BYTES: usize = 256 * 1024 * 1024;
/// Absolute ceiling for one aggregate request.
pub const MAX_AGGREGATE_ITEMS: usize = 65_536;

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

/// Hard coordinator bounds and fixed recovery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributedLimits {
    pub max_task_records: usize,
    pub max_active_tasks: usize,
    pub max_queued_tasks: usize,
    pub max_terminal_tasks: usize,
    pub max_workers: usize,
    pub max_retries: u32,
    pub max_lease_ttl_secs: u64,
    pub max_task_ttl_secs: u64,
    pub heartbeat_timeout_secs: u64,
}

impl Default for DistributedLimits {
    fn default() -> Self {
        Self {
            max_task_records: 4_096,
            max_active_tasks: 1_024,
            max_queued_tasks: 1_024,
            max_terminal_tasks: 4_096,
            max_workers: 256,
            max_retries: 3,
            max_lease_ttl_secs: 3_600,
            max_task_ttl_secs: 86_400,
            heartbeat_timeout_secs: 60,
        }
    }
}

fn validate_limits(limits: DistributedLimits) -> Result<(), DistributedError> {
    for (name, value) in [
        ("max_task_records", limits.max_task_records),
        ("max_active_tasks", limits.max_active_tasks),
        ("max_queued_tasks", limits.max_queued_tasks),
        ("max_terminal_tasks", limits.max_terminal_tasks),
        ("max_workers", limits.max_workers),
    ] {
        if value == 0 {
            return Err(DistributedError::InvalidLimit { name });
        }
    }
    for (name, actual, maximum) in [
        (
            "max_task_records",
            limits.max_task_records,
            MAX_TASK_RECORDS,
        ),
        (
            "max_active_tasks",
            limits.max_active_tasks,
            MAX_ACTIVE_TASKS,
        ),
        (
            "max_queued_tasks",
            limits.max_queued_tasks,
            MAX_ACTIVE_TASKS,
        ),
        (
            "max_terminal_tasks",
            limits.max_terminal_tasks,
            MAX_TASK_RECORDS,
        ),
        ("max_workers", limits.max_workers, MAX_WORKERS),
    ] {
        if actual > maximum {
            return Err(DistributedError::CountLimitExceedsMaximum {
                name,
                actual,
                maximum,
            });
        }
    }
    for (name, actual, maximum) in [
        (
            "max_lease_ttl_secs",
            limits.max_lease_ttl_secs,
            MAX_LEASE_TTL_SECS,
        ),
        (
            "max_task_ttl_secs",
            limits.max_task_ttl_secs,
            MAX_TASK_TTL_SECS,
        ),
        (
            "heartbeat_timeout_secs",
            limits.heartbeat_timeout_secs,
            MAX_HEARTBEAT_TIMEOUT_SECS,
        ),
    ] {
        if actual > maximum {
            return Err(DistributedError::TimeLimitExceedsMaximum {
                name,
                actual,
                maximum,
            });
        }
    }
    if limits.max_retries > MAX_RETRIES {
        return Err(DistributedError::RetryLimitExceedsMaximum {
            actual: limits.max_retries,
            maximum: MAX_RETRIES,
        });
    }
    for (name, value) in [
        ("max_lease_ttl_secs", limits.max_lease_ttl_secs),
        ("max_task_ttl_secs", limits.max_task_ttl_secs),
        ("heartbeat_timeout_secs", limits.heartbeat_timeout_secs),
    ] {
        if value == 0 {
            return Err(DistributedError::InvalidLimit { name });
        }
    }
    if limits.max_active_tasks > limits.max_task_records {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "max_active_tasks exceeds max_task_records",
        });
    }
    if limits.max_queued_tasks > limits.max_active_tasks {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "max_queued_tasks exceeds max_active_tasks",
        });
    }
    if limits.max_terminal_tasks > limits.max_task_records {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "max_terminal_tasks exceeds max_task_records",
        });
    }
    if limits.max_terminal_tasks < limits.max_active_tasks {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "max_terminal_tasks is smaller than max_active_tasks",
        });
    }
    Ok(())
}

/// Observational worker metadata tags. Ordering is stable and non-randomized;
/// the coordinator does not use these tags for eligibility or affinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkerTag {
    Linux,
    Windows,
    Gpu,
    Internal,
    External,
}

impl WorkerTag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Gpu => "gpu",
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

/// Worker eligibility state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus {
    Healthy,
    Busy,
    Degraded,
    Offline,
}

impl WorkerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Busy => "busy",
            Self::Degraded => "degraded",
            Self::Offline => "offline",
        }
    }
}

/// Caller-provided worker admission record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSpec {
    pub worker_id: String,
    pub capacity: u32,
    pub cpu_basis_points: u16,
    pub memory_basis_points: u16,
    pub network_basis_points: u16,
    pub tags: BTreeSet<WorkerTag>,
}

impl WorkerSpec {
    pub fn new(worker_id: impl Into<String>, capacity: u32) -> Self {
        Self {
            worker_id: worker_id.into(),
            capacity,
            cpu_basis_points: 0,
            memory_basis_points: 0,
            network_basis_points: 0,
            tags: BTreeSet::new(),
        }
    }
}

/// Caller-supplied heartbeat and resource observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerObservation {
    pub status: WorkerStatus,
    pub cpu_basis_points: u16,
    pub memory_basis_points: u16,
    pub network_basis_points: u16,
}

impl Default for WorkerObservation {
    fn default() -> Self {
        Self {
            status: WorkerStatus::Healthy,
            cpu_basis_points: 0,
            memory_basis_points: 0,
            network_basis_points: 0,
        }
    }
}

/// Coordinator-owned worker snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerNode {
    worker_id: String,
    generation: u64,
    status: WorkerStatus,
    capacity: u32,
    current_tasks: u32,
    completed_tasks: u64,
    last_heartbeat: u64,
    cpu_basis_points: u16,
    memory_basis_points: u16,
    network_basis_points: u16,
    tags: BTreeSet<WorkerTag>,
}

impl WorkerNode {
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn status(&self) -> WorkerStatus {
        self.status
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn current_tasks(&self) -> u32 {
        self.current_tasks
    }

    pub fn completed_tasks(&self) -> u64 {
        self.completed_tasks
    }

    pub fn last_heartbeat(&self) -> u64 {
        self.last_heartbeat
    }

    pub fn cpu_basis_points(&self) -> u16 {
        self.cpu_basis_points
    }

    pub fn memory_basis_points(&self) -> u16 {
        self.memory_basis_points
    }

    pub fn network_basis_points(&self) -> u16 {
        self.network_basis_points
    }

    pub fn tags(&self) -> &BTreeSet<WorkerTag> {
        &self.tags
    }

    pub fn effective_capacity(&self) -> u32 {
        if self.status != WorkerStatus::Healthy {
            return 0;
        }
        let max_load = self
            .cpu_basis_points
            .max(self.memory_basis_points)
            .max(self.network_basis_points) as u64;
        let free = u64::from(UTILIZATION_BASIS_POINTS) - max_load;
        let scaled = u64::from(self.capacity) * free;
        let divisor = u64::from(UTILIZATION_BASIS_POINTS);
        scaled.div_ceil(divisor) as u32
    }

    pub fn available_slots(&self) -> u32 {
        self.effective_capacity().saturating_sub(self.current_tasks)
    }

    fn is_eligible(&self, now_secs: u64, heartbeat_timeout_secs: u64) -> bool {
        self.status == WorkerStatus::Healthy
            && now_secs.saturating_sub(self.last_heartbeat) <= heartbeat_timeout_secs
            && self.available_slots() > 0
    }

    fn selection_key(&self, now_secs: u64) -> (u32, u64, u16, u16, u16) {
        (
            self.available_slots(),
            u64::MAX - now_secs.saturating_sub(self.last_heartbeat),
            UTILIZATION_BASIS_POINTS - self.cpu_basis_points,
            UTILIZATION_BASIS_POINTS - self.memory_basis_points,
            UTILIZATION_BASIS_POINTS - self.network_basis_points,
        )
    }
}

fn validate_worker_spec(spec: &WorkerSpec) -> Result<(), DistributedError> {
    validate_identifier(&spec.worker_id, "worker_id").map_err(|_| {
        DistributedError::InvalidWorker {
            reason: "worker_id is invalid",
        }
    })?;
    if spec.capacity == 0 {
        return Err(DistributedError::InvalidWorker {
            reason: "capacity is zero",
        });
    }
    if spec.capacity > MAX_WORKER_CAPACITY {
        return Err(DistributedError::InvalidWorker {
            reason: "capacity exceeds absolute maximum",
        });
    }
    if spec.cpu_basis_points > UTILIZATION_BASIS_POINTS
        || spec.memory_basis_points > UTILIZATION_BASIS_POINTS
        || spec.network_basis_points > UTILIZATION_BASIS_POINTS
    {
        return Err(DistributedError::InvalidWorker {
            reason: "utilization exceeds 10000 basis points",
        });
    }
    if spec.tags.len() > MAX_WORKER_TAGS {
        return Err(DistributedError::InvalidWorker {
            reason: "too many worker tags",
        });
    }
    Ok(())
}

/// Task priority. Higher priorities are selected first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Exact task lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Queued,
    Leased,
    Running,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Leased | Self::Running)
    }
}

/// Fresh task admission data. `target_ref` is opaque; this module never opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskSpec {
    pub task_id: String,
    pub scan_id: String,
    pub target_ref: String,
    pub phases: Vec<u8>,
    pub priority: TaskPriority,
}

impl std::fmt::Debug for TaskSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskSpec")
            .field("task_id", &self.task_id)
            .field("scan_id", &self.scan_id)
            .field("target_ref_bytes", &self.target_ref.len())
            .field("phases", &self.phases)
            .field("priority", &self.priority)
            .finish()
    }
}

impl TaskSpec {
    pub fn new(
        task_id: impl Into<String>,
        scan_id: impl Into<String>,
        target_ref: impl Into<String>,
        phases: Vec<u8>,
        priority: TaskPriority,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            scan_id: scan_id.into(),
            target_ref: target_ref.into(),
            phases,
            priority,
        }
    }
}

fn validate_task_spec(spec: &TaskSpec) -> Result<(), DistributedError> {
    validate_identifier(&spec.task_id, "task_id")?;
    validate_identifier(&spec.scan_id, "scan_id")?;
    if spec.target_ref.is_empty() {
        return Err(DistributedError::InvalidTask {
            reason: "target_ref is empty",
        });
    }
    if spec.target_ref.len() > MAX_TARGET_REF_BYTES {
        return Err(DistributedError::InvalidTask {
            reason: "target_ref is too long",
        });
    }
    if spec.phases.len() > MAX_TASK_PHASES {
        return Err(DistributedError::InvalidTask {
            reason: "too many phases",
        });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), DistributedError> {
    if value.is_empty() {
        return Err(DistributedError::InvalidTask {
            reason: match field {
                "task_id" => "task_id is empty",
                "scan_id" => "scan_id is empty",
                _ => "identifier is empty",
            },
        });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(DistributedError::InvalidTask {
            reason: match field {
                "task_id" => "task_id is too long",
                "scan_id" => "scan_id is too long",
                _ => "identifier is too long",
            },
        });
    }
    if !identifier_is_safe(value) {
        return Err(DistributedError::InvalidTask {
            reason: match field {
                "task_id" => "task_id contains unsafe characters",
                "scan_id" => "scan_id contains unsafe characters",
                _ => "identifier contains unsafe characters",
            },
        });
    }
    Ok(())
}

fn identifier_is_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn validate_task_command_id(value: &str) -> Result<(), DistributedError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || !identifier_is_safe(value) {
        return Err(DistributedError::InvalidTask {
            reason: "task command identifier is invalid",
        });
    }
    Ok(())
}

fn validate_worker_command_id(value: &str) -> Result<(), DistributedError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || !identifier_is_safe(value) {
        return Err(DistributedError::InvalidWorker {
            reason: "worker command identifier is invalid",
        });
    }
    Ok(())
}

/// Exact logical lease fence for one worker generation and task attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLease {
    task_id: String,
    worker_id: String,
    worker_generation: u64,
    task_generation: u64,
    attempt: u32,
    lease_id: u64,
    acquired_at: u64,
    expires_at: u64,
}

impl TaskLease {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }
    pub fn worker_generation(&self) -> u64 {
        self.worker_generation
    }
    pub fn task_generation(&self) -> u64 {
        self.task_generation
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn lease_id(&self) -> u64 {
        self.lease_id
    }
    pub fn acquired_at(&self) -> u64 {
        self.acquired_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Optimistic ownership fence for a queued task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedTaskFence {
    task_id: String,
    task_generation: u64,
    record_version: u64,
}

impl QueuedTaskFence {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn task_generation(&self) -> u64 {
        self.task_generation
    }
    pub fn record_version(&self) -> u64 {
        self.record_version
    }
}

/// Exact logical cancellation fence for queued or leased work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOwnership {
    Queued(QueuedTaskFence),
    Leased(TaskLease),
}

impl TaskOwnership {
    fn task_id(&self) -> &str {
        match self {
            Self::Queued(fence) => &fence.task_id,
            Self::Leased(lease) => &lease.task_id,
        }
    }
}

/// Versioned task snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct ScanTask {
    task_id: String,
    scan_id: String,
    target_ref: String,
    phases: Vec<u8>,
    status: TaskStatus,
    priority: TaskPriority,
    created_at: u64,
    started_at: Option<u64>,
    completed_at: Option<u64>,
    retry_count: u32,
    attempt: u32,
    task_generation: u64,
    record_version: u64,
    assigned_to: Option<String>,
    lease: Option<TaskLease>,
}

impl std::fmt::Debug for ScanTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanTask")
            .field("task_id", &self.task_id)
            .field("scan_id", &self.scan_id)
            .field("target_ref", &"<opaque>")
            .field("phases", &self.phases)
            .field("status", &self.status)
            .field("priority", &self.priority)
            .field("created_at", &self.created_at)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .field("retry_count", &self.retry_count)
            .field("attempt", &self.attempt)
            .field("task_generation", &self.task_generation)
            .field("record_version", &self.record_version)
            .field("assigned_to", &self.assigned_to)
            .field("lease", &self.lease)
            .finish()
    }
}

impl ScanTask {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    pub fn target_ref(&self) -> &str {
        &self.target_ref
    }

    pub fn phases(&self) -> &[u8] {
        &self.phases
    }

    pub fn status(&self) -> TaskStatus {
        self.status
    }

    pub fn priority(&self) -> TaskPriority {
        self.priority
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn started_at(&self) -> Option<u64> {
        self.started_at
    }

    pub fn completed_at(&self) -> Option<u64> {
        self.completed_at
    }

    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn task_generation(&self) -> u64 {
        self.task_generation
    }

    pub fn record_version(&self) -> u64 {
        self.record_version
    }

    pub fn assigned_to(&self) -> Option<&str> {
        self.assigned_to.as_deref()
    }

    pub fn lease(&self) -> Option<&TaskLease> {
        self.lease.as_ref()
    }

    pub fn ownership(&self) -> Option<TaskOwnership> {
        match self.status {
            TaskStatus::Queued => Some(TaskOwnership::Queued(QueuedTaskFence {
                task_id: self.task_id.clone(),
                task_generation: self.task_generation,
                record_version: self.record_version,
            })),
            TaskStatus::Leased | TaskStatus::Running => {
                self.lease.clone().map(TaskOwnership::Leased)
            },
            _ => None,
        }
    }

    pub fn age_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.created_at)
    }
}

/// A successful command result and the revision after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition<T> {
    pub revision: u64,
    pub value: T,
}

/// Bounded coordinator state summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateSnapshot {
    pub revision: u64,
    pub logical_time: u64,
    pub task_records: usize,
    pub active_tasks: usize,
    pub queued_tasks: usize,
    pub terminal_tasks: usize,
    pub workers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct QueueKey {
    inverted_priority: u8,
    enqueue_ordinal: u64,
    task_id: String,
}

impl QueueKey {
    fn new(priority: TaskPriority, enqueue_ordinal: u64, task_id: String) -> Self {
        Self {
            inverted_priority: u8::MAX - priority as u8,
            enqueue_ordinal,
            task_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CancellationProof {
    Queued(QueuedTaskFence),
    Leased(TaskLease),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FailureProof {
    lease: TaskLease,
    outcome: FailureOutcome,
}

impl CancellationProof {
    fn matches(&self, ownership: &TaskOwnership) -> bool {
        matches!(
            (self, ownership),
            (Self::Queued(left), TaskOwnership::Queued(right)) if left == right
        ) || matches!(
            (self, ownership),
            (Self::Leased(left), TaskOwnership::Leased(right)) if left == right
        )
    }
}

#[derive(Debug, Clone)]
struct TaskEntry {
    task: ScanTask,
    queue_key: Option<QueueKey>,
    completion: Option<CompletionReceipt>,
    cancellation: Option<CancellationProof>,
    failure: Option<FailureProof>,
}

struct CoordinatorState {
    limits: DistributedLimits,
    revision: u64,
    logical_time: u64,
    tasks: BTreeMap<String, TaskEntry>,
    queue: BTreeSet<QueueKey>,
    workers: BTreeMap<String, WorkerNode>,
    active_tasks: usize,
    terminal_tasks: usize,
    next_enqueue_ordinal: u64,
    next_lease_id: u64,
}

impl CoordinatorState {
    fn new(limits: DistributedLimits) -> Self {
        Self {
            limits,
            revision: 0,
            logical_time: 0,
            tasks: BTreeMap::new(),
            queue: BTreeSet::new(),
            workers: BTreeMap::new(),
            active_tasks: 0,
            terminal_tasks: 0,
            next_enqueue_ordinal: 1,
            next_lease_id: 1,
        }
    }

    fn preflight_command(
        &self,
        expected_revision: u64,
        now_secs: u64,
    ) -> Result<u64, DistributedError> {
        if expected_revision != self.revision {
            return Err(DistributedError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if now_secs < self.logical_time {
            return Err(DistributedError::LogicalTimeRegression {
                current: self.logical_time,
                proposed: now_secs,
            });
        }
        self.revision
            .checked_add(1)
            .ok_or(DistributedError::CounterExhausted {
                counter: "revision",
            })
    }

    fn commit(&mut self, revision: u64, now_secs: u64) {
        self.revision = revision;
        self.logical_time = now_secs;
    }

    fn next_task_id(&self) -> Option<String> {
        self.queue.first().map(|key| key.task_id.clone())
    }

    fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            revision: self.revision,
            logical_time: self.logical_time,
            task_records: self.tasks.len(),
            active_tasks: self.active_tasks,
            queued_tasks: self.queue.len(),
            terminal_tasks: self.terminal_tasks,
            workers: self.workers.len(),
        }
    }
}

fn lock_state(
    state: &Arc<Mutex<CoordinatorState>>,
) -> Result<MutexGuard<'_, CoordinatorState>, DistributedError> {
    state.lock().map_err(|_| DistributedError::StatePoisoned)
}

fn next_counter(value: u64, counter: &'static str) -> Result<u64, DistributedError> {
    value
        .checked_add(1)
        .ok_or(DistributedError::CounterExhausted { counter })
}

fn next_u32(value: u32, counter: &'static str) -> Result<u32, DistributedError> {
    value
        .checked_add(1)
        .ok_or(DistributedError::CounterExhausted { counter })
}

/// Cloneable task facade sharing the pool's single state lock.
#[derive(Clone)]
pub struct TaskQueue {
    state: Arc<Mutex<CoordinatorState>>,
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CoordinatorState::new(
                DistributedLimits::default(),
            ))),
        }
    }

    pub fn with_limits(limits: DistributedLimits) -> Result<Self, DistributedError> {
        validate_limits(limits)?;
        Ok(Self {
            state: Arc::new(Mutex::new(CoordinatorState::new(limits))),
        })
    }

    /// Admit one fresh task at an exact coordinator revision.
    pub fn enqueue(
        &self,
        expected_revision: u64,
        now_secs: u64,
        spec: TaskSpec,
    ) -> Result<Transition<ScanTask>, DistributedError> {
        validate_task_spec(&spec)?;
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        if state.tasks.contains_key(&spec.task_id) {
            return Err(DistributedError::TaskAlreadyExists {
                task_id: spec.task_id,
            });
        }
        if state.tasks.len() >= state.limits.max_task_records {
            return Err(DistributedError::TaskRecordCapacityReached {
                limit: state.limits.max_task_records,
            });
        }
        if state.active_tasks >= state.limits.max_active_tasks {
            return Err(DistributedError::ActiveTaskCapacityReached {
                limit: state.limits.max_active_tasks,
            });
        }
        if state.queue.len() >= state.limits.max_queued_tasks {
            return Err(DistributedError::QueuedTaskCapacityReached {
                limit: state.limits.max_queued_tasks,
            });
        }
        if state
            .terminal_tasks
            .checked_add(state.active_tasks)
            .and_then(|value| value.checked_add(1))
            .is_none_or(|value| value > state.limits.max_terminal_tasks)
        {
            return Err(DistributedError::TerminalCapacityReserved {
                limit: state.limits.max_terminal_tasks,
            });
        }
        let next_ordinal = next_counter(state.next_enqueue_ordinal, "enqueue_ordinal")?;
        let task = ScanTask {
            task_id: spec.task_id,
            scan_id: spec.scan_id,
            target_ref: spec.target_ref,
            phases: spec.phases,
            status: TaskStatus::Queued,
            priority: spec.priority,
            created_at: now_secs,
            started_at: None,
            completed_at: None,
            retry_count: 0,
            attempt: 0,
            task_generation: 0,
            record_version: 1,
            assigned_to: None,
            lease: None,
        };
        let key = QueueKey::new(
            task.priority,
            state.next_enqueue_ordinal,
            task.task_id.clone(),
        );
        state.next_enqueue_ordinal = next_ordinal;
        state.queue.insert(key.clone());
        state.tasks.insert(
            task.task_id.clone(),
            TaskEntry {
                task: task.clone(),
                queue_key: Some(key),
                completion: None,
                cancellation: None,
                failure: None,
            },
        );
        state.active_tasks += 1;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: task,
        })
    }

    /// Peek without consuming or mutating the task record.
    pub fn peek_next(&self) -> Result<Option<ScanTask>, DistributedError> {
        let state = lock_state(&self.state)?;
        let Some(task_id) = state.next_task_id() else {
            return Ok(None);
        };
        state
            .tasks
            .get(&task_id)
            .map(|entry| Some(entry.task.clone()))
            .ok_or(DistributedError::StateInvariant {
                reason: "queue key references a missing task",
            })
    }

    pub fn get_task(&self, task_id: &str) -> Result<Option<ScanTask>, DistributedError> {
        validate_task_command_id(task_id)?;
        Ok(lock_state(&self.state)?
            .tasks
            .get(task_id)
            .map(|entry| entry.task.clone()))
    }

    /// Return tasks in stable task-ID order.
    pub fn tasks(&self) -> Result<Vec<ScanTask>, DistributedError> {
        Ok(lock_state(&self.state)?
            .tasks
            .values()
            .map(|entry| entry.task.clone())
            .collect())
    }

    pub fn snapshot(&self) -> Result<StateSnapshot, DistributedError> {
        Ok(lock_state(&self.state)?.snapshot())
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Exact receipt for a terminal completion. Fields are intentionally private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionReceipt {
    task_id: String,
    task_generation: u64,
    attempt: u32,
    lease_id: u64,
    worker_id: String,
    worker_generation: u64,
    record_version: u64,
}

impl CompletionReceipt {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn task_generation(&self) -> u64 {
        self.task_generation
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn lease_id(&self) -> u64 {
        self.lease_id
    }
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }
    pub fn worker_generation(&self) -> u64 {
        self.worker_generation
    }
    pub fn record_version(&self) -> u64 {
        self.record_version
    }

    fn matches_lease(&self, lease: &TaskLease) -> bool {
        self.task_id == lease.task_id
            && self.task_generation == lease.task_generation
            && self.attempt == lease.attempt
            && self.lease_id == lease.lease_id
            && self.worker_id == lease.worker_id
            && self.worker_generation == lease.worker_generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    Started { record_version: u64 },
    AlreadyRunning { record_version: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    Completed(CompletionReceipt),
    AlreadyCompleted(CompletionReceipt),
}

impl CompletionOutcome {
    pub fn receipt(&self) -> &CompletionReceipt {
        match self {
            Self::Completed(receipt) | Self::AlreadyCompleted(receipt) => receipt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancellationOutcome {
    Cancelled { record_version: u64 },
    AlreadyCancelled { record_version: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureOutcome {
    Requeued {
        task_generation: u64,
        retry_count: u32,
        record_version: u64,
    },
    RetryExhausted {
        retry_count: u32,
        record_version: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoverySummary {
    pub workers_affected: usize,
    pub tasks_requeued: usize,
    pub tasks_failed: usize,
}

/// Atomic worker/task coordinator. All clones share one revisioned state lock.
#[derive(Clone)]
pub struct WorkerPool {
    state: Arc<Mutex<CoordinatorState>>,
    task_queue: TaskQueue,
}

impl WorkerPool {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(CoordinatorState::new(
            DistributedLimits::default(),
        )));
        Self {
            task_queue: TaskQueue {
                state: Arc::clone(&state),
            },
            state,
        }
    }

    pub fn with_limits(limits: DistributedLimits) -> Result<Self, DistributedError> {
        validate_limits(limits)?;
        let state = Arc::new(Mutex::new(CoordinatorState::new(limits)));
        Ok(Self {
            task_queue: TaskQueue {
                state: Arc::clone(&state),
            },
            state,
        })
    }

    pub fn snapshot(&self) -> Result<StateSnapshot, DistributedError> {
        Ok(lock_state(&self.state)?.snapshot())
    }

    /// Return a cloneable task facade guaranteed to share this pool's state.
    pub fn task_queue(&self) -> TaskQueue {
        self.task_queue.clone()
    }

    /// Register a never-before-seen worker. Duplicate IDs never overwrite.
    pub fn register_worker(
        &self,
        expected_revision: u64,
        now_secs: u64,
        spec: WorkerSpec,
    ) -> Result<Transition<WorkerNode>, DistributedError> {
        validate_worker_spec(&spec)?;
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        if state.workers.contains_key(&spec.worker_id) {
            return Err(DistributedError::WorkerAlreadyExists {
                worker_id: spec.worker_id,
            });
        }
        if state.workers.len() >= state.limits.max_workers {
            return Err(DistributedError::WorkerCapacityReached {
                limit: state.limits.max_workers,
            });
        }
        let worker = WorkerNode {
            worker_id: spec.worker_id,
            generation: 1,
            status: WorkerStatus::Healthy,
            capacity: spec.capacity,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: now_secs,
            cpu_basis_points: spec.cpu_basis_points,
            memory_basis_points: spec.memory_basis_points,
            network_basis_points: spec.network_basis_points,
            tags: spec.tags,
        };
        state
            .workers
            .insert(worker.worker_id.clone(), worker.clone());
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: worker,
        })
    }

    /// Reactivate an offline worker under a new generation fence.
    pub fn reactivate_worker(
        &self,
        expected_revision: u64,
        now_secs: u64,
        expected_generation: u64,
        spec: WorkerSpec,
    ) -> Result<Transition<WorkerNode>, DistributedError> {
        validate_worker_spec(&spec)?;
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let current = state.workers.get(&spec.worker_id).cloned().ok_or_else(|| {
            DistributedError::WorkerNotFound {
                worker_id: spec.worker_id.clone(),
            }
        })?;
        if current.generation != expected_generation {
            return Err(DistributedError::WorkerGenerationConflict {
                expected: expected_generation,
                actual: current.generation,
            });
        }
        if current.status != WorkerStatus::Offline || current.current_tasks != 0 {
            return Err(DistributedError::WorkerUnavailable {
                worker_id: spec.worker_id,
            });
        }
        let generation = next_counter(current.generation, "worker_generation")?;
        let worker = WorkerNode {
            worker_id: spec.worker_id,
            generation,
            status: WorkerStatus::Healthy,
            capacity: spec.capacity,
            current_tasks: 0,
            completed_tasks: current.completed_tasks,
            last_heartbeat: now_secs,
            cpu_basis_points: spec.cpu_basis_points,
            memory_basis_points: spec.memory_basis_points,
            network_basis_points: spec.network_basis_points,
            tags: spec.tags,
        };
        state
            .workers
            .insert(worker.worker_id.clone(), worker.clone());
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: worker,
        })
    }

    /// Update heartbeat, eligibility state, and integer resource observations.
    pub fn update_worker(
        &self,
        expected_revision: u64,
        now_secs: u64,
        worker_id: &str,
        worker_generation: u64,
        observation: WorkerObservation,
    ) -> Result<Transition<WorkerNode>, DistributedError> {
        validate_worker_command_id(worker_id)?;
        if observation.status == WorkerStatus::Offline {
            return Err(DistributedError::InvalidWorker {
                reason: "offline transition requires deregister or prune",
            });
        }
        if observation.cpu_basis_points > UTILIZATION_BASIS_POINTS
            || observation.memory_basis_points > UTILIZATION_BASIS_POINTS
            || observation.network_basis_points > UTILIZATION_BASIS_POINTS
        {
            return Err(DistributedError::InvalidWorker {
                reason: "utilization exceeds 10000 basis points",
            });
        }
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let current = state.workers.get(worker_id).cloned().ok_or_else(|| {
            DistributedError::WorkerNotFound {
                worker_id: worker_id.to_owned(),
            }
        })?;
        if current.generation != worker_generation {
            return Err(DistributedError::WorkerGenerationConflict {
                expected: worker_generation,
                actual: current.generation,
            });
        }
        if current.status == WorkerStatus::Offline {
            return Err(DistributedError::WorkerUnavailable {
                worker_id: worker_id.to_owned(),
            });
        }
        let worker = state
            .workers
            .get_mut(worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "worker disappeared during update",
            })?;
        worker.status = observation.status;
        worker.last_heartbeat = now_secs;
        worker.cpu_basis_points = observation.cpu_basis_points;
        worker.memory_basis_points = observation.memory_basis_points;
        worker.network_basis_points = observation.network_basis_points;
        let snapshot = worker.clone();
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: snapshot,
        })
    }

    /// Return the deterministically selected eligible worker at logical time.
    pub fn get_available_worker(
        &self,
        now_secs: u64,
    ) -> Result<Option<WorkerNode>, DistributedError> {
        let state = lock_state(&self.state)?;
        ensure_observation_time(&state, now_secs)?;
        Ok(best_worker_id(&state, now_secs)
            .and_then(|worker_id| state.workers.get(&worker_id).cloned()))
    }

    /// Atomically assign a specific queued task to a specific worker.
    pub fn assign_task(
        &self,
        expected_revision: u64,
        now_secs: u64,
        task_id: &str,
        worker_id: &str,
        lease_ttl_secs: u64,
    ) -> Result<Transition<TaskLease>, DistributedError> {
        validate_task_command_id(task_id)?;
        validate_worker_command_id(worker_id)?;
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let lease = prepare_assignment(&state, task_id, worker_id, now_secs, lease_ttl_secs)?;
        apply_assignment(&mut state, &lease)?;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: lease,
        })
    }

    /// Atomically assign the highest-priority FIFO task to a specific worker.
    pub fn assign_next(
        &self,
        expected_revision: u64,
        now_secs: u64,
        worker_id: &str,
        lease_ttl_secs: u64,
    ) -> Result<Transition<TaskLease>, DistributedError> {
        validate_worker_command_id(worker_id)?;
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let task_id = state.next_task_id().ok_or(DistributedError::NoQueuedTask)?;
        let lease = prepare_assignment(&state, &task_id, worker_id, now_secs, lease_ttl_secs)?;
        apply_assignment(&mut state, &lease)?;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: lease,
        })
    }

    /// Atomically choose both task and worker. Equal worker keys choose the
    /// lexicographically smallest worker ID.
    pub fn assign_next_available(
        &self,
        expected_revision: u64,
        now_secs: u64,
        lease_ttl_secs: u64,
    ) -> Result<Transition<TaskLease>, DistributedError> {
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let task_id = state.next_task_id().ok_or(DistributedError::NoQueuedTask)?;
        let worker_id =
            best_worker_id(&state, now_secs).ok_or(DistributedError::NoAvailableWorker)?;
        let lease = prepare_assignment(&state, &task_id, &worker_id, now_secs, lease_ttl_secs)?;
        apply_assignment(&mut state, &lease)?;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: lease,
        })
    }

    /// Transition a lease from `Leased` to `Running`. Exact replay is a no-op.
    pub fn start_task(
        &self,
        expected_revision: u64,
        now_secs: u64,
        lease: &TaskLease,
    ) -> Result<Transition<StartOutcome>, DistributedError> {
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let entry =
            state
                .tasks
                .get(&lease.task_id)
                .ok_or_else(|| DistributedError::TaskNotFound {
                    task_id: lease.task_id.clone(),
                })?;
        ensure_current_lease(entry, lease, now_secs)?;
        if entry.task.status == TaskStatus::Running {
            return Ok(Transition {
                revision: state.revision,
                value: StartOutcome::AlreadyRunning {
                    record_version: entry.task.record_version,
                },
            });
        }
        if entry.task.status != TaskStatus::Leased {
            return Err(DistributedError::InvalidTransition {
                task_id: lease.task_id.clone(),
                status: entry.task.status,
                operation: "start",
            });
        }
        let record_version = next_counter(entry.task.record_version, "record_version")?;
        let entry =
            state
                .tasks
                .get_mut(&lease.task_id)
                .ok_or(DistributedError::StateInvariant {
                    reason: "task disappeared during start",
                })?;
        entry.task.status = TaskStatus::Running;
        entry.task.started_at = Some(now_secs);
        entry.task.record_version = record_version;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: StartOutcome::Started { record_version },
        })
    }

    /// Complete only the current lease. Exact replay returns the same receipt
    /// without changing revision or worker counters.
    pub fn complete_task(
        &self,
        expected_revision: u64,
        now_secs: u64,
        lease: &TaskLease,
    ) -> Result<Transition<CompletionOutcome>, DistributedError> {
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let entry =
            state
                .tasks
                .get(&lease.task_id)
                .ok_or_else(|| DistributedError::TaskNotFound {
                    task_id: lease.task_id.clone(),
                })?;
        if entry.task.status == TaskStatus::Completed {
            return match entry.completion.as_ref() {
                Some(receipt) if receipt.matches_lease(lease) => Ok(Transition {
                    revision: state.revision,
                    value: CompletionOutcome::AlreadyCompleted(receipt.clone()),
                }),
                _ => Err(DistributedError::StaleOwnership {
                    task_id: lease.task_id.clone(),
                }),
            };
        }
        ensure_current_lease(entry, lease, now_secs)?;
        if entry.task.status != TaskStatus::Running {
            return Err(DistributedError::InvalidTransition {
                task_id: lease.task_id.clone(),
                status: entry.task.status,
                operation: "complete",
            });
        }
        let record_version = next_counter(entry.task.record_version, "record_version")?;
        preflight_worker_release(&state, lease)?;
        let completed_tasks = state
            .workers
            .get(&lease.worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "completion worker disappeared during preflight",
            })?
            .completed_tasks
            .checked_add(1)
            .ok_or(DistributedError::CounterExhausted {
                counter: "worker_completed_tasks",
            })?;
        let receipt = CompletionReceipt {
            task_id: lease.task_id.clone(),
            task_generation: lease.task_generation,
            attempt: lease.attempt,
            lease_id: lease.lease_id,
            worker_id: lease.worker_id.clone(),
            worker_generation: lease.worker_generation,
            record_version,
        };
        terminalize_leased_task(
            &mut state,
            lease,
            TaskStatus::Completed,
            now_secs,
            record_version,
        )?;
        let entry =
            state
                .tasks
                .get_mut(&lease.task_id)
                .ok_or(DistributedError::StateInvariant {
                    reason: "task disappeared during completion",
                })?;
        entry.completion = Some(receipt.clone());
        let worker =
            state
                .workers
                .get_mut(&lease.worker_id)
                .ok_or(DistributedError::StateInvariant {
                    reason: "worker disappeared during completion",
                })?;
        worker.completed_tasks = completed_tasks;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: CompletionOutcome::Completed(receipt),
        })
    }

    /// Cancel queued or leased work only with its exact ownership fence.
    /// Exact replay is a no-op; a different token fails closed.
    pub fn cancel_task(
        &self,
        expected_revision: u64,
        now_secs: u64,
        ownership: &TaskOwnership,
    ) -> Result<Transition<CancellationOutcome>, DistributedError> {
        let task_id = ownership.task_id().to_owned();
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let entry = state
            .tasks
            .get(&task_id)
            .ok_or_else(|| DistributedError::TaskNotFound {
                task_id: task_id.clone(),
            })?;
        if entry.task.status == TaskStatus::Cancelled {
            return match entry.cancellation.as_ref() {
                Some(proof) if proof.matches(ownership) => Ok(Transition {
                    revision: state.revision,
                    value: CancellationOutcome::AlreadyCancelled {
                        record_version: entry.task.record_version,
                    },
                }),
                _ => Err(DistributedError::StaleOwnership { task_id }),
            };
        }
        validate_cancellation_ownership(entry, ownership, now_secs)?;
        let record_version = next_counter(entry.task.record_version, "record_version")?;
        let proof = match ownership {
            TaskOwnership::Queued(fence) => CancellationProof::Queued(fence.clone()),
            TaskOwnership::Leased(lease) => {
                preflight_worker_release(&state, lease)?;
                CancellationProof::Leased(lease.clone())
            },
        };
        match ownership {
            TaskOwnership::Queued(_) => terminalize_queued_task(
                &mut state,
                &task_id,
                TaskStatus::Cancelled,
                now_secs,
                record_version,
            )?,
            TaskOwnership::Leased(lease) => terminalize_leased_task(
                &mut state,
                lease,
                TaskStatus::Cancelled,
                now_secs,
                record_version,
            )?,
        }
        let entry = state
            .tasks
            .get_mut(&task_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "task disappeared during cancellation",
            })?;
        entry.cancellation = Some(proof);
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: CancellationOutcome::Cancelled { record_version },
        })
    }

    /// Fail the current attempt. Retry policy is fixed in [`DistributedLimits`].
    pub fn fail_task(
        &self,
        expected_revision: u64,
        now_secs: u64,
        lease: &TaskLease,
    ) -> Result<Transition<FailureOutcome>, DistributedError> {
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let entry =
            state
                .tasks
                .get(&lease.task_id)
                .ok_or_else(|| DistributedError::TaskNotFound {
                    task_id: lease.task_id.clone(),
                })?;
        if entry.task.status == TaskStatus::Failed {
            return match entry.failure.as_ref() {
                Some(proof) if proof.lease == *lease => Ok(Transition {
                    revision: state.revision,
                    value: proof.outcome.clone(),
                }),
                _ => Err(DistributedError::StaleOwnership {
                    task_id: lease.task_id.clone(),
                }),
            };
        }
        ensure_current_lease(entry, lease, now_secs)?;
        if entry.task.status != TaskStatus::Running {
            return Err(DistributedError::InvalidTransition {
                task_id: lease.task_id.clone(),
                status: entry.task.status,
                operation: "fail",
            });
        }
        preflight_worker_release(&state, lease)?;
        let record_version = next_counter(entry.task.record_version, "record_version")?;
        if entry.task.retry_count < state.limits.max_retries {
            if state.queue.len() >= state.limits.max_queued_tasks {
                return Err(DistributedError::QueuedTaskCapacityReached {
                    limit: state.limits.max_queued_tasks,
                });
            }
            let retry_count = next_u32(entry.task.retry_count, "retry_count")?;
            let task_generation = next_counter(entry.task.task_generation, "task_generation")?;
            let enqueue_ordinal = state.next_enqueue_ordinal;
            let next_ordinal = next_counter(enqueue_ordinal, "enqueue_ordinal")?;
            release_worker(&mut state, lease)?;
            let entry =
                state
                    .tasks
                    .get_mut(&lease.task_id)
                    .ok_or(DistributedError::StateInvariant {
                        reason: "task disappeared during retry",
                    })?;
            entry.task.status = TaskStatus::Queued;
            entry.task.assigned_to = None;
            entry.task.lease = None;
            entry.task.started_at = None;
            entry.task.retry_count = retry_count;
            entry.task.task_generation = task_generation;
            entry.task.record_version = record_version;
            let key = QueueKey::new(entry.task.priority, enqueue_ordinal, lease.task_id.clone());
            entry.queue_key = Some(key.clone());
            state.queue.insert(key);
            state.next_enqueue_ordinal = next_ordinal;
            state.commit(revision, now_secs);
            Ok(Transition {
                revision,
                value: FailureOutcome::Requeued {
                    task_generation,
                    retry_count,
                    record_version,
                },
            })
        } else {
            let outcome = FailureOutcome::RetryExhausted {
                retry_count: entry.task.retry_count,
                record_version,
            };
            terminalize_leased_task(
                &mut state,
                lease,
                TaskStatus::Failed,
                now_secs,
                record_version,
            )?;
            let entry =
                state
                    .tasks
                    .get_mut(&lease.task_id)
                    .ok_or(DistributedError::StateInvariant {
                        reason: "failed task disappeared",
                    })?;
            entry.failure = Some(FailureProof {
                lease: lease.clone(),
                outcome: outcome.clone(),
            });
            state.commit(revision, now_secs);
            Ok(Transition {
                revision,
                value: outcome,
            })
        }
    }

    /// Mark a worker offline, fence its generation, and recover every lease it
    /// owned in original lease order under the fixed retry policy.
    pub fn deregister_worker(
        &self,
        expected_revision: u64,
        now_secs: u64,
        worker_id: &str,
        worker_generation: u64,
    ) -> Result<Transition<RecoverySummary>, DistributedError> {
        validate_worker_command_id(worker_id)?;
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let worker = state.workers.get(worker_id).cloned().ok_or_else(|| {
            DistributedError::WorkerNotFound {
                worker_id: worker_id.to_owned(),
            }
        })?;
        if worker.generation != worker_generation {
            return Err(DistributedError::WorkerGenerationConflict {
                expected: worker_generation,
                actual: worker.generation,
            });
        }
        if worker.status == WorkerStatus::Offline {
            return Err(DistributedError::WorkerUnavailable {
                worker_id: worker_id.to_owned(),
            });
        }
        let next_generation = next_counter(worker.generation, "worker_generation")?;
        let task_ids = leased_task_ids(&state, |lease| lease.worker_id == worker_id);
        preflight_recovery(&state, &task_ids)?;
        let mut tasks_requeued = 0usize;
        let mut tasks_failed = 0usize;
        for task_id in &task_ids {
            match apply_recovery(&mut state, task_id, now_secs)? {
                RecoveryDisposition::Requeued => tasks_requeued += 1,
                RecoveryDisposition::Failed => tasks_failed += 1,
            }
        }
        let worker = state
            .workers
            .get_mut(worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "worker disappeared during deregistration",
            })?;
        if worker.current_tasks != 0 {
            return Err(DistributedError::StateInvariant {
                reason: "worker retained active tasks after recovery",
            });
        }
        worker.status = WorkerStatus::Offline;
        worker.generation = next_generation;
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: RecoverySummary {
                workers_affected: 1,
                tasks_requeued,
                tasks_failed,
            },
        })
    }

    /// Recover every lease at or beyond its deadline (`now >= expires_at`) under
    /// the fixed retry policy.
    pub fn recover_expired_leases(
        &self,
        expected_revision: u64,
        now_secs: u64,
    ) -> Result<Transition<RecoverySummary>, DistributedError> {
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let task_ids = leased_task_ids(&state, |lease| now_secs >= lease.expires_at);
        preflight_recovery(&state, &task_ids)?;
        let workers: BTreeSet<String> = task_ids
            .iter()
            .filter_map(|task_id| {
                state
                    .tasks
                    .get(task_id)
                    .and_then(|entry| entry.task.assigned_to.clone())
            })
            .collect();
        let mut tasks_requeued = 0usize;
        let mut tasks_failed = 0usize;
        for task_id in &task_ids {
            match apply_recovery(&mut state, task_id, now_secs)? {
                RecoveryDisposition::Requeued => tasks_requeued += 1,
                RecoveryDisposition::Failed => tasks_failed += 1,
            }
        }
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: RecoverySummary {
                workers_affected: workers.len(),
                tasks_requeued,
                tasks_failed,
            },
        })
    }

    /// Mark heartbeat-stale workers offline and recover their leases. Stale
    /// workers are already ineligible for assignment before this command runs.
    pub fn prune_dead_workers(
        &self,
        expected_revision: u64,
        now_secs: u64,
    ) -> Result<Transition<RecoverySummary>, DistributedError> {
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        let dead_workers: Vec<String> = state
            .workers
            .iter()
            .filter(|(_, worker)| {
                worker.status != WorkerStatus::Offline
                    && now_secs.saturating_sub(worker.last_heartbeat)
                        > state.limits.heartbeat_timeout_secs
            })
            .map(|(worker_id, _)| worker_id.clone())
            .collect();
        for worker_id in &dead_workers {
            let worker = state
                .workers
                .get(worker_id)
                .ok_or(DistributedError::StateInvariant {
                    reason: "dead worker disappeared during preflight",
                })?;
            next_counter(worker.generation, "worker_generation")?;
        }
        let dead_set: BTreeSet<&str> = dead_workers.iter().map(String::as_str).collect();
        let task_ids = leased_task_ids(&state, |lease| dead_set.contains(lease.worker_id.as_str()));
        preflight_recovery(&state, &task_ids)?;
        let mut tasks_requeued = 0usize;
        let mut tasks_failed = 0usize;
        for task_id in &task_ids {
            match apply_recovery(&mut state, task_id, now_secs)? {
                RecoveryDisposition::Requeued => tasks_requeued += 1,
                RecoveryDisposition::Failed => tasks_failed += 1,
            }
        }
        for worker_id in &dead_workers {
            let worker =
                state
                    .workers
                    .get_mut(worker_id)
                    .ok_or(DistributedError::StateInvariant {
                        reason: "dead worker disappeared during prune",
                    })?;
            if worker.current_tasks != 0 {
                return Err(DistributedError::StateInvariant {
                    reason: "pruned worker retained active tasks",
                });
            }
            worker.status = WorkerStatus::Offline;
            worker.generation = next_counter(worker.generation, "worker_generation")?;
        }
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: RecoverySummary {
                workers_affected: dead_workers.len(),
                tasks_requeued,
                tasks_failed,
            },
        })
    }

    /// Terminally expire every active task whose age reaches `task_ttl_secs`.
    pub fn expire_old_tasks(
        &self,
        expected_revision: u64,
        now_secs: u64,
        task_ttl_secs: u64,
    ) -> Result<Transition<usize>, DistributedError> {
        if task_ttl_secs == 0 {
            return Err(DistributedError::InvalidLimit {
                name: "task_ttl_secs",
            });
        }
        let mut state = lock_state(&self.state)?;
        let revision = state.preflight_command(expected_revision, now_secs)?;
        if task_ttl_secs > state.limits.max_task_ttl_secs {
            return Err(DistributedError::InvalidLimitRelationship {
                reason: "task_ttl_secs exceeds configured maximum",
            });
        }
        let task_ids: Vec<String> = state
            .tasks
            .iter()
            .filter(|(_, entry)| {
                entry.task.status.is_active() && entry.task.age_secs(now_secs) >= task_ttl_secs
            })
            .map(|(task_id, _)| task_id.clone())
            .collect();
        for task_id in &task_ids {
            let entry = state
                .tasks
                .get(task_id)
                .ok_or(DistributedError::StateInvariant {
                    reason: "expiring task disappeared during preflight",
                })?;
            next_counter(entry.task.record_version, "record_version")?;
            match entry.task.status {
                TaskStatus::Queued => ensure_queue_entry(&state, entry)?,
                TaskStatus::Leased | TaskStatus::Running => {
                    let lease =
                        entry
                            .task
                            .lease
                            .as_ref()
                            .ok_or(DistributedError::StateInvariant {
                                reason: "leased task has no lease during expiry",
                            })?;
                    preflight_worker_release(&state, lease)?;
                },
                _ => {},
            }
        }
        for task_id in &task_ids {
            let task = state
                .tasks
                .get(task_id)
                .map(|entry| entry.task.clone())
                .ok_or(DistributedError::StateInvariant {
                    reason: "expiring task disappeared",
                })?;
            let record_version = next_counter(task.record_version, "record_version")?;
            match task.status {
                TaskStatus::Queued => terminalize_queued_task(
                    &mut state,
                    task_id,
                    TaskStatus::Expired,
                    now_secs,
                    record_version,
                )?,
                TaskStatus::Leased | TaskStatus::Running => {
                    let lease = task
                        .lease
                        .as_ref()
                        .ok_or(DistributedError::StateInvariant {
                            reason: "leased task lost lease during expiry",
                        })?;
                    terminalize_leased_task(
                        &mut state,
                        lease,
                        TaskStatus::Expired,
                        now_secs,
                        record_version,
                    )?;
                },
                _ => {},
            }
        }
        state.commit(revision, now_secs);
        Ok(Transition {
            revision,
            value: task_ids.len(),
        })
    }

    /// Return workers in stable worker-ID order.
    pub fn get_workers(&self) -> Result<Vec<WorkerNode>, DistributedError> {
        Ok(lock_state(&self.state)?.workers.values().cloned().collect())
    }

    pub fn get_worker(&self, worker_id: &str) -> Result<Option<WorkerNode>, DistributedError> {
        validate_worker_command_id(worker_id)?;
        Ok(lock_state(&self.state)?.workers.get(worker_id).cloned())
    }

    /// Actively verify all cross-record invariants.
    pub fn check_invariants(&self) -> Result<(), DistributedError> {
        let state = lock_state(&self.state)?;
        check_state_invariants(&state)
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

fn ensure_observation_time(
    state: &CoordinatorState,
    now_secs: u64,
) -> Result<(), DistributedError> {
    if now_secs < state.logical_time {
        return Err(DistributedError::LogicalTimeRegression {
            current: state.logical_time,
            proposed: now_secs,
        });
    }
    Ok(())
}

type WorkerSelectionKey = (u32, u64, u16, u16, u16);

fn best_worker_id(state: &CoordinatorState, now_secs: u64) -> Option<String> {
    let mut best: Option<(&str, WorkerSelectionKey)> = None;
    for (worker_id, worker) in &state.workers {
        if !worker.is_eligible(now_secs, state.limits.heartbeat_timeout_secs) {
            continue;
        }
        let key = worker.selection_key(now_secs);
        let replace = match best {
            None => true,
            Some((best_id, best_key)) => match key.cmp(&best_key) {
                Ordering::Greater => true,
                Ordering::Equal => worker_id.as_str() < best_id,
                Ordering::Less => false,
            },
        };
        if replace {
            best = Some((worker_id, key));
        }
    }
    best.map(|(worker_id, _)| worker_id.to_owned())
}

fn prepare_assignment(
    state: &CoordinatorState,
    task_id: &str,
    worker_id: &str,
    now_secs: u64,
    lease_ttl_secs: u64,
) -> Result<TaskLease, DistributedError> {
    if lease_ttl_secs == 0 {
        return Err(DistributedError::InvalidLimit {
            name: "lease_ttl_secs",
        });
    }
    if lease_ttl_secs > state.limits.max_lease_ttl_secs {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "lease_ttl_secs exceeds configured maximum",
        });
    }
    let entry = state
        .tasks
        .get(task_id)
        .ok_or_else(|| DistributedError::TaskNotFound {
            task_id: task_id.to_owned(),
        })?;
    if entry.task.status != TaskStatus::Queued {
        return Err(DistributedError::TaskNotQueued {
            task_id: task_id.to_owned(),
            status: entry.task.status,
        });
    }
    ensure_queue_entry(state, entry)?;
    let worker = state
        .workers
        .get(worker_id)
        .ok_or_else(|| DistributedError::WorkerNotFound {
            worker_id: worker_id.to_owned(),
        })?;
    if worker.status != WorkerStatus::Healthy
        || now_secs.saturating_sub(worker.last_heartbeat) > state.limits.heartbeat_timeout_secs
    {
        return Err(DistributedError::WorkerUnavailable {
            worker_id: worker_id.to_owned(),
        });
    }
    if worker.available_slots() == 0 {
        return Err(DistributedError::WorkerAtCapacity {
            worker_id: worker_id.to_owned(),
        });
    }
    next_u32(worker.current_tasks, "worker_current_tasks")?;
    let attempt = next_u32(entry.task.attempt, "attempt")?;
    next_counter(entry.task.record_version, "record_version")?;
    let expires_at =
        now_secs
            .checked_add(lease_ttl_secs)
            .ok_or(DistributedError::CounterExhausted {
                counter: "lease_deadline",
            })?;
    next_counter(state.next_lease_id, "lease_id")?;
    Ok(TaskLease {
        task_id: task_id.to_owned(),
        worker_id: worker_id.to_owned(),
        worker_generation: worker.generation,
        task_generation: entry.task.task_generation,
        attempt,
        lease_id: state.next_lease_id,
        acquired_at: now_secs,
        expires_at,
    })
}

fn apply_assignment(
    state: &mut CoordinatorState,
    lease: &TaskLease,
) -> Result<(), DistributedError> {
    let entry = state
        .tasks
        .get(&lease.task_id)
        .ok_or(DistributedError::StateInvariant {
            reason: "assignment task disappeared",
        })?;
    let queue_key = entry
        .queue_key
        .clone()
        .ok_or(DistributedError::StateInvariant {
            reason: "queued task has no queue key",
        })?;
    let record_version = next_counter(entry.task.record_version, "record_version")?;
    if !state.queue.remove(&queue_key) {
        return Err(DistributedError::StateInvariant {
            reason: "assignment queue key disappeared",
        });
    }
    let entry = state
        .tasks
        .get_mut(&lease.task_id)
        .ok_or(DistributedError::StateInvariant {
            reason: "assignment task disappeared during mutation",
        })?;
    entry.queue_key = None;
    entry.task.status = TaskStatus::Leased;
    entry.task.assigned_to = Some(lease.worker_id.clone());
    entry.task.attempt = lease.attempt;
    entry.task.lease = Some(lease.clone());
    entry.task.record_version = record_version;
    let worker =
        state
            .workers
            .get_mut(&lease.worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "assignment worker disappeared",
            })?;
    worker.current_tasks = next_u32(worker.current_tasks, "worker_current_tasks")?;
    state.next_lease_id = next_counter(state.next_lease_id, "lease_id")?;
    Ok(())
}

fn ensure_queue_entry(state: &CoordinatorState, entry: &TaskEntry) -> Result<(), DistributedError> {
    match entry.queue_key.as_ref() {
        Some(key) if state.queue.contains(key) && key.task_id == entry.task.task_id => Ok(()),
        _ => Err(DistributedError::StateInvariant {
            reason: "queued task does not have exactly one queue key",
        }),
    }
}

fn ensure_current_lease(
    entry: &TaskEntry,
    lease: &TaskLease,
    now_secs: u64,
) -> Result<(), DistributedError> {
    if entry.task.lease.as_ref() != Some(lease)
        || entry.task.task_generation != lease.task_generation
        || entry.task.attempt != lease.attempt
        || entry.task.assigned_to.as_deref() != Some(lease.worker_id.as_str())
    {
        return Err(DistributedError::StaleOwnership {
            task_id: lease.task_id.clone(),
        });
    }
    if now_secs >= lease.expires_at {
        return Err(DistributedError::LeaseExpired {
            task_id: lease.task_id.clone(),
        });
    }
    Ok(())
}

fn validate_cancellation_ownership(
    entry: &TaskEntry,
    ownership: &TaskOwnership,
    now_secs: u64,
) -> Result<(), DistributedError> {
    match ownership {
        TaskOwnership::Queued(fence) => {
            if entry.task.status != TaskStatus::Queued
                || entry.task.task_id != fence.task_id
                || entry.task.task_generation != fence.task_generation
                || entry.task.record_version != fence.record_version
            {
                return Err(DistributedError::StaleOwnership {
                    task_id: fence.task_id.clone(),
                });
            }
        },
        TaskOwnership::Leased(lease) => ensure_current_lease(entry, lease, now_secs)?,
    }
    Ok(())
}

fn preflight_worker_release(
    state: &CoordinatorState,
    lease: &TaskLease,
) -> Result<(), DistributedError> {
    let worker = state
        .workers
        .get(&lease.worker_id)
        .ok_or(DistributedError::StateInvariant {
            reason: "lease references a missing worker",
        })?;
    if worker.generation != lease.worker_generation || worker.current_tasks == 0 {
        return Err(DistributedError::StateInvariant {
            reason: "worker generation or active count disagrees with lease",
        });
    }
    Ok(())
}

fn release_worker(state: &mut CoordinatorState, lease: &TaskLease) -> Result<(), DistributedError> {
    let worker =
        state
            .workers
            .get_mut(&lease.worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "lease worker disappeared during release",
            })?;
    if worker.generation != lease.worker_generation || worker.current_tasks == 0 {
        return Err(DistributedError::StateInvariant {
            reason: "worker cannot release lease exactly once",
        });
    }
    worker.current_tasks -= 1;
    Ok(())
}

fn terminalize_queued_task(
    state: &mut CoordinatorState,
    task_id: &str,
    terminal_status: TaskStatus,
    now_secs: u64,
    record_version: u64,
) -> Result<(), DistributedError> {
    let entry = state
        .tasks
        .get(task_id)
        .ok_or(DistributedError::StateInvariant {
            reason: "queued terminal task disappeared",
        })?;
    if entry.task.status != TaskStatus::Queued || terminal_status.is_active() {
        return Err(DistributedError::StateInvariant {
            reason: "invalid queued terminalization",
        });
    }
    let key = entry
        .queue_key
        .clone()
        .ok_or(DistributedError::StateInvariant {
            reason: "queued terminal task has no queue key",
        })?;
    if !state.queue.remove(&key) {
        return Err(DistributedError::StateInvariant {
            reason: "queued terminal key disappeared",
        });
    }
    let entry = state
        .tasks
        .get_mut(task_id)
        .ok_or(DistributedError::StateInvariant {
            reason: "queued terminal task disappeared during mutation",
        })?;
    entry.queue_key = None;
    entry.task.status = terminal_status;
    entry.task.completed_at = Some(now_secs);
    entry.task.record_version = record_version;
    state.active_tasks -= 1;
    state.terminal_tasks += 1;
    Ok(())
}

fn terminalize_leased_task(
    state: &mut CoordinatorState,
    lease: &TaskLease,
    terminal_status: TaskStatus,
    now_secs: u64,
    record_version: u64,
) -> Result<(), DistributedError> {
    if terminal_status.is_active() {
        return Err(DistributedError::StateInvariant {
            reason: "leased terminalization received active status",
        });
    }
    preflight_worker_release(state, lease)?;
    release_worker(state, lease)?;
    let entry = state
        .tasks
        .get_mut(&lease.task_id)
        .ok_or(DistributedError::StateInvariant {
            reason: "leased terminal task disappeared",
        })?;
    entry.task.status = terminal_status;
    entry.task.assigned_to = None;
    entry.task.lease = None;
    entry.task.completed_at = Some(now_secs);
    entry.task.record_version = record_version;
    state.active_tasks -= 1;
    state.terminal_tasks += 1;
    Ok(())
}

fn leased_task_ids<F>(state: &CoordinatorState, mut predicate: F) -> Vec<String>
where
    F: FnMut(&TaskLease) -> bool,
{
    let mut leased: Vec<(u64, String)> = state
        .tasks
        .iter()
        .filter_map(|(task_id, entry)| {
            entry
                .task
                .lease
                .as_ref()
                .filter(|lease| predicate(lease))
                .map(|lease| (lease.lease_id, task_id.clone()))
        })
        .collect();
    leased.sort();
    leased.into_iter().map(|(_, task_id)| task_id).collect()
}

fn preflight_recovery(
    state: &CoordinatorState,
    task_ids: &[String],
) -> Result<(), DistributedError> {
    let requeue_count = task_ids
        .iter()
        .filter(|task_id| {
            state
                .tasks
                .get(*task_id)
                .is_some_and(|entry| entry.task.retry_count < state.limits.max_retries)
        })
        .count();
    let count = u64::try_from(requeue_count).map_err(|_| DistributedError::CounterExhausted {
        counter: "enqueue_ordinal",
    })?;
    state
        .next_enqueue_ordinal
        .checked_add(count)
        .ok_or(DistributedError::CounterExhausted {
            counter: "enqueue_ordinal",
        })?;
    if state.queue.len().saturating_add(requeue_count) > state.limits.max_queued_tasks {
        return Err(DistributedError::QueuedTaskCapacityReached {
            limit: state.limits.max_queued_tasks,
        });
    }
    let mut release_counts: BTreeMap<&str, u32> = BTreeMap::new();
    for task_id in task_ids {
        let entry = state
            .tasks
            .get(task_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "recovery task is missing",
            })?;
        if !matches!(entry.task.status, TaskStatus::Leased | TaskStatus::Running) {
            return Err(DistributedError::StateInvariant {
                reason: "recovery selected a non-leased task",
            });
        }
        let lease = entry
            .task
            .lease
            .as_ref()
            .ok_or(DistributedError::StateInvariant {
                reason: "recovery task has no lease",
            })?;
        preflight_worker_release(state, lease)?;
        next_counter(entry.task.record_version, "record_version")?;
        if entry.task.retry_count < state.limits.max_retries {
            next_counter(entry.task.task_generation, "task_generation")?;
            next_u32(entry.task.retry_count, "retry_count")?;
        }
        let count = release_counts.entry(&lease.worker_id).or_default();
        *count = next_u32(*count, "worker_release_count")?;
    }
    for (worker_id, releases) in release_counts {
        let worker = state
            .workers
            .get(worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "recovery lease references a missing worker",
            })?;
        if releases > worker.current_tasks {
            return Err(DistributedError::StateInvariant {
                reason: "recovery releases exceed worker active count",
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryDisposition {
    Requeued,
    Failed,
}

fn apply_recovery(
    state: &mut CoordinatorState,
    task_id: &str,
    now_secs: u64,
) -> Result<RecoveryDisposition, DistributedError> {
    let task = state
        .tasks
        .get(task_id)
        .map(|entry| entry.task.clone())
        .ok_or(DistributedError::StateInvariant {
            reason: "recovery task disappeared",
        })?;
    let lease = task
        .lease
        .as_ref()
        .ok_or(DistributedError::StateInvariant {
            reason: "recovery task lost its lease",
        })?
        .clone();
    let record_version = next_counter(task.record_version, "record_version")?;
    if task.retry_count < state.limits.max_retries {
        let task_generation = next_counter(task.task_generation, "task_generation")?;
        let retry_count = next_u32(task.retry_count, "retry_count")?;
        let enqueue_ordinal = state.next_enqueue_ordinal;
        let next_ordinal = next_counter(enqueue_ordinal, "enqueue_ordinal")?;
        release_worker(state, &lease)?;
        let entry = state
            .tasks
            .get_mut(task_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "recovery task disappeared during mutation",
            })?;
        entry.task.status = TaskStatus::Queued;
        entry.task.assigned_to = None;
        entry.task.lease = None;
        entry.task.started_at = None;
        entry.task.retry_count = retry_count;
        entry.task.task_generation = task_generation;
        entry.task.record_version = record_version;
        let key = QueueKey::new(entry.task.priority, enqueue_ordinal, task_id.to_owned());
        entry.queue_key = Some(key.clone());
        state.queue.insert(key);
        state.next_enqueue_ordinal = next_ordinal;
        Ok(RecoveryDisposition::Requeued)
    } else {
        terminalize_leased_task(state, &lease, TaskStatus::Failed, now_secs, record_version)?;
        Ok(RecoveryDisposition::Failed)
    }
}

fn check_state_invariants(state: &CoordinatorState) -> Result<(), DistributedError> {
    if state.tasks.len() > state.limits.max_task_records
        || state.active_tasks > state.limits.max_active_tasks
        || state.queue.len() > state.limits.max_queued_tasks
        || state.terminal_tasks > state.limits.max_terminal_tasks
        || state.workers.len() > state.limits.max_workers
    {
        return Err(DistributedError::StateInvariant {
            reason: "configured bound was exceeded",
        });
    }
    let active = state
        .tasks
        .values()
        .filter(|entry| entry.task.status.is_active())
        .count();
    let terminal = state.tasks.len().saturating_sub(active);
    if active != state.active_tasks || terminal != state.terminal_tasks {
        return Err(DistributedError::StateInvariant {
            reason: "task counters disagree with records",
        });
    }
    let mut observed_queue = BTreeSet::new();
    let mut worker_leases: BTreeMap<(&str, u64), u32> = BTreeMap::new();
    for entry in state.tasks.values() {
        if entry.task.record_version == 0 {
            return Err(DistributedError::StateInvariant {
                reason: "retained task has zero record version",
            });
        }
        match entry.task.status {
            TaskStatus::Queued => {
                let key = entry
                    .queue_key
                    .as_ref()
                    .ok_or(DistributedError::StateInvariant {
                        reason: "queued task has no queue key",
                    })?;
                if key.task_id != entry.task.task_id || !observed_queue.insert(key.clone()) {
                    return Err(DistributedError::StateInvariant {
                        reason: "queued task has duplicate or mismatched queue key",
                    });
                }
                if entry.task.lease.is_some() || entry.task.assigned_to.is_some() {
                    return Err(DistributedError::StateInvariant {
                        reason: "queued task retains lease ownership",
                    });
                }
            },
            TaskStatus::Leased | TaskStatus::Running => {
                if entry.queue_key.is_some() {
                    return Err(DistributedError::StateInvariant {
                        reason: "leased task still has a queue key",
                    });
                }
                let lease = entry
                    .task
                    .lease
                    .as_ref()
                    .ok_or(DistributedError::StateInvariant {
                        reason: "leased task has no lease",
                    })?;
                if entry.task.assigned_to.as_deref() != Some(lease.worker_id.as_str())
                    || entry.task.task_generation != lease.task_generation
                    || entry.task.attempt != lease.attempt
                {
                    return Err(DistributedError::StateInvariant {
                        reason: "task record disagrees with its lease",
                    });
                }
                let count = worker_leases
                    .entry((&lease.worker_id, lease.worker_generation))
                    .or_default();
                *count = next_u32(*count, "invariant_worker_leases")?;
            },
            _ => {
                if entry.queue_key.is_some()
                    || entry.task.lease.is_some()
                    || entry.task.assigned_to.is_some()
                {
                    return Err(DistributedError::StateInvariant {
                        reason: "terminal task retains active ownership",
                    });
                }
            },
        }
    }
    if observed_queue != state.queue {
        return Err(DistributedError::StateInvariant {
            reason: "queue keys disagree with queued task records",
        });
    }
    for worker in state.workers.values() {
        let expected = match worker_leases.get(&(worker.worker_id.as_str(), worker.generation)) {
            Some(count) => *count,
            None => 0,
        };
        if worker.current_tasks != expected || worker.current_tasks > worker.capacity {
            return Err(DistributedError::StateInvariant {
                reason: "worker counter disagrees with active leases",
            });
        }
    }
    for ((worker_id, generation), _) in worker_leases {
        let worker = state
            .workers
            .get(worker_id)
            .ok_or(DistributedError::StateInvariant {
                reason: "lease references an unknown worker",
            })?;
        if worker.generation != generation {
            return Err(DistributedError::StateInvariant {
                reason: "lease references a stale worker generation",
            });
        }
    }
    Ok(())
}

/// Hard limits for retained completion results and aggregate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultLimits {
    pub max_results: usize,
    pub max_result_bytes: usize,
    pub max_total_bytes: usize,
    pub max_aggregate_items: usize,
    pub max_aggregate_bytes: usize,
}

impl Default for ResultLimits {
    fn default() -> Self {
        Self {
            max_results: 1_024,
            max_result_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_aggregate_items: 1_024,
            max_aggregate_bytes: 16 * 1024 * 1024,
        }
    }
}

fn validate_result_limits(limits: ResultLimits) -> Result<(), DistributedError> {
    for (name, value) in [
        ("max_results", limits.max_results),
        ("max_result_bytes", limits.max_result_bytes),
        ("max_total_bytes", limits.max_total_bytes),
        ("max_aggregate_items", limits.max_aggregate_items),
        ("max_aggregate_bytes", limits.max_aggregate_bytes),
    ] {
        if value == 0 {
            return Err(DistributedError::InvalidLimit { name });
        }
    }
    for (name, actual, maximum) in [
        ("max_results", limits.max_results, MAX_RESULTS),
        (
            "max_result_bytes",
            limits.max_result_bytes,
            MAX_RESULT_BYTES,
        ),
        (
            "max_total_bytes",
            limits.max_total_bytes,
            MAX_TOTAL_RESULT_BYTES,
        ),
        (
            "max_aggregate_items",
            limits.max_aggregate_items,
            MAX_AGGREGATE_ITEMS,
        ),
        (
            "max_aggregate_bytes",
            limits.max_aggregate_bytes,
            MAX_TOTAL_RESULT_BYTES,
        ),
    ] {
        if actual > maximum {
            return Err(DistributedError::CountLimitExceedsMaximum {
                name,
                actual,
                maximum,
            });
        }
    }
    if limits.max_result_bytes > limits.max_total_bytes {
        return Err(DistributedError::InvalidLimitRelationship {
            reason: "max_result_bytes exceeds max_total_bytes",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredResult {
    receipt: CompletionReceipt,
    bytes: Vec<u8>,
}

struct ResultState {
    limits: ResultLimits,
    revision: u64,
    total_bytes: usize,
    results: BTreeMap<String, StoredResult>,
}

/// Idempotent result-store outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreResultOutcome {
    Stored,
    AlreadyStored,
}

/// One aggregate element in exact request order.
#[derive(Clone, PartialEq, Eq)]
pub struct AggregatedResult {
    task_id: String,
    bytes: Vec<u8>,
}

impl AggregatedResult {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for AggregatedResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatedResult")
            .field("task_id", &self.task_id)
            .field("result_bytes", &self.bytes.len())
            .finish()
    }
}

/// Bounded completion-receipt result store.
#[derive(Clone)]
pub struct ResultAggregator {
    state: Arc<Mutex<ResultState>>,
}

impl ResultAggregator {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ResultState {
                limits: ResultLimits::default(),
                revision: 0,
                total_bytes: 0,
                results: BTreeMap::new(),
            })),
        }
    }

    pub fn with_limits(limits: ResultLimits) -> Result<Self, DistributedError> {
        validate_result_limits(limits)?;
        Ok(Self {
            state: Arc::new(Mutex::new(ResultState {
                limits,
                revision: 0,
                total_bytes: 0,
                results: BTreeMap::new(),
            })),
        })
    }

    /// Store a result only with a completion receipt. Exact same-byte replay is
    /// idempotent; a different receipt or bytes for an occupied task ID fails.
    /// Receipt provenance remains scoped to the caller-enforced coordinator epoch.
    pub fn store_result(
        &self,
        expected_revision: u64,
        receipt: &CompletionReceipt,
        bytes: Vec<u8>,
    ) -> Result<Transition<StoreResultOutcome>, DistributedError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?;
        if expected_revision != state.revision {
            return Err(DistributedError::RevisionConflict {
                expected: expected_revision,
                actual: state.revision,
            });
        }
        if let Some(existing) = state.results.get(receipt.task_id()) {
            if existing.receipt == *receipt {
                if existing.bytes == bytes {
                    return Ok(Transition {
                        revision: state.revision,
                        value: StoreResultOutcome::AlreadyStored,
                    });
                }
                return Err(DistributedError::ConflictingResult {
                    task_id: receipt.task_id.clone(),
                });
            }
            return Err(DistributedError::MismatchedResultReceipt {
                task_id: receipt.task_id.clone(),
            });
        }
        if bytes.len() > state.limits.max_result_bytes {
            return Err(DistributedError::ResultTooLarge {
                actual: bytes.len(),
                limit: state.limits.max_result_bytes,
            });
        }
        if state.results.len() >= state.limits.max_results {
            return Err(DistributedError::ResultCapacityReached {
                limit: state.limits.max_results,
            });
        }
        let total_bytes = state.total_bytes.checked_add(bytes.len()).ok_or(
            DistributedError::TotalResultBytesExceeded {
                actual: usize::MAX,
                limit: state.limits.max_total_bytes,
            },
        )?;
        if total_bytes > state.limits.max_total_bytes {
            return Err(DistributedError::TotalResultBytesExceeded {
                actual: total_bytes,
                limit: state.limits.max_total_bytes,
            });
        }
        let revision = next_counter(state.revision, "result_revision")?;
        state.results.insert(
            receipt.task_id.clone(),
            StoredResult {
                receipt: receipt.clone(),
                bytes,
            },
        );
        state.total_bytes = total_bytes;
        state.revision = revision;
        Ok(Transition {
            revision,
            value: StoreResultOutcome::Stored,
        })
    }

    /// Aggregate all requested results in exact input order. Missing or repeated
    /// task IDs are explicit errors rather than silent filtering.
    pub fn aggregate_results(
        &self,
        task_ids: &[&str],
    ) -> Result<Vec<AggregatedResult>, DistributedError> {
        if task_ids.len() > MAX_AGGREGATE_ITEMS {
            return Err(DistributedError::AggregateItemLimitExceeded {
                actual: task_ids.len(),
                limit: MAX_AGGREGATE_ITEMS,
            });
        }
        let state = self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?;
        if task_ids.len() > state.limits.max_aggregate_items {
            return Err(DistributedError::AggregateItemLimitExceeded {
                actual: task_ids.len(),
                limit: state.limits.max_aggregate_items,
            });
        }
        for task_id in task_ids {
            validate_task_command_id(task_id)?;
        }
        let mut seen = BTreeSet::new();
        let mut total_bytes = 0usize;
        let mut aggregate = Vec::with_capacity(task_ids.len());
        for task_id in task_ids {
            if !seen.insert(*task_id) {
                return Err(DistributedError::DuplicateAggregateTask {
                    task_id: (*task_id).to_owned(),
                });
            }
            let stored =
                state
                    .results
                    .get(*task_id)
                    .ok_or_else(|| DistributedError::MissingResult {
                        task_id: (*task_id).to_owned(),
                    })?;
            total_bytes = total_bytes.checked_add(stored.bytes.len()).ok_or(
                DistributedError::AggregateBytesExceeded {
                    actual: usize::MAX,
                    limit: state.limits.max_aggregate_bytes,
                },
            )?;
            if total_bytes > state.limits.max_aggregate_bytes {
                return Err(DistributedError::AggregateBytesExceeded {
                    actual: total_bytes,
                    limit: state.limits.max_aggregate_bytes,
                });
            }
            aggregate.push(AggregatedResult {
                task_id: (*task_id).to_owned(),
                bytes: stored.bytes.clone(),
            });
        }
        Ok(aggregate)
    }

    pub fn get_result(&self, task_id: &str) -> Result<Option<Vec<u8>>, DistributedError> {
        validate_task_command_id(task_id)?;
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .results
            .get(task_id)
            .map(|stored| stored.bytes.clone()))
    }

    pub fn revision(&self) -> Result<u64, DistributedError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .revision)
    }

    pub fn result_count(&self) -> Result<usize, DistributedError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .results
            .len())
    }

    pub fn total_bytes(&self) -> Result<usize, DistributedError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DistributedError::StatePoisoned)?
            .total_bytes)
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
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
