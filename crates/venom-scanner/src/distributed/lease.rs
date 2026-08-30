use super::coordinator::CoordinatorState;
use super::model::{TaskPriority, TaskStatus};
use super::queue::TaskEntry;
use super::worker::{preflight_worker_release, release_worker};
use super::DistributedError;

/// Exact logical lease fence for one worker generation and task attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLease {
    pub(super) task_id: String,
    pub(super) worker_id: String,
    pub(super) worker_generation: u64,
    pub(super) task_generation: u64,
    pub(super) attempt: u32,
    pub(super) lease_id: u64,
    pub(super) acquired_at: u64,
    pub(super) expires_at: u64,
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
    pub(super) fn task_id(&self) -> &str {
        match self {
            Self::Queued(fence) => &fence.task_id,
            Self::Leased(lease) => &lease.task_id,
        }
    }
}

/// Versioned task snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct ScanTask {
    pub(super) task_id: String,
    pub(super) scan_id: String,
    pub(super) target_ref: String,
    pub(super) phases: Vec<u8>,
    pub(super) status: TaskStatus,
    pub(super) priority: TaskPriority,
    pub(super) created_at: u64,
    pub(super) started_at: Option<u64>,
    pub(super) completed_at: Option<u64>,
    pub(super) retry_count: u32,
    pub(super) attempt: u32,
    pub(super) task_generation: u64,
    pub(super) record_version: u64,
    pub(super) assigned_to: Option<String>,
    pub(super) lease: Option<TaskLease>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CancellationProof {
    Queued(QueuedTaskFence),
    Leased(TaskLease),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FailureProof {
    pub(super) lease: TaskLease,
    pub(super) outcome: FailureOutcome,
}

impl CancellationProof {
    pub(super) fn matches(&self, ownership: &TaskOwnership) -> bool {
        matches!(
            (self, ownership),
            (Self::Queued(left), TaskOwnership::Queued(right)) if left == right
        ) || matches!(
            (self, ownership),
            (Self::Leased(left), TaskOwnership::Leased(right)) if left == right
        )
    }
}

/// Exact receipt for a terminal completion. Fields are intentionally private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionReceipt {
    pub(super) task_id: String,
    pub(super) task_generation: u64,
    pub(super) attempt: u32,
    pub(super) lease_id: u64,
    pub(super) worker_id: String,
    pub(super) worker_generation: u64,
    pub(super) record_version: u64,
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

    pub(super) fn matches_lease(&self, lease: &TaskLease) -> bool {
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

pub(super) fn ensure_queue_entry(
    state: &CoordinatorState,
    entry: &TaskEntry,
) -> Result<(), DistributedError> {
    match entry.queue_key.as_ref() {
        Some(key) if state.queue.contains(key) && key.task_id == entry.task.task_id => Ok(()),
        _ => Err(DistributedError::StateInvariant {
            reason: "queued task does not have exactly one queue key",
        }),
    }
}

pub(super) fn ensure_current_lease(
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

pub(super) fn validate_cancellation_ownership(
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

pub(super) fn terminalize_queued_task(
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

pub(super) fn terminalize_leased_task(
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
