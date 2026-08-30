use super::limits::{MAX_IDENTIFIER_BYTES, MAX_TARGET_REF_BYTES, MAX_TASK_PHASES};
use super::DistributedError;

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

    pub(super) fn is_active(self) -> bool {
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

pub(super) fn validate_task_spec(spec: &TaskSpec) -> Result<(), DistributedError> {
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

pub(super) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), DistributedError> {
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

pub(super) fn validate_task_command_id(value: &str) -> Result<(), DistributedError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || !identifier_is_safe(value) {
        return Err(DistributedError::InvalidTask {
            reason: "task command identifier is invalid",
        });
    }
    Ok(())
}

pub(super) fn validate_worker_command_id(value: &str) -> Result<(), DistributedError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || !identifier_is_safe(value) {
        return Err(DistributedError::InvalidWorker {
            reason: "worker command identifier is invalid",
        });
    }
    Ok(())
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
