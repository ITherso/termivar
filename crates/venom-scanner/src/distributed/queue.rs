use std::sync::{Arc, Mutex};

use super::coordinator::{lock_state, next_counter, CoordinatorState};
use super::lease::{CancellationProof, CompletionReceipt, FailureProof, ScanTask};
use super::limits::{validate_limits, DistributedLimits};
use super::model::{
    validate_task_command_id, validate_task_spec, StateSnapshot, TaskPriority, TaskSpec,
    TaskStatus, Transition,
};
use super::DistributedError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct QueueKey {
    inverted_priority: u8,
    enqueue_ordinal: u64,
    pub(super) task_id: String,
}

impl QueueKey {
    pub(super) fn new(priority: TaskPriority, enqueue_ordinal: u64, task_id: String) -> Self {
        Self {
            inverted_priority: u8::MAX - priority as u8,
            enqueue_ordinal,
            task_id,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct TaskEntry {
    pub(super) task: ScanTask,
    pub(super) queue_key: Option<QueueKey>,
    pub(super) completion: Option<CompletionReceipt>,
    pub(super) cancellation: Option<CancellationProof>,
    pub(super) failure: Option<FailureProof>,
}

/// Cloneable task facade sharing the pool's single state lock.
#[derive(Clone)]
pub struct TaskQueue {
    pub(super) state: Arc<Mutex<CoordinatorState>>,
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
