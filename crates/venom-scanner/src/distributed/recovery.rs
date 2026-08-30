use std::collections::BTreeMap;

use super::coordinator::{next_counter, next_u32, CoordinatorState};
use super::lease::{terminalize_leased_task, TaskLease};
use super::model::TaskStatus;
use super::queue::QueueKey;
use super::worker::{preflight_worker_release, release_worker};
use super::DistributedError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoverySummary {
    pub workers_affected: usize,
    pub tasks_requeued: usize,
    pub tasks_failed: usize,
}

pub(super) fn leased_task_ids<F>(state: &CoordinatorState, mut predicate: F) -> Vec<String>
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

pub(super) fn preflight_recovery(
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
pub(super) enum RecoveryDisposition {
    Requeued,
    Failed,
}

pub(super) fn apply_recovery(
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
