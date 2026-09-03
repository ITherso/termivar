use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use super::lease::{
    ensure_current_lease, ensure_queue_entry, terminalize_leased_task, terminalize_queued_task,
    validate_cancellation_ownership, CancellationOutcome, CancellationProof, CompletionOutcome,
    CompletionReceipt, FailureOutcome, FailureProof, StartOutcome, TaskLease, TaskOwnership,
};
use super::limits::{validate_limits, DistributedLimits, UTILIZATION_BASIS_POINTS};
use super::model::{
    validate_task_command_id, validate_worker_command_id, StateSnapshot, TaskStatus, Transition,
};
use super::queue::{QueueKey, TaskEntry, TaskQueue};
use super::recovery::{
    apply_recovery, leased_task_ids, preflight_recovery, RecoveryDisposition, RecoverySummary,
};
use super::worker::{
    apply_assignment, best_worker_id, ensure_observation_time, preflight_worker_release,
    prepare_assignment, release_worker, validate_worker_spec, WorkerNode, WorkerObservation,
    WorkerSpec, WorkerStatus,
};
use super::{lock_state, DistributedError};

pub(super) struct CoordinatorState {
    pub(super) limits: DistributedLimits,
    pub(super) revision: u64,
    pub(super) logical_time: u64,
    pub(super) tasks: BTreeMap<String, TaskEntry>,
    pub(super) queue: BTreeSet<QueueKey>,
    pub(super) workers: BTreeMap<String, WorkerNode>,
    pub(super) active_tasks: usize,
    pub(super) terminal_tasks: usize,
    pub(super) next_enqueue_ordinal: u64,
    pub(super) next_lease_id: u64,
}

impl CoordinatorState {
    pub(super) fn new(limits: DistributedLimits) -> Self {
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

    pub(super) fn preflight_command(
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

    pub(super) fn commit(&mut self, revision: u64, now_secs: u64) {
        self.revision = revision;
        self.logical_time = now_secs;
    }

    pub(super) fn next_task_id(&self) -> Option<String> {
        self.queue.first().map(|key| key.task_id.clone())
    }

    pub(super) fn snapshot(&self) -> StateSnapshot {
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

pub(super) fn next_counter(value: u64, counter: &'static str) -> Result<u64, DistributedError> {
    value
        .checked_add(1)
        .ok_or(DistributedError::CounterExhausted { counter })
}

pub(super) fn next_u32(value: u32, counter: &'static str) -> Result<u32, DistributedError> {
    value
        .checked_add(1)
        .ok_or(DistributedError::CounterExhausted { counter })
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
