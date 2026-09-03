use std::cmp::Ordering;
use std::collections::BTreeSet;

use super::coordinator::{next_counter, next_u32, CoordinatorState};
use super::lease::{ensure_queue_entry, TaskLease};
use super::limits::{MAX_WORKER_CAPACITY, MAX_WORKER_TAGS, UTILIZATION_BASIS_POINTS};
use super::model::{validate_identifier, TaskStatus};
use super::DistributedError;

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
    pub(super) worker_id: String,
    pub(super) generation: u64,
    pub(super) status: WorkerStatus,
    pub(super) capacity: u32,
    pub(super) current_tasks: u32,
    pub(super) completed_tasks: u64,
    pub(super) last_heartbeat: u64,
    pub(super) cpu_basis_points: u16,
    pub(super) memory_basis_points: u16,
    pub(super) network_basis_points: u16,
    pub(super) tags: BTreeSet<WorkerTag>,
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

pub(super) fn validate_worker_spec(spec: &WorkerSpec) -> Result<(), DistributedError> {
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

pub(super) fn ensure_observation_time(
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

pub(super) fn best_worker_id(state: &CoordinatorState, now_secs: u64) -> Option<String> {
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

pub(super) fn prepare_assignment(
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

pub(super) fn apply_assignment(
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

pub(super) fn preflight_worker_release(
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

pub(super) fn release_worker(
    state: &mut CoordinatorState,
    lease: &TaskLease,
) -> Result<(), DistributedError> {
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
