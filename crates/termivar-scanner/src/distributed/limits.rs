use super::DistributedError;

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

pub(super) fn validate_limits(limits: DistributedLimits) -> Result<(), DistributedError> {
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
