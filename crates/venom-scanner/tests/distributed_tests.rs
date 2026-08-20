#![cfg(feature = "distributed")]

use std::sync::{Arc, Barrier};
use std::thread;
use venom_scanner::{
    CancellationOutcome, CompletionOutcome, CompletionReceipt, DistributedError, DistributedLimits,
    FailureOutcome, ResultAggregator, ResultLimits, ScanTask, StateSnapshot, StoreResultOutcome,
    TaskLease, TaskOwnership, TaskPriority, TaskSpec, TaskStatus, WorkerNode, WorkerObservation,
    WorkerPool, WorkerSpec, WorkerStatus, MAX_IDENTIFIER_BYTES, MAX_RESULTS, MAX_TASK_RECORDS,
    MAX_WORKER_CAPACITY, UTILIZATION_BASIS_POINTS,
};

fn limits() -> DistributedLimits {
    DistributedLimits {
        max_task_records: 32,
        max_active_tasks: 16,
        max_queued_tasks: 16,
        max_terminal_tasks: 32,
        max_workers: 8,
        max_retries: 1,
        max_lease_ttl_secs: 100,
        max_task_ttl_secs: 1_000,
        heartbeat_timeout_secs: 20,
    }
}

fn pool() -> WorkerPool {
    WorkerPool::with_limits(limits()).expect("test limits are valid")
}

fn task(id: &str, priority: TaskPriority) -> TaskSpec {
    TaskSpec::new(
        id,
        format!("scan-{id}"),
        format!("target-ref:{id}"),
        vec![1, 2],
        priority,
    )
}

fn worker(id: &str, capacity: u32) -> WorkerSpec {
    WorkerSpec::new(id, capacity)
}

fn revision(pool: &WorkerPool) -> u64 {
    pool.snapshot().expect("snapshot").revision
}

fn enqueue(pool: &WorkerPool, now: u64, id: &str, priority: TaskPriority) -> ScanTask {
    pool.task_queue()
        .enqueue(revision(pool), now, task(id, priority))
        .expect("enqueue")
        .value
}

fn register(pool: &WorkerPool, now: u64, id: &str, capacity: u32) -> WorkerNode {
    pool.register_worker(revision(pool), now, worker(id, capacity))
        .expect("register")
        .value
}

fn assign(pool: &WorkerPool, now: u64, task_id: &str, worker_id: &str) -> TaskLease {
    pool.assign_task(revision(pool), now, task_id, worker_id, 10)
        .expect("assign")
        .value
}

#[test]
fn priority_fifo_assignment_keeps_versioned_records() {
    let pool = pool();
    register(&pool, 1, "worker-a", 4);
    enqueue(&pool, 2, "normal", TaskPriority::Normal);
    enqueue(&pool, 3, "critical-a", TaskPriority::Critical);
    enqueue(&pool, 4, "critical-b", TaskPriority::Critical);

    let first = pool
        .assign_next(revision(&pool), 5, "worker-a", 10)
        .expect("first assignment")
        .value;
    let second = pool
        .assign_next(revision(&pool), 6, "worker-a", 10)
        .expect("second assignment")
        .value;

    assert_eq!(first.task_id(), "critical-a");
    assert_eq!(second.task_id(), "critical-b");
    let snapshot = pool.snapshot().expect("snapshot");
    assert_eq!(snapshot.task_records, 3);
    assert_eq!(snapshot.active_tasks, 3);
    assert_eq!(snapshot.queued_tasks, 1);
    assert_eq!(
        pool.task_queue()
            .get_task("critical-a")
            .expect("read")
            .expect("record")
            .status(),
        TaskStatus::Leased
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn task_queue_accessor_cannot_split_pool_state() {
    let pool = pool();
    let queue = pool.task_queue();
    queue
        .enqueue(0, 1, task("task", TaskPriority::Normal))
        .expect("shared enqueue");
    assert_eq!(pool.snapshot().expect("pool snapshot").task_records, 1);
    assert_eq!(
        pool.task_queue()
            .get_task("task")
            .expect("read")
            .expect("task")
            .record_version(),
        1
    );
}

#[test]
fn opaque_target_is_redacted_from_input_and_snapshot_debug() {
    let pool = pool();
    let spec = TaskSpec::new(
        "task",
        "scan-task",
        "SENTINEL_TARGET_SECRET",
        vec![1],
        TaskPriority::Normal,
    );
    assert!(!format!("{spec:?}").contains("SENTINEL_TARGET_SECRET"));
    let task = pool
        .task_queue()
        .enqueue(0, 1, spec)
        .expect("enqueue")
        .value;
    assert_eq!(task.target_ref(), "SENTINEL_TARGET_SECRET");
    assert!(!format!("{task:?}").contains("SENTINEL_TARGET_SECRET"));
}

#[test]
fn duplicate_and_capacity_failures_are_atomic() {
    let constrained = DistributedLimits {
        max_task_records: 2,
        max_active_tasks: 2,
        max_queued_tasks: 2,
        max_terminal_tasks: 2,
        max_workers: 1,
        ..limits()
    };
    let pool = WorkerPool::with_limits(constrained).expect("limits");
    enqueue(&pool, 1, "one", TaskPriority::Normal);
    let before = pool.snapshot().expect("before");
    assert_eq!(
        pool.task_queue()
            .enqueue(before.revision, 2, task("one", TaskPriority::Critical)),
        Err(DistributedError::TaskAlreadyExists {
            task_id: "one".to_owned()
        })
    );
    assert_eq!(pool.snapshot().expect("after duplicate"), before);

    enqueue(&pool, 2, "two", TaskPriority::Normal);
    let full = pool.snapshot().expect("full");
    assert_eq!(
        pool.task_queue()
            .enqueue(full.revision, 3, task("three", TaskPriority::Normal)),
        Err(DistributedError::TaskRecordCapacityReached { limit: 2 })
    );
    assert_eq!(pool.snapshot().expect("after full"), full);
    pool.check_invariants().expect("invariants");
}

#[test]
fn queued_capacity_may_be_smaller_than_active_capacity() {
    let limits = DistributedLimits {
        max_task_records: 8,
        max_active_tasks: 4,
        max_queued_tasks: 2,
        max_terminal_tasks: 4,
        max_workers: 1,
        ..limits()
    };
    let pool = WorkerPool::with_limits(limits).expect("valid asymmetric limits");
    register(&pool, 1, "worker-a", 4);
    enqueue(&pool, 2, "one", TaskPriority::Normal);
    enqueue(&pool, 2, "two", TaskPriority::Normal);
    assign(&pool, 3, "one", "worker-a");
    assign(&pool, 3, "two", "worker-a");
    enqueue(&pool, 4, "three", TaskPriority::Normal);
    enqueue(&pool, 4, "four", TaskPriority::Normal);
    let snapshot = pool.snapshot().expect("snapshot");
    assert_eq!(snapshot.active_tasks, 4);
    assert_eq!(snapshot.queued_tasks, 2);
    pool.check_invariants().expect("invariants");
}

#[test]
fn absolute_limit_ceilings_and_worker_capacity_are_enforced() {
    let excessive = DistributedLimits {
        max_task_records: MAX_TASK_RECORDS + 1,
        max_terminal_tasks: MAX_TASK_RECORDS + 1,
        ..limits()
    };
    assert_eq!(
        WorkerPool::with_limits(excessive).err(),
        Some(DistributedError::CountLimitExceedsMaximum {
            name: "max_task_records",
            actual: MAX_TASK_RECORDS + 1,
            maximum: MAX_TASK_RECORDS,
        })
    );
    let pool = pool();
    assert_eq!(
        pool.register_worker(0, 1, worker("worker-a", MAX_WORKER_CAPACITY + 1,),),
        Err(DistributedError::InvalidWorker {
            reason: "capacity exceeds absolute maximum"
        })
    );
    assert_eq!(pool.snapshot().expect("unchanged").revision, 0);
    let mut invalid_load = worker("worker-b", 1);
    invalid_load.cpu_basis_points = UTILIZATION_BASIS_POINTS + 1;
    assert_eq!(
        pool.register_worker(0, 1, invalid_load),
        Err(DistributedError::InvalidWorker {
            reason: "utilization exceeds 10000 basis points"
        })
    );
    let excessive_results = ResultLimits {
        max_results: MAX_RESULTS + 1,
        ..ResultLimits::default()
    };
    assert_eq!(
        ResultAggregator::with_limits(excessive_results).err(),
        Some(DistributedError::CountLimitExceedsMaximum {
            name: "max_results",
            actual: MAX_RESULTS + 1,
            maximum: MAX_RESULTS,
        })
    );
}

#[test]
fn unsafe_or_unbounded_command_ids_fail_without_diagnostic_echo() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    for invalid in [
        "x".repeat(MAX_IDENTIFIER_BYTES + 1),
        "task\u{202e}spoof".to_owned(),
        "task\ncontrol".to_owned(),
    ] {
        let before = pool.snapshot().expect("before invalid id");
        let error = pool
            .assign_task(before.revision, 3, &invalid, "worker-a", 10)
            .expect_err("invalid ID must fail");
        assert_eq!(
            error,
            DistributedError::InvalidTask {
                reason: "task command identifier is invalid"
            }
        );
        assert!(!error.to_string().contains(&invalid));
        assert_eq!(pool.snapshot().expect("unchanged invalid id"), before);
        assert_eq!(
            pool.task_queue().get_task(&invalid),
            Err(DistributedError::InvalidTask {
                reason: "task command identifier is invalid"
            })
        );
        assert_eq!(
            pool.get_worker(&invalid),
            Err(DistributedError::InvalidWorker {
                reason: "worker command identifier is invalid"
            })
        );
    }
}

#[test]
fn assignment_requires_real_eligible_capacity() {
    let pool = pool();
    enqueue(&pool, 1, "one", TaskPriority::Normal);
    let before = pool.snapshot().expect("before missing worker");
    assert_eq!(
        pool.assign_task(before.revision, 2, "one", "missing", 10),
        Err(DistributedError::WorkerNotFound {
            worker_id: "missing".to_owned()
        })
    );
    assert_eq!(pool.snapshot().expect("unchanged"), before);

    let worker = register(&pool, 2, "worker-a", 1);
    pool.update_worker(
        revision(&pool),
        3,
        "worker-a",
        worker.generation(),
        WorkerObservation {
            status: WorkerStatus::Degraded,
            cpu_basis_points: 0,
            memory_basis_points: 0,
            network_basis_points: 0,
        },
    )
    .expect("degrade");
    let unavailable = pool.snapshot().expect("unavailable");
    assert_eq!(
        pool.assign_task(unavailable.revision, 4, "one", "worker-a", 10),
        Err(DistributedError::WorkerUnavailable {
            worker_id: "worker-a".to_owned()
        })
    );
    assert_eq!(pool.snapshot().expect("unchanged unavailable"), unavailable);

    pool.update_worker(
        revision(&pool),
        4,
        "worker-a",
        worker.generation(),
        WorkerObservation::default(),
    )
    .expect("healthy");
    assign(&pool, 5, "one", "worker-a");
    enqueue(&pool, 6, "two", TaskPriority::Normal);
    let at_capacity = pool.snapshot().expect("at capacity");
    assert_eq!(
        pool.assign_task(at_capacity.revision, 7, "two", "worker-a", 10),
        Err(DistributedError::WorkerAtCapacity {
            worker_id: "worker-a".to_owned()
        })
    );
    assert_eq!(pool.snapshot().expect("unchanged capacity"), at_capacity);
    pool.check_invariants().expect("invariants");
}

#[test]
fn worker_selection_is_integer_ordered_with_id_tie_break() {
    let pool = pool();
    register(&pool, 1, "worker-b", 4);
    register(&pool, 1, "worker-a", 4);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = pool
        .assign_next_available(revision(&pool), 2, 10)
        .expect("assignment")
        .value;
    assert_eq!(lease.worker_id(), "worker-a");
    pool.check_invariants().expect("invariants");
}

#[test]
fn concurrent_assignment_linearizes_at_revision() {
    let pool = pool();
    register(&pool, 1, "worker-a", 2);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let expected = revision(&pool);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let cloned = pool.clone();
        let gate = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            gate.wait();
            cloned.assign_task(expected, 3, "task", "worker-a", 10)
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(DistributedError::RevisionConflict { .. })))
            .count(),
        1
    );
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("worker")
            .expect("present")
            .current_tasks(),
        1
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn completion_is_exactly_idempotent() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task", "worker-a");
    pool.start_task(revision(&pool), 4, &lease).expect("start");
    let completed = pool
        .complete_task(revision(&pool), 5, &lease)
        .expect("complete");
    assert!(matches!(completed.value, CompletionOutcome::Completed(_)));
    let after = pool.snapshot().expect("after");
    assert!(matches!(
        pool.complete_task(after.revision - 1, 6, &lease),
        Err(DistributedError::RevisionConflict { .. })
    ));
    assert_eq!(pool.snapshot().expect("stale revision unchanged"), after);
    let replay = pool
        .complete_task(after.revision, 6, &lease)
        .expect("idempotent replay");
    assert!(matches!(
        replay.value,
        CompletionOutcome::AlreadyCompleted(_)
    ));
    assert_eq!(replay.revision, after.revision);
    assert_eq!(pool.snapshot().expect("unchanged replay"), after);
    let worker = pool
        .get_worker("worker-a")
        .expect("worker")
        .expect("present");
    assert_eq!(worker.current_tasks(), 0);
    assert_eq!(worker.completed_tasks(), 1);
    pool.check_invariants().expect("invariants");
}

#[test]
fn leased_task_must_start_before_completion_or_failure() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task", "worker-a");
    let before = pool.snapshot().expect("before");
    assert!(matches!(
        pool.complete_task(before.revision, 4, &lease),
        Err(DistributedError::InvalidTransition {
            status: TaskStatus::Leased,
            operation: "complete",
            ..
        })
    ));
    assert_eq!(pool.snapshot().expect("complete unchanged"), before);
    assert!(matches!(
        pool.fail_task(before.revision, 4, &lease),
        Err(DistributedError::InvalidTransition {
            status: TaskStatus::Leased,
            operation: "fail",
            ..
        })
    ));
    assert_eq!(pool.snapshot().expect("fail unchanged"), before);
    pool.check_invariants().expect("invariants");
}

#[test]
fn cancellation_is_exactly_idempotent() {
    let pool = pool();
    let queued = enqueue(&pool, 1, "task", TaskPriority::Normal);
    let ownership = queued.ownership().expect("queued ownership");
    let cancelled = pool
        .cancel_task(revision(&pool), 2, &ownership)
        .expect("cancel");
    assert!(matches!(
        cancelled.value,
        CancellationOutcome::Cancelled { .. }
    ));
    let after = pool.snapshot().expect("after");
    let replay = pool
        .cancel_task(after.revision, 3, &ownership)
        .expect("replay");
    assert!(matches!(
        replay.value,
        CancellationOutcome::AlreadyCancelled { .. }
    ));
    assert_eq!(replay.revision, after.revision);
    assert_eq!(pool.snapshot().expect("unchanged"), after);
    pool.check_invariants().expect("invariants");
}

#[test]
fn completion_cancellation_race_has_one_terminal_winner() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task", "worker-a");
    pool.start_task(revision(&pool), 3, &lease)
        .expect("start before race");
    let expected = revision(&pool);
    let barrier = Arc::new(Barrier::new(3));
    let complete_pool = pool.clone();
    let complete_lease = lease.clone();
    let complete_gate = Arc::clone(&barrier);
    let complete = thread::spawn(move || {
        complete_gate.wait();
        complete_pool
            .complete_task(expected, 4, &complete_lease)
            .map(|_| ())
    });
    let cancel_pool = pool.clone();
    let cancel_ownership = TaskOwnership::Leased(lease);
    let cancel_gate = Arc::clone(&barrier);
    let cancel = thread::spawn(move || {
        cancel_gate.wait();
        cancel_pool
            .cancel_task(expected, 4, &cancel_ownership)
            .map(|_| ())
    });
    barrier.wait();
    let results = [
        complete.join().expect("complete thread"),
        cancel.join().expect("cancel thread"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(DistributedError::RevisionConflict { .. })))
            .count(),
        1
    );
    let task = pool
        .task_queue()
        .get_task("task")
        .expect("read")
        .expect("task");
    assert!(matches!(
        task.status(),
        TaskStatus::Completed | TaskStatus::Cancelled
    ));
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("read")
            .expect("worker")
            .current_tasks(),
        0
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn retry_releases_and_requeues_exactly_once_until_exhausted() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let first = assign(&pool, 3, "task", "worker-a");
    pool.start_task(revision(&pool), 3, &first)
        .expect("start first attempt");
    let retry = pool.fail_task(revision(&pool), 4, &first).expect("retry");
    assert!(matches!(
        retry.value,
        FailureOutcome::Requeued {
            task_generation: 1,
            retry_count: 1,
            ..
        }
    ));
    let after_retry = pool.snapshot().expect("after retry");
    assert_eq!(after_retry.queued_tasks, 1);
    assert_eq!(
        pool.fail_task(after_retry.revision, 5, &first),
        Err(DistributedError::StaleOwnership {
            task_id: "task".to_owned()
        })
    );
    assert_eq!(pool.snapshot().expect("unchanged stale"), after_retry);

    let second = assign(&pool, 5, "task", "worker-a");
    assert_eq!(second.task_generation(), 1);
    assert_eq!(second.attempt(), 2);
    pool.start_task(revision(&pool), 5, &second)
        .expect("start second attempt");
    let exhausted = pool
        .fail_task(revision(&pool), 6, &second)
        .expect("exhausted");
    assert!(matches!(
        exhausted.value,
        FailureOutcome::RetryExhausted { retry_count: 1, .. }
    ));
    let after_exhaustion = pool.snapshot().expect("after exhaustion");
    let replay = pool
        .fail_task(after_exhaustion.revision, 7, &second)
        .expect("terminal failure replay");
    assert_eq!(replay.value, exhausted.value);
    assert_eq!(replay.revision, after_exhaustion.revision);
    assert_eq!(
        pool.snapshot().expect("failure replay unchanged"),
        after_exhaustion
    );
    let task = pool
        .task_queue()
        .get_task("task")
        .expect("read")
        .expect("task");
    assert_eq!(task.status(), TaskStatus::Failed);
    assert_eq!(pool.snapshot().expect("snapshot").queued_tasks, 0);
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("worker")
            .expect("present")
            .current_tasks(),
        0
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn retry_backpressure_is_atomic_and_same_lease_can_retry_after_capacity_frees() {
    let limits = DistributedLimits {
        max_task_records: 2,
        max_active_tasks: 2,
        max_queued_tasks: 1,
        max_terminal_tasks: 2,
        max_workers: 1,
        max_retries: 1,
        ..limits()
    };
    let pool = WorkerPool::with_limits(limits).expect("backpressure limits");
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task-a", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task-a", "worker-a");
    pool.start_task(revision(&pool), 4, &lease)
        .expect("start task a");
    let queued_b = enqueue(&pool, 5, "task-b", TaskPriority::Normal);

    let before = pool.snapshot().expect("before backpressure");
    let task_a_before = pool
        .task_queue()
        .get_task("task-a")
        .expect("read task a")
        .expect("task a");
    let task_b_before = pool
        .task_queue()
        .get_task("task-b")
        .expect("read task b")
        .expect("task b");
    let worker_before = pool
        .get_worker("worker-a")
        .expect("read worker")
        .expect("worker");

    assert_eq!(
        pool.fail_task(before.revision, 6, &lease),
        Err(DistributedError::QueuedTaskCapacityReached { limit: 1 })
    );
    assert_eq!(pool.snapshot().expect("unchanged snapshot"), before);
    assert_eq!(
        pool.task_queue()
            .get_task("task-a")
            .expect("read task a")
            .expect("task a"),
        task_a_before
    );
    assert_eq!(
        pool.task_queue()
            .get_task("task-b")
            .expect("read task b")
            .expect("task b"),
        task_b_before
    );
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("read worker")
            .expect("worker"),
        worker_before
    );

    let ownership_b = queued_b.ownership().expect("queued ownership");
    pool.cancel_task(before.revision, 6, &ownership_b)
        .expect("cancel task b");
    let retry = pool
        .fail_task(revision(&pool), 7, &lease)
        .expect("retry after capacity frees");
    assert!(matches!(
        retry.value,
        FailureOutcome::Requeued {
            task_generation: 1,
            retry_count: 1,
            ..
        }
    ));
    assert_eq!(pool.snapshot().expect("after retry").queued_tasks, 1);
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("read worker")
            .expect("worker")
            .current_tasks(),
        0
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn expiry_at_deadline_requeues_and_fences_old_lease() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task", "worker-a");
    assert_eq!(lease.expires_at(), 13);
    let recovered = pool
        .recover_expired_leases(revision(&pool), 13)
        .expect("recover");
    assert_eq!(recovered.value.tasks_requeued, 1);
    let after = pool.snapshot().expect("after");
    assert_eq!(
        pool.complete_task(after.revision, 13, &lease),
        Err(DistributedError::StaleOwnership {
            task_id: "task".to_owned()
        })
    );
    assert_eq!(pool.snapshot().expect("unchanged"), after);
    let task = pool
        .task_queue()
        .get_task("task")
        .expect("read")
        .expect("task");
    assert_eq!(task.status(), TaskStatus::Queued);
    assert_eq!(task.task_generation(), 1);
    pool.check_invariants().expect("invariants");
}

#[test]
fn completion_expiry_race_linearizes_without_counter_drift() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task", "worker-a");
    pool.start_task(revision(&pool), 4, &lease).expect("start");
    let expected = revision(&pool);
    let barrier = Arc::new(Barrier::new(3));
    let complete_pool = pool.clone();
    let complete_lease = lease.clone();
    let complete_gate = Arc::clone(&barrier);
    let complete = thread::spawn(move || {
        complete_gate.wait();
        complete_pool
            .complete_task(expected, 12, &complete_lease)
            .map(|_| ())
    });
    let recovery_pool = pool.clone();
    let recovery_gate = Arc::clone(&barrier);
    let recovery = thread::spawn(move || {
        recovery_gate.wait();
        recovery_pool
            .recover_expired_leases(expected, 13)
            .map(|_| ())
    });
    barrier.wait();
    let results = [
        complete.join().expect("complete thread"),
        recovery.join().expect("recovery thread"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(DistributedError::RevisionConflict { .. })))
            .count(),
        1
    );
    let task = pool
        .task_queue()
        .get_task("task")
        .expect("read")
        .expect("task");
    assert!(matches!(
        task.status(),
        TaskStatus::Completed | TaskStatus::Queued
    ));
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("worker")
            .expect("present")
            .current_tasks(),
        0
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn repeated_recovery_consumes_retry_budget_and_terminally_fails() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let first = assign(&pool, 3, "task", "worker-a");
    let first_recovery = pool
        .recover_expired_leases(revision(&pool), first.expires_at())
        .expect("first recovery");
    assert_eq!(first_recovery.value.tasks_requeued, 1);
    assert_eq!(first_recovery.value.tasks_failed, 0);

    let second = assign(&pool, 14, "task", "worker-a");
    let exhausted = pool
        .recover_expired_leases(revision(&pool), second.expires_at())
        .expect("exhausted recovery");
    assert_eq!(exhausted.value.tasks_requeued, 0);
    assert_eq!(exhausted.value.tasks_failed, 1);
    let task = pool
        .task_queue()
        .get_task("task")
        .expect("read")
        .expect("task");
    assert_eq!(task.status(), TaskStatus::Failed);
    assert_eq!(task.retry_count(), 1);
    assert_eq!(task.attempt(), 2);
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("worker")
            .expect("present")
            .current_tasks(),
        0
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn worker_loss_recovery_fences_generation_and_preserves_lease_order() {
    let pool = pool();
    let admitted_worker = register(&pool, 1, "worker-a", 2);
    enqueue(&pool, 2, "first", TaskPriority::Normal);
    enqueue(&pool, 2, "second", TaskPriority::Normal);
    let first = assign(&pool, 3, "first", "worker-a");
    let second = assign(&pool, 4, "second", "worker-a");
    let recovered = pool
        .deregister_worker(revision(&pool), 5, "worker-a", admitted_worker.generation())
        .expect("deregister");
    assert_eq!(recovered.value.tasks_requeued, 2);
    let offline = pool.get_worker("worker-a").expect("read").expect("worker");
    assert_eq!(offline.status(), WorkerStatus::Offline);
    assert_eq!(offline.generation(), admitted_worker.generation() + 1);
    assert_eq!(offline.current_tasks(), 0);
    assert_eq!(
        pool.complete_task(revision(&pool), 6, &first),
        Err(DistributedError::StaleOwnership {
            task_id: "first".to_owned()
        })
    );
    pool.reactivate_worker(
        revision(&pool),
        6,
        offline.generation(),
        worker("worker-a", 2),
    )
    .expect("reactivate");
    let reassigned_first = pool
        .assign_next(revision(&pool), 7, "worker-a", 10)
        .expect("first recovered")
        .value;
    let reassigned_second = pool
        .assign_next(revision(&pool), 8, "worker-a", 10)
        .expect("second recovered")
        .value;
    assert_eq!(reassigned_first.task_id(), first.task_id());
    assert_eq!(reassigned_second.task_id(), second.task_id());
    assert!(reassigned_first.worker_generation() > first.worker_generation());
    pool.check_invariants().expect("invariants");
}

#[test]
fn stale_workers_are_ineligible_before_prune() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let before = pool.snapshot().expect("before");
    assert_eq!(
        pool.assign_next_available(before.revision, 22, 10),
        Err(DistributedError::NoAvailableWorker)
    );
    assert_eq!(pool.snapshot().expect("unchanged"), before);
    let pruned = pool.prune_dead_workers(before.revision, 22).expect("prune");
    assert_eq!(pruned.value.workers_affected, 1);
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("read")
            .expect("worker")
            .status(),
        WorkerStatus::Offline
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn task_ttl_expiry_releases_worker_once() {
    let pool = pool();
    register(&pool, 1, "worker-a", 1);
    enqueue(&pool, 2, "task", TaskPriority::Normal);
    let lease = assign(&pool, 3, "task", "worker-a");
    let expired = pool
        .expire_old_tasks(revision(&pool), 12, 10)
        .expect("expire");
    assert_eq!(expired.value, 1);
    assert_eq!(
        pool.task_queue()
            .get_task("task")
            .expect("read")
            .expect("task")
            .status(),
        TaskStatus::Expired
    );
    assert_eq!(
        pool.complete_task(revision(&pool), 13, &lease),
        Err(DistributedError::StaleOwnership {
            task_id: "task".to_owned()
        })
    );
    assert_eq!(
        pool.get_worker("worker-a")
            .expect("read")
            .expect("worker")
            .current_tasks(),
        0
    );
    pool.check_invariants().expect("invariants");
}

#[test]
fn revision_and_logical_time_fence_failed_commands() {
    let pool = pool();
    register(&pool, 10, "worker-a", 1);
    let before = pool.snapshot().expect("before");
    assert_eq!(
        pool.task_queue()
            .enqueue(before.revision - 1, 11, task("task", TaskPriority::Normal)),
        Err(DistributedError::RevisionConflict {
            expected: before.revision - 1,
            actual: before.revision
        })
    );
    assert_eq!(pool.snapshot().expect("revision unchanged"), before);
    assert_eq!(
        pool.task_queue()
            .enqueue(before.revision, 9, task("task", TaskPriority::Normal)),
        Err(DistributedError::LogicalTimeRegression {
            current: 10,
            proposed: 9
        })
    );
    assert_eq!(pool.snapshot().expect("time unchanged"), before);
}

#[test]
fn deterministic_replay_produces_equal_snapshots() {
    fn run() -> (Vec<ScanTask>, Vec<WorkerNode>, StateSnapshot) {
        let pool = pool();
        register(&pool, 1, "worker-b", 2);
        register(&pool, 1, "worker-a", 2);
        enqueue(&pool, 2, "low", TaskPriority::Low);
        enqueue(&pool, 2, "critical", TaskPriority::Critical);
        let lease = pool
            .assign_next_available(revision(&pool), 3, 10)
            .expect("assign")
            .value;
        pool.start_task(revision(&pool), 3, &lease).expect("start");
        pool.fail_task(revision(&pool), 4, &lease).expect("retry");
        pool.check_invariants().expect("invariants");
        (
            pool.task_queue().tasks().expect("tasks"),
            pool.get_workers().expect("workers"),
            pool.snapshot().expect("snapshot"),
        )
    }
    assert_eq!(run(), run());
}

fn completed_receipt(task_id: &str, worker_id: &str) -> CompletionReceipt {
    let pool = pool();
    register(&pool, 1, worker_id, 1);
    enqueue(&pool, 2, task_id, TaskPriority::Normal);
    let lease = assign(&pool, 3, task_id, worker_id);
    pool.start_task(revision(&pool), 3, &lease).expect("start");
    pool.complete_task(revision(&pool), 4, &lease)
        .expect("complete")
        .value
        .receipt()
        .clone()
}

#[test]
fn result_store_is_bounded_idempotent_and_explicit() {
    let limits = ResultLimits {
        max_results: 2,
        max_result_bytes: 3,
        max_total_bytes: 5,
        max_aggregate_items: 2,
        max_aggregate_bytes: 5,
    };
    let results = ResultAggregator::with_limits(limits).expect("result limits");
    let one = completed_receipt("one", "worker-a");
    let two = completed_receipt("two", "worker-a");
    let stale_one = completed_receipt("one", "worker-b");

    let stored = results
        .store_result(0, &one, vec![1, 2])
        .expect("store one");
    assert_eq!(stored.value, StoreResultOutcome::Stored);
    let replay = results
        .store_result(stored.revision, &one, vec![1, 2])
        .expect("replay");
    assert_eq!(replay.value, StoreResultOutcome::AlreadyStored);
    assert_eq!(replay.revision, stored.revision);
    assert_eq!(
        results.store_result(stored.revision, &one, vec![9]),
        Err(DistributedError::ConflictingResult {
            task_id: "one".to_owned()
        })
    );
    assert_eq!(
        results.store_result(stored.revision, &stale_one, vec![1]),
        Err(DistributedError::MismatchedResultReceipt {
            task_id: "one".to_owned()
        })
    );
    results
        .store_result(stored.revision, &two, vec![3, 4, 5])
        .expect("store two");
    assert_eq!(results.total_bytes().expect("bytes"), 5);

    let aggregate = results
        .aggregate_results(&["two", "one"])
        .expect("aggregate");
    assert_eq!(aggregate[0].task_id(), "two");
    assert_eq!(aggregate[0].bytes(), [3, 4, 5]);
    assert_eq!(aggregate[1].task_id(), "one");
    assert!(!format!("{:?}", aggregate[0]).contains("[3, 4, 5]"));
    assert_eq!(
        results.aggregate_results(&["one", "one"]),
        Err(DistributedError::DuplicateAggregateTask {
            task_id: "one".to_owned()
        })
    );
    assert_eq!(
        results.aggregate_results(&["missing"]),
        Err(DistributedError::MissingResult {
            task_id: "missing".to_owned()
        })
    );
    let oversized_id = "x".repeat(MAX_IDENTIFIER_BYTES + 1);
    assert_eq!(
        results.aggregate_results(&[&oversized_id, "one", "two"]),
        Err(DistributedError::AggregateItemLimitExceeded {
            actual: 3,
            limit: 2
        })
    );
    assert_eq!(
        results.get_result(&oversized_id),
        Err(DistributedError::InvalidTask {
            reason: "task command identifier is invalid"
        })
    );
}

#[test]
fn result_exact_limit_and_plus_one_are_pinned() {
    let results = ResultAggregator::with_limits(ResultLimits {
        max_results: 1,
        max_result_bytes: 2,
        max_total_bytes: 2,
        max_aggregate_items: 1,
        max_aggregate_bytes: 2,
    })
    .expect("limits");
    let one = completed_receipt("one", "worker-a");
    let two = completed_receipt("two", "worker-a");
    results
        .store_result(0, &one, vec![1, 2])
        .expect("exact limit");
    assert_eq!(
        results.store_result(1, &two, vec![3]),
        Err(DistributedError::ResultCapacityReached { limit: 1 })
    );
    let oversized = ResultAggregator::with_limits(ResultLimits {
        max_results: 1,
        max_result_bytes: 2,
        max_total_bytes: 2,
        max_aggregate_items: 1,
        max_aggregate_bytes: 2,
    })
    .expect("limits");
    assert_eq!(
        oversized.store_result(0, &one, vec![1, 2, 3]),
        Err(DistributedError::ResultTooLarge {
            actual: 3,
            limit: 2
        })
    );
    assert_eq!(oversized.revision().expect("revision"), 0);
}

#[test]
fn short_command_model_sequences_preserve_invariants() {
    for code in 0u32..256 {
        let pool = pool();
        register(&pool, 1, "worker-a", 2);
        enqueue(&pool, 2, "task-a", TaskPriority::Normal);
        enqueue(&pool, 2, "task-b", TaskPriority::High);
        let mut leases = Vec::new();
        for (now, step) in (3u64..).zip(0..4) {
            let operation = (code >> (step * 2)) & 3;
            let before = pool.snapshot().expect("before model command");
            let result = match operation {
                0 => pool
                    .assign_next_available(before.revision, now, 5)
                    .map(|transition| {
                        leases.push(transition.value);
                    }),
                1 => leases
                    .last()
                    .map_or(Err(DistributedError::NoQueuedTask), |lease| {
                        pool.fail_task(before.revision, now, lease).map(|_| ())
                    }),
                2 => pool
                    .recover_expired_leases(before.revision, now)
                    .map(|_| ()),
                _ => pool.expire_old_tasks(before.revision, now, 100).map(|_| ()),
            };
            if result.is_err() {
                assert_eq!(pool.snapshot().expect("failed command snapshot"), before);
            }
            pool.check_invariants().expect("model invariants");
        }
    }
}
