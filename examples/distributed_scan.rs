//! Exercise the bounded deterministic in-process coordinator.
//!
//! Run with:
//! `cargo run -p termivar-examples --bin distributed_scan`

use std::collections::BTreeSet;
use termivar_scanner::{TaskPriority, TaskSpec, WorkerPool, WorkerSpec, WorkerTag};

fn main() {
    let pool = WorkerPool::new();
    let mut worker = WorkerSpec::new("worker-a", 4);
    // Tags are bounded observational metadata, not affinity requirements.
    worker.tags = BTreeSet::from([WorkerTag::Linux, WorkerTag::Internal]);

    let registered = pool
        .register_worker(0, 1, worker)
        .expect("bounded worker admission");
    let queued = pool
        .task_queue()
        .enqueue(
            registered.revision,
            2,
            TaskSpec::new(
                "task-001",
                "scan-001",
                "opaque-target-ref",
                vec![1, 2, 3],
                TaskPriority::Normal,
            ),
        )
        .expect("bounded task admission");
    let assigned = pool
        .assign_next_available(queued.revision, 3, 30)
        .expect("eligible worker and queued task");
    let task = pool
        .task_queue()
        .get_task(assigned.value.task_id())
        .expect("state lock")
        .expect("assigned task remains queryable");

    println!(
        "revision={} task={} worker={} status={}",
        assigned.revision,
        task.task_id(),
        assigned.value.worker_id(),
        task.status().as_str()
    );
}
