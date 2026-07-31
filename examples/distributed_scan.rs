//! Exercise the in-process distributed scheduling primitives.
//!
//! Run with:
//! `cargo run -p venom-examples --bin distributed_scan`

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use venom_scanner::distributed::WorkerTag;
use venom_scanner::{ScanTask, TaskPriority, TaskStatus, WorkerNode, WorkerPool, WorkerStatus};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn worker(id: &str, cpu_utilization: f32) -> WorkerNode {
    WorkerNode {
        worker_id: id.into(),
        hostname: format!("{id}.example.test"),
        address: "127.0.0.1".into(),
        port: 7000,
        status: WorkerStatus::Healthy,
        capacity: 4,
        current_tasks: 0,
        completed_tasks: 0,
        last_heartbeat: now_secs(),
        cpu_utilization,
        memory_utilization: 20.0,
        network_utilization: 10.0,
        tags: HashSet::from([WorkerTag::Linux, WorkerTag::Internal]),
    }
}

fn main() {
    let pool = WorkerPool::new();
    pool.register_worker(worker("worker-a", 15.0));
    pool.register_worker(worker("worker-b", 70.0));

    let task = ScanTask {
        task_id: "task-001".into(),
        scan_id: "scan-001".into(),
        target: "https://example.test".into(),
        phases: vec![1, 2, 3],
        assigned_to: None,
        status: TaskStatus::Queued,
        created_at: now_secs(),
        started_at: None,
        completed_at: None,
        priority: TaskPriority::Normal,
        retry_count: 0,
    };
    pool.task_queue.enqueue(task);

    let selected = pool
        .get_available_worker()
        .expect("at least one worker should be available");
    assert!(pool.assign_task("task-001", &selected.worker_id));

    let assigned = pool
        .task_queue
        .get_task("task-001")
        .expect("assigned task should remain queryable");
    println!(
        "task={} worker={} status={}",
        assigned.task_id,
        assigned.assigned_to.as_deref().unwrap_or("unassigned"),
        assigned.status.as_str()
    );
}
