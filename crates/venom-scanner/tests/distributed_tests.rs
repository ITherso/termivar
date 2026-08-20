#![cfg(feature = "distributed")]

use std::collections::HashSet;
use venom_scanner::{
    ResultAggregator, ScanTask, TaskPriority, TaskQueue, TaskStatus, WorkerNode, WorkerStatus,
};

fn task(id: &str, priority: TaskPriority) -> ScanTask {
    ScanTask {
        task_id: id.to_owned(),
        scan_id: format!("scan-{id}"),
        target: "https://example.invalid".to_owned(),
        phases: vec![1],
        assigned_to: None,
        status: TaskStatus::Queued,
        created_at: 1,
        started_at: None,
        completed_at: None,
        priority,
        retry_count: 0,
    }
}

fn worker(status: WorkerStatus, current_tasks: u32) -> WorkerNode {
    WorkerNode {
        worker_id: "worker-a".to_owned(),
        hostname: "fixture".to_owned(),
        address: "127.0.0.1".to_owned(),
        port: 9000,
        status,
        capacity: 10,
        current_tasks,
        completed_tasks: 0,
        last_heartbeat: 1,
        cpu_utilization: 20.0,
        memory_utilization: 30.0,
        network_utilization: 10.0,
        tags: HashSet::new(),
    }
}

#[test]
fn task_queue_is_priority_ordered_and_fifo_within_a_priority() {
    let queue = TaskQueue::new();
    queue.enqueue(task("normal-a", TaskPriority::Normal));
    queue.enqueue(task("critical-a", TaskPriority::Critical));
    queue.enqueue(task("critical-b", TaskPriority::Critical));

    assert_eq!(queue.queue_size(), 3);
    assert_eq!(
        queue.dequeue().map(|task| task.task_id),
        Some("critical-a".to_owned())
    );
    assert_eq!(
        queue.dequeue().map(|task| task.task_id),
        Some("critical-b".to_owned())
    );
    assert_eq!(
        queue.dequeue().map(|task| task.task_id),
        Some("normal-a".to_owned())
    );
    assert!(queue.dequeue().is_none());
}

#[test]
fn worker_capacity_is_bounded_by_health_and_utilization() {
    let mut healthy = worker(WorkerStatus::Healthy, 2);
    assert_eq!(healthy.effective_capacity(), 7);
    assert_eq!(healthy.available_slots(), 5);

    healthy.update_metrics(200.0, -10.0, 50.0);
    assert_eq!(healthy.cpu_utilization, 100.0);
    assert_eq!(healthy.memory_utilization, 0.0);
    assert_eq!(healthy.available_slots(), 0);

    let offline = worker(WorkerStatus::Offline, 0);
    assert_eq!(offline.effective_capacity(), 0);
    assert_eq!(offline.available_slots(), 0);
}

#[test]
fn result_aggregation_returns_only_present_requested_entries() {
    let results = ResultAggregator::new();
    results.store_result("one", vec![1, 2]);
    results.store_result("three", vec![3]);

    assert_eq!(
        results.aggregate_results(&["one", "missing", "three"]),
        vec![vec![1, 2], vec![3]]
    );
}
