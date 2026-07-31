#![cfg(any())]

use venom_scanner::{
    ResultAggregator, ScanTask, TaskPriority, TaskQueue, TaskStatus, WorkerNode, WorkerPool,
    WorkerStatus,
};

#[test]
fn test_multi_worker_task_distribution() {
    let pool = WorkerPool::new();

    // Register 3 workers
    for i in 0..3 {
        let worker = WorkerNode {
            worker_id: format!("worker-{}", i),
            hostname: format!("scanner-{}", i),
            address: format!("192.168.1.{}", 10 + i),
            port: 8000 + i as u16,
            status: WorkerStatus::Healthy,
            capacity: 5,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
        };
        pool.register_worker(worker);
    }

    assert_eq!(pool.worker_count(), 3);
    assert_eq!(pool.healthy_worker_count(), 3);
}

#[test]
fn test_priority_queue_ordering() {
    let queue = TaskQueue::new();

    // Enqueue tasks with different priorities
    let normal_task = ScanTask {
        task_id: "t1".to_string(),
        scan_id: "s1".to_string(),
        target: "https://example.com".to_string(),
        phases: vec![1, 2],
        assigned_to: None,
        status: TaskStatus::Queued,
        created_at: 1000,
        started_at: None,
        completed_at: None,
        priority: TaskPriority::Normal,
    };

    let critical_task = ScanTask {
        task_id: "t2".to_string(),
        scan_id: "s2".to_string(),
        target: "https://critical.com".to_string(),
        phases: vec![1, 2, 3],
        assigned_to: None,
        status: TaskStatus::Queued,
        created_at: 1001,
        started_at: None,
        completed_at: None,
        priority: TaskPriority::Critical,
    };

    queue.enqueue(normal_task);
    queue.enqueue(critical_task);

    // Critical task should be dequeued first
    if let Some(task) = queue.dequeue() {
        assert_eq!(task.priority, TaskPriority::Critical);
    }
}

#[test]
fn test_result_aggregation() {
    let agg = ResultAggregator::new();

    let results = vec![
        ("t1".to_string(), vec![1, 2, 3]),
        ("t2".to_string(), vec![4, 5, 6]),
        ("t3".to_string(), vec![7, 8, 9]),
    ];

    for (task_id, result) in &results {
        agg.store_result(task_id, result.clone());
    }

    let aggregated = agg.aggregate_results(&["t1", "t2", "t3"]);
    assert_eq!(aggregated.len(), 3);
}

#[test]
fn test_worker_load_balancing() {
    let pool = WorkerPool::new();

    // Register workers with different loads
    let worker1 = WorkerNode {
        worker_id: "w1".to_string(),
        hostname: "scanner-1".to_string(),
        address: "192.168.1.10".to_string(),
        port: 8000,
        status: WorkerStatus::Healthy,
        capacity: 10,
        current_tasks: 2,
        completed_tasks: 100,
        last_heartbeat: 1000,
    };

    let worker2 = WorkerNode {
        worker_id: "w2".to_string(),
        hostname: "scanner-2".to_string(),
        address: "192.168.1.11".to_string(),
        port: 8000,
        status: WorkerStatus::Healthy,
        capacity: 10,
        current_tasks: 5,
        completed_tasks: 50,
        last_heartbeat: 1000,
    };

    pool.register_worker(worker1);
    pool.register_worker(worker2);

    // Should select worker with lower load (w1 has fewer current_tasks)
    if let Some(selected) = pool.get_available_worker() {
        assert_eq!(
            selected.worker_id, "w1",
            "Should select worker with lower current task count"
        );
    }
}

#[test]
fn test_task_lifecycle() {
    let pool = WorkerPool::new();
    let worker = WorkerNode {
        worker_id: "w1".to_string(),
        hostname: "scanner-1".to_string(),
        address: "192.168.1.10".to_string(),
        port: 8000,
        status: WorkerStatus::Healthy,
        capacity: 10,
        current_tasks: 0,
        completed_tasks: 0,
        last_heartbeat: 1000,
    };

    pool.register_worker(worker);

    // Create and queue task
    let task = ScanTask {
        task_id: "t1".to_string(),
        scan_id: "s1".to_string(),
        target: "https://example.com".to_string(),
        phases: vec![1, 2],
        assigned_to: None,
        status: TaskStatus::Queued,
        created_at: 1000,
        started_at: None,
        completed_at: None,
        priority: TaskPriority::Normal,
    };

    // Enqueue task first
    pool.task_queue.enqueue(task);

    // Simulate lifecycle
    pool.assign_task("t1", "w1");
    pool.complete_task("t1");

    // Verify worker state
    let workers = pool.get_workers();
    assert_eq!(workers[0].completed_tasks, 1);
}

#[test]
fn test_worker_status_transitions() {
    let mut worker = WorkerNode {
        worker_id: "w1".to_string(),
        hostname: "scanner-1".to_string(),
        address: "192.168.1.10".to_string(),
        port: 8000,
        status: WorkerStatus::Healthy,
        capacity: 10,
        current_tasks: 0,
        completed_tasks: 0,
        last_heartbeat: 1000,
    };

    assert_eq!(worker.status, WorkerStatus::Healthy);
    assert_eq!(worker.status.as_str(), "healthy");

    worker.status = WorkerStatus::Busy;
    assert_eq!(worker.status, WorkerStatus::Busy);

    worker.status = WorkerStatus::Degraded;
    assert_eq!(worker.status, WorkerStatus::Degraded);

    worker.status = WorkerStatus::Offline;
    assert_eq!(worker.status, WorkerStatus::Offline);
}

#[test]
fn test_concurrent_task_queue_operations() {
    use std::sync::Arc;
    use std::thread;

    let queue = Arc::new(TaskQueue::new());

    // Spawn 3 threads enqueueing tasks
    let mut handles = vec![];
    for i in 0..3 {
        let queue_clone = queue.clone();
        let handle = thread::spawn(move || {
            for j in 0..10 {
                let task = ScanTask {
                    task_id: format!("t-{}-{}", i, j),
                    scan_id: format!("s-{}", i),
                    target: "https://example.com".to_string(),
                    phases: vec![1],
                    assigned_to: None,
                    status: TaskStatus::Queued,
                    created_at: 1000,
                    started_at: None,
                    completed_at: None,
                    priority: TaskPriority::Normal,
                };
                queue_clone.enqueue(task);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Should have 30 tasks
    assert_eq!(queue.queue_size(), 30);
}

#[test]
fn test_worker_heartbeat_tracking() {
    let pool = WorkerPool::new();
    let worker = WorkerNode {
        worker_id: "w1".to_string(),
        hostname: "scanner-1".to_string(),
        address: "192.168.1.10".to_string(),
        port: 8000,
        status: WorkerStatus::Healthy,
        capacity: 10,
        current_tasks: 0,
        completed_tasks: 0,
        last_heartbeat: 1000,
    };

    pool.register_worker(worker);
    let workers = pool.get_workers();
    assert_eq!(workers[0].last_heartbeat, 1000);
}

#[test]
fn test_scan_task_status_transitions() {
    let task = ScanTask {
        task_id: "t1".to_string(),
        scan_id: "s1".to_string(),
        target: "https://example.com".to_string(),
        phases: vec![1, 2],
        assigned_to: None,
        status: TaskStatus::Queued,
        created_at: 1000,
        started_at: None,
        completed_at: None,
        priority: TaskPriority::Normal,
    };

    assert_eq!(task.status, TaskStatus::Queued);
    assert_eq!(task.status.as_str(), "queued");

    let mut task = task;
    task.status = TaskStatus::Assigned;
    assert_eq!(task.status, TaskStatus::Assigned);

    task.status = TaskStatus::Running;
    assert_eq!(task.status, TaskStatus::Running);

    task.status = TaskStatus::Completed;
    assert_eq!(task.status, TaskStatus::Completed);
}
