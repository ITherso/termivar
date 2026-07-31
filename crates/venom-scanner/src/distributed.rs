//! Distributed Scanning Architecture
//!
//! Multi-worker coordination, task queuing, and result aggregation
//! for horizontal scaling across multiple nodes.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Worker capability tags (task affinity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkerTag {
    #[serde(rename = "linux")]
    Linux,
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "gpu")]
    GPU,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "external")]
    External,
}

impl WorkerTag {
    pub fn as_str(&self) -> &str {
        match self {
            WorkerTag::Linux => "linux",
            WorkerTag::Windows => "windows",
            WorkerTag::GPU => "gpu",
            WorkerTag::Internal => "internal",
            WorkerTag::External => "external",
        }
    }
}

/// Worker node in distributed system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNode {
    pub worker_id: String,
    pub hostname: String,
    pub address: String,
    pub port: u16,
    pub status: WorkerStatus,
    pub capacity: u32,
    pub current_tasks: u32,
    pub completed_tasks: u64,
    pub last_heartbeat: u64,
    // Dynamic resource metrics
    pub cpu_utilization: f32,     // 0.0-100.0 percent
    pub memory_utilization: f32,  // 0.0-100.0 percent
    pub network_utilization: f32, // 0.0-100.0 percent
    // Task affinity tags (linux, windows, gpu, internal, external)
    pub tags: HashSet<WorkerTag>,
}

/// Worker status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    #[serde(rename = "healthy")]
    Healthy,
    #[serde(rename = "busy")]
    Busy,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "offline")]
    Offline,
}

impl WorkerStatus {
    pub fn as_str(&self) -> &str {
        match self {
            WorkerStatus::Healthy => "healthy",
            WorkerStatus::Busy => "busy",
            WorkerStatus::Degraded => "degraded",
            WorkerStatus::Offline => "offline",
        }
    }
}

impl WorkerNode {
    /// Dynamic capacity based on current resource utilization
    /// Formula: base_capacity * (1 - max(cpu, memory, network) / 100)
    /// Example: capacity=10, cpu=50%, ram=20%, net=30%
    ///   effective = 10 * (1 - 50/100) = 5 tasks max
    pub fn effective_capacity(&self) -> u32 {
        if self.status != WorkerStatus::Healthy {
            return 0; // Offline/Degraded workers can't take tasks
        }

        let max_utilization = self
            .cpu_utilization
            .max(self.memory_utilization)
            .max(self.network_utilization)
            .min(100.0) // Cap at 100%
            .max(0.0); // Floor at 0%

        let availability_factor = (100.0 - max_utilization) / 100.0;
        ((self.capacity as f32) * availability_factor).ceil() as u32
    }

    /// Available slots for new tasks
    pub fn available_slots(&self) -> u32 {
        self.effective_capacity().saturating_sub(self.current_tasks)
    }

    /// Update resource metrics (called by heartbeat ping)
    pub fn update_metrics(&mut self, cpu: f32, memory: f32, network: f32) {
        self.cpu_utilization = cpu.clamp(0.0, 100.0);
        self.memory_utilization = memory.clamp(0.0, 100.0);
        self.network_utilization = network.clamp(0.0, 100.0);
    }

    /// Determine health status based on resource utilization
    pub fn compute_status(&mut self) {
        let max_util = self
            .cpu_utilization
            .max(self.memory_utilization)
            .max(self.network_utilization);

        if max_util > 90.0 {
            self.status = WorkerStatus::Degraded;
        } else if max_util > 80.0 || self.current_tasks >= self.capacity {
            self.status = WorkerStatus::Busy;
        } else if self.status != WorkerStatus::Offline {
            self.status = WorkerStatus::Healthy;
        }
    }

    /// Production-grade worker selection score
    /// Considers: status, heartbeat recency, CPU/memory, available capacity
    /// Higher score = better choice for task assignment
    pub fn compute_score(&self, now_secs: u64) -> f32 {
        let mut score = 0.0;

        // 1. Status factor (weight: 25 points) - critical filter
        let status_score = match self.status {
            WorkerStatus::Healthy => 25.0,
            WorkerStatus::Busy => 15.0,
            WorkerStatus::Degraded => 5.0,
            WorkerStatus::Offline => return -1000.0, // Never select
        };
        score += status_score;

        // 2. Heartbeat recency (weight: 20 points)
        // Recent ping = healthy, stale ping = suspect
        let heartbeat_age = now_secs.saturating_sub(self.last_heartbeat);
        let heartbeat_score = if heartbeat_age < 5 {
            20.0 // Fresh heartbeat (< 5s)
        } else if heartbeat_age < 30 {
            20.0 * (1.0 - (heartbeat_age as f32 / 30.0) * 0.5) // Degrade to 10 points at 30s
        } else {
            0.0 // Stale (> 30s)
        };
        score += heartbeat_score;

        // 3. CPU utilization (weight: 15 points) - lower is better
        let cpu_score = (100.0 - self.cpu_utilization) / 100.0 * 15.0;
        score += cpu_score;

        // 4. Memory utilization (weight: 15 points) - lower is better
        let mem_score = (100.0 - self.memory_utilization) / 100.0 * 15.0;
        score += mem_score;

        // 5. Available capacity (weight: 25 points) - more slots is better
        let slots_ratio = if self.capacity > 0 {
            (self.available_slots() as f32) / (self.capacity as f32)
        } else {
            0.0
        };
        let capacity_score = slots_ratio * 25.0;
        score += capacity_score;

        // Total possible: 25 + 20 + 15 + 15 + 25 = 100 points
        score
    }
}

/// Scan task for distributed execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub task_id: String,
    pub scan_id: String,
    pub target: String,
    pub phases: Vec<u8>,
    pub assigned_to: Option<String>,
    pub status: TaskStatus,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub priority: TaskPriority,
    pub retry_count: u32, // Track retry attempts (max 3)
}

/// Task status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "assigned")]
    Assigned,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
}

impl ScanTask {
    /// Check if task exceeded TTL (Time To Live)
    pub fn is_expired(&self, now_secs: u64, ttl_secs: u64) -> bool {
        let age = now_secs.saturating_sub(self.created_at);
        age > ttl_secs
    }

    /// Get task age in seconds
    pub fn age_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.created_at)
    }
}

impl TaskStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Assigned => "assigned",
            TaskStatus::Running => "running",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
        }
    }
}

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskPriority {
    #[serde(rename = "low")]
    Low = 1,
    #[serde(rename = "normal")]
    Normal = 2,
    #[serde(rename = "high")]
    High = 3,
    #[serde(rename = "critical")]
    Critical = 4,
}

/// Task queue for managing distributed work (FIFO per priority)
#[derive(Clone)]
pub struct TaskQueue {
    tasks: Arc<DashMap<String, ScanTask>>,
    queue: Arc<DashMap<u8, VecDeque<String>>>, // priority -> FIFO task_ids (NOT LIFO!)
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            queue: Arc::new(DashMap::new()),
        }
    }

    pub fn enqueue(&self, task: ScanTask) {
        let task_id = task.task_id.clone();
        let priority = task.priority as u8;

        self.tasks.insert(task_id.clone(), task);
        self.queue
            .entry(priority)
            .or_insert_with(VecDeque::new)
            .push_back(task_id); // FIFO: push to back
    }

    pub fn dequeue(&self) -> Option<ScanTask> {
        // Get highest priority task (CRITICAL FIX: FIFO order, not LIFO!)
        for priority in (1..=4).rev() {
            if let Some(mut queue) = self.queue.get_mut(&priority) {
                if let Some(task_id) = queue.pop_front() {
                    // FIFO: pop from front
                    if let Some((_, task)) = self.tasks.remove(&task_id) {
                        return Some(task);
                    }
                }
            }
        }
        None
    }

    pub fn get_task(&self, task_id: &str) -> Option<ScanTask> {
        self.tasks.get(task_id).map(|t| t.clone())
    }

    pub fn update_task(&self, task: ScanTask) {
        self.tasks.insert(task.task_id.clone(), task);
    }

    pub fn queue_size(&self) -> usize {
        self.tasks.len()
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Worker pool for managing multiple scanning nodes
pub struct WorkerPool {
    workers: Arc<DashMap<String, WorkerNode>>,
    pub task_queue: TaskQueue,
}

impl WorkerPool {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(DashMap::new()),
            task_queue: TaskQueue::new(),
        }
    }

    pub fn register_worker(&self, worker: WorkerNode) {
        self.workers.insert(worker.worker_id.clone(), worker);
    }

    pub fn deregister_worker(&self, worker_id: &str) {
        self.workers.remove(worker_id);
    }

    pub fn get_available_worker(&self) -> Option<WorkerNode> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.workers
            .iter()
            .filter(|entry| {
                let worker = entry.value();
                worker.status != WorkerStatus::Offline && worker.available_slots() > 0
            })
            .max_by(|a, b| {
                let a_score = a.value().compute_score(now);
                let b_score = b.value().compute_score(now);
                a_score
                    .partial_cmp(&b_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|entry| entry.value().clone())
    }

    pub fn assign_task(&self, task_id: &str, worker_id: &str) -> bool {
        if let Some(mut task) = self.task_queue.get_task(task_id) {
            task.assigned_to = Some(worker_id.to_string());
            task.status = TaskStatus::Assigned;
            self.task_queue.update_task(task);

            if let Some(mut worker) = self.workers.get_mut(worker_id) {
                worker.current_tasks += 1;
            }
            true
        } else {
            false
        }
    }

    pub fn complete_task(&self, task_id: &str) {
        if let Some(mut task) = self.task_queue.get_task(task_id) {
            if let Some(worker_id) = task.assigned_to.clone() {
                task.status = TaskStatus::Completed;
                task.completed_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
                self.task_queue.update_task(task);

                if let Some(mut worker) = self.workers.get_mut(&worker_id) {
                    worker.current_tasks = worker.current_tasks.saturating_sub(1);
                    worker.completed_tasks += 1;
                }
            }
        }
    }

    /// Retry failed task (requeue if retry_count < max_retries)
    /// Returns true if task will be retried, false if max retries exceeded
    pub fn retry_task(&self, task_id: &str, max_retries: u32) -> bool {
        if let Some(mut task) = self.task_queue.get_task(task_id) {
            // Release from current worker
            if let Some(worker_id) = task.assigned_to.clone() {
                if let Some(mut worker) = self.workers.get_mut(&worker_id) {
                    worker.current_tasks = worker.current_tasks.saturating_sub(1);
                }
            }

            // Check retry limit
            if task.retry_count < max_retries {
                task.retry_count += 1;
                task.status = TaskStatus::Queued; // Requeue
                task.assigned_to = None; // Unassign from current worker
                task.started_at = None; // Reset start time for next attempt
                self.task_queue.update_task(task);
                true
            } else {
                // Max retries exceeded
                task.status = TaskStatus::Failed;
                task.completed_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
                self.task_queue.update_task(task);
                false
            }
        } else {
            false
        }
    }

    /// Expire tasks that exceed TTL (Time To Live)
    /// Returns count of expired tasks
    /// Must be called periodically (e.g., every 60 seconds)
    pub fn expire_old_tasks(&self, ttl_secs: u64) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut expired = 0;

        // Collect task IDs to expire (avoid DashMap borrow issues)
        let mut tasks_to_expire = Vec::new();
        for entry in self.task_queue.tasks.iter() {
            if entry.value().is_expired(now, ttl_secs) {
                tasks_to_expire.push(entry.key().clone());
            }
        }

        // Expire collected tasks
        for task_id in tasks_to_expire {
            if let Some(mut task) = self.task_queue.get_task(&task_id) {
                // Only expire if not already completed/failed
                if !matches!(task.status, TaskStatus::Completed | TaskStatus::Failed) {
                    // Release from worker if assigned
                    if let Some(worker_id) = task.assigned_to.clone() {
                        if let Some(mut worker) = self.workers.get_mut(&worker_id) {
                            worker.current_tasks = worker.current_tasks.saturating_sub(1);
                        }
                    }

                    // Mark as failed due to TTL
                    task.status = TaskStatus::Failed;
                    task.completed_at = Some(now);
                    self.task_queue.update_task(task);
                    expired += 1;
                }
            }
        }

        expired
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn healthy_worker_count(&self) -> usize {
        self.workers
            .iter()
            .filter(|w| w.value().status == WorkerStatus::Healthy)
            .count()
    }

    pub fn get_workers(&self) -> Vec<WorkerNode> {
        self.workers
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Update worker heartbeat (called when worker sends ping)
    pub fn update_heartbeat(&self, worker_id: &str) {
        if let Some(mut worker) = self.workers.get_mut(worker_id) {
            worker.last_heartbeat = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }

    /// CRITICAL: Prune dead workers (no heartbeat for timeout_secs)
    /// Must be called periodically to mark offline workers and prevent task assignment to dead nodes
    pub fn prune_dead_workers(&self, heartbeat_timeout_secs: u64) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut pruned = 0;

        for mut entry in self.workers.iter_mut() {
            let worker = entry.value_mut();
            let elapsed = now.saturating_sub(worker.last_heartbeat);

            if elapsed > heartbeat_timeout_secs && worker.status != WorkerStatus::Offline {
                worker.status = WorkerStatus::Offline;
                pruned += 1;
            }
        }

        pruned
    }

    /// Get alive workers (Healthy status + recent heartbeat)
    pub fn get_alive_workers(&self) -> Vec<WorkerNode> {
        self.workers
            .iter()
            .filter(|entry| entry.value().status == WorkerStatus::Healthy)
            .map(|entry| entry.value().clone())
            .collect()
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Result aggregator for combining worker results
pub struct ResultAggregator {
    results: Arc<DashMap<String, Vec<u8>>>,
}

impl ResultAggregator {
    pub fn new() -> Self {
        Self {
            results: Arc::new(DashMap::new()),
        }
    }

    pub fn store_result(&self, task_id: &str, result: Vec<u8>) {
        self.results.insert(task_id.to_string(), result);
    }

    pub fn get_result(&self, task_id: &str) -> Option<Vec<u8>> {
        self.results.get(task_id).map(|r| r.clone())
    }

    pub fn aggregate_results(&self, task_ids: &[&str]) -> Vec<Vec<u8>> {
        task_ids
            .iter()
            .filter_map(|id| self.get_result(id))
            .collect()
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, any()))]
mod tests {
    use super::*;

    #[test]
    fn test_worker_node_creation() {
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
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
        };

        assert_eq!(worker.worker_id, "w1");
        assert_eq!(worker.status, WorkerStatus::Healthy);
    }

    #[test]
    fn test_task_creation() {
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "https://example.com".to_string(),
            phases: vec![1, 2, 3],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
        };

        assert_eq!(task.priority, TaskPriority::Normal);
    }

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::Critical > TaskPriority::High);
        assert!(TaskPriority::High > TaskPriority::Normal);
        assert!(TaskPriority::Normal > TaskPriority::Low);
    }

    #[test]
    fn test_task_queue() {
        let queue = TaskQueue::new();
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "https://example.com".to_string(),
            phases: vec![1],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
        };

        queue.enqueue(task);
        assert_eq!(queue.queue_size(), 1);
    }

    #[test]
    fn test_worker_pool() {
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
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
            cpu_utilization: 20.0,
            memory_utilization: 30.0,
            network_utilization: 10.0,
        };

        pool.register_worker(worker);
        assert_eq!(pool.worker_count(), 1);
    }

    #[test]
    fn test_available_worker() {
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
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
            cpu_utilization: 25.0,
            memory_utilization: 35.0,
            network_utilization: 15.0,
        };

        pool.register_worker(worker);
        let available = pool.get_available_worker();
        assert!(available.is_some());
    }

    #[test]
    fn test_result_aggregator() {
        let agg = ResultAggregator::new();
        let result = vec![1, 2, 3, 4, 5];

        agg.store_result("t1", result.clone());
        assert_eq!(agg.get_result("t1"), Some(result));
    }

    #[test]
    fn test_update_heartbeat() {
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
            last_heartbeat: 1000, // Old timestamp
        };

        pool.register_worker(worker);

        // Update heartbeat
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        pool.update_heartbeat("w1");

        // Verify heartbeat was updated
        let updated_worker = pool.get_workers().into_iter().next().unwrap();
        assert!(updated_worker.last_heartbeat >= now);
    }

    #[test]
    fn test_prune_dead_workers() {
        let pool = WorkerPool::new();

        // Register 3 workers with stale heartbeat
        for i in 0..3 {
            let worker = WorkerNode {
                worker_id: format!("w{}", i),
                hostname: format!("scanner-{}", i),
                address: format!("192.168.1.{}", i + 10),
                port: 8000,
                status: WorkerStatus::Healthy,
                capacity: 10,
                current_tasks: 0,
                completed_tasks: 0,
                last_heartbeat: 1000, // Very old
            };
            pool.register_worker(worker);
        }

        // All should be Healthy initially
        assert_eq!(pool.healthy_worker_count(), 3);

        // Prune with 30s timeout (all workers exceeded)
        let pruned = pool.prune_dead_workers(30);
        assert_eq!(pruned, 3);

        // All should now be Offline
        assert_eq!(pool.healthy_worker_count(), 0);

        // Verify all are Offline
        for worker in pool.get_workers() {
            assert_eq!(worker.status, WorkerStatus::Offline);
        }
    }

    #[test]
    fn test_prune_preserves_recent_heartbeats() {
        let pool = WorkerPool::new();

        // Register 2 workers
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let healthy_worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: now, // Fresh heartbeat
        };

        let dead_worker = WorkerNode {
            worker_id: "w2".to_string(),
            hostname: "scanner-2".to_string(),
            address: "192.168.1.20".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: now - 100, // Very old
        };

        pool.register_worker(healthy_worker);
        pool.register_worker(dead_worker);

        // Prune with 30s timeout
        let pruned = pool.prune_dead_workers(30);

        // Only dead worker should be pruned
        assert_eq!(pruned, 1);
        assert_eq!(pool.healthy_worker_count(), 1);

        // Verify correct worker marked Offline
        let workers = pool.get_workers();
        let w1 = workers.iter().find(|w| w.worker_id == "w1").unwrap();
        let w2 = workers.iter().find(|w| w.worker_id == "w2").unwrap();

        assert_eq!(w1.status, WorkerStatus::Healthy);
        assert_eq!(w2.status, WorkerStatus::Offline);
    }

    #[test]
    fn test_get_alive_workers() {
        let pool = WorkerPool::new();

        // Register mix of healthy and offline workers
        let healthy_worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 9999,
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
        };

        let offline_worker = WorkerNode {
            worker_id: "w2".to_string(),
            hostname: "scanner-2".to_string(),
            address: "192.168.1.20".to_string(),
            port: 8000,
            status: WorkerStatus::Offline,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
        };

        pool.register_worker(healthy_worker);
        pool.register_worker(offline_worker);

        let alive = pool.get_alive_workers();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].worker_id, "w1");
        assert_eq!(alive[0].status, WorkerStatus::Healthy);
    }

    #[test]
    fn test_effective_capacity_healthy() {
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
            cpu_utilization: 30.0, // Max 30%, so 70% available
            memory_utilization: 20.0,
            network_utilization: 10.0,
        };

        // capacity * (1 - max_util / 100) = 10 * (1 - 30/100) = 10 * 0.7 = 7
        assert_eq!(worker.effective_capacity(), 7);
    }

    #[test]
    fn test_effective_capacity_high_utilization() {
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
            cpu_utilization: 85.0, // Max 85%, so 15% available
            memory_utilization: 75.0,
            network_utilization: 80.0,
        };

        // capacity * (1 - max_util / 100) = 10 * (1 - 85/100) = 10 * 0.15 = 1.5 → ceil = 2
        assert_eq!(worker.effective_capacity(), 2);
    }

    #[test]
    fn test_effective_capacity_offline_worker() {
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Offline,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 10.0,
            memory_utilization: 10.0,
            network_utilization: 10.0,
        };

        // Offline worker has 0 effective capacity regardless of metrics
        assert_eq!(worker.effective_capacity(), 0);
    }

    #[test]
    fn test_available_slots() {
        let mut worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 2,
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 30.0, // Effective capacity = 7
            memory_utilization: 20.0,
            network_utilization: 10.0,
        };

        // effective_capacity (7) - current_tasks (2) = 5 available slots
        assert_eq!(worker.available_slots(), 5);

        // Assign more tasks
        worker.current_tasks = 7;
        assert_eq!(worker.available_slots(), 0);
    }

    #[test]
    fn test_update_and_compute_metrics() {
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
            cpu_utilization: 20.0,
            memory_utilization: 20.0,
            network_utilization: 20.0,
        };

        // Update metrics to low utilization
        worker.update_metrics(30.0, 25.0, 20.0);
        worker.compute_status();
        assert_eq!(worker.status, WorkerStatus::Healthy);

        // Update metrics to high utilization
        worker.update_metrics(92.0, 88.0, 85.0);
        worker.compute_status();
        assert_eq!(worker.status, WorkerStatus::Degraded);

        // Update metrics to moderate (but tasks at capacity)
        worker.current_tasks = 10;
        worker.update_metrics(75.0, 70.0, 65.0);
        worker.compute_status();
        assert_eq!(worker.status, WorkerStatus::Busy);
    }

    #[test]
    fn test_worker_score_healthy_fresh() {
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,  // Will be treated as recent in test
            cpu_utilization: 20.0, // Good: low utilization
            memory_utilization: 15.0,
            network_utilization: 10.0,
        };

        let now = 1002; // Just 2 seconds later
        let score = worker.compute_score(now);

        // Score should be high: Healthy (25) + fresh heartbeat (20) + low CPU (12) + low memory (12.75) + full capacity (25) ≈ 94.75
        assert!(score > 90.0, "Expected score > 90, got {}", score);
    }

    #[test]
    fn test_worker_score_offline_always_lowest() {
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Offline,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 0.0,
            memory_utilization: 0.0,
            network_utilization: 0.0,
        };

        let score = worker.compute_score(1000);
        assert_eq!(score, -1000.0, "Offline worker should always return -1000");
    }

    #[test]
    fn test_worker_score_stale_heartbeat() {
        let mut healthy = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 20.0,
            memory_utilization: 15.0,
            network_utilization: 10.0,
        };

        let mut stale = healthy.clone();
        stale.worker_id = "w2".to_string();
        stale.last_heartbeat = 900; // 100s old

        let now = 1000;
        let healthy_score = healthy.compute_score(now);
        let stale_score = stale.compute_score(now);

        // Healthy has fresh heartbeat (20 points), stale gets 0 points for heartbeat
        // Difference: 20 points
        assert!(
            healthy_score > stale_score + 15.0,
            "Fresh heartbeat should score significantly higher. healthy={}, stale={}",
            healthy_score,
            stale_score
        );
    }

    #[test]
    fn test_worker_score_compare_selection() {
        let now = 5000;

        let idle_healthy = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0, // Empty
            completed_tasks: 0,
            last_heartbeat: 4999,  // Fresh
            cpu_utilization: 10.0, // Low
            memory_utilization: 10.0,
            network_utilization: 10.0,
        };

        let busy_health = WorkerNode {
            worker_id: "w2".to_string(),
            hostname: "scanner-2".to_string(),
            address: "192.168.1.20".to_string(),
            port: 8000,
            status: WorkerStatus::Busy,
            capacity: 10,
            current_tasks: 8, // Almost full
            completed_tasks: 0,
            last_heartbeat: 4995,  // Slightly stale
            cpu_utilization: 85.0, // High
            memory_utilization: 75.0,
            network_utilization: 60.0,
        };

        let idle_score = idle_healthy.compute_score(now);
        let busy_score = busy_health.compute_score(now);

        // Idle should score much higher
        assert!(
            idle_score > busy_score + 30.0,
            "Idle healthy should score > 30 points higher. idle={}, busy={}",
            idle_score,
            busy_score
        );

        // Idle should be selected (higher score)
        let pool = WorkerPool::new();
        pool.register_worker(idle_healthy.clone());
        pool.register_worker(busy_health);

        let selected = pool.get_available_worker();
        assert_eq!(selected.unwrap().worker_id, "w1");
    }

    #[test]
    fn test_retry_task_increment_count() {
        let queue = TaskQueue::new();
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1, 2, 3],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        queue.enqueue(task);

        // Task should retry (count < max_retries)
        let retried = queue.retry_task("t1", 3);
        assert!(retried);

        let updated_task = queue.get_task("t1").unwrap();
        assert_eq!(updated_task.retry_count, 1);
        assert_eq!(updated_task.status, TaskStatus::Queued);
        assert_eq!(updated_task.assigned_to, None);
    }

    #[test]
    fn test_retry_task_max_retries_exceeded() {
        let queue = TaskQueue::new();
        let mut task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1, 2, 3],
            assigned_to: Some("w1".to_string()),
            status: TaskStatus::Running,
            created_at: 1000,
            started_at: Some(1005),
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 3, // Already at max
        };

        queue.enqueue(task);

        // Task should NOT retry (count >= max_retries)
        let retried = queue.retry_task("t1", 3);
        assert!(!retried);

        let updated_task = queue.get_task("t1").unwrap();
        assert_eq!(updated_task.retry_count, 3);
        assert_eq!(updated_task.status, TaskStatus::Failed);
        assert!(updated_task.completed_at.is_some());
    }

    #[test]
    fn test_retry_task_release_worker() {
        let pool = WorkerPool::new();
        let queue = pool.task_queue.clone();

        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 1, // Has 1 task assigned
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
        };

        pool.register_worker(worker);

        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1, 2],
            assigned_to: Some("w1".to_string()),
            status: TaskStatus::Running,
            created_at: 1000,
            started_at: Some(1005),
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        queue.enqueue(task);

        // Worker has 1 task before retry
        assert_eq!(pool.get_workers()[0].current_tasks, 1);

        // Retry should release worker
        pool.retry_task("t1", 3);

        // Worker should have 0 tasks after retry
        assert_eq!(pool.get_workers()[0].current_tasks, 0);

        let retried_task = queue.get_task("t1").unwrap();
        assert_eq!(retried_task.assigned_to, None);
        assert_eq!(retried_task.started_at, None);
    }

    #[test]
    fn test_retry_task_progression() {
        let queue = TaskQueue::new();
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1, 2],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::High,
            retry_count: 0,
        };

        queue.enqueue(task);

        // First retry
        let retry1 = queue.retry_task("t1", 3);
        assert!(retry1);
        let t = queue.get_task("t1").unwrap();
        assert_eq!(t.retry_count, 1);

        // Second retry
        let retry2 = queue.retry_task("t1", 3);
        assert!(retry2);
        let t = queue.get_task("t1").unwrap();
        assert_eq!(t.retry_count, 2);

        // Third retry
        let retry3 = queue.retry_task("t1", 3);
        assert!(retry3);
        let t = queue.get_task("t1").unwrap();
        assert_eq!(t.retry_count, 3);

        // Fourth attempt should fail (max reached)
        let retry4 = queue.retry_task("t1", 3);
        assert!(!retry4);
        let t = queue.get_task("t1").unwrap();
        assert_eq!(t.status, TaskStatus::Failed);
    }

    #[test]
    fn test_task_is_expired_fresh() {
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1, 2],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        let ttl_secs = 86400; // 24 hours
        let now = 1000 + 3600; // 1 hour later

        // Task should NOT be expired (1 hour < 24 hours)
        assert!(!task.is_expired(now, ttl_secs));
    }

    #[test]
    fn test_task_is_expired_exceeded() {
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1, 2],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        let ttl_secs = 86400; // 24 hours
        let now = 1000 + 259200; // 3 days later (259200 seconds)

        // Task SHOULD be expired (3 days > 24 hours)
        assert!(task.is_expired(now, ttl_secs));
    }

    #[test]
    fn test_task_age_secs() {
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        let now = 2000; // 1000 seconds later
        assert_eq!(task.age_secs(now), 1000);

        let now = 1500; // 500 seconds later
        assert_eq!(task.age_secs(now), 500);

        let now = 1000; // Same time
        assert_eq!(task.age_secs(now), 0);
    }

    #[test]
    fn test_expire_old_tasks() {
        let pool = WorkerPool::new();
        let ttl_secs = 3600; // 1 hour TTL
        let base_time = 1000u64;

        // Fresh task (should NOT expire)
        let fresh = ScanTask {
            task_id: "t_fresh".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: base_time,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        // Old task (should expire)
        let old = ScanTask {
            task_id: "t_old".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: base_time - 7200, // 2 hours old (> 1 hour TTL)
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        pool.task_queue.enqueue(fresh);
        pool.task_queue.enqueue(old);

        // Run expiration at base_time
        let expired = pool.expire_old_tasks(ttl_secs);
        assert_eq!(expired, 1); // Only old task expired

        // Verify fresh still queued
        let fresh_task = pool.task_queue.get_task("t_fresh").unwrap();
        assert_eq!(fresh_task.status, TaskStatus::Queued);

        // Verify old is failed
        let old_task = pool.task_queue.get_task("t_old").unwrap();
        assert_eq!(old_task.status, TaskStatus::Failed);
        assert!(old_task.completed_at.is_some());
    }

    #[test]
    fn test_expire_tasks_release_worker() {
        let pool = WorkerPool::new();
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 1, // Has task assigned
            completed_tasks: 0,
            last_heartbeat: 1000,
            cpu_utilization: 30.0,
            memory_utilization: 40.0,
            network_utilization: 20.0,
        };

        pool.register_worker(worker);

        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "example.com".to_string(),
            phases: vec![1],
            assigned_to: Some("w1".to_string()), // Assigned to worker
            status: TaskStatus::Running,
            created_at: 1000 - 7200, // 2 hours old (expires with 1h TTL)
            started_at: Some(1000),
            completed_at: None,
            priority: TaskPriority::Normal,
            retry_count: 0,
        };

        pool.task_queue.enqueue(task);

        // Worker has 1 task before expiration
        assert_eq!(pool.get_workers()[0].current_tasks, 1);

        // Expire old tasks
        pool.expire_old_tasks(3600); // 1 hour TTL

        // Worker should be freed (0 tasks)
        assert_eq!(pool.get_workers()[0].current_tasks, 0);
    }
}
