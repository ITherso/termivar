//! Distributed Scanning Architecture
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `distributed`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! In-process worker models, task queuing, and result aggregation. This module
//! provides no durable queue, remote worker transport, or multi-node scaling.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
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
            .clamp(0.0, 100.0);

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

    /// Experimental in-memory worker selection score.
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
        self.queue.entry(priority).or_default().push_back(task_id); // FIFO: push to back
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
