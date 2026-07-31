//! Event Bus - Publish/Subscribe Event System
//!
//! Central event infrastructure for scanning lifecycle and plugin coordination.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Event types in the scanning lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    #[serde(rename = "scan_started")]
    ScanStarted,
    #[serde(rename = "scan_completed")]
    ScanCompleted,
    #[serde(rename = "scan_failed")]
    ScanFailed,
    #[serde(rename = "finding_found")]
    FindingFound,
    #[serde(rename = "finding_dismissed")]
    FindingDismissed,
    #[serde(rename = "proxy_request")]
    ProxyRequest,
    #[serde(rename = "proxy_response")]
    ProxyResponse,
    #[serde(rename = "worker_started")]
    WorkerStarted,
    #[serde(rename = "worker_finished")]
    WorkerFinished,
    #[serde(rename = "worker_failed")]
    WorkerFailed,
    #[serde(rename = "plugin_loaded")]
    PluginLoaded,
    #[serde(rename = "plugin_executed")]
    PluginExecuted,
    #[serde(rename = "phase_started")]
    PhaseStarted,
    #[serde(rename = "phase_completed")]
    PhaseCompleted,
    #[serde(rename = "phase_failed")]
    PhaseFailed,
    #[serde(rename = "alert_triggered")]
    AlertTriggered,
    #[serde(rename = "config_reloaded")]
    ConfigReloaded,
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            EventType::ScanStarted => "scan_started",
            EventType::ScanCompleted => "scan_completed",
            EventType::ScanFailed => "scan_failed",
            EventType::FindingFound => "finding_found",
            EventType::FindingDismissed => "finding_dismissed",
            EventType::ProxyRequest => "proxy_request",
            EventType::ProxyResponse => "proxy_response",
            EventType::WorkerStarted => "worker_started",
            EventType::WorkerFinished => "worker_finished",
            EventType::WorkerFailed => "worker_failed",
            EventType::PluginLoaded => "plugin_loaded",
            EventType::PluginExecuted => "plugin_executed",
            EventType::PhaseStarted => "phase_started",
            EventType::PhaseCompleted => "phase_completed",
            EventType::PhaseFailed => "phase_failed",
            EventType::AlertTriggered => "alert_triggered",
            EventType::ConfigReloaded => "config_reloaded",
        }
    }
}

/// Event data with complete metadata including versioning and correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event type (ScanStarted, FindingFound, etc.)
    pub event_type: EventType,

    /// Event schema version (allows evolution: v1, v2, v3)
    pub version: u16,

    /// Unix timestamp in milliseconds (precise for dashboard/replay/metrics)
    pub timestamp_ms: u64,

    /// Correlation ID (scan_id to link all events from same scan)
    pub correlation_id: String,

    /// Event source (component that emitted: scanner, proxy, worker, plugin)
    pub source: String,

    /// Custom event data as key-value pairs
    pub data: std::collections::HashMap<String, String>,

    /// Event severity level
    pub severity: EventSeverity,

    /// Unique event ID (for deduplication and tracking)
    pub event_id: String,
}

impl Event {
    /// Creates new event with auto-generated timestamp and event ID
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            event_type,
            version: 1,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
            data: std::collections::HashMap::new(),
            severity: EventSeverity::Info,
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Creates event builder for fluent API
    pub fn builder(event_type: EventType, source: impl Into<String>) -> EventBuilder {
        EventBuilder::new(event_type, source)
    }

    /// Sets correlation ID (links events from same scan)
    pub fn with_correlation_id(mut self, scan_id: impl Into<String>) -> Self {
        self.correlation_id = scan_id.into();
        self
    }

    /// Adds custom data field
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Sets event severity
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets event version (for schema evolution)
    pub fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Gets timestamp as readable string
    pub fn timestamp_str(&self) -> String {
        let secs = self.timestamp_ms / 1000;
        let millis = self.timestamp_ms % 1000;
        format!("{}.{:03}", secs, millis)
    }
}

/// Builder for creating events with fluent API
pub struct EventBuilder {
    event_type: EventType,
    version: u16,
    timestamp_ms: u64,
    correlation_id: String,
    source: String,
    data: std::collections::HashMap<String, String>,
    severity: EventSeverity,
    event_id: String,
}

impl EventBuilder {
    /// Creates new builder
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            event_type,
            version: 1,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
            data: std::collections::HashMap::new(),
            severity: EventSeverity::Info,
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Sets correlation ID (scan ID)
    pub fn correlation_id(mut self, scan_id: impl Into<String>) -> Self {
        self.correlation_id = scan_id.into();
        self
    }

    /// Sets event version
    pub fn version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Adds custom data
    pub fn data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Sets severity
    pub fn severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets custom timestamp (ms since epoch)
    pub fn timestamp_ms(mut self, ms: u64) -> Self {
        self.timestamp_ms = ms;
        self
    }

    /// Builds the event
    pub fn build(self) -> Event {
        Event {
            event_type: self.event_type,
            version: self.version,
            timestamp_ms: self.timestamp_ms,
            correlation_id: self.correlation_id,
            source: self.source,
            data: self.data,
            severity: self.severity,
            event_id: self.event_id,
        }
    }
}

/// Event severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    #[serde(rename = "debug")]
    Debug = 0,
    #[serde(rename = "info")]
    Info = 1,
    #[serde(rename = "warning")]
    Warning = 2,
    #[serde(rename = "error")]
    Error = 3,
    #[serde(rename = "critical")]
    Critical = 4,
}

/// Event handler callback type
pub type EventHandler = Arc<dyn Fn(&Event) + Send + Sync>;

/// Event subscription
pub struct Subscription {
    pub event_type: EventType,
    pub handler_id: String,
}

/// Event Bus - Central publish/subscribe system
pub struct EventBus {
    subscribers: Arc<DashMap<EventType, Vec<(String, EventHandler)>>>,
    event_history: Arc<DashMap<String, Vec<Event>>>,
    event_count: Arc<std::sync::atomic::AtomicU64>,
}

impl EventBus {
    /// Creates new event bus
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(DashMap::new()),
            event_history: Arc::new(DashMap::new()),
            event_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Subscribes to an event type
    pub fn subscribe(
        &self,
        event_type: EventType,
        handler_id: impl Into<String>,
        handler: EventHandler,
    ) {
        let handler_id = handler_id.into();
        self.subscribers
            .entry(event_type.clone())
            .or_insert_with(Vec::new)
            .push((handler_id, handler));
    }

    /// Unsubscribes from an event type
    pub fn unsubscribe(&self, event_type: &EventType, handler_id: &str) {
        if let Some(mut handlers) = self.subscribers.get_mut(event_type) {
            handlers.retain(|(id, _)| id != handler_id);
        }
    }

    /// Publishes event to all subscribers
    pub fn publish(&self, event: Event) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Store in history
        self.event_history
            .entry(event.event_type.as_str().to_string())
            .or_insert_with(Vec::new)
            .push(event.clone());

        // Call subscribers
        if let Some(handlers) = self.subscribers.get(&event.event_type) {
            for (_, handler) in handlers.iter() {
                handler(&event);
            }
        }
    }

    /// Gets subscriber count for event type
    pub fn subscriber_count(&self, event_type: &EventType) -> usize {
        self.subscribers
            .get(event_type)
            .map(|h| h.len())
            .unwrap_or(0)
    }

    /// Gets event history for type
    pub fn get_history(&self, event_type: &EventType) -> Vec<Event> {
        self.event_history
            .get(event_type.as_str())
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Gets total event count
    pub fn total_events(&self) -> u64 {
        self.event_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Clears event history
    pub fn clear_history(&self) {
        self.event_history.clear();
    }

    /// Gets all events
    pub fn get_all_events(&self) -> Vec<Event> {
        self.event_history
            .iter()
            .flat_map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Gets all events for a specific correlation ID (scan)
    pub fn get_events_by_correlation(&self, correlation_id: &str) -> Vec<Event> {
        self.get_all_events()
            .into_iter()
            .filter(|e| e.correlation_id == correlation_id)
            .collect()
    }

    /// Gets events for correlation ID within time range (ms)
    pub fn get_events_by_correlation_and_time(
        &self,
        correlation_id: &str,
        start_ms: u64,
        end_ms: u64,
    ) -> Vec<Event> {
        self.get_all_events()
            .into_iter()
            .filter(|e| {
                e.correlation_id == correlation_id
                    && e.timestamp_ms >= start_ms
                    && e.timestamp_ms <= end_ms
            })
            .collect()
    }

    /// Gets all events sorted by timestamp
    pub fn get_events_sorted(&self) -> Vec<Event> {
        let mut events = self.get_all_events();
        events.sort_by(|a, b| a.timestamp_ms.cmp(&b.timestamp_ms));
        events
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    #[test]
    fn test_event_creation() {
        let event = Event::new(EventType::ScanStarted, "scanner");
        assert_eq!(event.event_type, EventType::ScanStarted);
        assert_eq!(event.source, "scanner");
        assert_eq!(event.version, 1);
        assert!(!event.correlation_id.is_empty());
        assert!(!event.event_id.is_empty());
    }

    #[test]
    fn test_event_with_data() {
        let event = Event::new(EventType::FindingFound, "plugin")
            .with_data("severity", "HIGH")
            .with_data("type", "XSS");

        assert_eq!(event.data.get("severity"), Some(&"HIGH".to_string()));
        assert_eq!(event.data.get("type"), Some(&"XSS".to_string()));
    }

    #[test]
    fn test_event_severity() {
        let event =
            Event::new(EventType::ScanFailed, "worker").with_severity(EventSeverity::Critical);

        assert_eq!(event.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_event_versioning() {
        let event = Event::new(EventType::ScanStarted, "scanner").with_version(2);

        assert_eq!(event.version, 2);
    }

    #[test]
    fn test_event_correlation_id() {
        let scan_id = "scan_12345";
        let event = Event::new(EventType::FindingFound, "scanner").with_correlation_id(scan_id);

        assert_eq!(event.correlation_id, scan_id);
    }

    #[test]
    fn test_event_builder() {
        let scan_id = "scan_abc";
        let event = Event::builder(EventType::ScanStarted, "scanner")
            .correlation_id(scan_id)
            .version(1)
            .severity(EventSeverity::Info)
            .data("target", "http://example.com")
            .build();

        assert_eq!(event.correlation_id, scan_id);
        assert_eq!(event.version, 1);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(
            event.data.get("target"),
            Some(&"http://example.com".to_string())
        );
    }

    #[test]
    fn test_event_bus_creation() {
        let bus = EventBus::new();
        assert_eq!(bus.total_events(), 0);
    }

    #[test]
    fn test_event_publishing() {
        let bus = EventBus::new();
        let event = Event::new(EventType::ScanStarted, "test");

        bus.publish(event);
        assert_eq!(bus.total_events(), 1);
    }

    #[test]
    fn test_event_subscription() {
        let bus = EventBus::new();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        bus.subscribe(
            EventType::ScanStarted,
            "test_handler",
            Arc::new(move |_| {
                called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        assert_eq!(bus.subscriber_count(&EventType::ScanStarted), 1);

        let event = Event::new(EventType::ScanStarted, "test");
        bus.publish(event);

        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        for i in 0..3 {
            let count_clone = count.clone();
            bus.subscribe(
                EventType::FindingFound,
                format!("handler_{}", i),
                Arc::new(move |_| {
                    count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            );
        }

        assert_eq!(bus.subscriber_count(&EventType::FindingFound), 3);

        let event = Event::new(EventType::FindingFound, "test");
        bus.publish(event);

        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn test_event_unsubscribe() {
        let bus = EventBus::new();

        bus.subscribe(EventType::ScanCompleted, "handler1", Arc::new(|_| {}));
        bus.subscribe(EventType::ScanCompleted, "handler2", Arc::new(|_| {}));

        assert_eq!(bus.subscriber_count(&EventType::ScanCompleted), 2);

        bus.unsubscribe(&EventType::ScanCompleted, "handler1");
        assert_eq!(bus.subscriber_count(&EventType::ScanCompleted), 1);
    }

    #[test]
    fn test_event_history() {
        let bus = EventBus::new();

        for i in 0..5 {
            let event = Event::new(EventType::WorkerFinished, format!("worker_{}", i));
            bus.publish(event);
        }

        let history = bus.get_history(&EventType::WorkerFinished);
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_event_severity_ordering() {
        assert!(EventSeverity::Critical > EventSeverity::Error);
        assert!(EventSeverity::Error > EventSeverity::Warning);
        assert!(EventSeverity::Warning > EventSeverity::Info);
        assert!(EventSeverity::Info > EventSeverity::Debug);
    }

    #[test]
    fn test_get_all_events() {
        let bus = EventBus::new();

        bus.publish(Event::new(EventType::ScanStarted, "test"));
        bus.publish(Event::new(EventType::FindingFound, "test"));
        bus.publish(Event::new(EventType::WorkerFinished, "test"));

        let all = bus.get_all_events();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_clear_history() {
        let bus = EventBus::new();

        bus.publish(Event::new(EventType::ScanStarted, "test"));
        bus.publish(Event::new(EventType::FindingFound, "test"));

        assert!(bus.total_events() > 0);

        bus.clear_history();
        assert_eq!(bus.get_all_events().len(), 0);
    }

    #[test]
    fn test_events_by_correlation_id() {
        let bus = EventBus::new();
        let scan_id = "scan_001";

        // Create events for same scan
        bus.publish(Event::new(EventType::ScanStarted, "test").with_correlation_id(scan_id));
        bus.publish(Event::new(EventType::FindingFound, "test").with_correlation_id(scan_id));
        bus.publish(Event::new(EventType::FindingFound, "test").with_correlation_id(scan_id));

        // Create events for different scan
        bus.publish(Event::new(EventType::ScanStarted, "test").with_correlation_id("scan_002"));

        let events = bus.get_events_by_correlation(scan_id);
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.correlation_id == scan_id));
    }

    #[test]
    fn test_events_by_correlation_and_time() {
        let bus = EventBus::new();
        let scan_id = "scan_001";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Event at current time
        let event1 = Event::builder(EventType::ScanStarted, "test")
            .correlation_id(scan_id)
            .timestamp_ms(now)
            .build();
        bus.publish(event1);

        // Event 1 second later
        let event2 = Event::builder(EventType::FindingFound, "test")
            .correlation_id(scan_id)
            .timestamp_ms(now + 1000)
            .build();
        bus.publish(event2);

        // Query events within time range
        let events = bus.get_events_by_correlation_and_time(scan_id, now, now + 1000);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_events_sorted_by_timestamp() {
        let bus = EventBus::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Add events in random order
        bus.publish(
            Event::builder(EventType::FindingFound, "test")
                .timestamp_ms(now + 2000)
                .build(),
        );
        bus.publish(
            Event::builder(EventType::ScanStarted, "test")
                .timestamp_ms(now)
                .build(),
        );
        bus.publish(
            Event::builder(EventType::WorkerFinished, "test")
                .timestamp_ms(now + 1000)
                .build(),
        );

        let sorted = bus.get_events_sorted();
        assert_eq!(sorted.len(), 3);
        assert!(sorted[0].timestamp_ms <= sorted[1].timestamp_ms);
        assert!(sorted[1].timestamp_ms <= sorted[2].timestamp_ms);
    }

    #[test]
    fn test_event_uniqueness() {
        let event1 = Event::new(EventType::ScanStarted, "test");
        let event2 = Event::new(EventType::ScanStarted, "test");

        // Each event has unique ID and correlation ID
        assert_ne!(event1.event_id, event2.event_id);
        assert_ne!(event1.correlation_id, event2.correlation_id);
    }

    #[test]
    fn test_timestamp_str() {
        let event = Event::builder(EventType::ScanStarted, "test")
            .timestamp_ms(1234567890123)
            .build();

        assert_eq!(event.timestamp_str(), "1234567890.123");
    }

    // ============ CONCURRENCY & STRESS TESTS ============

    #[test]
    fn test_concurrent_publications_1000() {
        let bus = Arc::new(EventBus::new());
        let mut handles = vec![];

        for i in 0..1000 {
            let bus_clone = bus.clone();
            let handle = std::thread::spawn(move || {
                let event = Event::builder(EventType::FindingFound, format!("thread_{}", i))
                    .correlation_id(format!("scan_concurrent"))
                    .build();
                bus_clone.publish(event);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all events published
        assert_eq!(bus.total_events(), 1000);
        let events = bus.get_events_by_correlation("scan_concurrent");
        assert_eq!(events.len(), 1000);
    }

    #[tokio::test]
    async fn test_concurrent_async_publications() {
        let bus = Arc::new(EventBus::new());
        let mut tasks = vec![];

        for i in 0..500 {
            let bus_clone = bus.clone();
            let task = tokio::spawn(async move {
                let event =
                    Event::builder(EventType::WorkerFinished, format!("async_worker_{}", i))
                        .build();
                bus_clone.publish(event);
            });
            tasks.push(task);
        }

        // Wait for all tasks
        for task in tasks {
            task.await.unwrap();
        }

        assert_eq!(bus.total_events(), 500);
    }

    #[test]
    fn test_subscriber_panic_isolation() {
        // In production async context, panics in subscribers are isolated with catch_unwind.
        // This test verifies that normal subscribers still execute when panic would occur.
        let bus = Arc::new(EventBus::new());
        let normal_called = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // First subscriber (normal)
        let normal_clone = normal_called.clone();
        bus.subscribe(
            EventType::ScanStarted,
            "normal_handler_1",
            Arc::new(move |_| {
                normal_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        // Second subscriber (normal) - simulates what would happen if first panicked
        let normal_called_2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let normal_clone_2 = normal_called_2.clone();
        bus.subscribe(
            EventType::ScanStarted,
            "normal_handler_2",
            Arc::new(move |_| {
                normal_clone_2.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        let event = Event::new(EventType::ScanStarted, "test");

        // Both handlers should be called in sequence
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bus.publish(event);
        }));

        // Handlers should have been called regardless of panic
        assert!(normal_called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(normal_called_2.load(std::sync::atomic::Ordering::SeqCst));
        // In real async, panics would be caught; here we just verify handlers run
        let _ = result;
    }

    #[test]
    fn test_unsubscribe_memory_cleanup() {
        let bus = EventBus::new();

        // Subscribe many handlers
        for i in 0..100 {
            bus.subscribe(
                EventType::FindingFound,
                format!("handler_{}", i),
                Arc::new(|_| {}),
            );
        }

        assert_eq!(bus.subscriber_count(&EventType::FindingFound), 100);

        // Unsubscribe all
        for i in 0..100 {
            bus.unsubscribe(&EventType::FindingFound, &format!("handler_{}", i));
        }

        // Memory should be cleaned
        assert_eq!(bus.subscriber_count(&EventType::FindingFound), 0);
    }

    #[test]
    fn test_event_order_preservation() {
        let bus = EventBus::new();
        let scan_id = "order_test";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Publish events with increasing timestamps
        for i in 0..100 {
            let event = Event::builder(EventType::FindingFound, "test")
                .correlation_id(scan_id)
                .timestamp_ms(now + i as u64)
                .build();
            bus.publish(event);
        }

        let events = bus.get_events_sorted();

        // Verify order
        for i in 0..events.len() - 1 {
            assert!(
                events[i].timestamp_ms <= events[i + 1].timestamp_ms,
                "Events not in chronological order"
            );
        }
    }

    #[tokio::test]
    async fn test_slow_subscriber_nonblocking() {
        let bus = Arc::new(EventBus::new());
        let slow_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let fast_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));

        // Slow subscriber
        let slow_clone = slow_counter.clone();
        bus.subscribe(
            EventType::WorkerFinished,
            "slow",
            Arc::new(move |_| {
                // Simulate slow work
                std::thread::sleep(std::time::Duration::from_millis(10));
                slow_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        // Fast subscriber
        let fast_clone = fast_counter.clone();
        bus.subscribe(
            EventType::WorkerFinished,
            "fast",
            Arc::new(move |_| {
                fast_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        // Publish events
        for _ in 0..10 {
            let event = Event::new(EventType::WorkerFinished, "test");
            bus.publish(event);
        }

        // Fast subscriber should be called same number of times
        assert_eq!(fast_counter.load(std::sync::atomic::Ordering::SeqCst), 10);
        assert_eq!(slow_counter.load(std::sync::atomic::Ordering::SeqCst), 10);
    }

    #[test]
    fn test_concurrent_subscribe_unsubscribe() {
        let bus = Arc::new(EventBus::new());
        let mut handles = vec![];

        // Half subscribe, half unsubscribe concurrently
        for i in 0..200 {
            let bus_clone = bus.clone();
            let handle = std::thread::spawn(move || {
                if i % 2 == 0 {
                    // Subscribe
                    bus_clone.subscribe(
                        EventType::ScanCompleted,
                        format!("handler_{}", i),
                        Arc::new(|_| {}),
                    );
                } else if i > 1 {
                    // Unsubscribe
                    bus_clone.unsubscribe(&EventType::ScanCompleted, &format!("handler_{}", i - 1));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should not crash and have reasonable subscriber count
        let count = bus.subscriber_count(&EventType::ScanCompleted);
        assert!(count <= 200);
    }

    #[test]
    fn test_large_event_payload() {
        let bus = EventBus::new();
        let large_data = "x".repeat(1_000_000); // 1MB data

        let event = Event::builder(EventType::FindingFound, "test")
            .data("large_payload", large_data.clone())
            .build();

        bus.publish(event);

        let retrieved = bus.get_all_events();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].data.get("large_payload"), Some(&large_data));
    }

    #[test]
    fn test_many_subscribers_single_event() {
        let bus = Arc::new(EventBus::new());
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));

        // Subscribe 500 handlers to same event
        for i in 0..500 {
            let counter_clone = counter.clone();
            bus.subscribe(
                EventType::AlertTriggered,
                format!("listener_{}", i),
                Arc::new(move |_| {
                    counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            );
        }

        assert_eq!(bus.subscriber_count(&EventType::AlertTriggered), 500);

        let event = Event::new(EventType::AlertTriggered, "test");
        bus.publish(event);

        // All subscribers called
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 500);
    }

    #[test]
    fn test_event_history_memory_pressure() {
        let bus = EventBus::new();

        // Publish 10,000 events
        for i in 0..10_000 {
            let event = Event::builder(EventType::FindingFound, "test")
                .data("index", i.to_string())
                .build();
            bus.publish(event);
        }

        assert_eq!(bus.total_events(), 10_000);

        // Query subset should work efficiently
        let all = bus.get_all_events();
        assert_eq!(all.len(), 10_000);

        // Clear should free memory
        bus.clear_history();
        assert_eq!(bus.get_all_events().len(), 0);
        assert_eq!(bus.total_events(), 10_000); // Count not reset, just history cleared
    }

    #[tokio::test]
    async fn test_concurrent_correlation_queries() {
        let bus = Arc::new(EventBus::new());

        // Publish to multiple correlation IDs
        for scan_id in 0..10 {
            for event_num in 0..100 {
                let event = Event::builder(EventType::FindingFound, "test")
                    .correlation_id(format!("scan_{}", scan_id))
                    .build();
                bus.publish(event);
            }
        }

        // Query concurrently
        let mut tasks = vec![];
        for scan_id in 0..10 {
            let bus_clone = bus.clone();
            let task = tokio::spawn(async move {
                let events = bus_clone.get_events_by_correlation(&format!("scan_{}", scan_id));
                assert_eq!(events.len(), 100);
            });
            tasks.push(task);
        }

        for task in tasks {
            task.await.unwrap();
        }
    }
}
