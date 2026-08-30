//! Event Bus - Publish/Subscribe Event System
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `legacy-scanner`.
//! - **Execution:** `ScanRunner` publishes `Event` values.
//! - **Default `venom scan`:** no.
//! - **Support:** implemented.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Central event infrastructure for scanning lifecycle and plugin coordination.

use dashmap::DashMap;
use std::sync::Arc;
pub use venom_core::{Event, EventBuilder, EventSeverity, EventType};

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
            .or_default()
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
            .or_default()
            .push(event.clone());

        // Call subscribers
        if let Some(handlers) = self.subscribers.get(&event.event_type) {
            for (_, handler) in handlers.iter() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler(&event);
                }));
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
        events.sort_by_key(|event| event.timestamp_ms);
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
                format!("handler_{i}"),
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
            let event = Event::new(EventType::WorkerFinished, format!("worker_{i}"));
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
                let event = Event::builder(EventType::FindingFound, format!("thread_{i}"))
                    .correlation_id("scan_concurrent")
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
                    Event::builder(EventType::WorkerFinished, format!("async_worker_{i}")).build();
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
        let bus = Arc::new(EventBus::new());
        bus.subscribe(
            EventType::ScanStarted,
            "panicking_handler",
            Arc::new(|_| {
                panic!("subscriber fixture panic");
            }),
        );

        let normal_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let normal_clone = normal_called.clone();
        bus.subscribe(
            EventType::ScanStarted,
            "normal_handler",
            Arc::new(move |_| {
                normal_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        bus.publish(Event::new(EventType::ScanStarted, "test"));

        assert!(normal_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(bus.total_events(), 1);
    }

    #[test]
    fn test_unsubscribe_memory_cleanup() {
        let bus = EventBus::new();

        // Subscribe many handlers
        for i in 0..100 {
            bus.subscribe(
                EventType::FindingFound,
                format!("handler_{i}"),
                Arc::new(|_| {}),
            );
        }

        assert_eq!(bus.subscriber_count(&EventType::FindingFound), 100);

        // Unsubscribe all
        for i in 0..100 {
            bus.unsubscribe(&EventType::FindingFound, &format!("handler_{i}"));
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
                        format!("handler_{i}"),
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
                format!("listener_{i}"),
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
            for _ in 0..100 {
                let event = Event::builder(EventType::FindingFound, "test")
                    .correlation_id(format!("scan_{scan_id}"))
                    .build();
                bus.publish(event);
            }
        }

        // Query concurrently
        let mut tasks = vec![];
        for scan_id in 0..10 {
            let bus_clone = bus.clone();
            let task = tokio::spawn(async move {
                let events = bus_clone.get_events_by_correlation(&format!("scan_{scan_id}"));
                assert_eq!(events.len(), 100);
            });
            tasks.push(task);
        }

        for task in tasks {
            task.await.unwrap();
        }
    }
}
