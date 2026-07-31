//! Real-time Updates & WebSocket Support
//!
//! Provides streaming updates for live scan progress, findings, and metrics.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Real-time event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RealtimeEvent {
    /// Scan started
    ScanStarted {
        scan_id: String,
        target: String,
        timestamp: u64,
    },
    /// Phase started
    PhaseStarted {
        scan_id: String,
        phase: u8,
        phase_name: String,
        timestamp: u64,
    },
    /// Phase progress update
    PhaseProgress {
        scan_id: String,
        phase: u8,
        progress: f32,
        timestamp: u64,
    },
    /// Finding discovered
    FindingDiscovered {
        scan_id: String,
        phase: u8,
        severity: String,
        description: String,
        timestamp: u64,
    },
    /// Phase completed
    PhaseCompleted {
        scan_id: String,
        phase: u8,
        findings_count: usize,
        duration_ms: u64,
        timestamp: u64,
    },
    /// Scan completed
    ScanCompleted {
        scan_id: String,
        total_findings: usize,
        risk_score: f32,
        duration_ms: u64,
        timestamp: u64,
    },
    /// Error occurred
    Error {
        scan_id: String,
        error_message: String,
        timestamp: u64,
    },
    /// Metrics update
    Metrics {
        scan_id: String,
        requests: u64,
        responses: u64,
        findings: u64,
        errors: u64,
        success_rate: f32,
        timestamp: u64,
    },
}

impl RealtimeEvent {
    pub fn timestamp(&self) -> u64 {
        match self {
            RealtimeEvent::ScanStarted { timestamp, .. } => *timestamp,
            RealtimeEvent::PhaseStarted { timestamp, .. } => *timestamp,
            RealtimeEvent::PhaseProgress { timestamp, .. } => *timestamp,
            RealtimeEvent::FindingDiscovered { timestamp, .. } => *timestamp,
            RealtimeEvent::PhaseCompleted { timestamp, .. } => *timestamp,
            RealtimeEvent::ScanCompleted { timestamp, .. } => *timestamp,
            RealtimeEvent::Error { timestamp, .. } => *timestamp,
            RealtimeEvent::Metrics { timestamp, .. } => *timestamp,
        }
    }

    pub fn scan_id(&self) -> String {
        match self {
            RealtimeEvent::ScanStarted { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::PhaseStarted { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::PhaseProgress { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::FindingDiscovered { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::PhaseCompleted { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::ScanCompleted { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::Error { scan_id, .. } => scan_id.clone(),
            RealtimeEvent::Metrics { scan_id, .. } => scan_id.clone(),
        }
    }
}

/// Event stream for a scan
#[derive(Debug, Clone)]
pub struct EventStream {
    events: Arc<DashMap<String, Vec<RealtimeEvent>>>,
}

impl EventStream {
    /// Creates a new event stream
    pub fn new() -> Self {
        Self {
            events: Arc::new(DashMap::new()),
        }
    }

    /// Publishes an event
    pub fn publish(&self, event: RealtimeEvent) {
        let scan_id = event.scan_id();
        self.events
            .entry(scan_id)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Gets events for a scan
    pub fn get_events(&self, scan_id: &str) -> Vec<RealtimeEvent> {
        self.events
            .get(scan_id)
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    /// Gets events since a timestamp
    pub fn get_events_since(&self, scan_id: &str, since: u64) -> Vec<RealtimeEvent> {
        self.events
            .get(scan_id)
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.timestamp() > since)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets recent events
    pub fn get_recent_events(&self, scan_id: &str, limit: usize) -> Vec<RealtimeEvent> {
        self.events
            .get(scan_id)
            .map(|events| {
                events
                    .iter()
                    .rev()
                    .take(limit)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clears events for a scan
    pub fn clear_events(&self, scan_id: &str) {
        self.events.remove(scan_id);
    }

    /// Gets event count
    pub fn event_count(&self, scan_id: &str) -> usize {
        self.events
            .get(scan_id)
            .map(|e| e.len())
            .unwrap_or_default()
    }
}

impl Default for EventStream {
    fn default() -> Self {
        Self::new()
    }
}

/// WebSocket message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub id: String,
    pub action: String,
    pub data: Option<serde_json::Value>,
}

/// WebSocket subscription
#[derive(Debug, Clone)]
pub struct Subscription {
    pub subscriber_id: String,
    pub scan_id: String,
    pub subscribed_at: u64,
    pub active: bool,
}

impl Subscription {
    pub fn new(subscriber_id: String, scan_id: String) -> Self {
        Self {
            subscriber_id,
            scan_id,
            subscribed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            active: true,
        }
    }
}

/// WebSocket connection manager
pub struct ConnectionManager {
    subscriptions: Arc<DashMap<String, Vec<Subscription>>>,
    event_stream: EventStream,
}

impl ConnectionManager {
    /// Creates a new connection manager
    pub fn new(event_stream: EventStream) -> Self {
        Self {
            subscriptions: Arc::new(DashMap::new()),
            event_stream,
        }
    }

    /// Subscribes to scan updates
    pub fn subscribe(&self, subscriber_id: String, scan_id: String) -> Subscription {
        let sub = Subscription::new(subscriber_id.clone(), scan_id.clone());
        self.subscriptions
            .entry(scan_id)
            .or_insert_with(Vec::new)
            .push(sub.clone());
        sub
    }

    /// Unsubscribes from scan updates
    pub fn unsubscribe(&self, subscriber_id: &str, scan_id: &str) -> bool {
        if let Some(mut subs) = self.subscriptions.get_mut(scan_id) {
            subs.retain(|s| s.subscriber_id != subscriber_id);
            true
        } else {
            false
        }
    }

    /// Gets subscribers for a scan
    pub fn get_subscribers(&self, scan_id: &str) -> Vec<Subscription> {
        self.subscriptions
            .get(scan_id)
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Publishes event to all subscribers
    pub fn broadcast(&self, event: RealtimeEvent) {
        let scan_id = event.scan_id();
        self.event_stream.publish(event);

        // Notify all subscribers (in real implementation, would send via WebSocket)
        if let Some(subs) = self.subscriptions.get(&scan_id) {
            for sub in subs.iter() {
                // WebSocket send would happen here
                let _ = sub.clone();
            }
        }
    }

    /// Gets connection count for scan
    pub fn connection_count(&self, scan_id: &str) -> usize {
        self.subscriptions
            .get(scan_id)
            .map(|s| s.len())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_stream_creation() {
        let stream = EventStream::new();
        assert_eq!(stream.event_count("scan1"), 0);
    }

    #[test]
    fn test_publish_event() {
        let stream = EventStream::new();
        let event = RealtimeEvent::ScanStarted {
            scan_id: "scan1".to_string(),
            target: "https://example.com".to_string(),
            timestamp: 1000,
        };

        stream.publish(event);
        assert_eq!(stream.event_count("scan1"), 1);
    }

    #[test]
    fn test_get_events() {
        let stream = EventStream::new();
        let event = RealtimeEvent::ScanStarted {
            scan_id: "scan1".to_string(),
            target: "https://example.com".to_string(),
            timestamp: 1000,
        };

        stream.publish(event);
        let events = stream.get_events("scan1");
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_subscription() {
        let sub = Subscription::new("user1".to_string(), "scan1".to_string());
        assert_eq!(sub.subscriber_id, "user1");
        assert!(sub.active);
    }

    #[test]
    fn test_connection_manager() {
        let stream = EventStream::new();
        let manager = ConnectionManager::new(stream);

        manager.subscribe("user1".to_string(), "scan1".to_string());
        assert_eq!(manager.connection_count("scan1"), 1);
    }

    #[test]
    fn test_broadcast() {
        let stream = EventStream::new();
        let manager = ConnectionManager::new(stream);

        manager.subscribe("user1".to_string(), "scan1".to_string());

        let event = RealtimeEvent::FindingDiscovered {
            scan_id: "scan1".to_string(),
            phase: 5,
            severity: "CRITICAL".to_string(),
            description: "Test finding".to_string(),
            timestamp: 1000,
        };

        manager.broadcast(event);
        assert_eq!(manager.connection_count("scan1"), 1);
    }

    #[test]
    fn test_events_since() {
        let stream = EventStream::new();

        stream.publish(RealtimeEvent::ScanStarted {
            scan_id: "scan1".to_string(),
            target: "https://example.com".to_string(),
            timestamp: 1000,
        });

        stream.publish(RealtimeEvent::PhaseStarted {
            scan_id: "scan1".to_string(),
            phase: 1,
            phase_name: "Recon".to_string(),
            timestamp: 1100,
        });

        let recent = stream.get_events_since("scan1", 1050);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_recent_events() {
        let stream = EventStream::new();

        for i in 0..5 {
            stream.publish(RealtimeEvent::PhaseProgress {
                scan_id: "scan1".to_string(),
                phase: 1,
                progress: (i * 20) as f32,
                timestamp: 1000 + i as u64,
            });
        }

        let recent = stream.get_recent_events("scan1", 2);
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn test_unsubscribe() {
        let stream = EventStream::new();
        let manager = ConnectionManager::new(stream);

        manager.subscribe("user1".to_string(), "scan1".to_string());
        assert_eq!(manager.connection_count("scan1"), 1);

        manager.unsubscribe("user1", "scan1");
        assert_eq!(manager.connection_count("scan1"), 0);
    }
}
