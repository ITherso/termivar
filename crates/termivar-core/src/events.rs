//! Historical scanner lifecycle event records.
//!
//! This module is available only with the non-default `legacy-contracts`
//! feature. The default reasoning runtime does not publish these events.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Event types in the scanning lifecycle.
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
    /// Returns the serialized name for the event type.
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

/// Event severity levels.
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

/// Versioned event data used by the opt-in historical scanner event bus.
///
/// # Examples
///
/// ```
/// use termivar_core::{Event, EventSeverity, EventType};
///
/// let event = Event::builder(EventType::PhaseStarted, "scanner")
///     .correlation_id("scan-42")
///     .severity(EventSeverity::Info)
///     .data("phase", "recon")
///     .build();
///
/// assert_eq!(event.event_type, EventType::PhaseStarted);
/// assert_eq!(event.correlation_id, "scan-42");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: EventType,
    pub version: u16,
    pub timestamp_ms: u64,
    pub correlation_id: String,
    pub source: String,
    pub data: HashMap<String, String>,
    pub severity: EventSeverity,
    pub event_id: String,
}

impl Event {
    /// Creates an event with a generated timestamp, correlation ID, and event ID.
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        EventBuilder::new(event_type, source).build()
    }

    /// Creates a fluent event builder.
    pub fn builder(event_type: EventType, source: impl Into<String>) -> EventBuilder {
        EventBuilder::new(event_type, source)
    }

    /// Replaces the correlation ID.
    pub fn with_correlation_id(mut self, scan_id: impl Into<String>) -> Self {
        self.correlation_id = scan_id.into();
        self
    }

    /// Adds a custom data field.
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Replaces the event severity.
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Replaces the event schema version.
    pub fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Returns the timestamp in `seconds.milliseconds` form.
    pub fn timestamp_str(&self) -> String {
        let secs = self.timestamp_ms / 1000;
        let millis = self.timestamp_ms % 1000;
        format!("{secs}.{millis:03}")
    }
}

/// Fluent builder for [`Event`].
pub struct EventBuilder {
    event_type: EventType,
    version: u16,
    timestamp_ms: u64,
    correlation_id: String,
    source: String,
    data: HashMap<String, String>,
    severity: EventSeverity,
    event_id: String,
}

impl EventBuilder {
    /// Creates a builder with generated identifiers and an info severity.
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            event_type,
            version: 1,
            timestamp_ms: now_ms(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
            data: HashMap::new(),
            severity: EventSeverity::Info,
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn correlation_id(mut self, scan_id: impl Into<String>) -> Self {
        self.correlation_id = scan_id.into();
        self
    }

    pub fn version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    pub fn data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    pub fn severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn timestamp_ms(mut self, timestamp_ms: u64) -> Self {
        self.timestamp_ms = timestamp_ms;
        self
    }

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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{Event, EventType};

    #[test]
    fn timestamp_string_preserves_three_millisecond_digits() {
        let event = Event::builder(EventType::ScanStarted, "test")
            .timestamp_ms(1_007)
            .build();

        assert_eq!(event.timestamp_str(), "1.007");
    }
}
