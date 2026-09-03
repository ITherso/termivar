//! Recorded event and subscription data models.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `termivar scan`:** no.
//! - **Support:** experimental in-memory models.
//!
//! `EventStream` is an in-process event journal. This module has no WebSocket
//! listener, connection manager, subscriber delivery, or network broadcast.

use dashmap::DashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;

fn validate_bounded_f32(value: f32, minimum: f32, maximum: f32) -> bool {
    value.is_finite() && (minimum..=maximum).contains(&value)
}

fn serialize_bounded_f32<S>(
    value: &f32,
    minimum: f32,
    maximum: f32,
    field: &'static str,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if !validate_bounded_f32(*value, minimum, maximum) {
        return Err(serde::ser::Error::custom(format_args!(
            "{field} must be finite and in {minimum}..={maximum}"
        )));
    }
    serializer.serialize_f32(*value)
}

fn deserialize_bounded_f32<'de, D>(
    deserializer: D,
    minimum: f32,
    maximum: f32,
    field: &'static str,
) -> Result<f32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = f32::deserialize(deserializer)?;
    if !validate_bounded_f32(value, minimum, maximum) {
        return Err(serde::de::Error::custom(format_args!(
            "{field} must be finite and in {minimum}..={maximum}"
        )));
    }
    Ok(value)
}

mod percentage {
    use super::*;

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bounded_f32(value, 0.0, 100.0, "percentage", serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_f32(deserializer, 0.0, 100.0, "percentage")
    }
}

mod normalized_score {
    use super::*;

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bounded_f32(value, 0.0, 1.0, "normalized score", serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_f32(deserializer, 0.0, 1.0, "normalized score")
    }
}

mod optional_percentage {
    use super::*;

    pub fn serialize<S>(value: &Option<f32>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(value) = value {
            if !validate_bounded_f32(*value, 0.0, 100.0) {
                return Err(serde::ser::Error::custom(
                    "percentage must be finite and in 0..=100",
                ));
            }
        }
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<f32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<f32>::deserialize(deserializer)?;
        if let Some(value) = value {
            if !validate_bounded_f32(value, 0.0, 100.0) {
                return Err(serde::de::Error::custom(
                    "percentage must be finite and in 0..=100",
                ));
            }
        }
        Ok(value)
    }
}

/// Caller-supplied scan event record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RealtimeEvent {
    ScanStarted {
        scan_id: String,
        target: String,
        timestamp: u64,
    },
    PhaseStarted {
        scan_id: String,
        phase: u8,
        phase_name: String,
        timestamp: u64,
    },
    PhaseProgress {
        scan_id: String,
        phase: u8,
        #[serde(with = "percentage")]
        progress: f32,
        timestamp: u64,
    },
    FindingDiscovered {
        scan_id: String,
        phase: u8,
        severity: String,
        description: String,
        timestamp: u64,
    },
    PhaseCompleted {
        scan_id: String,
        phase: u8,
        findings_count: u64,
        duration_ms: u64,
        timestamp: u64,
    },
    ScanCompleted {
        scan_id: String,
        total_findings: u64,
        #[serde(with = "normalized_score")]
        risk_score: f32,
        duration_ms: u64,
        timestamp: u64,
    },
    Error {
        scan_id: String,
        error_message: String,
        timestamp: u64,
    },
    Metrics {
        scan_id: String,
        requests: u64,
        responses: u64,
        findings: u64,
        errors: u64,
        #[serde(with = "optional_percentage")]
        response_request_ratio_percent: Option<f32>,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealtimeEventValidationError {
    EmptyScanId,
    InvalidPhaseProgress,
    InvalidRiskScore,
    InvalidResponseRequestRatioPercent,
}

impl RealtimeEvent {
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::ScanStarted { timestamp, .. }
            | Self::PhaseStarted { timestamp, .. }
            | Self::PhaseProgress { timestamp, .. }
            | Self::FindingDiscovered { timestamp, .. }
            | Self::PhaseCompleted { timestamp, .. }
            | Self::ScanCompleted { timestamp, .. }
            | Self::Error { timestamp, .. }
            | Self::Metrics { timestamp, .. } => *timestamp,
        }
    }

    pub fn scan_id(&self) -> &str {
        match self {
            Self::ScanStarted { scan_id, .. }
            | Self::PhaseStarted { scan_id, .. }
            | Self::PhaseProgress { scan_id, .. }
            | Self::FindingDiscovered { scan_id, .. }
            | Self::PhaseCompleted { scan_id, .. }
            | Self::ScanCompleted { scan_id, .. }
            | Self::Error { scan_id, .. }
            | Self::Metrics { scan_id, .. } => scan_id,
        }
    }

    pub fn validate(&self) -> Result<(), RealtimeEventValidationError> {
        if self.scan_id().is_empty() {
            return Err(RealtimeEventValidationError::EmptyScanId);
        }
        match self {
            Self::PhaseProgress { progress, .. }
                if !validate_bounded_f32(*progress, 0.0, 100.0) =>
            {
                Err(RealtimeEventValidationError::InvalidPhaseProgress)
            },
            Self::ScanCompleted { risk_score, .. }
                if !validate_bounded_f32(*risk_score, 0.0, 1.0) =>
            {
                Err(RealtimeEventValidationError::InvalidRiskScore)
            },
            Self::Metrics {
                response_request_ratio_percent: Some(ratio),
                ..
            } if !validate_bounded_f32(*ratio, 0.0, 100.0) => {
                Err(RealtimeEventValidationError::InvalidResponseRequestRatioPercent)
            },
            _ => Ok(()),
        }
    }
}

/// Cloneable, in-memory journal keyed by scan ID.
#[derive(Debug, Clone, Default)]
pub struct EventStream {
    events: Arc<DashMap<String, Vec<RealtimeEvent>>>,
}

impl EventStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a valid event in memory. It does not deliver the event to a client.
    ///
    /// Invalid float ranges and empty scan IDs are rejected without mutating the journal.
    pub fn record(&self, event: RealtimeEvent) -> Result<(), RealtimeEventValidationError> {
        event.validate()?;
        self.events
            .entry(event.scan_id().to_string())
            .or_default()
            .push(event);
        Ok(())
    }

    pub fn events(&self, scan_id: &str) -> Vec<RealtimeEvent> {
        self.events
            .get(scan_id)
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn events_since(&self, scan_id: &str, since_exclusive: u64) -> Vec<RealtimeEvent> {
        self.events
            .get(scan_id)
            .map(|events| {
                events
                    .iter()
                    .filter(|event| event.timestamp() > since_exclusive)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn recent_events(&self, scan_id: &str, limit: usize) -> Vec<RealtimeEvent> {
        self.events
            .get(scan_id)
            .map(|events| {
                let start = events.len().saturating_sub(limit);
                events[start..].to_vec()
            })
            .unwrap_or_default()
    }

    /// Removes an in-memory journal and returns the number of removed events.
    pub fn clear_events(&self, scan_id: &str) -> usize {
        self.events
            .remove(scan_id)
            .map(|(_, events)| events.len())
            .unwrap_or_default()
    }

    pub fn event_count(&self, scan_id: &str) -> usize {
        self.events
            .get(scan_id)
            .map(|events| events.len())
            .unwrap_or_default()
    }
}

/// Caller-owned record of subscription state; no network connection is implied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub subscriber_id: String,
    pub scan_id: String,
    pub subscribed_at: u64,
    pub ended_at: Option<u64>,
}

impl Subscription {
    pub fn new(subscriber_id: String, scan_id: String, subscribed_at: u64) -> Self {
        Self {
            subscriber_id,
            scan_id,
            subscribed_at,
            ended_at: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.ended_at.is_none()
    }

    /// Records the end of this subscription.
    ///
    /// Returns `false` for a repeated end or a timestamp before subscription.
    pub fn end(&mut self, ended_at: u64) -> bool {
        if self.ended_at.is_some() || ended_at < self.subscribed_at {
            return false;
        }
        self.ended_at = Some(ended_at);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(timestamp: u64) -> RealtimeEvent {
        RealtimeEvent::PhaseProgress {
            scan_id: "scan-1".to_string(),
            phase: 1,
            progress: 50.0,
            timestamp,
        }
    }

    #[test]
    fn scan_started_exposes_identity_and_validates() {
        let event = RealtimeEvent::ScanStarted {
            scan_id: "scan-1".into(),
            target: "https://example.test".into(),
            timestamp: 42,
        };

        assert_eq!(event.scan_id(), "scan-1");
        assert_eq!(event.timestamp(), 42);
        assert_eq!(event.validate(), Ok(()));
    }

    #[test]
    fn journal_records_without_claiming_delivery() {
        let stream = EventStream::new();
        stream.record(event(10)).unwrap();
        stream.record(event(20)).unwrap();

        assert_eq!(stream.event_count("scan-1"), 2);
        assert_eq!(stream.events_since("scan-1", 10), vec![event(20)]);
        assert!(stream.events("unknown").is_empty());
    }

    #[test]
    fn recent_limit_zero_is_empty() {
        let stream = EventStream::new();
        stream.record(event(10)).unwrap();
        assert!(stream.recent_events("scan-1", 0).is_empty());
    }

    #[test]
    fn clear_reports_what_was_actually_removed() {
        let stream = EventStream::new();
        stream.record(event(10)).unwrap();

        assert_eq!(stream.clear_events("scan-1"), 1);
        assert_eq!(stream.clear_events("scan-1"), 0);
    }

    #[test]
    fn subscription_end_is_truthful() {
        let mut subscription = Subscription::new("observer".into(), "scan-1".into(), 100);
        assert!(subscription.is_active());
        assert!(!subscription.end(99));
        assert!(subscription.is_active());
        assert!(subscription.end(110));
        assert!(!subscription.is_active());
        assert!(!subscription.end(120));
        assert_eq!(subscription.ended_at, Some(110));
    }

    #[test]
    fn record_rejects_invalid_events_without_mutating_the_journal() {
        let stream = EventStream::new();
        let invalid = RealtimeEvent::PhaseProgress {
            scan_id: "scan-1".into(),
            phase: 1,
            progress: f32::NAN,
            timestamp: 10,
        };

        assert_eq!(
            stream.record(invalid),
            Err(RealtimeEventValidationError::InvalidPhaseProgress)
        );
        assert!(stream.events("scan-1").is_empty());
    }

    #[test]
    fn valid_events_round_trip_and_wire_counts_are_u64() {
        let event = RealtimeEvent::ScanCompleted {
            scan_id: "scan-1".into(),
            total_findings: u64::MAX,
            risk_score: 0.75,
            duration_ms: 25,
            timestamp: 100,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(&u64::MAX.to_string()));
        assert_eq!(serde_json::from_str::<RealtimeEvent>(&json).unwrap(), event);
    }

    #[test]
    fn serialization_and_deserialization_reject_invalid_floats() {
        let invalid_progress = RealtimeEvent::PhaseProgress {
            scan_id: "scan-1".into(),
            phase: 1,
            progress: -0.1,
            timestamp: 1,
        };
        assert!(serde_json::to_string(&invalid_progress).is_err());

        let invalid = RealtimeEvent::ScanCompleted {
            scan_id: "scan-1".into(),
            total_findings: 0,
            risk_score: f32::INFINITY,
            duration_ms: 25,
            timestamp: 100,
        };
        assert!(serde_json::to_string(&invalid).is_err());

        let invalid_score = r#"{"type":"scancompleted","scan_id":"scan-1","total_findings":0,"risk_score":1.1,"duration_ms":25,"timestamp":100}"#;
        assert!(serde_json::from_str::<RealtimeEvent>(invalid_score).is_err());

        let out_of_range = r#"{"type":"phaseprogress","scan_id":"scan-1","phase":1,"progress":100.1,"timestamp":1}"#;
        assert!(serde_json::from_str::<RealtimeEvent>(out_of_range).is_err());

        let invalid_ratio = RealtimeEvent::Metrics {
            scan_id: "scan-1".into(),
            requests: 1,
            responses: 1,
            findings: 0,
            errors: 0,
            response_request_ratio_percent: Some(-0.1),
            timestamp: 1,
        };
        assert!(serde_json::to_string(&invalid_ratio).is_err());

        let out_of_range_ratio = r#"{"type":"metrics","scan_id":"scan-1","requests":1,"responses":1,"findings":0,"errors":0,"response_request_ratio_percent":101.0,"timestamp":1}"#;
        assert!(serde_json::from_str::<RealtimeEvent>(out_of_range_ratio).is_err());
    }
}
