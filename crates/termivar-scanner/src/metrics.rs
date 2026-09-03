//! In-memory scan measurement records.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `termivar scan`:** no.
//! - **Support:** experimental data models.
//!
//! Ratios in this module describe recorded counters. A response/request ratio
//! is not a request success rate, and no outcome is inferred from it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Thread-safe counters and caller-recorded phase duration samples.
#[derive(Debug)]
pub struct MetricsCollector {
    total_requests: AtomicU64,
    total_responses: AtomicU64,
    total_findings: AtomicU64,
    total_bytes_sent: AtomicU64,
    total_bytes_received: AtomicU64,
    total_errors: AtomicU64,
    phase_duration_samples_ms: HashMap<u8, Vec<u64>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            total_responses: AtomicU64::new(0),
            total_findings: AtomicU64::new(0),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_received: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            phase_duration_samples_ms: HashMap::new(),
        }
    }

    pub fn record_request(&self, bytes: u64) {
        saturating_add(&self.total_requests, 1);
        saturating_add(&self.total_bytes_sent, bytes);
    }

    pub fn record_response(&self, bytes: u64) {
        saturating_add(&self.total_responses, 1);
        saturating_add(&self.total_bytes_received, bytes);
    }

    pub fn record_finding(&self) {
        saturating_add(&self.total_findings, 1);
    }

    pub fn record_error(&self) {
        saturating_add(&self.total_errors, 1);
    }

    pub fn record_phase_duration(&mut self, phase: u8, duration_ms: u64) {
        self.phase_duration_samples_ms
            .entry(phase)
            .or_default()
            .push(duration_ms);
    }

    pub fn phase_duration_samples(&self, phase: u8) -> Option<&[u64]> {
        self.phase_duration_samples_ms
            .get(&phase)
            .map(Vec::as_slice)
    }

    /// Mean calculated from the recorded samples, or `None` when there are none.
    pub fn phase_mean_duration_ms(&self, phase: u8) -> Option<f64> {
        mean(self.phase_duration_samples(phase)?)
    }

    /// Recorded responses divided by recorded requests, expressed as percent.
    pub fn response_request_ratio_percent(&self) -> Option<f64> {
        ratio_percent(
            self.total_responses.load(Ordering::Relaxed),
            self.total_requests.load(Ordering::Relaxed),
        )
    }

    pub fn findings_per_100_responses(&self) -> Option<f64> {
        ratio_percent(
            self.total_findings.load(Ordering::Relaxed),
            self.total_responses.load(Ordering::Relaxed),
        )
    }

    pub fn bytes_per_finding(&self) -> Option<f64> {
        ratio(
            self.total_bytes_received.load(Ordering::Relaxed),
            self.total_findings.load(Ordering::Relaxed),
        )
    }

    pub fn summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_responses: self.total_responses.load(Ordering::Relaxed),
            total_findings: self.total_findings.load(Ordering::Relaxed),
            total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            response_request_ratio_percent: self.response_request_ratio_percent(),
            findings_per_100_responses: self.findings_per_100_responses(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of recorded counters and directly derived ratios.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricsSummary {
    #[serde(rename = "requests")]
    pub total_requests: u64,
    #[serde(rename = "responses")]
    pub total_responses: u64,
    #[serde(rename = "findings")]
    pub total_findings: u64,
    #[serde(rename = "bytes_sent")]
    pub total_bytes_sent: u64,
    #[serde(rename = "bytes_received")]
    pub total_bytes_received: u64,
    #[serde(rename = "errors")]
    pub total_errors: u64,
    #[serde(with = "optional_finite_f64")]
    pub response_request_ratio_percent: Option<f64>,
    #[serde(with = "optional_finite_f64")]
    pub findings_per_100_responses: Option<f64>,
}

impl MetricsSummary {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

mod optional_finite_f64 {
    use serde::Serializer;

    pub fn serialize<S>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) if value.is_finite() => serializer.serialize_some(value),
            Some(_) => Err(serde::ser::Error::custom("metric ratio must be finite")),
            None => serializer.serialize_none(),
        }
    }
}

/// Phase-specific raw measurements supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseMetrics {
    pub phase_number: u8,
    pub phase_name: String,
    pub requests: u64,
    pub responses: u64,
    pub findings: u64,
    pub duration_ms: u64,
    pub response_time_samples_ms: Vec<u64>,
}

impl PhaseMetrics {
    pub fn mean_response_time_ms(&self) -> Option<f64> {
        mean(&self.response_time_samples_ms)
    }

    pub fn response_request_ratio_percent(&self) -> Option<f64> {
        ratio_percent(self.responses, self.requests)
    }
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator != 0).then_some(numerator as f64 / denominator as f64)
}

fn ratio_percent(numerator: u64, denominator: u64) -> Option<f64> {
    ratio(numerator, denominator).map(|value| value * 100.0)
}

fn mean(samples: &[u64]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let sum: u128 = samples.iter().map(|&sample| u128::from(sample)).sum();
    Some(sum as f64 / samples.len() as f64)
}

fn saturating_add(counter: &AtomicU64, increment: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(increment))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_denominators_produce_no_ratio() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.response_request_ratio_percent(), None);
        assert_eq!(collector.findings_per_100_responses(), None);
        assert_eq!(collector.bytes_per_finding(), None);
    }

    #[test]
    fn response_ratio_does_not_claim_success() {
        let collector = MetricsCollector::new();
        collector.record_request(10);
        collector.record_request(20);
        collector.record_response(30);
        collector.record_error();

        assert_eq!(collector.response_request_ratio_percent(), Some(50.0));
        let json = collector.summary().to_json().expect("finite summary");
        assert!(json.contains("response_request_ratio_percent"));
        assert!(!json.contains("success_rate"));
    }

    #[test]
    fn means_are_derived_from_raw_samples() {
        let mut collector = MetricsCollector::new();
        assert_eq!(collector.phase_mean_duration_ms(4), None);
        collector.record_phase_duration(4, 10);
        collector.record_phase_duration(4, 30);

        assert_eq!(collector.phase_duration_samples(4), Some(&[10, 30][..]));
        assert_eq!(collector.phase_mean_duration_ms(4), Some(20.0));
    }

    #[test]
    fn phase_mean_uses_only_supplied_samples() {
        let phase = PhaseMetrics {
            phase_number: 1,
            phase_name: "fixture".to_string(),
            requests: 4,
            responses: 3,
            findings: 1,
            duration_ms: 100,
            response_time_samples_ms: vec![10, 20, 30],
        };

        assert_eq!(phase.mean_response_time_ms(), Some(20.0));
        assert_eq!(phase.response_request_ratio_percent(), Some(75.0));
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let collector = MetricsCollector::new();
        collector.total_requests.store(u64::MAX, Ordering::Relaxed);
        collector
            .total_bytes_sent
            .store(u64::MAX - 1, Ordering::Relaxed);

        collector.record_request(10);

        assert_eq!(collector.total_requests.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(collector.total_bytes_sent.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn summary_json_rejects_nonfinite_public_values() {
        let summary = MetricsSummary {
            total_requests: 0,
            total_responses: 0,
            total_findings: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_errors: 0,
            response_request_ratio_percent: Some(f64::NAN),
            findings_per_100_responses: None,
        };
        assert!(summary.to_json().is_err());
    }
}
