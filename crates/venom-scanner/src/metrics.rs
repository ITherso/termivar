//! Performance Metrics & Analytics
//!
//! Tracks scanning performance, timing, and statistics for optimization.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Metrics collector for scan performance
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    /// Total requests sent
    pub total_requests: Arc<AtomicU64>,
    /// Total responses received
    pub total_responses: Arc<AtomicU64>,
    /// Total findings discovered
    pub total_findings: Arc<AtomicU64>,
    /// Total bytes transmitted
    pub total_bytes_sent: Arc<AtomicU64>,
    /// Total bytes received
    pub total_bytes_received: Arc<AtomicU64>,
    /// Total errors encountered
    pub total_errors: Arc<AtomicU64>,
    /// Phase execution times (ms)
    phase_times: HashMap<u8, Vec<u64>>,
}

impl MetricsCollector {
    /// Creates a new metrics collector
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            total_responses: Arc::new(AtomicU64::new(0)),
            total_findings: Arc::new(AtomicU64::new(0)),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            total_errors: Arc::new(AtomicU64::new(0)),
            phase_times: HashMap::new(),
        }
    }

    /// Records a request
    pub fn record_request(&self, bytes: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a response
    pub fn record_response(&self, bytes: u64) {
        self.total_responses.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a finding
    pub fn record_finding(&self) {
        self.total_findings.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an error
    pub fn record_error(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records phase execution time
    pub fn record_phase_time(&mut self, phase: u8, duration_ms: u64) {
        self.phase_times
            .entry(phase)
            .or_insert_with(Vec::new)
            .push(duration_ms);
    }

    /// Calculates average response time (ms)
    pub fn average_response_time(&self) -> f64 {
        let requests = self.total_requests.load(Ordering::Relaxed);
        if requests == 0 {
            return 0.0;
        }
        // Simplified: would need actual timing data
        0.0
    }

    /// Calculates success rate (%)
    pub fn success_rate(&self) -> f64 {
        let responses = self.total_responses.load(Ordering::Relaxed);
        let requests = self.total_requests.load(Ordering::Relaxed);

        if requests == 0 {
            return 0.0;
        }

        (responses as f64 / requests as f64) * 100.0
    }

    /// Calculates finding density
    pub fn finding_density(&self) -> f64 {
        let responses = self.total_responses.load(Ordering::Relaxed);
        let findings = self.total_findings.load(Ordering::Relaxed);

        if responses == 0 {
            return 0.0;
        }

        (findings as f64 / responses as f64) * 100.0
    }

    /// Calculates bytes per finding
    pub fn bytes_per_finding(&self) -> f64 {
        let bytes = self.total_bytes_received.load(Ordering::Relaxed);
        let findings = self.total_findings.load(Ordering::Relaxed);

        if findings == 0 {
            return 0.0;
        }

        bytes as f64 / findings as f64
    }

    /// Gets statistics summary
    pub fn summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_responses: self.total_responses.load(Ordering::Relaxed),
            total_findings: self.total_findings.load(Ordering::Relaxed),
            total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            success_rate: self.success_rate(),
            finding_density: self.finding_density(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub total_responses: u64,
    pub total_findings: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_errors: u64,
    pub success_rate: f64,
    pub finding_density: f64,
}

impl MetricsSummary {
    /// Generates JSON representation
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "requests": self.total_requests,
            "responses": self.total_responses,
            "findings": self.total_findings,
            "bytes_sent": self.total_bytes_sent,
            "bytes_received": self.total_bytes_received,
            "errors": self.total_errors,
            "success_rate": format!("{:.2}%", self.success_rate),
            "finding_density": format!("{:.2}%", self.finding_density),
        })
        .to_string()
    }
}

/// Phase-specific metrics
#[derive(Debug, Clone)]
pub struct PhaseMetrics {
    pub phase_number: u8,
    pub phase_name: String,
    pub requests: u64,
    pub findings: u64,
    pub duration_ms: u64,
    pub avg_response_time_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.total_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_request() {
        let collector = MetricsCollector::new();
        collector.record_request(100);
        assert_eq!(collector.total_requests.load(Ordering::Relaxed), 1);
        assert_eq!(collector.total_bytes_sent.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_record_response() {
        let collector = MetricsCollector::new();
        collector.record_response(200);
        assert_eq!(collector.total_responses.load(Ordering::Relaxed), 1);
        assert_eq!(collector.total_bytes_received.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn test_success_rate() {
        let collector = MetricsCollector::new();
        collector.record_request(100);
        collector.record_request(100);
        collector.record_response(200);

        let rate = collector.success_rate();
        assert_eq!(rate, 50.0);
    }

    #[test]
    fn test_finding_density() {
        let collector = MetricsCollector::new();
        for _ in 0..10 {
            collector.record_response(100);
        }
        for _ in 0..5 {
            collector.record_finding();
        }

        let density = collector.finding_density();
        assert_eq!(density, 50.0);
    }

    #[test]
    fn test_bytes_per_finding() {
        let collector = MetricsCollector::new();
        collector
            .total_bytes_received
            .store(1000, Ordering::Relaxed);
        collector.total_findings.store(10, Ordering::Relaxed);

        let bpf = collector.bytes_per_finding();
        assert_eq!(bpf, 100.0);
    }

    #[test]
    fn test_summary_generation() {
        let collector = MetricsCollector::new();
        collector.record_request(100);
        collector.record_response(200);
        collector.record_finding();

        let summary = collector.summary();
        assert_eq!(summary.total_requests, 1);
        assert_eq!(summary.total_responses, 1);
        assert_eq!(summary.total_findings, 1);
    }

    #[test]
    fn test_metrics_json() {
        let summary = MetricsSummary {
            total_requests: 100,
            total_responses: 95,
            total_findings: 10,
            total_bytes_sent: 1000,
            total_bytes_received: 2000,
            total_errors: 5,
            success_rate: 95.0,
            finding_density: 10.5,
        };

        let json = summary.to_json();
        assert!(json.contains("100"));
        assert!(json.contains("10"));
    }
}
