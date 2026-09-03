//! In-memory scan measurement and comparison models.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `monitoring`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `termivar scan`:** no.
//! - **Support:** experimental data models.
//!
//! Calculations are derived from caller-supplied measurements. This module does
//! not observe resources, select a winner when measurements tie, diagnose a
//! cause, or prescribe optimization actions.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Caller-supplied measurements for one phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseProfile {
    pub phase_number: u8,
    pub phase_name: String,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_ms: u64,
    pub requests_sent: u64,
    pub responses_received: u64,
    pub findings_discovered: u64,
    pub error_count: u64,
    pub response_time_samples_ms: Vec<u64>,
}

impl PhaseProfile {
    pub fn response_request_ratio_percent(&self) -> Option<f64> {
        ratio_percent(self.responses_received, self.requests_sent)
    }

    pub fn findings_per_100_responses(&self) -> Option<f64> {
        ratio_percent(self.findings_discovered, self.responses_received)
    }

    pub fn mean_response_time_ms(&self) -> Option<f64> {
        mean(&self.response_time_samples_ms)
    }
}

/// Caller-supplied resource measurements. No sampler is implemented here.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceMetrics {
    #[serde(with = "nonnegative_f32")]
    pub memory_used_mb: f32,
    #[serde(with = "nonnegative_f32")]
    pub memory_peak_mb: f32,
    #[serde(with = "percent_f32")]
    pub cpu_usage_percent: f32,
    #[serde(with = "percent_f32")]
    pub cpu_peak_percent: f32,
    #[serde(with = "nonnegative_f32")]
    pub disk_read_mb: f32,
    #[serde(with = "nonnegative_f32")]
    pub disk_write_mb: f32,
    #[serde(with = "nonnegative_f32")]
    pub network_in_mb: f32,
    #[serde(with = "nonnegative_f32")]
    pub network_out_mb: f32,
}

impl ResourceMetrics {
    /// Returns whether every measurement is finite and within its documented range.
    pub fn is_valid(&self) -> bool {
        [
            self.memory_used_mb,
            self.memory_peak_mb,
            self.disk_read_mb,
            self.disk_write_mb,
            self.network_in_mb,
            self.network_out_mb,
        ]
        .into_iter()
        .all(|value| value.is_finite() && value >= 0.0)
            && [self.cpu_usage_percent, self.cpu_peak_percent]
                .into_iter()
                .all(|value| value.is_finite() && (0.0..=100.0).contains(&value))
    }
}

mod nonnegative_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.is_finite() && *value >= 0.0 {
            serializer.serialize_f32(*value)
        } else {
            Err(serde::ser::Error::custom(
                "resource measurement must be finite and non-negative",
            ))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if value.is_finite() && value >= 0.0 {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "resource measurement must be finite and non-negative",
            ))
        }
    }
}

mod percent_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.is_finite() && (0.0..=100.0).contains(value) {
            serializer.serialize_f32(*value)
        } else {
            Err(serde::ser::Error::custom(
                "percentage must be finite and between 0 and 100",
            ))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if value.is_finite() && (0.0..=100.0).contains(&value) {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "percentage must be finite and between 0 and 100",
            ))
        }
    }
}

/// In-memory profile composed of caller-supplied phase measurements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProfile {
    pub scan_id: String,
    pub total_duration_ms: u64,
    pub phases: Vec<PhaseProfile>,
    pub resources: ResourceMetrics,
}

impl ScanProfile {
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            total_duration_ms: 0,
            phases: Vec::new(),
            resources: ResourceMetrics::default(),
        }
    }

    pub fn add_phase(&mut self, phase: PhaseProfile) {
        self.phases.push(phase);
    }

    /// Returns whether every retained resource measurement is wire-safe.
    pub fn is_valid(&self) -> bool {
        self.resources.is_valid()
    }

    pub fn total_requests(&self) -> u128 {
        self.phases
            .iter()
            .map(|phase| u128::from(phase.requests_sent))
            .sum()
    }

    pub fn total_responses(&self) -> u128 {
        self.phases
            .iter()
            .map(|phase| u128::from(phase.responses_received))
            .sum()
    }

    pub fn total_findings(&self) -> u128 {
        self.phases
            .iter()
            .map(|phase| u128::from(phase.findings_discovered))
            .sum()
    }

    pub fn total_errors(&self) -> u128 {
        self.phases
            .iter()
            .map(|phase| u128::from(phase.error_count))
            .sum()
    }

    pub fn response_request_ratio_percent(&self) -> Option<f64> {
        ratio_percent_u128(self.total_responses(), self.total_requests())
    }

    /// Returns every phase tied for the greatest recorded duration.
    pub fn slowest_phases(&self) -> Vec<&PhaseProfile> {
        let Some(maximum) = self.phases.iter().map(|phase| phase.duration_ms).max() else {
            return Vec::new();
        };
        self.phases
            .iter()
            .filter(|phase| phase.duration_ms == maximum)
            .collect()
    }

    /// Returns every phase tied for the greatest recorded finding count.
    pub fn most_productive_phases(&self) -> Vec<&PhaseProfile> {
        let Some(maximum) = self
            .phases
            .iter()
            .map(|phase| phase.findings_discovered)
            .max()
        else {
            return Vec::new();
        };
        self.phases
            .iter()
            .filter(|phase| phase.findings_discovered == maximum)
            .collect()
    }
}

/// In-memory profile catalog with pure comparison helpers.
#[derive(Debug, Clone, Default)]
pub struct PerformanceAnalyzer {
    profiles: BTreeMap<String, ScanProfile>,
}

impl PerformanceAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a validated profile, returning the rejected record on failure.
    pub fn record_profile(
        &mut self,
        profile: ScanProfile,
    ) -> Result<Option<ScanProfile>, ScanProfile> {
        if !profile.is_valid() {
            return Err(profile);
        }
        Ok(self.profiles.insert(profile.scan_id.clone(), profile))
    }

    pub fn get_profile(&self, scan_id: &str) -> Option<&ScanProfile> {
        self.profiles.get(scan_id)
    }

    pub fn get_profiles(&self) -> Vec<&ScanProfile> {
        self.profiles.values().collect()
    }

    pub fn compare(&self, first_id: &str, second_id: &str) -> Option<ScanComparison> {
        let first = self.profiles.get(first_id)?;
        let second = self.profiles.get(second_id)?;
        Some(ScanComparison {
            first_scan_id: first_id.to_string(),
            second_scan_id: second_id.to_string(),
            duration: DurationComparison::between(
                first.total_duration_ms,
                second.total_duration_ms,
            ),
            findings: CountComparison::between(first.total_findings(), second.total_findings()),
            response_request_ratio_difference_percentage_points: match (
                first.response_request_ratio_percent(),
                second.response_request_ratio_percent(),
            ) {
                (Some(first_ratio), Some(second_ratio)) => Some(second_ratio - first_ratio),
                _ => None,
            },
        })
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

/// Explicit duration comparison, including ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurationComparison {
    FirstFasterBy(u64),
    Equal,
    SecondFasterBy(u64),
}

impl DurationComparison {
    fn between(first_ms: u64, second_ms: u64) -> Self {
        match first_ms.cmp(&second_ms) {
            std::cmp::Ordering::Less => Self::FirstFasterBy(second_ms - first_ms),
            std::cmp::Ordering::Equal => Self::Equal,
            std::cmp::Ordering::Greater => Self::SecondFasterBy(first_ms - second_ms),
        }
    }
}

/// Explicit count comparison, including ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CountComparison {
    FirstHigherBy(u128),
    Equal,
    SecondHigherBy(u128),
}

impl CountComparison {
    fn between(first: u128, second: u128) -> Self {
        match first.cmp(&second) {
            std::cmp::Ordering::Less => Self::SecondHigherBy(second - first),
            std::cmp::Ordering::Equal => Self::Equal,
            std::cmp::Ordering::Greater => Self::FirstHigherBy(first - second),
        }
    }
}

/// Direct comparison between two recorded profiles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanComparison {
    pub first_scan_id: String,
    pub second_scan_id: String,
    pub duration: DurationComparison,
    pub findings: CountComparison,
    #[serde(with = "optional_finite_f64")]
    pub response_request_ratio_difference_percentage_points: Option<f64>,
}

mod optional_finite_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) if value.is_finite() => serializer.serialize_some(value),
            Some(_) => Err(serde::ser::Error::custom("value must be finite")),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<f64>::deserialize(deserializer)?;
        match value {
            Some(value) if value.is_finite() => Ok(Some(value)),
            Some(_) => Err(serde::de::Error::custom("value must be finite")),
            None => Ok(None),
        }
    }
}

/// Raw benchmark duration samples supplied by a caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub benchmark_id: String,
    pub benchmark_name: String,
    pub duration_samples_micros: Vec<u64>,
}

impl BenchmarkResult {
    pub fn mean_duration_micros(&self) -> Option<f64> {
        mean(&self.duration_samples_micros)
    }

    /// Nearest-rank percentile derived from the raw samples.
    pub fn percentile_duration_micros(&self, percentile: f64) -> Option<u64> {
        if self.duration_samples_micros.is_empty()
            || !percentile.is_finite()
            || !(0.0..=100.0).contains(&percentile)
        {
            return None;
        }
        let mut samples = self.duration_samples_micros.clone();
        samples.sort_unstable();
        let rank = ((percentile / 100.0) * samples.len() as f64).ceil() as usize;
        Some(samples[rank.saturating_sub(1).min(samples.len() - 1)])
    }
}

/// In-memory benchmark result catalog.
#[derive(Debug, Clone, Default)]
pub struct BenchmarkSuite {
    results: Vec<BenchmarkResult>,
}

impl BenchmarkSuite {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    pub fn get_result(&self, benchmark_id: &str) -> Option<&BenchmarkResult> {
        self.results
            .iter()
            .find(|result| result.benchmark_id == benchmark_id)
    }

    pub fn get_results(&self) -> &[BenchmarkResult] {
        &self.results
    }

    /// Selects records whose calculated mean exceeds the caller's threshold.
    pub fn results_with_mean_above(&self, threshold_micros: f64) -> Vec<&BenchmarkResult> {
        self.results
            .iter()
            .filter(|result| {
                result
                    .mean_duration_micros()
                    .is_some_and(|mean| mean > threshold_micros)
            })
            .collect()
    }

    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

fn ratio_percent(numerator: u64, denominator: u64) -> Option<f64> {
    ratio_percent_u128(u128::from(numerator), u128::from(denominator))
}

fn ratio_percent_u128(numerator: u128, denominator: u128) -> Option<f64> {
    (denominator != 0).then_some((numerator as f64 / denominator as f64) * 100.0)
}

fn mean(samples: &[u64]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let sum: u128 = samples.iter().map(|&sample| u128::from(sample)).sum();
    Some(sum as f64 / samples.len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phase(number: u8, duration_ms: u64, findings: u64) -> PhaseProfile {
        PhaseProfile {
            phase_number: number,
            phase_name: format!("phase-{number}"),
            start_time: 0,
            end_time: duration_ms,
            duration_ms,
            requests_sent: 2,
            responses_received: 1,
            findings_discovered: findings,
            error_count: 1,
            response_time_samples_ms: vec![10, 30],
        }
    }

    #[test]
    fn ratios_and_means_are_derived_from_raw_measurements() {
        let phase = phase(1, 40, 1);
        assert_eq!(phase.response_request_ratio_percent(), Some(50.0));
        assert_eq!(phase.findings_per_100_responses(), Some(100.0));
        assert_eq!(phase.mean_response_time_ms(), Some(20.0));
    }

    #[test]
    fn ties_return_every_tied_phase() {
        let mut profile = ScanProfile::new("scan".into());
        profile.add_phase(phase(1, 50, 2));
        profile.add_phase(phase(2, 50, 2));

        assert_eq!(profile.slowest_phases().len(), 2);
        assert_eq!(profile.most_productive_phases().len(), 2);
    }

    #[test]
    fn equal_profiles_are_reported_as_equal() {
        let mut catalog = PerformanceAnalyzer::new();
        let mut first = ScanProfile::new("first".into());
        first.total_duration_ms = 100;
        first.add_phase(phase(1, 100, 1));
        let mut second = first.clone();
        second.scan_id = "second".into();
        catalog.record_profile(first).expect("valid profile");
        catalog.record_profile(second).expect("valid profile");

        let comparison = catalog.compare("first", "second").unwrap();
        assert_eq!(comparison.duration, DurationComparison::Equal);
        assert_eq!(comparison.findings, CountComparison::Equal);
        assert_eq!(
            comparison.response_request_ratio_difference_percentage_points,
            Some(0.0)
        );
    }

    #[test]
    fn benchmark_statistics_require_raw_samples() {
        let empty = BenchmarkResult {
            benchmark_id: "empty".into(),
            benchmark_name: "empty".into(),
            duration_samples_micros: Vec::new(),
        };
        assert_eq!(empty.mean_duration_micros(), None);
        assert_eq!(empty.percentile_duration_micros(95.0), None);

        let result = BenchmarkResult {
            benchmark_id: "fixture".into(),
            benchmark_name: "fixture".into(),
            duration_samples_micros: vec![40, 10, 30, 20],
        };
        assert_eq!(result.mean_duration_micros(), Some(25.0));
        assert_eq!(result.percentile_duration_micros(50.0), Some(20));
        assert_eq!(result.percentile_duration_micros(f64::NAN), None);
    }

    #[test]
    fn resource_measurements_reject_nonfinite_and_out_of_range_wire_values() {
        let metrics = ResourceMetrics {
            memory_used_mb: f32::NAN,
            ..ResourceMetrics::default()
        };
        assert!(!metrics.is_valid());
        assert!(serde_json::to_string(&metrics).is_err());

        let invalid_cpu = r#"{
            "memory_used_mb": 1.0,
            "memory_peak_mb": 1.0,
            "cpu_usage_percent": 101.0,
            "cpu_peak_percent": 1.0,
            "disk_read_mb": 0.0,
            "disk_write_mb": 0.0,
            "network_in_mb": 0.0,
            "network_out_mb": 0.0
        }"#;
        assert!(serde_json::from_str::<ResourceMetrics>(invalid_cpu).is_err());
    }

    #[test]
    fn profile_catalog_rejects_invalid_resources_and_orders_by_id() {
        let mut catalog = PerformanceAnalyzer::new();
        let mut invalid = ScanProfile::new("invalid".into());
        invalid.resources.cpu_peak_percent = f32::INFINITY;
        assert!(catalog.record_profile(invalid).is_err());
        assert_eq!(catalog.profile_count(), 0);

        for id in ["zeta", "alpha"] {
            catalog
                .record_profile(ScanProfile::new(id.into()))
                .expect("valid profile");
        }
        assert_eq!(
            catalog
                .get_profiles()
                .into_iter()
                .map(|profile| profile.scan_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
    }

    #[test]
    fn comparison_wire_rejects_nonfinite_values() {
        let comparison = ScanComparison {
            first_scan_id: "first".into(),
            second_scan_id: "second".into(),
            duration: DurationComparison::Equal,
            findings: CountComparison::Equal,
            response_request_ratio_difference_percentage_points: Some(f64::NAN),
        };
        assert!(serde_json::to_string(&comparison).is_err());
    }
}
