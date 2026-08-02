//! Advanced Monitoring & Performance Analytics
//!
//! Comprehensive scan profiling, resource tracking, and optimization recommendations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Phase execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub avg_response_time_ms: f32,
}

impl PhaseProfile {
    pub fn success_rate(&self) -> f32 {
        if self.requests_sent == 0 {
            return 0.0;
        }
        (self.responses_received as f32 / self.requests_sent as f32) * 100.0
    }

    pub fn finding_density(&self) -> f32 {
        if self.responses_received == 0 {
            return 0.0;
        }
        (self.findings_discovered as f32 / self.responses_received as f32) * 100.0
    }
}

/// Resource usage during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub memory_used_mb: f32,
    pub memory_peak_mb: f32,
    pub cpu_usage_percent: f32,
    pub cpu_peak_percent: f32,
    pub disk_read_mb: f32,
    pub disk_write_mb: f32,
    pub network_in_mb: f32,
    pub network_out_mb: f32,
}

/// Scan performance profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub scan_id: String,
    pub total_duration_ms: u64,
    pub phases: Vec<PhaseProfile>,
    pub resources: ResourceMetrics,
    pub total_requests: u64,
    pub total_responses: u64,
    pub total_findings: u64,
    pub total_errors: u64,
}

impl ScanProfile {
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            total_duration_ms: 0,
            phases: Vec::new(),
            resources: ResourceMetrics {
                memory_used_mb: 0.0,
                memory_peak_mb: 0.0,
                cpu_usage_percent: 0.0,
                cpu_peak_percent: 0.0,
                disk_read_mb: 0.0,
                disk_write_mb: 0.0,
                network_in_mb: 0.0,
                network_out_mb: 0.0,
            },
            total_requests: 0,
            total_responses: 0,
            total_findings: 0,
            total_errors: 0,
        }
    }

    pub fn add_phase(&mut self, phase: PhaseProfile) {
        self.total_requests += phase.requests_sent;
        self.total_responses += phase.responses_received;
        self.total_findings += phase.findings_discovered;
        self.total_errors += phase.error_count;
        self.phases.push(phase);
    }

    pub fn overall_success_rate(&self) -> f32 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.total_responses as f32 / self.total_requests as f32) * 100.0
    }

    pub fn slowest_phase(&self) -> Option<&PhaseProfile> {
        self.phases.iter().max_by_key(|p| p.duration_ms)
    }

    pub fn most_productive_phase(&self) -> Option<&PhaseProfile> {
        self.phases.iter().max_by_key(|p| p.findings_discovered)
    }
}

/// Optimization recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendation {
    pub recommendation_id: String,
    pub category: RecommendationCategory,
    pub severity: String,
    pub description: String,
    pub impact: String,
    pub suggested_action: String,
}

/// Recommendation categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendationCategory {
    #[serde(rename = "performance")]
    Performance,
    #[serde(rename = "resource")]
    Resource,
    #[serde(rename = "efficiency")]
    Efficiency,
    #[serde(rename = "accuracy")]
    Accuracy,
}

impl RecommendationCategory {
    pub fn as_str(&self) -> &str {
        match self {
            RecommendationCategory::Performance => "performance",
            RecommendationCategory::Resource => "resource",
            RecommendationCategory::Efficiency => "efficiency",
            RecommendationCategory::Accuracy => "accuracy",
        }
    }
}

/// Performance analyzer
pub struct PerformanceAnalyzer {
    profiles: HashMap<String, ScanProfile>,
}

impl PerformanceAnalyzer {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Records a scan profile
    pub fn record_profile(&mut self, profile: ScanProfile) {
        self.profiles.insert(profile.scan_id.clone(), profile);
    }

    /// Gets profile by ID
    pub fn get_profile(&self, scan_id: &str) -> Option<&ScanProfile> {
        self.profiles.get(scan_id)
    }

    /// Analyzes profile and generates recommendations
    pub fn analyze(&self, scan_id: &str) -> Vec<OptimizationRecommendation> {
        let mut recommendations = Vec::new();

        if let Some(profile) = self.get_profile(scan_id) {
            // Detect slow phases
            if let Some(slowest) = profile.slowest_phase() {
                if slowest.duration_ms > 30000 {
                    recommendations.push(OptimizationRecommendation {
                        recommendation_id: format!("slow_phase_{}", slowest.phase_number),
                        category: RecommendationCategory::Performance,
                        severity: "HIGH".to_string(),
                        description: format!(
                            "Phase {} ({}) took {}ms",
                            slowest.phase_number, slowest.phase_name, slowest.duration_ms
                        ),
                        impact: "Slow phases delay overall scan completion".to_string(),
                        suggested_action: "Consider increasing concurrency or reducing timeout values"
                            .to_string(),
                    });
                }
            }

            // Detect high error rates
            if profile.total_requests > 0 {
                let error_rate =
                    (profile.total_errors as f32 / profile.total_requests as f32) * 100.0;
                if error_rate > 5.0 {
                    recommendations.push(OptimizationRecommendation {
                        recommendation_id: "high_error_rate".to_string(),
                        category: RecommendationCategory::Resource,
                        severity: "MEDIUM".to_string(),
                        description: format!("Error rate is {:.1}%", error_rate),
                        impact: "High error rates indicate potential connectivity issues"
                            .to_string(),
                        suggested_action: "Check network stability and target server availability"
                            .to_string(),
                    });
                }
            }

            // Detect low efficiency
            let low_finding_phases: Vec<_> = profile
                .phases
                .iter()
                .filter(|p| p.finding_density() < 0.5)
                .collect();

            if low_finding_phases.len() > 2 {
                recommendations.push(OptimizationRecommendation {
                    recommendation_id: "low_efficiency".to_string(),
                    category: RecommendationCategory::Efficiency,
                    severity: "LOW".to_string(),
                    description: "Multiple phases have low finding density".to_string(),
                    impact: "Time spent on less productive phases".to_string(),
                    suggested_action: "Consider reducing intensity or phases for faster scans"
                        .to_string(),
                });
            }

            // Detect resource spikes
            if profile.resources.memory_peak_mb > 500.0 {
                recommendations.push(OptimizationRecommendation {
                    recommendation_id: "high_memory".to_string(),
                    category: RecommendationCategory::Resource,
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "Peak memory usage: {:.1} MB",
                        profile.resources.memory_peak_mb
                    ),
                    impact: "High memory usage limits parallelism".to_string(),
                    suggested_action: "Reduce concurrency or scan fewer endpoints at once"
                        .to_string(),
                });
            }
        }

        recommendations
    }

    /// Gets all profiles
    pub fn get_profiles(&self) -> Vec<&ScanProfile> {
        self.profiles.values().collect()
    }

    /// Compares two scan profiles
    pub fn compare(&self, scan_id1: &str, scan_id2: &str) -> Option<ScanComparison> {
        let profile1 = self.profiles.get(scan_id1)?;
        let profile2 = self.profiles.get(scan_id2)?;

        let duration_diff = profile2.total_duration_ms as i64 - profile1.total_duration_ms as i64;
        let success_rate_diff = profile2.overall_success_rate() - profile1.overall_success_rate();
        let finding_diff = profile2.total_findings as i64 - profile1.total_findings as i64;

        Some(ScanComparison {
            scan_id1: scan_id1.to_string(),
            scan_id2: scan_id2.to_string(),
            duration_diff_ms: duration_diff,
            success_rate_diff,
            finding_diff,
            faster: if duration_diff > 0 {
                "scan_1"
            } else {
                "scan_2"
            }
            .to_string(),
        })
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

impl Default for PerformanceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Comparison between two scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    pub scan_id1: String,
    pub scan_id2: String,
    pub duration_diff_ms: i64,
    pub success_rate_diff: f32,
    pub finding_diff: i64,
    pub faster: String,
}

/// Benchmark suite for performance testing
pub struct BenchmarkSuite {
    results: Vec<BenchmarkResult>,
}

/// Individual benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub benchmark_id: String,
    pub benchmark_name: String,
    pub iterations: u32,
    pub min_ms: f32,
    pub max_ms: f32,
    pub avg_ms: f32,
    pub median_ms: f32,
    pub p95_ms: f32,
    pub p99_ms: f32,
    pub throughput_per_sec: f32,
}

impl BenchmarkSuite {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Records a benchmark result
    pub fn record_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    /// Gets benchmark by ID
    pub fn get_result(&self, benchmark_id: &str) -> Option<&BenchmarkResult> {
        self.results.iter().find(|r| r.benchmark_id == benchmark_id)
    }

    /// Gets all results
    pub fn get_results(&self) -> &[BenchmarkResult] {
        &self.results
    }

    /// Finds regressions (results slower than baseline)
    pub fn detect_regressions(&self, baseline_avg_ms: f32) -> Vec<&BenchmarkResult> {
        self.results
            .iter()
            .filter(|r| r.avg_ms > baseline_avg_ms * 1.1) // 10% slower = regression
            .collect()
    }

    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

impl Default for BenchmarkSuite {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_profile_creation() {
        let phase = PhaseProfile {
            phase_number: 1,
            phase_name: "Recon".to_string(),
            start_time: 1000,
            end_time: 2000,
            duration_ms: 1000,
            requests_sent: 100,
            responses_received: 95,
            findings_discovered: 5,
            error_count: 5,
            avg_response_time_ms: 10.5,
        };

        assert_eq!(phase.success_rate(), 95.0);
        assert!(phase.finding_density() > 0.0);
    }

    #[test]
    fn test_scan_profile() {
        let mut profile = ScanProfile::new("scan1".to_string());
        let phase = PhaseProfile {
            phase_number: 1,
            phase_name: "Recon".to_string(),
            start_time: 1000,
            end_time: 2000,
            duration_ms: 1000,
            requests_sent: 100,
            responses_received: 100,
            findings_discovered: 5,
            error_count: 0,
            avg_response_time_ms: 10.0,
        };

        profile.add_phase(phase);
        assert_eq!(profile.total_requests, 100);
        assert_eq!(profile.total_findings, 5);
    }

    #[test]
    fn test_performance_analyzer() {
        let mut analyzer = PerformanceAnalyzer::new();
        let profile = ScanProfile::new("scan1".to_string());
        analyzer.record_profile(profile);

        assert_eq!(analyzer.profile_count(), 1);
    }

    #[test]
    fn test_optimization_recommendations() {
        let mut analyzer = PerformanceAnalyzer::new();

        let mut profile = ScanProfile::new("scan1".to_string());
        profile.total_duration_ms = 60000;
        profile.resources.memory_peak_mb = 600.0;

        let phase = PhaseProfile {
            phase_number: 1,
            phase_name: "Recon".to_string(),
            start_time: 1000,
            end_time: 31000,
            duration_ms: 30000,
            requests_sent: 100,
            responses_received: 100,
            findings_discovered: 1,
            error_count: 0,
            avg_response_time_ms: 10.0,
        };

        profile.add_phase(phase);
        analyzer.record_profile(profile);

        let recommendations = analyzer.analyze("scan1");
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_scan_comparison() {
        let mut analyzer = PerformanceAnalyzer::new();

        let mut profile1 = ScanProfile::new("scan1".to_string());
        profile1.total_duration_ms = 10000;

        let mut profile2 = ScanProfile::new("scan2".to_string());
        profile2.total_duration_ms = 5000;

        analyzer.record_profile(profile1);
        analyzer.record_profile(profile2);

        let comparison = analyzer.compare("scan1", "scan2");
        assert!(comparison.is_some());
    }

    #[test]
    fn test_benchmark_suite() {
        let mut suite = BenchmarkSuite::new();

        let result = BenchmarkResult {
            benchmark_id: "bench1".to_string(),
            benchmark_name: "SQLi Detection".to_string(),
            iterations: 1000,
            min_ms: 0.5,
            max_ms: 5.0,
            avg_ms: 2.0,
            median_ms: 1.8,
            p95_ms: 4.5,
            p99_ms: 4.9,
            throughput_per_sec: 500.0,
        };

        suite.record_result(result);
        assert_eq!(suite.result_count(), 1);
    }

    #[test]
    fn test_regression_detection() {
        let mut suite = BenchmarkSuite::new();

        let baseline = BenchmarkResult {
            benchmark_id: "bench1".to_string(),
            benchmark_name: "Test".to_string(),
            iterations: 100,
            min_ms: 1.0,
            max_ms: 2.0,
            avg_ms: 1.5,
            median_ms: 1.4,
            p95_ms: 1.9,
            p99_ms: 2.0,
            throughput_per_sec: 667.0,
        };

        let regression = BenchmarkResult {
            benchmark_id: "bench2".to_string(),
            benchmark_name: "Test".to_string(),
            iterations: 100,
            min_ms: 2.0,
            max_ms: 3.0,
            avg_ms: 2.5, // 67% slower
            median_ms: 2.4,
            p95_ms: 2.9,
            p99_ms: 3.0,
            throughput_per_sec: 400.0,
        };

        suite.record_result(baseline);
        suite.record_result(regression);

        let regressions = suite.detect_regressions(1.5);
        assert_eq!(regressions.len(), 1);
    }

    #[test]
    fn test_recommendation_category() {
        assert_eq!(RecommendationCategory::Performance.as_str(), "performance");
        assert_eq!(RecommendationCategory::Resource.as_str(), "resource");
        assert_eq!(RecommendationCategory::Efficiency.as_str(), "efficiency");
        assert_eq!(RecommendationCategory::Accuracy.as_str(), "accuracy");
    }
}
