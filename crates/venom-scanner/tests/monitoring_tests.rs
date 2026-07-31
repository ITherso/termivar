use venom_scanner::{
    BenchmarkResult, BenchmarkSuite, PerformanceAnalyzer, PhaseProfile, RecommendationCategory,
    ScanProfile,
};

#[test]
fn test_phase_profile_metrics() {
    let phase = PhaseProfile {
        phase_number: 1,
        phase_name: "Recon".to_string(),
        start_time: 1000,
        end_time: 5000,
        duration_ms: 4000,
        requests_sent: 100,
        responses_received: 95,
        findings_discovered: 8,
        error_count: 5,
        avg_response_time_ms: 40.0,
    };

    assert_eq!(phase.success_rate(), 95.0);
    assert!(phase.finding_density() > 8.0 && phase.finding_density() < 9.0);
}

#[test]
fn test_scan_profile_aggregation() {
    let mut profile = ScanProfile::new("scan_001".to_string());

    for i in 1..=3 {
        let phase = PhaseProfile {
            phase_number: i,
            phase_name: format!("Phase {}", i),
            start_time: 1000 * i as u64,
            end_time: 2000 * i as u64,
            duration_ms: 1000,
            requests_sent: 100,
            responses_received: 95,
            findings_discovered: 5,
            error_count: 5,
            avg_response_time_ms: 10.0,
        };
        profile.add_phase(phase);
    }

    assert_eq!(profile.total_requests, 300);
    assert_eq!(profile.total_findings, 15);
    assert_eq!(profile.total_errors, 15);
}

#[test]
fn test_slowest_phase_detection() {
    let mut profile = ScanProfile::new("scan_slow".to_string());

    let phase1 = PhaseProfile {
        phase_number: 1,
        phase_name: "Fast Phase".to_string(),
        start_time: 1000,
        end_time: 2000,
        duration_ms: 1000,
        requests_sent: 50,
        responses_received: 50,
        findings_discovered: 2,
        error_count: 0,
        avg_response_time_ms: 20.0,
    };

    let phase2 = PhaseProfile {
        phase_number: 2,
        phase_name: "Slow Phase".to_string(),
        start_time: 2000,
        end_time: 12000,
        duration_ms: 10000,
        requests_sent: 200,
        responses_received: 200,
        findings_discovered: 15,
        error_count: 0,
        avg_response_time_ms: 50.0,
    };

    profile.add_phase(phase1);
    profile.add_phase(phase2);

    let slowest = profile.slowest_phase();
    assert!(slowest.is_some());
    assert_eq!(slowest.unwrap().phase_number, 2);
}

#[test]
fn test_most_productive_phase() {
    let mut profile = ScanProfile::new("scan_productive".to_string());

    let phase1 = PhaseProfile {
        phase_number: 1,
        phase_name: "Phase 1".to_string(),
        start_time: 1000,
        end_time: 2000,
        duration_ms: 1000,
        requests_sent: 100,
        responses_received: 100,
        findings_discovered: 2,
        error_count: 0,
        avg_response_time_ms: 10.0,
    };

    let phase2 = PhaseProfile {
        phase_number: 2,
        phase_name: "Phase 2".to_string(),
        start_time: 2000,
        end_time: 3000,
        duration_ms: 1000,
        requests_sent: 100,
        responses_received: 100,
        findings_discovered: 25,
        error_count: 0,
        avg_response_time_ms: 10.0,
    };

    profile.add_phase(phase1);
    profile.add_phase(phase2);

    let most_productive = profile.most_productive_phase();
    assert!(most_productive.is_some());
    assert_eq!(most_productive.unwrap().phase_number, 2);
    assert_eq!(most_productive.unwrap().findings_discovered, 25);
}

#[test]
fn test_performance_analyzer_recording() {
    let mut analyzer = PerformanceAnalyzer::new();

    let profile1 = ScanProfile::new("scan_1".to_string());
    let profile2 = ScanProfile::new("scan_2".to_string());

    analyzer.record_profile(profile1);
    analyzer.record_profile(profile2);

    assert_eq!(analyzer.profile_count(), 2);
    assert!(analyzer.get_profile("scan_1").is_some());
    assert!(analyzer.get_profile("scan_2").is_some());
}

#[test]
fn test_optimization_recommendations_high_memory() {
    let mut analyzer = PerformanceAnalyzer::new();

    let mut profile = ScanProfile::new("high_memory_scan".to_string());
    profile.resources.memory_peak_mb = 600.0;

    let phase = PhaseProfile {
        phase_number: 1,
        phase_name: "Test Phase".to_string(),
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
    analyzer.record_profile(profile);

    let recommendations = analyzer.analyze("high_memory_scan");
    assert!(!recommendations.is_empty());

    let memory_rec = recommendations
        .iter()
        .find(|r| r.category == RecommendationCategory::Resource);
    assert!(memory_rec.is_some());
}

#[test]
fn test_optimization_recommendations_slow_phase() {
    let mut analyzer = PerformanceAnalyzer::new();

    let mut profile = ScanProfile::new("slow_scan".to_string());

    let phase = PhaseProfile {
        phase_number: 1,
        phase_name: "Slow Phase".to_string(),
        start_time: 1000,
        end_time: 33000,
        duration_ms: 32000,
        requests_sent: 100,
        responses_received: 100,
        findings_discovered: 5,
        error_count: 0,
        avg_response_time_ms: 320.0,
    };

    profile.add_phase(phase);
    analyzer.record_profile(profile);

    let recommendations = analyzer.analyze("slow_scan");
    assert!(!recommendations.is_empty());

    let perf_rec = recommendations
        .iter()
        .find(|r| r.category == RecommendationCategory::Performance);
    assert!(perf_rec.is_some());
}

#[test]
fn test_high_error_rate_detection() {
    let mut analyzer = PerformanceAnalyzer::new();

    let mut profile = ScanProfile::new("error_scan".to_string());
    profile.total_requests = 100;
    profile.total_errors = 10;

    analyzer.record_profile(profile);

    let recommendations = analyzer.analyze("error_scan");
    assert!(!recommendations.is_empty());
}

#[test]
fn test_scan_comparison() {
    let mut analyzer = PerformanceAnalyzer::new();

    let mut profile1 = ScanProfile::new("scan_fast".to_string());
    profile1.total_duration_ms = 5000;
    profile1.total_findings = 10;

    let mut profile2 = ScanProfile::new("scan_slow".to_string());
    profile2.total_duration_ms = 15000;
    profile2.total_findings = 12;

    analyzer.record_profile(profile1);
    analyzer.record_profile(profile2);

    let comparison = analyzer.compare("scan_fast", "scan_slow");
    assert!(comparison.is_some());

    let comp = comparison.unwrap();
    assert_eq!(comp.duration_diff_ms, 10000);
    assert_eq!(comp.finding_diff, 2);
    assert_eq!(comp.faster, "scan_1");
}

#[test]
fn test_benchmark_creation() {
    let result = BenchmarkResult {
        benchmark_id: "bench_sqli".to_string(),
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

    assert_eq!(result.benchmark_name, "SQLi Detection");
    assert_eq!(result.iterations, 1000);
    assert!(result.avg_ms > result.median_ms);
}

#[test]
fn test_benchmark_suite_recording() {
    let mut suite = BenchmarkSuite::new();

    for i in 1..=3 {
        let result = BenchmarkResult {
            benchmark_id: format!("bench_{}", i),
            benchmark_name: format!("Benchmark {}", i),
            iterations: 100,
            min_ms: 1.0,
            max_ms: 5.0,
            avg_ms: 2.5,
            median_ms: 2.3,
            p95_ms: 4.5,
            p99_ms: 4.9,
            throughput_per_sec: 400.0,
        };
        suite.record_result(result);
    }

    assert_eq!(suite.result_count(), 3);
}

#[test]
fn test_regression_detection_10_percent_threshold() {
    let mut suite = BenchmarkSuite::new();

    let baseline = BenchmarkResult {
        benchmark_id: "baseline".to_string(),
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
        benchmark_id: "regression".to_string(),
        benchmark_name: "Test".to_string(),
        iterations: 100,
        min_ms: 1.5,
        max_ms: 3.0,
        avg_ms: 1.8, // 20% slower than baseline 1.5
        median_ms: 1.7,
        p95_ms: 2.9,
        p99_ms: 3.0,
        throughput_per_sec: 556.0,
    };

    suite.record_result(baseline);
    suite.record_result(regression);

    let regressions = suite.detect_regressions(1.5);
    assert_eq!(regressions.len(), 1);
}

#[test]
fn test_no_regression_within_threshold() {
    let mut suite = BenchmarkSuite::new();

    let baseline = BenchmarkResult {
        benchmark_id: "baseline".to_string(),
        benchmark_name: "Test".to_string(),
        iterations: 100,
        min_ms: 1.0,
        max_ms: 2.0,
        avg_ms: 2.0,
        median_ms: 1.9,
        p95_ms: 1.9,
        p99_ms: 2.0,
        throughput_per_sec: 500.0,
    };

    let acceptable = BenchmarkResult {
        benchmark_id: "acceptable".to_string(),
        benchmark_name: "Test".to_string(),
        iterations: 100,
        min_ms: 1.0,
        max_ms: 2.0,
        avg_ms: 2.05, // Only 2.5% slower
        median_ms: 1.95,
        p95_ms: 1.95,
        p99_ms: 2.0,
        throughput_per_sec: 488.0,
    };

    suite.record_result(baseline);
    suite.record_result(acceptable);

    let regressions = suite.detect_regressions(2.0);
    assert!(regressions.is_empty());
}

#[test]
fn test_benchmark_percentiles() {
    let result = BenchmarkResult {
        benchmark_id: "complete_bench".to_string(),
        benchmark_name: "Complete Test".to_string(),
        iterations: 10000,
        min_ms: 0.1,
        max_ms: 100.0,
        avg_ms: 10.0,
        median_ms: 5.0,
        p95_ms: 45.0,
        p99_ms: 90.0,
        throughput_per_sec: 100.0,
    };

    assert!(result.p95_ms >= result.median_ms);
    assert!(result.p99_ms >= result.p95_ms);
    assert_eq!(result.iterations, 10000);
}

#[test]
fn test_multiple_profile_analysis() {
    let mut analyzer = PerformanceAnalyzer::new();

    for scan_num in 1..=5 {
        let mut profile = ScanProfile::new(format!("scan_{}", scan_num));
        profile.total_duration_ms = 5000 * scan_num as u64;
        profile.total_findings = 10 + scan_num as u64;

        analyzer.record_profile(profile);
    }

    let profiles = analyzer.get_profiles();
    assert_eq!(profiles.len(), 5);

    // Verify sorting/retrieval
    assert!(analyzer.get_profile("scan_1").is_some());
    assert!(analyzer.get_profile("scan_5").is_some());
}
