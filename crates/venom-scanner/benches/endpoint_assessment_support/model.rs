use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

use serde::Serialize;

pub(crate) const ENDPOINT_PERFORMANCE_SCHEMA: &str = "venom.endpoint-performance/v1";
pub(crate) const FIXTURE_RESPONSE_DELAY_MS: u64 = 1;
pub(crate) const ACTIVE_VERIFICATIONS_PER_AUTHORITY: u16 = 1;
pub(crate) const MIN_WARMUP_SAMPLES: u8 = 1;
pub(crate) const MAX_WARMUP_SAMPLES: u8 = 3;
pub(crate) const MIN_MEASURED_SAMPLES: u8 = 3;
pub(crate) const MAX_MEASURED_SAMPLES: u8 = 10;
const PROXY_ENVIRONMENT_VARIABLES: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

pub(crate) fn require_proxy_free_environment() -> Result<(), String> {
    validate_proxy_environment(
        PROXY_ENVIRONMENT_VARIABLES
            .into_iter()
            .filter_map(|name| env::var_os(name).map(|value| (name, value))),
    )
}

fn validate_proxy_environment(
    variables: impl IntoIterator<Item = (&'static str, OsString)>,
) -> Result<(), String> {
    if let Some((name, _)) = variables.into_iter().find(|(_, value)| !value.is_empty()) {
        return Err(format!(
            "endpoint benchmark refuses proxy environment variable {name}; clear HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY variants before starting the loopback fixture"
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_proxy_environment_for_test<I>(variables: I) -> Result<(), String>
where
    I: IntoIterator<Item = (&'static str, OsString)>,
{
    validate_proxy_environment(variables)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkloadSelection {
    All,
    Endpoints100,
    Endpoints1000,
    Requests10000,
}

impl WorkloadSelection {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "all" => Ok(Self::All),
            "100" => Ok(Self::Endpoints100),
            "1000" => Ok(Self::Endpoints1000),
            "10000" => Ok(Self::Requests10000),
            _ => Err("--workload must be one of all, 100, 1000, or 10000".to_owned()),
        }
    }

    pub(crate) fn specs(self) -> Vec<WorkloadSpec> {
        let mut specs = Vec::new();
        if matches!(self, Self::All | Self::Endpoints100) {
            specs.push(WorkloadSpec::single("endpoints-100", 100));
        }
        if matches!(self, Self::All | Self::Endpoints1000) {
            specs.push(WorkloadSpec::single("endpoints-1000", 1_000));
        }
        if matches!(self, Self::All | Self::Requests10000) {
            specs.push(WorkloadSpec::ten_thousand_requests());
        }
        specs
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BenchmarkArguments {
    selection: WorkloadSelection,
    warmups: u8,
    samples: u8,
    output: Option<PathBuf>,
    help_requested: bool,
}

impl BenchmarkArguments {
    pub(crate) fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut selection = None;
        let mut warmups = None;
        let mut samples = None;
        let mut output = None;
        let mut help_requested = false;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let argument = argument
                .into_string()
                .map_err(|_| "benchmark arguments must be valid UTF-8".to_owned())?;
            match argument.as_str() {
                "--help" | "-h" => help_requested = true,
                "--workload" => {
                    reject_duplicate(selection.is_some(), "--workload")?;
                    selection = Some(WorkloadSelection::parse(&next_utf8(
                        &mut arguments,
                        "--workload",
                    )?)?);
                },
                "--warmups" => {
                    reject_duplicate(warmups.is_some(), "--warmups")?;
                    warmups = Some(parse_bounded_count(
                        &next_utf8(&mut arguments, "--warmups")?,
                        "--warmups",
                        MIN_WARMUP_SAMPLES,
                        MAX_WARMUP_SAMPLES,
                    )?);
                },
                "--samples" => {
                    reject_duplicate(samples.is_some(), "--samples")?;
                    samples = Some(parse_bounded_count(
                        &next_utf8(&mut arguments, "--samples")?,
                        "--samples",
                        MIN_MEASURED_SAMPLES,
                        MAX_MEASURED_SAMPLES,
                    )?);
                },
                "--output" => {
                    reject_duplicate(output.is_some(), "--output")?;
                    let value = next_utf8(&mut arguments, "--output")?;
                    if value.is_empty() {
                        return Err("--output must not be empty".to_owned());
                    }
                    output = Some(PathBuf::from(value));
                },
                _ => return Err(format!("unknown benchmark argument: {argument}")),
            }
        }
        Ok(Self {
            selection: selection.unwrap_or(WorkloadSelection::All),
            warmups: warmups.unwrap_or(MIN_WARMUP_SAMPLES),
            samples: samples.unwrap_or(MIN_MEASURED_SAMPLES),
            output,
            help_requested,
        })
    }

    pub(crate) const fn selection(&self) -> WorkloadSelection {
        self.selection
    }

    pub(crate) const fn warmups(&self) -> u8 {
        self.warmups
    }

    pub(crate) const fn samples(&self) -> u8 {
        self.samples
    }

    pub(crate) fn output(&self) -> Option<&Path> {
        self.output.as_deref()
    }

    pub(crate) const fn help_requested(&self) -> bool {
        self.help_requested
    }

    pub(crate) const fn help() -> &'static str {
        "Deterministic loopback endpoint assessment harness\n\n\
Usage:\n  endpoint_assessment --output PATH [--workload all|100|1000|10000] \\\n    [--warmups 1..3] [--samples 3..10]\n\n\
The target is always a harness-owned 127.0.0.1 fixture. No target argument exists."
    }
}

fn next_utf8<I>(arguments: &mut I, option: &str) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))?
        .into_string()
        .map_err(|_| format!("{option} must be valid UTF-8"))
}

fn reject_duplicate(duplicate: bool, option: &str) -> Result<(), String> {
    if duplicate {
        Err(format!("{option} may be supplied only once"))
    } else {
        Ok(())
    }
}

fn parse_bounded_count(value: &str, option: &str, minimum: u8, maximum: u8) -> Result<u8, String> {
    let parsed = value
        .parse::<u8>()
        .map_err(|_| format!("{option} must be an integer"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!(
            "{option} must be within the compiled range {minimum}..={maximum}"
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Clone)]
pub(crate) struct WorkloadSpec {
    pub(crate) id: &'static str,
    pub(crate) subjects_per_authority: Vec<usize>,
}

impl WorkloadSpec {
    fn single(id: &'static str, subjects: usize) -> Self {
        Self {
            id,
            subjects_per_authority: vec![subjects],
        }
    }

    fn ten_thousand_requests() -> Self {
        Self {
            id: "requests-10000",
            subjects_per_authority: vec![998; 10],
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture_test(subjects: usize) -> Self {
        Self::single("fixture-test", subjects)
    }

    pub(crate) fn endpoint_count(&self) -> usize {
        self.subjects_per_authority.iter().sum()
    }

    pub(crate) fn requests_per_authority(&self) -> Vec<u32> {
        self.subjects_per_authority
            .iter()
            .map(|subjects| u32::try_from(subjects.saturating_add(2)).unwrap_or(u32::MAX))
            .collect()
    }

    pub(crate) fn total_requests(&self) -> u32 {
        self.requests_per_authority()
            .into_iter()
            .fold(0_u32, u32::saturating_add)
    }

    pub(crate) fn authority_count(&self) -> usize {
        self.subjects_per_authority.len()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct EndpointPerformanceReport {
    pub(crate) schema: &'static str,
    pub(crate) environment: BenchmarkEnvironment,
    pub(crate) configuration: BenchmarkConfiguration,
    pub(crate) process_resources: ProcessResources,
    pub(crate) workloads: Vec<WorkloadReport>,
    pub(crate) thresholds: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BenchmarkEnvironment {
    pub(crate) commit_sha: String,
    pub(crate) rust_version: String,
    pub(crate) os: String,
    pub(crate) architecture: &'static str,
    pub(crate) build_profile: String,
    pub(crate) package_version: &'static str,
    pub(crate) hardware: HardwareEnvironment,
}

impl BenchmarkEnvironment {
    pub(crate) fn observed() -> Self {
        Self {
            commit_sha: env_or_unknown("VENOM_PERF_COMMIT_SHA"),
            rust_version: env_or_unknown("VENOM_PERF_RUST_VERSION"),
            os: env::var("VENOM_PERF_OS").unwrap_or_else(|_| env::consts::OS.to_owned()),
            architecture: env::consts::ARCH,
            build_profile: env::var("VENOM_PERF_BUILD_PROFILE")
                .unwrap_or_else(|_| "bench".to_owned()),
            package_version: env!("CARGO_PKG_VERSION"),
            hardware: HardwareEnvironment {
                cpu_model: env_or_unknown("VENOM_PERF_CPU_MODEL"),
                logical_cpus: std::thread::available_parallelism()
                    .map(std::num::NonZeroUsize::get)
                    .unwrap_or(1),
                total_memory_bytes: env::var("VENOM_PERF_TOTAL_MEMORY_BYTES")
                    .ok()
                    .and_then(|value| value.parse().ok()),
            },
        }
    }
}

fn env_or_unknown(name: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[derive(Debug, Serialize)]
pub(crate) struct HardwareEnvironment {
    pub(crate) cpu_model: String,
    pub(crate) logical_cpus: usize,
    pub(crate) total_memory_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BenchmarkConfiguration {
    pub(crate) warmup_samples: u8,
    pub(crate) measured_samples: u8,
    pub(crate) fixture: &'static str,
    pub(crate) fixture_response_delay_ms: u64,
    pub(crate) runtime_concurrency: usize,
    pub(crate) active_verifications_per_authority: u16,
    pub(crate) latency_source: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct ProcessResources {
    pub(crate) user_cpu_seconds: Option<f64>,
    pub(crate) system_cpu_seconds: Option<f64>,
    pub(crate) total_cpu_seconds: Option<f64>,
    pub(crate) cpu_percent: Option<f64>,
    pub(crate) peak_rss_kib: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkloadReport {
    pub(crate) id: &'static str,
    pub(crate) endpoint_count: usize,
    pub(crate) total_requests: u32,
    pub(crate) authority_count: usize,
    pub(crate) requests_per_authority: Vec<u32>,
    pub(crate) authority_model: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) samples: Vec<SampleMeasurement>,
    pub(crate) summary: WorkloadSummary,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SampleMeasurement {
    pub(crate) sample_index: u8,
    pub(crate) wall_time_ms: f64,
    pub(crate) requests_per_second: f64,
    pub(crate) p50_latency_ms: u64,
    pub(crate) p95_latency_ms: u64,
    pub(crate) p99_latency_ms: u64,
    pub(crate) total_requests: u32,
    pub(crate) response_bytes: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkloadSummary {
    pub(crate) wall_time_ms: MetricSummary,
    pub(crate) requests_per_second: MetricSummary,
    pub(crate) p50_latency_ms: MetricSummary,
    pub(crate) p95_latency_ms: MetricSummary,
    pub(crate) p99_latency_ms: MetricSummary,
    pub(crate) response_bytes: MetricSummary,
}

impl WorkloadSummary {
    pub(crate) fn from_samples(samples: &[SampleMeasurement]) -> Self {
        Self {
            wall_time_ms: MetricSummary::new(samples.iter().map(|sample| sample.wall_time_ms)),
            requests_per_second: MetricSummary::new(
                samples.iter().map(|sample| sample.requests_per_second),
            ),
            p50_latency_ms: MetricSummary::new(
                samples.iter().map(|sample| sample.p50_latency_ms as f64),
            ),
            p95_latency_ms: MetricSummary::new(
                samples.iter().map(|sample| sample.p95_latency_ms as f64),
            ),
            p99_latency_ms: MetricSummary::new(
                samples.iter().map(|sample| sample.p99_latency_ms as f64),
            ),
            response_bytes: MetricSummary::new(
                samples.iter().map(|sample| sample.response_bytes as f64),
            ),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricSummary {
    pub(crate) minimum: f64,
    pub(crate) median: f64,
    pub(crate) maximum: f64,
    pub(crate) mean: f64,
    pub(crate) standard_deviation: f64,
    pub(crate) coefficient_of_variation_percent: f64,
}

impl MetricSummary {
    fn new(values: impl Iterator<Item = f64>) -> Self {
        let mut values = values.collect::<Vec<_>>();
        values.sort_by(f64::total_cmp);
        let count = values.len() as f64;
        let mean = values.iter().sum::<f64>() / count;
        let variance = values
            .iter()
            .map(|value| {
                let delta = value - mean;
                delta * delta
            })
            .sum::<f64>()
            / count;
        let standard_deviation = variance.sqrt();
        let coefficient_of_variation_percent = if mean == 0.0 {
            0.0
        } else {
            standard_deviation / mean * 100.0
        };
        Self {
            minimum: values[0],
            median: median_f64(&values),
            maximum: values[values.len() - 1],
            mean,
            standard_deviation,
            coefficient_of_variation_percent,
        }
    }
}

fn median_f64(sorted: &[f64]) -> f64 {
    let midpoint = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[midpoint - 1] + sorted[midpoint]) / 2.0
    } else {
        sorted[midpoint]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn even_sample_summary_uses_the_statistical_median() {
        let summary = super::MetricSummary::new([4.0, 1.0, 3.0, 2.0].into_iter());
        assert_eq!(summary.median, 2.5);
    }
}
