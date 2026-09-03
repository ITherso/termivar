//! Shared implementation for the endpoint-scale harness and its contract test.

mod fixture;
mod model;
mod runner;

use clap::Parser as _;
use std::{ffi::OsString, path::Path};

#[cfg(test)]
pub(crate) use model::validate_proxy_environment_for_test;
pub(crate) use model::{BenchmarkArguments, EndpointPerformanceReport, WorkloadSelection};
pub(crate) use runner::run_benchmark;
#[cfg(test)]
pub(crate) use runner::run_fixture_benchmark;

pub(crate) async fn run_from_process_arguments() -> Result<(), String> {
    let arguments = ProcessArguments::try_parse()
        .map_err(|error| error.to_string())?
        .into_benchmark_arguments()?;
    if arguments.help_requested() {
        println!("{}", BenchmarkArguments::help());
        return Ok(());
    }
    let output = arguments
        .output()
        .ok_or_else(|| "--output is required".to_owned())?;
    let report = run_benchmark(
        arguments.selection(),
        arguments.warmups(),
        arguments.samples(),
    )
    .await?;
    write_json_atomically(output, &report)
}

#[derive(clap::Parser)]
#[command(
    name = "endpoint_assessment",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct ProcessArguments {
    #[arg(short = 'h', long = "help", action = clap::ArgAction::SetTrue)]
    help: bool,
    #[arg(long, value_name = "SELECTION", allow_hyphen_values = true)]
    workload: Option<OsString>,
    #[arg(long, value_name = "COUNT", allow_hyphen_values = true)]
    warmups: Option<OsString>,
    #[arg(long, value_name = "COUNT", allow_hyphen_values = true)]
    samples: Option<OsString>,
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    output: Option<OsString>,
}

impl ProcessArguments {
    fn into_benchmark_arguments(self) -> Result<BenchmarkArguments, String> {
        let mut arguments = Vec::with_capacity(9);
        if self.help {
            arguments.push(OsString::from("--help"));
        }
        append_process_option(&mut arguments, "--workload", self.workload);
        append_process_option(&mut arguments, "--warmups", self.warmups);
        append_process_option(&mut arguments, "--samples", self.samples);
        append_process_option(&mut arguments, "--output", self.output);
        BenchmarkArguments::parse(arguments)
    }
}

fn append_process_option(
    arguments: &mut Vec<OsString>,
    name: &'static str,
    value: Option<OsString>,
) {
    if let Some(value) = value {
        arguments.push(OsString::from(name));
        arguments.push(value);
    }
}

#[cfg(test)]
pub(crate) fn parse_process_arguments_for_test<I, T>(
    arguments: I,
) -> Result<BenchmarkArguments, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    ProcessArguments::try_parse_from(arguments)
        .map_err(|error| error.to_string())?
        .into_benchmark_arguments()
}

pub(crate) fn parse_arguments_for_test<I>(arguments: I) -> Result<BenchmarkArguments, String>
where
    I: IntoIterator<Item = OsString>,
{
    BenchmarkArguments::parse(arguments)
}

#[cfg(test)]
pub(crate) fn link_contract_test_surface() {
    let _ = parse_arguments_for_test::<Vec<OsString>>;
    let _ = parse_process_arguments_for_test::<Vec<OsString>, OsString>;
    let _ = run_fixture_benchmark;
    let _ = validate_proxy_environment_for_test::<Vec<(&'static str, OsString)>>;
    let _ = WorkloadSelection::All;
}

pub(crate) fn write_json_atomically(
    output: &Path,
    report: &EndpointPerformanceReport,
) -> Result<(), String> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create output directory: {error}"))?;
    let encoded = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("could not encode benchmark report: {error}"))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".endpoint-performance-")
        .suffix(".json.tmp")
        .tempfile_in(parent)
        .map_err(|error| format!("could not create temporary report: {error}"))?;
    use std::io::Write as _;
    temporary
        .write_all(&encoded)
        .and_then(|()| temporary.write_all(b"\n"))
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("could not complete temporary report: {error}"))?;
    temporary
        .persist(output)
        .map_err(|error| format!("could not atomically publish report: {}", error.error))?;
    Ok(())
}
