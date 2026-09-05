//! Offline composition of two explicit, bounded report files. The comparison
//! engine receives bytes only; this module has no scanner or network caller.

use std::{
    fmt,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand, ValueEnum};
use termivar_scanner::reporting::comparison::{
    compare_reports, ComparisonError, ComparisonFormat, MAX_COMPARISON_INPUT_BYTES,
};

const MAX_INPUT_BYTES: usize = MAX_COMPARISON_INPUT_BYTES;

#[derive(Subcommand)]
pub(crate) enum ReportCommands {
    /// Compare saved reports; --same-scope is your assertion, not a verified match.
    Compare(ReportCompareArgs),
}

#[derive(Args)]
pub(crate) struct ReportCompareArgs {
    /// Earlier saved assessment JSON. Only an explicit local regular file is accepted.
    #[arg(long, value_name = "FILE")]
    before: PathBuf,
    /// Later saved assessment JSON. Only an explicit local regular file is accepted.
    #[arg(long, value_name = "FILE")]
    after: PathBuf,
    /// Assert that these reports concern comparable scope; this is not machine-verified.
    #[arg(long, required = true)]
    same_scope: bool,
    /// Format of the complete offline comparison.
    #[arg(long, value_enum, default_value_t = CliComparisonFormat::Markdown)]
    format: CliComparisonFormat,
    /// Write atomically to a new local file instead of stdout; never overwrite.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum CliComparisonFormat {
    Markdown,
    Json,
    Html,
}

impl From<CliComparisonFormat> for ComparisonFormat {
    fn from(format: CliComparisonFormat) -> Self {
        match format {
            CliComparisonFormat::Markdown => Self::Markdown,
            CliComparisonFormat::Json => Self::Json,
            CliComparisonFormat::Html => Self::Html,
        }
    }
}

pub(crate) enum ReportCompareError {
    ScopeAssertionRequired,
    ExplicitLocalFileRequired,
    InputUnavailable,
    InputTooLarge,
    InputReadFailed,
    InputOutputCollision,
    OutputUnavailable,
    OutputFailed,
    Comparison(ComparisonError),
}

impl fmt::Display for ReportCompareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ScopeAssertionRequired => {
                "report comparison requires the explicit --same-scope assertion"
            },
            Self::ExplicitLocalFileRequired => {
                "report comparison accepts explicit local file paths only, not URLs or stdin"
            },
            Self::InputUnavailable => {
                "report comparison input is unavailable or is not a regular file"
            },
            Self::InputTooLarge => "report comparison input exceeds the 16 MiB byte limit",
            Self::InputReadFailed => "report comparison input could not be read",
            Self::InputOutputCollision => "report comparison output must not replace either input",
            Self::OutputUnavailable => {
                "report comparison output must name a new file in an existing directory"
            },
            Self::OutputFailed => "report comparison output could not be written",
            Self::Comparison(error) => return fmt::Display::fmt(error, formatter),
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for ReportCompareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReportCompareError {}

pub(crate) fn run(command: ReportCommands) -> Result<(), ReportCompareError> {
    let ReportCommands::Compare(args) = command;
    let rendered = render(&args)?;
    match args.output {
        Some(path) => crate::write_report_atomically(&path, rendered.as_bytes())
            .map_err(|_| ReportCompareError::OutputFailed),
        None => io::stdout()
            .lock()
            .write_all(rendered.as_bytes())
            .map_err(|_| ReportCompareError::OutputFailed),
    }
}

fn render(args: &ReportCompareArgs) -> Result<String, ReportCompareError> {
    if !args.same_scope {
        return Err(ReportCompareError::ScopeAssertionRequired);
    }
    validate_local_path(&args.before)?;
    validate_local_path(&args.after)?;
    if let Some(output) = &args.output {
        validate_local_path(output)?;
        if output == &args.before || output == &args.after {
            return Err(ReportCompareError::InputOutputCollision);
        }
    }
    crate::preflight_report_output(args.output.as_deref())
        .map_err(|_| ReportCompareError::OutputUnavailable)?;
    let before = read_input(&args.before)?;
    let after = read_input(&args.after)?;
    compare_reports(&before, &after, args.format.into()).map_err(ReportCompareError::Comparison)
}

fn validate_local_path(path: &Path) -> Result<(), ReportCompareError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let has_scheme_or_stream = bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b':'
            && !(index == 1
                && bytes[0].is_ascii_alphabetic()
                && matches!(bytes.get(2), Some(b'/' | b'\\')))
    });
    if bytes.is_empty()
        || bytes == b"-"
        || bytes.starts_with(b"//")
        || bytes.starts_with(b"\\\\")
        || bytes.windows(3).any(|window| window == b"://")
        || has_scheme_or_stream
    {
        return Err(ReportCompareError::ExplicitLocalFileRequired);
    }
    Ok(())
}

fn read_input(path: &Path) -> Result<Vec<u8>, ReportCompareError> {
    // Reuse the F6 final-component no-follow/same-handle regular-file boundary.
    // It does not read credentials, initialize a runtime, or validate contents.
    let mut file = crate::auth_input::open_regular_file(path.to_owned())
        .map_err(|_| ReportCompareError::InputUnavailable)?;
    let length = file
        .metadata()
        .map_err(|_| ReportCompareError::InputUnavailable)?
        .len();
    if length > MAX_INPUT_BYTES as u64 {
        return Err(ReportCompareError::InputTooLarge);
    }
    read_bounded(&mut file)
}

fn read_bounded(reader: &mut impl Read) -> Result<Vec<u8>, ReportCompareError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ReportCompareError::InputReadFailed)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ReportCompareError::InputTooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;

    const EMPTY_REPORT: &[u8] = br#"{"schema":"venom-rendered-assessment/v1","source_schema":"venom-assessment-run/v1","run_schema":"venom-run/v1","profile_schema":"venom.scan-profile/v1","profile":"web-review","status":"complete","subject_count":1,"item_count":0,"items":[]}"#;

    fn args(before: PathBuf, after: PathBuf) -> ReportCompareArgs {
        ReportCompareArgs {
            before,
            after,
            same_scope: true,
            format: CliComparisonFormat::Markdown,
            output: None,
        }
    }

    #[test]
    fn parser_requires_two_files_and_the_operator_assertion() {
        for omitted in ["--before", "--after", "--same-scope"] {
            let mut command = vec!["termivar", "report", "compare"];
            if omitted != "--before" {
                command.extend(["--before", "before.json"]);
            }
            if omitted != "--after" {
                command.extend(["--after", "after.json"]);
            }
            if omitted != "--same-scope" {
                command.push("--same-scope");
            }
            assert!(crate::Cli::try_parse_from(command).is_err());
        }
        for format in [None, Some("markdown"), Some("json"), Some("html")] {
            let mut command = vec![
                "termivar",
                "report",
                "compare",
                "--before",
                "before.json",
                "--after",
                "after.json",
                "--same-scope",
            ];
            if let Some(format) = format {
                command.extend(["--format", format]);
            }
            let parsed = crate::Cli::try_parse_from(command).unwrap();
            let Some(crate::Commands::Report {
                command: ReportCommands::Compare(args),
            }) = parsed.command
            else {
                panic!("expected offline comparison command");
            };
            assert!(args.same_scope);
            assert!(args.output.is_none());
            assert_eq!(args.before, Path::new("before.json"));
            assert_eq!(args.after, Path::new("after.json"));
            assert_eq!(
                args.format,
                match format {
                    Some("json") => CliComparisonFormat::Json,
                    Some("html") => CliComparisonFormat::Html,
                    _ => CliComparisonFormat::Markdown,
                }
            );
        }
        for extra in [
            vec!["--format", "csv"],
            vec!["--same-scope=false"],
            vec!["extra.json"],
            vec!["--auth-stdin"],
        ] {
            let mut command = vec![
                "termivar",
                "report",
                "compare",
                "--before",
                "before.json",
                "--after",
                "after.json",
                "--same-scope",
            ];
            command.extend(extra);
            assert!(crate::Cli::try_parse_from(command).is_err());
        }
    }

    #[test]
    fn local_path_validation_rejects_urls_stdin_unc_devices_and_streams() {
        for value in [
            "",
            "-",
            "https://example.test/private.json",
            "h://example.test/private.json",
            "file:/private.json",
            "data:private",
            "//server/share/input.json",
            r"\\server\share\input.json",
            r"\\.\pipe\private",
            r"\\?\C:\private.json",
            r"C:\private.json:stream",
            "C:relative.json",
        ] {
            assert!(matches!(
                validate_local_path(Path::new(value)),
                Err(ReportCompareError::ExplicitLocalFileRequired)
            ));
        }
        for value in [
            "before.json",
            "./before.json",
            "../before.json",
            "/tmp/before.json",
            r"C:\reports\before.json",
            "C:/reports/before.json",
        ] {
            assert!(validate_local_path(Path::new(value)).is_ok());
        }
    }

    #[test]
    fn scope_and_output_preflight_happen_before_input_reads() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("PRIVATE-MISSING.json");
        let mut invocation = args(missing.clone(), missing.clone());
        invocation.same_scope = false;
        assert!(matches!(
            render(&invocation),
            Err(ReportCompareError::ScopeAssertionRequired)
        ));
        invocation.same_scope = true;
        invocation.output = Some(missing);
        assert!(matches!(
            render(&invocation),
            Err(ReportCompareError::InputOutputCollision)
        ));
        let output = directory.path().join("existing.json");
        fs::write(&output, b"preserve").unwrap();
        invocation.output = Some(output.clone());
        assert!(matches!(
            render(&invocation),
            Err(ReportCompareError::OutputUnavailable)
        ));
        assert_eq!(fs::read(output).unwrap(), b"preserve");
        invocation.output = Some(PathBuf::from("https://example.test/output"));
        assert!(matches!(
            render(&invocation),
            Err(ReportCompareError::ExplicitLocalFileRequired)
        ));
    }

    #[test]
    fn file_reader_rejects_missing_directory_and_oversize_inputs() {
        let directory = tempfile::tempdir().unwrap();
        for path in [
            directory.path().to_owned(),
            directory.path().join("PRIVATE-MISSING.json"),
        ] {
            let error = read_input(&path).unwrap_err();
            assert!(matches!(error, ReportCompareError::InputUnavailable));
            assert!(!format!("{error:?}").contains("PRIVATE"));
            assert!(!error.to_string().contains(&path.display().to_string()));
        }
        let oversized = directory.path().join("oversized.json");
        fs::File::create(&oversized)
            .unwrap()
            .set_len((MAX_INPUT_BYTES + 1) as u64)
            .unwrap();
        assert!(matches!(
            read_input(&oversized),
            Err(ReportCompareError::InputTooLarge)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_reader_reuses_final_component_link_rejection() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("before.json");
        let link = directory.path().join("link.json");
        fs::write(&destination, EMPTY_REPORT).unwrap();
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        assert!(matches!(
            read_input(&link),
            Err(ReportCompareError::InputUnavailable)
        ));
        assert_eq!(fs::read(destination).unwrap(), EMPTY_REPORT);
    }

    #[cfg(windows)]
    #[test]
    fn file_reader_reuses_final_component_reparse_rejection_without_symlink_privilege() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("destination");
        let link = directory.path().join("link");
        fs::create_dir(&destination).unwrap();
        let result = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&destination)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(result.success(), "Windows junction fixture creation failed");
        assert!(matches!(
            read_input(&link),
            Err(ReportCompareError::InputUnavailable)
        ));
    }

    struct CountedReader(usize);
    impl Read for CountedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(b'x');
            self.0 += buffer.len();
            Ok(buffer.len())
        }
    }

    struct FailedReader;
    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("PRIVATE-READER-DIAGNOSTIC"))
        }
    }

    #[test]
    fn reader_preserves_exact_bytes_and_never_reads_beyond_one_overflow_byte() {
        let exact = vec![b' '; MAX_INPUT_BYTES];
        assert_eq!(read_bounded(&mut exact.as_slice()).unwrap(), exact);
        let mut unbounded = CountedReader(0);
        assert!(matches!(
            read_bounded(&mut unbounded),
            Err(ReportCompareError::InputTooLarge)
        ));
        assert_eq!(unbounded.0, MAX_INPUT_BYTES + 1);
        let error = read_bounded(&mut FailedReader).unwrap_err();
        assert!(matches!(error, ReportCompareError::InputReadFailed));
        assert!(!error.to_string().contains("PRIVATE"));
        assert_eq!(read_bounded(&mut b" \r\n ".as_slice()).unwrap(), b" \r\n ");
    }

    #[test]
    fn same_file_comparison_stays_synchronous_and_preserves_input() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("same.json");
        let output = directory.path().join("comparison.json");
        fs::write(&input, EMPTY_REPORT).unwrap();
        let mut invocation = args(input.clone(), input.clone());
        invocation.format = CliComparisonFormat::Json;
        invocation.output = Some(output.clone());
        assert!(tokio::runtime::Handle::try_current().is_err());
        run(ReportCommands::Compare(invocation)).unwrap();
        assert!(tokio::runtime::Handle::try_current().is_err());
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(document["schema"], "termivar-report-comparison/v1");
        assert_eq!(document["scope_assurance"], "operator-declared");
        assert_eq!(fs::read(input).unwrap(), EMPTY_REPORT);
    }

    #[test]
    fn malformed_input_returns_no_artifact_or_sensitive_diagnostic() {
        let directory = tempfile::tempdir().unwrap();
        let before = directory.path().join("PRIVATE-before.json");
        let after = directory.path().join("PRIVATE-after.json");
        let output = directory.path().join("comparison.md");
        fs::write(&before, EMPTY_REPORT).unwrap();
        fs::write(&after, b"PRIVATE-DOCUMENT").unwrap();
        let mut invocation = args(before, after);
        invocation.output = Some(output.clone());
        let error = run(ReportCommands::Compare(invocation)).unwrap_err();
        assert!(matches!(error, ReportCompareError::Comparison(_)));
        assert!(!error.to_string().contains("PRIVATE"));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn misplaced_offline_command_is_refused_without_reading_or_comparing() {
        let directory = tempfile::tempdir().unwrap();
        let command = ReportCommands::Compare(args(
            directory.path().join("PRIVATE-missing-before.json"),
            directory.path().join("PRIVATE-missing-after.json"),
        ));
        assert!(tokio::runtime::Handle::try_current().is_err());
        let error =
            crate::run_existing_command(Some(crate::Commands::Report { command })).unwrap_err();
        assert_eq!(
            error.to_string(),
            "offline report commands must be dispatched before runtime initialization"
        );
        assert!(tokio::runtime::Handle::try_current().is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
