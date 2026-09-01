//! Process-level command-line composition for Venom's scanner and optional
//! adapters.
//!
//! ## Runtime scope
//!
//! - **Build:** `venom-cli` binary crate.
//! - **Execution:** `scan` runs the bounded deterministic
//!   `StandardWebDecisionRuntime`. `decision-scan` is a deprecated compatibility
//!   alias to that same command definition and implementation.
//! - **Optional surfaces:** the historical mixed-authority, whole-run-unmetered
//!   runner is available only as `legacy-scan` under `legacy-scanner`;
//!   unsupported API and experimental proxy adapters are separately
//!   feature-gated. The local, explicit-file artifact adapter is available only
//!   under `artifact-adapter` and does not participate in `scan`.
//! - **Support:** all surfaces remain alpha. The default runtime emits
//!   operational decisions and verifier outcomes, not vulnerability findings.
//!
//! See `docs/internals/runtime-map.md`.

#![forbid(unsafe_code)]

#[cfg(feature = "artifact-adapter")]
mod artifact_adapter;
mod assessment_scan;
mod auth_input;
mod decision_scan;

use clap::{Parser, Subcommand, ValueEnum};
use std::{ffi::OsString, path::PathBuf};
use url::Url;
#[cfg(feature = "proxy-adapter")]
use venom_proxy::ProxyServer;
#[cfg(feature = "legacy-scanner")]
use venom_scanner::{
    phases, OutcomeStatus, ResourceAccounting, ResourceAccountingMode, RunStatus, RunStepStatus,
    ScanContext, ScanRunner, SecuritySeverity,
};

/// Output format for deterministic `scan`. `text` is the default human-readable
/// report. Without an explicit profile, `json` preserves the versioned
/// `decision-scan/v1` wire document. Explicit baseline retains the additive
/// `web-assessment/v1` document. Completed web-review runs use the centralized
/// `venom-rendered-assessment/v1` surface; incomplete/failed runs retain a
/// separate `web-assessment/v2` diagnostic audit with items unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum OutputFormat {
    Text,
    Json,
}

/// Additive typed assessment report format. This surface is available only
/// for the explicit `web-review` profile and never changes `decision-scan/v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum CliReportFormat {
    Json,
    Csv,
    Html,
    Markdown,
}

impl From<CliReportFormat> for venom_scanner::ReportFormat {
    fn from(value: CliReportFormat) -> Self {
        match value {
            CliReportFormat::Json => Self::Json,
            CliReportFormat::Csv => Self::Csv,
            CliReportFormat::Html => Self::Html,
            CliReportFormat::Markdown => Self::Markdown,
        }
    }
}

/// Explicit product profile. Absence is a compatibility state that preserves
/// the existing `decision-scan/v1` behavior and output byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum CliScanProfile {
    Baseline,
    WebReview,
}

/// Output format for the opt-in local artifact adapter.
#[cfg(feature = "artifact-adapter")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum ArtifactOutputFormat {
    Text,
    Json,
}

/// Explicit operations in the isolated artifact domain.
#[cfg(feature = "artifact-adapter")]
#[derive(Subcommand)]
enum ArtifactCommands {
    /// Scan one explicitly selected regular file with one signature manifest.
    ScanFile {
        /// Strict `venom.artifact-signatures/v1` manifest to compile.
        #[arg(long, value_name = "SIGNATURES.toml")]
        signatures: PathBuf,
        /// One explicit local regular file. Directories and links are rejected.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        /// Render the bounded observation report as text or JSON.
        #[arg(long, value_enum, default_value_t = ArtifactOutputFormat::Text)]
        format: ArtifactOutputFormat,
    },
}

impl From<CliScanProfile> for venom_scanner::web_runtime::BuiltInScanProfile {
    fn from(value: CliScanProfile) -> Self {
        match value {
            CliScanProfile::Baseline => Self::Baseline,
            CliScanProfile::WebReview => Self::WebReview,
        }
    }
}

/// True when `--format json` is combined with `--explain` — an ambiguous
/// combination rejected fail-fast, because the JSON document already carries the
/// full diagnostics `--explain` adds to the text report.
fn scan_flags_conflict(format: OutputFormat, explain: bool) -> bool {
    matches!(format, OutputFormat::Json) && explain
}

/// Returns a stable argument error for profile-specific combinations. This is
/// evaluated before the runtime warning, output, or network construction.
fn scan_profile_flags_conflict(
    profile: Option<CliScanProfile>,
    explain: bool,
    enforce_defense: bool,
) -> Option<&'static str> {
    if profile.is_some() && explain {
        Some("`--explain` is available only when no explicit `--profile` is selected")
    } else if enforce_defense && profile != Some(CliScanProfile::WebReview) {
        Some("`--enforce-defense` requires `--profile web-review`")
    } else {
        None
    }
}

fn scan_report_flags_conflict(
    profile: Option<CliScanProfile>,
    report_format: Option<CliReportFormat>,
    report_output: Option<&std::path::Path>,
) -> Option<&'static str> {
    if report_output.is_some() && report_format.is_none() {
        Some("`--report-output` requires `--report-format`")
    } else if report_format.is_some() && profile != Some(CliScanProfile::WebReview) {
        Some("`--report-format` requires `--profile web-review`")
    } else {
        None
    }
}

fn scan_authorization_flags_conflict(
    profile: Option<CliScanProfile>,
    authorization_source_selected: bool,
) -> Option<&'static str> {
    if authorization_source_selected && profile != Some(CliScanProfile::WebReview) {
        Some("authorization-context input requires `--profile web-review`")
    } else {
        None
    }
}

fn is_exact_origin_root(target: &Url) -> bool {
    matches!(target.scheme(), "http" | "https")
        && target.username().is_empty()
        && target.password().is_none()
        && target.host().is_some()
        && target.path() == "/"
        && target.query().is_none()
        && target.fragment().is_none()
}

fn authorization_context_transport_is_allowed(target: &Url) -> bool {
    target.scheme() == "https"
        || (target.scheme() == "http"
            && target.host().is_some_and(|host| {
                matches!(host, url::Host::Ipv4(ip) if ip.is_loopback())
                    || matches!(host, url::Host::Ipv6(ip) if ip.is_loopback())
            }))
}

#[cfg(feature = "legacy-scanner")]
const LEGACY_DIRECTORY_FUZZ_WARNING: &str = "[WARNING] Legacy directory discovery is enabled. This wordlist phase uses the bounded exact-origin discovery broker, but still increases request volume; run it only against explicitly authorized targets.";
#[cfg(feature = "legacy-scanner")]
const LEGACY_SCAN_RUNTIME_WARNING: &str = "[WARNING] The ordered CLI phase pipeline remains outside StandardWebDecisionRuntime. Phases 2-4 use bounded passive discovery and phases 5-9 use a separate bounded active-verification authority, but the complete legacy run remains Unmetered because phase 1 and custom extensions can retain direct I/O. Use it only against an explicitly authorized exact origin.";
const DETERMINISTIC_SCAN_WARNING: &str = "[ALPHA] Running the bounded deterministic decision runtime. Use only against an exact origin you own or are explicitly authorized to test.";

#[cfg(feature = "legacy-scanner")]
fn scan_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[derive(Parser)]
#[command(name = "venom")]
#[command(about = "Venom - bounded evidence-driven web security runtime", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the bounded deterministic scanner against an authorized origin.
    #[command(visible_alias = "decision-scan")]
    Scan {
        /// Authorized HTTP(S) target origin. Only scan targets you own or may test.
        target: Url,
        /// Output format. `text` (default) is the human-readable report; `json` is
        /// the versioned machine-readable document with full diagnostics.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Print the full explainable decision chain (hypotheses, planned/excluded
        /// actions with reasons, dispatched actions, outcomes). Text format only —
        /// `--format json` already contains full diagnostics. Off by default; the
        /// default text output is unchanged.
        #[arg(long)]
        explain: bool,
        /// Select an explicit versioned product profile. With no profile, the
        /// existing conservative single-resource command and wire schema remain
        /// unchanged.
        #[arg(long, value_enum)]
        profile: Option<CliScanProfile>,
        /// Apply monotonic defense suppression. Valid only with
        /// `--profile web-review`; observation and shadow planning remain enabled
        /// without this flag.
        #[arg(long, requires = "profile")]
        enforce_defense: bool,
        /// Select the centralized typed assessment renderer. Valid only with
        /// `--profile web-review`. Without this option, text maps to Markdown
        /// and JSON maps to JSON for completed web-review reports.
        #[arg(long, value_enum, requires = "profile")]
        report_format: Option<CliReportFormat>,
        /// Atomically create a new report file instead of writing a completed
        /// report to stdout. Existing files are never overwritten. Incomplete
        /// or started-failure runs emit their typed diagnostic audit to stdout.
        /// Publication requires same-directory hard-link support and does not
        /// promise crash-durable directory metadata.
        #[arg(long, requires = "report_format")]
        report_output: Option<PathBuf>,
        /// Read the complete authorized-root `Authorization` header value from
        /// this environment variable. The variable name and value are redacted.
        #[arg(
            long,
            value_name = "ENV_VAR",
            requires = "profile",
            conflicts_with_all = ["auth_file", "auth_stdin"]
        )]
        auth_env: Option<OsString>,
        /// Read the complete authorized-root `Authorization` header value from
        /// a bounded file. The path and value are redacted.
        #[arg(
            long,
            value_name = "PATH",
            requires = "profile",
            conflicts_with_all = ["auth_env", "auth_stdin"]
        )]
        auth_file: Option<PathBuf>,
        /// Read the complete authorized-root `Authorization` header value from
        /// standard input through EOF. At most one terminal LF or CRLF is removed.
        #[arg(
            long,
            requires = "profile",
            conflicts_with_all = ["auth_env", "auth_file"]
        )]
        auth_stdin: bool,
    },
    /// Run the historical mixed-authority, whole-run-unmetered heuristic pipeline.
    #[cfg(feature = "legacy-scanner")]
    LegacyScan {
        /// Authorized HTTP(S) target origin. Only scan targets you own or may test.
        target: Url,
        /// Required acknowledgement that results are partial heuristic
        /// observations, not verifier-backed vulnerability confirmations.
        #[arg(long, required = true)]
        acknowledge_legacy_heuristics: bool,
        /// Opt in to bounded, calibrated wordlist directory discovery.
        #[arg(long)]
        legacy_directory_fuzz: bool,
    },
    /// Report that the unsupported API listener adapter is unavailable.
    #[cfg(feature = "api-adapter")]
    Api {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: std::net::SocketAddr,
    },
    /// Start the experimental fixed-upstream TCP relay.
    #[cfg(feature = "proxy-adapter")]
    Proxy {
        /// Local socket on which the relay accepts connections.
        #[arg(long, default_value = "127.0.0.1:8081")]
        addr: std::net::SocketAddr,
        /// Explicit fixed upstream socket. No implicit destination is used.
        #[arg(long)]
        upstream: std::net::SocketAddr,
    },
    /// Run an opt-in bounded signature scan of one explicit local file.
    #[cfg(feature = "artifact-adapter")]
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommands,
    },
}

struct DeterministicScanInvocation {
    target: Url,
    format: OutputFormat,
    explain: bool,
    profile: Option<CliScanProfile>,
    enforce_defense: bool,
    report_format: Option<CliReportFormat>,
    report_output: Option<PathBuf>,
    auth_env: Option<OsString>,
    auth_file: Option<PathBuf>,
    auth_stdin: bool,
}

async fn run_deterministic_scan(
    invocation: DeterministicScanInvocation,
) -> Result<(), Box<dyn std::error::Error>> {
    let DeterministicScanInvocation {
        target,
        format,
        explain,
        profile,
        enforce_defense,
        report_format,
        report_output,
        auth_env,
        auth_file,
        auth_stdin,
    } = invocation;
    if scan_flags_conflict(format, explain) {
        use clap::CommandFactory;
        Cli::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                "`--explain` applies only to `--format text`; `--format json` already includes full diagnostics",
            )
            .exit();
    }
    if let Some(message) = scan_profile_flags_conflict(profile, explain, enforce_defense) {
        use clap::CommandFactory;
        Cli::command()
            .error(clap::error::ErrorKind::ArgumentConflict, message)
            .exit();
    }
    if let Some(message) =
        scan_report_flags_conflict(profile, report_format, report_output.as_deref())
    {
        use clap::CommandFactory;
        Cli::command()
            .error(clap::error::ErrorKind::ArgumentConflict, message)
            .exit();
    }
    let authorization_source =
        auth_input::AuthorizationInputSource::select(auth_env, auth_file, auth_stdin)?;
    if let Some(message) =
        scan_authorization_flags_conflict(profile, authorization_source.is_some())
    {
        use clap::CommandFactory;
        Cli::command()
            .error(clap::error::ErrorKind::ArgumentConflict, message)
            .exit();
    }
    if authorization_source.is_some() && !is_exact_origin_root(&target) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "authorization-context review requires an exact origin root target",
        )
        .into());
    }
    if authorization_source.is_some() && !authorization_context_transport_is_allowed(&target) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "authorization-context review requires HTTPS; numeric loopback HTTP is allowed only for local fixtures",
        )
        .into());
    }

    if let Some(selected_profile) = profile {
        let mut profile =
            venom_scanner::web_runtime::ScanProfileV1::for_builtin(selected_profile.into())?;
        if enforce_defense {
            profile = profile.with_defense_enforcement_enabled(true)?;
        }
        preflight_report_output(report_output.as_deref())?;
        // All flag, profile, target, and obvious report-output checks above
        // precede the only secret source read in the CLI.
        let root_authorization_context = authorization_source
            .map(auth_input::AuthorizationInputSource::load)
            .transpose()?;

        eprintln!("{DETERMINISTIC_SCAN_WARNING}");
        let execution = assessment_scan::run_profile_scan(
            target,
            profile,
            matches!(format, OutputFormat::Json),
            report_format.map(Into::into),
            report_output.is_some(),
            root_authorization_context,
        )
        .await?;
        let (rendered, report_artifact, post_render_failure) = execution.into_parts();
        if !rendered.is_empty() {
            use std::io::Write as _;
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            output.write_all(rendered.as_bytes())?;
            output.flush()?;
        }
        if let Some(artifact) = report_artifact {
            let output = report_output.as_deref().ok_or_else(|| {
                std::io::Error::other("report artifact has no authorized output path")
            })?;
            write_report_atomically(output, artifact.as_bytes())?;
        }
        if let Some(failure) = post_render_failure {
            return Err(std::io::Error::other(failure.message()).into());
        }
        return Ok(());
    }

    eprintln!("{DETERMINISTIC_SCAN_WARNING}");
    let summary = decision_scan::run_decision_scan(target).await?;
    match format {
        OutputFormat::Text => {
            let rendered = if explain {
                decision_scan::render_explain(&summary)
            } else {
                decision_scan::render_summary(&summary)
            };
            print!("{rendered}");
        },
        OutputFormat::Json => {
            println!("{}", decision_scan::render_json(&summary)?);
        },
    }
    Ok(())
}

fn preflight_report_output(path: Option<&std::path::Path>) -> std::io::Result<()> {
    use std::fs;

    let Some(path) = path else {
        return Ok(());
    };
    if path.file_name().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "report output must name a file",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "report output already exists",
            ));
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                "report output state could not be inspected",
            ));
        },
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let metadata = fs::metadata(parent).map_err(|error| {
        std::io::Error::new(error.kind(), "report output parent is unavailable")
    })?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "report output parent must be a directory",
        ));
    }
    Ok(())
}

fn write_report_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    if bytes.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to create an empty report",
        ));
    }
    preflight_report_output(Some(path))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));

    let mut last_collision = None;
    for _ in 0..32 {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".venom-report-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
                continue;
            },
            Err(error) => return Err(error),
        };
        let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::hard_link(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        fs::remove_file(&temporary)?;
        return Ok(());
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve a temporary report path",
        )
    }))
}

#[cfg(feature = "legacy-scanner")]
async fn run_legacy_scan(
    target: Url,
    acknowledge_legacy_heuristics: bool,
    legacy_directory_fuzz: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !acknowledge_legacy_heuristics {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "legacy-scan requires --acknowledge-legacy-heuristics",
        )
        .into());
    }

    eprintln!("{LEGACY_SCAN_RUNTIME_WARNING}");
    let client = scan_http_client()?;
    // Legacy phase prose is untrusted claim material. Drop the receiver so only
    // the typed report below crosses the CLI boundary.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    drop(rx);
    let ctx = ScanContext::new(target, client, tx);

    let mut runner = ScanRunner::new();
    runner.register_phase(Box::new(phases::ReconPhase));
    runner.register_phase(Box::new(phases::CrawlPhase));
    if legacy_directory_fuzz {
        eprintln!("{LEGACY_DIRECTORY_FUZZ_WARNING}");
        runner.register_phase(Box::new(
            phases::DirectoryFuzzer::with_default_wordlist_sequential(),
        ));
    }
    runner.register_phase(Box::new(
        phases::ParameterDiscoverer::with_default_wordlist_sequential(),
    ));
    runner.register_phase(Box::new(phases::SqliScanner));
    runner.register_phase(Box::new(phases::XssScanner));
    runner.register_phase(Box::new(phases::SstiScanner));
    runner.register_phase(Box::new(phases::LfiXxeScanner::new()));
    runner.register_phase(Box::new(phases::SsrfScanner::new()));

    let report = runner.run_pipeline(ctx).await?;
    println!("\n== legacy-scan typed report ==");
    println!("schema={}", report.schema());
    println!("status={}", legacy_run_status(report.status()));
    println!("stop_code={:?}", report.stop_reason().code());
    println!("stop_detail={}", report.stop_reason().detail());
    println!("target={}", report.target());
    println!("authorized_origin={}", report.authorized_origin());
    println!("started_at={}", report.started_at().to_rfc3339());
    println!("completed_at={}", report.completed_at().to_rfc3339());
    println!(
        "accounting requests={} response_body_bytes={} request_body_bytes={} wall_time_ms={}",
        legacy_accounting(report.accounting().requests()),
        legacy_accounting(report.accounting().response_body_bytes()),
        legacy_accounting(report.accounting().request_body_bytes()),
        legacy_accounting(report.accounting().wall_time_ms()),
    );
    for step in report.steps() {
        println!(
            "step ordinal={} action={} status={} duration_ms={}",
            step.ordinal(),
            step.action_id(),
            legacy_step_status(step.status()),
            step.duration_ms(),
        );
    }
    for outcome in report.outcomes() {
        println!(
            "outcome id={} subject={} action={} severity={} disposition={} confidence_parts_per_million={} evidence_ids={} rationale={} summary={}",
            outcome.fingerprint(),
            outcome.subject(),
            outcome.action_id(),
            legacy_severity(outcome.severity()),
            legacy_disposition(outcome.disposition()),
            outcome.confidence().parts_per_million(),
            outcome.evidence_ids().len(),
            outcome.rationale(),
            outcome.redacted_summary(),
        );
    }
    println!("[*] Legacy records are unresolved observations, not verifier-backed findings.");

    if !matches!(report.status(), RunStatus::Complete) {
        Err(std::io::Error::other("legacy scan did not complete").into())
    } else {
        Ok(())
    }
}

#[cfg(feature = "legacy-scanner")]
fn legacy_run_status(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Complete => "complete",
        RunStatus::Partial => "partial",
        RunStatus::Cancelled => "cancelled",
        RunStatus::Failed => "failed",
        _ => "unknown",
    }
}

#[cfg(feature = "legacy-scanner")]
fn legacy_step_status(status: RunStepStatus) -> &'static str {
    match status {
        RunStepStatus::Succeeded => "succeeded",
        RunStepStatus::Failed => "failed",
        RunStepStatus::TimedOut => "timed_out",
        RunStepStatus::Cancelled => "cancelled",
        RunStepStatus::Skipped => "skipped",
        RunStepStatus::BudgetExhausted => "budget_exhausted",
        _ => "unknown",
    }
}

#[cfg(feature = "legacy-scanner")]
fn legacy_accounting(accounting: &ResourceAccounting) -> String {
    match accounting.mode() {
        ResourceAccountingMode::Metered => format!(
            "metered(limit={},consumed={},remaining={})",
            legacy_optional_count(accounting.limit()),
            legacy_optional_count(accounting.consumed()),
            legacy_optional_count(accounting.remaining()),
        ),
        ResourceAccountingMode::Observed => {
            format!(
                "observed(consumed={})",
                legacy_optional_count(accounting.consumed())
            )
        },
        ResourceAccountingMode::Unmetered => "unmetered".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(feature = "legacy-scanner")]
fn legacy_optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_string(), |value| value.to_string())
}

#[cfg(feature = "legacy-scanner")]
fn legacy_severity(severity: SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Info => "info",
        SecuritySeverity::Low => "low",
        SecuritySeverity::Medium => "medium",
        SecuritySeverity::High => "high",
        SecuritySeverity::Critical => "critical",
        _ => "unknown",
    }
}

#[cfg(feature = "legacy-scanner")]
fn legacy_disposition(disposition: OutcomeStatus) -> &'static str {
    match disposition {
        OutcomeStatus::Success => "success",
        OutcomeStatus::Blocked => "blocked",
        OutcomeStatus::Unknown => "unknown",
        OutcomeStatus::FalsePositive => "false_positive",
        OutcomeStatus::NeedsReview => "needs_review",
        OutcomeStatus::ConfirmedNegative => "confirmed_negative",
        _ => "unknown",
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan {
            target,
            format,
            explain,
            profile,
            enforce_defense,
            report_format,
            report_output,
            auth_env,
            auth_file,
            auth_stdin,
        }) => {
            run_deterministic_scan(DeterministicScanInvocation {
                target,
                format,
                explain,
                profile,
                enforce_defense,
                report_format,
                report_output,
                auth_env,
                auth_file,
                auth_stdin,
            })
            .await?;
        },
        #[cfg(feature = "legacy-scanner")]
        Some(Commands::LegacyScan {
            target,
            acknowledge_legacy_heuristics,
            legacy_directory_fuzz,
        }) => {
            run_legacy_scan(target, acknowledge_legacy_heuristics, legacy_directory_fuzz).await?;
        },
        #[cfg(feature = "api-adapter")]
        Some(Commands::Api { addr }) => {
            venom_api::start_api(&addr.to_string()).await?;
        },
        #[cfg(feature = "proxy-adapter")]
        Some(Commands::Proxy { addr, upstream }) => {
            ProxyServer::new(addr, upstream).start().await?;
        },
        #[cfg(feature = "artifact-adapter")]
        Some(Commands::Artifact {
            command:
                ArtifactCommands::ScanFile {
                    signatures,
                    input,
                    format,
                },
        }) => {
            artifact_adapter::scan_file(&signatures, &input, format)?;
        },
        None => {
            println!("Venom v{}", env!("CARGO_PKG_VERSION"));
            println!("Use --help for more information");
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn scan_selects_the_deterministic_command() {
        let cli = Cli::try_parse_from(["venom", "scan", "https://example.test"]).unwrap();
        match cli.command {
            Some(Commands::Scan {
                target,
                format,
                explain,
                profile,
                enforce_defense,
                report_format,
                report_output,
                auth_env,
                auth_file,
                auth_stdin,
            }) => {
                assert_eq!(target.as_str(), "https://example.test/");
                assert_eq!(format, OutputFormat::Text);
                assert!(!explain);
                assert_eq!(profile, None);
                assert!(!enforce_defense);
                assert_eq!(report_format, None);
                assert_eq!(report_output, None);
                assert_eq!(auth_env, None);
                assert_eq!(auth_file, None);
                assert!(!auth_stdin);
            },
            _ => panic!("expected the deterministic scan command"),
        }
        assert!(DETERMINISTIC_SCAN_WARNING.contains("bounded deterministic"));
    }

    #[test]
    fn decision_scan_is_an_alias_to_the_same_command_variant() {
        let cli = Cli::try_parse_from(["venom", "decision-scan", "https://example.test/"]).unwrap();
        match cli.command {
            Some(Commands::Scan {
                target,
                format,
                explain,
                profile,
                enforce_defense,
                report_format,
                report_output,
                auth_env,
                auth_file,
                auth_stdin,
            }) => {
                assert_eq!(target.as_str(), "https://example.test/");
                assert_eq!(format, OutputFormat::Text, "text is the default format");
                assert!(
                    !explain,
                    "explain must default off so the default output is unchanged"
                );
                assert_eq!(profile, None);
                assert!(!enforce_defense);
                assert_eq!(report_format, None);
                assert_eq!(report_output, None);
                assert_eq!(auth_env, None);
                assert_eq!(auth_file, None);
                assert!(!auth_stdin);
            },
            _ => panic!("expected the deterministic scan command"),
        }
    }

    #[test]
    fn scan_and_compatibility_alias_accept_the_same_json_format() {
        let primary =
            Cli::try_parse_from(["venom", "scan", "--format", "json", "https://example.test/"])
                .unwrap();
        let cli = Cli::try_parse_from([
            "venom",
            "decision-scan",
            "--format",
            "json",
            "https://example.test/",
        ])
        .unwrap();
        assert!(matches!(
            primary.command,
            Some(Commands::Scan {
                format: OutputFormat::Json,
                ..
            })
        ));
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                format: OutputFormat::Json,
                ..
            })
        ));
    }

    #[test]
    fn scan_rejects_json_with_explain() {
        // The combination is ambiguous — JSON already contains full diagnostics —
        // and is rejected fail-fast.
        assert!(scan_flags_conflict(OutputFormat::Json, true));
        assert!(!scan_flags_conflict(OutputFormat::Json, false));
        assert!(!scan_flags_conflict(OutputFormat::Text, true));
        assert!(!scan_flags_conflict(OutputFormat::Text, false));
    }

    #[test]
    fn scan_accepts_the_explain_flag() {
        let cli =
            Cli::try_parse_from(["venom", "scan", "--explain", "https://example.test/"]).unwrap();
        match cli.command {
            Some(Commands::Scan { explain, .. }) => {
                assert!(explain, "--explain must enable the explain view");
            },
            _ => panic!("expected the deterministic scan command"),
        }
    }

    #[test]
    fn scan_profiles_are_explicit_exact_and_shared_by_both_spellings() {
        for command in ["scan", "decision-scan"] {
            let baseline = Cli::try_parse_from([
                "venom",
                command,
                "--profile",
                "baseline",
                "https://example.test/",
            ])
            .unwrap();
            assert!(matches!(
                baseline.command,
                Some(Commands::Scan {
                    profile: Some(CliScanProfile::Baseline),
                    enforce_defense: false,
                    ..
                })
            ));

            let review = Cli::try_parse_from([
                "venom",
                command,
                "--profile",
                "web-review",
                "--enforce-defense",
                "https://example.test/",
            ])
            .unwrap();
            assert!(matches!(
                review.command,
                Some(Commands::Scan {
                    profile: Some(CliScanProfile::WebReview),
                    enforce_defense: true,
                    ..
                })
            ));
        }

        for rejected in [
            "Baseline",
            " baseline",
            "web_review",
            "enterprise",
            "cloud",
            "aggressive",
            "stealth",
        ] {
            assert!(Cli::try_parse_from([
                "venom",
                "scan",
                "--profile",
                rejected,
                "https://example.test/",
            ])
            .is_err());
        }
    }

    #[test]
    fn profile_conflicts_fail_before_runtime_dispatch() {
        assert!(Cli::try_parse_from([
            "venom",
            "scan",
            "--enforce-defense",
            "https://example.test/",
        ])
        .is_err());
        assert_eq!(
            scan_profile_flags_conflict(Some(CliScanProfile::Baseline), false, true),
            Some("`--enforce-defense` requires `--profile web-review`")
        );
        assert_eq!(
            scan_profile_flags_conflict(Some(CliScanProfile::WebReview), false, true),
            None
        );
        assert!(scan_profile_flags_conflict(Some(CliScanProfile::Baseline), true, false).is_some());
        assert!(
            scan_profile_flags_conflict(Some(CliScanProfile::WebReview), true, false).is_some()
        );
        assert_eq!(scan_profile_flags_conflict(None, false, false), None);
    }

    #[test]
    fn authorization_transport_matches_the_scanner_fixture_boundary() {
        assert!(authorization_context_transport_is_allowed(
            &Url::parse("https://example.test/").unwrap()
        ));
        assert!(authorization_context_transport_is_allowed(
            &Url::parse("http://127.0.0.1/").unwrap()
        ));
        assert!(authorization_context_transport_is_allowed(
            &Url::parse("http://[::1]/").unwrap()
        ));
        assert!(!authorization_context_transport_is_allowed(
            &Url::parse("http://localhost/").unwrap()
        ));
    }

    #[test]
    fn assessment_report_flags_are_explicit_and_web_review_only() {
        let cli = Cli::try_parse_from([
            "venom",
            "scan",
            "--profile",
            "web-review",
            "--report-format",
            "html",
            "--report-output",
            "review.html",
            "https://example.test/",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                profile: Some(CliScanProfile::WebReview),
                report_format: Some(CliReportFormat::Html),
                report_output: Some(_),
                ..
            })
        ));
        assert_eq!(
            scan_report_flags_conflict(
                Some(CliScanProfile::Baseline),
                Some(CliReportFormat::Json),
                None,
            ),
            Some("`--report-format` requires `--profile web-review`")
        );
        assert_eq!(
            scan_report_flags_conflict(
                Some(CliScanProfile::WebReview),
                None,
                Some(std::path::Path::new("review.json")),
            ),
            Some("`--report-output` requires `--report-format`")
        );
        assert_eq!(
            scan_report_flags_conflict(
                Some(CliScanProfile::WebReview),
                Some(CliReportFormat::Markdown),
                None,
            ),
            None
        );
        assert!(Cli::try_parse_from([
            "venom",
            "scan",
            "--report-output",
            "review.json",
            "https://example.test/",
        ])
        .is_err());
    }

    #[test]
    fn atomic_report_output_is_complete_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        write_report_atomically(&path, br#"{"schema":"test"}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"schema":"test"}"#);
        let error = write_report_atomically(&path, b"replacement").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"schema":"test"}"#);
    }

    #[test]
    fn both_scan_spellings_require_a_target() {
        assert!(Cli::try_parse_from(["venom", "scan"]).is_err());
        assert!(Cli::try_parse_from(["venom", "decision-scan"]).is_err());
    }

    #[test]
    fn both_scan_spellings_reject_a_malformed_url() {
        assert!(Cli::try_parse_from(["venom", "scan", "not a url"]).is_err());
        assert!(Cli::try_parse_from(["venom", "decision-scan", "not a url"]).is_err());
    }

    #[test]
    #[cfg(not(feature = "legacy-scanner"))]
    fn default_cli_has_no_legacy_command() {
        assert!(Cli::try_parse_from(["venom", "legacy-scan"]).is_err());
    }

    #[test]
    #[cfg(not(feature = "api-adapter"))]
    fn default_cli_has_no_api_command() {
        assert!(Cli::try_parse_from(["venom", "api"]).is_err());
    }

    #[test]
    #[cfg(not(feature = "proxy-adapter"))]
    fn default_cli_has_no_proxy_command() {
        assert!(Cli::try_parse_from(["venom", "proxy"]).is_err());
    }

    #[test]
    #[cfg(not(feature = "artifact-adapter"))]
    fn default_cli_has_no_artifact_command() {
        assert!(Cli::try_parse_from(["venom", "artifact"]).is_err());
    }

    #[test]
    #[cfg(feature = "artifact-adapter")]
    fn artifact_scan_file_requires_explicit_paths_and_has_a_closed_format() {
        let cli = Cli::try_parse_from([
            "venom",
            "artifact",
            "scan-file",
            "--signatures",
            "signatures.toml",
            "--input",
            "artifact.bin",
            "--format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Artifact {
                command: ArtifactCommands::ScanFile {
                    signatures,
                    input,
                    format: ArtifactOutputFormat::Json,
                },
            }) if signatures == PathBuf::from("signatures.toml")
                && input == PathBuf::from("artifact.bin")
        ));

        assert!(Cli::try_parse_from(["venom", "artifact", "scan-file"]).is_err());
        assert!(Cli::try_parse_from([
            "venom",
            "artifact",
            "scan-file",
            "--signatures",
            "signatures.toml",
            "--input",
            "artifact.bin",
            "--format",
            "yaml",
        ])
        .is_err());
    }

    #[test]
    #[cfg(feature = "legacy-scanner")]
    fn legacy_scan_requires_acknowledgement_and_keeps_directory_fuzz_separate() {
        assert!(Cli::try_parse_from(["venom", "legacy-scan", "https://example.test"]).is_err());
        let cli = Cli::try_parse_from([
            "venom",
            "legacy-scan",
            "https://example.test",
            "--acknowledge-legacy-heuristics",
            "--legacy-directory-fuzz",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::LegacyScan {
                acknowledge_legacy_heuristics: true,
                legacy_directory_fuzz: true,
                ..
            })
        ));
        assert!(LEGACY_SCAN_RUNTIME_WARNING.contains("outside StandardWebDecisionRuntime"));
        assert!(LEGACY_SCAN_RUNTIME_WARNING.contains("complete legacy run remains Unmetered"));
        assert!(LEGACY_DIRECTORY_FUZZ_WARNING.contains("bounded exact-origin discovery broker"));
        assert!(LEGACY_DIRECTORY_FUZZ_WARNING.contains("increases request volume"));
        assert!(!LEGACY_DIRECTORY_FUZZ_WARNING.contains("outside RuntimeBudget"));
    }

    #[tokio::test]
    #[cfg(feature = "legacy-scanner")]
    async fn legacy_scan_client_never_follows_cross_origin_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/outside\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let response = scan_http_client()
            .unwrap()
            .get(format!("http://{address}/authorized"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.unwrap();
    }

    #[test]
    #[cfg(feature = "api-adapter")]
    fn api_adapter_uses_socket_addr_and_accepts_ipv6() {
        let cli = Cli::try_parse_from(["venom", "api", "--addr", "[::1]:8080"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Api { addr }) if addr == "[::1]:8080".parse().unwrap()
        ));
        assert!(Cli::try_parse_from(["venom", "api", "--addr", "invalid"]).is_err());
    }

    #[test]
    #[cfg(feature = "proxy-adapter")]
    fn proxy_adapter_uses_socket_addr_and_accepts_ipv6() {
        let cli = Cli::try_parse_from([
            "venom",
            "proxy",
            "--addr",
            "[::1]:8081",
            "--upstream",
            "[::1]:9081",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Proxy { addr, upstream })
                if addr == "[::1]:8081".parse().unwrap()
                    && upstream == "[::1]:9081".parse().unwrap()
        ));
        assert!(Cli::try_parse_from([
            "venom",
            "proxy",
            "--addr",
            "invalid",
            "--upstream",
            "127.0.0.1:9081",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["venom", "proxy", "--addr", "127.0.0.1:8081"]).is_err());
    }

    // --- offline end-to-end preview run --------------------------------------

    /// Serve one fixed HTTP/1.1 response to every connection until aborted.
    async fn serve_static() -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), handle)
    }

    #[tokio::test]
    async fn decision_scan_preview_runs_bounded_against_a_local_server() {
        let (target, server) = serve_static().await;

        let summary = decision_scan::run_decision_scan(target.clone())
            .await
            .expect("decision preview should complete against the local server");

        // Bootstrap committed evidence, and the run was bounded by the budget.
        assert!(
            summary.bootstrap_writes >= 1,
            "expected at least one bootstrap evidence write"
        );
        assert!(
            summary.total_requests > 0,
            "the runtime should make requests"
        );
        assert!(
            summary.total_requests <= u64::from(decision_scan::PREVIEW_MAX_TOTAL_REQUESTS),
            "the runtime must respect the 16-request budget"
        );
        // The summary retains the authorized input origin. Exact-origin request
        // enforcement (scheme, credentials, allowed origin) is covered by the
        // existing HttpEvidencePolicy/broker tests, not re-proved here.
        assert_eq!(summary.target, target.origin().ascii_serialization());
        // A terminal (bounded stop) state is always reported.
        assert!(!summary.terminal.is_empty());

        server.abort();
    }

    #[tokio::test]
    async fn decision_scan_preview_is_deterministic_excluding_elapsed_time() {
        // Two fresh runtimes against the *same* listener and target: only the
        // wall-clock (elapsed) field may differ.
        let (target, server) = serve_static().await;
        let mut first = decision_scan::run_decision_scan(target.clone())
            .await
            .unwrap();
        let mut second = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        first.elapsed_ms = 0;
        second.elapsed_ms = 0;
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn decision_scan_rejects_non_http_scheme_before_dispatch() {
        // The HttpEvidencePolicy contract rejects a non-HTTP(S) origin; no network
        // dispatch occurs.
        let target = Url::parse("ftp://example.test/").unwrap();
        let result = decision_scan::run_decision_scan(target).await;
        assert!(
            result.is_err(),
            "a non-http(s) scheme must be rejected before any dispatch"
        );
    }

    fn sample_summary() -> decision_scan::DecisionScanSummary {
        decision_scan::DecisionScanSummary {
            target: "https://example.test".to_string(),
            bootstrap_writes: 1,
            planning_turns: 1,
            verification_outcomes: 1,
            conclusive_outcomes: 0,
            inconclusive_outcomes: 1,
            outcomes: vec![decision_scan::OutcomeView {
                action_id: "web.action.probe".to_string(),
                status: "unknown",
                conclusive: false,
            }],
            terminal: "halt",
            stop_reason: Some("no_eligible_action"),
            total_requests: 3,
            active_verifications: 1,
            response_bytes: 42,
            elapsed_ms: 5,
            limit_exceeded: None,
            limit_exceeded_text: None,
            experience_records: 1,
            hypotheses: vec![decision_scan::HypothesisView {
                predicate: "technology.framework".to_string(),
                value: Some("laravel".to_string()),
                value_kind: "text",
                value_disposition: "exposed",
                strength: "weak",
                posterior_basis_points: 8900,
                posterior_percent: 89,
                state: "supported",
            }],
            planning: vec![decision_scan::PlanningView {
                eligible: Vec::new(),
                excluded: vec![(
                    "web.action.laravel.input-analysis".to_string(),
                    "policy_suppressed",
                )],
            }],
            dispatched: vec![decision_scan::DispatchView {
                sequence: 0,
                action_id: "web.action.bootstrap".to_string(),
                stage: "passive",
                origin: Some("bootstrap"),
            }],
            unavailable_routes: vec!["web.action.laravel.input-analysis".to_string()],
        }
    }

    #[test]
    fn render_summary_is_stable_and_never_labels_vulnerabilities() {
        let rendered = decision_scan::render_summary(&sample_summary());
        assert!(rendered.contains("engine: decision-preview"));
        assert!(rendered.contains("target origin: https://example.test"));
        assert!(rendered.contains("verification outcomes: 1"));
        assert!(rendered.contains("terminal: halt"));
        assert!(rendered.contains("stop_reason: no_eligible_action"));
        assert!(rendered.contains("usage: requests=3"));
        // The default summary does not include the explain section.
        assert!(!rendered.contains("-- explain --"));
        // The user surface never labels an outcome a vulnerability, and never
        // leaks a Debug dump of internal runtime types.
        assert!(!rendered.to_lowercase().contains("vulnerabilit"));
        assert!(!rendered.contains("VerificationCase {"));
    }

    #[test]
    fn render_explain_extends_the_summary_with_the_full_chain() {
        let rendered = decision_scan::render_explain(&sample_summary());
        // It is a strict superset of the default summary.
        assert!(rendered.starts_with(&decision_scan::render_summary(&sample_summary())));
        assert!(rendered.contains("-- explain --"));
        // Executor Routes: only the runtime's explicit unavailable routes, counted.
        assert!(rendered.contains("Executor Routes"));
        assert!(rendered.contains("  Unavailable (1)"));
        assert!(rendered.contains("    • web.action.laravel.input-analysis\n"));
        // No synthesized "available" list.
        assert!(!rendered.contains("Available"));
        // Hierarchical hypotheses with aligned, stable labels.
        assert!(rendered.contains("Hypotheses (1)"));
        assert!(rendered.contains("  technology.framework=laravel"));
        assert!(rendered.contains("strength : weak"));
        assert!(rendered.contains("posterior: 89%"));
        assert!(rendered.contains("state    : supported"));
        // Planning turn with counted sections and one-line excluded entries.
        assert!(rendered.contains("Planning (turn 0)"));
        assert!(rendered.contains("  Planned (0)"));
        assert!(rendered.contains("  Excluded (1)"));
        assert!(rendered.contains("• web.action.laravel.input-analysis — policy_suppressed"));
        // The old two-line indented `reason:` form is gone (no information lost).
        assert!(!rendered.contains("      reason:"));
        // No ambiguous `(none)` token anywhere (empty sections rely on the count).
        assert!(!rendered.contains("(none)"));
        // Dispatch, Verification, and Terminal sections.
        assert!(rendered.contains("Dispatch"));
        assert!(rendered.contains("web.action.bootstrap (bootstrap)"));
        assert!(rendered.contains("Verification"));
        assert!(rendered.contains("web.action.probe: unknown"));
        assert!(rendered.contains("Terminal"));
        assert!(rendered.contains("halt (no_eligible_action)"));
        // Same honesty guarantees as the summary.
        assert!(!rendered.to_lowercase().contains("vulnerabilit"));
        assert!(!rendered.contains("VerificationCase {"));
        assert!(!rendered.contains("ExclusionReason"));
    }

    #[tokio::test]
    async fn decision_scan_explain_reports_the_chain_for_a_basic_auth_origin() {
        // A 401 Basic challenge activates the supported http-basic path end to end;
        // the explain view must surface the hypothesis, the dispatched action, and
        // a success outcome — all offline.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();

        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        let rendered = decision_scan::render_explain(&summary);
        assert!(
            rendered.contains("authentication.mechanism=http-basic"),
            "explain must surface the http-basic hypothesis:\n{rendered}"
        );
        assert!(
            rendered.contains("strength : strong"),
            "explain must surface the hypothesis strength:\n{rendered}"
        );
        assert!(
            rendered.contains("(planned)"),
            "explain must surface the planned dispatch:\n{rendered}"
        );
        assert!(
            rendered.contains(": success"),
            "explain must surface the success outcome:\n{rendered}"
        );
        assert!(!rendered.to_lowercase().contains("vulnerabilit"));
    }

    #[test]
    fn default_summary_output_is_byte_stable() {
        // This PR changes only `--explain`. Pin the exact default `decision-scan`
        // bytes so the default output cannot drift unnoticed.
        let expected = concat!(
            "== scan (deterministic alpha) ==\n",
            "engine: decision-preview\n",
            "target origin: https://example.test\n",
            "evidence: 1 bootstrap write(s)\n",
            "planning: 1 turn(s)\n",
            "verification outcomes: 1 (conclusive 0, inconclusive 1)\n",
            "  outcome: action=web.action.probe status=unknown\n",
            "terminal: halt\n",
            "stop_reason: no_eligible_action\n",
            "usage: requests=3 active_verifications=1 response_bytes=42 elapsed_ms=5\n",
            "experience records: 1\n",
        );
        assert_eq!(decision_scan::render_summary(&sample_summary()), expected);
    }

    #[test]
    fn runtime_limit_text_matches_the_legacy_display_format() {
        // The text surface emits the exact legacy `RuntimeLimitExceeded` Display
        // (which `run_decision_scan` stores verbatim via `.to_string()`); only the
        // JSON surface uses the structured object. The wall-time dimension keeps
        // its `wall_time_ms` label in text.
        let mut summary = sample_summary();
        summary.limit_exceeded_text =
            Some("runtime wall_time_ms limit 60000 reached by 60001".to_owned());
        let rendered = decision_scan::render_summary(&summary);
        assert!(rendered.contains(
            "runtime limit reached (controlled stop): runtime wall_time_ms limit 60000 reached by 60001\n"
        ));
    }

    #[test]
    fn runtime_limit_with_action_matches_the_legacy_display_format() {
        let mut summary = sample_summary();
        summary.limit_exceeded_text = Some(
            "runtime response_bytes limit 1048576 reached by 1100000 for action web.action.laravel.route-discovery"
                .to_owned(),
        );
        let rendered = decision_scan::render_summary(&summary);
        assert!(rendered.contains(
            "runtime limit reached (controlled stop): runtime response_bytes limit 1048576 reached by 1100000 for action web.action.laravel.route-discovery\n"
        ));
    }

    #[tokio::test]
    async fn decision_scan_explain_labels_the_active_verification_dispatch() {
        // The Sanctum cookie pair drives Laravel route discovery, whose second
        // probe is an active-verification dispatch with no passive origin. The
        // explain view must label it `active_verification`, never `none`.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=eyJ; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=abc123; Path=/\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();

        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        let rendered = decision_scan::render_explain(&summary);
        assert!(
            rendered.contains("(active_verification)"),
            "the active probe must be labelled active_verification:\n{rendered}"
        );
        assert!(
            !rendered.contains("(none)"),
            "no dispatch may render the ambiguous (none) label:\n{rendered}"
        );
        // Planned/dispatched/outcome distinctions remain intact.
        assert!(rendered.contains("✓ web.action.laravel.route-discovery"));
        assert!(rendered.contains("✓ web.action.sanctum.auth-boundary"));
        assert!(rendered.contains("web.action.laravel.route-discovery (planned)"));
        // Sanctum has an available executor route (not in the unavailable
        // inventory) and, under multi-objective continuation, now dispatches after
        // the route is suppressed — so a dispatch line carries its action id.
        assert!(
            !summary
                .unavailable_routes
                .contains(&"web.action.sanctum.auth-boundary".to_string()),
            "sanctum has an available route: {:?}",
            summary.unavailable_routes
        );
        assert!(
            rendered.contains("web.action.sanctum.auth-boundary ("),
            "sanctum dispatches under multi-objective continuation:\n{rendered}"
        );
    }

    /// The unavailable executor-route inventory is a fixed property of the runtime
    /// composition — identical regardless of what a fixture discloses.
    #[tokio::test]
    async fn executor_route_inventory_is_fixture_independent() {
        // A generic 200 (no hypotheses) and a Basic challenge (a full supported
        // path) must report the identical unavailable-route inventory.
        let (generic_target, generic_server) = serve_static().await;
        let generic = decision_scan::run_decision_scan(generic_target)
            .await
            .unwrap();
        generic_server.abort();

        let basic_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let basic_address = basic_listener.local_addr().unwrap();
        let basic_server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match basic_listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let basic_target = Url::parse(&format!("http://{basic_address}/")).unwrap();
        let basic = decision_scan::run_decision_scan(basic_target)
            .await
            .unwrap();
        basic_server.abort();

        assert_eq!(
            generic.unavailable_routes, basic.unavailable_routes,
            "the unavailable-route inventory must not depend on the fixture"
        );
        // It is the runtime's single executor-less action. nginx, apache, and php
        // input discovery are now executor-backed and no longer appear here.
        assert_eq!(
            generic.unavailable_routes,
            vec!["web.action.laravel.input-analysis".to_string()]
        );
    }

    /// Route status (runtime composition) and planning eligibility (this turn's
    /// decision) are independent axes and must render as distinct facts.
    #[tokio::test]
    async fn decision_scan_explain_separates_route_status_from_planning_eligibility() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nX-Powered-By: Laravel\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();
        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        // laravel input analysis: no executor route AND excluded this turn as
        // policy_suppressed.
        assert!(summary
            .unavailable_routes
            .contains(&"web.action.laravel.input-analysis".to_string()));
        // http-basic: HAS an executor route (not in the unavailable inventory) yet
        // is still excluded this turn — for a different reason (requirements not
        // met). Route availability and eligibility are orthogonal.
        assert!(!summary
            .unavailable_routes
            .contains(&"web.action.http-basic.auth-boundary".to_string()));

        let rendered = decision_scan::render_explain(&summary);
        // Both facts appear, framed distinctly: the route inventory lists laravel
        // input analysis without a reason; the planning turn excludes it with one.
        assert!(rendered.contains("Executor Routes"));
        assert!(rendered.contains("    • web.action.laravel.input-analysis\n"));
        assert!(rendered.contains("• web.action.laravel.input-analysis — policy_suppressed"));
        assert!(
            rendered.contains("• web.action.http-basic.auth-boundary — requirements_not_met"),
            "an available route can still be excluded this turn:\n{rendered}"
        );
    }

    // --- Machine-readable (`--format json`) tests -----------------------------

    /// Runs one fixture and returns the parsed JSON document.
    async fn json_for(response: &'static [u8]) -> serde_json::Value {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();
        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();
        let json = decision_scan::render_json(&summary).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn render_json_emits_the_versioned_schema() {
        let json = decision_scan::render_json(&sample_summary()).unwrap();
        // It is valid JSON.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schema_version"], "decision-scan/v1");
        assert_eq!(value["engine"], "decision-preview");
        assert_eq!(value["target_origin"], "https://example.test");
        // Every top-level contract group is present with stable names.
        for key in [
            "summary",
            "executor_routes",
            "hypotheses",
            "planning_turns",
            "dispatches",
            "verification_outcomes",
            "terminal",
            "usage",
        ] {
            assert!(value.get(key).is_some(), "missing top-level key {key}");
        }
        // Basis points is the numeric source of truth; there is no percent field.
        assert_eq!(value["hypotheses"][0]["posterior_basis_points"], 8900);
        assert!(value["hypotheses"][0].get("posterior_percent").is_none());
        // Executor routes: only the unavailable set, never a synthesized available.
        assert_eq!(
            value["executor_routes"]["unavailable"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(value["executor_routes"].get("available").is_none());
        // Terminal and usage.
        assert_eq!(value["terminal"]["command"], "halt");
        assert_eq!(value["terminal"]["stop_reason"], "no_eligible_action");
        assert!(value["terminal"]["runtime_limit"].is_null());
        assert_eq!(value["usage"]["total_requests"], 3);
        // Hypothesis value carries an explicit kind and safety disposition.
        assert_eq!(value["hypotheses"][0]["value"], "laravel");
        assert_eq!(value["hypotheses"][0]["value_kind"], "text");
        assert_eq!(value["hypotheses"][0]["value_disposition"], "exposed");
        // Never a vulnerability claim, never a Debug dump.
        assert!(!json.to_lowercase().contains("vulnerabilit"));
        assert!(!json.contains("VerificationCase"));
    }

    #[test]
    fn render_json_matches_the_exact_v1_golden() {
        // Pins the current canonical renderer output (field set, types,
        // nullability, and the renderer's member order) — not just the presence of
        // selected keys. JSON object member order is not itself a consumer-semantic
        // contract (see the schema doc); this golden guards the renderer. Regenerate
        // deliberately on an intended change.
        let expected = concat!(
            "{\n",
            "  \"schema_version\": \"decision-scan/v1\",\n",
            "  \"engine\": \"decision-preview\",\n",
            "  \"target_origin\": \"https://example.test\",\n",
            "  \"summary\": {\n",
            "    \"bootstrap_evidence_writes\": 1,\n",
            "    \"planning_turns\": 1,\n",
            "    \"verification_outcomes\": 1,\n",
            "    \"conclusive_outcomes\": 0,\n",
            "    \"inconclusive_outcomes\": 1,\n",
            "    \"experience_records\": 1\n",
            "  },\n",
            "  \"executor_routes\": {\n",
            "    \"unavailable\": [\n",
            "      \"web.action.laravel.input-analysis\"\n",
            "    ]\n",
            "  },\n",
            "  \"hypotheses\": [\n",
            "    {\n",
            "      \"predicate\": \"technology.framework\",\n",
            "      \"value\": \"laravel\",\n",
            "      \"value_kind\": \"text\",\n",
            "      \"value_disposition\": \"exposed\",\n",
            "      \"strength\": \"weak\",\n",
            "      \"posterior_basis_points\": 8900,\n",
            "      \"state\": \"supported\"\n",
            "    }\n",
            "  ],\n",
            "  \"planning_turns\": [\n",
            "    {\n",
            "      \"turn\": 0,\n",
            "      \"planned\": [],\n",
            "      \"excluded\": [\n",
            "        {\n",
            "          \"action_id\": \"web.action.laravel.input-analysis\",\n",
            "          \"reason\": \"policy_suppressed\"\n",
            "        }\n",
            "      ]\n",
            "    }\n",
            "  ],\n",
            "  \"dispatches\": [\n",
            "    {\n",
            "      \"sequence\": 0,\n",
            "      \"action_id\": \"web.action.bootstrap\",\n",
            "      \"stage\": \"passive\",\n",
            "      \"origin\": \"bootstrap\"\n",
            "    }\n",
            "  ],\n",
            "  \"verification_outcomes\": [\n",
            "    {\n",
            "      \"action_id\": \"web.action.probe\",\n",
            "      \"status\": \"unknown\",\n",
            "      \"conclusive\": false\n",
            "    }\n",
            "  ],\n",
            "  \"terminal\": {\n",
            "    \"command\": \"halt\",\n",
            "    \"stop_reason\": \"no_eligible_action\",\n",
            "    \"runtime_limit\": null\n",
            "  },\n",
            "  \"usage\": {\n",
            "    \"total_requests\": 3,\n",
            "    \"active_verifications\": 1,\n",
            "    \"response_bytes\": 42,\n",
            "    \"elapsed_ms\": 5\n",
            "  }\n",
            "}"
        );
        assert_eq!(
            decision_scan::render_json(&sample_summary()).unwrap(),
            expected
        );
    }

    /// Structural invariants the v1 document must always satisfy on a real run.
    #[tokio::test]
    async fn json_invariants_hold_on_a_real_run() {
        // Sanctum drives multiple planning entries, dispatches, and outcomes.
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=eyJ; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=abc123; Path=/\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        )
        .await;

        // Duplicated count fields must equal their array lengths.
        assert_eq!(
            value["summary"]["planning_turns"].as_u64().unwrap(),
            value["planning_turns"].as_array().unwrap().len() as u64
        );
        let outcomes = value["verification_outcomes"].as_array().unwrap();
        assert_eq!(
            value["summary"]["verification_outcomes"].as_u64().unwrap(),
            outcomes.len() as u64
        );
        // conclusive + inconclusive == total outcomes.
        assert_eq!(
            value["summary"]["conclusive_outcomes"].as_u64().unwrap()
                + value["summary"]["inconclusive_outcomes"].as_u64().unwrap(),
            outcomes.len() as u64
        );
        // Dispatch sequences are strictly increasing.
        let sequences: Vec<u64> = value["dispatches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|dispatch| dispatch["sequence"].as_u64().unwrap())
            .collect();
        assert!(
            sequences.windows(2).all(|pair| pair[0] < pair[1]),
            "dispatch sequences must be strictly increasing: {sequences:?}"
        );
        // Posterior basis points never exceed 10000.
        for hypothesis in value["hypotheses"].as_array().unwrap() {
            assert!(hypothesis["posterior_basis_points"].as_u64().unwrap() <= 10_000);
        }
    }

    #[tokio::test]
    async fn json_generic_structure_is_inert() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await;
        assert_eq!(value["schema_version"], "decision-scan/v1");
        assert!(value["hypotheses"].as_array().unwrap().is_empty());
        assert!(value["planning_turns"][0]["planned"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(value["verification_outcomes"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(value["terminal"]["command"], "halt");
        assert_eq!(value["terminal"]["stop_reason"], "no_eligible_action");
        // The unavailable-route inventory is present and fixture-independent.
        // nginx, apache, and php input discovery are now executor-backed, leaving
        // one executor-less route.
        assert_eq!(
            value["executor_routes"]["unavailable"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn json_basic_structure_reports_a_conclusive_success() {
        let value = json_for(
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let hypothesis = &value["hypotheses"][0];
        assert_eq!(hypothesis["predicate"], "authentication.mechanism");
        assert_eq!(hypothesis["value"], "http-basic");
        assert_eq!(hypothesis["strength"], "strong");
        assert!(hypothesis["posterior_basis_points"].as_u64().unwrap() >= 9000);
        let outcome = &value["verification_outcomes"][0];
        assert_eq!(outcome["action_id"], "web.action.http-basic.auth-boundary");
        assert_eq!(outcome["status"], "success");
        assert_eq!(outcome["conclusive"], true);
        // No raw challenge header/realm leaks into the machine surface.
        let json = value.to_string();
        assert!(!json.contains("WWW-Authenticate"));
        assert!(!json.contains("realm"));
    }

    #[tokio::test]
    async fn json_php_form_discovery_reports_success_without_a_conclusive_transition() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.3.7\r\nContent-Type: text/html\r\nContent-Length: 36\r\nConnection: close\r\n\r\n<form><input name=\"username\"></form>",
        )
        .await;

        assert_eq!(value["schema_version"], "decision-scan/v1");
        let hypothesis = &value["hypotheses"][0];
        assert_eq!(hypothesis["predicate"], "technology.language");
        assert_eq!(hypothesis["value"], "php");
        assert_eq!(hypothesis["state"], "supported");
        let outcome = &value["verification_outcomes"][0];
        assert_eq!(outcome["action_id"], "web.action.php.input-discovery");
        assert_eq!(outcome["status"], "success");
        assert_eq!(outcome["conclusive"], false);
        assert_eq!(value["summary"]["verification_outcomes"], 1);
        assert_eq!(value["summary"]["conclusive_outcomes"], 0);
        assert_eq!(value["summary"]["inconclusive_outcomes"], 1);
        assert_eq!(value["terminal"]["command"], "complete");
        assert_eq!(value["usage"]["total_requests"], 2);
        assert_eq!(value["usage"]["active_verifications"], 0);
    }

    #[tokio::test]
    async fn json_livewire_structure_reports_a_dispatched_success() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 23\r\nConnection: close\r\n\r\n<div wire:id=\"x\"></div>",
        )
        .await;
        assert_eq!(value["hypotheses"][0]["value"], "livewire");
        assert!(value["planning_turns"][0]["planned"]
            .as_array()
            .unwrap()
            .iter()
            .any(|planned| *planned == "web.action.livewire.component-discovery"));
        assert!(value["dispatches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dispatch| {
                dispatch["action_id"] == "web.action.livewire.component-discovery"
            }));
        assert_eq!(value["verification_outcomes"][0]["status"], "success");
    }

    #[tokio::test]
    async fn json_sanctum_success_is_nonconclusive_and_leaks_no_secrets() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=eyJ; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=abc123; Path=/\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        )
        .await;

        let dispatches = value["dispatches"].as_array().unwrap();
        // An active-verification dispatch keeps stage/origin as separate facts:
        // stage = "active", origin = null (never a fused "active_verification").
        assert!(
            dispatches
                .iter()
                .any(|dispatch| dispatch["stage"] == "active" && dispatch["origin"].is_null()),
            "expected an active dispatch with null origin: {dispatches:?}"
        );
        // Passive/bootstrap dispatches carry an explicit origin.
        assert!(dispatches
            .iter()
            .any(|dispatch| dispatch["origin"] == "bootstrap"));

        // Sanctum is planned in the first turn and, under multi-objective
        // continuation, dispatches after the route is suppressed; it has an
        // available route.
        let planned = value["planning_turns"][0]["planned"].as_array().unwrap();
        assert!(planned
            .iter()
            .any(|action| *action == "web.action.sanctum.auth-boundary"));
        assert!(dispatches
            .iter()
            .any(|dispatch| dispatch["action_id"] == "web.action.sanctum.auth-boundary"));
        assert!(!value["executor_routes"]["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| *route == "web.action.sanctum.auth-boundary"));

        let sanctum_hypothesis = value["hypotheses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|hypothesis| hypothesis["value"] == "sanctum")
            .expect("Sanctum motivation");
        assert_eq!(sanctum_hypothesis["state"], "supported");
        let sanctum_outcome = value["verification_outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outcome| outcome["action_id"] == "web.action.sanctum.auth-boundary")
            .expect("Sanctum-compatible action outcome");
        assert_eq!(sanctum_outcome["status"], "success");
        assert_eq!(sanctum_outcome["conclusive"], false);
        assert_eq!(value["summary"]["verification_outcomes"], 3);
        assert_eq!(value["summary"]["conclusive_outcomes"], 0);
        assert_eq!(value["summary"]["inconclusive_outcomes"], 3);
        assert_eq!(value["terminal"]["command"], "await_human_review");
        assert_eq!(value["usage"]["total_requests"], 4);
        assert_eq!(value["usage"]["active_verifications"], 1);

        // No raw cookies, values, or headers leak into the machine surface.
        let json = value.to_string();
        for secret in [
            "eyJ",
            "abc123",
            "Set-Cookie",
            "laravel_session",
            "XSRF-TOKEN",
        ] {
            assert!(!json.contains(secret), "json leaked `{secret}`: {json}");
        }
    }

    #[tokio::test]
    async fn json_is_deterministic_for_equivalent_non_boundary_fixture_excluding_elapsed_ms() {
        // A generic 200 sits well away from any budget boundary, so two runs agree
        // once elapsed time is excluded. (Near a boundary, chunking/scheduling may
        // affect response_bytes / runtime_limit.observed / total_requests — see the
        // schema doc.)
        let (target, server) = serve_static().await;
        let first = decision_scan::run_decision_scan(target.clone())
            .await
            .unwrap();
        let second = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        let mut a: serde_json::Value =
            serde_json::from_str(&decision_scan::render_json(&first).unwrap()).unwrap();
        let mut b: serde_json::Value =
            serde_json::from_str(&decision_scan::render_json(&second).unwrap()).unwrap();
        a["usage"]["elapsed_ms"] = serde_json::json!(0);
        b["usage"]["elapsed_ms"] = serde_json::json!(0);
        assert_eq!(
            a, b,
            "JSON must be deterministic once elapsed time is excluded"
        );
    }
}
