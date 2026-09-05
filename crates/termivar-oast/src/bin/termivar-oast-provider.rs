//! Loopback-only process boundary for the self-hosted native OAST provider.

use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{ArgGroup, Parser};
use termivar_oast::{
    serve_provider, AdminToken, LoopbackBind, ProviderConfig, ProviderLimits, ProviderState,
    PublicOrigin,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_ADMIN_TOKEN_BYTES: usize = 4_096;

#[derive(Parser)]
#[command(
    name = "termivar-oast-provider",
    version,
    about = "Loopback-only raw-free HTTP callback mailbox for Termivar",
    group = ArgGroup::new("admin-token-source")
        .required(true)
        .multiple(false)
        .args(["admin_token_env", "admin_token_file", "admin_token_stdin"])
)]
struct Args {
    /// Exact IPv4 or IPv6 loopback socket to bind.
    #[arg(long)]
    bind: String,

    /// Externally visible HTTPS origin of the operator-managed reverse proxy.
    #[arg(long)]
    public_origin: String,

    /// Read the provider administrator token from this environment variable.
    #[arg(long, value_name = "NAME")]
    admin_token_env: Option<OsString>,

    /// Read the provider administrator token from this bounded regular file.
    #[arg(long, value_name = "PATH")]
    admin_token_file: Option<PathBuf>,

    /// Read the provider administrator token once from standard input.
    #[arg(long)]
    admin_token_stdin: bool,

    /// Hard ceiling for simultaneously live sessions.
    #[arg(long)]
    max_active_sessions: usize,

    /// Hard ceiling for callbacks allocated in one session.
    #[arg(long)]
    max_callbacks_per_session: usize,

    /// Hard ceiling for retained events in one session.
    #[arg(long)]
    max_events_per_session: usize,

    /// Hard ceiling for polls in one session.
    #[arg(long)]
    max_polls_per_session: usize,

    /// Hard ceiling for events returned by one poll.
    #[arg(long)]
    max_poll_events_per_response: usize,

    /// Hard ceiling for a session lifetime in seconds.
    #[arg(long)]
    max_session_lifetime_secs: u64,

    /// Hard ceiling for concurrently admitted HTTP requests.
    #[arg(long)]
    max_concurrent_requests: u16,
}

enum AdminTokenSource {
    Environment(OsString),
    File(PathBuf),
    Stdin,
}

impl fmt::Debug for AdminTokenSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminTokenSource(<redacted>)")
    }
}

impl AdminTokenSource {
    fn select(args: Args) -> Result<(Self, ProviderArguments), BinaryError> {
        let source = match (
            args.admin_token_env,
            args.admin_token_file,
            args.admin_token_stdin,
        ) {
            (Some(name), None, false) => Self::Environment(name),
            (None, Some(path), false) => Self::File(path),
            (None, None, true) => Self::Stdin,
            _ => return Err(BinaryError::InvalidArguments),
        };
        Ok((
            source,
            ProviderArguments {
                bind: args.bind,
                public_origin: args.public_origin,
                max_active_sessions: args.max_active_sessions,
                max_callbacks_per_session: args.max_callbacks_per_session,
                max_events_per_session: args.max_events_per_session,
                max_polls_per_session: args.max_polls_per_session,
                max_poll_events_per_response: args.max_poll_events_per_response,
                max_session_lifetime_secs: args.max_session_lifetime_secs,
                max_concurrent_requests: args.max_concurrent_requests,
            },
        ))
    }

    fn load(self) -> Result<AdminToken, BinaryError> {
        let bytes = match self {
            Self::Environment(name) => {
                if name.is_empty()
                    || name.as_encoded_bytes().contains(&b'=')
                    || name.as_encoded_bytes().contains(&b'\0')
                {
                    return Err(BinaryError::AdminTokenUnavailable);
                }
                let value = std::env::var_os(name).ok_or(BinaryError::AdminTokenUnavailable)?;
                let bytes = Zeroizing::new(value.into_encoded_bytes());
                validate_source_length(bytes.len())?;
                bytes
            },
            Self::File(path) => {
                let mut file = open_regular_file(path)?;
                read_bounded_line(&mut file)?
            },
            Self::Stdin => {
                let stdin = io::stdin();
                read_bounded_line(&mut stdin.lock())?
            },
        };
        into_admin_token(bytes)
    }
}

struct ProviderArguments {
    bind: String,
    public_origin: String,
    max_active_sessions: usize,
    max_callbacks_per_session: usize,
    max_events_per_session: usize,
    max_polls_per_session: usize,
    max_poll_events_per_response: usize,
    max_session_lifetime_secs: u64,
    max_concurrent_requests: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryError {
    InvalidArguments,
    AdminTokenUnavailable,
    AdminTokenNotRegularFile,
    AdminTokenReadFailed,
    AdminTokenTooLarge,
    InvalidAdminToken,
    InvalidBind,
    InvalidPublicOrigin,
    InvalidLimits,
    ProviderInitialization,
    ProviderTransport,
}

impl fmt::Display for BinaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArguments => "provider arguments are invalid",
            Self::AdminTokenUnavailable => "administrator token source is unavailable",
            Self::AdminTokenNotRegularFile => "administrator token source must be a regular file",
            Self::AdminTokenReadFailed => "administrator token source could not be read",
            Self::AdminTokenTooLarge => "administrator token exceeds the compiled byte limit",
            Self::InvalidAdminToken => "administrator token is invalid",
            Self::InvalidBind => "provider bind must be an exact loopback socket",
            Self::InvalidPublicOrigin => "provider public origin must be an exact HTTPS origin",
            Self::InvalidLimits => "provider resource limits are invalid",
            Self::ProviderInitialization => "provider initialization failed",
            Self::ProviderTransport => "provider transport failed",
        })
    }
}

impl std::error::Error for BinaryError {}

fn open_regular_file(path: PathBuf) -> Result<File, BinaryError> {
    // No-follow applies only to the final component. Parent directories must
    // be trusted; this is not whole-path containment or an immutable snapshot.
    // A special/network path may still be contacted while opening it. Inspect
    // the resulting handle before reading, never a separately checked path.
    let file = open_no_follow(&path)?;
    validate_opened_file(file)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, BinaryError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        // NONBLOCK ensures opening a FIFO cannot wait for a writer before its
        // handle is rejected as non-regular. It does not bound regular-file I/O.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                BinaryError::AdminTokenNotRegularFile
            } else {
                BinaryError::AdminTokenUnavailable
            }
        })
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> Result<File, BinaryError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        // BACKUP_SEMANTICS allows a directory handle, which validation rejects.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        // SECURITY_ANONYMOUS prevents named-pipe impersonation before opened-
        // handle metadata can reject a non-file. std sets SQOS_PRESENT.
        .security_qos_flags(0)
        .open(path)
        .map_err(|_| BinaryError::AdminTokenUnavailable)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(_: &Path) -> Result<File, BinaryError> {
    Err(BinaryError::AdminTokenUnavailable)
}

fn validate_opened_file(file: File) -> Result<File, BinaryError> {
    let metadata = file
        .metadata()
        .map_err(|_| BinaryError::AdminTokenUnavailable)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        // Reject every reparse tag, not just symbolic-link file types.
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BinaryError::AdminTokenNotRegularFile);
        }
    }
    if !metadata.is_file() {
        return Err(BinaryError::AdminTokenNotRegularFile);
    }
    if metadata.len() > u64::try_from(MAX_ADMIN_TOKEN_BYTES + 2).unwrap_or(u64::MAX) {
        return Err(BinaryError::AdminTokenTooLarge);
    }
    Ok(file)
}

fn read_bounded_line(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, BinaryError> {
    let retained_limit = MAX_ADMIN_TOKEN_BYTES.saturating_add(2);
    let mut bytes = Zeroizing::new(Vec::with_capacity(retained_limit));
    reader
        .by_ref()
        .take(u64::try_from(retained_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| BinaryError::AdminTokenReadFailed)?;
    let mut overflow = Zeroizing::new([0_u8; 1]);
    if reader
        .read(overflow.as_mut())
        .map_err(|_| BinaryError::AdminTokenReadFailed)?
        != 0
    {
        return Err(BinaryError::AdminTokenTooLarge);
    }
    let normalized_length = wipe_terminal_line_ending(&mut bytes);
    bytes.truncate(normalized_length);
    validate_source_length(bytes.len())?;
    Ok(bytes)
}

fn wipe_terminal_line_ending(bytes: &mut [u8]) -> usize {
    let length = if bytes.ends_with(b"\r\n") {
        bytes.len().saturating_sub(2)
    } else if bytes.ends_with(b"\n") {
        bytes.len().saturating_sub(1)
    } else {
        bytes.len()
    };
    // Truncating first would leave removed bytes outside Zeroizing's live
    // slice. Wipe the suffix while it is still addressable and initialized.
    bytes[length..].zeroize();
    length
}

fn into_admin_token(mut bytes: Zeroizing<Vec<u8>>) -> Result<AdminToken, BinaryError> {
    AdminToken::new(std::mem::take(&mut *bytes)).map_err(|_| BinaryError::InvalidAdminToken)
}

fn validate_source_length(length: usize) -> Result<(), BinaryError> {
    if length > MAX_ADMIN_TOKEN_BYTES {
        return Err(BinaryError::AdminTokenTooLarge);
    }
    Ok(())
}

async fn run(args: Args) -> Result<(), BinaryError> {
    let (source, args) = AdminTokenSource::select(args)?;
    let bind: LoopbackBind = args.bind.parse().map_err(|_| BinaryError::InvalidBind)?;
    let public_origin: PublicOrigin = args
        .public_origin
        .parse()
        .map_err(|_| BinaryError::InvalidPublicOrigin)?;
    let lifetime_ms = args
        .max_session_lifetime_secs
        .checked_mul(1_000)
        .ok_or(BinaryError::InvalidLimits)?;
    let limits = ProviderLimits::new(
        args.max_active_sessions
            .try_into()
            .map_err(|_| BinaryError::InvalidLimits)?,
        args.max_callbacks_per_session
            .try_into()
            .map_err(|_| BinaryError::InvalidLimits)?,
        args.max_events_per_session
            .try_into()
            .map_err(|_| BinaryError::InvalidLimits)?,
        args.max_polls_per_session
            .try_into()
            .map_err(|_| BinaryError::InvalidLimits)?,
        args.max_poll_events_per_response
            .try_into()
            .map_err(|_| BinaryError::InvalidLimits)?,
        lifetime_ms,
        args.max_concurrent_requests,
    )
    .map_err(|_| BinaryError::InvalidLimits)?;
    let config = ProviderConfig::new(bind, public_origin, limits);
    let admin_token = source.load()?;
    let state =
        ProviderState::new(config, admin_token).map_err(|_| BinaryError::ProviderInitialization)?;
    serve_provider(state)
        .await
        .map_err(|_| BinaryError::ProviderTransport)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor, Error, Read},
    };

    use clap::CommandFactory as _;

    use super::*;

    const SECRET: &str = "ADMIN-TOKEN-MUST-NOT-LEAK-7C3A19-0123456789";

    #[test]
    fn bounded_reader_normalizes_one_terminal_line_ending() {
        let mut lf = Cursor::new(format!("{SECRET}\n"));
        assert_eq!(
            read_bounded_line(&mut lf).unwrap().as_slice(),
            SECRET.as_bytes()
        );
        let mut crlf = Cursor::new(format!("{SECRET}\r\n"));
        assert_eq!(
            read_bounded_line(&mut crlf).unwrap().as_slice(),
            SECRET.as_bytes()
        );
        let mut two = Cursor::new(format!("{SECRET}\n\n"));
        assert_eq!(
            read_bounded_line(&mut two).unwrap().as_slice(),
            format!("{SECRET}\n").as_bytes()
        );
    }

    #[test]
    fn terminal_line_endings_are_wiped_while_the_suffix_is_still_live() {
        for (input, expected) in [
            (b"fixture\n".as_slice(), b"fixture".as_slice()),
            (b"fixture\r\n".as_slice(), b"fixture".as_slice()),
            (b"fixture\n\n".as_slice(), b"fixture\n".as_slice()),
            (b"fixture\r".as_slice(), b"fixture\r".as_slice()),
            (b"fixture".as_slice(), b"fixture".as_slice()),
            (b"\r\n".as_slice(), b"".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            let mut bytes = input.to_vec();
            let length = wipe_terminal_line_ending(&mut bytes);
            assert_eq!(length, expected.len());
            assert_eq!(bytes.len(), input.len());
            assert_eq!(&bytes[..length], expected);
            assert!(bytes[length..].iter().all(|byte| *byte == 0));
            bytes.truncate(length);
            assert_eq!(bytes, expected);
        }
    }

    #[test]
    fn bounded_reader_rejects_invalid_and_oversized_secret_inputs() {
        for invalid in [
            Vec::new(),
            vec![b'x'; 31],
            format!("{SECRET}\nX").into_bytes(),
        ] {
            let bytes = read_bounded_line(&mut Cursor::new(invalid)).unwrap();
            assert_eq!(
                into_admin_token(bytes).unwrap_err(),
                BinaryError::InvalidAdminToken
            );
        }

        let mut oversized = Cursor::new(vec![b'x'; MAX_ADMIN_TOKEN_BYTES + 3]);
        assert_eq!(
            read_bounded_line(&mut oversized).unwrap_err(),
            BinaryError::AdminTokenTooLarge
        );
    }

    #[test]
    fn bounded_reader_and_errors_never_echo_secret_material() {
        let mut oversized = Cursor::new(vec![b'x'; MAX_ADMIN_TOKEN_BYTES + 3]);
        let error = read_bounded_line(&mut oversized).unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenTooLarge);
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(!rendered.contains(SECRET));
            assert!(!rendered.contains("4099"));
        }
        assert_eq!(
            format!("{:?}", AdminTokenSource::Stdin),
            "AdminTokenSource(<redacted>)"
        );
    }

    #[test]
    fn binary_error_messages_are_static_and_exhaustive() {
        let cases = [
            (
                BinaryError::InvalidArguments,
                "provider arguments are invalid",
            ),
            (
                BinaryError::AdminTokenUnavailable,
                "administrator token source is unavailable",
            ),
            (
                BinaryError::AdminTokenNotRegularFile,
                "administrator token source must be a regular file",
            ),
            (
                BinaryError::AdminTokenReadFailed,
                "administrator token source could not be read",
            ),
            (
                BinaryError::AdminTokenTooLarge,
                "administrator token exceeds the compiled byte limit",
            ),
            (
                BinaryError::InvalidAdminToken,
                "administrator token is invalid",
            ),
            (
                BinaryError::InvalidBind,
                "provider bind must be an exact loopback socket",
            ),
            (
                BinaryError::InvalidPublicOrigin,
                "provider public origin must be an exact HTTPS origin",
            ),
            (
                BinaryError::InvalidLimits,
                "provider resource limits are invalid",
            ),
            (
                BinaryError::ProviderInitialization,
                "provider initialization failed",
            ),
            (BinaryError::ProviderTransport, "provider transport failed"),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            assert!(!error.to_string().contains(SECRET));
        }
    }

    struct SecretThenReadFailure {
        emitted: bool,
    }

    impl Read for SecretThenReadFailure {
        fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                return Err(Error::other("PRIVATE-ADMIN-TOKEN-READ-DIAGNOSTIC"));
            }
            self.emitted = true;
            let length = destination.len().min(SECRET.len());
            destination[..length].copy_from_slice(&SECRET.as_bytes()[..length]);
            Ok(length)
        }
    }

    #[test]
    fn read_failure_after_secret_bytes_returns_only_a_static_error() {
        let error = read_bounded_line(&mut SecretThenReadFailure { emitted: false }).unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenReadFailed);
        assert!(!error.to_string().contains(SECRET));
        assert!(!error
            .to_string()
            .contains("PRIVATE-ADMIN-TOKEN-READ-DIAGNOSTIC"));
    }

    #[test]
    fn cli_has_no_raw_admin_token_argument_and_requires_one_source() {
        let help = Args::command().render_long_help().to_string();
        assert!(help.contains("--admin-token-env"));
        assert!(help.contains("--admin-token-file"));
        assert!(help.contains("--admin-token-stdin"));
        assert!(!help.contains("--admin-token <"));

        let base = [
            "termivar-oast-provider",
            "--bind",
            "127.0.0.1:8080",
            "--public-origin",
            "https://oast.example.test",
            "--max-active-sessions",
            "4",
            "--max-callbacks-per-session",
            "2",
            "--max-events-per-session",
            "4",
            "--max-polls-per-session",
            "4",
            "--max-poll-events-per-response",
            "4",
            "--max-session-lifetime-secs",
            "30",
            "--max-concurrent-requests",
            "16",
        ];
        assert!(Args::try_parse_from(base).is_err());
        let mut selected = base.to_vec();
        selected.extend(["--admin-token-env", "TERMIVAR_OAST_ADMIN"]);
        assert!(Args::try_parse_from(selected).is_ok());
        let mut conflicting = base.to_vec();
        conflicting.extend([
            "--admin-token-env",
            "TERMIVAR_OAST_ADMIN",
            "--admin-token-stdin",
        ]);
        assert!(Args::try_parse_from(conflicting).is_err());
    }

    #[test]
    fn stdin_source_is_selected_without_materializing_secret_arguments() {
        let args = Args {
            bind: "127.0.0.1:8080".to_owned(),
            public_origin: "https://oast.example.test".to_owned(),
            admin_token_env: None,
            admin_token_file: None,
            admin_token_stdin: true,
            max_active_sessions: 4,
            max_callbacks_per_session: 2,
            max_events_per_session: 4,
            max_polls_per_session: 4,
            max_poll_events_per_response: 4,
            max_session_lifetime_secs: 30,
            max_concurrent_requests: 16,
        };
        let (source, provider) = AdminTokenSource::select(args).unwrap();
        assert!(matches!(source, AdminTokenSource::Stdin));
        assert_eq!(provider.bind, "127.0.0.1:8080");
        assert_eq!(provider.public_origin, "https://oast.example.test");
    }

    #[tokio::test]
    async fn run_rejects_invalid_limits_before_secret_input_or_transport() {
        let args = Args {
            bind: "127.0.0.1:8080".to_owned(),
            public_origin: "https://oast.example.test".to_owned(),
            admin_token_env: None,
            admin_token_file: None,
            admin_token_stdin: true,
            max_active_sessions: 0,
            max_callbacks_per_session: 2,
            max_events_per_session: 4,
            max_polls_per_session: 4,
            max_poll_events_per_response: 4,
            max_session_lifetime_secs: 30,
            max_concurrent_requests: 16,
        };

        assert_eq!(run(args).await.unwrap_err(), BinaryError::InvalidLimits);
    }

    #[test]
    fn environment_and_regular_file_sources_load_without_exposing_locations() {
        let directory = tempfile::tempdir().unwrap();
        let environment_name = "TERMIVAR_OAST_TEST_ADMIN_81E4D7";
        std::env::set_var(environment_name, SECRET);
        let token = AdminTokenSource::Environment(OsString::from(environment_name))
            .load()
            .unwrap();
        assert_eq!(format!("{token:?}"), "AdminToken(<redacted>)");
        std::env::remove_var(environment_name);

        std::env::set_var(environment_name, "too-short");
        assert_eq!(
            AdminTokenSource::Environment(OsString::from(environment_name))
                .load()
                .unwrap_err(),
            BinaryError::InvalidAdminToken
        );
        std::env::remove_var(environment_name);

        std::env::set_var(environment_name, "x".repeat(MAX_ADMIN_TOKEN_BYTES + 1));
        assert_eq!(
            AdminTokenSource::Environment(OsString::from(environment_name))
                .load()
                .unwrap_err(),
            BinaryError::AdminTokenTooLarge
        );
        std::env::remove_var(environment_name);

        let path = directory.path().join("admin.txt");
        fs::write(&path, format!("{SECRET}\r\n")).unwrap();
        let source = AdminTokenSource::File(path.clone());
        assert!(!format!("{source:?}").contains(path.to_string_lossy().as_ref()));
        let token = source.load().unwrap();
        assert_eq!(format!("{token:?}"), "AdminToken(<redacted>)");

        let oversized_path = directory.path().join("oversized-admin.txt");
        fs::write(&oversized_path, vec![b'x'; MAX_ADMIN_TOKEN_BYTES + 3]).unwrap();
        assert_eq!(
            AdminTokenSource::File(oversized_path.clone())
                .load()
                .unwrap_err(),
            BinaryError::AdminTokenTooLarge
        );
    }

    #[test]
    fn invalid_source_names_and_non_files_fail_with_static_errors() {
        assert_eq!(
            AdminTokenSource::Environment(OsString::from("INVALID=NAME"))
                .load()
                .unwrap_err(),
            BinaryError::AdminTokenUnavailable
        );
        let directory = tempfile::tempdir().unwrap();
        let directory_path = directory.path().to_path_buf();
        let error = AdminTokenSource::File(directory_path.clone())
            .load()
            .unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenNotRegularFile);
        assert!(!error
            .to_string()
            .contains(directory_path.to_string_lossy().as_ref()));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn opened_file_identity_survives_deterministic_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected.txt");
        let original = directory.path().join("original.txt");
        fs::write(&path, SECRET).unwrap();
        let file = open_no_follow(&path).unwrap();
        // The pathname is replaced between open and handle validation, with
        // no timing races and no reads before the handle is validated.
        fs::rename(&path, &original).unwrap();
        fs::write(&path, b"REPLACEMENT-FIXTURE-MUST-NOT-BE-READ").unwrap();
        let mut file = validate_opened_file(file).unwrap();
        let bytes = read_bounded_line(&mut file).unwrap();
        assert_eq!(bytes.as_slice(), SECRET.as_bytes());
        assert_eq!(file.metadata().unwrap().len(), SECRET.len() as u64);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn opened_file_size_rejection_uses_the_handle_after_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected.txt");
        let original = directory.path().join("original.txt");
        fs::write(&path, vec![b'x'; MAX_ADMIN_TOKEN_BYTES + 3]).unwrap();
        let file = open_no_follow(&path).unwrap();
        fs::rename(&path, &original).unwrap();
        fs::write(&path, SECRET).unwrap();
        assert!(fs::metadata(&path).unwrap().len() < MAX_ADMIN_TOKEN_BYTES as u64);
        let error = validate_opened_file(file).unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenTooLarge);
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn opened_file_validation_rejects_directories_before_any_read() {
        let directory = tempfile::tempdir().unwrap();
        let file = open_no_follow(directory.path()).unwrap();
        assert!(file.metadata().unwrap().is_dir());
        let error = validate_opened_file(file).unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenNotRegularFile);
        assert!(!error
            .to_string()
            .contains(directory.path().to_string_lossy().as_ref()));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn growth_after_handle_validation_still_hits_the_bounded_reader() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("growing-fixture.txt");
        fs::write(&path, SECRET).unwrap();
        let mut file = open_regular_file(path.clone()).unwrap();
        // The contract is not immutability: a writer may still change this
        // regular file. Intake remains bounded even after successful metadata.
        fs::write(&path, vec![b'x'; MAX_ADMIN_TOKEN_BYTES + 3]).unwrap();
        assert_eq!(
            read_bounded_line(&mut file).unwrap_err(),
            BinaryError::AdminTokenTooLarge
        );
    }

    #[cfg(unix)]
    fn create_test_file_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link)
            .expect("temporary symbolic-link fixture must be supported");
    }

    #[cfg(windows)]
    fn create_test_file_link(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_file(target, link)
            .expect("temporary symbolic-link fixture must be supported");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn final_component_swapped_to_a_link_is_rejected_without_reading_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected.txt");
        let original = directory.path().join("original.txt");
        let target = directory.path().join("replacement-target.txt");
        fs::write(&path, SECRET).unwrap();
        fs::write(&target, b"REPLACEMENT-FIXTURE-MUST-NOT-BE-READ").unwrap();
        assert!(fs::metadata(&path).unwrap().is_file());
        fs::rename(&path, &original).unwrap();
        create_test_file_link(&target, &path);
        // Only the atomic open/handle check, not the earlier path observation,
        // determines whether the final entry can supply credential bytes.
        let error = AdminTokenSource::File(path.clone()).load().unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenNotRegularFile);
        assert!(!error.to_string().contains(SECRET));
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    }

    #[cfg(windows)]
    #[test]
    fn opened_windows_reparse_handle_is_rejected_before_reading() {
        use std::os::windows::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.txt");
        let link = directory.path().join("link.txt");
        fs::write(&target, SECRET).unwrap();
        create_test_file_link(&target, &link);
        let file = open_no_follow(&link).unwrap();
        assert_ne!(file.metadata().unwrap().file_attributes() & 0x0000_0400, 0);
        assert_eq!(
            validate_opened_file(file).unwrap_err(),
            BinaryError::AdminTokenNotRegularFile
        );
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_token_source_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("admin-symlink-target.txt");
        let link = directory.path().join("admin-symlink.txt");
        fs::write(&target, SECRET).unwrap();
        symlink(&target, &link).unwrap();

        let error = AdminTokenSource::File(link.clone()).load().unwrap_err();
        assert_eq!(error, BinaryError::AdminTokenNotRegularFile);
        assert!(!error.to_string().contains(SECRET));
        assert!(!error.to_string().contains(link.to_string_lossy().as_ref()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_symbolic_link_token_source_is_rejected_when_supported() {
        use std::os::windows::fs::symlink_file;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("admin-windows-symlink-target.txt");
        let link = directory.path().join("admin-windows-symlink.txt");
        fs::write(&target, SECRET).unwrap();
        if symlink_file(&target, &link).is_ok() {
            let error = AdminTokenSource::File(link.clone()).load().unwrap_err();
            assert_eq!(error, BinaryError::AdminTokenNotRegularFile);
            assert!(!error.to_string().contains(SECRET));
            assert!(!error.to_string().contains(link.to_string_lossy().as_ref()));
        }
    }
}
