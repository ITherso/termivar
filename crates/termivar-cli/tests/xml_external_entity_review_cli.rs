//! Focused actual-process preflight acceptance for XML external-entity review.
//!
//! Full owned target/provider execution belongs to the runtime acceptance slice.
//! These tests lock the CLI authority and policy-before-secret/output/network
//! ordering without contacting a provider or interpreting XML.

#![cfg(feature = "xml-external-entity-review")]

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn termivar() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(key);
    }
    command.env("NO_PROXY", "127.0.0.1,localhost");
    command.env("no_proxy", "127.0.0.1,localhost");
    command
}

fn run(arguments: &[&str]) -> Output {
    termivar()
        .args(arguments)
        .output()
        .expect("termivar process must start")
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary path must be Unicode")
}

fn private_path(directory: &Path, name: &str) -> PathBuf {
    directory.join(name)
}

fn production_policy(endpoint: &str) -> String {
    format!(
        "schema = \"security.xml-external-entity-review-policy/v1\"\n\
endpoint = \"{endpoint}\"\n\
provider_origin = \"https://oast.example.test/\"\n\
method = \"POST\"\n\
media_type = \"application/xml; charset=utf-8\"\n\
acknowledge_xml_post = true\n\
acknowledge_external_interaction = true\n\
acknowledge_disposable_test_endpoint = true\n\
polls_per_leg = 1\n\
poll_interval_ms = 250\n\
lifetime_ms = 5000\n"
    )
}

#[test]
fn help_exposes_only_explicit_policy_and_out_of_argv_secret_sources() {
    let output = run(&["scan", "--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("help must be UTF-8");
    for option in [
        "--xml-external-entity-review",
        "--xml-external-entity-policy",
        "--oast-admin-token-env",
        "--oast-admin-token-file",
        "--oast-admin-token-stdin",
    ] {
        assert!(help.contains(option), "scan help omitted {option}");
    }
    assert!(!help.contains("--oast-admin-token <"));
    assert!(!help.contains("--xml-body"));
    assert!(!help.contains("--xml-file"));
    assert!(!help.contains("--external-entity-url"));
}

#[test]
fn baseline_rejection_precedes_policy_secret_output_and_network_access() {
    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let policy = private_path(temporary.path(), "PRIVATE-XML-POLICY-MUST-NOT-OPEN");
    let administrator = private_path(temporary.path(), "PRIVATE-OAST-ADMINISTRATOR-MUST-NOT-OPEN");
    let report = private_path(temporary.path(), "PRIVATE-REPORT-MUST-NOT-RESERVE");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind network tripwire");
    listener
        .set_nonblocking(true)
        .expect("make network tripwire nonblocking");
    let target = format!("http://{}/", listener.local_addr().unwrap());

    let output = run(&[
        "scan",
        "--profile",
        "baseline",
        "--xml-external-entity-review",
        "--xml-external-entity-policy",
        path_text(&policy),
        "--oast-admin-token-file",
        path_text(&administrator),
        "--report-dir",
        path_text(&report),
        &target,
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
    assert!(stderr.contains("XML external-entity review requires `--profile web-review`"));
    assert!(!stderr.contains("PRIVATE-XML-POLICY"));
    assert!(!stderr.contains("PRIVATE-OAST-ADMINISTRATOR"));
    assert!(!stderr.contains("PRIVATE-REPORT"));
    assert!(!policy.exists());
    assert!(!administrator.exists());
    assert!(!report.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn invalid_policy_precedes_secret_output_and_network_access() {
    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let policy = private_path(temporary.path(), "PRIVATE-invalid-policy.toml");
    let administrator = private_path(temporary.path(), "PRIVATE-OAST-ADMINISTRATOR-MUST-NOT-OPEN");
    let report = private_path(temporary.path(), "PRIVATE-REPORT-MUST-NOT-RESERVE");
    fs::write(&policy, b"schema = [invalid-policy").expect("write invalid policy");
    let policy_before = fs::read(&policy).expect("snapshot policy bytes");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind network tripwire");
    listener
        .set_nonblocking(true)
        .expect("make network tripwire nonblocking");
    let target = format!("http://{}/", listener.local_addr().unwrap());

    let output = run(&[
        "scan",
        "--profile",
        "web-review",
        "--xml-external-entity-review",
        "--xml-external-entity-policy",
        path_text(&policy),
        "--oast-admin-token-file",
        path_text(&administrator),
        "--report-dir",
        path_text(&report),
        &target,
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
    assert!(stderr.contains("InvalidPolicy"));
    assert!(!stderr.contains("PRIVATE-invalid-policy"));
    assert!(!stderr.contains("PRIVATE-OAST-ADMINISTRATOR"));
    assert!(!stderr.contains("PRIVATE-REPORT"));
    assert_eq!(fs::read(&policy).unwrap(), policy_before);
    assert!(!administrator.exists());
    assert!(!report.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn normalized_policy_endpoint_is_rejected_before_secret_and_output_access() {
    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let policy = private_path(temporary.path(), "PRIVATE-normalized-endpoint-policy.toml");
    let administrator = private_path(temporary.path(), "PRIVATE-OAST-ADMIN-MUST-NOT-OPEN");
    let report = private_path(temporary.path(), "PRIVATE-REPORT-MUST-NOT-RESERVE");
    fs::write(
        &policy,
        production_policy("https://app.example.test/application/fixtures/safe/%2e%2e/xml-parser"),
    )
    .expect("write authority-mutation policy");

    let output = run(&[
        "scan",
        "--profile",
        "web-review",
        "--xml-external-entity-review",
        "--xml-external-entity-policy",
        path_text(&policy),
        "--oast-admin-token-file",
        path_text(&administrator),
        "--report-dir",
        path_text(&report),
        "https://app.example.test/application/",
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
    assert!(stderr.contains("InvalidPolicy"));
    for private in [
        "PRIVATE-normalized-endpoint-policy",
        "PRIVATE-OAST-ADMIN",
        "PRIVATE-REPORT",
        "%2e%2e",
    ] {
        assert!(!stderr.contains(private));
    }
    assert!(!administrator.exists());
    assert!(!report.exists());
}

#[test]
fn invalid_administrator_value_cleans_reserved_output_and_remains_redacted() {
    const SECRET_SENTINEL: &str = "XML-OAST-ADMIN-SECRET MUST NOT LEAK";

    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let policy = private_path(temporary.path(), "PRIVATE-valid-policy.toml");
    let administrator = private_path(temporary.path(), "PRIVATE-invalid-administrator.txt");
    let report = private_path(temporary.path(), "PRIVATE-REPORT-MUST-CLEAN");
    fs::write(
        &policy,
        production_policy("https://app.example.test/application/fixtures/xml-parser"),
    )
    .expect("write valid policy");
    fs::write(&administrator, SECRET_SENTINEL).expect("write invalid administrator token");

    let output = run(&[
        "scan",
        "--profile",
        "web-review",
        "--xml-external-entity-review",
        "--xml-external-entity-policy",
        path_text(&policy),
        "--oast-admin-token-file",
        path_text(&administrator),
        "--report-dir",
        path_text(&report),
        "https://app.example.test/application/",
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
    assert!(stderr.contains("InvalidAdministratorValue"));
    for private in [
        SECRET_SENTINEL,
        "PRIVATE-valid-policy",
        "PRIVATE-invalid-administrator",
        "PRIVATE-REPORT",
    ] {
        assert!(!stderr.contains(private));
    }
    assert!(
        !report.exists(),
        "failed secret intake left reserved output"
    );
}

#[test]
fn selection_requires_one_admin_source_without_reading_policy_or_network() {
    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let policy = private_path(temporary.path(), "PRIVATE-XML-POLICY-MUST-NOT-OPEN");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind network tripwire");
    listener
        .set_nonblocking(true)
        .expect("make network tripwire nonblocking");
    let target = format!("http://{}/", listener.local_addr().unwrap());

    let output = run(&[
        "scan",
        "--profile",
        "web-review",
        "--xml-external-entity-review",
        "--xml-external-entity-policy",
        path_text(&policy),
        &target,
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
    assert!(stderr.contains("MissingAdministratorSource"));
    assert!(!stderr.contains("PRIVATE-XML-POLICY"));
    assert!(!policy.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn ambiguous_application_target_precedes_policy_secret_output_and_network_access() {
    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let policy = private_path(temporary.path(), "PRIVATE-XML-POLICY-MUST-NOT-OPEN");
    let administrator = private_path(temporary.path(), "PRIVATE-OAST-ADMIN-MUST-NOT-OPEN");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind network tripwire");
    listener
        .set_nonblocking(true)
        .expect("make network tripwire nonblocking");
    let authority = listener.local_addr().unwrap();

    for (index, target) in [
        format!("http://{authority}/application/./"),
        format!("http://{authority}/application/safe/../"),
        format!("http://{authority}/application/safe/%2e%2e/"),
        format!("http://{authority}/application/%2f/"),
        format!(r"http://{authority}/application\fixtures/"),
        format!("HTTP://{authority}/application/"),
    ]
    .into_iter()
    .enumerate()
    {
        let report = private_path(temporary.path(), &format!("PRIVATE-REPORT-{index}"));
        let output = run(&[
            "scan",
            "--profile",
            "web-review",
            "--xml-external-entity-review",
            "--xml-external-entity-policy",
            path_text(&policy),
            "--oast-admin-token-file",
            path_text(&administrator),
            "--report-dir",
            path_text(&report),
            &target,
        ]);

        assert!(
            !output.status.success(),
            "ambiguous target passed: {target}"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
        assert!(stderr.contains(
            "XML external-entity application target must use an unambiguous raw trailing-slash path"
        ));
        for private in ["PRIVATE-XML-POLICY", "PRIVATE-OAST-ADMIN", "PRIVATE-REPORT"] {
            assert!(!stderr.contains(private));
        }
        assert!(!report.exists());
    }

    assert!(!policy.exists());
    assert!(!administrator.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(windows)]
#[test]
fn remote_and_special_xml_file_sources_are_rejected_before_open_or_output_reservation() {
    let temporary = tempfile::tempdir().expect("create private temporary directory");
    let report = private_path(temporary.path(), "PRIVATE-REPORT-MUST-NOT-RESERVE");
    let local_policy = r"C:\termivar\PRIVATE-local-xml-policy-must-not-open.toml";
    let local_administrator = r"C:\termivar\PRIVATE-local-xml-admin-must-not-open.secret";

    for (policy, administrator, expected) in [
        (
            r"\\server\share\PRIVATE-remote-xml-policy.toml",
            local_administrator,
            "PolicySource(SourceUnavailable)",
        ),
        (
            local_policy,
            r"\\.\pipe\PRIVATE-termivar-xml-administrator",
            "AdministratorSource(SourceUnavailable)",
        ),
        (
            local_policy,
            r"C:\termivar\PRIVATE-xml-administrator.secret:stream",
            "AdministratorSource(SourceUnavailable)",
        ),
    ] {
        let output = run(&[
            "scan",
            "--profile",
            "web-review",
            "--xml-external-entity-review",
            "--xml-external-entity-policy",
            policy,
            "--oast-admin-token-file",
            administrator,
            "--report-dir",
            path_text(&report),
            "https://app.example.test/application/",
        ]);

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
        assert!(stderr.contains(expected));
        for private in [
            "PRIVATE-remote",
            "PRIVATE-local",
            "PRIVATE-termivar",
            "PRIVATE-REPORT",
        ] {
            assert!(!stderr.contains(private));
        }
        assert!(!report.exists());
    }
}
