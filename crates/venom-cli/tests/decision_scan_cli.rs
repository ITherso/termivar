//! Process-level contract tests for deterministic `venom scan`, exercising the real
//! compiled binary (stdout/stderr/exit code), not just the render functions.
//!
//! These assert the machine-consumption contract: JSON goes to stdout with no
//! warning contamination, runtime notices go to stderr, the deprecated
//! `decision-scan` alias executes the same behavior, and invalid flag combinations
//! are rejected before contacting a target.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

fn venom() -> Command {
    Command::new(env!("CARGO_BIN_EXE_venom"))
}

/// A local server that replies to every connection with a fixed response and
/// counts the connections it accepted. The accept loop is a detached thread that
/// ends when the process exits.
struct TestServer {
    url: String,
    connections: Arc<AtomicUsize>,
}

fn serve(response: &'static [u8]) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(_) => break,
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(response);
            let _ = stream.flush();
        }
    });
    TestServer {
        url: format!("http://{address}/"),
        connections,
    }
}

const BASIC_CHALLENGE: &[u8] =
    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const GENERIC_OK: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

#[test]
fn json_format_writes_parseable_json_to_stdout_and_the_runtime_notice_to_stderr() {
    let server = serve(BASIC_CHALLENGE);
    let output = venom()
        .args(["scan", "--format", "json", &server.url])
        .output()
        .expect("failed to run venom");

    assert!(output.status.success(), "exit status: {:?}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    // stdout is pure JSON — the preview warning never contaminates it.
    assert!(
        !stdout.contains("[ALPHA]"),
        "stdout leaked the runtime notice:\n{stdout}"
    );
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(value["schema_version"], "decision-scan/v1");
    assert_eq!(value["hypotheses"][0]["value"], "http-basic");

    // The alpha/authorization notice is on stderr.
    assert!(
        stderr.contains("[ALPHA]") && stderr.contains("authorized"),
        "stderr must carry the runtime notice:\n{stderr}"
    );
    assert!(!stderr.contains("[DEPRECATED]"));
}

#[test]
fn json_with_explain_is_rejected_and_contacts_no_target() {
    let server = serve(GENERIC_OK);
    let output = venom()
        .args(["scan", "--format", "json", "--explain", &server.url])
        .output()
        .expect("failed to run venom");

    // Fail-fast: non-zero exit with an argument-conflict diagnostic.
    assert!(
        !output.status.success(),
        "the invalid combination must exit non-zero"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--explain") && stderr.to_lowercase().contains("json"),
        "expected an argument-conflict diagnostic naming both flags:\n{stderr}"
    );
    // The conflict is caught before dispatch — the target is never contacted.
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        0,
        "a rejected invocation must perform zero dispatches"
    );
}

#[cfg(feature = "legacy-scanner")]
#[test]
fn legacy_scan_without_acknowledgement_is_rejected_before_network_io() {
    let server = serve(GENERIC_OK);
    let output = venom()
        .args(["legacy-scan", &server.url])
        .output()
        .expect("failed to run venom");

    assert!(
        !output.status.success(),
        "missing acknowledgement must exit non-zero"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--acknowledge-legacy-heuristics"),
        "the diagnostic must name the required acknowledgement:\n{stderr}"
    );
    assert!(
        stdout.is_empty(),
        "a rejected invocation must not render scan output:\n{stdout}"
    );
    assert!(
        !stderr.contains("ordered CLI phase pipeline"),
        "the runtime warning would show that dispatch was entered:\n{stderr}"
    );
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        0,
        "a rejected legacy invocation must perform zero dispatches"
    );
}

#[cfg(feature = "api-adapter")]
#[test]
fn unsupported_api_adapter_exits_nonzero_without_fake_startup_success() {
    let output = venom()
        .args(["api", "--addr", "[::1]:8080"])
        .output()
        .expect("failed to run venom");

    assert!(
        !output.status.success(),
        "the unsupported listener adapter must exit non-zero"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stdout.is_empty(),
        "unsupported startup must not print a success message:\n{stdout}"
    );
    assert!(
        stderr.contains("unsupported") && stderr.contains("did not bind [::1]:8080"),
        "stderr must state that no listener was bound:\n{stderr}"
    );
    let stderr_lower = stderr.to_lowercase();
    assert!(
        !stderr_lower.contains("starting api")
            && !stderr_lower.contains("api started")
            && !stderr_lower.contains("listening on"),
        "unsupported startup must not claim listener success:\n{stderr}"
    );
}

#[test]
fn explicit_text_format_matches_the_default_output() {
    // Both runs hit the SAME server (same origin); only the elapsed time differs,
    // which is normalized away before the byte comparison.
    let server = serve(GENERIC_OK);
    let default = venom()
        .args(["scan", &server.url])
        .output()
        .expect("failed to run venom");
    let text = venom()
        .args(["scan", "--format", "text", &server.url])
        .output()
        .expect("failed to run venom");

    assert!(default.status.success() && text.status.success());
    let normalize = |bytes: Vec<u8>| {
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| match line.find(" elapsed_ms=") {
                Some(index) => line[..index].to_string(),
                None => line.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        normalize(default.stdout),
        normalize(text.stdout),
        "explicit --format text must match the default output"
    );
}

#[test]
fn deprecated_alias_produces_the_same_json_as_scan() {
    let server = serve(GENERIC_OK);
    let primary = venom()
        .args(["scan", "--format", "json", &server.url])
        .output()
        .expect("failed to run primary scan");
    let alias = venom()
        .args(["decision-scan", "--format", "json", &server.url])
        .output()
        .expect("failed to run compatibility alias");

    assert!(primary.status.success() && alias.status.success());
    let mut primary_json: serde_json::Value = serde_json::from_slice(&primary.stdout).unwrap();
    let mut alias_json: serde_json::Value = serde_json::from_slice(&alias.stdout).unwrap();
    primary_json["usage"]["elapsed_ms"] = serde_json::json!(0);
    alias_json["usage"]["elapsed_ms"] = serde_json::json!(0);
    assert_eq!(primary_json, alias_json);

    let primary_stderr = String::from_utf8(primary.stderr).unwrap();
    let alias_stderr = String::from_utf8(alias.stderr).unwrap();
    assert!(!primary_stderr.contains("[DEPRECATED]"));
    assert!(alias_stderr.contains("[DEPRECATED]"));
    assert!(alias_stderr.contains("same deterministic engine"));
}

#[test]
fn help_exposes_primary_product_and_only_enabled_optional_commands() {
    let output = venom().arg("--help").output().expect("failed to run help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout
        .lines()
        .any(|line| line.trim_start().starts_with("scan ")));
    let has_command = |name: &str| {
        stdout
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("{name} ")))
    };
    assert_eq!(has_command("legacy-scan"), cfg!(feature = "legacy-scanner"));
    assert_eq!(has_command("api"), cfg!(feature = "api-adapter"));
    assert_eq!(has_command("proxy"), cfg!(feature = "proxy-adapter"));
    assert!(
        stdout.contains("decision-scan"),
        "deprecated alias should remain discoverable"
    );
}
