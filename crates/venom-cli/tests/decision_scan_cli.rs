//! Process-level contract tests for `venom decision-scan`, exercising the real
//! compiled binary (stdout/stderr/exit code), not just the render functions.
//!
//! These assert the machine-consumption contract: JSON goes to stdout with no
//! warning contamination, the preview warning goes to stderr, the default and
//! explicit-`text` outputs agree, and `--format json --explain` is rejected
//! fail-fast without contacting the target.

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
fn json_format_writes_parseable_json_to_stdout_and_the_warning_to_stderr() {
    let server = serve(BASIC_CHALLENGE);
    let output = venom()
        .args(["decision-scan", "--format", "json", &server.url])
        .output()
        .expect("failed to run venom");

    assert!(output.status.success(), "exit status: {:?}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    // stdout is pure JSON — the preview warning never contaminates it.
    assert!(
        !stdout.contains("[PREVIEW]"),
        "stdout leaked the preview warning:\n{stdout}"
    );
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(value["schema_version"], "decision-scan/v1");
    assert_eq!(value["hypotheses"][0]["value"], "http-basic");

    // The preview warning is on stderr.
    assert!(
        stderr.contains("[PREVIEW]"),
        "stderr must carry the preview warning:\n{stderr}"
    );
}

#[test]
fn json_with_explain_is_rejected_and_contacts_no_target() {
    let server = serve(GENERIC_OK);
    let output = venom()
        .args([
            "decision-scan",
            "--format",
            "json",
            "--explain",
            &server.url,
        ])
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

#[test]
fn explicit_text_format_matches_the_default_output() {
    // Both runs hit the SAME server (same origin); only the elapsed time differs,
    // which is normalized away before the byte comparison.
    let server = serve(GENERIC_OK);
    let default = venom()
        .args(["decision-scan", &server.url])
        .output()
        .expect("failed to run venom");
    let text = venom()
        .args(["decision-scan", "--format", "text", &server.url])
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
