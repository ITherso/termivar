//! Process-level contracts for explicitly selected deterministic scan profiles.
//!
//! Every network interaction stays on an in-process loopback fixture. These
//! tests keep the no-profile compatibility schema separate from the additive
//! profile schema and verify fail-closed, redacted exact-origin behavior.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn venom() -> Command {
    Command::new(env!("CARGO_BIN_EXE_venom"))
}

struct TestServer {
    url: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

fn serve<F>(handler: F) -> TestServer
where
    F: Fn(&str) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_connections = Arc::clone(&connections);
    let thread_requests = Arc::clone(&requests);
    let handler = Arc::new(handler);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            thread_connections.fetch_add(1, Ordering::SeqCst);
            handle_connection(&mut stream, handler.as_ref(), thread_requests.as_ref());
        }
    });

    TestServer {
        url: format!("http://{address}/"),
        connections,
        requests,
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    handler: &(dyn Fn(&str) -> Vec<u8> + Send + Sync),
    requests: &Mutex<Vec<String>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0_u8; 16 * 1024];
    let bytes_read = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    requests.lock().unwrap().push(target.clone());
    let response = handler(&target);
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

fn ok_html(body: &str, extra_headers: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn parse_stdout(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must be one complete JSON document ({error}):\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn no_profile_preserves_decision_scan_v1() {
    let server = serve(|_| ok_html("hello", ""));
    let output = venom()
        .args(["scan", "--format", "json", &server.url])
        .output()
        .expect("failed to run venom");

    assert!(
        output.status.success(),
        "unexpected exit status: {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_stdout(&output);
    assert_eq!(value["schema_version"], "decision-scan/v1");
    assert!(value.get("profile_contract").is_none());
    assert!(value.get("assessment").is_none());
}

#[test]
fn explicit_profiles_emit_the_additive_schema_and_exact_scope() {
    let server = serve(|_| ok_html("hello", ""));
    for (profile, scope) in [
        ("baseline", "single-resource"),
        ("web-review", "exact-origin"),
    ] {
        let output = venom()
            .args([
                "scan",
                "--profile",
                profile,
                "--format",
                "json",
                &server.url,
            ])
            .output()
            .expect("failed to run venom");

        assert!(
            output.status.success(),
            "profile {profile} failed with {:?}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let value = parse_stdout(&output);
        assert_eq!(value["schema_version"], "web-assessment/v1");
        assert_eq!(value["disposition"], "complete");
        assert_eq!(value["profile_contract"]["schema"], "venom.scan-profile/v1");
        assert_eq!(value["profile_contract"]["profile"], profile);
        assert_eq!(value["profile_contract"]["scope"], scope);
        assert_eq!(value["assessment"]["scope"], scope);
        assert_eq!(
            value["profile_contract"]["defense"]["enforcement_enabled"],
            false
        );
    }
}

#[test]
fn profile_conflicts_fail_before_connection_or_output() {
    let server = serve(|_| ok_html("must not be requested", ""));
    for arguments in [
        vec![
            "scan",
            "--profile",
            "baseline",
            "--enforce-defense",
            &server.url,
        ],
        vec!["scan", "--profile", "web-review", "--explain", &server.url],
    ] {
        let output = venom()
            .args(arguments)
            .output()
            .expect("failed to run venom");
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "a rejected profile invocation emitted output:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--profile"),
            "conflict must identify the profile boundary:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        0,
        "profile conflicts must be rejected before network dispatch"
    );
}

#[test]
fn web_review_is_exact_origin_bounded_parseable_and_value_redacted() {
    const QUERY_VALUE: &str = "CLI_QUERY_VALUE_SECRET";
    const LINK_VALUE: &str = "CLI_LINK_VALUE_SECRET";
    const FORM_VALUE: &str = "CLI_FORM_VALUE_SECRET";
    const PATH_VALUE: &str = "CLI_PATH_VALUE_SECRET";
    const FORM_PATH_VALUE: &str = "CLI_FORM_PATH_VALUE_SECRET";
    const CREDENTIAL_VALUE: &str = "CLI_CREDENTIAL_VALUE_SECRET";
    const COOKIE_VALUE: &str = "CLI_COOKIE_VALUE_SECRET";
    const OUTSIDE_VALUE: &str = "CLI_OUTSIDE_VALUE_SECRET";

    let outside = serve(|_| ok_html("outside", ""));
    let outside_reference = format!("{}outside?leak={OUTSIDE_VALUE}", outside.url);
    let root_html = format!(concat!(
        "<html><body>",
        "<a href=\"/reset/{PATH_VALUE}?token={LINK_VALUE}\">child</a>",
        "<a href=\"{outside_reference}\">outside</a>",
        "<form method=\"get\" action=\"/submit/{FORM_PATH_VALUE}?next={FORM_VALUE}\">",
        "<input name=\"authorization\" value=\"{CREDENTIAL_VALUE}\">",
        "<input name=\"password\" value=\"{CREDENTIAL_VALUE}\">",
        "</form></body></html>"
    ));
    let inside = serve(move |target| {
        if target.split('?').next() == Some("/") {
            ok_html(
                &root_html,
                "Set-Cookie: session=CLI_COOKIE_VALUE_SECRET; HttpOnly\r\n",
            )
        } else {
            ok_html("child", "")
        }
    });
    let query = (0..65)
        .map(|index| format!("parameter_{index:02}={QUERY_VALUE}"))
        .collect::<Vec<_>>()
        .join("&");
    let target = format!("{}?{query}", inside.url);

    let output = venom()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            &target,
        ])
        .output()
        .expect("failed to run venom");

    assert!(
        !output.status.success(),
        "a bounded incomplete assessment must exit nonzero"
    );
    let value = parse_stdout(&output);
    assert_eq!(value["schema_version"], "web-assessment/v1");
    assert_eq!(value["disposition"], "incomplete");
    assert_eq!(value["assessment"]["scope"], "exact-origin");
    assert!(value["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str() == Some("query_parameter_name_limit")));

    let subjects = value["assessment"]["report"]["subjects"]
        .as_array()
        .unwrap();
    assert!(subjects.len() >= 3, "same-origin routes were not retained");
    assert_eq!(subjects[0]["subject_reference"], "subject-0000");
    assert!(subjects.iter().enumerate().all(|(index, subject)| {
        subject["subject_reference"] == format!("subject-{index:04}")
            && subject.get("canonical_url").is_none()
    }));
    assert!(subjects.iter().any(|subject| {
        subject["query_parameter_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some("token")))
    }));
    assert!(subjects.iter().any(|subject| {
        subject["query_parameter_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some("next")))
    }));
    let forms = value["assessment"]["report"]["forms"].as_array().unwrap();
    assert!(forms.iter().any(|form| {
        form["form_reference"] == "form-0000"
            && form.get("document_url").is_none()
            && form.get("action_url").is_none()
            && form["control_names"].as_array().is_some_and(|names| {
                names
                    .iter()
                    .any(|name| name.as_str() == Some("authorization"))
            })
    }));
    assert_eq!(
        outside.connections.load(Ordering::SeqCst),
        0,
        "cross-origin discovery must never dispatch"
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("profiled assessment did not complete within its authority"),
        "nonzero status must follow the complete JSON document:\n{stderr}"
    );
    for secret in [
        QUERY_VALUE,
        LINK_VALUE,
        FORM_VALUE,
        PATH_VALUE,
        FORM_PATH_VALUE,
        CREDENTIAL_VALUE,
        COOKIE_VALUE,
        OUTSIDE_VALUE,
    ] {
        assert!(!stdout.contains(secret), "stdout leaked {secret}");
        assert!(!stderr.contains(secret), "stderr leaked {secret}");
    }
    assert!(!stdout.contains(&outside.url));

    let dispatched_targets = inside.requests.lock().unwrap();
    assert!(dispatched_targets
        .iter()
        .any(|request| request.contains(PATH_VALUE)));
    assert!(dispatched_targets
        .iter()
        .any(|request| request.contains(FORM_PATH_VALUE)));
    assert!(dispatched_targets.iter().all(|request| {
        !request.contains(QUERY_VALUE)
            && !request.contains(LINK_VALUE)
            && !request.contains(FORM_VALUE)
            && !request.contains(CREDENTIAL_VALUE)
            && !request.contains(COOKIE_VALUE)
    }));
}
