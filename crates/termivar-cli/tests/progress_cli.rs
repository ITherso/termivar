//! Actual-process contracts for opt-in live assessment progress.
//!
//! Every request remains on a test-owned numeric-loopback fixture. Progress is
//! observed on stderr while the first response is deliberately held, proving
//! that the presentation is live rather than a replay of a final report.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const PROGRESS_PREFIX: &str = "[progress]";
const MAX_PROGRESS_LINE_BYTES: usize = 512;
const MAX_PROGRESS_BYTES: usize = 64 * 1024;

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

struct FixtureServer {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn serve_html() -> FixtureServer {
    serve_html_with_pause(None, None)
}

fn serve_html_with_pause(
    request_seen: Option<mpsc::Sender<()>>,
    release: Option<mpsc::Receiver<()>>,
) -> FixtureServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
    let address: SocketAddr = listener.local_addr().expect("fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        let mut first = true;
        let mut release = release;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let request = read_request_identity(&mut stream);
            recorded.lock().unwrap().push(request);
            if first {
                first = false;
                if let Some(request_seen) = &request_seen {
                    let _ = request_seen.send(());
                }
                if let Some(release) = release.take() {
                    let _ = release.recv_timeout(Duration::from_secs(10));
                }
            }
            write_html_response(&mut stream);
        }
    });
    FixtureServer {
        origin: format!("http://{address}/"),
        requests,
    }
}

fn read_request_identity(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut bytes = [0_u8; 16 * 1024];
    let read = stream.read(&mut bytes).unwrap_or(0);
    let request = String::from_utf8_lossy(&bytes[..read]);
    let line = request.lines().next().unwrap_or("GET /");
    let mut fields = line.split_ascii_whitespace();
    format!(
        "{} {}",
        fields.next().unwrap_or("GET"),
        fields.next().unwrap_or("/")
    )
}

fn write_html_response(stream: &mut TcpStream) {
    const BODY: &str = "<main>bounded progress fixture</main>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn spawn_progress_json(origin: &str) -> Child {
    termivar()
        .args([
            "scan",
            origin,
            "--profile",
            "web-review",
            "--format",
            "json",
            "--progress",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn development CLI")
}

fn progress_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.starts_with(PROGRESS_PREFIX))
        .collect()
}

fn assert_bounded_private_progress(stderr: &str, private_values: &[&str]) {
    let lines = progress_lines(stderr);
    assert!(!lines.is_empty(), "expected progress lines in:\n{stderr}");
    let bytes = lines.iter().map(|line| line.len() + 1).sum::<usize>();
    assert!(bytes <= MAX_PROGRESS_BYTES);
    for line in lines {
        assert!(line.is_ascii());
        assert!(line.len() < MAX_PROGRESS_LINE_BYTES);
        for private in private_values {
            assert!(!line.contains(private), "progress leaked a private value");
        }
    }
}

fn claim_projection(items: &serde_json::Value) -> serde_json::Value {
    let mut items = items.as_array().expect("assessment items").clone();
    for item in &mut items {
        let object = item.as_object_mut().expect("assessment item object");
        for report_local_reference in [
            "subject_reference",
            "evidence_references",
            "control_evidence_references",
            "candidate_evidence_references",
            "case_reference",
            "outcome_reference",
        ] {
            object.remove(report_local_reference);
        }
    }
    serde_json::Value::Array(items)
}

fn numeric_progress_field(line: &str, key: &str) -> u64 {
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(key))
        .expect("progress field")
        .parse()
        .expect("numeric progress field")
}

fn optional_numeric_progress_field(line: &str, key: &str) -> Option<u64> {
    let value = line
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(key))
        .expect("progress field");
    (value != "unknown").then(|| value.parse().expect("numeric progress field"))
}

fn assert_progress_values_never_regress(lines: &[&str], key: &str) {
    let observed = lines
        .iter()
        .map(|line| optional_numeric_progress_field(line, key))
        .collect::<Vec<_>>();
    if let Some(first_known) = observed.iter().position(Option::is_some) {
        assert!(
            observed[first_known..].iter().all(Option::is_some),
            "progress field {key} regressed from known to unknown: {observed:?}"
        );
    }
    let values = observed.into_iter().flatten().collect::<Vec<_>>();
    assert!(
        values.windows(2).all(|pair| pair[0] <= pair[1]),
        "progress field {key} regressed: {values:?}"
    );
}

fn assert_completed_stdout_lifecycle(lines: &[&str]) {
    let states = lines
        .iter()
        .map(|line| {
            line.split_ascii_whitespace()
                .find_map(|field| field.strip_prefix("state="))
                .expect("progress state")
        })
        .collect::<Vec<_>>();
    let running = states
        .iter()
        .take_while(|state| **state == "assessment_running")
        .count();
    assert!(running > 0, "missing initial running state: {states:?}");
    assert_eq!(
        &states[running..],
        [
            "composing_report",
            "rendering_report",
            "writing_stdout",
            "completed",
        ],
        "progress lifecycle regressed or repeated: {states:?}"
    );
}

fn assert_failed_terminal(stderr: &str, expected_forward_state: &str) {
    let lines = progress_lines(stderr);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("state={expected_forward_state}"))),
        "missing {expected_forward_state} transition:\n{stderr}"
    );
    assert!(
        lines
            .last()
            .is_some_and(|line| line.contains("state=failed")),
        "failure was not the final progress state:\n{stderr}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("state=failed"))
            .count(),
        1,
        "failure terminal repeated:\n{stderr}"
    );
    assert!(
        lines.iter().all(|line| !line.contains("state=completed")),
        "failed output path announced completion:\n{stderr}"
    );
}

#[test]
fn progress_is_observable_while_analyze_is_still_in_flight_and_stdout_stays_json() {
    let (seen_tx, seen_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = serve_html_with_pause(Some(seen_tx), Some(release_rx));
    let mut child = spawn_progress_json(&server.origin);
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout).read_to_end(&mut bytes).unwrap();
        bytes
    });
    let (line_tx, line_rx) = mpsc::channel();
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut reader = BufReader::new(stderr);
        loop {
            let start = bytes.len();
            if reader.read_until(b'\n', &mut bytes).unwrap() == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&bytes[start..]).into_owned();
            let _ = line_tx.send(line);
        }
        bytes
    });

    seen_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("first fixture request must start");
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut lines_before_release = Vec::new();
    let live_line = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = line_rx
            .recv_timeout(remaining)
            .expect("live progress line before fixture release");
        lines_before_release.push(line.clone());
        if line.contains("state=assessment_running")
            && line.contains("subjects_started=1")
            && line.contains("counts=last_observed")
        {
            break line;
        }
    };
    assert!(live_line.contains("accounted_requests="));
    assert!(numeric_progress_field(&live_line, "elapsed_ms=") > 0);
    assert!(lines_before_release.iter().any(|line| {
        line.contains("state=assessment_running")
            && line.contains("accounted_requests=unknown")
            && line.contains("subjects_started=unknown")
    }));
    assert!(child.try_wait().unwrap().is_none(), "scan already finished");
    release_tx
        .send(())
        .expect("release paused fixture response");

    let status = child.wait().expect("wait for development CLI");
    let stdout = stdout_reader.join().unwrap();
    let stderr = String::from_utf8(stderr_reader.join().unwrap()).unwrap();
    assert!(status.success(), "scan failed:\n{stderr}");
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must remain one JSON document ({error}):\n{}",
            String::from_utf8_lossy(&stdout)
        )
    });
    assert_eq!(report["schema"], "venom-rendered-assessment/v1");
    assert_eq!(report["status"], "complete");
    let progress = progress_lines(&stderr);
    assert_completed_stdout_lifecycle(&progress);
    let terminal = progress.last().unwrap();
    assert!(terminal.contains("state=completed"));
    assert_eq!(numeric_progress_field(terminal, "accounted_requests="), 3);
    let active = numeric_progress_field(terminal, "accounted_active_verifications=");
    let started = numeric_progress_field(terminal, "subjects_started=");
    let processed = numeric_progress_field(terminal, "subjects_processed=");
    assert_eq!(
        active, 0,
        "the inert HTML fixture charges no active verification"
    );
    assert_eq!(started, 1, "the fixture executes exactly one root subject");
    assert_eq!(
        processed, 1,
        "the fixture commits exactly one subject state"
    );
    for key in [
        "elapsed_ms=",
        "accounted_requests=",
        "accounted_active_verifications=",
        "subjects_started=",
        "subjects_processed=",
    ] {
        assert_progress_values_never_regress(&progress, key);
    }
    assert_bounded_private_progress(&stderr, &[&server.origin, "127.0.0.1"]);
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        ["GET /", "GET /", "GET /"],
        "progress must not add a fixture request"
    );
}

#[test]
fn progress_requires_explicit_web_review_before_any_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    for args in [
        vec!["scan", &origin, "--progress"],
        vec!["scan", &origin, "--profile", "baseline", "--progress"],
        vec!["decision-scan", &origin, "--progress"],
    ] {
        let output = termivar().args(args).output().expect("run invalid CLI");
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--profile") || stderr.contains("web-review"));
        assert!(!stderr.contains(PROGRESS_PREFIX));
    }
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn progress_bundle_stays_off_stdout_and_offline_consumers_add_no_requests() {
    let server = serve_html();
    let parent = tempfile::tempdir().unwrap();
    let bundle = parent.path().join("progress-bundle");
    let output = termivar()
        .arg("scan")
        .arg(&server.origin)
        .args(["--profile", "web-review", "--progress", "--report-dir"])
        .arg(&bundle)
        .output()
        .expect("run progress bundle");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "bundle failed:\n{stderr}");
    assert!(output.stdout.is_empty());
    assert!(progress_lines(&stderr)
        .iter()
        .any(|line| line.contains("state=publishing_report")));
    assert!(progress_lines(&stderr)
        .last()
        .unwrap()
        .contains("state=completed"));
    assert_bounded_private_progress(&stderr, &[&server.origin, &parent.path().to_string_lossy()]);
    let mut names = fs::read_dir(&bundle)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["assessment.html", "assessment.json", "manifest.json"]
    );
    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(requests_after_scan, ["GET /", "GET /", "GET /"]);

    let verified = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .output()
        .expect("verify progress bundle");
    assert!(verified.status.success());
    assert!(verified.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap()["status"],
        "integrity_match"
    );

    let assessment = bundle.join("assessment.json");
    let compared = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment)
        .arg("--after")
        .arg(&assessment)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("self-compare progress bundle");
    assert!(compared.status.success());
    assert!(compared.stderr.is_empty());
    let compared: serde_json::Value = serde_json::from_slice(&compared.stdout).unwrap();
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(compared[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        compared["unchanged"].as_array().unwrap().len(),
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(bundle.join("assessment.json")).unwrap()
        )
        .unwrap()["item_count"]
            .as_u64()
            .unwrap() as usize
    );
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline report commands must not contact the fixture"
    );
}

#[test]
fn progress_off_and_on_preserve_request_and_claim_projection() {
    let server = serve_html();
    let without_started = Instant::now();
    let without = termivar()
        .args([
            "scan",
            &server.origin,
            "--profile",
            "web-review",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let without_elapsed = without_started.elapsed();
    let with_started = Instant::now();
    let with = termivar()
        .args([
            "scan",
            &server.origin,
            "--profile",
            "web-review",
            "--format",
            "json",
            "--progress",
        ])
        .output()
        .unwrap();
    let with_elapsed = with_started.elapsed();
    assert!(without.status.success());
    assert!(with.status.success());
    let without_json: serde_json::Value = serde_json::from_slice(&without.stdout).unwrap();
    let with_json: serde_json::Value = serde_json::from_slice(&with.stdout).unwrap();
    for field in ["schema", "profile", "status", "subject_count", "item_count"] {
        assert_eq!(
            without_json[field], with_json[field],
            "changed field {field}"
        );
    }
    assert_eq!(
        claim_projection(&without_json["items"]),
        claim_projection(&with_json["items"]),
        "progress must not change claim identity or content; report-local references may be renumbered"
    );
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        ["GET /", "GET /", "GET /", "GET /", "GET /", "GET /"]
    );
    assert!(!String::from_utf8_lossy(&without.stderr).contains(PROGRESS_PREFIX));
    let stderr = String::from_utf8(with.stderr).unwrap();
    assert_bounded_private_progress(&stderr, &[&server.origin, "127.0.0.1"]);
    let lines = progress_lines(&stderr);
    let progress_bytes = lines.iter().map(|line| line.len() + 1).sum::<usize>();
    eprintln!(
        "controlled progress sample: off_elapsed_ms={} on_elapsed_ms={} requests_each=3 progress_lines={} progress_bytes={progress_bytes}",
        without_elapsed.as_millis(),
        with_elapsed.as_millis(),
        lines.len(),
    );
}

#[test]
fn stdout_write_failure_ends_progress_as_failed_without_changing_scan_work() {
    let server = serve_html();
    let mut child = spawn_progress_json(&server.origin);
    drop(child.stdout.take().expect("piped stdout"));

    let output = child
        .wait_with_output()
        .expect("wait for CLI with a closed stdout reader");
    assert!(
        !output.status.success(),
        "closed stdout unexpectedly succeeded"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_failed_terminal(&stderr, "writing_stdout");
    assert_bounded_private_progress(&stderr, &[&server.origin, "127.0.0.1"]);
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        ["GET /", "GET /", "GET /"],
        "stdout failure must neither restart nor skip completed assessment work"
    );
}

#[test]
fn in_flight_single_file_collision_reports_publication_failure_without_overwrite() {
    const FOREIGN_BYTES: &[u8] = b"FOREIGN_OUTPUT_DESTINATION";
    let (seen_tx, seen_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = serve_html_with_pause(Some(seen_tx), Some(release_rx));
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("colliding-report.json");
    let child = termivar()
        .arg("scan")
        .arg(&server.origin)
        .args([
            "--profile",
            "web-review",
            "--progress",
            "--report-format",
            "json",
            "--report-output",
        ])
        .arg(&destination)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn single-file progress scan");
    seen_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("assessment reached the paused fixture");
    fs::create_dir(&destination).expect("reserve colliding foreign destination");
    fs::write(destination.join("foreign.txt"), FOREIGN_BYTES)
        .expect("write foreign destination sentinel");
    release_tx.send(()).expect("release paused fixture");

    let output = child
        .wait_with_output()
        .expect("wait for failed publication");
    assert!(
        !output.status.success(),
        "colliding output unexpectedly succeeded"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_failed_terminal(&stderr, "publishing_report");
    assert_bounded_private_progress(&stderr, &[&server.origin, &parent.path().to_string_lossy()]);
    assert_eq!(
        fs::read(destination.join("foreign.txt")).unwrap(),
        FOREIGN_BYTES,
        "single-file publisher changed a foreign collision"
    );
    assert_eq!(
        fs::read_dir(&destination).unwrap().count(),
        1,
        "single-file failure left an unexpected partial artifact"
    );
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        ["GET /", "GET /", "GET /"],
        "single-file publication failure must not change or repeat scan requests"
    );
}

#[test]
fn in_flight_bundle_collision_reports_not_committed_and_preserves_foreign_file() {
    const FOREIGN_BYTES: &[u8] = b"FOREIGN_BUNDLE_DESTINATION";
    let (seen_tx, seen_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = serve_html_with_pause(Some(seen_tx), Some(release_rx));
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("colliding-bundle");
    let child = termivar()
        .arg("scan")
        .arg(&server.origin)
        .args(["--profile", "web-review", "--progress", "--report-dir"])
        .arg(&destination)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bundle progress scan");
    seen_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("assessment reached the paused fixture");
    assert!(
        destination.is_dir(),
        "bundle destination must already be exclusively reserved"
    );
    fs::write(destination.join("assessment.html"), FOREIGN_BYTES)
        .expect("write colliding foreign bundle member");
    release_tx.send(()).expect("release paused fixture");

    let output = child
        .wait_with_output()
        .expect("wait for failed publication");
    assert!(
        !output.status.success(),
        "colliding bundle unexpectedly succeeded"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_failed_terminal(&stderr, "publishing_report");
    let terminal = progress_lines(&stderr).last().copied().unwrap();
    assert!(terminal.contains("bundle_commit=not_committed"), "{stderr}");
    assert_bounded_private_progress(&stderr, &[&server.origin, &parent.path().to_string_lossy()]);
    assert_eq!(
        fs::read(destination.join("assessment.html")).unwrap(),
        FOREIGN_BYTES,
        "bundle cleanup changed a foreign collision"
    );
    let names = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, ["assessment.html"]);
    assert!(!destination.join("manifest.json").exists());
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        ["GET /", "GET /", "GET /"],
        "bundle publication failure must not change or repeat scan requests"
    );
}
