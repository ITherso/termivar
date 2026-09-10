//! Process-level CLI boundaries for explicit WordPress metadata discovery.

#![cfg(feature = "wordpress-review")]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Command, Output},
    sync::{Arc, Mutex},
    thread,
};

const ROOT: &[u8] = br#"<!doctype html><html><head>
<meta name="generator" content="WordPress 6.9.4">
<link rel="https://api.w.org/" href="/wp-json/">
<link rel="stylesheet" href="/wp-content/themes/synthetic-discovery-theme/style.css">
<link rel="stylesheet" href="/wp-content/plugins/synthetic-discovery-plugin/style.css">
</head><body>synthetic discovery fixture</body></html>"#;
const REST_INDEX: &[u8] = br#"{"namespaces":["wp/v2","oembed/1.0"]}"#;
const THEME_STYLESHEET: &[u8] = br#"/*
Theme Name: Synthetic Discovery Theme
Version: 1.5
Requires at least: 6.0
Tested up to: 6.9
*/
body { color: #111; }
"#;
const PLUGIN_README: &[u8] = br#"=== Synthetic Discovery Plugin ===
Stable tag: 9.9.9
Requires at least: 6.0
Tested up to: 6.9
"#;

fn termivar() -> Command {
    Command::new(env!("CARGO_BIN_EXE_termivar"))
}

struct RoutedServer {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn serve() -> RoutedServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                break;
            };
            let mut request = [0_u8; 16 * 1024];
            let read = stream.read(&mut request).unwrap_or(0);
            let first_line = String::from_utf8_lossy(&request[..read])
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            thread_requests.lock().unwrap().push(first_line.clone());
            let mut words = first_line.split_ascii_whitespace();
            let method = words.next().unwrap_or_default();
            let path = words.next().unwrap_or_default();
            let (status, media_type, body): (&str, &str, &[u8]) = match (method, path) {
                ("GET" | "HEAD", "/") => ("200 OK", "text/html; charset=utf-8", ROOT),
                ("GET", "/wp-json/") => ("200 OK", "application/json; charset=utf-8", REST_INDEX),
                ("GET" | "HEAD", "/wp-content/themes/synthetic-discovery-theme/style.css") => {
                    ("200 OK", "text/css; charset=utf-8", THEME_STYLESHEET)
                },
                ("HEAD", "/wp-content/plugins/synthetic-discovery-plugin/style.css") => {
                    ("200 OK", "text/css; charset=utf-8", b"/* plugin asset */")
                },
                ("GET", "/wp-content/plugins/synthetic-discovery-plugin/readme.txt") => {
                    ("200 OK", "text/plain; charset=utf-8", PLUGIN_README)
                },
                _ => ("404 Not Found", "text/plain; charset=utf-8", b"not found"),
            };
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            if method != "HEAD" {
                let _ = stream.write_all(body);
            }
            let _ = stream.flush();
        }
    });
    RoutedServer {
        origin: format!("http://{address}/"),
        requests,
    }
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn discovery_requires_explicit_review_before_transport_or_output() {
    let server = serve();
    let temporary = tempfile::tempdir().unwrap();
    let output_directory = temporary.path().join("must-not-exist");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-discovery",
            "--report-dir",
        ])
        .arg(&output_directory)
        .arg(&server.origin)
        .output()
        .expect("termivar process must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output_directory.exists());
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn discovery_bundle_is_verified_and_self_compares_without_extra_requests() {
    let server = serve();
    let temporary = tempfile::tempdir().unwrap();
    let output_directory = temporary.path().join("discovery-bundle");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--report-dir",
        ])
        .arg(&output_directory)
        .arg(&server.origin)
        .output()
        .expect("termivar process must start");
    assert_success(&output, "discovery scan");
    assert!(output.stdout.is_empty());

    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        assert!(output_directory.join(name).is_file(), "missing {name}");
    }
    let assessment = read_json(&output_directory.join("assessment.json"));
    assert_eq!(
        assessment["wordpress_discovery"]["schema"],
        "security.wordpress-discovery-audit/v1"
    );
    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(
        discovery["policy_id"],
        "termivar.wordpress-metadata-discovery/v1"
    );
    assert_eq!(
        discovery["capability_id"],
        "technology.wordpress-metadata-discovery@1"
    );
    assert_eq!(discovery["selected"], true);
    assert_eq!(discovery["method"], "get");
    assert_eq!(discovery["credential_mode"], "anonymous");
    assert_eq!(discovery["seed_count"], 3);
    assert_eq!(discovery["candidate_count"], 3);
    assert_eq!(discovery["candidate_limit_reached"], false);
    assert_eq!(discovery["omitted_candidate_count"], 0);
    assert_eq!(discovery["attempted_request_count"], 3);
    assert_eq!(discovery["completed_response_count"], 3);
    assert_eq!(discovery["committed_response_count"], 3);
    assert!(discovery["response_bytes"].as_u64().unwrap() > 0);

    let sources = discovery["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(discovery["source_count"], 3);
    assert!(sources
        .iter()
        .all(|source| source["evidence_reference_count"] == 1));
    assert!(sources.iter().all(|source| source.get("url").is_none()));
    assert!(sources.iter().any(|source| {
        source["kind"] == "rest_index"
            && source["outcome"] == "observed"
            && source["namespaces"] == serde_json::json!(["oembed/1.0", "wp/v2"])
    }));
    assert!(sources.iter().any(|source| {
        source["kind"] == "theme_stylesheet"
            && source["component"]
                == serde_json::json!({"kind": "theme", "slug": "synthetic-discovery-theme"})
            && source["theme"]["version"] == "1.5"
    }));
    assert!(sources.iter().any(|source| {
        source["kind"] == "plugin_readme"
            && source["component"]
                == serde_json::json!({"kind": "plugin", "slug": "synthetic-discovery-plugin"})
            && source["plugin"]["stable_tag"] == "9.9.9"
    }));
    let discovery_items = assessment["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| {
            item["capability_id"] == "technology.wordpress-metadata-source-response-observed@1"
        })
        .collect::<Vec<_>>();
    assert_eq!(discovery_items.len(), 1);
    let discovery_item = discovery_items[0];
    assert_eq!(discovery_item["disposition"], "informational");
    assert_eq!(discovery_item["claim_basis"], "observation");
    assert_eq!(
        discovery_item["category"],
        "wordpress-metadata-source-response"
    );
    assert_eq!(discovery_item["evidence_count"], 3);
    let item_references = discovery_item["evidence_references"].as_array().unwrap();
    let source_references = sources
        .iter()
        .flat_map(|source| source["evidence_references"].as_array().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(item_references.len(), 3);
    assert_eq!(
        source_references,
        item_references.iter().collect::<Vec<_>>()
    );

    let requests = server.requests.lock().unwrap().clone();
    assert_eq!(
        requests,
        [
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET /wp-json/ HTTP/1.1",
            "GET /wp-content/themes/synthetic-discovery-theme/style.css HTTP/1.1",
            "GET /wp-content/plugins/synthetic-discovery-plugin/readme.txt HTTP/1.1",
            "HEAD /wp-content/plugins/synthetic-discovery-plugin/style.css HTTP/1.1",
            "HEAD /wp-content/themes/synthetic-discovery-theme/style.css HTTP/1.1",
            "HEAD /wp-json/ HTTP/1.1",
        ]
        .map(str::to_owned)
    );

    let before_offline = requests.len();
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&output_directory)
        .args(["--format", "json"])
        .output()
        .expect("termivar process must start");
    assert_success(&verify, "Report Verify");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verify.stdout).unwrap()["status"],
        "integrity_match"
    );

    let assessment_path = output_directory.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("termivar process must start");
    assert_success(&compare, "Report Compare");
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert!(comparison["only_in_after"].as_array().unwrap().is_empty());
    assert!(comparison["only_in_before"].as_array().unwrap().is_empty());
    assert!(comparison["changed"].as_array().unwrap().is_empty());
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    assert!(comparison["unchanged"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["capability_id"] == "technology.wordpress-metadata-source-response-observed@1"
        }));
    assert_eq!(server.requests.lock().unwrap().len(), before_offline);
}
