//! Process-level CLI boundaries for explicit WordPress metadata discovery.

#![cfg(feature = "wordpress-review")]

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Command, Output},
    sync::{Arc, Mutex},
    thread,
};

use sha2::{Digest, Sha256};

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

const BLOG_ROOT: &[u8] = br#"<!doctype html><html><head>
<meta name="generator" content="WordPress 6.9.4">
<link rel="https://api.w.org/" href="/blog/wp-json/">
<script src="/blog/wp-content/themes/synthetic-child/assets/site.js"></script>
<script src="/blog/wp-content/plugins/synthetic-discovery-plugin/assets/site.js"></script>
</head><body>synthetic prefixed deployment</body></html>"#;
const CUSTOM_ROOT: &[u8] = br#"<!doctype html><html><head>
<meta name="generator" content="WordPress 6.9.4">
<link rel="https://api.w.org/" href="/blog/wp-json/">
<script src="/site-content/themes/synthetic-child/assets/site.js"></script>
<script src="/modules/synthetic-discovery-plugin/assets/site.js"></script>
</head><body>synthetic declared deployment</body></html>"#;
const CHILD_THEME_STYLESHEET: &[u8] = br#"/*
Theme Name: Synthetic Child
Template: synthetic-parent
Version: 1.5
*/
body { color: #111; }
"#;
const PARENT_THEME_STYLESHEET: &[u8] = br#"/*
Theme Name: Synthetic Parent
Version: 2.0
*/
body { color: #222; }
"#;
const FINGERPRINT_ROOT: &[u8] = br#"<!doctype html><html><head>
<link rel="stylesheet" href="/wp-content/themes/fingerprint-base/assets/site.css">
</head><body>
<a href="/contact/">contact</a>
<a href="/gallery/">gallery</a>
</body></html>"#;
const FINGERPRINT_PAGE: &[u8] = br#"<!doctype html><html><head>
<script src="/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42"></script>
<link rel="stylesheet" href="/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42">
</head><body>synthetic secondary fingerprint page</body></html>"#;
const CUSTOM_OBSERVED_FINGERPRINT_ROOT: &[u8] = br#"<!doctype html><html><head>
<meta name="generator" content="WordPress 6.9.4">
<link rel="https://api.w.org/" href="/blog/wp-json/">
<script src="/site-content/themes/synthetic-child/assets/site.js"></script>
<script src="/modules/synthetic-discovery-plugin/assets/site.js"></script>
</head><body>
<a href="/blog/contact/">contact</a>
<a href="/blog/gallery/">gallery</a>
</body></html>"#;
const CUSTOM_OBSERVED_FINGERPRINT_PAGE: &[u8] = br#"<!doctype html><html><head>
<script src="/modules/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42"></script>
<link rel="stylesheet" href="/modules/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42">
</head><body>synthetic custom-layout secondary fingerprint page</body></html>"#;
const FINGERPRINT_PLUGIN_README: &[u8] = br#"=== Termivar Fingerprint Lab ===
Stable tag: 9.9.9
"#;
const FINGERPRINT_JS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/examples/wordpress-review/asset-fingerprints/reference-assets/release-b/assets/fingerprint.js"
));
const FINGERPRINT_CSS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/examples/wordpress-review/asset-fingerprints/reference-assets/release-b/assets/fingerprint.css"
));

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

#[derive(Clone, Copy)]
enum DeploymentFixture {
    Prefixed,
    Declared,
}

fn serve_deployment(fixture: DeploymentFixture) -> RoutedServer {
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
            let (status, media_type, body): (&str, &str, &[u8]) = match (fixture, method, path) {
                (DeploymentFixture::Prefixed, "GET" | "HEAD", "/blog/") => {
                    ("200 OK", "text/html; charset=utf-8", BLOG_ROOT)
                },
                (DeploymentFixture::Declared, "GET" | "HEAD", "/blog/") => {
                    ("200 OK", "text/html; charset=utf-8", CUSTOM_ROOT)
                },
                (_, "GET", "/blog/wp-json/") => {
                    ("200 OK", "application/json; charset=utf-8", REST_INDEX)
                },
                (
                    DeploymentFixture::Prefixed,
                    "GET",
                    "/blog/wp-content/themes/synthetic-child/style.css",
                )
                | (
                    DeploymentFixture::Declared,
                    "GET",
                    "/site-content/themes/synthetic-child/style.css",
                ) => ("200 OK", "text/css; charset=utf-8", CHILD_THEME_STYLESHEET),
                (
                    DeploymentFixture::Prefixed,
                    "GET",
                    "/blog/wp-content/themes/synthetic-parent/style.css",
                )
                | (
                    DeploymentFixture::Declared,
                    "GET",
                    "/site-content/themes/synthetic-parent/style.css",
                ) => ("200 OK", "text/css; charset=utf-8", PARENT_THEME_STYLESHEET),
                (
                    DeploymentFixture::Prefixed,
                    "GET",
                    "/blog/wp-content/plugins/synthetic-discovery-plugin/readme.txt",
                )
                | (
                    DeploymentFixture::Declared,
                    "GET",
                    "/modules/synthetic-discovery-plugin/readme.txt",
                ) => ("200 OK", "text/plain; charset=utf-8", PLUGIN_README),
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

fn serve_fingerprint_fixture() -> RoutedServer {
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
                ("GET" | "HEAD", "/") => {
                    ("200 OK", "text/html; charset=utf-8", FINGERPRINT_ROOT)
                }
                ("GET" | "HEAD", "/contact/" | "/gallery/") => {
                    ("200 OK", "text/html; charset=utf-8", FINGERPRINT_PAGE)
                }
                ("GET", "/wp-content/themes/fingerprint-base/style.css") => (
                    "200 OK",
                    "text/css; charset=utf-8",
                    b"/* Theme Name: Fingerprint Base\nVersion: 1.0 */",
                ),
                (
                    "GET" | "HEAD",
                    "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42",
                ) => ("200 OK", "application/javascript", FINGERPRINT_JS),
                (
                    "GET" | "HEAD",
                    "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42",
                ) => ("200 OK", "text/css", FINGERPRINT_CSS),
                (
                    "GET",
                    "/wp-content/plugins/termivar-fingerprint-lab/readme.txt",
                ) => ("200 OK", "text/plain; charset=utf-8", FINGERPRINT_PLUGIN_README),
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

fn serve_custom_observed_fingerprint_fixture() -> RoutedServer {
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
                ("GET" | "HEAD", "/blog/") => (
                    "200 OK",
                    "text/html; charset=utf-8",
                    CUSTOM_OBSERVED_FINGERPRINT_ROOT,
                ),
                ("GET" | "HEAD", "/blog/contact/" | "/blog/gallery/") => (
                    "200 OK",
                    "text/html; charset=utf-8",
                    CUSTOM_OBSERVED_FINGERPRINT_PAGE,
                ),
                ("GET", "/blog/wp-json/") => {
                    ("200 OK", "application/json; charset=utf-8", REST_INDEX)
                },
                ("GET", "/site-content/themes/synthetic-child/style.css") => {
                    ("200 OK", "text/css; charset=utf-8", CHILD_THEME_STYLESHEET)
                },
                ("GET", "/site-content/themes/synthetic-parent/style.css") => {
                    ("200 OK", "text/css; charset=utf-8", PARENT_THEME_STYLESHEET)
                },
                ("GET", "/modules/synthetic-discovery-plugin/readme.txt") => {
                    ("200 OK", "text/plain; charset=utf-8", PLUGIN_README)
                },
                ("GET", "/modules/termivar-fingerprint-lab/readme.txt") => (
                    "200 OK",
                    "text/plain; charset=utf-8",
                    FINGERPRINT_PLUGIN_README,
                ),
                (
                    "GET" | "HEAD",
                    "/modules/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42",
                ) => ("200 OK", "application/javascript", FINGERPRINT_JS),
                (
                    "GET" | "HEAD",
                    "/modules/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42",
                ) => ("200 OK", "text/css", FINGERPRINT_CSS),
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

fn assert_custom_observed_pages_and_metadata(
    assessment: &serde_json::Value,
    review_schema: &str,
    expected_additional_requests: u64,
) -> BTreeSet<String> {
    assert_eq!(assessment["wordpress_review"]["schema"], review_schema);
    assert_eq!(
        assessment["wordpress_review"]["additional_request_count"],
        expected_additional_requests
    );
    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(discovery["schema"], "security.wordpress-discovery-audit/v3");
    assert_eq!(discovery["attempted_request_count"], 5);
    assert_eq!(discovery["completed_response_count"], 5);
    assert_eq!(discovery["committed_response_count"], 5);
    assert_eq!(discovery["source_count"], 5);

    let pages = &discovery["page_collection"];
    assert_eq!(pages["mode"], "observed");
    assert_eq!(pages["candidate_count"], 2);
    assert_eq!(pages["selected_count"], 2);
    assert_eq!(pages["reused_response_count"], 2);
    assert_eq!(pages["fetched_response_count"], 0);
    assert_eq!(pages["attempted_request_count"], 0);
    assert_eq!(pages["completed_response_count"], 2);
    assert_eq!(pages["committed_response_count"], 2);
    assert_eq!(pages["accepted_association_count"], 2);
    assert_eq!(pages["rejected_association_count"], 0);
    let page_rows = pages["pages"].as_array().unwrap();
    assert_eq!(page_rows.len(), 2);
    assert!(page_rows.iter().all(|page| {
        page["acquisition"] == "reused"
            && page["association"] == "accepted"
            && page["outcome"] == "accepted"
            && page["request_attempted"] == false
    }));
    let page_references = page_rows
        .iter()
        .map(|page| page["page_reference"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(page_references.len(), 2);
    assert!(page_references
        .iter()
        .all(|reference| reference.starts_with("sha256:") && reference.len() == 71));

    let sources = discovery["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 5);
    let source_identities = sources
        .iter()
        .map(|source| {
            let component = source.get("component");
            format!(
                "{}:{}:{}",
                source["kind"].as_str().unwrap(),
                component
                    .and_then(|value| value.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("none"),
                component
                    .and_then(|value| value.get("slug"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("none")
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        source_identities,
        BTreeSet::from([
            "plugin_readme:plugin:synthetic-discovery-plugin".to_owned(),
            "plugin_readme:plugin:termivar-fingerprint-lab".to_owned(),
            "rest_index:none:none".to_owned(),
            "theme_stylesheet:theme:synthetic-child".to_owned(),
            "theme_stylesheet:theme:synthetic-parent".to_owned(),
        ])
    );
    assert!(sources.iter().any(|source| {
        source["kind"] == "theme_stylesheet"
            && source["component"] == serde_json::json!({"kind":"theme","slug":"synthetic-child"})
            && source["association"] == "explicit_operator"
    }));
    assert!(sources.iter().any(|source| {
        source["kind"] == "theme_stylesheet"
            && source["component"] == serde_json::json!({"kind":"theme","slug":"synthetic-parent"})
            && source["association"] == "same_theme_base_parent"
    }));
    assert!(sources.iter().any(|source| {
        source["kind"] == "plugin_readme"
            && source["component"]
                == serde_json::json!({"kind":"plugin","slug":"synthetic-discovery-plugin"})
            && source["association"] == "explicit_operator"
    }));
    let conditional_readme = sources
        .iter()
        .find(|source| {
            source["kind"] == "plugin_readme"
                && source["component"]
                    == serde_json::json!({"kind":"plugin","slug":"termivar-fingerprint-lab"})
        })
        .unwrap();
    assert_eq!(conditional_readme["association"], "explicit_operator");
    assert_eq!(conditional_readme["outcome"], "observed");
    assert_eq!(conditional_readme["plugin"]["stable_tag"], "9.9.9");
    assert_eq!(
        conditional_readme["source_page_references"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        conditional_readme["source_page_references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|reference| reference.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>(),
        page_references
    );

    let conditional_component = assessment["wordpress_review"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["identity"]["slug"] == "termivar-fingerprint-lab")
        .expect("the accepted secondary pages must nominate their plugin");
    assert_eq!(conditional_component["versions"], serde_json::json!([]));
    page_references
}

#[test]
fn declared_custom_layout_secondary_pages_drive_metadata_and_fingerprints_through_cli() {
    let server = serve_custom_observed_fingerprint_fixture();
    let temporary = tempfile::tempdir().unwrap();
    let selected_application = format!("{}blog/", server.origin);
    let layout = temporary.path().join("custom-layout.json");
    let layout_document = format!(
        "{{\"schema\":\"security.wordpress-layout/v1\",\"application_url\":\"{selected_application}\",\"core_base_url\":\"{}cms/\",\"themes_base_url\":\"{}site-content/themes/\",\"plugins_base_url\":\"{}modules/\"}}",
        server.origin, server.origin, server.origin
    );
    fs::write(&layout, layout_document.as_bytes()).unwrap();
    let catalogue = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/wordpress-review/asset-fingerprints/catalogue.synthetic.json");
    let original_catalogue = fs::read(&catalogue).unwrap();

    let option_off_directory = temporary.path().join("custom-option-off");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--wordpress-page-scope",
            "observed",
            "--wordpress-layout",
        ])
        .arg(&layout)
        .arg("--report-dir")
        .arg(&option_off_directory)
        .arg(&selected_application)
        .output()
        .expect("termivar process must start");
    assert_success(&output, "custom-layout observed option-off scan");
    assert!(output.stdout.is_empty());
    let option_off_assessment = read_json(&option_off_directory.join("assessment.json"));
    assert!(option_off_assessment
        .get("wordpress_asset_fingerprints")
        .is_none());
    assert_custom_observed_pages_and_metadata(
        &option_off_assessment,
        "security.wordpress-review-audit/v7",
        5,
    );
    let option_off_requests = server.requests.lock().unwrap().clone();
    for page in ["/blog/contact/", "/blog/gallery/"] {
        assert_eq!(
            option_off_requests
                .iter()
                .filter(|request| *request == &format!("GET {page} HTTP/1.1"))
                .count(),
            1,
            "observed mode must reuse each ordinary page GET exactly once"
        );
    }
    assert_eq!(
        option_off_requests
            .iter()
            .filter(|request| {
                *request == "GET /modules/termivar-fingerprint-lab/readme.txt HTTP/1.1"
            })
            .count(),
        1
    );
    assert!(!option_off_requests
        .iter()
        .any(|request| { request.starts_with("GET /modules/termivar-fingerprint-lab/assets/") }));

    let fingerprint_directory = temporary.path().join("custom-fingerprints");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--wordpress-page-scope",
            "observed",
            "--wordpress-layout",
        ])
        .arg(&layout)
        .arg("--wordpress-fingerprints")
        .arg(&catalogue)
        .arg("--report-dir")
        .arg(&fingerprint_directory)
        .arg(&selected_application)
        .output()
        .expect("termivar process must start");
    assert_success(&output, "custom-layout observed fingerprint scan");
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&layout).unwrap(), layout_document.as_bytes());
    assert_eq!(fs::read(&catalogue).unwrap(), original_catalogue);

    let assessment = read_json(&fingerprint_directory.join("assessment.json"));
    let page_references = assert_custom_observed_pages_and_metadata(
        &assessment,
        "security.wordpress-review-audit/v8",
        7,
    );
    let fingerprints = &assessment["wordpress_asset_fingerprints"];
    assert_eq!(
        fingerprints["schema"],
        "security.wordpress-asset-fingerprint-audit/v1"
    );
    assert_eq!(
        fingerprints["installed_version_assurance"],
        "not_established_by_asset_fingerprints"
    );
    assert_eq!(fingerprints["candidate_count"], 2);
    assert_eq!(fingerprints["selected_resource_count"], 2);
    assert_eq!(fingerprints["attempted_request_count"], 2);
    assert_eq!(fingerprints["fetched_response_count"], 2);
    assert_eq!(fingerprints["reused_response_count"], 0);
    assert_eq!(fingerprints["resource_count"], 2);
    assert_eq!(fingerprints["component_count"], 1);
    let component = &fingerprints["components"][0];
    assert_eq!(
        component["identity"],
        serde_json::json!({"kind":"plugin","slug":"termivar-fingerprint-lab"})
    );
    assert_eq!(component["state"], "single_catalogue_candidate");
    assert_eq!(
        component["compatible_release_ids"],
        serde_json::json!(["release-b"])
    );
    assert_eq!(component["candidate_resource_count"], 2);
    assert_eq!(component["selected_resource_count"], 2);
    assert_eq!(component["completely_interpreted_resource_count"], 2);

    let resources = fingerprints["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2);
    for resource in resources {
        assert_eq!(resource["outcome"], "observed");
        assert_eq!(resource["request_attempted"], true);
        assert_eq!(
            resource["source_page_references"].as_array().unwrap().len(),
            2
        );
        assert_eq!(
            resource["source_page_references"]
                .as_array()
                .unwrap()
                .iter()
                .map(|reference| reference.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>(),
            page_references
        );
        let expected = match resource["relative_path"].as_str().unwrap() {
            "assets/fingerprint.js" => FINGERPRINT_JS,
            "assets/fingerprint.css" => FINGERPRINT_CSS,
            path => panic!("unexpected custom fingerprint resource {path}"),
        };
        assert_eq!(resource["observation"]["byte_length"], expected.len());
        assert_eq!(
            resource["observation"]["sha256"],
            format!("{:x}", Sha256::digest(expected))
        );
    }

    let all_requests = server.requests.lock().unwrap().clone();
    let fingerprint_requests = &all_requests[option_off_requests.len()..];
    for page in ["/blog/contact/", "/blog/gallery/"] {
        assert_eq!(
            fingerprint_requests
                .iter()
                .filter(|request| *request == &format!("GET {page} HTTP/1.1"))
                .count(),
            1
        );
    }
    assert_eq!(
        fingerprint_requests
            .iter()
            .filter(|request| {
                *request == "GET /modules/termivar-fingerprint-lab/readme.txt HTTP/1.1"
            })
            .count(),
        1
    );
    for path in [
        "/modules/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42",
        "/modules/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42",
    ] {
        assert_eq!(
            fingerprint_requests
                .iter()
                .filter(|request| *request == &format!("GET {path} HTTP/1.1"))
                .count(),
            1
        );
    }

    let before_offline = all_requests.len();
    for (label, directory, assessment) in [
        ("option-off", &option_off_directory, &option_off_assessment),
        ("fingerprint", &fingerprint_directory, &assessment),
    ] {
        let verify = termivar()
            .args(["report", "verify", "--dir"])
            .arg(directory)
            .args(["--format", "json"])
            .output()
            .expect("termivar process must start");
        assert_success(&verify, &format!("custom-layout {label} Report Verify"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&verify.stdout).unwrap()["status"],
            "integrity_match"
        );

        let assessment_path = directory.join("assessment.json");
        let compare = termivar()
            .args(["report", "compare", "--before"])
            .arg(&assessment_path)
            .arg("--after")
            .arg(&assessment_path)
            .args(["--same-scope", "--format", "json"])
            .output()
            .expect("termivar process must start");
        assert_success(&compare, &format!("custom-layout {label} self-Compare"));
        let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
        assert!(comparison["only_in_after"].as_array().unwrap().is_empty());
        assert!(comparison["only_in_before"].as_array().unwrap().is_empty());
        assert!(comparison["changed"].as_array().unwrap().is_empty());
        assert_eq!(
            comparison["unchanged"].as_array().unwrap().len(),
            assessment["item_count"].as_u64().unwrap() as usize
        );
    }
    assert_eq!(server.requests.lock().unwrap().len(), before_offline);
}

#[test]
fn observed_asset_fingerprints_intersect_listed_releases_and_remain_offline_readable() {
    let server = serve_fingerprint_fixture();
    let temporary = tempfile::tempdir().unwrap();
    let catalogue = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/wordpress-review/asset-fingerprints/catalogue.synthetic.json");
    let original_catalogue = fs::read(&catalogue).unwrap();

    let option_off = temporary.path().join("fingerprint-option-off");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--wordpress-page-scope",
            "observed",
            "--report-dir",
        ])
        .arg(&option_off)
        .arg(&server.origin)
        .output()
        .expect("termivar process must start");
    assert_success(&output, "fingerprint option-off scan");
    let option_off_document = read_json(&option_off.join("assessment.json"));
    assert!(option_off_document
        .get("wordpress_asset_fingerprints")
        .is_none());
    assert_eq!(
        option_off_document["wordpress_review"]["schema"],
        "security.wordpress-review-audit/v7"
    );
    let option_off_requests = server.requests.lock().unwrap().clone();
    assert!(!option_off_requests.iter().any(|request| {
        request.starts_with("GET /wp-content/plugins/termivar-fingerprint-lab/assets/")
    }));

    let output_directory = temporary.path().join("fingerprint-bundle");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--wordpress-page-scope",
            "observed",
            "--wordpress-fingerprints",
        ])
        .arg(&catalogue)
        .arg("--report-dir")
        .arg(&output_directory)
        .arg(&server.origin)
        .output()
        .expect("termivar process must start");
    assert_success(&output, "asset fingerprint scan");
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&catalogue).unwrap(), original_catalogue);

    let assessment = read_json(&output_directory.join("assessment.json"));
    assert_eq!(
        assessment["wordpress_review"]["schema"],
        "security.wordpress-review-audit/v8"
    );
    let fingerprints = &assessment["wordpress_asset_fingerprints"];
    assert_eq!(
        fingerprints["schema"],
        "security.wordpress-asset-fingerprint-audit/v1"
    );
    assert_eq!(
        fingerprints["representation_profile"],
        "identity-content-bytes/v1"
    );
    assert_eq!(
        fingerprints["installed_version_assurance"],
        "not_established_by_asset_fingerprints"
    );
    assert_eq!(fingerprints["candidate_count"], 2);
    assert_eq!(fingerprints["selected_resource_count"], 2);
    assert_eq!(fingerprints["attempted_request_count"], 2);
    assert_eq!(fingerprints["fetched_response_count"], 2);
    assert_eq!(fingerprints["reused_response_count"], 0);
    assert_eq!(fingerprints["stop"], "complete");
    assert_eq!(fingerprints["resource_count"], 2);
    assert_eq!(fingerprints["component_count"], 1);
    let pages = &assessment["wordpress_discovery"]["page_collection"];
    assert_eq!(pages["mode"], "observed");
    assert_eq!(pages["candidate_count"], 2);
    assert_eq!(pages["selected_count"], 2);
    assert_eq!(pages["reused_response_count"], 2);
    assert_eq!(pages["fetched_response_count"], 0);
    assert_eq!(pages["attempted_request_count"], 0);
    assert_eq!(pages["completed_response_count"], 2);
    assert_eq!(pages["committed_response_count"], 2);
    assert_eq!(pages["accepted_association_count"], 2);
    assert_eq!(pages["rejected_association_count"], 0);
    let accepted_page_references = pages["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|page| page["page_reference"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(accepted_page_references.len(), 2);
    let component = &fingerprints["components"][0];
    assert_eq!(
        component["identity"],
        serde_json::json!({"kind":"plugin","slug":"termivar-fingerprint-lab"})
    );
    assert_eq!(component["state"], "single_catalogue_candidate");
    assert_eq!(component["candidate_resource_count"], 2);
    assert_eq!(component["selected_resource_count"], 2);
    assert_eq!(component["completely_interpreted_resource_count"], 2);
    assert_eq!(component["omitted_resource_count"], 0);
    assert_eq!(component["informative_resource_count"], 2);
    assert_eq!(component["listed_matrix_complete"], true);
    assert_eq!(
        component["compatible_release_ids"],
        serde_json::json!(["release-b"])
    );
    assert_eq!(component["undetermined_release_ids"], serde_json::json!([]));
    assert_eq!(
        component["inconsistent_release_ids"],
        serde_json::json!(["release-a", "release-c"])
    );
    assert_eq!(component["releases"][1]["version"], "2.0.0");
    assert_eq!(component["releases"][1]["state"], "compatible");
    assert!(fingerprints["resources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|resource| {
            resource.get("url").is_none()
                && resource["observed_variant_count"] == 1
                && resource["outcome"] == "observed"
                && resource["request_attempted"] == true
                && resource["source_page_references"]
                    .as_array()
                    .is_some_and(|pages| {
                        pages
                            .iter()
                            .map(|page| page.as_str().unwrap())
                            .collect::<BTreeSet<_>>()
                            == accepted_page_references
                    })
                && resource["observation"]["sha256"]
                    .as_str()
                    .is_some_and(|digest| digest.len() == 64)
        }));
    assert_eq!(
        fingerprints["response_bytes"],
        (FINGERPRINT_JS.len() + FINGERPRINT_CSS.len()) as u64
    );
    for resource in fingerprints["resources"].as_array().unwrap() {
        let expected = match resource["relative_path"].as_str().unwrap() {
            "assets/fingerprint.js" => FINGERPRINT_JS,
            "assets/fingerprint.css" => FINGERPRINT_CSS,
            path => panic!("unexpected fingerprint resource {path}"),
        };
        let expected_digest = Sha256::digest(expected);
        assert_eq!(
            resource["observation"]["byte_length"],
            expected.len() as u64
        );
        assert_eq!(
            resource["observation"]["sha256"],
            format!("{expected_digest:x}")
        );
    }
    let fingerprint_component = assessment["wordpress_review"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["identity"]["slug"] == "termivar-fingerprint-lab")
        .expect("fingerprinted plugin remains present in the WordPress review");
    assert_eq!(fingerprint_component["versions"], serde_json::json!([]));

    let requests = server.requests.lock().unwrap().clone();
    let fingerprint_requests = &requests[option_off_requests.len()..];
    for page in ["/contact/", "/gallery/"] {
        assert_eq!(
            fingerprint_requests
                .iter()
                .filter(|request| *request == &format!("GET {page} HTTP/1.1"))
                .count(),
            1,
            "the ordinary assessment must retrieve each selected page exactly once"
        );
    }
    for path in [
        "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42",
        "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42",
    ] {
        assert_eq!(
            fingerprint_requests
                .iter()
                .filter(|request| *request == &format!("GET {path} HTTP/1.1"))
                .count(),
            1
        );
    }
    assert!(!requests
        .iter()
        .any(|request| request.contains("assets/common.css")));

    let before_offline = requests.len();
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&output_directory)
        .args(["--format", "json"])
        .output()
        .expect("termivar process must start");
    assert_success(&verify, "fingerprint Report Verify");
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
    assert_success(&compare, "fingerprint Report Compare");
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert!(comparison["only_in_after"].as_array().unwrap().is_empty());
    assert!(comparison["only_in_before"].as_array().unwrap().is_empty());
    assert!(comparison["changed"].as_array().unwrap().is_empty());
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    let wordpress = &comparison["wordpress_review_comparison"];
    assert_eq!(
        wordpress["schema"],
        "termivar-wordpress-review-comparison/v3"
    );
    assert_eq!(wordpress["asset_fingerprints"]["status"], "compared");
    assert_eq!(
        wordpress["asset_fingerprints"]["components"]["paired_unchanged_count"],
        1
    );

    let option_off_assessment_path = option_off.join("assessment.json");
    for (case, before, after, expected) in [
        (
            "self",
            assessment_path.as_path(),
            assessment_path.as_path(),
            "compared",
        ),
        (
            "presence",
            option_off_assessment_path.as_path(),
            assessment_path.as_path(),
            "before_fingerprint_audit_missing",
        ),
    ] {
        for format in ["markdown", "html"] {
            let output = termivar()
                .args(["report", "compare", "--before"])
                .arg(before)
                .arg("--after")
                .arg(after)
                .args(["--same-scope", "--format", format])
                .output()
                .expect("termivar process must start");
            assert_success(
                &output,
                &format!("fingerprint {case} Report Compare {format}"),
            );
            let rendered = String::from_utf8(output.stdout).unwrap();
            assert!(rendered.contains("Asset fingerprint candidates"));
            assert!(rendered.contains(expected));
            assert!(rendered.contains("not installed-version evidence"));
        }
    }
    assert_eq!(server.requests.lock().unwrap().len(), before_offline);

    for format in ["csv", "markdown"] {
        let output = termivar()
            .args([
                "scan",
                "--profile",
                "web-review",
                "--wordpress-review",
                "--wordpress-discovery",
                "--wordpress-page-scope",
                "observed",
                "--wordpress-fingerprints",
            ])
            .arg(&catalogue)
            .args(["--report-format", format])
            .arg(&server.origin)
            .output()
            .expect("termivar process must start");
        assert_success(&output, &format!("asset fingerprint {format} report"));
        let rendered = String::from_utf8(output.stdout).unwrap();
        assert!(rendered.contains("release-b"));
        assert!(rendered.contains("single_catalogue_candidate"));
        match format {
            "csv" => assert!(rendered.contains("wordpress_asset_fingerprint_audit")),
            "markdown" => {
                assert!(rendered.contains("WordPress observed asset fingerprint candidates"));
                assert!(rendered.contains("Finite reference catalogue"));
            },
            _ => unreachable!(),
        }
    }
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
        "security.wordpress-discovery-audit/v2"
    );
    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(
        discovery["policy_id"],
        "termivar.wordpress-deployment-aware-metadata-discovery/v1"
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
    assert_eq!(source_references.len(), 3);
    let item_reference_set = item_references
        .iter()
        .map(|reference| reference.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let source_reference_set = source_references
        .into_iter()
        .map(|reference| reference.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(item_reference_set.len(), 3);
    assert_eq!(source_reference_set.len(), 3);
    assert_eq!(source_reference_set, item_reference_set);

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

#[test]
fn prefixed_and_declared_layouts_preserve_role_bases_through_offline_readers() {
    for fixture in [DeploymentFixture::Prefixed, DeploymentFixture::Declared] {
        let server = serve_deployment(fixture);
        let temporary = tempfile::tempdir().unwrap();
        let output_directory = temporary.path().join("layout-bundle");
        let selected_application = format!("{}blog/", server.origin);
        let mut command = termivar();
        command.args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--report-dir",
        ]);
        command.arg(&output_directory);

        let layout_bytes = if matches!(fixture, DeploymentFixture::Declared) {
            let document = format!(
                "{{\"schema\":\"security.wordpress-layout/v1\",\"application_url\":\"{selected_application}\",\"core_base_url\":\"{}cms/\",\"themes_base_url\":\"{}site-content/themes/\",\"plugins_base_url\":\"{}modules/\"}}",
                server.origin, server.origin, server.origin
            );
            let path = temporary.path().join("layout.json");
            fs::write(&path, document.as_bytes()).unwrap();
            command.arg("--wordpress-layout").arg(&path);
            Some((path, document.into_bytes()))
        } else {
            None
        };
        command.arg(&selected_application);

        let output = command.output().expect("termivar process must start");
        assert_success(&output, "deployment-aware discovery scan");
        assert!(output.stdout.is_empty());
        if let Some((path, original)) = &layout_bytes {
            assert_eq!(fs::read(path).unwrap(), *original);
        }

        let assessment = read_json(&output_directory.join("assessment.json"));
        let discovery = &assessment["wordpress_discovery"];
        assert_eq!(discovery["schema"], "security.wordpress-discovery-audit/v2");
        assert_eq!(
            discovery["policy_id"],
            "termivar.wordpress-deployment-aware-metadata-discovery/v1"
        );
        assert_eq!(discovery["attempted_request_count"], 4);
        assert_eq!(discovery["committed_response_count"], 4);
        assert_eq!(discovery["layout"]["skipped_foreign_origin_count"], 0);
        assert_eq!(discovery["layout"]["skipped_sibling_application_count"], 0);
        let roles = discovery["layout"]["roles"].as_array().unwrap();
        for role in ["themes", "plugins", "rest_index"] {
            assert!(roles.iter().any(|entry| {
                entry["role"] == role
                    && entry["status"] == "exact"
                    && entry["reference"].as_str().is_some_and(|value| {
                        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64
                    })
            }));
        }
        let sources = discovery["sources"].as_array().unwrap();
        assert!(sources.iter().any(|source| {
            source["kind"] == "theme_stylesheet"
                && source["component"]
                    == serde_json::json!({"kind": "theme", "slug": "synthetic-parent"})
                && source["parent_depth"] == 1
                && source["association"] == "same_theme_base_parent"
        }));
        assert!(sources.iter().all(|source| {
            source["resource_reference"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71)
                && source.get("url").is_none()
        }));

        let expected_metadata_requests = match fixture {
            DeploymentFixture::Prefixed => vec![
                "GET /blog/wp-json/ HTTP/1.1",
                "GET /blog/wp-content/themes/synthetic-child/style.css HTTP/1.1",
                "GET /blog/wp-content/themes/synthetic-parent/style.css HTTP/1.1",
                "GET /blog/wp-content/plugins/synthetic-discovery-plugin/readme.txt HTTP/1.1",
            ],
            DeploymentFixture::Declared => vec![
                "GET /blog/wp-json/ HTTP/1.1",
                "GET /site-content/themes/synthetic-child/style.css HTTP/1.1",
                "GET /site-content/themes/synthetic-parent/style.css HTTP/1.1",
                "GET /modules/synthetic-discovery-plugin/readme.txt HTTP/1.1",
            ],
        };
        let requests = server.requests.lock().unwrap().clone();
        let actual_metadata_requests = requests
            .iter()
            .filter(|request| expected_metadata_requests.contains(&request.as_str()))
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(actual_metadata_requests, expected_metadata_requests);
        assert!(requests.iter().all(|request| !request.contains("/shop/")));

        if let Some((_, original)) = &layout_bytes {
            let expected_digest = format!("{:x}", Sha256::digest(original));
            assert_eq!(
                discovery["layout"]["declaration"]["byte_length"],
                original.len()
            );
            assert_eq!(
                discovery["layout"]["declaration"]["sha256"],
                expected_digest
            );
            assert!(sources.iter().any(|source| {
                source["association"] == "explicit_operator" && source["kind"] == "theme_stylesheet"
            }));
            assert!(sources.iter().any(|source| {
                source["association"] == "explicit_operator" && source["kind"] == "plugin_readme"
            }));
        } else {
            assert!(discovery["layout"].get("declaration").is_none());
            assert!(sources.iter().any(|source| {
                source["association"] == "observed_conventional"
                    && source["kind"] == "theme_stylesheet"
            }));
        }

        let before_offline = requests.len();
        let verify = termivar()
            .args(["report", "verify", "--dir"])
            .arg(&output_directory)
            .args(["--format", "json"])
            .output()
            .expect("termivar process must start");
        assert_success(&verify, "deployment-aware Report Verify");
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
        assert_success(&compare, "deployment-aware Report Compare");
        let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
        assert!(comparison["only_in_after"].as_array().unwrap().is_empty());
        assert!(comparison["only_in_before"].as_array().unwrap().is_empty());
        assert!(comparison["changed"].as_array().unwrap().is_empty());
        assert_eq!(
            comparison["unchanged"].as_array().unwrap().len(),
            assessment["item_count"].as_u64().unwrap() as usize
        );
        assert_eq!(server.requests.lock().unwrap().len(), before_offline);
    }
}
