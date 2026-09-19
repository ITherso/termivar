//! Real-process acceptance for the compile-time CLI capability inventory.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

const FEATURE_NAMES: &[&str] = &[
    "api-adapter",
    "artifact-adapter",
    "authorization-review",
    "graphql-review",
    "legacy-scanner",
    "normalization-resilience",
    "openapi-review",
    "proxy-adapter",
    "release-bundle",
    "rest-review",
    "secret-exposure-review",
    "ssrf-oast-review",
    "supplied-session-review",
    "tls-observation",
    "wordpress-review",
];

fn manifest_release_bundle_members() -> Vec<&'static str> {
    let mut inside = false;
    let mut members = Vec::new();
    for line in include_str!("../Cargo.toml").lines() {
        let line = line.trim();
        if line == "release-bundle = [" {
            inside = true;
        } else if inside && line == "]" {
            break;
        } else if inside {
            let member = line
                .trim_end_matches(',')
                .strip_prefix('"')
                .and_then(|member| member.strip_suffix('"'))
                .expect("release-bundle members must remain literal feature names");
            members.push(member);
        }
    }
    assert!(
        inside,
        "release-bundle feature is missing from the manifest"
    );
    assert!(!members.is_empty(), "release-bundle feature has no members");
    members
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_termivar"))
}

fn run(binary: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .output()
        .expect("termivar process must start")
}

fn run_json(binary: &Path) -> (Output, Value) {
    let output = run(binary, &["capabilities", "--format", "json"]);
    let value = serde_json::from_slice(&output.stdout).expect("capabilities JSON must parse");
    (output, value)
}

fn feature_states(document: &Value) -> BTreeMap<&str, &str> {
    document["cli_package_features"]
        .as_array()
        .expect("feature array")
        .iter()
        .map(|feature| {
            (
                feature["name"].as_str().expect("feature name"),
                feature["build_state"].as_str().expect("feature state"),
            )
        })
        .collect()
}

fn surface_state<'a>(document: &'a Value, key: &str) -> &'a str {
    document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == key)
        .unwrap_or_else(|| panic!("missing surface {key}"))["build_state"]
        .as_str()
        .expect("surface state")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn actual_binary_reports_package_scoped_compile_time_truth() {
    let (output, document) = run_json(&binary());
    assert_success(&output);
    assert_eq!(document["schema"], "termivar-cli-capabilities/v1");
    assert_eq!(document["product"], "Termivar");
    assert_eq!(document["package_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(document["inventory_scope"], "cli_surfaces");
    assert_eq!(document["runtime_execution"], "not_performed");

    let states = feature_states(&document);
    assert_eq!(states.len(), FEATURE_NAMES.len());
    assert_eq!(states.keys().copied().collect::<Vec<_>>(), FEATURE_NAMES);
    for (feature, compiled) in [
        ("api-adapter", cfg!(feature = "api-adapter")),
        ("artifact-adapter", cfg!(feature = "artifact-adapter")),
        (
            "authorization-review",
            cfg!(feature = "authorization-review"),
        ),
        ("graphql-review", cfg!(feature = "graphql-review")),
        ("legacy-scanner", cfg!(feature = "legacy-scanner")),
        (
            "normalization-resilience",
            cfg!(feature = "normalization-resilience"),
        ),
        ("openapi-review", cfg!(feature = "openapi-review")),
        ("proxy-adapter", cfg!(feature = "proxy-adapter")),
        ("release-bundle", cfg!(feature = "release-bundle")),
        ("rest-review", cfg!(feature = "rest-review")),
        (
            "secret-exposure-review",
            cfg!(feature = "secret-exposure-review"),
        ),
        ("ssrf-oast-review", cfg!(feature = "ssrf-oast-review")),
        (
            "supplied-session-review",
            cfg!(feature = "supplied-session-review"),
        ),
        ("tls-observation", cfg!(feature = "tls-observation")),
        ("wordpress-review", cfg!(feature = "wordpress-review")),
    ] {
        assert_eq!(
            states[feature],
            if compiled { "compiled" } else { "not_compiled" },
            "{feature}"
        );
    }
    assert_eq!(
        surface_state(&document, "option.rest-review"),
        states["rest-review"]
    );
    assert_eq!(
        surface_state(&document, "option.secret-exposure-review"),
        states["secret-exposure-review"]
    );
    assert_eq!(
        surface_state(&document, "option.wordpress-review"),
        states["wordpress-review"]
    );
    assert_eq!(
        surface_state(&document, "option.wordpress-discovery"),
        states["wordpress-review"]
    );
    assert_eq!(
        surface_state(&document, "option.supplied-session-review"),
        states["supplied-session-review"]
    );
    assert_eq!(
        surface_state(&document, "option.tls-observation"),
        states["tls-observation"]
    );
    let tls = document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == "option.tls-observation")
        .expect("TLS-observation surface");
    assert_eq!(
        tls["documentation"],
        "docs/internals/existing-connection-tls-observation.md"
    );
    assert_eq!(
        tls["prerequisites"],
        serde_json::json!(["--profile web-review", "--tls-observation"])
    );
    let tls_limit = tls["limitation"]
        .as_str()
        .expect("TLS-observation limitation");
    for required in [
        "successful HTTPS responses already obtained through the assessment broker",
        "adds no request or handshake",
        "only one leaf DER certificate",
        "Negotiated TLS version, cipher suite, ALPN, full chain, connection reuse, handshake kind and resumption are not exposed",
        "revocation, OCSP, CT and AIA retrieval are not performed",
        "Repeated certificate bytes do not identify one connection",
        "one successful connection does not enumerate server support",
        "Plain HTTP is not applicable",
        "missing TLS metadata remains unavailable",
    ] {
        assert!(
            tls_limit.contains(required),
            "missing TLS-observation limitation `{required}`"
        );
    }
    let secret_exposure = document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == "option.secret-exposure-review")
        .expect("secret-exposure surface");
    assert_eq!(
        secret_exposure["documentation"],
        "docs/internals/passive-secret-exposure-review.md"
    );
    assert_eq!(
        secret_exposure["prerequisites"],
        serde_json::json!(["--profile web-review", "--secret-exposure-review"])
    );
    let secret_exposure_limit = secret_exposure["limitation"]
        .as_str()
        .expect("secret-exposure limitation");
    for required in [
        "existing anonymous committed complete status-200 uncoded textual GET response bodies",
        "zero additional requests",
        "fixed bounded detector catalogue",
        "no raw matched values or hashes",
        "V1 fails closed when GraphQL, OpenAPI, REST, resource authorization, or WordPress discovery is selected",
        "those response paths do not share its value-free body-digest boundary",
        "Credential validity, ownership, source authenticity, provider acceptance",
        "exploit execution, and impact validation are not established or performed",
        "Authenticated supplied-session response bodies are not selected",
    ] {
        assert!(
            secret_exposure_limit.contains(required),
            "missing secret-exposure limitation `{required}`"
        );
    }
    let supplied_session = document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == "option.supplied-session-review")
        .expect("supplied-session surface");
    assert_eq!(
        supplied_session["documentation"],
        "docs/internals/supplied-session-review.md"
    );
    assert_eq!(
        supplied_session["prerequisites"],
        serde_json::json!([
            "--profile web-review",
            "--session-policy FILE",
            "V1: one of --session-auth-env, --session-auth-file, or --session-auth-stdin",
            "V2: --session-cookie-file FILE",
            "optional --wordpress-supplied-session when also compiled with wordpress-review",
            "HTTPS, except numeric-loopback HTTP fixtures; Secure cookies still require HTTPS"
        ])
    );
    let session_limit = supplied_session["limitation"]
        .as_str()
        .expect("supplied-session limitation");
    for required in [
        "context-isolated, no-proxy",
        "health checks qualify",
        "without anonymous fallback",
        "no request body or non-GET method",
        "GET handling can still have server-side effects",
        "operator must authorize every selected resource",
        "strict local V1 authorization_header or V2 cookie_jar policy",
        "selected response-cookie update",
        "unusable response-cookie classification",
        "No response cookie update is applied, no refresh occurs",
        "host/domain/path/Secure/expiry",
        "Domain never expands it",
        "HttpOnly and SameSite are preserved facts, not browser CSRF emulation",
        "No browser-profile import, login, automatic refresh, OAuth, MFA",
        "exploit, or impact validation",
        "health-qualified session-resource HTML may nominate public WordPress metadata",
        "credential is not sent to metadata or fingerprint requests",
        "authenticated-page fingerprint acquisition is not selected",
    ] {
        assert!(
            session_limit.contains(required),
            "missing supplied-session limitation `{required}`"
        );
    }
    let wordpress = document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == "option.wordpress-review")
        .expect("WordPress surface");
    assert_eq!(wordpress["documentation"], "docs/wordpress-review.md");
    assert_eq!(
        wordpress["prerequisites"],
        serde_json::json!([
            "--profile web-review",
            "--wordpress-review",
            "optional --wordpress-context FILE",
            "optional --wordpress-advisories FILE",
            "optional --wordpress-advisories-format termivar|wordfence-v3-production",
            "optional --wordpress-external-version-profile numeric-dotted/v1|php-release-subset/v1 (Wordfence Production only)",
            "optional --wordpress-plugins-json FILE",
            "optional --wordpress-themes-json FILE",
            "optional --wordpress-core-version-file FILE"
        ])
    );
    let wordpress_limit = wordpress["limitation"]
        .as_str()
        .expect("WordPress limitation");
    for required in [
        "no target requests",
        "catalogue_not_supplied",
        "never an all-clear",
        "no exploit or impact validation",
        "operator may explicitly select",
        "source's own comparison semantics remain not established",
        "Without that selector the external relation stays indeterminate",
    ] {
        assert!(
            wordpress_limit.contains(required),
            "missing WordPress limitation `{required}`"
        );
    }
    let wordpress_discovery = document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == "option.wordpress-discovery")
        .expect("WordPress discovery surface");
    assert_eq!(
        wordpress_discovery["documentation"],
        "docs/wordpress-review.md"
    );
    assert_eq!(wordpress_discovery["compile_feature"], "wordpress-review");
    assert_eq!(
        wordpress_discovery["prerequisites"],
        serde_json::json!([
            "--profile web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "optional --wordpress-page-scope observed",
            "optional --wordpress-layout FILE",
            "optional --wordpress-fingerprints FILE",
            "optional --wordpress-supplied-session when also compiled with supplied-session-review"
        ])
    );
    let discovery_limit = wordpress_discovery["limitation"]
        .as_str()
        .expect("WordPress discovery limitation");
    for required in [
        "at most 12",
        "anonymous same-origin WordPress-owned GET requests",
        "never enabled by --wordpress-review alone",
        "observed reuses eligible committed page responses without retrieving pages",
        "Reused pages may nominate metadata within the same shared limit",
        "finite listed release set",
        "cannot nominate unseen resources or establish an installed version",
        "URL ver remain hints",
        "plugin Stable tag is not treated as an installed version",
        "no exploit or impact validation",
        "health-qualified session-resource HTML may nominate public metadata",
        "credential is never forwarded to WordPress metadata or fingerprint requests",
        "authenticated-page fingerprint acquisition is not selected",
    ] {
        assert!(
            discovery_limit.contains(required),
            "missing WordPress discovery limitation `{required}`"
        );
    }
    assert_eq!(
        surface_state(&document, "option.live-assessment-progress"),
        "compiled"
    );
    let progress = document["surfaces"]
        .as_array()
        .expect("surface array")
        .iter()
        .find(|surface| surface["key"] == "option.live-assessment-progress")
        .expect("live progress surface");
    assert_eq!(
        progress["prerequisites"],
        serde_json::json!(["--profile web-review", "--progress"])
    );
    assert_eq!(progress["group"], "everyday");
    assert_eq!(progress["kind"], "scan_option");
    let limitation = progress["limitation"]
        .as_str()
        .expect("progress limitation");
    for required in [
        "stderr-only",
        "last-observed",
        "no ETA",
        "neither controls execution",
    ] {
        assert!(limitation.contains(required), "missing `{required}`");
    }
    assert_eq!(
        surface_state(&document, "command.api"),
        states["api-adapter"]
    );
    assert_eq!(
        document["build_origin_authenticity"],
        "Self-reported package version and compile features do not establish source authenticity, an official release origin, or runtime readiness."
    );
}

#[test]
fn text_and_json_are_stable_views_of_the_same_inventory() {
    let text = run(&binary(), &["capabilities"]);
    let (json_output, document) = run_json(&binary());
    assert_success(&text);
    assert_success(&json_output);
    let text = String::from_utf8(text.stdout).expect("text UTF-8");
    assert!(text.starts_with("Termivar CLI capabilities\n"));
    assert!(text.contains(&format!("version: {}", env!("CARGO_PKG_VERSION"))));
    assert!(text.contains("runtime_execution: not_performed"));
    assert!(text.contains("Build inventory only. No assessment was started or evaluated."));
    for surface in document["surfaces"].as_array().expect("surfaces") {
        let state = surface["build_state"].as_str().expect("state");
        let label = surface["label"].as_str().expect("label");
        assert!(text.contains(&format!("[{state}] {label}")));
    }

    let repeated_text = run(&binary(), &["capabilities"]);
    let repeated_json = run(&binary(), &["capabilities", "--format", "json"]);
    assert_eq!(text.as_bytes(), repeated_text.stdout);
    assert_eq!(json_output.stdout, repeated_json.stdout);
}

#[test]
fn compiled_inventory_matches_the_actual_binary_help() {
    let (_, document) = run_json(&binary());
    let top = run(&binary(), &["--help"]);
    let scan = run(&binary(), &["scan", "--help"]);
    let report = run(&binary(), &["report", "--help"]);
    assert_success(&top);
    assert_success(&scan);
    assert_success(&report);
    let top = String::from_utf8(top.stdout).unwrap();
    let scan = String::from_utf8(scan.stdout).unwrap();
    let report = String::from_utf8(report.stdout).unwrap();
    for command in ["capabilities", "scan", "report"] {
        assert!(top.contains(command));
    }
    for command in ["compare", "verify"] {
        assert!(report.contains(command));
    }
    for (key, option) in [
        ("option.live-assessment-progress", "--progress"),
        (
            "option.normalization-resilience",
            "--normalization-resilience",
        ),
        ("option.graphql-review", "--graphql-review"),
        ("option.openapi-review", "--openapi-review"),
        ("option.rest-review", "--rest-review"),
        (
            "option.resource-authorization-review",
            "--authorization-review-policy",
        ),
        ("option.secret-exposure-review", "--secret-exposure-review"),
        ("option.tls-observation", "--tls-observation"),
        ("option.ssrf-oast-review", "--ssrf-oast-review"),
        ("option.supplied-session-review", "--session-policy"),
        ("option.wordpress-review", "--wordpress-review"),
        ("option.wordpress-discovery", "--wordpress-discovery"),
    ] {
        assert_eq!(
            surface_state(&document, key) == "compiled",
            scan.contains(option),
            "{key}"
        );
    }
    assert_eq!(
        surface_state(&document, "option.supplied-session-review") == "compiled",
        scan.contains("--session-cookie-file"),
        "supplied-session cookie source/help drift"
    );
    let feature_states = feature_states(&document);
    assert_eq!(
        feature_states["supplied-session-review"] == "compiled"
            && feature_states["wordpress-review"] == "compiled",
        scan.contains("--wordpress-supplied-session"),
        "combined WordPress supplied-session help must require both compiled features"
    );
    for (key, command) in [
        ("command.artifact", "artifact"),
        ("command.legacy-scan", "legacy-scan"),
        ("command.api", "api"),
        ("command.proxy", "proxy"),
    ] {
        assert_eq!(
            surface_state(&document, key) == "compiled",
            top.contains(command),
            "{key}"
        );
    }
    let alias = run(&binary(), &["decision-scan", "--help"]);
    assert_success(&alias);
    let scan_surface = document["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|surface| surface["key"] == "command.scan")
        .unwrap();
    assert_eq!(scan_surface["alias"]["name"], "decision-scan");
    assert_eq!(scan_surface["alias"]["maturity"], "deprecated");
    assert_eq!(
        scan_surface["alias"]["relation"],
        "compatibility_alias_same_engine"
    );
    assert!(!document["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|surface| surface["key"] == "command.decision-scan"));
}

#[test]
fn copied_binary_runs_from_an_empty_directory_without_tool_discovery() {
    let temporary = tempfile::tempdir().unwrap();
    let empty_path = temporary.path().join("empty-path");
    fs::create_dir(&empty_path).unwrap();
    let copied = temporary.path().join(if cfg!(windows) {
        "termivar.exe"
    } else {
        "termivar"
    });
    fs::copy(binary(), &copied).unwrap();

    let baseline = run(&binary(), &["capabilities", "--format", "json"]);
    assert_success(&baseline);
    let isolated = Command::new(&copied)
        .args(["capabilities", "--format", "json"])
        .current_dir(temporary.path())
        .env("PATH", &empty_path)
        .env("CARGO_FEATURE_REST_REVIEW", "runtime-values-are-ignored")
        .env("CARGO_FEATURE_RELEASE_BUNDLE", "runtime-values-are-ignored")
        .env("TERMIVAR_TEST_CREDENTIAL_SENTINEL", "must-not-appear")
        .output()
        .expect("copied binary must start");
    assert_success(&isolated);
    assert_eq!(baseline.stdout, isolated.stdout);
    let text = String::from_utf8(isolated.stdout).unwrap();
    let temporary_path = temporary.path().to_string_lossy();
    for forbidden in [
        "runtime-values-are-ignored",
        "must-not-appear",
        temporary_path.as_ref(),
    ] {
        assert!(!text.contains(forbidden));
    }
}

#[test]
fn malformed_capabilities_invocations_are_usage_errors() {
    for arguments in [
        vec!["capabilities", "extra"],
        vec!["capabilities", "--format", "yaml"],
        vec!["capabilities", "--target", "https://example.test"],
    ] {
        let output = run(&binary(), &arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn matrix_case_proves_release_bundle_is_composition_not_origin() {
    let Ok(case) = env::var("TERMIVAR_CAPABILITIES_MATRIX_CASE") else {
        return;
    };
    let (output, document) = run_json(&binary());
    assert_success(&output);
    let states = feature_states(&document);
    let compiled = |name: &str| states[name] == "compiled";
    let release_members = manifest_release_bundle_members();
    assert_eq!(
        release_members,
        [
            "artifact-adapter",
            "normalization-resilience",
            "graphql-review",
            "openapi-review",
            "rest-review",
            "authorization-review",
            "wordpress-review",
        ]
    );
    let excluded = [
        "api-adapter",
        "legacy-scanner",
        "proxy-adapter",
        "secret-exposure-review",
        "ssrf-oast-review",
        "supplied-session-review",
        "tls-observation",
    ];
    match case.as_str() {
        "default" | "no-default" => {
            assert!(FEATURE_NAMES.iter().all(|feature| !compiled(feature)));
        },
        "release-bundle" => {
            assert!(compiled("release-bundle"));
            assert!(release_members.iter().all(|feature| compiled(feature)));
            assert!(excluded.iter().all(|feature| !compiled(feature)));
            assert_eq!(
                states
                    .values()
                    .filter(|state| **state == "compiled")
                    .count(),
                8
            );
            assert_eq!(
                states
                    .values()
                    .filter(|state| **state == "not_compiled")
                    .count(),
                7
            );
        },
        "rest-only" => {
            assert!(compiled("rest-review"));
            assert!(compiled("openapi-review"));
            assert!(FEATURE_NAMES.iter().all(|feature| {
                matches!(*feature, "rest-review" | "openapi-review") || !compiled(feature)
            }));
        },
        "session-only" => {
            assert!(compiled("supplied-session-review"));
            assert!(FEATURE_NAMES
                .iter()
                .all(|feature| { *feature == "supplied-session-review" || !compiled(feature) }));
        },
        "secret-only" => {
            assert!(compiled("secret-exposure-review"));
            assert!(FEATURE_NAMES
                .iter()
                .all(|feature| { *feature == "secret-exposure-review" || !compiled(feature) }));
        },
        "tls-only" => {
            assert!(compiled("tls-observation"));
            assert!(FEATURE_NAMES
                .iter()
                .all(|feature| { *feature == "tls-observation" || !compiled(feature) }));
        },
        "bundle-members-individual" => {
            assert!(!compiled("release-bundle"));
            assert!(release_members.iter().all(|feature| compiled(feature)));
            assert!(excluded.iter().all(|feature| !compiled(feature)));
        },
        "all-features" => {
            assert!(FEATURE_NAMES.iter().all(|feature| compiled(feature)));
        },
        other => panic!("unknown matrix case {other}"),
    }
    assert_eq!(document["runtime_execution"], "not_performed");
    assert_eq!(
        surface_state(&document, "option.live-assessment-progress"),
        "compiled",
        "the UI option is always compiled and is not a Cargo feature"
    );
    assert!(document["build_origin_authenticity"]
        .as_str()
        .unwrap()
        .contains("do not establish source authenticity"));

    let bytes = fs::read(binary()).unwrap();
    let digest = Sha256::digest(&bytes);
    eprintln!(
        "capabilities-build-evidence case={case} package_version={} binary_sha256={digest:x} features={}",
        env!("CARGO_PKG_VERSION"),
        states
            .iter()
            .filter_map(|(feature, state)| (*state == "compiled").then_some(*feature))
            .collect::<Vec<_>>()
            .join(",")
    );
}
