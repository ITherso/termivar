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
    "ssrf-oast-review",
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
        ("ssrf-oast-review", cfg!(feature = "ssrf-oast-review")),
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
        ("option.ssrf-oast-review", "--ssrf-oast-review"),
    ] {
        assert_eq!(
            surface_state(&document, key) == "compiled",
            scan.contains(option),
            "{key}"
        );
    }
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
        ]
    );
    let excluded = [
        "api-adapter",
        "legacy-scanner",
        "proxy-adapter",
        "ssrf-oast-review",
    ];
    match case.as_str() {
        "default" | "no-default" => {
            assert!(FEATURE_NAMES.iter().all(|feature| !compiled(feature)));
        },
        "release-bundle" => {
            assert!(compiled("release-bundle"));
            assert!(release_members.iter().all(|feature| compiled(feature)));
            assert!(excluded.iter().all(|feature| !compiled(feature)));
        },
        "rest-only" => {
            assert!(compiled("rest-review"));
            assert!(compiled("openapi-review"));
            assert!(FEATURE_NAMES.iter().all(|feature| {
                matches!(*feature, "rest-review" | "openapi-review") || !compiled(feature)
            }));
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
