//! Synthetic actual-process V3/WordPress composition, using the normal CLI.
//! The independent WordPress-backed login oracle belongs to the separate CMS lab.

use super::*;

const ENTRY: &str = r#"<!doctype html><html><head>
<meta name="generator" content="WordPress 6.9.4">
<link rel="https://api.w.org/" href="/app/wp-json/">
<link rel="stylesheet" href="/app/wp-content/themes/form-page-theme/style.css">
</head><body>public original fixture</body></html>"#;
const PRIVATE_PAGE: &str = r#"<!doctype html><html><head>
<script src="/app/wp-content/plugins/form-page-component/assets/site.js"></script>
<link rel="stylesheet" href="/app/wp-content/plugins/form-page-component/assets/site.css">
</head><body>PRIVATE-RESPONSE-CANARY-MUST-NOT-LEAK</body></html>"#;
const README: &str = "=== Form Page Component ===\nStable tag: 9.9.9\n";
const PLUGIN_README: &str = "/app/wp-content/plugins/form-page-component/readme.txt";
const STYLE: &str = "/app/wp-content/themes/form-page-theme/style.css";

#[derive(Clone, Copy, Debug)]
enum Scene {
    Healthy,
    WrongPassword,
    WrongPrincipal,
    HealthLoss,
    DuplicateCsrf,
    CookieUpdate,
    SiblingApplication,
}

fn serve_wordpress_form_login() -> TestServer {
    serve_scene(Scene::Healthy)
}

fn serve_scene(scene: Scene) -> TestServer {
    let health_count = std::sync::atomic::AtomicUsize::new(0);
    serve_form_login(move |_, record| {
        if record.authorization != AuthorizationClass::Absent {
            return response("401 Unauthorized", "text/plain", "unavailable", "");
        }
        match (
            record.method.as_str(),
            record.target.as_str(),
            record.cookie,
            record.form_body,
        ) {
            ("GET", "/app/login", CookieClass::Absent, FormBodyClass::Absent) => {
                if matches!(scene, Scene::DuplicateCsrf) {
                    html_ok(&valid_form_login_page().replace(
                        "</form>",
                        &format!("<input type=\"hidden\" name=\"csrf\" value=\"{LOGIN_CSRF}\"></form>"),
                    ))
                } else {
                    html_ok(&valid_form_login_page())
                }
            },
            ("POST", "/app/login", CookieClass::Absent, FormBodyClass::Expected)
                if record.form_content_type =>
            {
                if matches!(scene, Scene::WrongPassword) {
                    return html_ok(&valid_form_login_page());
                }
                response(
                    "200 OK",
                    "application/json",
                    r#"{"received":true}"#,
                    &format!(
                        "Set-Cookie: session={LOGIN_COOKIE}; Path=/app/; HttpOnly; SameSite=Lax\r\n"
                    ),
                )
            },
            ("GET", "/app/health", CookieClass::LoginExpected, FormBodyClass::Absent) => {
                let sequence = health_count.fetch_add(1, Ordering::Relaxed);
                if matches!(scene, Scene::WrongPrincipal)
                    || (matches!(scene, Scene::HealthLoss) && sequence > 0)
                {
                    json_ok(r#"{"authenticated":false}"#)
                } else {
                    json_ok(r#"{"authenticated":true}"#)
                }
            },
            ("GET", "/app/private", CookieClass::LoginExpected, FormBodyClass::Absent) => {
                match scene {
                    Scene::CookieUpdate => response(
                        "200 OK", "text/html", PRIVATE_PAGE,
                        "Set-Cookie: session=rotated-cookie-canary; Path=/app/; HttpOnly\r\n",
                    ),
                    Scene::SiblingApplication => html_ok(&PRIVATE_PAGE.replace(
                        "</head>",
                        "<link rel=\"stylesheet\" href=\"/shop/wp-content/themes/other/style.css\"></head>",
                    )),
                    _ => html_ok(PRIVATE_PAGE),
                }
            },
            ("GET" | "HEAD", "/app/", CookieClass::Absent, FormBodyClass::Absent) => html_ok(ENTRY),
            ("GET", "/app/wp-json/", CookieClass::Absent, FormBodyClass::Absent) => {
                json_ok(r#"{"namespaces":["wp/v2"]}"#)
            },
            ("GET" | "HEAD", STYLE, CookieClass::Absent, FormBodyClass::Absent) => response(
                "200 OK",
                "text/css",
                "/* Theme Name: Form Page Theme\nVersion: 1.5\n*/\nbody{color:black}\n",
                "",
            ),
            ("GET", PLUGIN_README, CookieClass::Absent, FormBodyClass::Absent) => {
                response("200 OK", "text/plain", README, "")
            },
            _ => response("404 Not Found", "text/plain", "unavailable", ""),
        }
    })
}

fn scan_wordpress_form_login(
    server: &TestServer,
    policy: &Path,
    login: &Path,
    destination: &Path,
    integration: bool,
) -> Output {
    let mut command = termivar();
    command.args([
        "scan",
        &server.application_url,
        "--profile",
        "web-review",
        "--wordpress-review",
        "--wordpress-discovery",
        "--format",
        "json",
        "--progress",
    ]);
    if integration {
        command.arg("--wordpress-supplied-session");
    }
    command
        .arg("--session-policy")
        .arg(policy)
        .arg("--session-login-file")
        .arg(login)
        .arg("--report-dir")
        .arg(destination)
        .output()
        .expect("run actual V3 WordPress CLI")
}

#[test]
fn wordpress_form_login_real_cli_qualifies_anonymous_metadata() {
    let mut server = serve_wordpress_form_login();
    let parent = tempfile::tempdir().expect("create private V3 WordPress fixture");
    let (policy, login) = write_form_login_inputs(parent.path(), &server.application_url);
    let policy_before = fs::read(&policy).expect("read original policy bytes");
    let login_before = fs::read(&login).expect("read original synthetic login bytes");
    let destination = parent.path().join("wordpress-form-login-bundle");
    let output = scan_wordpress_form_login(&server, &policy, &login, &destination, true);
    assert!(
        output.status.success(),
        "actual V3 WordPress scan failed: {:?}",
        output.status
    );
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let (assessment_bytes, assessment) = read_assessment(&destination);
    assert_no_private_values(&assessment_bytes);
    assert_bundle_has_no_private_values(&destination);
    let session = &assessment["supplied_session"];
    assert_complete_v3_diagnostic_login(session);
    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(discovery["schema"], "security.wordpress-discovery-audit/v4");
    assert_eq!(
        discovery["policy_id"],
        "termivar.wordpress-supplied-session-metadata-discovery/v2"
    );
    assert_eq!(discovery["credential_mode"], "anonymous");
    assert_eq!(discovery["attempted_request_count"], 3);
    assert_eq!(discovery["source_count"], 3);
    let pages = &discovery["supplied_session_pages"];
    assert_eq!(pages["mode"], "form_login_supplied_session_resources");
    assert_eq!(pages["session_epoch"], 1);
    assert_eq!(pages["selected_count"], 1);
    assert_eq!(pages["committed_count"], 1);
    assert_eq!(pages["accepted_association_count"], 1);
    let page = &pages["pages"].as_array().expect("typed page array")[0];
    assert_eq!(
        page["page_reference"],
        independent_page_reference(&server, session)
    );
    assert_eq!(page["association"], "accepted");
    assert_eq!(page["outcome"], "accepted");
    assert_eq!(
        page["resource_evidence_reference"],
        session["resources"][0]["evidence_reference"]
    );
    let sources = discovery["sources"].as_array().expect("typed source array");
    let plugin = sources
        .iter()
        .find(|source| {
            source["kind"] == "plugin_readme"
                && source["component"]["slug"] == "form-page-component"
        })
        .expect("private page must nominate its plugin without inventory");
    assert_eq!(plugin["plugin"]["stable_tag"], "9.9.9");
    assert_eq!(
        plugin["source_supplied_session_page_references"],
        serde_json::json!([page["page_reference"]])
    );
    let component = assessment["wordpress_review"]["components"]
        .as_array()
        .expect("typed component rows")
        .iter()
        .find(|component| component["identity"]["slug"] == "form-page-component")
        .expect("observed plugin component");
    assert_eq!(component["versions"], serde_json::json!([]));
    assert!(assessment.get("wordpress_asset_fingerprints").is_none());
    let records = server.requests.lock().unwrap().clone();
    let session_trace = records
        .iter()
        .filter(|record| {
            matches!(
                record.target.as_str(),
                "/app/login" | "/app/health" | "/app/private"
            )
        })
        .map(|record| {
            (
                record.method.as_str(),
                record.target.as_str(),
                record.cookie,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        session_trace,
        [
            ("GET", "/app/login", CookieClass::Absent),
            ("POST", "/app/login", CookieClass::Absent),
            ("GET", "/app/health", CookieClass::LoginExpected),
            ("GET", "/app/private", CookieClass::LoginExpected),
            ("GET", "/app/health", CookieClass::LoginExpected),
        ]
    );
    assert!(records.iter().all(|record| {
        record.authorization == AuthorizationClass::Absent
            && (matches!(record.target.as_str(), "/app/health" | "/app/private")
                || record.cookie == CookieClass::Absent)
    }));
    assert_eq!(
        records
            .iter()
            .filter(|record| record.target == PLUGIN_README)
            .count(),
        1
    );
    assert!(!records
        .iter()
        .any(|record| record.target.contains("/form-page-component/assets/")));
    server.stop();
    assert_bundle_verify_and_self_compare_are_offline(&server, &destination, &assessment);
    assert_eq!(fs::read(&policy).unwrap(), policy_before);
    assert_eq!(fs::read(&login).unwrap(), login_before);
    assert_eq!(
        fs::read(destination.join("assessment.json")).unwrap(),
        assessment_bytes
    );
    record_executed_binary_identity();
}

// Test-only identity of the actual CLI used above, not the earlier OAuth-only
// build in a native job. The observer binds this to that job's exact checkout;
// GITHUB_SHA is intentionally not treated as the PR head (it can be a merge ref).
fn record_executed_binary_identity() {
    use sha2::{Digest, Sha256};
    const LIMIT: u64 = 128 * 1024 * 1024;
    // The four native qualification commands explicitly use --release. Debug
    // images may embed extensive symbols; they still execute EVERY functional
    // assertion above, but this extra release-image measurement is not theirs.
    if cfg!(debug_assertions) {
        eprintln!("TERMIVAR_WORDPRESS_FORM_LOGIN_IDENTITY_NOT_MEASURED profile=debug reason=release_only_qualification");
        return;
    }
    let path = Path::new(env!("CARGO_BIN_EXE_termivar"));
    let metadata = fs::symlink_metadata(path).expect("inspect executed fixture CLI");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert!(metadata.len() > 0 && metadata.len() <= LIMIT);
    let mut file = fs::File::open(path).expect("read executed fixture CLI");
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = file.read(&mut buffer).expect("hash executed fixture CLI");
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).unwrap();
        assert!(total <= LIMIT);
        hasher.update(&buffer[..count]);
    }
    assert_eq!(total, metadata.len());
    assert_eq!(fs::metadata(path).unwrap().len(), total);
    let record = serde_json::json!({
        "schema": "native-wordpress-form-login-executable/v1",
        "run_id": std::env::var("GITHUB_RUN_ID").ok(),
        "run_attempt": std::env::var("GITHUB_RUN_ATTEMPT").ok(),
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "package_version": env!("CARGO_PKG_VERSION"),
        "supplied_session_review": true,
        "wordpress_review": true,
        "release_bundle": cfg!(feature = "release-bundle"),
        "bytes": total,
        "sha256": format!("{:x}", hasher.finalize()),
        "assurance": "self_reported_hash_joined_to_exact_job_checkout_not_attestation"
    });
    eprintln!("TERMIVAR_WORDPRESS_FORM_LOGIN_EXECUTABLE {record}");
}

// Literal framing oracle: no production collector/reference helper is called.
fn independent_page_reference(server: &TestServer, session: &Value) -> String {
    use sha2::{Digest, Sha256};
    let target = format!("{}private", server.application_url);
    let mut input = Vec::new();
    for value in [
        b"security.wordpress-supplied-session-page.v1".as_slice(),
        session["policy_reference"].as_str().unwrap().as_bytes(),
        session["application_reference"]
            .as_str()
            .unwrap()
            .as_bytes(),
        session["principal_reference"].as_str().unwrap().as_bytes(),
        target.as_bytes(),
        session["resources"][0]["resource_reference"]
            .as_str()
            .unwrap()
            .as_bytes(),
        &[0],
    ] {
        input.extend_from_slice(&(value.len() as u64).to_be_bytes());
        input.extend_from_slice(value);
    }
    format!("sha256:{:x}", Sha256::digest(input))
}

fn assert_negative_scene(scene: Scene) {
    // These expected results are specified independently of the collector.
    let (outcome, requests, epoch, committed, association, page_outcome) = match scene {
        Scene::WrongPassword => (
            "login_cookie_unavailable",
            2,
            0,
            0,
            "not_established",
            "not_evaluated",
        ),
        Scene::DuplicateCsrf => (
            "login_form_unavailable",
            1,
            0,
            0,
            "not_established",
            "not_evaluated",
        ),
        Scene::WrongPrincipal => (
            "startup_unhealthy",
            3,
            0,
            0,
            "not_established",
            "not_evaluated",
        ),
        Scene::HealthLoss => ("session_lost", 5, 1, 0, "not_established", "not_evaluated"),
        Scene::CookieUpdate => (
            "credential_update_required",
            4,
            1,
            0,
            "not_established",
            "not_evaluated",
        ),
        Scene::SiblingApplication => ("complete", 5, 1, 1, "rejected", "incompatible_application"),
        Scene::Healthy => panic!("positive scene has its own independent test"),
    };
    {
        let mut server = serve_scene(scene);
        let parent = tempfile::tempdir().unwrap();
        let (policy, login) = write_form_login_inputs(parent.path(), &server.application_url);
        let policy_before = fs::read(&policy).unwrap();
        let login_before = fs::read(&login).unwrap();
        let destination = parent.path().join("negative-bundle");
        let output = scan_wordpress_form_login(&server, &policy, &login, &destination, true);
        assert!(
            output.status.success(),
            "{scene:?}: exit {:?}",
            output.status
        );
        assert_no_private_values(&output.stdout);
        assert_no_private_values(&output.stderr);
        let (bytes, document) = read_assessment(&destination);
        assert_no_private_values(&bytes);
        assert_bundle_has_no_private_values(&destination);
        let session = &document["supplied_session"];
        assert_eq!(session["outcome"], outcome, "{scene:?}");
        assert_eq!(session["dispatched_request_count"], requests, "{scene:?}");
        assert_eq!(session["committed_resource_count"], committed, "{scene:?}");
        assert_eq!(
            session["cookie_lifecycle"]["final_epoch"], epoch,
            "{scene:?}"
        );
        // Planned S01 resource identities are NOT rewritten after failed login.
        assert_eq!(session["resources"][0]["epoch"], 1);
        let discovery = &document["wordpress_discovery"];
        assert_eq!(
            discovery["policy_id"],
            "termivar.wordpress-supplied-session-metadata-discovery/v2"
        );
        assert_eq!(discovery["attempted_request_count"], 2);
        assert_eq!(discovery["source_count"], 2);
        let pages = &discovery["supplied_session_pages"];
        assert_eq!(pages["mode"], "form_login_supplied_session_resources");
        assert_eq!(pages["session_epoch"], epoch);
        assert_eq!(pages["selected_count"], 1);
        assert_eq!(pages["committed_count"], committed);
        assert_eq!(pages["accepted_association_count"], 0);
        assert_eq!(pages["rejected_association_count"], committed);
        let page = &pages["pages"].as_array().unwrap()[0];
        assert_eq!(
            page["page_reference"],
            independent_page_reference(&server, session)
        );
        assert_eq!(page["association"], association);
        assert_eq!(page["outcome"], page_outcome);
        if committed == 0 {
            assert_eq!(pages["interpreted_response_bytes"], 0);
            assert_eq!(page.get("resource_evidence_reference"), Some(&Value::Null));
        }
        for source in discovery["sources"].as_array().unwrap() {
            assert_eq!(
                source["source_supplied_session_page_references"],
                serde_json::json!([])
            );
        }
        assert!(!document["wordpress_review"]["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["identity"]["slug"] == "form-page-component"));
        assert!(document.get("wordpress_asset_fingerprints").is_none());
        let records = server.requests.lock().unwrap().clone();
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(
                    record.target.as_str(),
                    "/app/login" | "/app/health" | "/app/private"
                ))
                .count(),
            requests as usize
        );
        assert!(!records.iter().any(|record| record.target == PLUGIN_README
            || record.target.starts_with("/shop/")
            || record.target.contains("/form-page-component/assets/")));
        assert!(records
            .iter()
            .all(|record| record.authorization == AuthorizationClass::Absent
                && (matches!(record.target.as_str(), "/app/health" | "/app/private")
                    || record.cookie == CookieClass::Absent)));
        server.stop();
        assert_bundle_verify_and_self_compare_are_offline(&server, &destination, &document);
        assert_eq!(fs::read(&policy).unwrap(), policy_before);
        assert_eq!(fs::read(&login).unwrap(), login_before);
        assert_eq!(
            fs::read(destination.join("assessment.json")).unwrap(),
            bytes
        );
    }
}

#[test]
fn wordpress_form_login_wrong_password_retains_epoch_zero_empty_coverage() {
    assert_negative_scene(Scene::WrongPassword);
}

#[test]
fn wordpress_form_login_duplicate_csrf_refuses_post_and_component_authority() {
    assert_negative_scene(Scene::DuplicateCsrf);
}

#[test]
fn wordpress_form_login_wrong_principal_cookie_is_not_an_authenticated_epoch() {
    assert_negative_scene(Scene::WrongPrincipal);
}

#[test]
fn wordpress_form_login_health_loss_discards_staged_component_nomination() {
    assert_negative_scene(Scene::HealthLoss);
}

#[test]
fn wordpress_form_login_cookie_update_stops_without_component_nomination() {
    assert_negative_scene(Scene::CookieUpdate);
}

#[test]
fn wordpress_form_login_sibling_application_is_coverage_not_supporting_evidence() {
    assert_negative_scene(Scene::SiblingApplication);
}

#[test]
fn wordpress_form_login_option_off_preserves_session_and_generic_traffic_and_compares_offline() {
    let mut server = serve_wordpress_form_login();
    let parent = tempfile::tempdir().unwrap();
    let (policy, login) = write_form_login_inputs(parent.path(), &server.application_url);
    let mut bundles = Vec::new();
    let mut traces = Vec::new();
    for enabled in [false, true] {
        let start = server.requests.lock().unwrap().len();
        let directory = parent.path().join(if enabled { "on" } else { "off" });
        let output = scan_wordpress_form_login(&server, &policy, &login, &directory, enabled);
        assert!(
            output.status.success(),
            "option {enabled}: exit {:?}",
            output.status
        );
        assert_no_private_values(&output.stdout);
        assert_no_private_values(&output.stderr);
        let (bytes, assessment) = read_assessment(&directory);
        assert_complete_v3_diagnostic_login(&assessment["supplied_session"]);
        assert_eq!(
            assessment["wordpress_discovery"]["attempted_request_count"],
            if enabled { 3 } else { 2 }
        );
        assert_eq!(
            assessment["wordpress_discovery"]
                .get("supplied_session_pages")
                .is_some(),
            enabled
        );
        assert_bundle_has_no_private_values(&directory);
        traces.push(server.requests.lock().unwrap()[start..].to_vec());
        bundles.push((directory, bytes, assessment));
    }
    assert_eq!(
        traces[1]
            .iter()
            .filter(|row| row.target == PLUGIN_README)
            .count(),
        1
    );
    // Integration deliberately freezes the entry layout before S01 collection;
    // option-off S01 runs earlier. Compare the two owners' ordered subsequences,
    // not an invented invariant about their global interleaving.
    let is_session = |row: &&RequestRecord| {
        matches!(
            row.target.as_str(),
            "/app/login" | "/app/health" | "/app/private"
        )
    };
    assert_eq!(
        traces[0].iter().filter(is_session).collect::<Vec<_>>(),
        traces[1].iter().filter(is_session).collect::<Vec<_>>()
    );
    let ordinary = |rows: &[RequestRecord]| {
        rows.iter()
            .filter(|row| {
                !matches!(
                    row.target.as_str(),
                    "/app/login" | "/app/health" | "/app/private"
                ) && row.target != PLUGIN_README
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(ordinary(&traces[0]), ordinary(&traces[1]));
    server.stop();
    for (directory, bytes, assessment) in &bundles {
        assert_bundle_verify_and_self_compare_are_offline(&server, directory, assessment);
        assert_eq!(&fs::read(directory.join("assessment.json")).unwrap(), bytes);
    }
    let stopped_trace = server.requests.lock().unwrap().clone();
    for (before, after) in [(0, 1), (1, 0)] {
        let result = termivar()
            .args(["report", "compare", "--before"])
            .arg(bundles[before].0.join("assessment.json"))
            .arg("--after")
            .arg(bundles[after].0.join("assessment.json"))
            .args(["--same-scope", "--format", "json"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "controlled Compare exit {:?}",
            result.status
        );
        assert_no_private_values(&result.stdout);
        assert_no_private_values(&result.stderr);
        let comparison: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
        let length = |key: &str| {
            comparison[key]
                .as_array()
                .expect("four required arrays")
                .len() as u64
        };
        assert_eq!(
            length("only_in_before") + length("changed") + length("unchanged"),
            bundles[before].2["item_count"].as_u64().unwrap()
        );
        assert_eq!(
            length("only_in_after") + length("changed") + length("unchanged"),
            bundles[after].2["item_count"].as_u64().unwrap()
        );
        let wordpress = &comparison["wordpress_review_comparison"];
        assert_eq!(wordpress["status"], "not_compared");
        assert_eq!(wordpress["reason"], "supplied_session_context_unknown");
        assert_eq!(wordpress["methodology"]["status"], "changed");
        assert_eq!(wordpress["coverage"]["status"], "changed");
        for group in ["components", "advisories"] {
            assert_eq!(
                wordpress[group],
                serde_json::json!({
                    "paired_unchanged_count": 0, "paired_changed": [],
                    "only_in_before": [], "only_in_after": []
                })
            );
        }
    }
    assert_eq!(*server.requests.lock().unwrap(), stopped_trace);
}
