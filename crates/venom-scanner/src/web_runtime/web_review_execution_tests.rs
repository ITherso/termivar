//! Native review executor regression tests.

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use venom_core::EntityId;

use super::super::web_assessment::{
    classify_exact_html_reflection, cross_validate_attribute_reflection_source,
    cross_validate_javascript_reflection_source, select_xss_probe_families, AttributeSourceResult,
    ExactHtmlReflectionContext, JavaScriptSourceResult, XssProbeSelection,
};
use super::super::web_review_decision::NativeWebReviewDecisionProfile;
use super::*;
use crate::{
    DecisionActionOrigin, DecisionLoopCommand, DecisionRunnerAdapter, HttpEvidencePolicy,
    KnowledgeBase, VerificationCase,
};

fn request_broker(root: &Url) -> HttpRequestBroker {
    let policy = HttpEvidencePolicy::new([root.clone()], Duration::from_secs(2), 4 * 1024).unwrap();
    HttpRequestBroker::new_unmetered(policy).unwrap()
}

fn expected_strategy(kind: NativeWebReviewActionKind) -> PayloadStrategyRef {
    let (id, revision) = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => {
            (CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            (EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
        },
        NativeWebReviewActionKind::ReflectionContextQueryPair => (
            REFLECTION_MARKER_QUERY_PAIR_ID,
            REFLECTION_MARKER_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => (
            SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
            SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => (
            SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
            SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssStructuralQueryPair => (
            XSS_STRUCTURAL_QUERY_PAIR_ID,
            XSS_STRUCTURAL_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => (
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => (
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION,
        ),
    };
    PayloadStrategyRef::new(id, revision).unwrap()
}

fn profile_without_observer(
    requests: HttpRequestBroker,
    root: Url,
    redirect_query_parameter: Option<String>,
) -> Result<NativeWebReviewExecutorProfile, NativeWebReviewExecutionError> {
    let seeds = NativeWebReviewSeeds::from_authorized_origin(&root)?;
    NativeWebReviewExecutorProfile::new_without_observer_for_test(
        requests,
        root,
        seeds,
        redirect_query_parameter,
    )
}

fn case(root: &Url, case_id: &str, kind: NativeWebReviewActionKind) -> VerificationCase {
    VerificationCase::new(
        case_id,
        EntityId::new(format!("endpoint:{root}")).unwrap(),
        kind.action_id(),
        "hypothesis:web-review",
    )
    .unwrap()
    .with_payload_strategy(Some(expected_strategy(kind)))
}

fn html_xss_selection() -> XssProbeSelection {
    select_xss_probe_families(
        ExactHtmlReflectionContext::HtmlText,
        &AttributeSourceResult::Absent,
        &JavaScriptSourceResult::Absent,
    )
    .into_iter()
    .next()
    .unwrap()
}

fn attribute_xss_selection() -> XssProbeSelection {
    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";
    let html = format!("<div title=\"{MARKER}\"></div>");
    let context = classify_exact_html_reflection(&html, MARKER);
    let source = cross_validate_attribute_reflection_source(&html, MARKER, context);
    select_xss_probe_families(context, &source, &JavaScriptSourceResult::Absent)
        .into_iter()
        .next()
        .unwrap()
}

fn script_xss_selection() -> XssProbeSelection {
    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";
    let html = format!("<script>const value = '{MARKER}';</script>");
    let context = classify_exact_html_reflection(&html, MARKER);
    let source = cross_validate_javascript_reflection_source(&html, MARKER, context);
    select_xss_probe_families(context, &AttributeSourceResult::Absent, &source)
        .into_iter()
        .next()
        .unwrap()
}

async fn serve_capturing(connections: usize) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    tokio::spawn(async move {
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0_u8; 8 * 1024];
            let read = stream.read(&mut bytes).await.unwrap();
            sink.lock()
                .await
                .push(String::from_utf8_lossy(&bytes[..read]).into_owned());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    (
        Url::parse(&format!("http://{address}/review")).unwrap(),
        captured,
    )
}

#[test]
fn construction_is_deterministic_and_seeds_are_reserved_non_secret_values() {
    let root = Url::parse("https://example.test/stable/root").unwrap();
    let first = NativeWebReviewSeeds::from_authorized_origin(&root).unwrap();
    let second = NativeWebReviewSeeds::from_authorized_origin(&root).unwrap();
    let same_origin_other_path = NativeWebReviewSeeds::from_authorized_origin(
        &Url::parse("https://example.test/secret-like/path").unwrap(),
    )
    .unwrap();
    let other_origin = NativeWebReviewSeeds::from_authorized_origin(
        &Url::parse("https://other.example.test/root").unwrap(),
    )
    .unwrap();

    assert_eq!(first, second);
    assert_eq!(first, same_origin_other_path);
    assert_ne!(first, other_origin);
    assert!(first.cors_origin().starts_with("https://cors-"));
    assert!(first.cors_origin().ends_with(".review.invalid"));
    assert!(first.external_url().starts_with("https://redirect-"));
    assert!(first
        .external_url()
        .ends_with(".review.invalid/venom-review"));
    assert!(first.cors_origin().is_ascii());
    assert!(first.external_url().is_ascii());
    assert!(first.reflection_control_marker().is_ascii());
    assert!(first.reflection_candidate_marker().is_ascii());
    assert_ne!(
        first.reflection_control_marker(),
        first.reflection_candidate_marker()
    );
}

#[test]
fn debug_output_redacts_root_and_both_seed_values() {
    let root = Url::parse("https://example.test/opaque-root-marker").unwrap();
    let seeds = NativeWebReviewSeeds::from_authorized_origin(&root).unwrap();
    let profile =
        profile_without_observer(request_broker(&root), root.clone(), Some("next".to_owned()))
            .unwrap();

    let debug = format!("{profile:?}");
    assert!(!debug.contains(root.as_str()));
    assert!(!debug.contains("opaque-root-marker"));
    assert!(!debug.contains(seeds.cors_origin()));
    assert!(!debug.contains(seeds.external_url()));
    assert!(!debug.contains(&seeds.reflection_control_marker()));
    assert!(!debug.contains(&seeds.reflection_candidate_marker()));
    assert!(debug.contains("<redacted>"));

    let seed_debug = format!("{seeds:?}");
    assert!(!seed_debug.contains(seeds.cors_origin()));
    assert!(!seed_debug.contains(seeds.external_url()));
    assert!(!seed_debug.contains(&seeds.reflection_control_marker()));
    assert!(!seed_debug.contains(&seeds.reflection_candidate_marker()));
    assert!(seed_debug.contains("<redacted>"));
}

#[test]
fn query_state_and_invalid_query_names_fail_closed() {
    let root = Url::parse("https://example.test/review").unwrap();
    let requests = request_broker(&root);
    let with_query = Url::parse("https://example.test/review?existing=value").unwrap();
    assert!(matches!(
        NativeWebReviewExecutorProfile::new_without_observer_for_test(
            requests.clone(),
            with_query.clone(),
            NativeWebReviewSeeds::from_authorized_origin(&with_query).unwrap(),
            Some("next".to_owned()),
        ),
        Err(NativeWebReviewExecutionError::RootQueryNotAllowed)
    ));

    let with_fragment = Url::parse("https://example.test/review#section").unwrap();
    assert!(matches!(
        NativeWebReviewExecutorProfile::new_without_observer_for_test(
            requests.clone(),
            with_fragment.clone(),
            NativeWebReviewSeeds::from_authorized_origin(&with_fragment).unwrap(),
            Some("next".to_owned()),
        ),
        Err(NativeWebReviewExecutionError::RootFragmentNotAllowed)
    ));

    for invalid in ["", "has space", "unsafe&name", "x=y"] {
        assert!(matches!(
            profile_without_observer(requests.clone(), root.clone(), Some(invalid.to_owned()),),
            Err(NativeWebReviewExecutionError::Http(
                HttpEvidenceError::InvalidQueryPayloadParameter
            ))
        ));
    }
    assert!(matches!(
        profile_without_observer(requests, root, Some("x".repeat(65)),),
        Err(NativeWebReviewExecutionError::Http(
            HttpEvidenceError::InvalidQueryPayloadParameter
        ))
    ));
}

#[test]
fn broader_broker_authority_is_rejected_before_executor_construction() {
    let root = Url::parse("https://example.test/review").unwrap();
    let broader = HttpEvidencePolicy::new(
        [
            root.clone(),
            Url::parse("https://other.test/review").unwrap(),
        ],
        Duration::from_secs(2),
        4 * 1024,
    )
    .unwrap();
    let requests = HttpRequestBroker::new_unmetered(broader).unwrap();

    assert!(matches!(
        NativeWebReviewExecutorProfile::new_without_observer_for_test(
            requests,
            root.clone(),
            NativeWebReviewSeeds::from_authorized_origin(&root).unwrap(),
            Some("next".to_owned()),
        ),
        Err(NativeWebReviewExecutionError::ExactOriginBrokerRequired)
    ));
}

#[test]
fn seeds_cannot_be_rebound_across_authorized_origins() {
    let root = Url::parse("https://example.test/review").unwrap();
    let other = Url::parse("https://other.test/review").unwrap();
    let other_seeds = NativeWebReviewSeeds::from_authorized_origin(&other).unwrap();

    assert!(matches!(
        NativeWebReviewExecutorProfile::new_without_observer_for_test(
            request_broker(&root),
            root,
            other_seeds,
            Some("next".to_owned()),
        ),
        Err(NativeWebReviewExecutionError::SeedOriginMismatch)
    ));
}

#[test]
fn absent_query_parameter_omits_redirect_executor_and_both_routes() {
    let root = Url::parse("https://example.test/review").unwrap();
    let profile = profile_without_observer(request_broker(&root), root, None).unwrap();
    let mut registry = DecisionExecutorRegistry::new();
    let report = profile.install(&mut registry).unwrap();

    assert_eq!(report.executors_inserted(), 1);
    assert_eq!(
        profile.actions().collect::<Vec<_>>(),
        [NativeWebReviewActionKind::CorsPolicyPair]
    );
    assert_eq!(profile.executor_ids().len(), 1);
    assert!(registry.contains(NativeWebReviewActionKind::CorsPolicyPair.executor_id()));
    assert!(
        !registry.contains(NativeWebReviewActionKind::RedirectReflectionQueryPair.executor_id())
    );
    assert!(profile.supports_exact_strategy(NativeWebReviewActionKind::CorsPolicyPair));
    assert!(
        !profile.supports_exact_strategy(NativeWebReviewActionKind::RedirectReflectionQueryPair)
    );
}

#[test]
fn decision_and_executor_share_each_subject_specific_enabled_action_set() {
    let root = Url::parse("https://example.test/review").unwrap();
    for (include_cors, redirect, reflection, sql, ssti) in [
        (true, None, None, None, None),
        (true, Some("next"), Some("item"), None, None),
        (true, None, Some("item"), Some("item"), Some("item")),
        (true, Some("next"), Some("item"), Some("item"), Some("item")),
        (false, None, Some("item"), Some("item"), Some("item")),
        (false, None, None, None, Some("item")),
    ] {
        let profile = NativeWebReviewExecutorProfile::build(
            request_broker(&root),
            root.clone(),
            NativeWebReviewSeeds::from_authorized_origin(&root).unwrap(),
            None,
            NativeWebReviewQueryParameters {
                redirect: redirect.map(str::to_owned),
                reflection: reflection.map(str::to_owned),
                sql: sql.map(str::to_owned),
                ssti: ssti.map(str::to_owned),
                xss: None,
            },
            include_cors,
        )
        .unwrap();
        let executor_actions = profile.actions().collect::<Vec<_>>();
        assert_eq!(
            executor_actions,
            enabled_native_web_review_actions(
                include_cors,
                redirect.is_some(),
                reflection.is_some(),
                sql.is_some(),
                ssti.is_some(),
                None,
            )
        );
        let decision =
            NativeWebReviewDecisionProfile::for_actions(executor_actions.iter().copied()).unwrap();
        assert_eq!(decision.actions().collect::<Vec<_>>(), executor_actions);
    }
}

#[test]
fn xss_only_subject_uses_one_exact_decision_executor_and_completeness_action() {
    let root = Url::parse("https://example.test/review").unwrap();
    for (selection, expected, stale) in [
        (
            html_xss_selection(),
            NativeWebReviewActionKind::XssStructuralQueryPair,
            [
                NativeWebReviewActionKind::XssAttributeBoundaryQueryPair,
                NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
            ],
        ),
        (
            attribute_xss_selection(),
            NativeWebReviewActionKind::XssAttributeBoundaryQueryPair,
            [
                NativeWebReviewActionKind::XssStructuralQueryPair,
                NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
            ],
        ),
        (
            script_xss_selection(),
            NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
            [
                NativeWebReviewActionKind::XssStructuralQueryPair,
                NativeWebReviewActionKind::XssAttributeBoundaryQueryPair,
            ],
        ),
    ] {
        let seeds = NativeWebReviewSeeds::from_authorized_origin(&root).unwrap();
        let observer = Arc::new(
            super::super::assessment_review::AssessmentReviewObserverSet::new_xss(
                root.clone(),
                seeds.clone(),
                "item",
                selection.clone(),
            )
            .unwrap(),
        );
        let profile = NativeWebReviewExecutorProfile::new_structural_only(
            request_broker(&root),
            root.clone(),
            seeds,
            observer,
            NativeWebReviewQueryParameters::xss_only("item".to_owned(), selection),
        )
        .unwrap();
        let enabled = profile.actions().collect::<Vec<_>>();
        assert_eq!(enabled, [expected]);
        let decision =
            NativeWebReviewDecisionProfile::for_actions(enabled.iter().copied()).unwrap();
        assert_eq!(decision.actions().collect::<Vec<_>>(), enabled);
        assert!(profile.supports_exact_strategy(expected));
        for stale in stale {
            assert!(!profile.supports_exact_strategy(stale));
        }
    }
}

#[tokio::test]
async fn enabled_native_action_without_executor_route_still_fails_closed() {
    let root = Url::parse("https://example.test/review").unwrap();
    for kind in [
        NativeWebReviewActionKind::CorsPolicyPair,
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        NativeWebReviewActionKind::SstiStructuralQueryPair,
        NativeWebReviewActionKind::XssStructuralQueryPair,
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair,
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
    ] {
        let decision = NativeWebReviewDecisionProfile::for_actions([kind]).unwrap();
        assert_eq!(decision.actions().collect::<Vec<_>>(), [kind]);

        let adapter = DecisionRunnerAdapter::new(DecisionExecutorRegistry::new());
        let error = adapter
            .execute_command(
                &DecisionLoopCommand::ExecuteAction {
                    case: case(&root, "case:web-review:missing-executor", kind),
                    executor: None,
                    origin: DecisionActionOrigin::Planned,
                    delay_ms: None,
                },
                &KnowledgeBase::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DecisionRunnerError::MissingActionRoute {
                stage: DecisionExecutionStage::Passive,
                action_id,
            } if action_id == kind.action_id()
        ));
    }
}

#[test]
fn installation_is_atomic_idempotent_and_preserves_exact_strategy_support() {
    let root = Url::parse("https://example.test/review").unwrap();
    let requests = request_broker(&root);
    let profile =
        profile_without_observer(requests.clone(), root.clone(), Some("return_to".to_owned()))
            .unwrap();
    let mut registry = DecisionExecutorRegistry::new();

    let first = profile.install(&mut registry).unwrap();
    let second = profile.install(&mut registry).unwrap();
    assert_eq!(first.executors_inserted(), 3);
    assert_eq!(second, NativeWebReviewExecutionInstallReport::default());
    assert_eq!(registry.len(), 3);
    assert_eq!(profile.executor_ids().len(), 3);
    for kind in profile.actions() {
        assert!(registry.contains(kind.executor_id()));
        assert!(profile.supports_exact_strategy(kind));
    }

    let host_executor = HttpEvidenceExecutor::with_id_and_request_broker(
        "host.review-executor",
        requests,
        Arc::new(SubjectHttpProbeProvider::new(HttpProbeMethod::Get)),
    )
    .unwrap();
    let mut conflicted = DecisionExecutorRegistry::new();
    conflicted.register(Arc::new(host_executor)).unwrap();
    conflicted
        .route_action(
            DecisionExecutionStage::Passive,
            NativeWebReviewActionKind::CorsPolicyPair.action_id(),
            "host.review-executor",
        )
        .unwrap();

    assert!(matches!(
        profile.install(&mut conflicted),
        Err(NativeWebReviewExecutionError::Runner(
            DecisionRunnerError::ActionRouteConflict { .. }
        ))
    ));
    assert_eq!(conflicted.len(), 1);
    assert!(conflicted.contains("host.review-executor"));
    assert!(!conflicted.contains(NativeWebReviewActionKind::CorsPolicyPair.executor_id()));
    assert!(
        !conflicted.contains(NativeWebReviewActionKind::RedirectReflectionQueryPair.executor_id())
    );
    assert!(
        !conflicted.contains(NativeWebReviewActionKind::ReflectionContextQueryPair.executor_id())
    );
}

#[tokio::test]
async fn passive_and_active_routes_share_each_exact_executor_and_materialize_pairs() {
    let (root, captured) = serve_capturing(6).await;
    let seeds = NativeWebReviewSeeds::from_authorized_origin(&root).unwrap();
    let profile =
        profile_without_observer(request_broker(&root), root.clone(), Some("next".to_owned()))
            .unwrap();
    let mut registry = DecisionExecutorRegistry::new();
    profile.install(&mut registry).unwrap();
    let adapter = DecisionRunnerAdapter::new(registry);
    let knowledge = KnowledgeBase::new();

    for (ordinal, kind) in profile.actions().enumerate() {
        let case = case(&root, &format!("case:web-review:{ordinal}"), kind);
        let passive = adapter
            .execute_command(
                &DecisionLoopCommand::ExecuteAction {
                    case: case.clone(),
                    executor: None,
                    origin: DecisionActionOrigin::Planned,
                    delay_ms: None,
                },
                &knowledge,
            )
            .await
            .unwrap();
        let active = adapter
            .execute_command(
                &DecisionLoopCommand::CollectActiveEvidence { case },
                &knowledge,
            )
            .await
            .unwrap();
        assert_eq!(passive.executor_id(), kind.executor_id());
        assert_eq!(active.executor_id(), kind.executor_id());
    }

    let requests = captured.lock().await.clone();
    assert_eq!(requests.len(), 6);
    let cors_control = requests[0].to_ascii_lowercase();
    let cors_candidate = requests[1].to_ascii_lowercase();
    assert!(!cors_control.contains("\r\norigin:"));
    assert!(cors_candidate.contains(&format!("\r\norigin: {}\r\n", seeds.cors_origin())));

    let redirect_control_line = requests[2].lines().next().unwrap();
    let redirect_candidate_line = requests[3].lines().next().unwrap();
    assert_eq!(redirect_control_line, "GET /review HTTP/1.1");
    assert!(redirect_candidate_line.starts_with("GET /review?next="));
    assert!(redirect_candidate_line.ends_with(" HTTP/1.1"));
    assert!(redirect_candidate_line.contains("review.invalid%2Fvenom-review"));
    assert!(!redirect_candidate_line.contains(seeds.external_url()));

    let reflection_control_line = requests[4].lines().next().unwrap();
    let reflection_candidate_line = requests[5].lines().next().unwrap();
    assert!(reflection_control_line.contains("venom-reflection-control-"));
    assert!(reflection_candidate_line.contains("venom-reflection-candidate-"));
    let marker = reflection_candidate_line
        .split_once("?next=")
        .unwrap()
        .1
        .strip_suffix(" HTTP/1.1")
        .unwrap();
    assert!(marker
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
}
