use std::{
    collections::{BTreeMap, BTreeSet},
    future::pending,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex, Notify},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use venom_core::{ConfidenceScore, EntityId, KnowledgePredicate};

use super::*;
#[cfg(feature = "graphql-review")]
use crate::graphql_review::{MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES, MAX_GRAPHQL_RESPONSE_BYTES};
use crate::web_actions::{
    NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE, NATIVE_WEB_REVIEW_REQUESTS_PER_CASE,
};
use crate::web_runtime::assessment_defense::{
    CommittedAssessmentDefenseLedger, ASSESSMENT_DEFENSE_NAMESPACE,
};
use crate::web_runtime::assessment_passive::{
    CommittedAssessmentPassiveLedger, CommittedAssessmentPassiveObservation,
    CommittedPassiveMediaClass, ASSESSMENT_PASSIVE_NAMESPACE,
};
use crate::web_runtime::{AssessmentBasis, AssessmentDisposition};
#[cfg(feature = "reporting")]
use crate::web_runtime::{BuiltInScanProfile, ASSESSMENT_RUN_REPORT_SCHEMA};
use crate::{
    defense::MAX_FINGERPRINT_BODY_SCAN_BYTES,
    http_evidence::{
        complete_http_response_observation_for_test, passive_response_projection_for_test,
        passive_review::{
            PassiveCookieSameSite, PassiveProjectionIncompleteReason, PassiveProjectionState,
        },
        CompleteHttpResponseObservationTestInput,
    },
    HttpBodyCapture, HttpEvidencePolicy, KnowledgeWrite, RuntimeBudgetDimension,
    SemanticEntityType, TransportDispatchOutcome, DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS,
    DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_MAX_SAME_ACTION_ATTEMPTS,
};
#[cfg(feature = "reporting")]
use crate::{ReportFormat, ReportGenerator};

#[test]
fn defense_mode_is_explicit_and_defaults_to_observation_only() {
    let target = Url::parse("https://example.test/").unwrap();
    let observed = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    assert_eq!(
        observed.defense_audit.mode(),
        WebAssessmentDefenseMode::ObservationOnly
    );

    let enforced = WebAssessmentRuntime::builder(target)
        .enable_defense_enforcement()
        .build()
        .unwrap();
    assert_eq!(
        enforced.defense_audit.mode(),
        WebAssessmentDefenseMode::Enforced
    );
}

#[tokio::test]
async fn default_assessment_does_not_dispatch_native_review_mutations() {
    let server = serve(|_| FixtureReply::Response(FixtureResponse::html("root"))).await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/?return_to=host-value"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);

    let requests = server.requests().await;
    assert!(requests.iter().all(|request| {
        !request.headers.contains_key("origin") && !request.target.contains('?')
    }));
    assert!(report.subjects()[0].turns().iter().all(|turn| match turn {
        StandardWebDecisionRuntimeTurn::Outcome { evidence, .. } =>
            !is_native_review_action(evidence.case().action_id()),
        StandardWebDecisionRuntimeTurn::Planning(_) => true,
    }));
}

#[cfg(feature = "graphql-review")]
#[derive(Clone, Copy)]
enum GraphqlFixtureMode {
    Available,
    Restricted,
    GenericJson,
    Html,
    ReplayMismatch,
}

#[cfg(feature = "graphql-review")]
const GRAPHQL_REVIEW_SECRET: &str = "GRAPHQL-REVIEW-MUST-NOT-LEAK-SECRET-1F92A7";
#[cfg(feature = "graphql-review")]
const GRAPHQL_ROOT_NAME_SECRET: &str = "GraphqlRootSecret1F92A7";

#[cfg(feature = "graphql-review")]
fn graphql_fixture_reply(mode: GraphqlFixtureMode, request: &RecordedRequest) -> FixtureReply {
    if request.method != "POST" {
        return FixtureReply::Response(FixtureResponse::html("graphql fixture root"));
    }
    let query = serde_json::from_slice::<serde_json::Value>(request.body())
        .ok()
        .and_then(|value| {
            let object = value.as_object()?;
            (object.len() == 1)
                .then(|| object.get("query").and_then(serde_json::Value::as_str))
                .flatten()
                .map(str::to_owned)
        });
    let Some(query) = query else {
        return FixtureReply::Response(FixtureResponse::new(
            "400 Bad Request",
            Some("application/json"),
            "{}",
        ));
    };

    if matches!(mode, GraphqlFixtureMode::Html) {
        return FixtureReply::Response(FixtureResponse::html("not graphql"));
    }
    if matches!(mode, GraphqlFixtureMode::GenericJson) {
        return FixtureReply::Response(FixtureResponse::new(
            "200 OK",
            Some("application/json"),
            r#"{"ok":true}"#,
        ));
    }
    if query.contains("VenomGraphqlControlV1") {
        return FixtureReply::Response(FixtureResponse::new(
            "200 OK",
            Some("application/graphql-response+json"),
            r#"{"data":{"venomControlV1":"Query"}}"#,
        ));
    }
    if matches!(mode, GraphqlFixtureMode::Restricted) {
        return FixtureReply::Response(FixtureResponse::new(
            "200 OK",
            Some("application/graphql-response+json"),
            format!(
                r#"{{"errors":[{{"message":"introspection is disabled: {GRAPHQL_REVIEW_SECRET}"}}]}}"#
            ),
        ));
    }
    if query.contains("VenomGraphqlCandidateV1") {
        return FixtureReply::Response(FixtureResponse::new(
            "200 OK",
            Some("application/graphql-response+json"),
            format!(
                r#"{{"data":{{"venomCandidateV1":"{GRAPHQL_ROOT_NAME_SECRET}","__schema":{{"queryType":{{"name":"{GRAPHQL_ROOT_NAME_SECRET}"}},"mutationType":null,"subscriptionType":null}}}}}}"#
            ),
        ));
    }
    if query.contains("VenomGraphqlReplayV1") {
        let (media_type, body) = if matches!(mode, GraphqlFixtureMode::ReplayMismatch) {
            ("application/json", r#"{"ok":true}"#)
        } else {
            (
                "application/graphql-response+json",
                r#"{"data":{"venomReplayV1":"GraphqlRootSecret1F92A7","__schema":{"queryType":{"name":"GraphqlRootSecret1F92A7"},"mutationType":null,"subscriptionType":null}}}"#,
            )
        };
        return FixtureReply::Response(FixtureResponse::new("200 OK", Some(media_type), body));
    }
    FixtureReply::Response(FixtureResponse::new(
        "400 Bad Request",
        Some("application/json"),
        "{}",
    ))
}

#[cfg(feature = "graphql-review")]
async fn run_graphql_fixture(
    mode: GraphqlFixtureMode,
    enabled: bool,
) -> (WebAssessmentRunReport, Vec<RecordedRequest>) {
    let server = serve(move |request| graphql_fixture_reply(mode, request)).await;
    let mut builder = WebAssessmentRuntime::builder(server.url("/"));
    if enabled {
        builder = builder.enable_graphql_review();
    }
    let mut runtime = builder.build().unwrap();
    let report = runtime.analyze().await.unwrap();
    let requests = server.requests().await;
    (report, requests)
}

#[cfg(feature = "graphql-review")]
fn graphql_items(report: &WebAssessmentRunReport) -> BTreeMap<&str, &AssessmentItem> {
    report
        .assessment_items()
        .iter()
        .filter(|item| item.capability_id().starts_with("graphql."))
        .map(|item| (item.capability_id(), item))
        .collect()
}

#[cfg(feature = "graphql-review")]
fn graphql_posts(requests: &[RecordedRequest]) -> Vec<&RecordedRequest> {
    requests
        .iter()
        .filter(|request| request.method == "POST" && request.path() == "/graphql")
        .collect()
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_review_happy_path_is_three_anonymous_posts_and_two_informational_items() {
    let (report, requests) = run_graphql_fixture(GraphqlFixtureMode::Available, true).await;
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let posts = graphql_posts(&requests);
    assert_eq!(posts.len(), 3);
    assert_eq!(report.usage().total_requests(), 4);
    assert_eq!(report.usage().active_verifications(), 1);
    assert_eq!(
        report.usage().request_body_bytes(),
        posts
            .iter()
            .map(|request| u64::try_from(request.body().len()).unwrap())
            .sum::<u64>()
    );
    let expected_host =
        &report.authorized_root().url()[url::Position::BeforeHost..url::Position::AfterPort];
    for request in &posts {
        assert_eq!(request.host(), expected_host);
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/graphql-response+json, application/json")
        );
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("cookie"));
    }
    assert!(posts
        .windows(2)
        .all(|pair| pair[0].body() != pair[1].body()));
    let operation_names = [
        "VenomGraphqlControlV1",
        "VenomGraphqlCandidateV1",
        "VenomGraphqlReplayV1",
    ];
    for (request, operation) in posts.iter().zip(operation_names) {
        let body = std::str::from_utf8(request.body()).unwrap();
        assert!(body.contains(operation));
        assert!(body.contains("\"query\":"));
        assert!(!body.contains("\"variables\""));
        assert!(!body.contains("\"operationName\""));
    }

    let dispatches = report
        .transport()
        .receipts()
        .iter()
        .filter(|receipt| receipt.action_id().starts_with("web.review.graphql."))
        .collect::<Vec<_>>();
    assert_eq!(dispatches.len(), 3);
    assert_eq!(dispatches[0].action_id(), "web.review.graphql.control");
    assert_eq!(
        dispatches[1].action_id(),
        "web.review.graphql.introspection"
    );
    assert_eq!(
        dispatches[2].action_id(),
        "web.review.graphql.introspection-replay"
    );
    assert_eq!(dispatches[0].stage(), DecisionExecutionStage::Passive);
    assert_eq!(dispatches[1].stage(), DecisionExecutionStage::Passive);
    assert_eq!(dispatches[2].stage(), DecisionExecutionStage::Active);
    let defense = report
        .defense()
        .observations()
        .iter()
        .filter(|observation| observation.case_id().starts_with("case:web.graphql."))
        .map(|observation| (observation.case_id(), observation.stage()))
        .collect::<Vec<_>>();
    assert_eq!(
        defense,
        [
            ("case:web.graphql.control", DecisionExecutionStage::Passive,),
            (
                "case:web.graphql.introspection",
                DecisionExecutionStage::Passive,
            ),
            (
                "case:web.graphql.introspection-replay",
                DecisionExecutionStage::Active,
            ),
        ]
    );

    let items = graphql_items(&report);
    assert_eq!(items.len(), 2);
    for capability in [
        "graphql.surface-observed@1",
        "graphql.anonymous-root-introspection@1",
    ] {
        let item = items.get(capability).unwrap();
        assert_eq!(item.disposition(), AssessmentDisposition::Informational);
        assert!(matches!(item.basis(), AssessmentBasis::Observation(_)));
        assert_eq!(item.basis().case_reference(), None);
    }
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_transport_persists_presence_and_replay_match_but_no_root_name_digest() {
    let server =
        serve(|request| graphql_fixture_reply(GraphqlFixtureMode::Available, request)).await;
    let endpoint = server.url("/graphql");
    let reliability = ConfidenceScore::from_percent(73).unwrap();
    let policy = HttpEvidencePolicy::for_origin(server.url("/"))
        .unwrap()
        .with_reliability(reliability)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .http_policy(policy)
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let subject = EntityId::new(format!("graphql-endpoint:{endpoint}")).unwrap();
    let evidence = runtime.authority.knowledge().evidence_for_subject(&subject);
    let property = |name| KnowledgePredicate::new("web.graphql.transport", name).unwrap();
    assert!(!evidence.is_empty());
    assert!(evidence
        .iter()
        .all(|observation| observation.subject() == &subject
            && observation.reliability() == reliability));
    assert!(evidence
        .iter()
        .all(|item| item.predicate() != &property("root_identity_digest")));
    assert!(evidence.iter().any(|item| {
        item.predicate() == &property("query_root_present")
            && item.value() == &venom_core::EvidenceValue::Boolean(true)
    }));
    let replay_matches = evidence
        .iter()
        .filter(|item| item.predicate() == &property("replay_matches_candidate_roots"))
        .collect::<Vec<_>>();
    assert_eq!(replay_matches.len(), 1);
    assert_eq!(
        replay_matches[0].value(),
        &venom_core::EvidenceValue::Boolean(true)
    );

    let classifications = evidence
        .iter()
        .filter(|item| item.predicate() == &property("classification"))
        .collect::<Vec<_>>();
    assert_eq!(classifications.len(), 3);
    for classification in classifications {
        let derivation = classification.origin().derivation().unwrap();
        assert_eq!(
            derivation.algorithm().name(),
            "web.graphql.transport-classification"
        );
        assert_eq!(derivation.algorithm().version(), 1);
        assert!(derivation.parents().iter().all(|parent| {
            runtime
                .authority
                .knowledge()
                .evidence(parent)
                .is_some_and(|evidence| {
                    evidence.subject() == &subject && evidence.reliability() == reliability
                })
        }));
        for required in [
            HttpEvidencePredicate::REQUEST_URL,
            HttpEvidencePredicate::RESPONSE_STATUS,
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            HttpEvidencePredicate::RESPONSE_BODY_SHA256,
        ] {
            assert!(derivation.parents().iter().any(|parent| {
                runtime
                    .authority
                    .knowledge()
                    .evidence(parent)
                    .is_some_and(|evidence| evidence.predicate() == &required.into_knowledge())
            }));
        }
    }

    let media_predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
    assert_eq!(
        evidence
            .iter()
            .filter(|item| item.predicate() == &media_predicate)
            .count(),
        3,
        "each broker receipt owns exactly one media observation; API reasoning adds none"
    );
    let path = evidence
        .iter()
        .find(|item| {
            item.predicate() == &HttpEvidencePredicate::REQUEST_PATH_SEGMENT.into_knowledge()
        })
        .unwrap();
    assert_eq!(
        path.origin().derivation().unwrap().algorithm().name(),
        "web.graphql.api-path-segment"
    );
    assert_eq!(path.reliability(), reliability);

    let items = graphql_items(&report);
    let surface_evidence = match items["graphql.surface-observed@1"].basis() {
        AssessmentBasis::Observation(basis) => basis.evidence().len(),
        _ => unreachable!(),
    };
    let introspection_evidence = match items["graphql.anonymous-root-introspection@1"].basis() {
        AssessmentBasis::Observation(basis) => basis.evidence().len(),
        _ => unreachable!(),
    };
    assert_eq!(surface_evidence, 1);
    assert_eq!(introspection_evidence, MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES);
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn equivalent_graphql_reruns_have_stable_unique_item_identity() {
    let server =
        serve(|request| graphql_fixture_reply(GraphqlFixtureMode::Available, request)).await;
    let mut first_runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_graphql_review()
        .build()
        .unwrap();
    let first = first_runtime.analyze().await.unwrap();
    let mut second_runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_graphql_review()
        .build()
        .unwrap();
    let second = second_runtime.analyze().await.unwrap();

    let identities = |report: &WebAssessmentRunReport| {
        graphql_items(report)
            .into_iter()
            .map(|(capability, item)| (capability.to_owned(), item.fingerprint().to_owned()))
            .collect::<BTreeMap<_, _>>()
    };
    let first_identities = identities(&first);
    let second_identities = identities(&second);
    assert_eq!(first_identities.len(), 2);
    assert_eq!(first_identities, second_identities);
    assert_eq!(
        first_identities.values().collect::<BTreeSet<_>>().len(),
        first_identities.len()
    );
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn more_than_thirty_two_discovered_graphql_hints_remain_bounded_runtime_input() {
    let links = (0..40)
        .map(|index| format!(r#"<a href="/g{index:02}/graphql">candidate</a>"#))
        .collect::<String>();
    let server = serve(move |request| {
        if request.method == "POST" {
            graphql_fixture_reply(GraphqlFixtureMode::Available, request)
        } else if request.path() == "/" {
            FixtureReply::Response(FixtureResponse::html(links.clone()))
        } else {
            FixtureReply::Response(FixtureResponse::html("candidate surface"))
        }
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
    let requests = server.requests().await;
    let posts = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 3);
    assert!(posts.iter().all(|request| request.path() == "/g00/graphql"));
    assert_eq!(graphql_items(&report).len(), 2);
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn enforced_root_rate_limit_dispatches_zero_graphql_posts() {
    let server = serve(move |_| {
        FixtureReply::Response(FixtureResponse::new(
            "429 Too Many Requests",
            Some("text/html"),
            "<html><body>slow down</body></html>",
        ))
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_defense_enforcement()
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let requests = server.requests().await;

    assert!(graphql_posts(&requests).is_empty());
    assert!(report
        .transport()
        .receipts()
        .iter()
        .all(|receipt| !receipt.action_id().starts_with("web.review.graphql.")));
    assert!(report
        .defense()
        .observations()
        .iter()
        .any(|observation| observation.status() == 429 && observation.rate_limit_observed()));
    assert!(graphql_items(&report).is_empty());
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn enforced_candidate_block_or_rate_limit_suppresses_graphql_replay() {
    for (status, rate_limited) in [("403 Forbidden", false), ("429 Too Many Requests", true)] {
        let server = serve(move |request| {
            if request.method != "POST" {
                return FixtureReply::Response(FixtureResponse::html("graphql fixture root"));
            }
            if request
                .body()
                .windows(b"VenomGraphqlControlV1".len())
                .any(|window| window == b"VenomGraphqlControlV1")
            {
                return graphql_fixture_reply(GraphqlFixtureMode::Available, request);
            }
            FixtureReply::Response(FixtureResponse::new(
                status,
                Some("application/graphql-response+json"),
                r#"{"errors":[{"message":"introspection is disabled"}]}"#,
            ))
        })
        .await;
        let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
            .enable_defense_enforcement()
            .enable_graphql_review()
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        let requests = server.requests().await;

        assert_eq!(graphql_posts(&requests).len(), 2);
        assert!(requests.iter().all(|request| !request
            .body()
            .windows(b"VenomGraphqlReplayV1".len())
            .any(|window| window == b"VenomGraphqlReplayV1")));
        let graphql_defense = report
            .defense()
            .observations()
            .iter()
            .filter(|observation| observation.case_id().starts_with("case:web.graphql."))
            .collect::<Vec<_>>();
        assert_eq!(graphql_defense.len(), 2);
        assert_eq!(
            graphql_defense[1].status(),
            if rate_limited { 429 } else { 403 }
        );
        assert_eq!(graphql_defense[1].rate_limit_observed(), rate_limited);
        assert_eq!(graphql_items(&report).len(), 1);
        assert!(graphql_items(&report).contains_key("graphql.surface-observed@1"));
    }
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn enforced_control_backoff_suppresses_candidate_before_differential_read() {
    let server = serve(move |request| {
        if request.method == "POST"
            && request
                .body()
                .windows(b"VenomGraphqlControlV1".len())
                .any(|window| window == b"VenomGraphqlControlV1")
        {
            return FixtureReply::Response(
                FixtureResponse::new(
                    "200 OK",
                    Some("application/graphql-response+json"),
                    r#"{"data":{"venomControlV1":"Query"}}"#,
                )
                .with_header("Retry-After", "5"),
            );
        }
        graphql_fixture_reply(GraphqlFixtureMode::Available, request)
    })
    .await;

    let mut enforced = WebAssessmentRuntime::builder(server.url("/"))
        .enable_defense_enforcement()
        .enable_graphql_review()
        .build()
        .unwrap();
    let enforced_report = enforced.analyze().await.unwrap();
    let enforced_requests = server.requests().await;
    assert_report_reconciles(&enforced_report);
    assert_eq!(graphql_posts(&enforced_requests).len(), 1);
    assert_eq!(enforced_report.usage().active_verifications(), 0);
    let enforced_items = graphql_items(&enforced_report);
    assert_eq!(enforced_items.len(), 1);
    assert!(enforced_items.contains_key("graphql.surface-observed@1"));
    assert!(enforced_report.defense().observations().iter().any(|item| {
        item.case_id() == "case:web.graphql.control" && item.rate_limit_observed()
    }));

    let before_observation = enforced_requests.len();
    let mut observation_only = WebAssessmentRuntime::builder(server.url("/"))
        .enable_graphql_review()
        .build()
        .unwrap();
    let observation_report = observation_only.analyze().await.unwrap();
    let all_requests = server.requests().await;
    assert_report_reconciles(&observation_report);
    assert_eq!(graphql_posts(&all_requests[before_observation..]).len(), 3);
    assert_eq!(observation_report.usage().active_verifications(), 1);
    assert_eq!(graphql_items(&observation_report).len(), 2);
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_restricted_and_replay_mismatch_project_endpoint_only() {
    for mode in [
        GraphqlFixtureMode::Restricted,
        GraphqlFixtureMode::ReplayMismatch,
    ] {
        let (report, requests) = run_graphql_fixture(mode, true).await;
        assert_report_reconciles(&report);
        assert_eq!(graphql_posts(&requests).len(), 3);
        assert_eq!(report.usage().active_verifications(), 1);
        let items = graphql_items(&report);
        assert_eq!(items.len(), 1);
        assert!(items.contains_key("graphql.surface-observed@1"));
        assert!(!items.contains_key("graphql.anonymous-root-introspection@1"));
    }
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn generic_json_and_html_never_become_graphql_items() {
    for mode in [GraphqlFixtureMode::GenericJson, GraphqlFixtureMode::Html] {
        let (report, requests) = run_graphql_fixture(mode, true).await;
        assert_report_reconciles(&report);
        assert_eq!(graphql_posts(&requests).len(), 1);
        assert_eq!(report.usage().active_verifications(), 0);
        assert!(graphql_items(&report).is_empty());
    }
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_review_flag_off_dispatches_no_graphql_request() {
    let (report, requests) = run_graphql_fixture(GraphqlFixtureMode::Available, false).await;
    assert_report_reconciles(&report);
    assert!(graphql_posts(&requests).is_empty());
    assert!(report
        .transport()
        .receipts()
        .iter()
        .all(|receipt| !receipt.action_id().starts_with("web.review.graphql.")));
    assert_eq!(report.usage().active_verifications(), 0);
    assert!(graphql_items(&report).is_empty());
}

#[cfg(all(feature = "graphql-review", feature = "reporting"))]
#[tokio::test]
async fn graphql_reports_redact_structured_errors_and_schema_root_names() {
    for mode in [
        GraphqlFixtureMode::Available,
        GraphqlFixtureMode::Restricted,
    ] {
        let (report, _) = run_graphql_fixture(mode, true).await;
        let debug = format!("{report:?}");
        assert!(!debug.contains(GRAPHQL_REVIEW_SECRET));
        assert!(!debug.contains(GRAPHQL_ROOT_NAME_SECRET));

        let product =
            ReportGenerator::compose_assessment(report, ScanProfileV1::web_review().unwrap())
                .unwrap();
        for format in [
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Html,
            ReportFormat::Markdown,
        ] {
            let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
            assert!(!rendered.contains(GRAPHQL_REVIEW_SECRET));
            assert!(!rendered.contains(GRAPHQL_ROOT_NAME_SECRET));
            assert!(!rendered.contains("introspection is disabled"));
        }
    }
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_redirect_is_not_followed_or_retargeted() {
    let redirected = serve(|_| {
        FixtureReply::Response(FixtureResponse::new(
            "200 OK",
            Some("application/graphql-response+json"),
            r#"{"data":{"venomControlV1":"Query"}}"#,
        ))
    })
    .await;
    let location = redirected.url("/graphql").to_string();
    let server = serve(move |request| {
        if request.method == "POST" {
            FixtureReply::Response(
                FixtureResponse::new(
                    "302 Found",
                    Some("application/graphql-response+json"),
                    r#"{"data":{"venomControlV1":"Query"}}"#,
                )
                .with_header("Location", &location),
            )
        } else {
            FixtureReply::Response(FixtureResponse::html("graphql fixture root"))
        }
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/graphql"))
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_eq!(graphql_posts(&server.requests().await).len(), 1);
    assert_eq!(redirected.hit_count("/graphql").await, 0);
    assert!(graphql_items(&report).is_empty());
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_replay_stall_honors_host_cancellation_without_completed_items() {
    let replay_started = Arc::new(Notify::new());
    let observed_replay = replay_started.clone();
    let server = serve(move |request| {
        if request
            .body()
            .windows(b"VenomGraphqlReplayV1".len())
            .any(|window| window == b"VenomGraphqlReplayV1")
        {
            observed_replay.notify_one();
            FixtureReply::Stall
        } else {
            graphql_fixture_reply(GraphqlFixtureMode::Available, request)
        }
    })
    .await;
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let canceller = tokio::spawn(async move {
        replay_started.notified().await;
        cancel.cancel();
    });
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .cancellation_token(cancellation)
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    canceller.await.unwrap();

    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::HostCancellation));
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::GraphqlReviewIncomplete));
    assert_eq!(graphql_posts(&server.requests().await).len(), 3);
    assert_eq!(report.usage().active_verifications(), 1);
    assert_eq!(
        report
            .defense()
            .observations()
            .iter()
            .filter(|observation| observation.case_id().starts_with("case:web.graphql."))
            .map(WebAssessmentDefenseObservation::case_id)
            .collect::<Vec<_>>(),
        ["case:web.graphql.control", "case:web.graphql.introspection",]
    );
    assert!(graphql_items(&report).is_empty());
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_replay_stall_honors_wall_deadline_without_completed_items() {
    let server = serve(|request| {
        if request
            .body()
            .windows(b"VenomGraphqlReplayV1".len())
            .any(|window| window == b"VenomGraphqlReplayV1")
        {
            FixtureReply::Stall
        } else {
            graphql_fixture_reply(GraphqlFixtureMode::Available, request)
        }
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_wall_time(Duration::from_millis(500))
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .limits(limits)
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::WallTimeLimit));
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::GraphqlReviewIncomplete));
    assert_eq!(graphql_posts(&server.requests().await).len(), 3);
    assert_eq!(report.usage().active_verifications(), 1);
    assert!(graphql_items(&report).is_empty());
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn host_narrowed_zero_active_budget_is_not_widened_by_graphql_opt_in() {
    let server =
        serve(|request| graphql_fixture_reply(GraphqlFixtureMode::Available, request)).await;
    let limits = WebAssessmentLimits::default()
        .with_max_active_verifications(0)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .limits(limits)
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    assert_report_reconciles(&report);
    assert_eq!(report.runtime_active_verification_limit(), 0);
    assert_eq!(report.usage().active_verifications(), 0);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::ActiveVerificationLimit));
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::GraphqlReviewIncomplete));
    assert_eq!(graphql_posts(&server.requests().await).len(), 2);
    assert!(graphql_items(&report).is_empty());
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_response_retention_stays_clamped_below_a_wider_host_limit() {
    let oversized = vec![b'x'; MAX_GRAPHQL_RESPONSE_BYTES + 1];
    let server = serve(move |request| {
        if request.method == "POST" {
            FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/graphql-response+json"),
                oversized.clone(),
            ))
        } else {
            FixtureReply::Response(FixtureResponse::html("graphql fixture root"))
        }
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_response_body_bytes(MAX_GRAPHQL_RESPONSE_BYTES * 2)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .limits(limits)
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::GraphqlReviewIncomplete));
    assert_eq!(graphql_posts(&server.requests().await).len(), 1);
    let receipt = report
        .transport()
        .receipts()
        .iter()
        .find(|receipt| receipt.action_id() == "web.review.graphql.control")
        .unwrap();
    // The broker charges one bounded look-ahead byte to prove truncation.
    assert_eq!(
        receipt.response_bytes(),
        u64::try_from(MAX_GRAPHQL_RESPONSE_BYTES + 1).unwrap()
    );
    assert!(graphql_items(&report).is_empty());
}

const PRIVATE_AUTHORIZATION_SENTINEL: &str = "Bearer PRIVATE_AUTHORIZATION_SENTINEL";

fn root_authorization_context() -> WebAssessmentRootAuthorizationContext {
    WebAssessmentRootAuthorizationContext::new(PRIVATE_AUTHORIZATION_SENTINEL.as_bytes().to_vec())
        .unwrap()
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn graphql_review_coexists_with_authorization_comparison_but_remains_anonymous() {
    let server = serve(|request| {
        if request.headers.get("accept").map(String::as_str) == Some("application/json") {
            FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/json"),
                r#"{"id":1}"#,
            ))
        } else {
            graphql_fixture_reply(GraphqlFixtureMode::Available, request)
        }
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .with_root_authorization_context(root_authorization_context())
        .enable_graphql_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let requests = server.requests().await;
    let posts = graphql_posts(&requests);
    assert_eq!(posts.len(), 3);
    assert!(posts.iter().all(|request| {
        !request.headers.contains_key("authorization") && !request.headers.contains_key("cookie")
    }));
    assert_eq!(
        report
            .transport()
            .receipts()
            .iter()
            .filter(|receipt| receipt.action_id().starts_with("web.review.graphql."))
            .count(),
        3
    );
    assert_eq!(
        report
            .transport()
            .receipts()
            .iter()
            .filter(|receipt| {
                receipt.action_id().starts_with("web.review.graphql.")
                    && receipt.stage() == DecisionExecutionStage::Active
            })
            .count(),
        1
    );
    assert_eq!(graphql_items(&report).len(), 2);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.headers.contains_key("authorization"))
            .count(),
        1
    );
}

#[cfg(feature = "graphql-review")]
#[tokio::test]
async fn cli_equivalent_low_risk_auth_and_graphql_share_the_exact_optional_allowance() {
    let server = serve(|request| {
        if request.method == "POST" {
            return graphql_fixture_reply(GraphqlFixtureMode::Available, request);
        }
        if request.headers.get("accept").map(String::as_str) == Some("application/json") {
            return FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/json"),
                r#"{"id":1}"#,
            ));
        }
        if let Some(origin) = request.headers.get("origin") {
            return FixtureReply::Response(
                FixtureResponse::html("cors candidate")
                    .with_header("Access-Control-Allow-Origin", origin)
                    .with_header("Access-Control-Allow-Credentials", "true")
                    .with_header("Vary", "Origin"),
            );
        }
        if request.target.starts_with("/review?") {
            let request_url = Url::parse(&format!("http://fixture{}", request.target)).unwrap();
            let candidate = request_url
                .query_pairs()
                .find_map(|(name, value)| (name == "input").then(|| value.into_owned()))
                .unwrap();
            return FixtureReply::Response(FixtureResponse::html(format!(
                "<script>const value = '{candidate}'</script>"
            )));
        }
        FixtureReply::Response(FixtureResponse::html(
            r#"<a href="/review?input=host-value">review</a>"#,
        ))
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_low_risk_differential_review()
        .with_root_authorization_context(root_authorization_context())
        .enable_graphql_review()
        .build()
        .unwrap();

    let base_closed_active = DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS;
    let graphql_active = GRAPHQL_REVIEW_ACTIVE_VERIFICATION_ALLOWANCE;
    assert_eq!(base_closed_active, 10);
    assert_eq!(graphql_active, 1);
    assert_eq!(runtime.runtime_active_verification_limit, 11);
    assert_eq!(
        runtime
            .authority
            .request_accounting()
            .budget()
            .max_active_verifications(),
        base_closed_active + graphql_active
    );

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
    assert_eq!(report.runtime_active_verification_limit(), 11);
    let root_native = enabled_native_web_review_actions(true, false, false, false, false, None);
    let non_root_native = enabled_native_web_review_actions(false, false, true, true, true, None);
    let xss_child = runtime
        .xss_structural_review
        .as_ref()
        .expect("the discovered script context selects one bounded XSS child")
        .enabled_actions
        .len();
    let auth_pair_active = 2_usize;
    let graphql_replay_active = usize::from(GRAPHQL_REVIEW_ACTIVE_VERIFICATION_ALLOWANCE);
    let expected_active = root_native.len()
        + non_root_native.len()
        + xss_child
        + auth_pair_active
        + graphql_replay_active;
    assert_eq!(expected_active, 10);
    assert_eq!(
        usize::from(report.usage().active_verifications()),
        expected_active
    );
    assert_eq!(graphql_posts(&server.requests().await).len(), 3);
    assert_eq!(graphql_items(&report).len(), 2);
    #[cfg(feature = "reporting")]
    {
        ReportGenerator::compose_assessment(report, ScanProfileV1::web_review().unwrap())
            .expect("the feature-local allowance remains compatible with profile-v1 reporting");
    }
}

#[tokio::test]
async fn root_authorization_pair_uses_shared_authority_and_projects_one_atomic_review_basis() {
    let server = serve(|request| {
        if request.headers.get("accept").map(String::as_str) == Some("application/json") {
            let body = if request.headers.contains_key("authorization") {
                r#"{"id":1,"private_field":"visible"}"#
            } else {
                r#"{"id":1}"#
            };
            return FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/json"),
                body,
            ));
        }
        FixtureReply::Response(FixtureResponse::html("root"))
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .with_root_authorization_context(root_authorization_context())
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
    assert_eq!(report.usage().active_verifications(), 2);
    assert_eq!(report.usage().total_requests(), 3);

    let item = report
        .assessment_items()
        .iter()
        .find(|item| {
            item.capability_id() == "api.review.authorization-context.visibility-difference@1"
        })
        .expect("canonical API visibility difference must project once");
    assert_eq!(item.disposition(), AssessmentDisposition::NeedsReview);
    assert_eq!(item.evidence_count(), 1);
    let AssessmentBasis::Differential(basis) = item.basis() else {
        panic!("API visibility review must retain a differential basis");
    };
    assert!(basis.control().is_empty());
    assert!(basis.candidate().is_empty());
    assert!(basis.paired_comparison().is_some());
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));

    let requests = server.requests().await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.headers.contains_key("authorization"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .find_map(|request| request.headers.get("authorization"))
            .map(String::as_str),
        Some(PRIVATE_AUTHORIZATION_SENTINEL)
    );
    assert!(!format!("{report:?}").contains(PRIVATE_AUTHORIZATION_SENTINEL));
}

#[tokio::test]
async fn equivalent_root_authorization_pair_is_observation_only_and_emits_no_review_item() {
    let server = serve(|request| {
        if request.headers.get("accept").map(String::as_str) == Some("application/json") {
            FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/json"),
                r#"{"id":1}"#,
            ))
        } else {
            FixtureReply::Response(FixtureResponse::html("root"))
        }
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .with_root_authorization_context(root_authorization_context())
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
    assert_eq!(report.usage().active_verifications(), 2);
    assert!(report.assessment_items().iter().all(|item| {
        item.capability_id() != "api.review.authorization-context.visibility-difference@1"
    }));
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
}

#[tokio::test]
async fn root_authorization_pair_limit_is_incomplete_and_suppresses_discovery() {
    let server = serve(|request| {
        if request.headers.get("accept").map(String::as_str) == Some("application/json") {
            return FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/json"),
                r#"{"id":1}"#,
            ));
        }
        FixtureReply::Response(FixtureResponse::html(
            r#"<a href="/must-not-be-discovered">next</a>"#,
        ))
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_active_verifications(1)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .limits(limits)
        .with_root_authorization_context(root_authorization_context())
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::ActiveVerificationLimit));
    assert_eq!(report.subjects().len(), 1);
    assert_eq!(report.usage().active_verifications(), 1);
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| !item.capability_id().starts_with("api.review.")));
    assert_eq!(server.hit_count("/must-not-be-discovered").await, 0);
}

#[test]
fn root_authorization_context_is_redacted_bounded_and_root_only() {
    let context = root_authorization_context();
    assert!(!format!("{context:?}").contains(PRIVATE_AUTHORIZATION_SENTINEL));
    for invalid in [b"".as_slice(), b" leading", b"trailing ", b"Bearer a\r\nb"] {
        assert!(WebAssessmentRootAuthorizationContext::new(invalid.to_vec()).is_err());
    }

    for target in [
        "https://example.test/path",
        "https://example.test/?query=value",
        "https://example.test/#fragment",
        "https://user:password@example.test/",
    ] {
        let result = WebAssessmentRuntime::builder(Url::parse(target).unwrap())
            .with_root_authorization_context(root_authorization_context())
            .build();
        let Err(error) = result else {
            panic!("non-root authorization context must fail closed");
        };
        assert!(matches!(
            error,
            WebAssessmentRuntimeError::RootAuthorizationContextRequiresOriginRoot
        ));
        assert!(!format!("{error:?}").contains(PRIVATE_AUTHORIZATION_SENTINEL));
    }
}

#[tokio::test]
async fn opted_in_native_review_uses_exact_root_shared_authority_and_no_redirect_follow() {
    let server = serve(|request| {
        if let Some(origin) = request.headers.get("origin") {
            return FixtureReply::Response(
                FixtureResponse::html("cors candidate")
                    .with_header("Access-Control-Allow-Origin", origin)
                    .with_header("Access-Control-Allow-Credentials", "true")
                    .with_header("Vary", "Origin"),
            );
        }
        if request.target.contains('?') {
            let request_url = Url::parse(&format!("http://fixture{}", request.target)).unwrap();
            let candidate = request_url
                .query_pairs()
                .find_map(|(name, value)| (name == "return_to").then(|| value.into_owned()))
                .expect("the review candidate uses the authorized query name");
            return FixtureReply::Response(
                FixtureResponse::new(
                    "302 Found",
                    Some("text/html"),
                    format!("<script>const destination = '{candidate}'</script>"),
                )
                .with_header("Location", &candidate),
            );
        }
        FixtureReply::Response(FixtureResponse::html("root control"))
    })
    .await;
    let target = server.url("/?return_to=host-value");
    let mut runtime = WebAssessmentRuntime::builder(target)
        .enable_low_risk_differential_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let requests = server.requests().await;
    let initial_enabled_actions =
        enabled_native_web_review_actions(true, true, true, true, true, None);
    let xss_enabled_actions = runtime
        .xss_structural_review
        .as_ref()
        .expect("the exact single-quoted script anchor selects one child review")
        .enabled_actions
        .clone();
    assert_eq!(
        xss_enabled_actions,
        [NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair]
    );
    assert_eq!(
        report.usage().active_verifications(),
        u16::try_from(initial_enabled_actions.len() + xss_enabled_actions.len()).unwrap(),
        "the exact initial plan plus one selected script child own every active verification"
    );
    // Each runtime owns one bootstrap plus both legs of its exact enabled set.
    let initial_requests = 1 + initial_enabled_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    let xss_child_requests = 1 + xss_enabled_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    assert_eq!(
        xss_child_requests,
        usize::from(xss_probe_catalog::XSS_V1_MAX_TOTAL_REQUESTS)
    );
    let expected_requests = initial_requests + xss_child_requests;
    assert_eq!(requests.len(), expected_requests);
    assert!(requests.iter().all(|request| request.path() == "/"));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.headers.contains_key("origin"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.contains("return_to="))
            .count(),
        initial_enabled_actions
            .iter()
            .map(|kind| match kind {
                NativeWebReviewActionKind::CorsPolicyPair => 0,
                NativeWebReviewActionKind::RedirectReflectionQueryPair => 1,
                _ => NATIVE_WEB_REVIEW_REQUESTS_PER_CASE,
            })
            .sum::<usize>()
            + xss_enabled_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE
    );
    assert_eq!(
        report.subjects()[0]
            .turns()
            .iter()
            .filter(|turn| matches!(
                turn,
                StandardWebDecisionRuntimeTurn::Outcome { evidence, .. }
                    if is_native_review_action(evidence.case().action_id())
            ))
            .count(),
        initial_enabled_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE,
        "the parent subject turn log retains the exact initial runtime; the selected child is accounted by its separate action receipts"
    );
    let native_items = report
        .assessment_items()
        .iter()
        .filter(|item| item.capability_id().starts_with("web.review."))
        .collect::<Vec<_>>();
    let expected_capabilities = BTreeSet::from([
        "web.review.cors.credentialed-external-origin@1",
        "web.review.redirect.candidate-specific-external@1",
        "web.review.reflection.script-element-context@1",
        "web.review.xss.structural-boundary@1",
    ]);
    assert_eq!(native_items.len(), expected_capabilities.len());
    assert_eq!(
        native_items
            .iter()
            .map(|item| item.capability_id())
            .collect::<BTreeSet<_>>(),
        expected_capabilities
    );
    assert!(native_items.iter().all(|item| {
        item.disposition() == AssessmentDisposition::NeedsReview
            && matches!(item.basis(), AssessmentBasis::Differential(_))
    }));
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition().as_str() != "confirmed"));
}

#[tokio::test]
async fn native_review_is_additive_to_eligible_standard_actions_under_one_budget() {
    let server = serve(|request| {
        let response = if let Some(origin) = request.headers.get("origin") {
            FixtureResponse::html("cors candidate")
                .with_header("Access-Control-Allow-Origin", origin)
                .with_header("Access-Control-Allow-Credentials", "true")
                .with_header("Vary", "Origin")
        } else {
            FixtureResponse::html("standard and cors control")
        };
        FixtureReply::Response(response)
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_low_risk_differential_review()
        .build()
        .unwrap();
    seed_laravel_planning_evidence(&runtime);

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::HumanReviewRequired));
    assert!(!report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::DifferentialReviewIncomplete));

    let action_ids = report.subjects()[0]
        .turns()
        .iter()
        .filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Outcome { evidence, .. } => {
                Some(evidence.case().action_id())
            },
            StandardWebDecisionRuntimeTurn::Planning(_) => None,
        })
        .collect::<Vec<_>>();
    assert!(
        action_ids.iter().any(|action_id| {
            StandardWebActionKind::all()
                .iter()
                .any(|kind| kind.action_id() == *action_id)
        }),
        "native review replaced the eligible standard action set: {action_ids:?}"
    );
    assert_eq!(
        action_ids
            .iter()
            .copied()
            .filter(|action_id| {
                *action_id == NativeWebReviewActionKind::CorsPolicyPair.action_id()
            })
            .count(),
        2
    );

    let requests = server.requests().await;
    assert!(requests
        .iter()
        .all(|request| request.host() == requests[0].host()));
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        requests.len()
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.headers.contains_key("origin"))
            .count(),
        1
    );
}

#[tokio::test]
async fn reflected_origin_and_generic_redirect_are_not_findings_and_text_boundary_is_review() {
    let server = serve(|request| {
        if let Some(origin) = request.headers.get("origin") {
            return FixtureReply::Response(
                FixtureResponse::html("origin reflected without credential policy")
                    .with_header("Access-Control-Allow-Origin", origin),
            );
        }
        if request.target.contains('?') {
            let request_url = Url::parse(&format!("http://fixture{}", request.target)).unwrap();
            let candidate = request_url
                .query_pairs()
                .find_map(|(name, value)| (name == "next").then(|| value.into_owned()))
                .unwrap();
            return FixtureReply::Response(
                FixtureResponse::new(
                    "302 Found",
                    Some("text/html"),
                    format!("<p>{candidate}</p>"),
                )
                .with_header("Location", "/login"),
            );
        }
        FixtureReply::Response(
            FixtureResponse::new("302 Found", Some("text/html"), "control")
                .with_header("Location", "/login"),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/?next=host-value"))
        .enable_low_risk_differential_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let native_items = report
        .assessment_items()
        .iter()
        .filter(|item| item.capability_id().starts_with("web.review."))
        .collect::<Vec<_>>();
    assert_eq!(native_items.len(), 2);
    assert_eq!(
        native_items
            .iter()
            .map(|item| (item.capability_id(), item.disposition()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "web.review.reflection.text-context@1",
                AssessmentDisposition::Informational,
            ),
            (
                "web.review.xss.structural-boundary@1",
                AssessmentDisposition::NeedsReview,
            ),
        ])
    );
    assert!(native_items.iter().all(|item| {
        item.disposition() != AssessmentDisposition::Confirmed
            && match item.capability_id() {
                "web.review.reflection.text-context@1" => {
                    matches!(item.basis(), AssessmentBasis::Observation(_))
                },
                "web.review.xss.structural-boundary@1" => {
                    matches!(item.basis(), AssessmentBasis::Differential(_))
                },
                _ => false,
            }
    }));
    let initial_enabled_actions =
        enabled_native_web_review_actions(true, true, true, true, true, None);
    // One bootstrap, the exact initial native legs, then the selected XSS
    // child bootstrap plus its control/candidate pair.
    let expected_requests = 1
        + initial_enabled_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE
        + usize::from(xss_probe_catalog::XSS_V1_MAX_TOTAL_REQUESTS);
    assert_eq!(server.requests().await.len(), expected_requests);
}

#[tokio::test]
async fn native_review_never_invents_an_unrecognized_query_parameter() {
    let server = serve(|request| {
        let response = if let Some(origin) = request.headers.get("origin") {
            FixtureResponse::html("cors candidate")
                .with_header("Access-Control-Allow-Origin", origin)
                .with_header("Access-Control-Allow-Credentials", "true")
        } else {
            FixtureResponse::html("root control")
        };
        FixtureReply::Response(response)
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/?opaque=host-value"))
        .enable_low_risk_differential_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let requests = server.requests().await;
    assert_eq!(requests.len(), 13);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.contains("opaque="))
            .count(),
        10
    );
    assert!(requests
        .iter()
        .all(|request| !request.target.contains("review.invalid")));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.headers.contains_key("origin"))
            .count(),
        1
    );
}

#[tokio::test]
async fn sql_review_projects_one_repeatable_non_root_item_without_query_value_leakage() {
    const SECRET: &str = "PRIVATE-SQL-QUERY-VALUE-SENTINEL";
    let server = serve(|request| {
        if request.path() == "/" {
            return FixtureReply::Response(FixtureResponse::html(format!(
                "<a href='/search?item={SECRET}'>search</a>"
            )));
        }
        let value = Url::parse(&format!("http://fixture{}", request.target))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find_map(|(name, value)| (name == "item").then(|| value.into_owned()))
            });
        if value
            .as_deref()
            .is_some_and(|value| value.starts_with("venom-reflection-candidate-"))
        {
            return FixtureReply::Response(FixtureResponse::html(format!(
                "<button onclick=\"{}\">continue</button>",
                value.as_deref().unwrap()
            )));
        }
        let candidate = value.is_some_and(|value| value.ends_with('\''));
        if candidate {
            FixtureReply::Response(FixtureResponse::new(
                "500 Internal Server Error",
                Some("text/html"),
                "<html><body><section><code>failure</code></section></body></html>",
            ))
        } else {
            FixtureReply::Response(FixtureResponse::html(
                "<html><body><main>normal</main></body></html>",
            ))
        }
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .enable_low_risk_differential_review()
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
    let sql_items = report
        .assessment_items()
        .iter()
        .filter(|item| item.capability_id() == "web.review.sql.structural-differential@1")
        .collect::<Vec<_>>();
    assert_eq!(sql_items.len(), 1);
    assert_eq!(
        sql_items[0].disposition(),
        AssessmentDisposition::NeedsReview
    );
    assert!(matches!(
        sql_items[0].basis(),
        AssessmentBasis::Differential(_)
    ));
    let reflection_item = report
        .assessment_items()
        .iter()
        .find(|item| item.capability_id() == "web.review.reflection.event-handler-context@1")
        .unwrap();
    assert_eq!(
        reflection_item.disposition(),
        AssessmentDisposition::NeedsReview
    );
    assert_eq!(
        reflection_item.subject_reference().to_string(),
        "subject-0001"
    );
    let expected_root_actions =
        enabled_native_web_review_actions(true, false, false, false, false, None);
    let expected_non_root_actions =
        enabled_native_web_review_actions(false, false, true, true, true, None);
    let root_review = runtime.native_review.as_ref().unwrap();
    let non_root_review = runtime.non_root_structural_review.as_ref().unwrap();
    let xss_review = runtime.xss_structural_review.as_ref().unwrap();
    assert_eq!(&root_review.enabled_actions, &expected_root_actions);
    assert_eq!(&non_root_review.enabled_actions, &expected_non_root_actions);
    assert_eq!(
        xss_review.enabled_actions.as_slice(),
        &[NativeWebReviewActionKind::XssAttributeBoundaryQueryPair]
    );
    assert_eq!(
        expected_non_root_actions
            .iter()
            .copied()
            .filter(|kind| matches!(
                kind,
                NativeWebReviewActionKind::SqlStructuralQueryPair
                    | NativeWebReviewActionKind::SqlStructuralQueryReplayPair
            ))
            .collect::<Vec<_>>(),
        [
            NativeWebReviewActionKind::SqlStructuralQueryPair,
            NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
        ]
    );
    assert!(expected_root_actions
        .iter()
        .chain(&expected_non_root_actions)
        .all(|kind| *kind != NativeWebReviewActionKind::RedirectReflectionQueryPair));

    // The initial root/non-root plans still own six active actions. The one
    // context-selected attribute-XSS child owns the seventh independently.
    let expected_initial_active_verifications =
        u16::try_from(expected_root_actions.len() + expected_non_root_actions.len()).unwrap();
    let expected_xss_active_verifications =
        u16::try_from(xss_review.enabled_actions.len()).unwrap();
    assert_eq!(expected_initial_active_verifications, 6);
    assert_eq!(expected_xss_active_verifications, 1);
    assert_eq!(
        report.usage().active_verifications(),
        expected_initial_active_verifications + expected_xss_active_verifications
    );
    // Each executed assessment subject owns one bootstrap request, and each
    // initial native action owns its fixed control/candidate legs. The selected
    // XSS child then owns its separate bootstrap and control/candidate pair.
    let expected_initial_bootstrap_requests = report.usage().executed_subjects();
    let expected_initial_requests = expected_initial_bootstrap_requests
        + usize::from(expected_initial_active_verifications) * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    let expected_xss_child_requests = usize::from(xss_probe_catalog::XSS_V1_MAX_TOTAL_REQUESTS);
    assert_eq!(expected_initial_bootstrap_requests, 2);
    assert_eq!(expected_initial_requests, 14);
    assert_eq!(expected_xss_child_requests, 3);
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        expected_initial_requests + expected_xss_child_requests
    );
    let requests = server.requests().await;
    assert!(requests
        .iter()
        .all(|request| request.host() == requests[0].host()));
    assert!(requests
        .iter()
        .all(|request| !request.target.contains(SECRET)));
    assert!(!format!("{report:?}").contains(SECRET));
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
}

#[cfg(feature = "reporting")]
#[tokio::test]
async fn ssti_review_requires_two_exact_evaluations_and_redacts_every_renderer() {
    const SECRET: &str = "VENOM-SSTI-MUST-NOT-LEAK-SECRET-123";
    let server = serve(|request| {
        let evaluated = Url::parse(&format!("http://fixture{}", request.target))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find_map(|(name, value)| (name == "item").then(|| value.into_owned()))
            })
            .and_then(|value| {
                let (prefix, expression) = value.split_once("-{{")?;
                let expression = expression.strip_suffix("}}-end")?;
                let (left, right) = expression.split_once('*')?;
                let product = left.parse::<u16>().ok()? * right.parse::<u16>().ok()?;
                Some(format!("{prefix}-{product}-end"))
            });
        FixtureReply::Response(FixtureResponse::html(
            evaluated.unwrap_or_else(|| "matched control".to_owned()),
        ))
    })
    .await;

    let run = async || {
        let mut runtime = WebAssessmentRuntime::builder(server.url(&format!("/?item={SECRET}")))
            .enable_low_risk_differential_review()
            .build()
            .unwrap();
        runtime.analyze().await.unwrap()
    };
    let first = run().await;
    let second = run().await;
    for report in [&first, &second] {
        assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
        let items = report
            .assessment_items()
            .iter()
            .filter(|item| item.capability_id() == "web.review.ssti.structural-evaluation@1")
            .collect::<Vec<_>>();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].disposition(), AssessmentDisposition::NeedsReview);
        assert!(matches!(items[0].basis(), AssessmentBasis::Differential(_)));
        assert!(!format!("{report:?}").contains(SECRET));
        assert!(report
            .assessment_items()
            .iter()
            .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
    }
    let first_fingerprint = first
        .assessment_items()
        .iter()
        .find(|item| item.capability_id() == "web.review.ssti.structural-evaluation@1")
        .unwrap()
        .fingerprint();
    let second_fingerprint = second
        .assessment_items()
        .iter()
        .find(|item| item.capability_id() == "web.review.ssti.structural-evaluation@1")
        .unwrap()
        .fingerprint();
    assert_eq!(first_fingerprint, second_fingerprint);

    let product =
        ReportGenerator::compose_assessment(first, ScanProfileV1::web_review().unwrap()).unwrap();
    for format in [
        ReportFormat::Json,
        ReportFormat::Csv,
        ReportFormat::Html,
        ReportFormat::Markdown,
    ] {
        let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
        assert!(!rendered.contains(SECRET));
        assert!(rendered.contains("web.review.ssti.structural-evaluation@1"));
        assert!(!rendered.contains("confirmed"));
    }
}

#[cfg(feature = "reporting")]
#[tokio::test]
async fn html_text_boundary_is_needs_review_deterministic_and_report_safe() {
    const SECRET: &str = "VENOM-XSS-ARSENAL-MUST-NOT-LEAK-SECRET-123";
    let server = serve(|request| {
        let value = Url::parse(&format!("http://fixture{}", request.target))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find_map(|(name, value)| (name == "item").then(|| value.into_owned()))
            });
        let body = match value {
            Some(value) if value.starts_with("venom-reflection-candidate-") => {
                format!("<p>{value}</p>")
            },
            Some(value) if value.starts_with("<span data-venom-xss-boundary-token=") => value,
            _ => "matched control".to_owned(),
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let run = async || {
        let mut runtime = WebAssessmentRuntime::builder(server.url(&format!("/?item={SECRET}")))
            .enable_low_risk_differential_review()
            .build()
            .unwrap();
        runtime.analyze().await.unwrap()
    };
    let first = run().await;
    let second = run().await;
    for report in [&first, &second] {
        assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
        let item = report
            .assessment_items()
            .iter()
            .find(|item| item.capability_id() == "web.review.reflection.text-context@1")
            .unwrap();
        assert_eq!(item.disposition(), AssessmentDisposition::Informational);
        assert!(matches!(item.basis(), AssessmentBasis::Observation(_)));
        let xss_item = report
            .assessment_items()
            .iter()
            .find(|item| item.capability_id() == "web.review.xss.structural-boundary@1")
            .unwrap();
        assert_eq!(xss_item.disposition(), AssessmentDisposition::NeedsReview);
        assert!(matches!(xss_item.basis(), AssessmentBasis::Differential(_)));
        assert!(!format!("{report:?}").contains(SECRET));
        assert!(report
            .assessment_items()
            .iter()
            .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
    }
    let fingerprint = |report: &WebAssessmentRunReport, capability: &str| {
        report
            .assessment_items()
            .iter()
            .find(|item| item.capability_id() == capability)
            .unwrap()
            .fingerprint()
            .to_owned()
    };
    for capability in [
        "web.review.reflection.text-context@1",
        "web.review.xss.structural-boundary@1",
    ] {
        assert_eq!(
            fingerprint(&first, capability),
            fingerprint(&second, capability)
        );
    }
    let requests = server.requests().await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.contains("venom-xss-boundary"))
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.contains("venom-xss-control-"))
            .count(),
        2
    );
    assert!(requests.iter().all(|request| {
        !request.target.contains("javascript%3A") && !request.target.contains("http%3A%2F%2F")
    }));

    let product =
        ReportGenerator::compose_assessment(first, ScanProfileV1::web_review().unwrap()).unwrap();
    for format in [
        ReportFormat::Json,
        ReportFormat::Csv,
        ReportFormat::Html,
        ReportFormat::Markdown,
    ] {
        let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("venom-reflection-candidate-"));
        assert!(rendered.contains("web.review.reflection.text-context@1"));
        assert!(rendered.contains("web.review.xss.structural-boundary@1"));
        assert!(!rendered.contains("venom-xss-boundary"));
        assert!(!rendered.contains("data-venom-xss-boundary-token"));
        assert!(!rendered.contains("confirmed"));
    }
}

#[tokio::test]
async fn quote_aware_attribute_boundaries_are_bounded_needs_review_only() {
    const SECRET: &str = "VENOM-ATTRIBUTE-XSS-MUST-NOT-LEAK-SECRET-123";
    for (element, attribute, delimiter) in [
        ("div", "title", "\""),
        ("a", "href", "'"),
        ("button", "onclick", ""),
    ] {
        let server = serve(move |request| {
            let value = Url::parse(&format!("http://fixture{}", request.target))
                .ok()
                .and_then(|url| {
                    url.query_pairs()
                        .find_map(|(name, value)| (name == "item").then(|| value.into_owned()))
                });
            let body = value.map_or_else(
                || "matched control".to_owned(),
                |value| {
                    format!("<{element} {attribute}={delimiter}{value}{delimiter}></{element}>")
                },
            );
            FixtureReply::Response(FixtureResponse::html(body))
        })
        .await;
        let mut runtime = WebAssessmentRuntime::builder(server.url(&format!("/?item={SECRET}")))
            .enable_low_risk_differential_review()
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
        let xss_items = report
            .assessment_items()
            .iter()
            .filter(|item| item.capability_id() == "web.review.xss.structural-boundary@1")
            .collect::<Vec<_>>();
        assert_eq!(xss_items.len(), 1);
        assert_eq!(
            xss_items[0].disposition(),
            AssessmentDisposition::NeedsReview
        );
        assert!(matches!(
            xss_items[0].basis(),
            AssessmentBasis::Differential(_)
        ));
        assert!(report
            .assessment_items()
            .iter()
            .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
        assert!(!format!("{report:?}").contains(SECRET));

        let query_parameter_names = vec!["item".to_owned()];
        let redirect_query_parameter =
            select_redirect_review_query_parameter(&query_parameter_names);
        assert_eq!(redirect_query_parameter, None);
        let initial = enabled_native_web_review_actions(
            true,
            redirect_query_parameter.is_some(),
            true,
            true,
            true,
            None,
        );
        assert_eq!(
            runtime.native_review.as_ref().unwrap().enabled_actions,
            initial
        );
        assert!(!initial.contains(&NativeWebReviewActionKind::RedirectReflectionQueryPair));
        assert_eq!(
            runtime
                .xss_structural_review
                .as_ref()
                .unwrap()
                .enabled_actions
                .as_slice(),
            &[NativeWebReviewActionKind::XssAttributeBoundaryQueryPair]
        );
        let expected_initial_requests = 1 + initial.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
        let expected_xss_child_requests = usize::from(xss_probe_catalog::XSS_V1_MAX_TOTAL_REQUESTS);
        assert_eq!(expected_xss_child_requests, 3);
        let requests = server.requests().await;
        assert_eq!(
            requests.len(),
            expected_initial_requests + expected_xss_child_requests
        );
        assert!(requests
            .iter()
            .all(|request| request.host() == requests[0].host()));
        assert!(requests
            .iter()
            .all(|request| !request.target.contains("review.invalid")));
        assert!(requests
            .iter()
            .filter(|request| request.target.contains("data-venom-xss-boundary-token"))
            .all(|request| {
                !request.target.contains("javascript%3A")
                    && !request.target.contains("data%3A")
                    && !request.target.contains("http%3A%2F%2F")
            }));
        #[cfg(feature = "reporting")]
        {
            let product =
                ReportGenerator::compose_assessment(report, ScanProfileV1::web_review().unwrap())
                    .unwrap();
            for format in [
                ReportFormat::Json,
                ReportFormat::Csv,
                ReportFormat::Html,
                ReportFormat::Markdown,
            ] {
                let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
                assert!(!rendered.contains(SECRET));
                assert!(!rendered.contains("data-venom-xss-boundary-token"));
                assert!(!rendered.contains("data-venom-xss-tail-token"));
                assert!(!rendered.contains("venom-reflection-candidate-"));
                assert!(!rendered.contains("confirmed"));
            }
        }
    }
}

#[tokio::test]
async fn single_quoted_script_boundary_is_bounded_needs_review_and_report_safe() {
    const SECRET: &str = "VENOM-JS-XSS-MUST-NOT-LEAK-SECRET-123";
    let server = serve(|request| {
        let value = Url::parse(&format!("http://fixture{}", request.target))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find_map(|(name, value)| (name == "item").then(|| value.into_owned()))
            })
            .unwrap_or_else(|| "matched-control".to_owned());
        FixtureReply::Response(FixtureResponse::html(format!(
            "<script>const value = '{value}';</script>"
        )))
    })
    .await;

    let mut runtime = WebAssessmentRuntime::builder(server.url(&format!("/?item={SECRET}")))
        .enable_low_risk_differential_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let query_parameter_names = vec!["item".to_owned()];
    let redirect_query_parameter = select_redirect_review_query_parameter(&query_parameter_names);
    assert_eq!(redirect_query_parameter, None);
    let initial_actions = enabled_native_web_review_actions(
        true,
        redirect_query_parameter.is_some(),
        true,
        true,
        true,
        None,
    );
    assert_eq!(
        runtime.native_review.as_ref().unwrap().enabled_actions,
        initial_actions
    );
    assert!(!initial_actions.contains(&NativeWebReviewActionKind::RedirectReflectionQueryPair));

    let xss_actions = runtime
        .xss_structural_review
        .as_ref()
        .expect("the exact JavaScript source anchor selects one child review")
        .enabled_actions
        .as_slice();
    assert_eq!(
        xss_actions,
        &[NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair]
    );
    assert_eq!(
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair.verification_target(),
        crate::planner::VerificationTarget::KnowledgeOnly
    );

    let expected_initial_requests = 1 + initial_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    let expected_xss_child_requests = 1 + xss_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    assert_eq!(
        expected_xss_child_requests,
        usize::from(xss_probe_catalog::XSS_V1_MAX_TOTAL_REQUESTS)
    );
    assert_eq!(expected_xss_child_requests, 3);

    let expected_initial_active =
        initial_actions.len() * NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE;
    let expected_xss_active = xss_actions.len() * NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE;
    assert_eq!(expected_xss_active, 1);
    assert_eq!(
        usize::from(report.usage().active_verifications()),
        expected_initial_active + expected_xss_active
    );

    let xss_items = report
        .assessment_items()
        .iter()
        .filter(|item| item.capability_id() == "web.review.xss.structural-boundary@1")
        .collect::<Vec<_>>();
    assert_eq!(xss_items.len(), 1);
    assert_eq!(
        xss_items[0].disposition(),
        AssessmentDisposition::NeedsReview
    );
    assert!(matches!(
        xss_items[0].basis(),
        AssessmentBasis::Differential(_)
    ));
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));

    let script_action = NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair.action_id();
    let script_receipts = report
        .transport()
        .receipts()
        .iter()
        .filter(|receipt| receipt.action_id() == script_action)
        .collect::<Vec<_>>();
    assert_eq!(script_receipts.len(), NATIVE_WEB_REVIEW_REQUESTS_PER_CASE);
    assert_eq!(
        script_receipts
            .iter()
            .filter(|receipt| receipt.stage() == DecisionExecutionStage::Active)
            .count(),
        NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE
    );

    let requests = server.requests().await;
    assert_eq!(
        requests.len(),
        expected_initial_requests + expected_xss_child_requests
    );
    assert!(requests.iter().all(|request| request.path() == "/"));
    assert!(requests
        .iter()
        .all(|request| request.host() == requests[0].host()));
    assert!(requests
        .iter()
        .all(|request| !request.target.contains("review.invalid")));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.contains("venom-xss-js-control-"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.target.contains("venom-xss-js-boundary-"))
            .count(),
        1
    );
    assert!(requests.iter().all(|request| {
        let target = request.target.to_ascii_lowercase();
        !target.contains("javascript%3a")
            && !target.contains("data%3a")
            && !target.contains("http%3a%2f%2f")
            && !target.contains("https%3a%2f%2f")
            && !target.contains("alert")
            && !target.contains("prompt")
            && !target.contains("confirm")
    }));
    assert!(!format!("{report:?}").contains(SECRET));

    #[cfg(feature = "reporting")]
    {
        let product =
            ReportGenerator::compose_assessment(report, ScanProfileV1::web_review().unwrap())
                .unwrap();
        for format in [
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Html,
            ReportFormat::Markdown,
        ] {
            let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
            assert!(!rendered.contains(SECRET));
            assert!(!rendered.contains("venom-xss-js-control-"));
            assert!(!rendered.contains("venom-xss-js-boundary-"));
            assert!(!rendered.contains("venom-xss-js-tail-"));
            assert!(!rendered.contains("confirmed"));
        }
    }
}

#[cfg(feature = "normalization-resilience")]
const NORMALIZATION_RESILIENCE_SECRET: &str =
    "VENOM-NORMALIZATION-RESILIENCE-MUST-NOT-LEAK-SECRET-123";
#[cfg(feature = "normalization-resilience")]
const HTML_TOKEN_CASE_NORMALIZATION_CAPABILITY: &str =
    "web.review.normalization-resilience.xss.html-text-boundary.html-token-case@1";

#[cfg(feature = "normalization-resilience")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NormalizationFixtureMode {
    Positive,
    AcceptedWithoutSemantics,
    StandingBlock,
    RateLimit,
    CanonicalAllowed,
    ReplayMismatch,
}

#[cfg(feature = "normalization-resilience")]
fn normalization_query_value(request: &RecordedRequest) -> Option<String> {
    Url::parse(&format!("http://fixture{}", request.target))
        .ok()?
        .query_pairs()
        .find_map(|(name, value)| (name == "item").then(|| value.into_owned()))
}

#[cfg(feature = "normalization-resilience")]
async fn run_normalization_fixture(
    mode: NormalizationFixtureMode,
) -> (LocalServer, WebAssessmentRuntime, WebAssessmentRunReport) {
    let transformed_legs = Arc::new(AtomicUsize::new(0));
    let transformed_legs_for_server = transformed_legs.clone();
    let server = serve(move |request| {
        let Some(value) = normalization_query_value(request) else {
            return FixtureReply::Response(FixtureResponse::html("matched control"));
        };
        if value.starts_with("venom-reflection-candidate-") {
            return FixtureReply::Response(FixtureResponse::html(format!("<p>{value}</p>")));
        }
        if value.starts_with("venom-xss-control-") {
            return FixtureReply::Response(if mode == NormalizationFixtureMode::StandingBlock {
                FixtureResponse::new(
                    "403 Forbidden",
                    Some("text/html"),
                    "candidate-specific policy block",
                )
            } else {
                FixtureResponse::html("matched control")
            });
        }
        if value.starts_with("<span data-venom-xss-boundary-token=") {
            return FixtureReply::Response(match mode {
                NormalizationFixtureMode::CanonicalAllowed => FixtureResponse::html(value),
                NormalizationFixtureMode::RateLimit => {
                    FixtureResponse::new("429 Too Many Requests", Some("text/html"), "slow down")
                },
                NormalizationFixtureMode::Positive
                | NormalizationFixtureMode::AcceptedWithoutSemantics
                | NormalizationFixtureMode::StandingBlock
                | NormalizationFixtureMode::ReplayMismatch => FixtureResponse::new(
                    "403 Forbidden",
                    Some("text/html"),
                    "candidate-specific policy block",
                ),
            });
        }
        if value.starts_with("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN=") {
            let ordinal = transformed_legs_for_server.fetch_add(1, Ordering::SeqCst);
            let body = match mode {
                NormalizationFixtureMode::Positive => value,
                NormalizationFixtureMode::ReplayMismatch if ordinal == 0 => value,
                NormalizationFixtureMode::AcceptedWithoutSemantics
                | NormalizationFixtureMode::ReplayMismatch => {
                    "accepted without equivalent application semantics".to_owned()
                },
                NormalizationFixtureMode::StandingBlock
                | NormalizationFixtureMode::RateLimit
                | NormalizationFixtureMode::CanonicalAllowed => value,
            };
            return FixtureReply::Response(FixtureResponse::html(body));
        }
        FixtureReply::Response(FixtureResponse::html("matched control"))
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(
        server.url(&format!("/?item={NORMALIZATION_RESILIENCE_SECRET}")),
    )
    .enable_low_risk_differential_review()
    .enable_normalization_resilience()
    .build()
    .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    (server, runtime, report)
}

#[cfg(feature = "normalization-resilience")]
fn normalization_items(report: &WebAssessmentRunReport) -> Vec<&AssessmentItem> {
    report
        .assessment_items()
        .iter()
        .filter(|item| {
            item.capability_id()
                .starts_with("web.review.normalization-resilience.")
        })
        .collect()
}

#[cfg(feature = "normalization-resilience")]
fn assert_no_normalization_child(
    server_requests: &[RecordedRequest],
    runtime: &WebAssessmentRuntime,
    report: &WebAssessmentRunReport,
) {
    assert!(runtime.normalization_review.is_none());
    assert!(normalization_items(report).is_empty());
    assert_eq!(
        server_requests
            .iter()
            .filter_map(normalization_query_value)
            .filter(|value| value.starts_with("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN="))
            .count(),
        0
    );
    assert_eq!(
        report
            .transport()
            .receipts()
            .iter()
            .filter(|receipt| {
                receipt.action_id()
                    == NativeWebReviewActionKind::NormalizationResilienceQueryPair.action_id()
            })
            .count(),
        0
    );
}

#[cfg(feature = "normalization-resilience")]
#[tokio::test]
async fn html_token_case_normalization_gap_is_replayed_bounded_and_report_safe() {
    let (server, runtime, report) =
        run_normalization_fixture(NormalizationFixtureMode::Positive).await;
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);

    let items = normalization_items(&report);
    assert_eq!(items.len(), 1);
    let item = items[0];
    assert_eq!(
        item.capability_id(),
        HTML_TOKEN_CASE_NORMALIZATION_CAPABILITY
    );
    assert_eq!(item.disposition(), AssessmentDisposition::NeedsReview);
    assert!(matches!(item.basis(), AssessmentBasis::Differential(_)));
    assert_eq!(item.severity(), None);
    assert_eq!(
        NativeWebReviewActionKind::NormalizationResilienceQueryPair.verification_target(),
        crate::planner::VerificationTarget::KnowledgeOnly
    );
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));

    let initial_actions = enabled_native_web_review_actions(true, false, true, true, true, None);
    let xss_actions = runtime
        .xss_structural_review
        .as_ref()
        .expect("the HTML-text parent must own one structural child")
        .enabled_actions
        .as_slice();
    assert_eq!(
        xss_actions,
        &[NativeWebReviewActionKind::XssStructuralQueryPair]
    );
    let normalization_actions = runtime
        .normalization_review
        .as_ref()
        .expect("the exact candidate-specific parent must own one normalization child")
        .enabled_actions
        .as_slice();
    assert_eq!(
        normalization_actions,
        &[NativeWebReviewActionKind::NormalizationResilienceQueryPair]
    );

    let initial_requests = 1 + initial_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    let parent_requests = 1 + xss_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    let normalization_requests =
        1 + normalization_actions.len() * NATIVE_WEB_REVIEW_REQUESTS_PER_CASE;
    assert_eq!(
        parent_requests,
        usize::from(xss_probe_catalog::XSS_V1_MAX_TOTAL_REQUESTS)
    );
    assert_eq!(
        normalization_requests,
        usize::from(NORMALIZATION_V1_MAX_CHILD_REQUESTS)
    );
    let expected_requests = initial_requests + parent_requests + normalization_requests;
    let expected_active = initial_actions.len()
        + xss_actions.len() * NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE
        + normalization_actions.len() * NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE;
    assert_eq!(
        normalization_actions.len() * NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE,
        usize::from(NORMALIZATION_V1_MAX_CHILD_ACTIVE_VERIFICATIONS)
    );
    assert_eq!(
        usize::from(report.usage().active_verifications()),
        expected_active
    );
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        expected_requests
    );

    let action_id = NativeWebReviewActionKind::NormalizationResilienceQueryPair.action_id();
    let action_receipts = report
        .transport()
        .receipts()
        .iter()
        .filter(|receipt| receipt.action_id() == action_id)
        .collect::<Vec<_>>();
    assert_eq!(action_receipts.len(), NATIVE_WEB_REVIEW_REQUESTS_PER_CASE);
    assert_eq!(
        action_receipts
            .iter()
            .filter(|receipt| receipt.stage() == DecisionExecutionStage::Active)
            .count(),
        NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE
    );

    let requests = server.requests().await;
    assert_eq!(requests.len(), expected_requests);
    assert!(requests.iter().all(|request| request.path() == "/"));
    assert!(requests
        .iter()
        .all(|request| request.host() == requests[0].host()));
    let values = requests
        .iter()
        .filter_map(normalization_query_value)
        .collect::<Vec<_>>();
    assert_eq!(
        values
            .iter()
            .filter(|value| value.starts_with("venom-xss-control-"))
            .count(),
        1,
        "the committed parent control must not be resent"
    );
    assert_eq!(
        values
            .iter()
            .filter(|value| value.starts_with("<span data-venom-xss-boundary-token="))
            .count(),
        1,
        "the committed canonical parent candidate must not be resent"
    );
    let transformed = values
        .iter()
        .filter(|value| value.starts_with("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN="))
        .collect::<Vec<_>>();
    assert_eq!(transformed.len(), 2);
    assert_ne!(transformed[0], transformed[1]);
    let transformed_identities = transformed
        .iter()
        .map(|value| {
            value
                .strip_prefix("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN=\"")
                .and_then(|value| value.strip_suffix("\"></SPAN>"))
                .filter(|value| {
                    value.len() == 32
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
                .expect("the typed serializer must retain one bounded opaque identity")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_ne!(transformed_identities[0], transformed_identities[1]);
    let report_debug = format!("{report:?}");
    assert!(!report_debug.contains(NORMALIZATION_RESILIENCE_SECRET));
    for identity in &transformed_identities {
        assert!(!report_debug.contains(identity));
    }
    assert!(requests
        .iter()
        .all(|request| !request.target.contains(NORMALIZATION_RESILIENCE_SECRET)));

    #[cfg(feature = "reporting")]
    {
        let capability = item.capability_id();
        let product =
            ReportGenerator::compose_assessment(report, ScanProfileV1::web_review().unwrap())
                .unwrap();
        for format in [
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Html,
            ReportFormat::Markdown,
        ] {
            let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
            assert!(!rendered.contains(NORMALIZATION_RESILIENCE_SECRET));
            assert!(!rendered.contains("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN="));
            assert!(!rendered.contains("<span data-venom-xss-boundary-token="));
            assert!(rendered.contains(capability));
            assert!(rendered.contains("needs_review"));
            assert!(!rendered.contains("WafBypassConfirmed"));
            assert!(!rendered.contains("waf-bypass-confirmed"));
            for identity in &transformed_identities {
                assert!(!rendered.contains(identity));
            }
        }
    }
}

#[cfg(feature = "normalization-resilience")]
#[tokio::test]
async fn accepted_normalization_without_application_semantics_projects_no_item() {
    let (server, runtime, report) =
        run_normalization_fixture(NormalizationFixtureMode::AcceptedWithoutSemantics).await;
    assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
    assert!(runtime.normalization_review.is_some());
    assert!(normalization_items(&report).is_empty());
    assert_eq!(
        server
            .requests()
            .await
            .iter()
            .filter_map(normalization_query_value)
            .filter(|value| value.starts_with("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN="))
            .count(),
        NATIVE_WEB_REVIEW_REQUESTS_PER_CASE
    );
}

#[cfg(feature = "normalization-resilience")]
#[tokio::test]
async fn standing_parent_block_dispatches_no_normalization_child() {
    let (server, runtime, report) =
        run_normalization_fixture(NormalizationFixtureMode::StandingBlock).await;
    let requests = server.requests().await;
    assert_no_normalization_child(&requests, &runtime, &report);
}

#[cfg(feature = "normalization-resilience")]
#[tokio::test]
async fn parent_rate_limit_dispatches_no_normalization_child() {
    let (server, runtime, report) =
        run_normalization_fixture(NormalizationFixtureMode::RateLimit).await;
    let requests = server.requests().await;
    assert_no_normalization_child(&requests, &runtime, &report);
}

#[cfg(feature = "normalization-resilience")]
#[tokio::test]
async fn canonical_semantic_success_dispatches_no_normalization_child() {
    let (server, runtime, report) =
        run_normalization_fixture(NormalizationFixtureMode::CanonicalAllowed).await;
    let requests = server.requests().await;
    assert_no_normalization_child(&requests, &runtime, &report);
    assert!(report
        .assessment_items()
        .iter()
        .any(|item| item.capability_id() == "web.review.xss.structural-boundary@1"));
}

#[cfg(feature = "normalization-resilience")]
#[tokio::test]
async fn normalization_replay_semantic_mismatch_projects_no_item() {
    let (server, runtime, report) =
        run_normalization_fixture(NormalizationFixtureMode::ReplayMismatch).await;
    assert!(runtime.normalization_review.is_some());
    assert!(normalization_items(&report).is_empty());
    assert_eq!(
        server
            .requests()
            .await
            .iter()
            .filter_map(normalization_query_value)
            .filter(|value| value.starts_with("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN="))
            .count(),
        NATIVE_WEB_REVIEW_REQUESTS_PER_CASE
    );
}

#[tokio::test]
async fn native_review_budget_exhaustion_is_typed_incomplete_not_empty_success() {
    let server = serve(|_| FixtureReply::Response(FixtureResponse::html("bounded"))).await;
    let limits = WebAssessmentLimits::default()
        .with_max_total_requests(2)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/?return_to=value"))
        .limits(limits)
        .enable_low_risk_differential_review()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::DifferentialReviewIncomplete));
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(report.usage().total_requests(), 2);
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition().as_str() != "confirmed"));
}

#[tokio::test]
async fn incomplete_reflection_analysis_is_typed_incomplete_not_empty_success() {
    let server = serve(|request| {
        let body = if request.target.contains('?') {
            "x".repeat(256)
        } else {
            "bounded".to_owned()
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_response_body_bytes(64)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/?return_to=host-value"))
        .limits(limits)
        .enable_low_risk_differential_review()
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::DifferentialReviewIncomplete));
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
}

#[tokio::test]
async fn truncated_explicit_non_html_is_not_applicable_to_reflection_review() {
    let server = serve(|request| {
        let response = if request.target.contains('?') {
            FixtureResponse::new("200 OK", Some("application/json"), "x".repeat(256))
        } else {
            FixtureResponse::html("bounded")
        };
        FixtureReply::Response(response)
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_response_body_bytes(64)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/?return_to=host-value"))
        .limits(limits)
        .enable_low_risk_differential_review()
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::DifferentialReviewIncomplete));
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
}

#[cfg(feature = "reporting")]
#[tokio::test]
async fn web_review_consumes_one_context_owned_item_set_into_the_additive_report() {
    let server = serve(|_| FixtureReply::Response(FixtureResponse::html("root"))).await;
    let target = server.url("/");
    let mut runtime = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    let audit = runtime.analyze().await.unwrap();
    assert_eq!(audit.authorized_root().url(), &target);
    assert_eq!(audit.limits(), WebAssessmentLimits::default());
    assert!(!audit.assessment_items().is_empty());
    assert!(audit
        .assessment_items()
        .iter()
        .all(|item| item.disposition().as_str() == "informational"));

    let product =
        ReportGenerator::compose_assessment(audit, ScanProfileV1::web_review().unwrap()).unwrap();

    assert_eq!(product.schema(), ASSESSMENT_RUN_REPORT_SCHEMA);
    assert_eq!(product.profile().profile(), BuiltInScanProfile::WebReview);
    assert_eq!(product.subject_count(), 1);
    assert!(!product.items().is_empty());
    assert!(product
        .items()
        .windows(2)
        .all(|pair| pair[0].fingerprint() < pair[1].fingerprint()));
}

#[cfg(feature = "reporting")]
#[tokio::test]
async fn discovered_passive_items_have_repeatable_private_identity_in_every_renderer() {
    const SECRET: &str = "VENOM-MUST-NOT-LEAK-QUERY-SECRET-123";
    let server = serve(|request| {
        let body = if request.path() == "/" {
            format!(
                "<a href='/account/./profile?tab={SECRET}&page=1'>first</a>\
                 <a href='/account/profile?page=999&tab=other#ignored'>duplicate</a>"
            )
        } else {
            "profile".to_owned()
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let run = async || {
        let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
            .build()
            .unwrap();
        runtime.analyze().await.unwrap()
    };
    let first = run().await;
    let second = run().await;
    for report in [&first, &second] {
        assert_eq!(report.completion(), &WebAssessmentCompletion::Complete);
        assert!(!report
            .completion()
            .reasons()
            .contains(&WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable));
        assert_eq!(report.subjects().len(), 2);
        assert_eq!(
            report
                .subjects()
                .iter()
                .filter(|subject| subject.subject().url().path() == "/account/profile")
                .count(),
            1
        );
        assert!(report.assessment_items().iter().any(|item| {
            item.subject_reference().to_string() == "subject-0001"
                && item.disposition() == AssessmentDisposition::Informational
        }));
        assert!(report
            .assessment_items()
            .iter()
            .all(|item| item.disposition() != AssessmentDisposition::Confirmed));
        assert!(!format!("{report:?}").contains(SECRET));
    }
    assert_eq!(
        first
            .assessment_items()
            .iter()
            .map(|item| item.fingerprint())
            .collect::<Vec<_>>(),
        second
            .assessment_items()
            .iter()
            .map(|item| item.fingerprint())
            .collect::<Vec<_>>()
    );

    let product =
        ReportGenerator::compose_assessment(first, ScanProfileV1::web_review().unwrap()).unwrap();
    assert_eq!(product.subject_count(), 2);
    for format in [
        ReportFormat::Json,
        ReportFormat::Csv,
        ReportFormat::Html,
        ReportFormat::Markdown,
    ] {
        let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
        assert!(!rendered.contains(SECRET));
        assert!(rendered.contains("subject-0001"));
    }
}

#[cfg(feature = "reporting")]
#[tokio::test]
async fn atomic_api_visibility_basis_is_distinct_and_redacted_in_every_renderer() {
    let server = serve(|request| {
        if request.headers.get("accept").map(String::as_str) == Some("application/json") {
            let body = if request.headers.contains_key("authorization") {
                r#"{"id":1,"private_field":"visible"}"#
            } else {
                r#"{"id":1}"#
            };
            FixtureReply::Response(FixtureResponse::new(
                "200 OK",
                Some("application/json"),
                body,
            ))
        } else {
            FixtureReply::Response(FixtureResponse::html("root"))
        }
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/"))
        .with_root_authorization_context(root_authorization_context())
        .build()
        .unwrap();
    let audit = runtime.analyze().await.unwrap();
    let product =
        ReportGenerator::compose_assessment(audit, ScanProfileV1::web_review().unwrap()).unwrap();

    let json = ReportGenerator::generate_assessment(&product, ReportFormat::Json).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let item = value["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["capability_id"] == "api.review.authorization-context.visibility-difference@1"
        })
        .unwrap();
    assert_eq!(item["disposition"], "needs_review");
    assert_eq!(item["claim_basis"], "differential");
    assert_eq!(item["evidence_references"].as_array().unwrap().len(), 1);
    assert!(item["control_evidence_references"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(item["candidate_evidence_references"]
        .as_array()
        .unwrap()
        .is_empty());

    for format in [
        ReportFormat::Json,
        ReportFormat::Csv,
        ReportFormat::Html,
        ReportFormat::Markdown,
    ] {
        let rendered = ReportGenerator::generate_assessment(&product, format).unwrap();
        assert!(!rendered.contains(PRIVATE_AUTHORIZATION_SENTINEL));
        assert!(rendered.contains("needs_review"));
        assert!(!rendered.contains("confirmed"));
    }
}

#[tokio::test]
async fn default_defense_audit_replays_committed_receipts_without_enforcement() {
    let server = serve(|_| {
        FixtureReply::Response(
            FixtureResponse::new(
                "403 Forbidden",
                Some("text/html"),
                "<html><body>blocked</body></html>",
            )
            .with_header("CF-Ray", "fixed-fixture-id")
            .with_header("Set-Cookie", "laravel_session=secret; HttpOnly")
            .with_header("Set-Cookie", "XSRF-TOKEN=secret"),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    seed_laravel_planning_evidence(&runtime);
    let report = runtime.analyze().await.unwrap();
    assert_eq!(
        report.defense().mode(),
        WebAssessmentDefenseMode::ObservationOnly
    );
    assert!(!report.defense().observations().is_empty());
    assert!(report
        .defense()
        .observations()
        .iter()
        .all(|observation| observation.subject().as_str().starts_with("endpoint:")));
    assert!(report
        .defense()
        .shadow_plans()
        .iter()
        .all(|shadow| shadow.policy_authorized().subject() == shadow.shadow().subject()));
    assert!(report
        .defense()
        .shadow_plans()
        .iter()
        .any(|shadow| !shadow.delta().is_empty()));
    let actual_plans = actual_assessment_plans(&report);
    assert_eq!(actual_plans.len(), report.defense().shadow_plans().len());
    for (actual, shadow) in actual_plans
        .into_iter()
        .zip(report.defense().shadow_plans())
    {
        assert_eq!(actual, shadow.policy_authorized());
        let baseline_ids: Vec<_> = shadow
            .policy_authorized()
            .steps()
            .iter()
            .map(|step| step.action_id())
            .collect();
        assert!(shadow
            .shadow()
            .steps()
            .iter()
            .all(|step| baseline_ids.contains(&step.action_id())));
    }
    assert!(server.hit_count("/root").await >= 2);

    let bootstrap = report.subjects()[0].bootstrap().unwrap();
    let without_projection: Vec<_> = bootstrap
        .evidence()
        .iter()
        .filter(|evidence| evidence.predicate().namespace() != ASSESSMENT_DEFENSE_NAMESPACE)
        .cloned()
        .collect();
    let (knowledge, local_receipt) = receipt_with_committed_batch(bootstrap, without_projection);
    let mut replay = CommittedAssessmentDefenseLedger::default();
    assert!(replay
        .ingest_receipt(&local_receipt, &knowledge, false)
        .is_ok());
    let before = replay.clone();
    assert!(replay
        .ingest_receipt(&local_receipt, &knowledge, true)
        .is_err());
    assert_eq!(replay, before);
}

#[tokio::test]
async fn enforced_defense_plan_exactly_matches_public_shadow_and_suppresses() {
    let server = serve(|_| {
        FixtureReply::Response(
            FixtureResponse::new(
                "403 Forbidden",
                Some("text/html"),
                "<html><body>blocked</body></html>",
            )
            .with_header("CF-Ray", "fixed-fixture-id")
            .with_header("Set-Cookie", "laravel_session=secret; HttpOnly")
            .with_header("Set-Cookie", "XSRF-TOKEN=secret"),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .enable_defense_enforcement()
        .build()
        .unwrap();
    seed_laravel_planning_evidence(&runtime);
    let report = runtime.analyze().await.unwrap();

    assert_eq!(report.defense().mode(), WebAssessmentDefenseMode::Enforced);
    let actual_plans = actual_assessment_plans(&report);
    assert!(!actual_plans.is_empty());
    assert_eq!(actual_plans.len(), report.defense().shadow_plans().len());
    for (actual, shadow) in actual_plans
        .into_iter()
        .zip(report.defense().shadow_plans())
    {
        assert_eq!(actual, shadow.shadow());
    }
    assert!(report
        .defense()
        .shadow_plans()
        .iter()
        .any(|shadow| !shadow.delta().suppressed().is_empty()));
    assert!(server.hit_count("/root").await >= 2);
}

#[tokio::test]
async fn public_defense_coverage_withholds_open_and_weak_hint_never_suppresses() {
    let mut root_body =
        b"<html><head><link href='/asset' rel='stylesheet'></head><body><a href='/weak'>weak</a>"
            .to_vec();
    root_body.resize(MAX_FINGERPRINT_BODY_SCAN_BYTES + 1, b'x');
    root_body.extend_from_slice(b"</body></html>");
    let server = serve(move |request| {
        let response = match request.path() {
            "/root" => FixtureResponse::html(root_body.clone()),
            "/weak" => FixtureResponse::html("<html><body>ok</body></html>")
                .with_header("X-Amzn-RequestId", "fixed-weak-hint")
                .with_header("Set-Cookie", "laravel_session=secret; HttpOnly")
                .with_header("Set-Cookie", "XSRF-TOKEN=secret"),
            _ => FixtureResponse::new("200 OK", Some("text/css"), "body{}"),
        };
        FixtureReply::Response(response)
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .enable_defense_enforcement()
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();

    let capped = defense_observation_for_path(&report, "/root");
    assert_eq!(
        capped.body_coverage(),
        WebAssessmentDefenseBodyCoverage::CompleteUtf8Prefix
    );
    assert!(capped.input_limit_reached());
    assert_eq!(capped.posture(), None);
    assert!(!capped.challenge_observed());
    assert!(!capped.rate_limit_observed());
    assert!(capped.fingerprint_hint().is_none());

    let metadata_only = defense_observation_for_path(&report, "/asset");
    assert_eq!(
        metadata_only.body_coverage(),
        WebAssessmentDefenseBodyCoverage::MetadataOnly
    );
    assert_eq!(metadata_only.posture(), None);
    assert!(!metadata_only.challenge_observed());
    assert!(!metadata_only.rate_limit_observed());
    assert!(metadata_only.fingerprint_hint().is_none());

    let weak = defense_observation_for_path(&report, "/weak");
    assert_eq!(
        weak.fingerprint_hint(),
        Some((DefenseProduct::AwsWaf, FingerprintConfidence::Weak))
    );
    assert_eq!(weak.posture(), Some(DefensePosture::Suspected));
    let weak_subject = weak.subject().clone();
    let weak_shadows: Vec<_> = report
        .defense()
        .shadow_plans()
        .iter()
        .filter(|shadow| shadow.policy_authorized().subject() == &weak_subject)
        .collect();
    assert!(!weak_shadows.is_empty());
    assert!(weak_shadows
        .iter()
        .all(|shadow| shadow.delta().suppressed().is_empty()));
    let requests = server.requests().await;
    assert!(requests
        .iter()
        .any(|request| request.path() == "/asset" && request.method == "HEAD"));
}

#[tokio::test]
async fn defense_ledger_is_idempotent_and_rejects_tampering_atomically() {
    let server =
        serve(|_| FixtureReply::Response(FixtureResponse::html("<html><body>ok</body></html>")))
            .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let bootstrap = report.subjects()[0].bootstrap().unwrap();

    let mut ledger = CommittedAssessmentDefenseLedger::default();
    assert!(ledger
        .ingest_receipt(bootstrap, runtime.knowledge(), true)
        .unwrap()
        .is_some());
    let committed = ledger.clone();
    assert!(ledger
        .ingest_receipt(bootstrap, runtime.knowledge(), true)
        .unwrap()
        .is_none());
    assert_eq!(ledger, committed);

    let mut reordered = bootstrap.evidence().to_vec();
    let method_index = reordered
        .iter()
        .position(|evidence| {
            evidence.predicate() == &HttpEvidencePredicate::REQUEST_METHOD.into_knowledge()
        })
        .unwrap();
    let url_index = reordered
        .iter()
        .position(|evidence| {
            evidence.predicate() == &HttpEvidencePredicate::REQUEST_URL.into_knowledge()
        })
        .unwrap();
    reordered.swap(method_index, url_index);
    let (reordered_knowledge, reordered_receipt) =
        receipt_with_committed_batch(bootstrap, reordered);
    let mut rejected = CommittedAssessmentDefenseLedger::default();
    let before = rejected.clone();
    assert!(rejected
        .ingest_receipt(&reordered_receipt, &reordered_knowledge, true)
        .is_err());
    assert_eq!(rejected, before);

    let mut defense_reordered = bootstrap.evidence().to_vec();
    let first_defense = defense_reordered
        .iter()
        .position(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE)
        .unwrap();
    defense_reordered.swap(first_defense, first_defense + 1);
    let (defense_reordered_knowledge, defense_reordered_receipt) =
        receipt_with_committed_batch(bootstrap, defense_reordered);
    assert!(rejected
        .ingest_receipt(
            &defense_reordered_receipt,
            &defense_reordered_knowledge,
            true,
        )
        .is_err());
    assert_eq!(rejected, before);

    let mut direct_defense = bootstrap.evidence().to_vec();
    let original_defense = direct_defense[first_defense].clone();
    direct_defense[first_defense] = rebuild_evidence(
        &original_defense,
        original_defense.kind().clone(),
        original_defense.value().clone(),
        original_defense.source().clone(),
        EvidenceOrigin::Direct,
    );
    let (direct_defense_knowledge, direct_defense_receipt) =
        receipt_with_committed_batch(bootstrap, direct_defense);
    assert!(rejected
        .ingest_receipt(&direct_defense_receipt, &direct_defense_knowledge, true)
        .is_err());
    assert_eq!(rejected, before);

    let mut updated_writes = bootstrap.writes().to_vec();
    updated_writes[0] = KnowledgeWrite::Updated;
    let updated_receipt = bootstrap.with_test_committed_batch(
        bootstrap.evidence().to_vec(),
        updated_writes,
        bootstrap.after_execution().clone(),
    );
    assert!(rejected
        .ingest_receipt(&updated_receipt, runtime.knowledge(), true)
        .is_err());
    assert_eq!(rejected, before);

    assert!(rejected
        .ingest_receipt(bootstrap, &KnowledgeBase::new(), true)
        .is_err());
    assert_eq!(rejected, before);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    fn host(&self) -> &str {
        self.headers.get("host").map(String::as_str).unwrap_or("")
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

#[derive(Clone)]
struct FixtureResponse {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl FixtureResponse {
    fn html(body: impl Into<Vec<u8>>) -> Self {
        Self::new("200 OK", Some("text/html"), body)
    }

    fn new(status: &'static str, media_type: Option<&str>, body: impl Into<Vec<u8>>) -> Self {
        let mut headers = Vec::new();
        if let Some(media_type) = media_type {
            headers.push(("Content-Type".to_owned(), media_type.to_owned()));
        }
        Self {
            status,
            headers,
            body: body.into(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn encode(&self, method: &str) -> Vec<u8> {
        let mut encoded = format!("HTTP/1.1 {}\r\n", self.status).into_bytes();
        for (name, value) in &self.headers {
            encoded.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        encoded.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                self.body.len()
            )
            .as_bytes(),
        );
        if method != "HEAD" {
            encoded.extend_from_slice(&self.body);
        }
        encoded
    }
}

#[derive(Clone)]
enum FixtureReply {
    Response(FixtureResponse),
    CloseWithoutResponse,
    Stall,
}

struct LocalServer {
    origin: Url,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    request_seen: Arc<Notify>,
    task: JoinHandle<()>,
}

impl LocalServer {
    fn url(&self, path: &str) -> Url {
        self.origin.join(path).expect("fixture path must be valid")
    }

    async fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().await.clone()
    }

    async fn hit_count(&self, path: &str) -> usize {
        self.requests()
            .await
            .iter()
            .filter(|request| request.path() == path)
            .count()
    }

    fn request_notification(&self) -> Arc<Notify> {
        self.request_seen.clone()
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    handler: impl Fn(&RecordedRequest) -> FixtureReply + Send + Sync + 'static,
) -> LocalServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback fixture must bind");
    let address = listener.local_addr().expect("fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let request_seen = Arc::new(Notify::new());
    let notify = request_seen.clone();
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut bytes = Vec::new();
            let mut invalid = false;
            loop {
                let mut chunk = [0_u8; 1_024];
                let Ok(read) = stream.read(&mut chunk).await else {
                    invalid = true;
                    break;
                };
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() > MAX_FIXTURE_REQUEST_BYTES {
                    invalid = true;
                    break;
                }
                match complete_request_len(&bytes) {
                    Ok(Some(expected)) if bytes.len() >= expected => {
                        bytes.truncate(expected);
                        break;
                    },
                    Ok(_) => {},
                    Err(()) => {
                        invalid = true;
                        break;
                    },
                }
            }
            if invalid {
                let _ = stream.shutdown().await;
                continue;
            }
            let Some(request) = parse_request(&bytes) else {
                let _ = stream.shutdown().await;
                continue;
            };
            recorded.lock().await.push(request.clone());
            notify.notify_one();
            match handler(&request) {
                FixtureReply::Response(response) => {
                    let _ = stream.write_all(&response.encode(&request.method)).await;
                    let _ = stream.shutdown().await;
                },
                FixtureReply::CloseWithoutResponse => {
                    let _ = stream.shutdown().await;
                },
                FixtureReply::Stall => pending::<()>().await,
            }
        }
    });
    LocalServer {
        origin: Url::parse(&format!("http://{address}/")).expect("fixture URL"),
        requests,
        request_seen,
        task,
    }
}

const MAX_FIXTURE_REQUEST_BYTES: usize = 64 * 1_024;

fn complete_request_len(bytes: &[u8]) -> Result<Option<usize>, ()> {
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|_| ())?;
    let mut content_length = None;
    for line in headers.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(());
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(());
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| ())?);
        }
    }
    let expected = header_end
        .checked_add(4)
        .and_then(|value| value.checked_add(content_length.unwrap_or(0)))
        .ok_or(())?;
    if expected > MAX_FIXTURE_REQUEST_BYTES {
        return Err(());
    }
    Ok(Some(expected))
}

fn parse_request(bytes: &[u8]) -> Option<RecordedRequest> {
    let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let request = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = request.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if headers
            .insert(name.trim().to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return None;
        }
    }
    let body_bytes = headers
        .get("content-length")
        .map_or(Some(0), |value| value.parse::<usize>().ok())?;
    let body_start = header_end.checked_add(4)?;
    let body_end = body_start.checked_add(body_bytes)?;
    let body = bytes.get(body_start..body_end)?.to_vec();
    Some(RecordedRequest {
        method,
        target,
        headers,
        body,
    })
}

#[derive(Clone, Copy)]
struct TestObservationEnvelope<'a> {
    case_id: &'a str,
    action_id: &'a str,
    hypothesis_id: &'a str,
    has_payload_strategy: bool,
    applies_hypothesis_transition: bool,
    stage: DecisionExecutionStage,
    subject: &'a EntityId,
    method: HttpProbeMethod,
    requested_url: &'a Url,
}

impl<'a> TestObservationEnvelope<'a> {
    fn exact(subject: &'a EntityId, requested_url: &'a Url, method: HttpProbeMethod) -> Self {
        Self {
            case_id: BOOTSTRAP_CASE_ID,
            action_id: BOOTSTRAP_ACTION_ID,
            hypothesis_id: BOOTSTRAP_HYPOTHESIS_ID,
            has_payload_strategy: false,
            applies_hypothesis_transition: true,
            stage: DecisionExecutionStage::Passive,
            subject,
            method,
            requested_url,
        }
    }
}

struct TestObservationParents {
    request_method: EvidenceId,
    request_url: EvidenceId,
    response_status: EvidenceId,
    response_final_url: EvidenceId,
    response_media_type: EvidenceId,
    response_body_truncated: EvidenceId,
    response_body_digest: EvidenceId,
}

impl TestObservationParents {
    fn new() -> Self {
        Self {
            request_method: EvidenceId::new(),
            request_url: EvidenceId::new(),
            response_status: EvidenceId::new(),
            response_final_url: EvidenceId::new(),
            response_media_type: EvidenceId::new(),
            response_body_truncated: EvidenceId::new(),
            response_body_digest: EvidenceId::new(),
        }
    }

    fn refs(&self, include_media: bool) -> TestObservationParentRefs<'_> {
        TestObservationParentRefs {
            request_method: Some(&self.request_method),
            request_url: Some(&self.request_url),
            response_status: Some(&self.response_status),
            response_final_url: Some(&self.response_final_url),
            response_media_type: include_media.then_some(&self.response_media_type),
            response_body_truncated: Some(&self.response_body_truncated),
            response_body_digest: Some(&self.response_body_digest),
        }
    }

    fn expected(&self, include_media: bool) -> Vec<EvidenceId> {
        let mut expected = vec![
            self.request_method.clone(),
            self.request_url.clone(),
            self.response_status.clone(),
            self.response_body_truncated.clone(),
            self.response_body_digest.clone(),
        ];
        if include_media {
            expected.push(self.response_media_type.clone());
        }
        expected.sort();
        expected
    }
}

#[derive(Clone, Copy)]
struct TestObservationParentRefs<'a> {
    request_method: Option<&'a EvidenceId>,
    request_url: Option<&'a EvidenceId>,
    response_status: Option<&'a EvidenceId>,
    response_final_url: Option<&'a EvidenceId>,
    response_media_type: Option<&'a EvidenceId>,
    response_body_truncated: Option<&'a EvidenceId>,
    response_body_digest: Option<&'a EvidenceId>,
}

fn observe_for_test(
    observer: &AssessmentDiscoveryObserver,
    envelope: TestObservationEnvelope<'_>,
    status: u16,
    media_type: Option<&str>,
    complete_body: Option<&[u8]>,
    parents: TestObservationParentRefs<'_>,
) -> Result<Vec<Evidence>, HttpEvidenceError> {
    let passive = passive_response_projection_for_test(&[]);
    Ok(observe_full_for_test(
        observer,
        envelope,
        status,
        media_type,
        complete_body,
        parents,
        &passive,
    )?
    .into_iter()
    .filter(|item| item.predicate().namespace() == "web.discovery")
    .collect())
}

fn observe_full_for_test(
    observer: &AssessmentDiscoveryObserver,
    envelope: TestObservationEnvelope<'_>,
    status: u16,
    media_type: Option<&str>,
    complete_body: Option<&[u8]>,
    parents: TestObservationParentRefs<'_>,
    passive_response_projection: &crate::http_evidence::passive_review::PassiveResponseProjection,
) -> Result<Vec<Evidence>, HttpEvidenceError> {
    observer.observe(complete_http_response_observation_for_test(
        CompleteHttpResponseObservationTestInput {
            case_id: envelope.case_id,
            action_id: envelope.action_id,
            executor_id: HTTP_EVIDENCE_EXECUTOR_ID,
            hypothesis_id: envelope.hypothesis_id,
            has_payload_strategy: envelope.has_payload_strategy,
            payload_strategy: None,
            applies_hypothesis_transition: envelope.applies_hypothesis_transition,
            stage: envelope.stage,
            subject: envelope.subject,
            method: envelope.method,
            requested_url: envelope.requested_url,
            status,
            media_type,
            reliability: ConfidenceScore::from_percent(100).unwrap(),
            complete_body,
            request_method_evidence_id: parents.request_method,
            request_url_evidence_id: parents.request_url,
            response_status_evidence_id: parents.response_status,
            response_final_url_evidence_id: parents.response_final_url,
            response_media_type_evidence_id: parents.response_media_type,
            response_body_truncated_evidence_id: parents.response_body_truncated,
            response_body_digest_evidence_id: parents.response_body_digest,
            passive_response_projection,
            review_response_projection: None,
        },
    ))
}

fn observer_fixture(
    url: Url,
    method: WebAssessmentMethod,
    cancellation: CancellationToken,
    deadline: Option<tokio::time::Instant>,
) -> (AssessmentDiscoveryObserver, WebAssessmentSubject, EntityId) {
    let limits = WebAssessmentLimits::default();
    let subject = WebAssessmentSubject {
        url: url.clone(),
        method,
        depth: 0,
        origin: WebAssessmentSubjectOrigin::AuthorizedRoot,
        query_parameter_names: Vec::new(),
        evidence_ids: Vec::new(),
    };
    let mut envelope = AssessmentLedger::new(&subject).snapshot(limits, subject.depth);
    envelope
        .subjects
        .get_mut(url.as_str())
        .expect("observer subject admission")
        .executed = true;
    let policy = HttpEvidencePolicy::for_origin(url.clone()).unwrap();
    let observer = AssessmentDiscoveryObserver::new(
        policy,
        limits,
        envelope,
        &subject,
        cancellation,
        deadline,
    );
    let entity = EntityId::new(format!("endpoint:{url}")).unwrap();
    (observer, subject, entity)
}

fn derivation_parents(evidence: &Evidence) -> &[EvidenceId] {
    evidence
        .origin()
        .derivation()
        .expect("discovery evidence must be derived")
        .parents()
}

fn rebuild_evidence(
    original: &Evidence,
    kind: EvidenceKind,
    value: EvidenceValue,
    source: EvidenceSource,
    origin: EvidenceOrigin,
) -> Evidence {
    let rebuilt = Evidence::with_id_at(
        original.id().clone(),
        original.subject().clone(),
        kind,
        original.predicate().clone(),
        value,
        source,
        original.reliability(),
        original.observed_at_ms(),
    );
    match origin {
        EvidenceOrigin::Derived(derivation) => rebuilt.derived_from(derivation),
        EvidenceOrigin::Direct => rebuilt,
        _ => unreachable!("test only handles known evidence origins"),
    }
}

fn fresh_evidence(original: &Evidence) -> Evidence {
    let rebuilt = Evidence::new(
        original.subject().clone(),
        original.kind().clone(),
        original.predicate().clone(),
        original.value().clone(),
        original.source().clone(),
        original.reliability(),
    );
    match original.origin() {
        EvidenceOrigin::Derived(derivation) => rebuilt.derived_from(derivation.clone()),
        EvidenceOrigin::Direct => rebuilt,
        _ => unreachable!("test only handles known evidence origins"),
    }
}

fn source_with_method(original: &Evidence, method: &str) -> EvidenceSource {
    let source = EvidenceSource::new(original.source().component(), method).unwrap();
    match original.source().correlation_id() {
        Some(correlation_id) => source.with_correlation_id(correlation_id).unwrap(),
        None => source,
    }
}

fn receipt_with_committed_batch(
    template: &DecisionEvidenceReceipt,
    evidence: Vec<Evidence>,
) -> (KnowledgeBase, DecisionEvidenceReceipt) {
    let knowledge = KnowledgeBase::new();
    let writes = knowledge
        .insert_evidence_batch(evidence.clone())
        .expect("mutated test batch must be structurally committable");
    let after_execution = knowledge.snapshot_for_subject(template.case().subject());
    let receipt = template.with_test_committed_batch(evidence, writes, after_execution);
    (knowledge, receipt)
}

fn assert_passive_replay_rejected_atomically(
    template: &DecisionEvidenceReceipt,
    evidence: Vec<Evidence>,
    expected_subject: &WebAssessmentSubject,
) {
    let (knowledge, receipt) = receipt_with_committed_batch(template, evidence);
    let mut ledger = CommittedAssessmentPassiveLedger::default();
    assert!(ledger
        .ingest_receipt(&receipt, &knowledge, expected_subject)
        .is_err());
    assert!(ledger.observations().is_empty());
    assert_eq!(ledger.receipt_count(), 0);
}

fn subject_path(report: &WebAssessmentSubjectReport) -> &str {
    report.subject().url().path()
}

fn actual_assessment_plans(report: &WebAssessmentRunReport) -> Vec<&AttackPlan> {
    report
        .subjects()
        .iter()
        .flat_map(WebAssessmentSubjectReport::turns)
        .filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Planning(planning) => Some(planning.plan()),
            StandardWebDecisionRuntimeTurn::Outcome { .. } => None,
        })
        .collect()
}

fn defense_observation_for_path<'a>(
    report: &'a WebAssessmentRunReport,
    path: &str,
) -> &'a WebAssessmentDefenseObservation {
    report
        .defense()
        .observations()
        .iter()
        .find(|observation| observation.subject().as_str().contains(path))
        .unwrap_or_else(|| panic!("missing defense observation for {path}"))
}

fn passive_observation_for_path<'a>(
    runtime: &'a WebAssessmentRuntime,
    path: &str,
) -> &'a CommittedAssessmentPassiveObservation {
    runtime
        .passive_ledger
        .observations()
        .iter()
        .find(|observation| observation.subject().as_str().contains(path))
        .unwrap_or_else(|| panic!("missing passive observation for {path}"))
}

fn seed_laravel_planning_evidence(runtime: &WebAssessmentRuntime) {
    runtime
        .knowledge()
        .insert_evidence(Evidence::new(
            EntityId::new(format!("endpoint:{}", runtime.authorized_root().url())).unwrap(),
            EvidenceKind::Http,
            HttpEvidencePredicate::response_header("x-powered-by").unwrap(),
            EvidenceValue::Text("Laravel".to_owned()),
            EvidenceSource::new("web-assessment-test", "host-seeded-planning-evidence").unwrap(),
            ConfidenceScore::from_percent(100).unwrap(),
        ))
        .unwrap();
}

fn public_subject_shape(
    report: &WebAssessmentSubjectReport,
) -> (String, WebAssessmentMethod, u16, Vec<String>) {
    (
        report.subject().url().path().to_owned(),
        report.subject().method(),
        report.subject().depth(),
        report.subject().query_parameter_names().to_vec(),
    )
}

fn assert_transport_reconciles(usage: WebAssessmentUsage, audit: &TransportDispatchAudit) {
    let audited = u64::try_from(audit.receipts().len())
        .unwrap_or(u64::MAX)
        .saturating_add(audit.omitted_receipt_count());
    assert_eq!(audited, u64::from(usage.total_requests()));
    for (sequence, receipt) in audit.receipts().iter().enumerate() {
        assert_eq!(receipt.sequence(), u64::try_from(sequence).unwrap());
    }
}

fn assert_report_reconciles(report: &WebAssessmentRunReport) {
    let usage = report.usage();
    assert_eq!(usage.retained_subjects(), report.subjects().len());
    assert_eq!(
        usage.executed_subjects(),
        report
            .subjects()
            .iter()
            .filter(|subject| subject.was_executed())
            .count()
    );
    assert_eq!(usage.retained_forms(), report.forms().len());
    assert_eq!(
        usage.request_body_bytes(),
        report
            .transport()
            .receipts()
            .iter()
            .map(|receipt| receipt.request_body_bytes())
            .sum::<u64>()
    );
    assert_transport_reconciles(usage, report.transport());

    let unique_urls: BTreeSet<_> = report
        .subjects()
        .iter()
        .map(|subject| subject.subject().url().to_string())
        .chain(report.forms().iter().map(|form| form.action().to_string()))
        .collect();
    assert_eq!(
        usage.retained_unique_url_bytes(),
        unique_urls.iter().map(String::len).sum::<usize>()
    );
    assert!(report.subjects().windows(2).all(|pair| {
        let left = pair[0].subject();
        let right = pair[1].subject();
        (left.depth(), left.url().as_str()) <= (right.depth(), right.url().as_str())
    }));
    assert!(report.forms().windows(2).all(|pair| {
        (pair[0].action().as_str(), pair[0].method())
            <= (pair[1].action().as_str(), pair[1].method())
    }));

    match report.completion() {
        WebAssessmentCompletion::Complete => {
            assert!(report.completion().reasons().is_empty());
            assert!(report
                .subjects()
                .iter()
                .all(|subject| subject.was_executed()));
        },
        WebAssessmentCompletion::Incomplete { reasons } => {
            assert!(!reasons.is_empty());
        },
    }

    for subject in report.subjects() {
        let Some(bootstrap) = subject.bootstrap() else {
            continue;
        };
        let expected = format!("endpoint:{}", subject.subject().url());
        assert_eq!(bootstrap.case().subject().as_str(), expected);
        assert!(
            bootstrap
                .evidence()
                .iter()
                .all(|evidence| evidence.subject().as_str() == expected),
            "bootstrap evidence crossed subject boundary for {expected}"
        );
    }

    let debug = format!("{:?}", report.subjects());
    assert!(!debug.contains("TransportDispatchAudit"));
    assert!(!debug.contains("RuntimeUsage"));
}

fn assert_product_identity_boundary_is_explicit(report: &WebAssessmentRunReport) {
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable));
    assert!(report.unprojected_assessment_subjects() > 0);
    assert!(report.unprojected_assessment_conditions() > 0);
    assert!(report
        .assessment_items()
        .iter()
        .all(|item| item.disposition().as_str() == "informational"));
}

fn assert_failure_reconciles(receipt: &WebAssessmentFailureReceipt) {
    assert!(receipt.inventory_consistent());
    assert_eq!(receipt.unrepresented_ledger_subjects(), 0);
    assert!(!receipt.incomplete_reasons().is_empty());
    let usage = receipt.usage();
    let retained = receipt
        .completed_subjects()
        .len()
        .saturating_add(1)
        .saturating_add(receipt.pending_subjects().len());
    assert_eq!(usage.retained_subjects(), retained);
    let executed = receipt
        .completed_subjects()
        .iter()
        .filter(|subject| subject.was_executed())
        .count()
        .saturating_add(usize::from(receipt.current_subject_report().was_executed()));
    assert_eq!(usage.executed_subjects(), executed);
    assert_eq!(usage.retained_forms(), receipt.forms().len());
    assert_eq!(usage.request_body_bytes(), 0);
    assert_transport_reconciles(usage, receipt.transport());

    let completed: BTreeSet<_> = receipt
        .completed_subjects()
        .iter()
        .map(|subject| subject.subject().url().to_string())
        .collect();
    let pending: BTreeSet<_> = receipt
        .pending_subjects()
        .iter()
        .map(|subject| subject.url().to_string())
        .collect();
    let current = receipt.current_subject().url().to_string();
    assert_eq!(completed.len(), receipt.completed_subjects().len());
    assert_eq!(pending.len(), receipt.pending_subjects().len());
    assert!(!completed.contains(&current));
    assert!(!pending.contains(&current));
    assert!(completed.is_disjoint(&pending));
    assert!(receipt.pending_subjects().windows(2).all(|pair| {
        (pair[0].depth(), pair[0].url().as_str()) <= (pair[1].depth(), pair[1].url().as_str())
    }));

    let unique_urls: BTreeSet<_> = completed
        .into_iter()
        .chain(std::iter::once(current))
        .chain(pending)
        .chain(receipt.forms().iter().map(|form| form.action().to_string()))
        .collect();
    assert_eq!(
        usage.retained_unique_url_bytes(),
        unique_urls.iter().map(String::len).sum::<usize>()
    );
    let debug = format!(
        "{:?}{:?}",
        receipt.completed_subjects(),
        receipt.current_subject_report()
    );
    assert!(!debug.contains("TransportDispatchAudit"));
    assert!(!debug.contains("RuntimeUsage"));
}

fn assert_no_secret(haystack: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !haystack.contains(secret),
            "secret sentinel {secret:?} escaped into: {haystack}"
        );
    }
}

fn knowledge_debug(runtime: &WebAssessmentRuntime, report: &WebAssessmentRunReport) -> String {
    report
        .subjects()
        .iter()
        .map(|subject| {
            let id = EntityId::new(format!("endpoint:{}", subject.subject().url()))
                .expect("canonical endpoint identity");
            format!("{:?}", runtime.knowledge().snapshot_for_subject(&id))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn limits_defaults_and_compiled_ceilings_are_coherent() {
    let defaults = WebAssessmentLimits::default();
    assert_eq!(defaults.max_subjects(), DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS);
    assert_eq!(
        defaults.max_discovery_depth(),
        DEFAULT_WEB_ASSESSMENT_MAX_DEPTH
    );
    assert_eq!(
        defaults.max_references_per_document(),
        DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT
    );
    assert_eq!(
        defaults.max_canonical_url_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES
    );
    assert_eq!(
        defaults.max_retained_url_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES
    );
    assert_eq!(defaults.max_forms(), DEFAULT_WEB_ASSESSMENT_MAX_FORMS);
    assert_eq!(
        defaults.max_controls_per_form(),
        DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM
    );
    assert_eq!(
        defaults.max_query_parameter_names(),
        DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES
    );
    assert_eq!(
        defaults.max_total_requests(),
        DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS
    );
    assert_eq!(
        defaults.max_response_body_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES
    );
    assert_eq!(
        defaults.max_total_response_bytes(),
        DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES
    );
    assert_eq!(
        defaults.max_wall_time(),
        DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME
    );
    assert_eq!(
        defaults.max_active_verifications(),
        DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS
    );
    assert_eq!(defaults.concurrency(), WEB_ASSESSMENT_CONCURRENCY);
    assert_eq!(WEB_ASSESSMENT_CONCURRENCY, 1);

    const {
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS <= HARD_MAX_WEB_ASSESSMENT_SUBJECTS);
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_DEPTH <= HARD_MAX_WEB_ASSESSMENT_DEPTH);
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT
                <= HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES
        );
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_FORMS <= HARD_MAX_WEB_ASSESSMENT_FORMS);
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM
                <= HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM
        );
        assert!(DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES <= HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES);
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS <= HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES
                <= HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME.as_secs()
                <= HARD_MAX_WEB_ASSESSMENT_WALL_TIME.as_secs()
        );
        assert!(
            DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS
                <= HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS
        );
    }

    assert!(matches!(
        defaults.with_max_subjects(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_subjects"
        })
    ));
    assert!(matches!(
        defaults.with_max_canonical_url_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_canonical_url_bytes"
        })
    ));
    assert!(matches!(
        defaults.with_max_retained_url_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_retained_url_bytes"
        })
    ));
    assert!(matches!(
        defaults.with_max_response_body_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_response_body_bytes"
        })
    ));
    assert!(matches!(
        defaults.with_max_total_response_bytes(0),
        Err(WebAssessmentLimitsError::ZeroRequired {
            dimension: "max_total_response_bytes"
        })
    ));

    macro_rules! assert_above {
        ($result:expr, $dimension:literal, $maximum:expr) => {
            assert!(matches!(
                $result,
                Err(WebAssessmentLimitsError::AboveHardMaximum {
                    dimension: $dimension,
                    maximum,
                    ..
                }) if maximum == u64::try_from($maximum).unwrap()
            ));
        };
    }
    assert_above!(
        defaults.with_max_subjects(HARD_MAX_WEB_ASSESSMENT_SUBJECTS + 1),
        "max_subjects",
        HARD_MAX_WEB_ASSESSMENT_SUBJECTS
    );
    assert_above!(
        defaults.with_max_discovery_depth(HARD_MAX_WEB_ASSESSMENT_DEPTH + 1),
        "max_discovery_depth",
        HARD_MAX_WEB_ASSESSMENT_DEPTH
    );
    assert_above!(
        defaults
            .with_max_references_per_document(HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT + 1),
        "max_references_per_document",
        HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT
    );
    assert_above!(
        defaults.with_max_canonical_url_bytes(HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES + 1),
        "max_canonical_url_bytes",
        HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES
    );
    assert_above!(
        defaults.with_max_retained_url_bytes(HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES + 1),
        "max_retained_url_bytes",
        HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES
    );
    assert_above!(
        defaults.with_max_forms(HARD_MAX_WEB_ASSESSMENT_FORMS + 1),
        "max_forms",
        HARD_MAX_WEB_ASSESSMENT_FORMS
    );
    assert_above!(
        defaults.with_max_controls_per_form(HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM + 1),
        "max_controls_per_form",
        HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM
    );
    assert_above!(
        defaults.with_max_query_parameter_names(HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES + 1),
        "max_query_parameter_names",
        HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES
    );
    assert_above!(
        defaults.with_max_total_requests(HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS + 1),
        "max_total_requests",
        HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS
    );
    assert_above!(
        defaults.with_max_response_body_bytes(HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES + 1),
        "max_response_body_bytes",
        HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES
    );
    assert_above!(
        defaults.with_max_total_response_bytes(HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES + 1),
        "max_total_response_bytes",
        HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES
    );
    assert_above!(
        defaults.with_max_active_verifications(HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS + 1),
        "max_active_verifications",
        HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS
    );
    assert!(matches!(
        defaults.with_max_wall_time(HARD_MAX_WEB_ASSESSMENT_WALL_TIME + Duration::from_millis(1)),
        Err(WebAssessmentLimitsError::AboveHardMaximum {
            dimension: "max_wall_time_ms",
            ..
        })
    ));

    let zero_capable = defaults
        .with_max_discovery_depth(0)
        .unwrap()
        .with_max_references_per_document(0)
        .unwrap()
        .with_max_forms(0)
        .unwrap()
        .with_max_controls_per_form(0)
        .unwrap()
        .with_max_query_parameter_names(0)
        .unwrap()
        .with_max_total_requests(0)
        .unwrap()
        .with_max_wall_time(Duration::ZERO)
        .unwrap()
        .with_max_active_verifications(0)
        .unwrap();
    assert_eq!(zero_capable.max_discovery_depth(), 0);
    assert_eq!(zero_capable.max_total_requests(), 0);
    assert_eq!(zero_capable.max_wall_time(), Duration::ZERO);

    let budget = defaults.runtime_budget(0);
    assert_eq!(
        budget.max_request_body_bytes(),
        DEFAULT_MAX_REQUEST_BODY_BYTES
    );
    assert_eq!(
        budget.max_same_action_attempts(),
        DEFAULT_MAX_SAME_ACTION_ATTEMPTS
    );
    assert_eq!(
        budget.max_consecutive_no_progress_turns(),
        DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS
    );
}

#[test]
fn sealed_observer_requires_the_exact_bootstrap_envelope_and_head_never_discovers() {
    let url = Url::parse("http://127.0.0.1:7777/root").unwrap();
    let (observer, _, entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Get,
        CancellationToken::new(),
        None,
    );
    let parents = TestObservationParents::new();
    let exact = TestObservationEnvelope::exact(&entity, &url, HttpProbeMethod::Get);
    let other_entity = EntityId::new("endpoint:http://127.0.0.1:7777/other").unwrap();
    let other_url = Url::parse("http://127.0.0.1:7777/other").unwrap();
    let query_url = Url::parse("http://127.0.0.1:7777/root?secret=value").unwrap();
    let fragment_url = Url::parse("http://127.0.0.1:7777/root#fragment").unwrap();
    let cross_origin_url = Url::parse("http://127.0.0.1:7778/root").unwrap();

    let mut wrong_envelopes = Vec::new();
    let mut wrong = exact;
    wrong.case_id = "case:wrong";
    wrong_envelopes.push(("case", wrong));
    let mut wrong = exact;
    wrong.action_id = "web.action.wrong";
    wrong_envelopes.push(("action", wrong));
    let mut wrong = exact;
    wrong.hypothesis_id = "hypothesis:wrong";
    wrong_envelopes.push(("hypothesis", wrong));
    let mut wrong = exact;
    wrong.has_payload_strategy = true;
    wrong_envelopes.push(("payload", wrong));
    let mut wrong = exact;
    wrong.applies_hypothesis_transition = false;
    wrong_envelopes.push(("transition", wrong));
    let mut wrong = exact;
    wrong.stage = DecisionExecutionStage::Active;
    wrong_envelopes.push(("stage", wrong));
    let mut wrong = exact;
    wrong.subject = &other_entity;
    wrong_envelopes.push(("subject", wrong));
    let mut wrong = exact;
    wrong.method = HttpProbeMethod::Head;
    wrong_envelopes.push(("method", wrong));
    let mut wrong = exact;
    wrong.requested_url = &other_url;
    wrong_envelopes.push(("request-url", wrong));
    let mut wrong = exact;
    wrong.requested_url = &query_url;
    wrong_envelopes.push(("query", wrong));
    let mut wrong = exact;
    wrong.requested_url = &fragment_url;
    wrong_envelopes.push(("fragment", wrong));
    let mut wrong = exact;
    wrong.requested_url = &cross_origin_url;
    wrong_envelopes.push(("origin", wrong));

    let ledger_shape = (
        observer.envelope.subjects.len(),
        observer.envelope.form_identities.len(),
        observer.envelope.retained_urls.clone(),
        observer.envelope.remaining_subjects,
        observer.envelope.remaining_forms,
        observer.envelope.remaining_url_bytes,
    );
    for (boundary, envelope) in wrong_envelopes {
        let evidence = observe_for_test(
            &observer,
            envelope,
            200,
            Some("text/html"),
            Some(b"<a href='/wrong-envelope-canary'>canary</a>"),
            parents.refs(true),
        )
        .unwrap_or_else(|error| panic!("{boundary} mismatch errored: {error}"));
        assert!(evidence.is_empty(), "{boundary} mismatch emitted evidence");
    }
    assert_eq!(
        (
            observer.envelope.subjects.len(),
            observer.envelope.form_identities.len(),
            observer.envelope.retained_urls.clone(),
            observer.envelope.remaining_subjects,
            observer.envelope.remaining_forms,
            observer.envelope.remaining_url_bytes,
        ),
        ledger_shape
    );

    let evidence = observe_for_test(
        &observer,
        exact,
        200,
        Some("text/html"),
        Some(b"<a href='/admitted'>admitted</a>"),
        parents.refs(true),
    )
    .unwrap();
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].predicate(),
        &WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED.into_knowledge()
    );
    assert_eq!(derivation_parents(&evidence[0]), parents.expected(true));
    assert_eq!(
        evidence[1].predicate(),
        &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge()
    );

    let (head_observer, _, head_entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Head,
        CancellationToken::new(),
        None,
    );
    let head_envelope = TestObservationEnvelope::exact(&head_entity, &url, HttpProbeMethod::Head);
    for body in [None, Some(b"<a href='/head-canary'>canary</a>".as_slice())] {
        assert!(observe_for_test(
            &head_observer,
            head_envelope,
            200,
            Some("text/html"),
            body,
            parents.refs(true),
        )
        .unwrap()
        .is_empty());
    }
}

#[test]
fn no_eof_truth_precedes_stop_state_and_uses_exact_five_or_six_parents() {
    let url = Url::parse("http://127.0.0.1:7777/root").unwrap();
    let parents = TestObservationParents::new();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let (cancelled_observer, _, cancelled_entity) =
        observer_fixture(url.clone(), WebAssessmentMethod::Get, cancelled, None);
    let cancelled_envelope =
        TestObservationEnvelope::exact(&cancelled_entity, &url, HttpProbeMethod::Get);

    for (status, media_type, include_media) in [
        (200, None, false),
        (200, Some("text/plain"), true),
        (206, Some("text/html"), true),
        (500, Some("text/html"), true),
    ] {
        let evidence = observe_for_test(
            &cancelled_observer,
            cancelled_envelope,
            status,
            media_type,
            None,
            parents.refs(include_media),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1, "status={status} media={media_type:?}");
        assert_eq!(
            evidence[0].predicate(),
            &WebDiscoveryEvidencePredicate::DOCUMENT_BODY_INCOMPLETE.into_knowledge()
        );
        assert_eq!(
            derivation_parents(&evidence[0]),
            parents.expected(include_media)
        );
    }
    assert!(observe_for_test(
        &cancelled_observer,
        cancelled_envelope,
        200,
        Some("text/html"),
        Some(b"<a href='/cancelled-complete-canary'>canary</a>"),
        parents.refs(true),
    )
    .unwrap()
    .is_empty());

    let expired_deadline = tokio::time::Instant::now() - Duration::from_millis(1);
    let (deadline_observer, _, deadline_entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Get,
        CancellationToken::new(),
        Some(expired_deadline),
    );
    let deadline_envelope =
        TestObservationEnvelope::exact(&deadline_entity, &url, HttpProbeMethod::Get);
    let deadline_no_eof = observe_for_test(
        &deadline_observer,
        deadline_envelope,
        200,
        None,
        None,
        parents.refs(false),
    )
    .unwrap();
    assert_eq!(deadline_no_eof.len(), 1);
    assert_eq!(
        derivation_parents(&deadline_no_eof[0]),
        parents.expected(false)
    );
    assert!(observe_for_test(
        &deadline_observer,
        deadline_envelope,
        200,
        Some("text/html"),
        Some(b"<a href='/deadline-complete-canary'>canary</a>"),
        parents.refs(true),
    )
    .unwrap()
    .is_empty());

    let (eligible_observer, _, eligible_entity) = observer_fixture(
        url.clone(),
        WebAssessmentMethod::Get,
        CancellationToken::new(),
        None,
    );
    let eligible_envelope =
        TestObservationEnvelope::exact(&eligible_entity, &url, HttpProbeMethod::Get);
    let partial = observe_for_test(
        &eligible_observer,
        eligible_envelope,
        206,
        Some("text/html"),
        Some(b"<a href='/partial-canary'>canary</a>"),
        parents.refs(true),
    )
    .unwrap();
    assert_eq!(partial.len(), 1);
    assert_eq!(
        partial[0].predicate(),
        &WebDiscoveryEvidencePredicate::DOCUMENT_PARTIAL_REPRESENTATION.into_knowledge()
    );
    assert_eq!(derivation_parents(&partial[0]), parents.expected(true));
    for (status, media_type) in [(200, "text/plain"), (201, "text/html")] {
        assert!(observe_for_test(
            &eligible_observer,
            eligible_envelope,
            status,
            Some(media_type),
            Some(b"<a href='/ineligible-canary'>canary</a>"),
            parents.refs(true),
        )
        .unwrap()
        .is_empty());
    }

    let incomplete_required = [
        "request-method-evidence",
        "request-url-evidence",
        "response-status-evidence",
        "response-final-url-evidence",
        "response-body-truncated-evidence",
        "response-body-digest-evidence",
    ];
    for (missing, expected_invariant) in incomplete_required.into_iter().enumerate() {
        let mut refs = parents.refs(false);
        match missing {
            0 => refs.request_method = None,
            1 => refs.request_url = None,
            2 => refs.response_status = None,
            3 => refs.response_final_url = None,
            4 => refs.response_body_truncated = None,
            5 => refs.response_body_digest = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            observe_for_test(
                &eligible_observer,
                eligible_envelope,
                200,
                None,
                None,
                refs,
            ),
            Err(HttpEvidenceError::AssessmentObserverInvariant { invariant })
                if invariant == expected_invariant
        ));
    }

    let complete_required = [
        "request-method-evidence",
        "request-url-evidence",
        "response-status-evidence",
        "response-final-url-evidence",
        "response-media-type-evidence",
        "response-body-truncated-evidence",
        "response-body-digest-evidence",
    ];
    for (missing, expected_invariant) in complete_required.into_iter().enumerate() {
        let mut refs = parents.refs(true);
        match missing {
            0 => refs.request_method = None,
            1 => refs.request_url = None,
            2 => refs.response_status = None,
            3 => refs.response_final_url = None,
            4 => refs.response_media_type = None,
            5 => refs.response_body_truncated = None,
            6 => refs.response_body_digest = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            observe_for_test(
                &eligible_observer,
                eligible_envelope,
                200,
                Some("text/html"),
                Some(b"complete"),
                refs,
            ),
            Err(HttpEvidenceError::AssessmentObserverInvariant { invariant })
                if invariant == expected_invariant
        ));
    }
}

#[tokio::test]
async fn committed_bootstrap_replay_rejects_non_exact_batches_without_mutating_the_ledger() {
    let server = serve(|request| {
        let body = match request.path() {
            "/root" => {
                "<a href='/a'>a</a><a href='/b'>b</a>\
                 <form action='/submit' method='post'><input name='title'></form>"
            },
            _ => "done",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let target = server.url("/root");
    let mut runtime = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    let root_report = report
        .subjects()
        .iter()
        .find(|report| subject_path(report) == "/root")
        .expect("root report");
    let subject = root_report.subject().clone();
    let template = root_report
        .bootstrap()
        .expect("committed bootstrap")
        .clone();
    let original = template.evidence().to_vec();
    let marker_index = original
        .iter()
        .position(|evidence| {
            evidence.predicate()
                == &WebDiscoveryEvidencePredicate::DOCUMENT_PROJECTED.into_knowledge()
        })
        .expect("document projection marker");
    let first_defense = original
        .iter()
        .position(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE)
        .expect("assessment defense suffix");
    assert!(marker_index + 1 < first_defense);
    assert!(original[marker_index..first_defense]
        .iter()
        .all(|evidence| evidence.predicate().namespace() == "web.discovery"));
    assert!(original[first_defense..]
        .iter()
        .all(|evidence| evidence.predicate().namespace() == ASSESSMENT_DEFENSE_NAMESPACE));
    let marker = original[marker_index].clone();
    let marker_parents = derivation_parents(&marker).to_vec();
    assert_eq!(marker_parents.len(), 6);

    let mut initial_ledger = AssessmentLedger::new(&subject);
    let mut envelope = initial_ledger.snapshot(runtime.limits, subject.depth);
    envelope
        .subjects
        .get_mut(subject.url.as_str())
        .expect("root admission")
        .executed = true;
    initial_ledger.mark_executed(&subject).unwrap();
    let exact = projection_from_committed_bootstrap(
        Some(&template),
        runtime.knowledge(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .expect("exact committed receipt must project")
    .expect("HTML projection");
    assert_eq!(exact.routes.len(), 2);
    assert_eq!(exact.forms.len(), 1);

    let mut defense_before_discovery = original.clone();
    let leading_defense = defense_before_discovery.remove(first_defense);
    defense_before_discovery.insert(marker_index, leading_defense);

    let mut interleaved = original.clone();
    interleaved.swap(marker_index + 1, first_defense);

    let mut foreign_trailing = original.clone();
    foreign_trailing.push(Evidence::new(
        template.case().subject().clone(),
        EvidenceKind::Custom("assessment-test".to_owned()),
        KnowledgePredicate::new("test.web-assessment", "foreign-trailing").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, "foreign-trailing")
            .unwrap()
            .with_correlation_id(BOOTSTRAP_CASE_ID)
            .unwrap(),
        marker.reliability(),
    ));
    for (name, batch) in [
        ("defense-before-discovery", defense_before_discovery),
        ("discovery-defense-interleaving", interleaved),
        ("foreign-trailing-namespace", foreign_trailing),
    ] {
        let (knowledge, receipt) = receipt_with_committed_batch(&template, batch);
        assert!(
            projection_from_committed_bootstrap(
                Some(&receipt),
                &knowledge,
                &subject,
                &runtime.discovery_policy,
                runtime.limits,
                &envelope,
            )
            .is_err(),
            "{name} batch was accepted",
        );
    }

    let mut semantic_evidence = super::semantic::AssessmentSemanticEvidence::default();
    assert!(semantic_evidence
        .commit_bootstrap(Some(&template), &KnowledgeBase::new(), &subject)
        .is_err());
    assert_eq!(semantic_evidence.record_count(), 0);
    semantic_evidence
        .commit_bootstrap(Some(&template), runtime.knowledge(), &subject)
        .expect("exact committed bootstrap must enter semantic input");
    let exact_record_count = semantic_evidence.record_count();
    semantic_evidence
        .commit_bootstrap(Some(&template), runtime.knowledge(), &subject)
        .expect("exact replay must be idempotent");
    assert_eq!(semantic_evidence.record_count(), exact_record_count);
    let semantic_once = semantic_evidence.extract(&runtime.semantic_limits);
    let semantic_twice = semantic_evidence.extract(&runtime.semantic_limits);
    assert_eq!(
        serde_json::to_vec(&semantic_once).unwrap(),
        serde_json::to_vec(&semantic_twice).unwrap()
    );
    let receipt_ids = original
        .iter()
        .map(|evidence| evidence.id().clone())
        .collect::<BTreeSet<_>>();
    assert!(semantic_once
        .entities
        .iter()
        .flat_map(|entity| entity.source_evidence_ids())
        .all(|id| receipt_ids.contains(id)));

    assert!(projection_from_committed_bootstrap(
        Some(&template),
        &KnowledgeBase::new(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .is_err());

    let mut foreign_runtime = WebAssessmentRuntime::builder(target).build().unwrap();
    let foreign_report = foreign_runtime.analyze().await.unwrap();
    assert_report_reconciles(&foreign_report);
    assert!(projection_from_committed_bootstrap(
        Some(&template),
        foreign_runtime.knowledge(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .is_err());

    let runtime_ledger_before = (
        runtime.ledger.subjects.keys().cloned().collect::<Vec<_>>(),
        runtime.ledger.form_identities.clone(),
        runtime.ledger.retained_urls.clone(),
        runtime.ledger.retained_unique_url_bytes,
    );

    let mut conflicting_batch = original.clone();
    let conflicting_marker = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        EvidenceValue::Boolean(false),
        marker.source().clone(),
        marker.origin().clone(),
    );
    conflicting_batch.insert(marker_index, conflicting_marker);
    let rejected_knowledge = KnowledgeBase::new();
    assert!(rejected_knowledge
        .insert_evidence_batch(conflicting_batch)
        .is_err());
    assert!(original
        .iter()
        .all(|evidence| rejected_knowledge.evidence(evidence.id()).is_none()));

    let mut mutations = Vec::<(&str, Vec<Evidence>)>::new();

    let mut batch = original.clone();
    let duplicate_marker = Evidence::new(
        marker.subject().clone(),
        marker.kind().clone(),
        marker.predicate().clone(),
        marker.value().clone(),
        marker.source().clone(),
        marker.reliability(),
    )
    .derived_from(
        EvidenceDerivation::new(
            marker_parents.clone(),
            DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1).unwrap(),
        )
        .unwrap(),
    );
    assert_ne!(duplicate_marker.id(), marker.id());
    batch.insert(marker_index + 1, duplicate_marker);
    mutations.push(("duplicate-predicate", batch));

    let mut batch = original.clone();
    let route_indexes = batch
        .iter()
        .enumerate()
        .filter_map(|(index, evidence)| {
            (evidence.predicate() == &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge())
                .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(route_indexes.len(), 2);
    batch.swap(route_indexes[0], route_indexes[1]);
    mutations.push(("route-order", batch));

    let mut batch = original.clone();
    batch[marker_index] = rebuild_evidence(
        &marker,
        EvidenceKind::Http,
        marker.value().clone(),
        marker.source().clone(),
        marker.origin().clone(),
    );
    mutations.push(("kind", batch));

    let mut batch = original.clone();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        source_with_method(&marker, "wrong-source-method"),
        marker.origin().clone(),
    );
    mutations.push(("source-method", batch));

    let mut batch = original.clone();
    let wrong_algorithm = EvidenceDerivation::new(
        marker_parents.clone(),
        DerivationAlgorithm::new("web.discovery.wrong-algorithm", 1).unwrap(),
    )
    .unwrap();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        marker.source().clone(),
        EvidenceOrigin::Derived(wrong_algorithm),
    );
    mutations.push(("algorithm", batch));

    let mut batch = original.clone();
    let missing_parent = EvidenceDerivation::new(
        marker_parents.iter().skip(1).cloned(),
        DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1).unwrap(),
    )
    .unwrap();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        marker.source().clone(),
        EvidenceOrigin::Derived(missing_parent),
    );
    mutations.push(("missing-parent", batch));

    let mut batch = original.clone();
    let extra_parent = Evidence::new(
        marker.subject().clone(),
        EvidenceKind::Content,
        KnowledgePredicate::new("test.web-assessment", "extra-parent").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, "extra-parent")
            .unwrap()
            .with_correlation_id("case:foreign")
            .unwrap(),
        marker.reliability(),
    );
    let extra_parent_id = extra_parent.id().clone();
    let extra_derivation = EvidenceDerivation::new(
        marker_parents
            .iter()
            .cloned()
            .chain(std::iter::once(extra_parent_id)),
        DerivationAlgorithm::new("web.discovery.html5ever-names-only", 1).unwrap(),
    )
    .unwrap();
    batch[marker_index] = rebuild_evidence(
        &marker,
        marker.kind().clone(),
        marker.value().clone(),
        marker.source().clone(),
        EvidenceOrigin::Derived(extra_derivation),
    );
    batch.insert(marker_index, extra_parent);
    mutations.push(("extra-cross-case-parent", batch));

    let mut batch = original.clone();
    let route_index = route_indexes[0];
    let route = batch[route_index].clone();
    batch[route_index] = rebuild_evidence(
        &route,
        route.kind().clone(),
        EvidenceValue::Text(format!("{}a/../noncanonical", server.origin)),
        route.source().clone(),
        route.origin().clone(),
    );
    mutations.push(("canonical-url", batch));

    let mut batch = original.clone();
    let request_url_index = batch
        .iter()
        .position(|evidence| {
            evidence.predicate() == &HttpEvidencePredicate::REQUEST_URL.into_knowledge()
        })
        .expect("request URL evidence");
    let request_url = batch[request_url_index].clone();
    batch[request_url_index] = rebuild_evidence(
        &request_url,
        request_url.kind().clone(),
        EvidenceValue::Text(server.url("/other").to_string()),
        request_url.source().clone(),
        request_url.origin().clone(),
    );
    let mismatched_receipt = template.with_test_committed_batch(
        batch.clone(),
        template.writes().to_vec(),
        template.after_execution().clone(),
    );
    assert!(projection_from_committed_bootstrap(
        Some(&mismatched_receipt),
        runtime.knowledge(),
        &subject,
        &runtime.discovery_policy,
        runtime.limits,
        &envelope,
    )
    .is_err());
    mutations.push(("request-url", batch));

    for (name, batch) in mutations {
        let (knowledge, receipt) = receipt_with_committed_batch(&template, batch);
        assert!(
            projection_from_committed_bootstrap(
                Some(&receipt),
                &knowledge,
                &subject,
                &runtime.discovery_policy,
                runtime.limits,
                &envelope,
            )
            .is_err(),
            "{name} committed batch was accepted"
        );
    }
    assert_eq!(
        (
            runtime.ledger.subjects.keys().cloned().collect::<Vec<_>>(),
            runtime.ledger.form_identities.clone(),
            runtime.ledger.retained_urls.clone(),
            runtime.ledger.retained_unique_url_bytes,
        ),
        runtime_ledger_before
    );
}

#[tokio::test]
async fn deterministic_bfs_is_exact_origin_deduplicated_and_subject_isolated() {
    let outside = serve(|_| {
        FixtureReply::Response(FixtureResponse::html(
            "<a href='/outside-canary'>outside</a>",
        ))
    })
    .await;
    let outside_url = outside.url("/escape?outside_value=never-retain");
    let server = serve(move |request| {
        let body = match request.path() {
            "/root" => format!(
                "<a href='/b?b_value=hidden#frag'>b</a>\
                 <a href='./a?token=link-secret'>a</a>\
                 <a href='http://{}/a?other=also-secret#two'>absolute-a</a>\
                 <a href='/a#duplicate'>duplicate-a</a>\
                 <link href='/head.css?cache=secret' rel='stylesheet'>\
                 <a href='{outside_url}'>outside</a>",
                request.host()
            ),
            "/a" => "<a href='/root'>cycle</a><a href='/c'>c</a><a href='/b'>b</a>".to_owned(),
            "/b" => "<a href='/c#again'>c</a><a href='/a'>a</a>".to_owned(),
            "/c" => "done".to_owned(),
            "/head.css" => "<a href='/head-body-canary'>must-not-project</a>".to_owned(),
            _ => "not-found-canary".to_owned(),
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let mut first_runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let first = first_runtime.analyze().await.unwrap();
    assert_report_reconciles(&first);
    assert_product_identity_boundary_is_explicit(&first);
    let first_shape: Vec<_> = first.subjects().iter().map(public_subject_shape).collect();
    assert_eq!(
        first_shape
            .iter()
            .map(|item| item.0.as_str())
            .collect::<Vec<_>>(),
        ["/root", "/a", "/b", "/head.css", "/c"]
    );
    assert_eq!(first_shape[0].2, 0);
    assert!(first_shape[1..=3].iter().all(|item| item.2 == 1));
    assert_eq!(first_shape[4].2, 2);
    assert_eq!(first_shape[1].3, ["other", "token"]);
    assert_eq!(first_shape[2].3, ["b_value"]);
    assert_eq!(first_shape[3].1, WebAssessmentMethod::Head);
    assert!(first
        .subjects()
        .iter()
        .all(|subject| subject.subject().url().query().is_none()));
    assert!(!first_shape.iter().any(|item| item.0 == "/head-body-canary"));
    assert_eq!(outside.requests().await, []);

    let requests = server.requests().await;
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|request| !request.target.contains('?')));
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/root"),
            ("GET", "/a"),
            ("GET", "/b"),
            ("HEAD", "/head.css"),
            ("GET", "/c"),
        ]
    );

    let mut replay_runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let replay = replay_runtime.analyze().await.unwrap();
    assert_report_reconciles(&replay);
    assert_product_identity_boundary_is_explicit(&replay);
    assert_eq!(
        replay
            .subjects()
            .iter()
            .map(public_subject_shape)
            .collect::<Vec<_>>(),
        first_shape
    );
    assert_eq!(outside.requests().await, []);
}

#[tokio::test]
async fn same_layer_head_candidate_upgrades_to_get_and_executed_urls_are_not_redispatched() {
    let server = serve(|request| {
        let body = match request.path() {
            "/root" => "<a href='/a'>a</a><a href='/b'>b</a>",
            "/a" => "<link href='/target' rel='stylesheet'>",
            "/b" => "<a href='/target'>target</a>",
            "/target" => {
                "<a href='/a'>executed-get</a><link href='/b' rel='stylesheet'>executed-head"
            },
            _ => "unexpected",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let limits = WebAssessmentLimits::default()
        .with_max_discovery_depth(3)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_product_identity_boundary_is_explicit(&report);
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/root", "/a", "/b", "/target"]
    );
    let target = report
        .subjects()
        .iter()
        .find(|subject| subject_path(subject) == "/target")
        .expect("merged pending target");
    assert_eq!(target.subject().method(), WebAssessmentMethod::Get);
    assert_eq!(target.subject().depth(), 2);
    assert_eq!(server.hit_count("/a").await, 1);
    assert_eq!(server.hit_count("/b").await, 1);
    assert_eq!(server.hit_count("/target").await, 1);
    assert_eq!(
        server
            .requests()
            .await
            .iter()
            .map(|request| (request.method.as_str(), request.path()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/root"),
            ("GET", "/a"),
            ("GET", "/b"),
            ("GET", "/target"),
        ]
    );
}

#[tokio::test]
async fn forms_are_names_only_and_only_get_actions_are_dispatched() {
    const SECRETS: &[&str] = &[
        "ROOT_QUERY_SECRET",
        "FORM_QUERY_SECRET",
        "POST_QUERY_SECRET",
        "CONTROL_VALUE_SECRET",
        "PASSWORD_VALUE_SECRET",
        "COOKIE_VALUE_SECRET",
        "AUTH_HEADER_SECRET",
        "CSP_NONCE_SECRET",
        "CONTENT_TYPE_SECRET",
        "BODY_TEXT_SECRET",
        "RETRY_AFTER_SECRET",
        "RATELIMIT_SECRET",
    ];
    let outside =
        serve(|_| FixtureReply::Response(FixtureResponse::html("outside must not be reached")))
            .await;
    let outside_origin = outside.url("/");
    let server = serve(|request| {
        let response = match request.path() {
            "/forms" => FixtureResponse::new(
                "200 OK",
                Some("text/html; boundary=CONTENT_TYPE_SECRET"),
                "<p>BODY_TEXT_SECRET</p>\
                 <form action='/search?q=FORM_QUERY_SECRET' method='get'>\
                   <input name='q' value='CONTROL_VALUE_SECRET'>\
                   <input name='csrf' value='CONTROL_VALUE_SECRET'>\
                   <input name='password' type='password' value='PASSWORD_VALUE_SECRET'>\
                 </form>\
                 <form action='/write?token=POST_QUERY_SECRET' method='post'>\
                   <textarea name='title'>CONTROL_VALUE_SECRET</textarea>\
                 </form>\
                 <form action='/modal' method='dialog'><button name='accept'>yes</button></form>",
            )
            .with_header("Set-Cookie", "session=COOKIE_VALUE_SECRET; HttpOnly")
            .with_header("WWW-Authenticate", "Bearer AUTH_HEADER_SECRET")
            .with_header(
                "Content-Security-Policy",
                "script-src 'nonce-CSP_NONCE_SECRET'",
            )
            .with_header("Retry-After", "RETRY_AFTER_SECRET")
            .with_header("RateLimit-Remaining", "RATELIMIT_SECRET"),
            "/search" => FixtureResponse::html("search result"),
            _ => FixtureResponse::new("404 Not Found", Some("text/plain"), Vec::new()),
        };
        FixtureReply::Response(response)
    })
    .await;
    let target = server.url("/forms?root=ROOT_QUERY_SECRET#fragment");
    let policy = HttpEvidencePolicy::new(
        [target.clone(), outside_origin],
        Duration::from_secs(2),
        8 * 1_024,
    )
    .unwrap()
    .with_body_capture(HttpBodyCapture::TextSample { max_chars: 4_096 })
    .unwrap()
    .capture_header("set-cookie")
    .unwrap()
    .capture_header("www-authenticate")
    .unwrap()
    .capture_header("content-security-policy")
    .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(target)
        .http_policy(policy)
        .build()
        .unwrap();
    assert_eq!(runtime.authorized_root().query_parameter_names(), ["root"]);
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert_product_identity_boundary_is_explicit(&report);
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/forms", "/search"]
    );
    assert_eq!(report.forms().len(), 3);
    let get = report
        .forms()
        .iter()
        .find(|form| form.method() == WebAssessmentFormMethod::Get)
        .unwrap();
    assert_eq!(get.action().path(), "/search");
    assert_eq!(get.query_parameter_names(), ["q"]);
    assert_eq!(get.control_names(), ["csrf", "password", "q"]);
    let post = report
        .forms()
        .iter()
        .find(|form| form.method() == WebAssessmentFormMethod::Post)
        .unwrap();
    assert_eq!(post.action().path(), "/write");
    assert_eq!(post.query_parameter_names(), ["token"]);
    assert_eq!(post.control_names(), ["title"]);

    let requests = server.requests().await;
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.path()))
            .collect::<Vec<_>>(),
        [("GET", "/forms"), ("GET", "/search")]
    );
    assert!(requests.iter().all(|request| !request.target.contains('?')));
    assert_eq!(outside.requests().await, []);

    let report_debug = format!("{report:?}");
    let knowledge = knowledge_debug(&runtime, &report);
    assert_no_secret(&report_debug, SECRETS);
    assert_no_secret(&knowledge, SECRETS);
}

#[tokio::test]
async fn redirects_are_observed_without_following_same_or_cross_origin_locations() {
    const REDIRECT_SECRET: &str = "REDIRECT_LOCATION_SECRET";
    let outside =
        serve(|_| FixtureReply::Response(FixtureResponse::html("cross-origin redirect canary")))
            .await;
    let outside_location = outside.url(&format!("/cross-target?token={REDIRECT_SECRET}"));
    let server = serve(move |request| {
        let response = match request.path() {
            "/same-redirect" => FixtureResponse::new("302 Found", None, Vec::new())
                .with_header("Location", &format!("/same-target?token={REDIRECT_SECRET}")),
            "/cross-redirect" => FixtureResponse::new("302 Found", None, Vec::new())
                .with_header("Location", outside_location.as_str()),
            "/same-target" => FixtureResponse::html("same-origin redirect canary"),
            _ => FixtureResponse::new("404 Not Found", None, Vec::new()),
        };
        FixtureReply::Response(response)
    })
    .await;

    for path in ["/same-redirect", "/cross-redirect"] {
        let mut runtime = WebAssessmentRuntime::builder(server.url(path))
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        assert_report_reconciles(&report);
        assert!(matches!(
            report.completion(),
            WebAssessmentCompletion::Incomplete { .. }
        ));
        assert!(report
            .completion()
            .reasons()
            .contains(&WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable));
        assert!(report.assessment_items().is_empty());
        assert_eq!(report.subjects().len(), 1);
        assert_no_secret(&format!("{report:?}"), &[REDIRECT_SECRET]);
        assert_no_secret(&knowledge_debug(&runtime, &report), &[REDIRECT_SECRET]);
    }
    assert_eq!(server.hit_count("/same-target").await, 0);
    assert_eq!(outside.requests().await, []);
}

#[tokio::test]
async fn complete_body_status_and_media_boundaries_fail_closed() {
    const BODY_LIMIT: usize = 96;
    let exact_prefix = "<a href='/exact-cap-canary'>x</a>";
    let mut exact_body = exact_prefix.as_bytes().to_vec();
    exact_body.resize(BODY_LIMIT, b' ');
    let over_prefix = "<a href='/over-cap-canary'>x</a>";
    let mut over_body = over_prefix.as_bytes().to_vec();
    over_body.resize(BODY_LIMIT + 1, b' ');
    let server = serve(move |request| {
        let response = match request.path() {
            "/short" => FixtureResponse::html("<a href='/short-child'>child</a>"),
            "/short-child" => FixtureResponse::html("done"),
            "/exact" => FixtureResponse::html(exact_body.clone()),
            "/over" => FixtureResponse::html(over_body.clone()),
            "/partial" => FixtureResponse::new(
                "206 Partial Content",
                Some("text/html"),
                "<a href='/partial-canary'>partial</a>",
            ),
            "/created" => FixtureResponse::new(
                "201 Created",
                Some("text/html"),
                "<a href='/created-canary'>created</a>",
            ),
            "/plain" => FixtureResponse::new(
                "200 OK",
                Some("text/plain"),
                "<a href='/plain-canary'>plain</a>",
            ),
            "/invalid" => FixtureResponse::new("200 OK", Some("text/html"), vec![0xff, 0xfe, 0xfd]),
            _ => FixtureResponse::html("unexpected canary target"),
        };
        FixtureReply::Response(response)
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_response_body_bytes(BODY_LIMIT)
        .unwrap();

    let mut short_runtime = WebAssessmentRuntime::builder(server.url("/short"))
        .limits(limits)
        .build()
        .unwrap();
    let short = short_runtime.analyze().await.unwrap();
    assert_report_reconciles(&short);
    assert_product_identity_boundary_is_explicit(&short);
    assert_eq!(
        short
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/short", "/short-child"]
    );

    let cases = [
        (
            "/exact",
            Some(WebAssessmentIncompleteReason::ResponseBodyIncomplete),
            "/exact-cap-canary",
        ),
        (
            "/over",
            Some(WebAssessmentIncompleteReason::ResponseBodyIncomplete),
            "/over-cap-canary",
        ),
        (
            "/partial",
            Some(WebAssessmentIncompleteReason::PartialRepresentation),
            "/partial-canary",
        ),
        ("/created", None, "/created-canary"),
        ("/plain", None, "/plain-canary"),
        (
            "/invalid",
            Some(WebAssessmentIncompleteReason::InvalidUtf8),
            "/invalid-canary",
        ),
    ];
    for (path, expected_reason, canary) in cases {
        let mut runtime = WebAssessmentRuntime::builder(server.url(path))
            .limits(limits)
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        assert_report_reconciles(&report);
        assert_eq!(report.subjects().len(), 1);
        assert!(!report
            .subjects()
            .iter()
            .any(|subject| subject.subject().url().path() == canary));
        if let Some(reason) = expected_reason {
            assert!(report.completion().reasons().contains(&reason));
        }
        assert!(matches!(
            report.completion(),
            WebAssessmentCompletion::Incomplete { .. }
        ));
        assert!(report
            .completion()
            .reasons()
            .contains(&WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable));
        assert!(report.assessment_items().is_empty());
    }
}

#[tokio::test]
async fn subject_form_and_unique_url_limits_drop_canaries_with_typed_reasons() {
    let server = serve(|request| {
        let body = match request.path() {
            "/caps" => {
                "<a href='/a'>a</a><a href='/b'>b</a>\
                        <form action='/form-a' method='post'><input name='a'></form>\
                        <form action='/form-b' method='post'><input name='b'></form>"
            },
            "/url-caps" => "<a href='/url-a'>a</a><a href='/url-b'>b</a>",
            _ => "done",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;

    let limits = WebAssessmentLimits::default()
        .with_max_subjects(2)
        .unwrap()
        .with_max_forms(1)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/caps"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    let reasons = report.completion().reasons();
    assert!(reasons.contains(&WebAssessmentIncompleteReason::SubjectLimit));
    assert!(reasons.contains(&WebAssessmentIncompleteReason::FormLimit));
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/caps", "/a"]
    );
    assert_eq!(report.forms().len(), 1);
    assert_eq!(report.forms()[0].action().path(), "/form-a");
    assert_eq!(server.hit_count("/b").await, 0);
    assert_eq!(server.hit_count("/form-b").await, 0);

    let root = server.url("/url-caps");
    let first = server.url("/url-a");
    let retained_limit = root.as_str().len().saturating_add(first.as_str().len());
    let url_limits = WebAssessmentLimits::default()
        .with_max_retained_url_bytes(retained_limit)
        .unwrap();
    let mut url_runtime = WebAssessmentRuntime::builder(root)
        .limits(url_limits)
        .build()
        .unwrap();
    let url_report = url_runtime.analyze().await.unwrap();
    assert_report_reconciles(&url_report);
    assert!(url_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::RetainedUrlBytesLimit));
    assert_eq!(
        url_report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/url-caps", "/url-a"]
    );
    assert_eq!(
        url_report.usage().retained_unique_url_bytes(),
        retained_limit
    );
    assert_eq!(server.hit_count("/url-b").await, 0);
}

#[tokio::test]
async fn wildcard_cycle_is_bounded_by_depth_and_never_reported_complete() {
    let server = serve(|request| {
        let body = match request.path() {
            "/wild/0" => "<a href='/wild/1'>next</a>",
            "/wild/1" => "<a href='/wild/0'>cycle</a><a href='/wild/2'>next</a>",
            "/wild/2" => "<a href='/wild/3'>next</a>",
            "/wild/3" => "<a href='/wild/4'>next</a>",
            _ => "<a href='/wild/0'>wildcard-cycle</a>",
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_discovery_depth(2)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/wild/0"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::DiscoveryDepthLimit));
    assert!(matches!(
        report.completion(),
        WebAssessmentCompletion::Incomplete { .. }
    ));
    assert_eq!(
        report
            .subjects()
            .iter()
            .map(subject_path)
            .collect::<Vec<_>>(),
        ["/wild/0", "/wild/1", "/wild/2"]
    );
    assert_eq!(server.hit_count("/wild/0").await, 1);
    assert_eq!(server.hit_count("/wild/1").await, 1);
    assert_eq!(server.hit_count("/wild/2").await, 1);
    assert_eq!(server.hit_count("/wild/3").await, 0);
}

#[tokio::test]
async fn cancellation_wall_and_global_budgets_are_fail_closed() {
    let server = serve(|request| {
        let response = match request.path() {
            "/budget" => FixtureResponse::html("<a href='/a'>a</a><a href='/b'>b</a>"),
            "/bytes" => FixtureResponse::html(vec![b'x'; 512]),
            _ => FixtureResponse::html("done"),
        };
        FixtureReply::Response(response)
    })
    .await;

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut cancelled_runtime = WebAssessmentRuntime::builder(server.url("/cancelled"))
        .cancellation_token(cancelled)
        .build()
        .unwrap();
    let cancelled_report = cancelled_runtime.analyze().await.unwrap();
    assert_report_reconciles(&cancelled_report);
    assert!(cancelled_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::HostCancellation));
    assert_eq!(cancelled_report.usage().total_requests(), 0);
    assert!(!cancelled_report.subjects()[0].was_executed());

    let wall_limits = WebAssessmentLimits::default()
        .with_max_wall_time(Duration::ZERO)
        .unwrap();
    let mut wall_runtime = WebAssessmentRuntime::builder(server.url("/wall"))
        .limits(wall_limits)
        .build()
        .unwrap();
    let wall_report = wall_runtime.analyze().await.unwrap();
    assert_report_reconciles(&wall_report);
    assert!(wall_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::WallTimeLimit));
    assert_eq!(wall_report.usage().total_requests(), 0);
    assert!(!wall_report.subjects()[0].was_executed());

    let request_limits = WebAssessmentLimits::default()
        .with_max_total_requests(1)
        .unwrap();
    let mut request_runtime = WebAssessmentRuntime::builder(server.url("/budget"))
        .limits(request_limits)
        .build()
        .unwrap();
    let request_report = request_runtime.analyze().await.unwrap();
    assert_report_reconciles(&request_report);
    assert!(request_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(request_report.usage().total_requests(), 1);
    assert_eq!(server.hit_count("/budget").await, 1);
    assert_eq!(server.hit_count("/a").await, 0);
    assert_eq!(server.hit_count("/b").await, 0);

    let response_limits = WebAssessmentLimits::default()
        .with_max_total_response_bytes(32)
        .unwrap();
    let mut response_runtime = WebAssessmentRuntime::builder(server.url("/bytes"))
        .limits(response_limits)
        .build()
        .unwrap();
    let response_report = response_runtime.analyze().await.unwrap();
    assert_report_reconciles(&response_report);
    assert!(response_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::ResponseBytesLimit));
    assert!(response_report.usage().response_bytes() >= 32);
    assert_eq!(response_report.usage().total_requests(), 1);
}

#[tokio::test]
async fn semantic_projection_consumes_only_receipt_owned_names_and_never_unrelated_secrets() {
    const SECRET: &str = "UNRELATED_SHARED_KB_AUTH_SECRET";
    let server = serve(|request| {
        let body = if request.path() == "/root" {
            "<a href='/search?q=discarded-value&page=2'>search</a>\
             <form action='/submit?next=discarded-target' method='post'>\
               <input name='email' value='private@example.test'>\
               <input name='password' value='never-retain-this'>\
             </form>"
        } else {
            "done"
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let target = server.url("/root");
    let mut runtime = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    let root_id = EntityId::new(format!("endpoint:{target}")).unwrap();
    let hostile = Evidence::new(
        root_id,
        EvidenceKind::Authentication,
        KnowledgePredicate::new("authentication", "bearer").unwrap(),
        EvidenceValue::Text(SECRET.to_owned()),
        EvidenceSource::new("hostile.test", "unrelated-auth").unwrap(),
        ConfidenceScore::from_percent(100).unwrap(),
    );
    let hostile_id = hostile.id().clone();
    runtime.knowledge().insert_evidence(hostile).unwrap();

    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(!report.semantics().truncated);
    assert!(report.semantics().entities.iter().all(|entity| matches!(
        entity.entity_type(),
        SemanticEntityType::Endpoint | SemanticEntityType::Parameter
    )));
    let parameters = report
        .semantics()
        .entities
        .iter()
        .filter(|entity| entity.entity_type() == SemanticEntityType::Parameter)
        .flat_map(|entity| entity.attributes()["name"].iter().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        parameters,
        BTreeSet::from([
            "email".to_owned(),
            "next".to_owned(),
            "page".to_owned(),
            "password".to_owned(),
            "q".to_owned(),
        ])
    );
    assert!(report.semantics().entities.iter().all(|entity| {
        entity
            .attributes()
            .values()
            .flatten()
            .all(|value| !value.contains("discarded") && !value.contains("never-retain"))
    }));

    let committed_ids = report
        .subjects()
        .iter()
        .filter_map(WebAssessmentSubjectReport::bootstrap)
        .flat_map(DecisionEvidenceReceipt::evidence)
        .map(|evidence| evidence.id().clone())
        .collect::<BTreeSet<_>>();
    assert!(report
        .semantics()
        .entities
        .iter()
        .flat_map(|entity| entity.source_evidence_ids())
        .all(|id| committed_ids.contains(id) && id != &hostile_id));
    let semantic_debug = format!("{:?}", report.semantics());
    let semantic_json = serde_json::to_string(report.semantics()).unwrap();
    assert!(!semantic_debug.contains(SECRET));
    assert!(!semantic_json.contains(SECRET));

    let first = runtime.semantic_evidence.extract(&runtime.semantic_limits);
    let second = runtime.semantic_evidence.extract(&runtime.semantic_limits);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(&first, report.semantics());
}

#[tokio::test]
async fn semantic_entity_ceiling_marks_the_assessment_incomplete_without_extra_dispatch() {
    let links = (0..16)
        .map(|route| {
            let query = (0..64)
                .map(|name| format!("name-{name:02}=discarded"))
                .collect::<Vec<_>>()
                .join("&");
            format!("<a href='/route-{route:02}?{query}'>route</a>")
        })
        .collect::<String>();
    let server = serve(move |request| {
        let body = if request.path() == "/root" {
            links.clone()
        } else {
            "done".to_owned()
        };
        FixtureReply::Response(FixtureResponse::html(body))
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_total_requests(1)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .limits(limits)
        .build()
        .unwrap();

    let report = runtime.analyze().await.unwrap();

    assert_report_reconciles(&report);
    assert!(report.semantics().truncated);
    assert_eq!(
        report.semantics().entities.len(),
        SemanticExtractionLimits::default().max_entities()
    );
    assert!(report.semantics().dropped_entities > 0);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::SemanticExtractionLimit));
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(report.usage().total_requests(), 1);
    assert_eq!(server.hit_count("/root").await, 1);
    assert!(server
        .requests()
        .await
        .iter()
        .all(|request| request.path() == "/root"));

    runtime.limits = runtime
        .limits
        .with_max_wall_time(Duration::from_millis(1))
        .unwrap();
    let deliberately_expired = tokio::time::Instant::now() - Duration::from_millis(2);
    let mut post_extraction_reasons = BTreeSet::new();
    let repeated = runtime
        .extract_semantics_and_refresh_limits(&mut post_extraction_reasons, deliberately_expired);
    assert!(repeated.truncated);
    assert!(post_extraction_reasons.contains(&WebAssessmentIncompleteReason::WallTimeLimit));
    assert!(
        post_extraction_reasons.contains(&WebAssessmentIncompleteReason::SemanticExtractionLimit)
    );
}

#[tokio::test]
async fn in_flight_cancellation_and_timeout_preserve_typed_audits() {
    let server = serve(|_| FixtureReply::Stall).await;
    let target = server.url("/stall");
    let token = CancellationToken::new();
    let policy = HttpEvidencePolicy::new(
        [target.clone()],
        Duration::from_millis(50),
        DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES,
    )
    .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(target)
        .http_policy(policy)
        .cancellation_token(token.clone())
        .build()
        .unwrap();
    let notification = server.request_notification();
    let canceller = tokio::spawn(async move {
        notification.notified().await;
        token.cancel();
    });
    let report = runtime.analyze().await.unwrap();
    canceller.await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::HostCancellation));
    assert_eq!(report.usage().total_requests(), 1);
    assert_eq!(report.transport().receipts().len(), 1);
    assert_eq!(
        report.transport().receipts()[0].outcome(),
        TransportDispatchOutcome::Cancelled
    );

    drop(server);
    let timeout_server = serve(|_| FixtureReply::Stall).await;
    let timeout_target = timeout_server.url("/timeout");
    let timeout_policy = HttpEvidencePolicy::new(
        [timeout_target.clone()],
        Duration::from_millis(50),
        DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES,
    )
    .unwrap();
    let mut timeout_runtime = WebAssessmentRuntime::builder(timeout_target)
        .http_policy(timeout_policy)
        .build()
        .unwrap();
    let timeout_error = timeout_runtime.analyze().await.unwrap_err();
    let timeout_receipt = timeout_error
        .failure_receipt()
        .expect("started timeout failure receipt");
    assert_failure_reconciles(timeout_receipt);
    assert!(timeout_receipt
        .incomplete_reasons()
        .contains(&WebAssessmentIncompleteReason::SubjectExecutionIncomplete));
    assert_eq!(timeout_receipt.usage().total_requests(), 1);
    assert_eq!(timeout_receipt.transport().receipts().len(), 1);
    assert_eq!(
        timeout_receipt.transport().receipts()[0].outcome(),
        TransportDispatchOutcome::RequestTimeout
    );
}

#[tokio::test]
async fn committed_bootstrap_is_drained_once_when_a_later_action_fails() {
    const COOKIE_VALUE_SECRETS: &[&str] = &["LARAVEL_COOKIE_SECRET", "XSRF_COOKIE_SECRET"];
    let root_requests = Arc::new(AtomicUsize::new(0));
    let observed_root_requests = root_requests.clone();
    let server = serve(move |request| {
        if request.path() != "/root" {
            return FixtureReply::Response(FixtureResponse::html("unexpected subject"));
        }
        if observed_root_requests.fetch_add(1, Ordering::SeqCst) == 0 {
            return FixtureReply::Response(
                FixtureResponse::html(
                    "<a href='/pending?name=route'>pending</a>\
                     <form action='/write?mode=preview' method='post'>\
                       <input name='title' value='not-retained'>\
                     </form>",
                )
                .with_header(
                    "Set-Cookie",
                    "laravel_session=LARAVEL_COOKIE_SECRET; HttpOnly",
                )
                .with_header("Set-Cookie", "XSRF-TOKEN=XSRF_COOKIE_SECRET"),
            );
        }
        FixtureReply::CloseWithoutResponse
    })
    .await;

    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    seed_laravel_planning_evidence(&runtime);
    let error = runtime.analyze().await.unwrap_err();
    let receipt = error
        .failure_receipt()
        .expect("later action failure receipt");
    assert_failure_reconciles(receipt);
    assert!(receipt.completed_subjects().is_empty());
    assert_eq!(receipt.current_subject().url().path(), "/root");
    assert!(receipt.current_subject_report().bootstrap().is_some());
    assert_eq!(receipt.pending_subjects().len(), 1);
    assert_eq!(receipt.pending_subjects()[0].url().path(), "/pending");
    assert_eq!(
        receipt.pending_subjects()[0].query_parameter_names(),
        ["name"]
    );
    assert_eq!(receipt.forms().len(), 1);
    assert_eq!(receipt.forms()[0].action().path(), "/write");
    assert_eq!(receipt.forms()[0].method(), WebAssessmentFormMethod::Post);
    assert_eq!(receipt.forms()[0].query_parameter_names(), ["mode"]);
    assert_eq!(receipt.forms()[0].control_names(), ["title"]);
    assert_eq!(server.hit_count("/root").await, 2);
    assert_eq!(server.hit_count("/pending").await, 0);
    assert_eq!(receipt.usage().total_requests(), 2);
    assert_eq!(receipt.committed_passive_observations(), 1);
    assert_eq!(receipt.transport().receipts().len(), 2);
    assert_eq!(
        receipt.transport().receipts()[1].outcome(),
        TransportDispatchOutcome::TransportFailure
    );
    let debug = format!("{error:?}{receipt:?}");
    assert_no_secret(&debug, COOKIE_VALUE_SECRETS);
    let root_id = EntityId::new(format!("endpoint:{}", receipt.current_subject().url())).unwrap();
    assert_no_secret(
        &format!("{:?}", runtime.knowledge().snapshot_for_subject(&root_id)),
        COOKIE_VALUE_SECRETS,
    );
}

#[tokio::test]
async fn started_subject_failure_partitions_completed_current_and_pending_inventory() {
    const FAILURE_SECRETS: &[&str] = &[
        "FAIL_ROOT_PATH_SECRET",
        "FAIL_DISCOVERED_PATH_SECRET",
        "FAIL_ROOT_SECRET",
        "FAIL_LINK_SECRET",
        "FAIL_PENDING_SECRET",
        "FAIL_FORM_SECRET",
        "FAIL_CONTROL_SECRET",
        "FAIL_BODY_SECRET",
        "FAIL_COOKIE_SECRET",
        "FAIL_AUTH_SECRET",
        "FAIL_LOCATION_SECRET",
        "FAIL_RETRY_AFTER_SECRET",
        "FAIL_RATELIMIT_SECRET",
    ];
    let server = serve(|request| match request.path() {
        "/FAIL_ROOT_PATH_SECRET" => FixtureReply::Response(
            FixtureResponse::html(
                "<p>FAIL_BODY_SECRET</p>\
                 <a href='/FAIL_DISCOVERED_PATH_SECRET?candidate=FAIL_LINK_SECRET'>a</a>\
                 <a href='/b?pending=FAIL_PENDING_SECRET'>b</a>\
                 <form action='/write?token=FAIL_FORM_SECRET' method='post'>\
                   <input name='csrf' value='FAIL_CONTROL_SECRET'>\
                 </form>",
            )
            .with_header("Set-Cookie", "failure=FAIL_COOKIE_SECRET")
            .with_header("WWW-Authenticate", "Bearer FAIL_AUTH_SECRET")
            .with_header("Location", "/unused?token=FAIL_LOCATION_SECRET")
            .with_header("Retry-After", "FAIL_RETRY_AFTER_SECRET")
            .with_header("X-RateLimit-Reset", "FAIL_RATELIMIT_SECRET"),
        ),
        "/FAIL_DISCOVERED_PATH_SECRET" => FixtureReply::CloseWithoutResponse,
        _ => FixtureReply::Response(FixtureResponse::html("done")),
    })
    .await;
    let mut runtime =
        WebAssessmentRuntime::builder(server.url("/FAIL_ROOT_PATH_SECRET?root=FAIL_ROOT_SECRET"))
            .build()
            .unwrap();
    let error = runtime.analyze().await.unwrap_err();
    let receipt = error.failure_receipt().expect("started failure receipt");
    assert_failure_reconciles(receipt);
    assert_eq!(receipt.completed_subjects().len(), 1);
    assert_eq!(
        subject_path(&receipt.completed_subjects()[0]),
        "/FAIL_ROOT_PATH_SECRET"
    );
    assert_eq!(
        receipt.current_subject().url().path(),
        "/FAIL_DISCOVERED_PATH_SECRET"
    );
    assert!(receipt.current_subject_report().was_executed());
    assert_eq!(receipt.pending_subjects().len(), 1);
    assert_eq!(receipt.pending_subjects()[0].url().path(), "/b");
    assert_eq!(receipt.forms().len(), 1);
    assert_eq!(receipt.forms()[0].action().path(), "/write");
    assert_eq!(receipt.forms()[0].query_parameter_names(), ["token"]);
    assert_eq!(receipt.forms()[0].control_names(), ["csrf"]);
    assert!(receipt
        .incomplete_reasons()
        .contains(&WebAssessmentIncompleteReason::SubjectExecutionIncomplete));
    assert_eq!(
        server
            .requests()
            .await
            .iter()
            .map(|request| request.path())
            .collect::<Vec<_>>(),
        ["/FAIL_ROOT_PATH_SECRET", "/FAIL_DISCOVERED_PATH_SECRET"]
    );
    assert_eq!(receipt.transport().receipts().len(), 2);
    assert_eq!(receipt.committed_passive_observations(), 1);
    assert_eq!(
        receipt.transport().receipts()[1].outcome(),
        TransportDispatchOutcome::TransportFailure
    );
    let failure_debug = format!("{error:?}{receipt:?}");
    assert_no_secret(&failure_debug, FAILURE_SECRETS);
    assert!(!receipt.semantics().truncated);
    assert!(receipt.semantics().entities.iter().all(|entity| matches!(
        entity.entity_type(),
        SemanticEntityType::Endpoint | SemanticEntityType::Parameter
    )));
    let semantic_names = receipt
        .semantics()
        .entities
        .iter()
        .filter(|entity| entity.entity_type() == SemanticEntityType::Parameter)
        .flat_map(|entity| entity.attributes()["name"].iter().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        semantic_names,
        BTreeSet::from([
            "candidate".to_owned(),
            "csrf".to_owned(),
            "pending".to_owned(),
            "token".to_owned(),
        ])
    );
    // Endpoint paths are intentional semantic resource identity. Values from
    // the root query, discovered queries, controls, headers, cookies, and body
    // must never enter the semantic projection.
    assert_no_secret(
        &serde_json::to_string(receipt.semantics()).unwrap(),
        &FAILURE_SECRETS[2..],
    );
    let subject_ids: Vec<_> = receipt
        .completed_subjects()
        .iter()
        .map(|report| report.subject().url().clone())
        .chain(std::iter::once(receipt.current_subject().url().clone()))
        .chain(
            receipt
                .pending_subjects()
                .iter()
                .map(|subject| subject.url().clone()),
        )
        .collect();
    let knowledge = subject_ids
        .iter()
        .map(|url| {
            let id = EntityId::new(format!("endpoint:{url}"))
                .expect("failure subject identity must be valid");
            format!("{:?}", runtime.knowledge().snapshot_for_subject(&id))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_no_secret(&knowledge, &FAILURE_SECRETS[2..]);
    let nested_debug = format!(
        "{:?}{:?}",
        receipt.completed_subjects(),
        receipt.current_subject_report()
    );
    assert!(!nested_debug.contains("TransportDispatchAudit"));
    assert!(!nested_debug.contains("RuntimeUsage"));
}

#[tokio::test]
async fn ledger_only_subject_drift_returns_one_current_subject_and_typed_inventory_failure() {
    let server = serve(|_| FixtureReply::Response(FixtureResponse::html("done"))).await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/root"))
        .build()
        .unwrap();
    let ghost_url = server.url("/ledger-only");
    runtime.ledger.subjects.insert(
        ghost_url.to_string(),
        SubjectAdmission {
            method: WebAssessmentMethod::Head,
            query_parameter_names: BTreeSet::new(),
            executed: false,
        },
    );
    runtime.ledger.retain_url(&ghost_url);

    let error = runtime.analyze().await.unwrap_err();
    assert!(matches!(
        error,
        WebAssessmentRuntimeError::ProjectionInvariant { .. }
    ));
    let receipt = error.failure_receipt().expect("projection receipt");
    assert!(!receipt.inventory_consistent());
    assert_eq!(receipt.unrepresented_ledger_subjects(), 1);
    let root_occurrences = receipt
        .completed_subjects()
        .iter()
        .filter(|report| subject_path(report) == "/root")
        .count()
        + receipt
            .pending_subjects()
            .iter()
            .filter(|subject| subject.url().path() == "/root")
            .count()
        + usize::from(receipt.current_subject().url().path() == "/root");
    assert_eq!(root_occurrences, 1);
    assert!(receipt.completed_subjects().is_empty());
    assert!(receipt.pending_subjects().is_empty());
    assert_eq!(receipt.current_subject().url().path(), "/root");
    assert!(receipt.current_subject_report().was_executed());
    assert_eq!(receipt.usage().retained_subjects(), 1);
    assert_eq!(receipt.usage().executed_subjects(), 1);
    assert_eq!(server.hit_count("/root").await, 1);
    assert_eq!(server.hit_count("/ledger-only").await, 0);
}

#[tokio::test]
async fn zero_request_budget_is_typed_incomplete_without_network_io() {
    let server =
        serve(|_| FixtureReply::Response(FixtureResponse::html("network must not be reached")))
            .await;
    let limits = WebAssessmentLimits::default()
        .with_max_total_requests(0)
        .unwrap();
    let mut runtime = WebAssessmentRuntime::builder(server.url("/zero"))
        .limits(limits)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert_report_reconciles(&report);
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::TotalRequestLimit));
    assert_eq!(report.usage().total_requests(), 0);
    assert_eq!(report.transport().receipts(), []);
    assert_eq!(server.requests().await, []);
}

#[tokio::test]
async fn assessment_passive_projection_is_ordered_value_free_and_strictly_replayed() {
    const HEADER_SECRETS: &[&str] = &[
        "COOKIE_VALUE_SENTINEL",
        "CSP_NONCE_SENTINEL",
        "CSP_HASH_SENTINEL",
        "CSP_ORIGIN_SENTINEL",
        "PERMISSIONS_ORIGIN_SENTINEL",
        "COOKIE_DOMAIN_SENTINEL",
        "COOKIE_PATH_SENTINEL",
    ];
    let server = serve(|_| {
        FixtureReply::Response(
            FixtureResponse::html("<html><body>safe fixture</body></html>")
                .with_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                .with_header(
                    "Content-Security-Policy",
                    "default-src 'self' https://CSP_ORIGIN_SENTINEL.invalid; script-src 'nonce-CSP_NONCE_SENTINEL' 'sha256-CSP_HASH_SENTINEL' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
                )
                .with_header("X-Content-Type-Options", "nosniff")
                .with_header("Referrer-Policy", "strict-origin-when-cross-origin")
                .with_header(
                    "Permissions-Policy",
                    "geolocation=(self \"https://PERMISSIONS_ORIGIN_SENTINEL.invalid\")",
                )
                .with_header(
                    "Set-Cookie",
                    "session=COOKIE_VALUE_SENTINEL; Domain=COOKIE_DOMAIN_SENTINEL.invalid; Path=/COOKIE_PATH_SENTINEL; HttpOnly; SameSite=None",
                ),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/passive-root"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let subject_report = report
        .subjects()
        .iter()
        .find(|subject| subject.subject().url().path() == "/passive-root")
        .unwrap();
    let bootstrap = subject_report.bootstrap().unwrap();

    assert!(runtime
        .knowledge()
        .evidence_for_predicate(&HttpEvidencePredicate::COOKIE_NAME.into_knowledge())
        .is_empty());
    let passive: Vec<_> = bootstrap
        .evidence()
        .iter()
        .filter(|evidence| evidence.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
        .collect();
    assert!(!passive.is_empty());
    assert!(passive.len() <= 160);
    let passive_start = bootstrap
        .evidence()
        .iter()
        .position(|evidence| evidence.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
        .unwrap();
    assert_eq!(
        bootstrap.evidence()[passive_start - 2].predicate(),
        &HttpEvidencePredicate::RATE_LIMIT_DETECTED.into_knowledge()
    );
    assert_eq!(
        bootstrap.evidence()[passive_start - 1].predicate(),
        &HttpEvidencePredicate::RATE_LIMIT_ADVERTISED.into_knowledge()
    );
    let mut expected_parents = [
        HttpEvidencePredicate::REQUEST_METHOD,
        HttpEvidencePredicate::REQUEST_URL,
        HttpEvidencePredicate::RESPONSE_STATUS,
        HttpEvidencePredicate::RESPONSE_FINAL_URL,
    ]
    .into_iter()
    .map(|predicate| {
        bootstrap
            .evidence()
            .iter()
            .find(|evidence| evidence.predicate() == &predicate.into_knowledge())
            .unwrap()
            .id()
            .clone()
    })
    .collect::<Vec<_>>();
    expected_parents.sort();
    assert!(passive.iter().all(|evidence| {
        let derivation = evidence.origin().derivation().unwrap();
        derivation.algorithm().name() == "web.passive-review.value-free-response-metadata"
            && derivation.algorithm().version() == 1
            && derivation.parents() == expected_parents
    }));
    let first_discovery = bootstrap
        .evidence()
        .iter()
        .position(|evidence| evidence.predicate().namespace() == "web.discovery")
        .unwrap();
    let first_defense = bootstrap
        .evidence()
        .iter()
        .position(|evidence| evidence.predicate().namespace() == "web.defense")
        .unwrap();
    let passive_end = bootstrap
        .evidence()
        .iter()
        .rposition(|evidence| evidence.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
        .unwrap();
    assert!(passive_end < first_discovery && first_discovery < first_defense);

    let observation = passive_observation_for_path(&runtime, "/passive-root");
    assert_eq!(observation.case_id(), BOOTSTRAP_CASE_ID);
    assert_eq!(observation.stage(), DecisionExecutionStage::Passive);
    assert_eq!(observation.method(), WebAssessmentMethod::Get);
    assert_eq!(observation.status(), 200);
    assert_eq!(observation.media_class(), CommittedPassiveMediaClass::Html);
    assert_eq!(
        observation.parent_evidence_ids(),
        expected_parents.as_slice()
    );
    assert_eq!(observation.evidence_ids().len(), passive.len());
    assert_eq!(observation.hsts().state(), PassiveProjectionState::Parsed);
    assert_eq!(observation.csp().state(), PassiveProjectionState::Parsed);
    assert_eq!(observation.xcto().state(), PassiveProjectionState::Parsed);
    assert_eq!(
        observation.referrer_policy().state(),
        PassiveProjectionState::Parsed
    );
    assert_eq!(
        observation.permissions_policy().state(),
        PassiveProjectionState::Parsed
    );
    assert_eq!(
        observation.cookies().state(),
        PassiveProjectionState::Nonconformant
    );
    let csp = observation.csp().metadata().unwrap();
    assert!(csp.declares_unsafe_inline);
    assert!(!csp.declares_unsafe_eval);
    assert!(csp.declares_nonce);
    assert!(csp.declares_hash);
    let cookie = &observation.cookies().metadata().unwrap()[0];
    assert_eq!(cookie.name, "session");
    assert!(!cookie.secure);
    assert!(cookie.http_only);
    assert_eq!(cookie.same_site, PassiveCookieSameSite::None);
    assert!(cookie.domain_attribute_present);
    assert!(cookie.path_attribute_present);

    let safe_debug = format!(
        "{bootstrap:?}{:?}{:?}",
        runtime
            .knowledge()
            .snapshot_for_subject(observation.subject()),
        runtime.passive_ledger
    );
    assert_no_secret(&safe_debug, HEADER_SECRETS);
    assert!(!format!("{observation:?}{:?}", runtime.passive_ledger).contains("session"));
}

#[tokio::test]
async fn passive_projection_limit_is_partial_and_keeps_malformed_missing_distinct() {
    let server = serve(|_| {
        let mut response = FixtureResponse::html("<html><body>bounded</body></html>")
            .with_header("Strict-Transport-Security", "max-age=not-a-number");
        for index in 0..17 {
            response = response.with_header(
                "Set-Cookie",
                &format!("cookie{index}=COOKIE_LIMIT_VALUE_{index}; Secure; SameSite=Lax"),
            );
        }
        FixtureReply::Response(response)
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/cookie-limit"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert!(report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::PassiveResponseProjectionLimit));
    assert!(runtime
        .knowledge()
        .evidence_for_predicate(&HttpEvidencePredicate::COOKIE_NAME.into_knowledge())
        .is_empty());
    let bootstrap = report.subjects()[0].bootstrap().unwrap();
    assert_eq!(
        bootstrap
            .evidence()
            .iter()
            .filter(|evidence| evidence.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
            .count(),
        6
    );
    let observation = passive_observation_for_path(&runtime, "/cookie-limit");
    assert_eq!(
        observation.hsts().state(),
        PassiveProjectionState::Malformed
    );
    assert_eq!(observation.xcto().state(), PassiveProjectionState::Missing);
    assert_eq!(
        observation.cookies().state(),
        PassiveProjectionState::ProjectionIncomplete
    );
    assert_eq!(
        observation.cookies().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManySetCookieOccurrences)
    );
    assert!(observation.cookies().metadata().is_none());
    assert_no_secret(
        &format!(
            "{bootstrap:?}{:?}{:?}",
            runtime
                .knowledge()
                .snapshot_for_subject(observation.subject()),
            runtime.passive_ledger
        ),
        &["COOKIE_LIMIT_VALUE_"],
    );
}

#[tokio::test]
async fn head_and_truncated_get_keep_passive_observations() {
    let head_server = serve(|request| {
        let response = if request.path() == "/head-root" {
            FixtureResponse::html("<html><head><link rel='stylesheet' href='/asset'></head></html>")
        } else {
            FixtureResponse::new("200 OK", Some("text/css"), "body{}")
                .with_header("Strict-Transport-Security", "max-age=60")
                .with_header("Set-Cookie", "asset=HEAD_COOKIE_VALUE; Secure")
        };
        FixtureReply::Response(response)
    })
    .await;
    let mut head_runtime = WebAssessmentRuntime::builder(head_server.url("/head-root"))
        .build()
        .unwrap();
    let head_report = head_runtime.analyze().await.unwrap();
    let asset = head_report
        .subjects()
        .iter()
        .find(|subject| subject.subject().url().path() == "/asset")
        .unwrap();
    assert_eq!(asset.subject().method(), WebAssessmentMethod::Head);
    let asset_bootstrap = asset.bootstrap().unwrap();
    assert!(asset_bootstrap
        .evidence()
        .iter()
        .any(|evidence| evidence.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE));
    assert!(!asset_bootstrap
        .evidence()
        .iter()
        .any(|evidence| evidence.predicate().namespace() == "web.discovery"));
    let head_observation = passive_observation_for_path(&head_runtime, "/asset");
    assert_eq!(head_observation.method(), WebAssessmentMethod::Head);
    assert_eq!(head_observation.status(), 200);
    assert_eq!(
        head_observation.media_class(),
        CommittedPassiveMediaClass::Other
    );
    assert_eq!(
        head_observation.hsts().state(),
        PassiveProjectionState::Parsed
    );
    assert!(head_runtime
        .knowledge()
        .evidence_for_predicate(&HttpEvidencePredicate::COOKIE_NAME.into_knowledge())
        .is_empty());
    assert_no_secret(
        &format!(
            "{asset_bootstrap:?}{:?}",
            head_runtime
                .knowledge()
                .snapshot_for_subject(head_observation.subject())
        ),
        &["HEAD_COOKIE_VALUE"],
    );

    let body = format!(
        "<html><body>{}<a href='/must-not-be-discovered'>hidden</a></body></html>",
        "x".repeat(256)
    );
    let truncated_server = serve(move |_| {
        FixtureReply::Response(
            FixtureResponse::html(body.clone()).with_header("X-Content-Type-Options", "nosniff"),
        )
    })
    .await;
    let limits = WebAssessmentLimits::default()
        .with_max_response_body_bytes(32)
        .unwrap();
    let mut truncated_runtime = WebAssessmentRuntime::builder(truncated_server.url("/truncated"))
        .limits(limits)
        .build()
        .unwrap();
    let truncated_report = truncated_runtime.analyze().await.unwrap();
    assert!(truncated_report
        .completion()
        .reasons()
        .contains(&WebAssessmentIncompleteReason::ResponseBodyIncomplete));
    assert_eq!(truncated_report.subjects().len(), 1);
    let truncated_bootstrap = truncated_report.subjects()[0].bootstrap().unwrap();
    let passive_end = truncated_bootstrap
        .evidence()
        .iter()
        .rposition(|evidence| evidence.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
        .unwrap();
    let incomplete = truncated_bootstrap
        .evidence()
        .iter()
        .position(|evidence| {
            evidence.predicate()
                == &WebDiscoveryEvidencePredicate::DOCUMENT_BODY_INCOMPLETE.into_knowledge()
        })
        .unwrap();
    assert!(passive_end < incomplete);
    let truncated_observation = passive_observation_for_path(&truncated_runtime, "/truncated");
    assert_eq!(truncated_observation.method(), WebAssessmentMethod::Get);
    assert_eq!(
        truncated_observation.xcto().state(),
        PassiveProjectionState::Parsed
    );
    assert!(truncated_observation.xcto().metadata().unwrap().nosniff);
}

#[test]
fn stopped_observer_emits_passive_before_suppressing_complete_body_discovery() {
    let url = Url::parse("http://127.0.0.1:7777/cancelled-passive").unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let (observer, _, entity) =
        observer_fixture(url.clone(), WebAssessmentMethod::Get, cancelled, None);
    let parents = TestObservationParents::new();
    let projection = passive_response_projection_for_test(&[("x-content-type-options", "nosniff")]);
    let evidence = observe_full_for_test(
        &observer,
        TestObservationEnvelope::exact(&entity, &url, HttpProbeMethod::Get),
        200,
        Some("text/html"),
        Some(b"<a href='/cancelled-canary'>canary</a>"),
        parents.refs(true),
        &projection,
    )
    .unwrap();
    assert!(!evidence.is_empty());
    assert!(evidence
        .iter()
        .all(|item| item.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE));
    assert!(evidence.iter().any(|item| {
        item.predicate().name() == "x_content_type_options_nosniff"
            && item.value() == &EvidenceValue::Boolean(true)
    }));
}

#[tokio::test]
async fn passive_ledger_replay_is_idempotent_and_rejects_divergence_atomically() {
    let server = serve(|request| {
        let body = if request.path() == "/replay" {
            "<html><body><a href='/child'>child</a></body></html>"
        } else {
            "<html><body>done</body></html>"
        };
        FixtureReply::Response(
            FixtureResponse::html(body)
                .with_header("Strict-Transport-Security", "max-age=60")
                .with_header("X-Content-Type-Options", "nosniff")
                .with_header("Set-Cookie", "replay_cookie=value; HttpOnly; SameSite=None"),
        )
    })
    .await;
    let mut runtime = WebAssessmentRuntime::builder(server.url("/replay"))
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let root = report
        .subjects()
        .iter()
        .find(|subject| subject.subject().url().path() == "/replay")
        .unwrap();
    let expected_subject = root.subject().clone();
    let bootstrap = root.bootstrap().unwrap();
    let passive_start = bootstrap
        .evidence()
        .iter()
        .position(|item| item.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE)
        .unwrap();
    let first_discovery = bootstrap
        .evidence()
        .iter()
        .position(|item| item.predicate().namespace() == "web.discovery")
        .unwrap();

    let mut ledger = CommittedAssessmentPassiveLedger::default();
    let committed = ledger
        .ingest_receipt(bootstrap, runtime.knowledge(), &expected_subject)
        .unwrap()
        .expect("first exact receipt must commit");
    assert_eq!(
        committed.cookies().state(),
        PassiveProjectionState::Nonconformant
    );
    let insecure_cookie = &committed.cookies().metadata().unwrap()[0];
    assert_eq!(insecure_cookie.same_site, PassiveCookieSameSite::None);
    assert!(!insecure_cookie.secure);
    assert!(committed
        .evidence_ids_for_property("cookie_same_site")
        .is_some_and(|ids| ids.len() == 1));
    let committed_ids = committed.evidence_ids().to_vec();
    assert!(ledger
        .ingest_receipt(bootstrap, runtime.knowledge(), &expected_subject)
        .unwrap()
        .is_none());
    assert_eq!(ledger.receipt_count(), 1);
    assert_eq!(ledger.observations().len(), 1);

    let mut divergent_ids = bootstrap.evidence().to_vec();
    for item in &mut divergent_ids {
        if item.predicate().namespace() == ASSESSMENT_PASSIVE_NAMESPACE {
            let fresh = fresh_evidence(item);
            *item = fresh;
        }
    }
    let (divergent_knowledge, divergent_receipt) =
        receipt_with_committed_batch(bootstrap, divergent_ids);
    assert!(ledger
        .ingest_receipt(&divergent_receipt, &divergent_knowledge, &expected_subject,)
        .is_err());
    assert_eq!(ledger.receipt_count(), 1);
    assert_eq!(ledger.observations().len(), 1);
    assert_eq!(ledger.observations()[0].evidence_ids(), committed_ids);

    let mut reordered = bootstrap.evidence().to_vec();
    reordered.swap(passive_start, passive_start + 1);
    assert_passive_replay_rejected_atomically(bootstrap, reordered, &expected_subject);

    let mut interleaved = bootstrap.evidence().to_vec();
    interleaved.swap(passive_start + 1, first_discovery);
    assert_passive_replay_rejected_atomically(bootstrap, interleaved, &expected_subject);

    let mut wrong_source = bootstrap.evidence().to_vec();
    let original = &wrong_source[passive_start];
    let replacement = rebuild_evidence(
        original,
        original.kind().clone(),
        original.value().clone(),
        source_with_method(original, "injected-source"),
        original.origin().clone(),
    );
    wrong_source[passive_start] = replacement;
    assert_passive_replay_rejected_atomically(bootstrap, wrong_source, &expected_subject);

    let mut cross_case = bootstrap.evidence().to_vec();
    let original = &cross_case[passive_start];
    let source = EvidenceSource::new(original.source().component(), original.source().method())
        .unwrap()
        .with_correlation_id("case:cross-case")
        .unwrap();
    let replacement = rebuild_evidence(
        original,
        original.kind().clone(),
        original.value().clone(),
        source,
        original.origin().clone(),
    );
    cross_case[passive_start] = replacement;
    assert_passive_replay_rejected_atomically(bootstrap, cross_case, &expected_subject);

    let mut wrong_parents = bootstrap.evidence().to_vec();
    let original = &wrong_parents[passive_start];
    let derivation = original.origin().derivation().unwrap();
    let replacement_derivation = EvidenceDerivation::new(
        derivation.parents()[1..].iter().cloned(),
        DerivationAlgorithm::new(
            derivation.algorithm().name(),
            derivation.algorithm().version(),
        )
        .unwrap(),
    )
    .unwrap();
    let replacement = rebuild_evidence(
        original,
        original.kind().clone(),
        original.value().clone(),
        original.source().clone(),
        EvidenceOrigin::Derived(replacement_derivation),
    );
    wrong_parents[passive_start] = replacement;
    assert_passive_replay_rejected_atomically(bootstrap, wrong_parents, &expected_subject);

    let mut wrong_reason = bootstrap.evidence().to_vec();
    let original = &wrong_reason[passive_start];
    let replacement = rebuild_evidence(
        original,
        original.kind().clone(),
        EvidenceValue::TextList(vec![
            "projection_incomplete".to_owned(),
            "too_many_cookie_attributes".to_owned(),
        ]),
        original.source().clone(),
        original.origin().clone(),
    );
    wrong_reason[passive_start] = replacement;
    wrong_reason.drain(passive_start + 1..passive_start + 5);
    assert_passive_replay_rejected_atomically(bootstrap, wrong_reason, &expected_subject);

    let mut impossible_xcto = bootstrap.evidence().to_vec();
    let xcto = impossible_xcto
        .iter()
        .position(|item| item.predicate().name() == "x_content_type_options_nosniff")
        .unwrap();
    let original = &impossible_xcto[xcto];
    let replacement = rebuild_evidence(
        original,
        original.kind().clone(),
        EvidenceValue::Boolean(false),
        original.source().clone(),
        original.origin().clone(),
    );
    impossible_xcto[xcto] = replacement;
    assert_passive_replay_rejected_atomically(bootstrap, impossible_xcto, &expected_subject);

    let mut unknown_passive = bootstrap.evidence().to_vec();
    let original = &unknown_passive[passive_start];
    let replacement = Evidence::with_id_at(
        original.id().clone(),
        original.subject().clone(),
        original.kind().clone(),
        KnowledgePredicate::new(ASSESSMENT_PASSIVE_NAMESPACE, "unknown_property").unwrap(),
        original.value().clone(),
        original.source().clone(),
        original.reliability(),
        original.observed_at_ms(),
    )
    .derived_from(original.origin().derivation().unwrap().clone());
    unknown_passive[passive_start] = replacement;
    assert_passive_replay_rejected_atomically(bootstrap, unknown_passive, &expected_subject);

    let mut unknown_namespace = bootstrap.evidence().to_vec();
    unknown_namespace.push(Evidence::new(
        bootstrap.case().subject().clone(),
        EvidenceKind::Custom("injected".to_owned()),
        KnowledgePredicate::new("web.injected", "unknown").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, "injected")
            .unwrap()
            .with_correlation_id(BOOTSTRAP_CASE_ID)
            .unwrap(),
        ConfidenceScore::from_percent(100).unwrap(),
    ));
    assert_passive_replay_rejected_atomically(bootstrap, unknown_namespace, &expected_subject);

    let mut wrong_method = expected_subject.clone();
    wrong_method.method = WebAssessmentMethod::Head;
    let mut rejected = CommittedAssessmentPassiveLedger::default();
    assert!(rejected
        .ingest_receipt(bootstrap, runtime.knowledge(), &wrong_method)
        .is_err());
    assert!(rejected.observations().is_empty());
    assert_eq!(rejected.receipt_count(), 0);

    let mut wrong_url = expected_subject;
    wrong_url.url = server.url("/wrong-subject");
    assert!(rejected
        .ingest_receipt(bootstrap, runtime.knowledge(), &wrong_url)
        .is_err());
    assert!(rejected.observations().is_empty());
    assert_eq!(rejected.receipt_count(), 0);

    assert!(rejected
        .ingest_receipt(bootstrap, &KnowledgeBase::new(), root.subject())
        .is_err());
    assert!(rejected.observations().is_empty());
    assert_eq!(rejected.receipt_count(), 0);
}

#[tokio::test]
async fn passive_replay_accepts_the_maximum_authorized_subject_identity() {
    let server =
        serve(|_| FixtureReply::Response(FixtureResponse::html("<html>maximum</html>"))).await;
    let origin_bytes = server.origin.as_str().len();
    let path = format!(
        "/{}",
        "a".repeat(HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES - origin_bytes)
    );
    let target = server.url(&path);
    assert_eq!(
        target.as_str().len(),
        HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES
    );
    let mut runtime = WebAssessmentRuntime::builder(target.clone())
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let subject = report.subjects()[0].subject();
    assert_eq!(subject.url(), &target);
    let observation = passive_observation_for_path(&runtime, &path);
    assert_eq!(
        observation.subject().as_str().len(),
        "endpoint:".len() + target.as_str().len()
    );
}

#[test]
fn runtime_budget_dimension_mapping_remains_total_and_exhaustive() {
    let expected = [
        (
            RuntimeBudgetDimension::TotalRequests,
            WebAssessmentIncompleteReason::TotalRequestLimit,
        ),
        (
            RuntimeBudgetDimension::WallTime,
            WebAssessmentIncompleteReason::WallTimeLimit,
        ),
        (
            RuntimeBudgetDimension::ResponseBytes,
            WebAssessmentIncompleteReason::ResponseBytesLimit,
        ),
        (
            RuntimeBudgetDimension::RequestBodyBytes,
            WebAssessmentIncompleteReason::RequestBodyBytesLimit,
        ),
        (
            RuntimeBudgetDimension::ActiveVerifications,
            WebAssessmentIncompleteReason::ActiveVerificationLimit,
        ),
        (
            RuntimeBudgetDimension::SameActionAttempts,
            WebAssessmentIncompleteReason::SameActionAttemptLimit,
        ),
        (
            RuntimeBudgetDimension::ConsecutiveNoProgressTurns,
            WebAssessmentIncompleteReason::ConsecutiveNoProgressLimit,
        ),
    ];
    for (dimension, reason) in expected {
        assert_eq!(reason_for_runtime_dimension(dimension), reason);
    }
}
