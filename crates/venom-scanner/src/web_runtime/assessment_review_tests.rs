use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;
use venom_core::{ConfidenceScore, EntityId, EvidenceId, EvidenceValue};

use super::super::web_assessment::AttributeQuoteMode;
use super::*;
use crate::http_evidence::{
    complete_http_response_observation_for_test, passive_response_projection_for_test,
    project_review_response, CompleteHttpResponseObservationTestInput, HttpProbe,
    ReviewResponseProjection,
};

const CASE_ID: &str = "case:decision:1:planned:web-review";
const HYPOTHESIS_ID: &str = "hypothesis:web-review:eligible";
const QUERY_PARAMETER: &str = "return_to";

fn root() -> Url {
    Url::parse("https://review.test/account").unwrap()
}

fn seeds() -> NativeWebReviewSeeds {
    NativeWebReviewSeeds::from_authorized_origin(&root()).unwrap()
}

fn subject() -> EntityId {
    EntityId::new(format!("endpoint:{}", root())).unwrap()
}

fn html_text_selection() -> XssProbeSelection {
    super::super::web_assessment::select_xss_probe_families(
        ExactHtmlReflectionContext::HtmlText,
        &AttributeSourceResult::Absent,
        &JavaScriptSourceResult::Absent,
    )
    .into_iter()
    .next()
    .unwrap()
}

fn attribute_xss_selection(element: &str, attribute: &str, delimiter: &str) -> XssProbeSelection {
    let marker = seeds().reflection_candidate_marker();
    let html = format!("<{element} {attribute}={delimiter}{marker}{delimiter}></{element}>");
    let context = classify_exact_html_reflection(&html, &marker);
    let source = cross_validate_attribute_reflection_source(&html, &marker, context);
    super::super::web_assessment::select_xss_probe_families(
        context,
        &source,
        &JavaScriptSourceResult::Absent,
    )
    .into_iter()
    .next()
    .unwrap()
}

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

#[allow(clippy::too_many_arguments)]
fn observe(
    observer: &AssessmentReviewObserverSet,
    kind: NativeWebReviewActionKind,
    stage: DecisionExecutionStage,
    requested_url: &Url,
    response_headers: &HeaderMap,
    status: u16,
    media_type: Option<&str>,
    complete_body: Option<&[u8]>,
    executor_id: &str,
    strategy: Option<&PayloadStrategyRef>,
    applies_transition: bool,
) -> Result<Vec<Evidence>, HttpEvidenceError> {
    let mut probe = HttpProbe::new(requested_url.clone(), HttpProbeMethod::Get).unwrap();
    if kind == NativeWebReviewActionKind::CorsPolicyPair && stage == DecisionExecutionStage::Active
    {
        probe = probe.with_header("origin", seeds().cors_origin()).unwrap();
    }
    let review = project_review_response(&probe, response_headers);
    let passive = passive_response_projection_for_test(&[]);
    let ids = (0..7).map(|_| EvidenceId::new()).collect::<Vec<_>>();
    let expected_subject = subject();
    let observation =
        complete_http_response_observation_for_test(CompleteHttpResponseObservationTestInput {
            case_id: CASE_ID,
            action_id: kind.action_id(),
            executor_id,
            hypothesis_id: HYPOTHESIS_ID,
            has_payload_strategy: strategy.is_some(),
            payload_strategy: strategy,
            applies_hypothesis_transition: applies_transition,
            stage,
            subject: &expected_subject,
            method: HttpProbeMethod::Get,
            requested_url,
            status,
            media_type,
            reliability: ConfidenceScore::MAX,
            complete_body,
            request_method_evidence_id: Some(&ids[0]),
            request_url_evidence_id: Some(&ids[1]),
            response_status_evidence_id: Some(&ids[2]),
            response_final_url_evidence_id: Some(&ids[3]),
            response_media_type_evidence_id: media_type.map(|_| &ids[4]),
            response_body_truncated_evidence_id: Some(&ids[5]),
            response_body_digest_evidence_id: Some(&ids[6]),
            passive_response_projection: &passive,
            review_response_projection: Some(&review),
        });
    observer.observe(observation)
}

fn values(evidence: &[Evidence]) -> Vec<(&str, &str)> {
    evidence
        .iter()
        .map(|item| {
            let EvidenceValue::Text(value) = item.value() else {
                panic!("native review evidence must use fixed text relations")
            };
            (item.predicate().name(), value.as_str())
        })
        .collect()
}

#[test]
fn composite_observer_projects_both_exact_action_contracts_without_raw_values() {
    let root = root();
    let seeds = seeds();
    let observer =
        AssessmentReviewObserverSet::new(root.clone(), seeds.clone(), Some(QUERY_PARAMETER))
            .unwrap();
    let cors_strategy = native_review_strategy_ref(NativeWebReviewActionKind::CorsPolicyPair);
    let cors = observe(
        &observer,
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Active,
        &root,
        &headers(&[
            ("access-control-allow-origin", seeds.cors_origin()),
            ("access-control-allow-credentials", "true"),
            ("vary", "Accept-Encoding, Origin"),
        ]),
        200,
        Some("text/html"),
        Some(b"<p>ordinary</p>"),
        NativeWebReviewActionKind::CorsPolicyPair.executor_id(),
        Some(&cors_strategy),
        false,
    )
    .unwrap();
    assert_eq!(
        values(&cors),
        vec![
            (NATIVE_WEB_REVIEW_RESPONSE_MARKER, "active-candidate"),
            (CORS_HTTP_STATUS_CLASS, "successful"),
            (CORS_ALLOW_ORIGIN_RELATION, "exact-request-origin"),
            (CORS_ALLOW_CREDENTIALS_RELATION, "true"),
            (CORS_VARY_ORIGIN_RELATION, "contains-origin"),
        ]
    );

    let mut candidate_url = root.clone();
    candidate_url
        .query_pairs_mut()
        .append_pair(QUERY_PARAMETER, seeds.external_url());
    let redirect_strategy =
        native_review_strategy_ref(NativeWebReviewActionKind::RedirectReflectionQueryPair);
    let redirect = observe(
        &observer,
        NativeWebReviewActionKind::RedirectReflectionQueryPair,
        DecisionExecutionStage::Active,
        &candidate_url,
        &headers(&[("location", seeds.external_url())]),
        302,
        None,
        None,
        NativeWebReviewActionKind::RedirectReflectionQueryPair.executor_id(),
        Some(&redirect_strategy),
        false,
    )
    .unwrap();
    assert_eq!(
        values(&redirect),
        vec![
            (NATIVE_WEB_REVIEW_RESPONSE_MARKER, "active-candidate"),
            (REDIRECT_STATUS_RELATION, "redirect"),
            (REDIRECT_LOCATION_RELATION, "exact-external-query-value",),
        ]
    );

    let reflection_contract = observer.reflection.as_ref().unwrap();
    let marker = seeds.reflection_candidate_marker();
    let body = format!("<script>const data = '{marker}';</script>");
    let reflection_strategy =
        native_review_strategy_ref(NativeWebReviewActionKind::ReflectionContextQueryPair);
    let reflection = observe(
        &observer,
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        DecisionExecutionStage::Active,
        &reflection_contract.candidate_url,
        &HeaderMap::new(),
        200,
        Some("text/html"),
        Some(body.as_bytes()),
        NativeWebReviewActionKind::ReflectionContextQueryPair.executor_id(),
        Some(&reflection_strategy),
        false,
    )
    .unwrap();
    assert_eq!(
        values(&reflection),
        vec![
            (NATIVE_WEB_REVIEW_RESPONSE_MARKER, "active-candidate"),
            (HTML_REFLECTION_CONTEXT, "script-element-content"),
            (HTML_ATTRIBUTE_SOURCE_STATUS, "absent"),
            (HTML_ATTRIBUTE_SOURCE_QUOTE_MODE, "none"),
            (HTML_ATTRIBUTE_SOURCE_ELEMENT, "none"),
            (HTML_ATTRIBUTE_SOURCE_NAME, "none"),
            (HTML_ATTRIBUTE_SOURCE_CONTEXT, "none"),
            (JAVASCRIPT_SOURCE_STATUS, "exact-script-anchor"),
            (JAVASCRIPT_SOURCE_SCRIPT_KIND, "classic-javascript"),
            (JAVASCRIPT_SOURCE_CONTEXT, "single-quoted-string"),
            (JAVASCRIPT_SOURCE_SCRIPT_ORDINAL, "0"),
        ]
    );

    for debug in [
        format!("{observer:?}"),
        format!("{cors:?}"),
        format!("{redirect:?}"),
        format!("{reflection:?}"),
    ] {
        assert!(!debug.contains(seeds.cors_origin()));
        assert!(!debug.contains(seeds.external_url()));
        assert!(!debug.contains(body.as_str()));
    }
}

#[test]
fn reflection_observer_commits_only_bounded_source_anchor_fields() {
    let root = root();
    let seeds = seeds();
    let observer = AssessmentReviewObserverSet::new_with_sql(
        root,
        seeds.clone(),
        None,
        Some(QUERY_PARAMETER),
        None,
        None,
    )
    .unwrap();
    let contract = observer.reflection.as_ref().unwrap();
    let marker = seeds.reflection_candidate_marker();
    let strategy =
        native_review_strategy_ref(NativeWebReviewActionKind::ReflectionContextQueryPair);
    for (body, quote_mode, element, attribute, context) in [
        (
            format!("<div title=\"{marker}\"></div>"),
            "double-quoted",
            "div",
            "title",
            "attribute-value",
        ),
        (
            format!("<a href='{marker}'>x</a>"),
            "single-quoted",
            "a",
            "href",
            "uri-attribute",
        ),
        (
            format!("<button onclick={marker}>x</button>"),
            "unquoted",
            "button",
            "onclick",
            "event-handler-attribute",
        ),
    ] {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::ReflectionContextQueryPair,
            DecisionExecutionStage::Active,
            &contract.candidate_url,
            &HeaderMap::new(),
            200,
            Some("text/html"),
            Some(body.as_bytes()),
            NativeWebReviewActionKind::ReflectionContextQueryPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        let projected = values(&evidence);
        for expected in [
            (HTML_ATTRIBUTE_SOURCE_STATUS, "exact-attribute-anchor"),
            (HTML_ATTRIBUTE_SOURCE_QUOTE_MODE, quote_mode),
            (HTML_ATTRIBUTE_SOURCE_ELEMENT, element),
            (HTML_ATTRIBUTE_SOURCE_NAME, attribute),
            (HTML_ATTRIBUTE_SOURCE_CONTEXT, context),
        ] {
            assert!(projected.contains(&expected), "{projected:?}");
        }
        let debug = format!("{evidence:?}");
        assert!(!debug.contains(&marker));
        assert!(!debug.contains(&body));
    }
}

#[test]
fn redirect_projection_accepts_only_the_closed_redirect_status_set() {
    let root = root();
    let seeds = seeds();
    let observer =
        AssessmentReviewObserverSet::new(root.clone(), seeds.clone(), Some(QUERY_PARAMETER))
            .unwrap();
    let mut candidate_url = root;
    candidate_url
        .query_pairs_mut()
        .append_pair(QUERY_PARAMETER, seeds.external_url());
    let strategy =
        native_review_strategy_ref(NativeWebReviewActionKind::RedirectReflectionQueryPair);

    for status in [301, 302, 303, 307, 308] {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Active,
            &candidate_url,
            &headers(&[("location", seeds.external_url())]),
            status,
            None,
            None,
            NativeWebReviewActionKind::RedirectReflectionQueryPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        assert!(values(&evidence).contains(&(REDIRECT_STATUS_RELATION, "redirect")));
    }

    for status in [300, 304, 305, 306, 399] {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Active,
            &candidate_url,
            &headers(&[("location", seeds.external_url())]),
            status,
            None,
            None,
            NativeWebReviewActionKind::RedirectReflectionQueryPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        assert!(values(&evidence).contains(&(REDIRECT_STATUS_RELATION, "other")));
    }
}

#[test]
fn cors_status_projection_retains_only_a_fixed_vocabulary_class() {
    let root = root();
    let observer = AssessmentReviewObserverSet::new(root.clone(), seeds(), None).unwrap();
    let strategy = native_review_strategy_ref(NativeWebReviewActionKind::CorsPolicyPair);

    for (status, expected) in [
        (199, "informational"),
        (200, "successful"),
        (302, "redirection"),
        (404, "client-error"),
        (500, "server-error"),
        (600, "other"),
    ] {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::CorsPolicyPair,
            DecisionExecutionStage::Passive,
            &root,
            &HeaderMap::new(),
            status,
            None,
            None,
            NativeWebReviewActionKind::CorsPolicyPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        let projected = values(&evidence);
        assert!(projected.contains(&(CORS_HTTP_STATUS_CLASS, expected)));
        let raw_status = status.to_string();
        assert!(projected
            .iter()
            .all(|(_, value)| *value != raw_status.as_str()));
    }
}

#[test]
fn unrelated_actions_are_ignored_but_malformed_recognized_actions_fail_closed() {
    let root = root();
    let seeds = seeds();
    let observer =
        AssessmentReviewObserverSet::new(root.clone(), seeds, Some(QUERY_PARAMETER)).unwrap();
    let projection = ReviewResponseProjection::empty();
    let passive = passive_response_projection_for_test(&[]);
    let ids = (0..7).map(|_| EvidenceId::new()).collect::<Vec<_>>();
    let subject = subject();
    let unrelated =
        complete_http_response_observation_for_test(CompleteHttpResponseObservationTestInput {
            case_id: "",
            action_id: "web.action.bootstrap.http-evidence",
            executor_id: "wrong",
            hypothesis_id: "",
            has_payload_strategy: false,
            payload_strategy: None,
            applies_hypothesis_transition: true,
            stage: DecisionExecutionStage::Passive,
            subject: &subject,
            method: HttpProbeMethod::Head,
            requested_url: &root,
            status: 200,
            media_type: None,
            reliability: ConfidenceScore::MAX,
            complete_body: None,
            request_method_evidence_id: Some(&ids[0]),
            request_url_evidence_id: Some(&ids[1]),
            response_status_evidence_id: Some(&ids[2]),
            response_final_url_evidence_id: Some(&ids[3]),
            response_media_type_evidence_id: None,
            response_body_truncated_evidence_id: Some(&ids[5]),
            response_body_digest_evidence_id: Some(&ids[6]),
            passive_response_projection: &passive,
            review_response_projection: Some(&projection),
        });
    assert!(observer.observe(unrelated).unwrap().is_empty());

    let strategy = native_review_strategy_ref(NativeWebReviewActionKind::CorsPolicyPair);
    assert!(matches!(
        observe(
            &observer,
            NativeWebReviewActionKind::CorsPolicyPair,
            DecisionExecutionStage::Passive,
            &root,
            &HeaderMap::new(),
            200,
            None,
            None,
            NativeWebReviewActionKind::RedirectReflectionQueryPair.executor_id(),
            Some(&strategy),
            false,
        ),
        Err(HttpEvidenceError::AssessmentObserverInvariant {
            invariant: "native-review-action-contract"
        })
    ));
    assert!(matches!(
        observe(
            &observer,
            NativeWebReviewActionKind::CorsPolicyPair,
            DecisionExecutionStage::Passive,
            &root,
            &HeaderMap::new(),
            200,
            None,
            None,
            NativeWebReviewActionKind::CorsPolicyPair.executor_id(),
            Some(&strategy),
            true,
        ),
        Err(HttpEvidenceError::AssessmentObserverInvariant { .. })
    ));
}

#[test]
fn reflection_context_requires_complete_utf8_html_and_exact_request_shape() {
    let root = root();
    let seeds = seeds();
    let observer =
        AssessmentReviewObserverSet::new(root.clone(), seeds.clone(), Some(QUERY_PARAMETER))
            .unwrap();
    let strategy =
        native_review_strategy_ref(NativeWebReviewActionKind::ReflectionContextQueryPair);
    let contract = observer.reflection.as_ref().unwrap();

    for (media_type, body, expected) in [
        (Some("text/html"), None, "incomplete"),
        (Some("application/json"), None, "not-applicable"),
        (None, Some(b"{}".as_slice()), "incomplete"),
        (Some("text/html"), Some([0xff].as_slice()), "incomplete"),
    ] {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::ReflectionContextQueryPair,
            DecisionExecutionStage::Active,
            &contract.candidate_url,
            &HeaderMap::new(),
            200,
            media_type,
            body,
            NativeWebReviewActionKind::ReflectionContextQueryPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        let projected = values(&evidence);
        assert_eq!(
            projected
                .iter()
                .find(|(property, _)| *property == HTML_REFLECTION_CONTEXT),
            Some(&(HTML_REFLECTION_CONTEXT, expected))
        );
        let expected_source = if expected == "not-applicable" {
            "unsupported"
        } else {
            "incomplete"
        };
        assert_eq!(
            projected
                .iter()
                .find(|(property, _)| *property == HTML_ATTRIBUTE_SOURCE_STATUS),
            Some(&(HTML_ATTRIBUTE_SOURCE_STATUS, expected_source))
        );
        assert_eq!(
            projected
                .iter()
                .find(|(property, _)| *property == JAVASCRIPT_SOURCE_STATUS),
            Some(&(JAVASCRIPT_SOURCE_STATUS, expected_source))
        );
    }

    let mut wrong_name = root.clone();
    wrong_name
        .query_pairs_mut()
        .append_pair("next", &seeds.reflection_candidate_marker());
    assert!(matches!(
        observe(
            &observer,
            NativeWebReviewActionKind::ReflectionContextQueryPair,
            DecisionExecutionStage::Active,
            &wrong_name,
            &HeaderMap::new(),
            200,
            Some("text/html"),
            Some(b"<p>ordinary</p>"),
            NativeWebReviewActionKind::ReflectionContextQueryPair.executor_id(),
            Some(&strategy),
            false,
        ),
        Err(HttpEvidenceError::AssessmentObserverInvariant { .. })
    ));
}

#[test]
fn xss_html_text_family_requires_one_exact_candidate_specific_node_boundary() {
    let root = root();
    let seeds = seeds();
    let observer =
        AssessmentReviewObserverSet::new_xss(root, seeds, QUERY_PARAMETER, html_text_selection())
            .unwrap();
    let contract = observer.xss.as_ref().unwrap();
    let strategy = native_review_strategy_ref(NativeWebReviewActionKind::XssStructuralQueryPair);
    let control = observe(
        &observer,
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Passive,
        &contract.control_url,
        &HeaderMap::new(),
        200,
        Some("text/html"),
        Some(b"<p>matched control</p>"),
        NativeWebReviewActionKind::XssStructuralQueryPair.executor_id(),
        Some(&strategy),
        false,
    )
    .unwrap();
    assert_eq!(
        values(&control).last(),
        Some(&(XSS_STRUCTURAL_RELATION, "encoded-or-inert"))
    );

    let candidate = observe(
        &observer,
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Active,
        &contract.candidate_url,
        &HeaderMap::new(),
        200,
        Some("text/html"),
        Some(contract.probe.parts().candidate_value.as_bytes()),
        NativeWebReviewActionKind::XssStructuralQueryPair.executor_id(),
        Some(&strategy),
        false,
    )
    .unwrap();
    assert_eq!(
        values(&candidate).last(),
        Some(&(XSS_STRUCTURAL_RELATION, "structural-boundary-observed"))
    );

    let encoded = format!(
        "<p>{}</p>",
        contract
            .probe
            .parts()
            .candidate_value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    );
    let candidate = observe(
        &observer,
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Active,
        &contract.candidate_url,
        &HeaderMap::new(),
        200,
        Some("text/html"),
        Some(encoded.as_bytes()),
        NativeWebReviewActionKind::XssStructuralQueryPair.executor_id(),
        Some(&strategy),
        false,
    )
    .unwrap();
    assert_eq!(
        values(&candidate).last(),
        // Encoding removes both the exact raw candidate and its parser-visible
        // boundary. `ReflectedSameContext` remains reserved for an exact raw
        // candidate that survives without establishing the required node.
        Some(&(XSS_STRUCTURAL_RELATION, "encoded-or-inert"))
    );
}

#[test]
fn xss_seed_identity_is_pinned_canonical_and_redacted() {
    const EXPECTED_IDENTITY: &str = "cbde631857b638780e0cd315f53a6801";
    let seeds = seeds();
    assert_eq!(seeds.reflection_identity().len(), 32);
    assert!(seeds
        .reflection_identity()
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    assert_eq!(seeds.reflection_identity(), EXPECTED_IDENTITY);
    assert!(!format!("{seeds:?}").contains(EXPECTED_IDENTITY));
}

#[test]
fn production_derived_xss_candidate_bytes_and_matcher_share_one_identity() {
    const IDENTITY: &str = "0123456789abcdef0123456789abcdef";
    const EXPECTED: &str =
        "<span data-venom-xss-boundary-token=\"0123456789abcdef0123456789abcdef\"></span>";
    let parts = XssStructuralProbeParts::derive_values(html_text_selection(), IDENTITY).unwrap();
    assert_eq!(parts.identity, IDENTITY);
    assert_eq!(parts.candidate_value.as_bytes(), EXPECTED.as_bytes());
    assert_eq!(
        validate_exact_xss_html_boundary_fragment(&parts.candidate_value, &parts.identity),
        ExactXssBoundaryMatch::Matched
    );
    let probe = parts.validate().unwrap();
    assert_eq!(probe.parts().identity, IDENTITY);
    assert_eq!(probe.parts().candidate_value, EXPECTED);
}

#[test]
fn xss_metadata_only_families_never_upgrade_same_context_reflection() {
    for family in [
        XssProbeFamily::UriAttributeStructure,
        XssProbeFamily::EventHandlerStructure,
        XssProbeFamily::ScriptContentStructure,
    ] {
        assert!(!family.is_v1_executable());
        assert!(super::super::web_assessment::select_xss_probe_families(
            family.compatible_context(),
            &AttributeSourceResult::Absent,
            &JavaScriptSourceResult::Absent,
        )
        .is_empty());
    }
}

#[test]
fn xss_structural_analysis_fails_closed_for_truncation_and_non_html_media() {
    let root = root();
    let observer =
        AssessmentReviewObserverSet::new_xss(root, seeds(), QUERY_PARAMETER, html_text_selection())
            .unwrap();
    let contract = observer.xss.as_ref().unwrap();
    let strategy = native_review_strategy_ref(NativeWebReviewActionKind::XssStructuralQueryPair);
    for (media_type, body, expected) in [
        (Some("text/html"), None, "incomplete"),
        (
            Some("application/json"),
            Some(b"{}".as_slice()),
            "unsupported",
        ),
        (None, Some(b"text".as_slice()), "incomplete"),
    ] {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::XssStructuralQueryPair,
            DecisionExecutionStage::Active,
            &contract.candidate_url,
            &HeaderMap::new(),
            200,
            media_type,
            body,
            NativeWebReviewActionKind::XssStructuralQueryPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        assert_eq!(
            values(&evidence).last(),
            Some(&(XSS_STRUCTURAL_RELATION, expected))
        );
    }
}

#[test]
fn quote_aware_attribute_families_require_exact_host_sink_dom_boundaries() {
    for (element, attribute, delimiter, quote_mode, family) in [
        (
            "div",
            "title",
            "\"",
            AttributeQuoteMode::DoubleQuoted,
            XssProbeFamily::AttributeValueBoundary,
        ),
        (
            "div",
            "title",
            "'",
            AttributeQuoteMode::SingleQuoted,
            XssProbeFamily::AttributeValueBoundary,
        ),
        (
            "div",
            "title",
            "",
            AttributeQuoteMode::Unquoted,
            XssProbeFamily::AttributeValueBoundary,
        ),
        (
            "a",
            "href",
            "\"",
            AttributeQuoteMode::DoubleQuoted,
            XssProbeFamily::UriAttributeBoundary,
        ),
        (
            "a",
            "href",
            "'",
            AttributeQuoteMode::SingleQuoted,
            XssProbeFamily::UriAttributeBoundary,
        ),
        (
            "a",
            "href",
            "",
            AttributeQuoteMode::Unquoted,
            XssProbeFamily::UriAttributeBoundary,
        ),
        (
            "button",
            "onclick",
            "\"",
            AttributeQuoteMode::DoubleQuoted,
            XssProbeFamily::EventHandlerAttributeBoundary,
        ),
        (
            "button",
            "onclick",
            "'",
            AttributeQuoteMode::SingleQuoted,
            XssProbeFamily::EventHandlerAttributeBoundary,
        ),
        (
            "button",
            "onclick",
            "",
            AttributeQuoteMode::Unquoted,
            XssProbeFamily::EventHandlerAttributeBoundary,
        ),
    ] {
        let selection = attribute_xss_selection(element, attribute, delimiter);
        assert_eq!(selection.family(), family);
        assert_eq!(selection.quote_mode(), Some(quote_mode));
        assert_eq!(
            selection.action_kind(),
            NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
        );
        let observer = AssessmentReviewObserverSet::new_xss(
            root(),
            seeds(),
            QUERY_PARAMETER,
            selection.clone(),
        )
        .unwrap();
        let contract = observer.xss.as_ref().unwrap();
        let strategy = native_review_strategy_ref(selection.action_kind());
        let control_body = format!(
            "<{element} {attribute}={delimiter}{}{delimiter}></{element}>",
            contract.probe.parts().control_value,
        );
        let control = observe(
            &observer,
            selection.action_kind(),
            DecisionExecutionStage::Passive,
            &contract.control_url,
            &HeaderMap::new(),
            200,
            Some("text/html"),
            Some(control_body.as_bytes()),
            selection.action_kind().executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        assert_eq!(
            values(&control).last(),
            Some(&(XSS_STRUCTURAL_RELATION, "encoded-or-inert"))
        );

        let candidate_body = format!(
            "<{element} {attribute}={delimiter}{}{delimiter}></{element}>",
            contract.probe.parts().candidate_value,
        );
        let candidate = observe(
            &observer,
            selection.action_kind(),
            DecisionExecutionStage::Active,
            &contract.candidate_url,
            &HeaderMap::new(),
            200,
            Some("text/html"),
            Some(candidate_body.as_bytes()),
            selection.action_kind().executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        let projected = values(&candidate);
        assert!(projected.contains(&(XSS_PROBE_FAMILY, family.stable_id())));
        assert!(projected.contains(&(XSS_PROBE_VARIANT, selection.variant_id())));
        assert_eq!(
            projected.last(),
            Some(&(XSS_STRUCTURAL_RELATION, "structural-boundary-observed"))
        );
    }
}

#[test]
fn ledger_url_contract_rejects_cross_name_and_cross_seed_candidates() {
    let root = root();
    let seeds = seeds();
    let observer =
        AssessmentReviewObserverSet::new(root.clone(), seeds.clone(), Some(QUERY_PARAMETER))
            .unwrap();
    let contract = observer.redirect.as_ref().unwrap();
    let exact = EvidenceValue::Text(contract.candidate_url.to_string());
    assert!(requested_url_value_matches(
        &exact,
        &root,
        Some(contract),
        DecisionExecutionStage::Active,
        NativeWebReviewActionKind::RedirectReflectionQueryPair,
    ));

    let mut cross_name = root.clone();
    cross_name
        .query_pairs_mut()
        .append_pair("next", seeds.external_url());
    assert!(!requested_url_value_matches(
        &EvidenceValue::Text(cross_name.to_string()),
        &root,
        Some(contract),
        DecisionExecutionStage::Active,
        NativeWebReviewActionKind::RedirectReflectionQueryPair,
    ));

    let mut cross_seed = root.clone();
    cross_seed.query_pairs_mut().append_pair(
        QUERY_PARAMETER,
        "https://foreign.review.invalid/venom-review",
    );
    assert!(!requested_url_value_matches(
        &EvidenceValue::Text(cross_seed.to_string()),
        &root,
        Some(contract),
        DecisionExecutionStage::Active,
        NativeWebReviewActionKind::RedirectReflectionQueryPair,
    ));
}

fn fake_id(label: &str) -> EvidenceId {
    EvidenceId::parse(format!("evidence:native-review:{label}")).unwrap()
}

fn fake_observation(
    kind: NativeWebReviewActionKind,
    stage: DecisionExecutionStage,
    response: CommittedReviewResponse,
    active_pair_success: bool,
    suffix: &str,
) -> CommittedAssessmentReviewObservation {
    let mut property_evidence = BTreeMap::new();
    let evidence_ids = expected_properties(kind)
        .iter()
        .copied()
        .map(|property| {
            let id = fake_id(&format!("{suffix}:{}", property.name()));
            property_evidence.insert(property, id.clone());
            id
        })
        .collect();
    CommittedAssessmentReviewObservation {
        kind,
        subject: subject(),
        case_id: CASE_ID.to_owned(),
        hypothesis_id: HYPOTHESIS_ID.to_owned(),
        stage,
        response,
        evidence_ids,
        property_evidence,
        active_pair_success,
    }
}

#[test]
fn exact_cors_relationship_is_review_only_and_requires_disjoint_verified_pair() {
    let control = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::Cors {
            status: ReviewHttpStatusClass::Successful,
            allow_origin: CorsAllowOriginRelation::Missing,
            allow_credentials: CorsAllowCredentialsRelation::Missing,
            vary_origin: VaryOriginRelation::Missing,
        },
        false,
        "cors-control",
    );
    let mut candidate = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::Cors {
            status: ReviewHttpStatusClass::Successful,
            allow_origin: CorsAllowOriginRelation::ExactRequestOrigin,
            allow_credentials: CorsAllowCredentialsRelation::True,
            vary_origin: VaryOriginRelation::ContainsOrigin,
        },
        true,
        "cors-candidate",
    );
    let mut output = Vec::new();
    append_pair_candidates(&control, &candidate, None, &mut output);
    assert_eq!(output.len(), 1);
    assert_eq!(
        output[0].disposition(),
        NativeReviewDisposition::NeedsReview
    );
    assert!(output[0].query_parameter().is_none());
    assert_eq!(
        output[0].cors_status_relationship(),
        Some(CorsStatusRelationship::MatchedSuccessful)
    );
    assert_eq!(output[0].control_evidence_ids().len(), 3);
    assert_eq!(output[0].candidate_evidence_ids().len(), 5);
    assert!(disjoint(
        output[0].control_evidence_ids(),
        output[0].candidate_evidence_ids()
    ));

    candidate.active_pair_success = false;
    output.clear();
    append_pair_candidates(&control, &candidate, None, &mut output);
    assert!(output.is_empty());

    candidate.active_pair_success = true;
    candidate.evidence_ids[0] = control.evidence_ids[0].clone();
    output.clear();
    append_pair_candidates(&control, &candidate, None, &mut output);
    assert!(output.is_empty());
}

#[test]
fn cors_status_divergence_and_error_only_pairs_never_produce_review_candidates() {
    let successful_control = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::Cors {
            status: ReviewHttpStatusClass::Successful,
            allow_origin: CorsAllowOriginRelation::Missing,
            allow_credentials: CorsAllowCredentialsRelation::Missing,
            vary_origin: VaryOriginRelation::Missing,
        },
        false,
        "cors-status-success-control",
    );
    let error_candidate = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::Cors {
            status: ReviewHttpStatusClass::ServerError,
            allow_origin: CorsAllowOriginRelation::ExactRequestOrigin,
            allow_credentials: CorsAllowCredentialsRelation::True,
            vary_origin: VaryOriginRelation::ContainsOrigin,
        },
        true,
        "cors-status-error-candidate",
    );
    let mut output = Vec::new();
    append_pair_candidates(&successful_control, &error_candidate, None, &mut output);
    assert!(
        output.is_empty(),
        "a status-divergent pair is not comparable"
    );

    let error_control = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::Cors {
            status: ReviewHttpStatusClass::ServerError,
            allow_origin: CorsAllowOriginRelation::Missing,
            allow_credentials: CorsAllowCredentialsRelation::Missing,
            vary_origin: VaryOriginRelation::Missing,
        },
        false,
        "cors-status-error-control",
    );
    output.clear();
    append_pair_candidates(&error_control, &error_candidate, None, &mut output);
    assert!(
        output.is_empty(),
        "matching error responses are not CORS claims"
    );
}

#[test]
fn exact_pair_completion_rejects_cross_case_and_cross_hypothesis_observations() {
    let mut ledger =
        CommittedAssessmentReviewLedger::new(root(), seeds(), Some(QUERY_PARAMETER)).unwrap();
    let response = CommittedReviewResponse::Cors {
        status: ReviewHttpStatusClass::Successful,
        allow_origin: CorsAllowOriginRelation::Missing,
        allow_credentials: CorsAllowCredentialsRelation::Missing,
        vary_origin: VaryOriginRelation::Missing,
    };
    let control = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Passive,
        response.clone(),
        false,
        "control",
    );
    let mut candidate = fake_observation(
        NativeWebReviewActionKind::CorsPolicyPair,
        DecisionExecutionStage::Active,
        response,
        true,
        "candidate",
    );
    candidate.case_id = "case:cross-case".to_owned();
    ledger.observations.insert(
        ReviewReceiptKey {
            kind: control.kind,
            case_id: control.case_id.clone(),
            stage: control.stage,
        },
        control.clone(),
    );
    ledger.observations.insert(
        ReviewReceiptKey {
            kind: candidate.kind,
            case_id: candidate.case_id.clone(),
            stage: candidate.stage,
        },
        candidate.clone(),
    );
    assert!(!ledger.pair_is_complete(NativeWebReviewActionKind::CorsPolicyPair));

    ledger.observations.clear();
    candidate.case_id = control.case_id.clone();
    candidate.hypothesis_id = "hypothesis:cross-hypothesis".to_owned();
    ledger.observations.insert(
        ReviewReceiptKey {
            kind: control.kind,
            case_id: control.case_id.clone(),
            stage: control.stage,
        },
        control,
    );
    ledger.observations.insert(
        ReviewReceiptKey {
            kind: candidate.kind,
            case_id: candidate.case_id.clone(),
            stage: candidate.stage,
        },
        candidate,
    );
    assert!(!ledger.pair_is_complete(NativeWebReviewActionKind::CorsPolicyPair));
}

#[test]
fn redirect_and_script_reflection_remain_distinct_needs_review_candidates() {
    let control = fake_observation(
        NativeWebReviewActionKind::RedirectReflectionQueryPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::Redirect {
            status: ReviewStatusRelation::Other,
            location: LocationRelation::Missing,
        },
        false,
        "redirect-control",
    );
    let candidate = fake_observation(
        NativeWebReviewActionKind::RedirectReflectionQueryPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::Redirect {
            status: ReviewStatusRelation::Redirect,
            location: LocationRelation::ExactExternalQueryValue,
        },
        true,
        "redirect-candidate",
    );
    let mut output = Vec::new();
    append_pair_candidates(&control, &candidate, Some(QUERY_PARAMETER), &mut output);
    assert_eq!(output.len(), 1);
    assert_eq!(
        output[0].disposition(),
        NativeReviewDisposition::NeedsReview
    );
    assert_eq!(output[0].query_parameter(), Some(QUERY_PARAMETER));

    let reflection_control = fake_observation(
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::Reflection {
            reflection: ExactHtmlReflectionContext::Absent,
            attribute_source: AttributeSourceResult::Absent,
            javascript_source: JavaScriptSourceResult::Absent,
        },
        false,
        "context-control",
    );
    let reflection_candidate = fake_observation(
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::Reflection {
            reflection: ExactHtmlReflectionContext::ScriptElementContent,
            attribute_source: AttributeSourceResult::Absent,
            javascript_source: JavaScriptSourceResult::Absent,
        },
        true,
        "context-candidate",
    );
    append_pair_candidates(
        &reflection_control,
        &reflection_candidate,
        Some(QUERY_PARAMETER),
        &mut output,
    );
    assert_eq!(output.len(), 2);
    assert_eq!(
        output[1].reflection_context(),
        Some(ReviewReflectionContext::ScriptElementContent)
    );
}

#[test]
fn inert_reflection_is_informational_and_incomplete_or_control_reflection_yields_no_claim() {
    let base_response = CommittedReviewResponse::Reflection {
        reflection: ExactHtmlReflectionContext::Absent,
        attribute_source: AttributeSourceResult::Absent,
        javascript_source: JavaScriptSourceResult::Absent,
    };
    let control = fake_observation(
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        DecisionExecutionStage::Passive,
        base_response,
        false,
        "reflection-control",
    );
    let mut candidate = fake_observation(
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::Reflection {
            reflection: ExactHtmlReflectionContext::HtmlComment,
            attribute_source: AttributeSourceResult::Absent,
            javascript_source: JavaScriptSourceResult::Absent,
        },
        true,
        "reflection-candidate",
    );
    let mut output = Vec::new();
    append_pair_candidates(&control, &candidate, Some(QUERY_PARAMETER), &mut output);
    assert_eq!(output.len(), 1);
    assert_eq!(
        output[0].disposition(),
        NativeReviewDisposition::Informational
    );

    candidate.response = CommittedReviewResponse::Reflection {
        reflection: ExactHtmlReflectionContext::Incomplete,
        attribute_source: AttributeSourceResult::Incomplete,
        javascript_source: JavaScriptSourceResult::Incomplete,
    };
    output.clear();
    append_pair_candidates(&control, &candidate, Some(QUERY_PARAMETER), &mut output);
    assert!(output.is_empty());

    let reflected_control = fake_observation(
        NativeWebReviewActionKind::ReflectionContextQueryPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::Reflection {
            reflection: ExactHtmlReflectionContext::HtmlText,
            attribute_source: AttributeSourceResult::Absent,
            javascript_source: JavaScriptSourceResult::Absent,
        },
        false,
        "reflected-control",
    );
    candidate.response = CommittedReviewResponse::Reflection {
        reflection: ExactHtmlReflectionContext::EventHandlerAttribute,
        attribute_source: AttributeSourceResult::Absent,
        javascript_source: JavaScriptSourceResult::Absent,
    };
    output.clear();
    append_pair_candidates(
        &reflected_control,
        &candidate,
        Some(QUERY_PARAMETER),
        &mut output,
    );
    assert!(output.is_empty());
}

#[test]
fn xss_structural_candidate_requires_clean_control_and_exact_parser_boundary() {
    let family = XssProbeFamily::HtmlTextBoundary;
    let selection = html_text_selection();
    let variant = selection.variant_id();
    let mut ledger =
        CommittedAssessmentReviewLedger::new_xss(root(), seeds(), QUERY_PARAMETER, selection)
            .unwrap();
    let control = fake_observation(
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::XssStructural {
            family,
            variant,
            relation: XssStructuralRelation::EncodedOrInert,
        },
        false,
        "xss-control",
    );
    let mut candidate = fake_observation(
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::XssStructural {
            family,
            variant,
            relation: XssStructuralRelation::StructuralBoundaryObserved,
        },
        true,
        "xss-candidate",
    );
    let insert_pair = |ledger: &mut CommittedAssessmentReviewLedger,
                       control: CommittedAssessmentReviewObservation,
                       candidate: CommittedAssessmentReviewObservation| {
        ledger.observations.clear();
        for observation in [control, candidate] {
            ledger.observations.insert(
                ReviewReceiptKey {
                    kind: observation.kind,
                    case_id: observation.case_id.clone(),
                    stage: observation.stage,
                },
                observation,
            );
        }
    };
    insert_pair(&mut ledger, control.clone(), candidate.clone());
    let items = ledger.candidates();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].disposition(), NativeReviewDisposition::NeedsReview);
    assert_eq!(items[0].xss_family(), Some(family));
    assert_eq!(items[0].query_parameter(), Some(QUERY_PARAMETER));

    candidate.response = CommittedReviewResponse::XssStructural {
        family,
        variant,
        relation: XssStructuralRelation::ReflectedSameContext,
    };
    insert_pair(&mut ledger, control.clone(), candidate.clone());
    assert!(ledger.candidates().is_empty());

    let reflected_control = fake_observation(
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::XssStructural {
            family,
            variant,
            relation: XssStructuralRelation::ReflectedSameContext,
        },
        false,
        "xss-reflected-control",
    );
    candidate.response = CommittedReviewResponse::XssStructural {
        family,
        variant,
        relation: XssStructuralRelation::StructuralBoundaryObserved,
    };
    insert_pair(&mut ledger, reflected_control, candidate);
    assert!(ledger.candidates().is_empty());

    let boundary_control = fake_observation(
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Passive,
        CommittedReviewResponse::XssStructural {
            family,
            variant,
            relation: XssStructuralRelation::StructuralBoundaryObserved,
        },
        false,
        "xss-preexisting-boundary-control",
    );
    let boundary_candidate = fake_observation(
        NativeWebReviewActionKind::XssStructuralQueryPair,
        DecisionExecutionStage::Active,
        CommittedReviewResponse::XssStructural {
            family,
            variant,
            relation: XssStructuralRelation::StructuralBoundaryObserved,
        },
        true,
        "xss-preexisting-boundary-candidate",
    );
    insert_pair(&mut ledger, boundary_control, boundary_candidate);
    assert!(ledger.candidates().is_empty());
}

#[test]
fn observer_and_ledger_constructors_reject_ambiguous_authority() {
    let seeds = seeds();
    for invalid in [
        "https://review.test/account?existing=1",
        "https://review.test/account#fragment",
        "ftp://review.test/account",
    ] {
        assert!(AssessmentReviewObserverSet::new(
            Url::parse(invalid).unwrap(),
            seeds.clone(),
            Some(QUERY_PARAMETER),
        )
        .is_err());
    }
    assert!(matches!(
        AssessmentReviewObserverSet::new(root(), seeds.clone(), Some("bad parameter")),
        Err(AssessmentReviewObserverError::QueryParameter)
    ));
    assert!(CommittedAssessmentReviewLedger::new(root(), seeds, Some(QUERY_PARAMETER)).is_ok());
}

fn sql_observation(
    kind: NativeWebReviewActionKind,
    stage: DecisionExecutionStage,
    status: ReviewHttpStatusClass,
    structure: &str,
    active_success: bool,
    evidence_prefix: &str,
) -> CommittedAssessmentReviewObservation {
    fake_observation(
        kind,
        stage,
        CommittedReviewResponse::SqlStructural {
            status,
            body_structure: structure.to_owned(),
        },
        active_success,
        evidence_prefix,
    )
}

fn sql_pair_set(
    candidate_status: ReviewHttpStatusClass,
    candidate_structure: &str,
    replay_candidate_status: ReviewHttpStatusClass,
    replay_candidate_structure: &str,
) -> [CommittedAssessmentReviewObservation; 4] {
    let control_structure =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let control = sql_observation(
        NativeWebReviewActionKind::SqlStructuralQueryPair,
        DecisionExecutionStage::Passive,
        ReviewHttpStatusClass::Successful,
        control_structure,
        false,
        "sql-control",
    );
    let candidate = sql_observation(
        NativeWebReviewActionKind::SqlStructuralQueryPair,
        DecisionExecutionStage::Active,
        candidate_status,
        candidate_structure,
        true,
        "sql-candidate",
    );
    let mut replay_control = sql_observation(
        NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
        DecisionExecutionStage::Passive,
        ReviewHttpStatusClass::Successful,
        control_structure,
        false,
        "sql-replay-control",
    );
    replay_control.case_id = "case:decision:2:sql-replay".to_owned();
    let mut replay_candidate = sql_observation(
        NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
        DecisionExecutionStage::Active,
        replay_candidate_status,
        replay_candidate_structure,
        true,
        "sql-replay-candidate",
    );
    replay_candidate.case_id = replay_control.case_id.clone();
    [control, candidate, replay_control, replay_candidate]
}

#[test]
fn sql_review_requires_two_repeatable_status_and_structure_differentials() {
    let changed = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let [control, candidate, replay_control, replay_candidate] = sql_pair_set(
        ReviewHttpStatusClass::ServerError,
        changed,
        ReviewHttpStatusClass::ServerError,
        changed,
    );
    let mut output = Vec::new();
    append_sql_candidate(
        &control,
        &candidate,
        &replay_control,
        &replay_candidate,
        "item",
        &mut output,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(
        output[0].disposition(),
        NativeReviewDisposition::NeedsReview
    );
    assert!(matches!(
        output[0],
        AssessmentReviewCandidate::SqlStructural(_)
    ));

    let mut repeated = Vec::new();
    append_sql_candidate(
        &control,
        &candidate,
        &replay_control,
        &replay_candidate,
        "item",
        &mut repeated,
    );
    assert_eq!(output, repeated);
}

#[test]
fn sql_text_only_identical_noisy_and_incomplete_observations_make_no_claim() {
    let same = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let changed = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    for (status, structure, replay_status, replay_structure) in [
        (
            ReviewHttpStatusClass::ServerError,
            same,
            ReviewHttpStatusClass::ServerError,
            same,
        ),
        (
            ReviewHttpStatusClass::Successful,
            changed,
            ReviewHttpStatusClass::Successful,
            changed,
        ),
        (
            ReviewHttpStatusClass::ServerError,
            changed,
            ReviewHttpStatusClass::ClientError,
            changed,
        ),
        (
            ReviewHttpStatusClass::ServerError,
            "incomplete",
            ReviewHttpStatusClass::ServerError,
            "incomplete",
        ),
    ] {
        let [control, candidate, replay_control, replay_candidate] =
            sql_pair_set(status, structure, replay_status, replay_structure);
        let mut output = Vec::new();
        append_sql_candidate(
            &control,
            &candidate,
            &replay_control,
            &replay_candidate,
            "item",
            &mut output,
        );
        assert!(output.is_empty());
    }
}

fn ssti_observation(
    kind: NativeWebReviewActionKind,
    stage: DecisionExecutionStage,
    status: ReviewHttpStatusClass,
    evaluation: SstiEvaluationRelation,
    active_success: bool,
    evidence_prefix: &str,
) -> CommittedAssessmentReviewObservation {
    fake_observation(
        kind,
        stage,
        CommittedReviewResponse::SstiStructural { status, evaluation },
        active_success,
        evidence_prefix,
    )
}

fn ssti_pair_set(
    candidate: SstiEvaluationRelation,
    replay_candidate: SstiEvaluationRelation,
) -> [CommittedAssessmentReviewObservation; 4] {
    let control = ssti_observation(
        NativeWebReviewActionKind::SstiStructuralQueryPair,
        DecisionExecutionStage::Passive,
        ReviewHttpStatusClass::Successful,
        SstiEvaluationRelation::Absent,
        false,
        "ssti-control",
    );
    let candidate = ssti_observation(
        NativeWebReviewActionKind::SstiStructuralQueryPair,
        DecisionExecutionStage::Active,
        ReviewHttpStatusClass::Successful,
        candidate,
        true,
        "ssti-candidate",
    );
    let mut replay_control = ssti_observation(
        NativeWebReviewActionKind::SstiStructuralQueryReplayPair,
        DecisionExecutionStage::Passive,
        ReviewHttpStatusClass::Successful,
        SstiEvaluationRelation::Absent,
        false,
        "ssti-replay-control",
    );
    replay_control.case_id = "case:decision:2:ssti-replay".to_owned();
    let mut replay_candidate = ssti_observation(
        NativeWebReviewActionKind::SstiStructuralQueryReplayPair,
        DecisionExecutionStage::Active,
        ReviewHttpStatusClass::Successful,
        replay_candidate,
        true,
        "ssti-replay-candidate",
    );
    replay_candidate.case_id = replay_control.case_id.clone();
    [control, candidate, replay_control, replay_candidate]
}

#[test]
fn ssti_review_requires_two_exact_evaluations_and_is_never_confirmed() {
    let [control, candidate, replay_control, replay_candidate] = ssti_pair_set(
        SstiEvaluationRelation::ExpectedEvaluation,
        SstiEvaluationRelation::ExpectedEvaluation,
    );
    let mut output = Vec::new();
    append_ssti_candidate(
        &control,
        &candidate,
        &replay_control,
        &replay_candidate,
        "item",
        &mut output,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(
        output[0].disposition(),
        NativeReviewDisposition::NeedsReview
    );
    assert!(matches!(
        output[0],
        AssessmentReviewCandidate::SstiStructural(_)
    ));

    let mut repeated = Vec::new();
    append_ssti_candidate(
        &control,
        &candidate,
        &replay_control,
        &replay_candidate,
        "item",
        &mut repeated,
    );
    assert_eq!(output, repeated);
}

#[test]
fn ssti_literal_static_error_noisy_wrong_replay_and_incomplete_make_no_claim() {
    for (candidate_relation, replay_relation) in [
        (
            SstiEvaluationRelation::LiteralReflection,
            SstiEvaluationRelation::LiteralReflection,
        ),
        (
            SstiEvaluationRelation::ExpectedEvaluation,
            SstiEvaluationRelation::Absent,
        ),
        (
            SstiEvaluationRelation::Absent,
            SstiEvaluationRelation::ExpectedEvaluation,
        ),
        (
            SstiEvaluationRelation::Unsupported,
            SstiEvaluationRelation::Unsupported,
        ),
        (
            SstiEvaluationRelation::Incomplete,
            SstiEvaluationRelation::ExpectedEvaluation,
        ),
    ] {
        let [control, candidate, replay_control, replay_candidate] =
            ssti_pair_set(candidate_relation, replay_relation);
        let mut output = Vec::new();
        append_ssti_candidate(
            &control,
            &candidate,
            &replay_control,
            &replay_candidate,
            "item",
            &mut output,
        );
        assert!(output.is_empty());
    }

    let [mut control, candidate, replay_control, replay_candidate] = ssti_pair_set(
        SstiEvaluationRelation::ExpectedEvaluation,
        SstiEvaluationRelation::ExpectedEvaluation,
    );
    control.response = CommittedReviewResponse::SstiStructural {
        status: ReviewHttpStatusClass::Successful,
        evaluation: SstiEvaluationRelation::ExpectedPresentInControl,
    };
    let mut output = Vec::new();
    append_ssti_candidate(
        &control,
        &candidate,
        &replay_control,
        &replay_candidate,
        "item",
        &mut output,
    );
    assert!(output.is_empty());

    let [control, mut candidate, replay_control, replay_candidate] = ssti_pair_set(
        SstiEvaluationRelation::ExpectedEvaluation,
        SstiEvaluationRelation::ExpectedEvaluation,
    );
    candidate.response = CommittedReviewResponse::SstiStructural {
        status: ReviewHttpStatusClass::ServerError,
        evaluation: SstiEvaluationRelation::ExpectedEvaluation,
    };
    output.clear();
    append_ssti_candidate(
        &control,
        &candidate,
        &replay_control,
        &replay_candidate,
        "item",
        &mut output,
    );
    assert!(output.is_empty());
}

#[test]
fn ssti_observer_classifies_literal_static_evaluated_unsupported_and_incomplete_bodies() {
    let observer =
        AssessmentReviewObserverSet::new_with_sql(root(), seeds(), None, None, None, Some("item"))
            .unwrap();
    let contract = observer.ssti.as_ref().unwrap();
    let probe = &contract.primary.probe;
    let strategy = native_review_strategy_ref(NativeWebReviewActionKind::SstiStructuralQueryPair);
    let cases = [
        (
            DecisionExecutionStage::Active,
            &contract.primary.candidate_url,
            Some(probe.candidate_value()),
            Some("text/html"),
            "literal-reflection",
        ),
        (
            DecisionExecutionStage::Active,
            &contract.primary.candidate_url,
            Some(probe.expected_value()),
            Some("text/html"),
            "expected-evaluation",
        ),
        (
            DecisionExecutionStage::Passive,
            &contract.primary.control_url,
            Some(probe.expected_value()),
            Some("text/html"),
            "expected-present-in-control",
        ),
        (
            DecisionExecutionStage::Active,
            &contract.primary.candidate_url,
            Some(probe.expected_value()),
            Some("application/octet-stream"),
            "unsupported",
        ),
        (
            DecisionExecutionStage::Active,
            &contract.primary.candidate_url,
            None,
            Some("text/html"),
            "incomplete",
        ),
    ];
    for (stage, url, body, media_type, expected) in cases {
        let evidence = observe(
            &observer,
            NativeWebReviewActionKind::SstiStructuralQueryPair,
            stage,
            url,
            &HeaderMap::new(),
            200,
            media_type,
            body.as_deref().map(str::as_bytes),
            NativeWebReviewActionKind::SstiStructuralQueryPair.executor_id(),
            Some(&strategy),
            false,
        )
        .unwrap();
        assert!(values(&evidence).contains(&(SSTI_EVALUATION_RELATION, expected)));
    }
}
