use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use venom_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    HttpEvidencePredicate, KnowledgePredicate,
};
use venom_scanner::{EntityExtractor, SemanticEntity, SemanticEntityType, SemanticExtractionLimits};

const SECRET_AUTH_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.s3ltdGVzdA";

#[derive(Debug, Deserialize)]
struct FixtureCollection {
    name: String,
    contract_class: ContractClass,
    #[serde(default)]
    limits: FixtureLimits,
    evidence: Vec<FixtureEvidence>,
    expected: FixtureExpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ContractClass {
    ProductionBacked,
    SyntheticExtractorContract,
    NegativeDeferred,
    BoundedMechanics,
}

impl ContractClass {
    fn expected_for_fixture(name: &str) -> Self {
        match name {
            "rest_request_url_and_method" => Self::ProductionBacked,
            "response_header_concepts" => Self::ProductionBacked,
            "jwt_or_bearer_auth_artifact" => Self::SyntheticExtractorContract,
            "session_cookie_name_is_not_a_credential" => Self::ProductionBacked,
            "graphql_request_surface" => Self::SyntheticExtractorContract,
            "dns_domain_and_ip_are_distinct" => Self::SyntheticExtractorContract,
            "unsupported_query_parameter_contract" => Self::NegativeDeferred,
            "technology_product_and_version_gap" => Self::SyntheticExtractorContract,
            "bounded_truncation_receipt" => Self::BoundedMechanics,
            _ => panic!("unknown fixture: {name}"),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct FixtureLimits {
    #[serde(default = "FixtureLimits::default_max_entities")]
    max_entities: usize,
    #[serde(default = "FixtureLimits::default_max_attribute_keys")]
    max_attribute_keys: usize,
    #[serde(default = "FixtureLimits::default_max_values_per_attribute")]
    max_values_per_attribute: usize,
    #[serde(default = "FixtureLimits::default_max_value_bytes")]
    max_value_bytes: usize,
    #[serde(default = "FixtureLimits::default_max_source_evidence_ids")]
    max_source_evidence_ids: usize,
    #[serde(default = "FixtureLimits::default_max_url_bytes")]
    max_url_bytes: usize,
}

impl FixtureLimits {
    const fn default_max_entities() -> usize {
        1000
    }

    const fn default_max_attribute_keys() -> usize {
        50
    }

    const fn default_max_values_per_attribute() -> usize {
        50
    }

    const fn default_max_value_bytes() -> usize {
        4096
    }

    const fn default_max_source_evidence_ids() -> usize {
        100
    }

    const fn default_max_url_bytes() -> usize {
        2048
    }

    fn extractor(&self) -> EntityExtractor {
        if self == &FixtureLimits::default() {
            EntityExtractor::new()
        } else {
            EntityExtractor::with_limits(
                SemanticExtractionLimits::new(
                    self.max_entities,
                    self.max_attribute_keys,
                    self.max_values_per_attribute,
                    self.max_value_bytes,
                    self.max_source_evidence_ids,
                    self.max_url_bytes,
                )
                .expect("fixture extractor limits must be valid"),
            )
        }
    }
}

impl Default for FixtureLimits {
    fn default() -> Self {
        Self {
            max_entities: Self::default_max_entities(),
            max_attribute_keys: Self::default_max_attribute_keys(),
            max_values_per_attribute: Self::default_max_values_per_attribute(),
            max_value_bytes: Self::default_max_value_bytes(),
            max_source_evidence_ids: Self::default_max_source_evidence_ids(),
            max_url_bytes: Self::default_max_url_bytes(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct FixtureEvidence {
    id: String,
    subject: String,
    kind: String,
    predicate_namespace: String,
    predicate_name: String,
    value: String,
    source_component: String,
    source_method: String,
    correlation_id: Option<String>,
    observed_at_ms: u64,
    reliability_percent: u8,
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    entities: Vec<FixtureExpectedEntity>,
    truncated: bool,
    dropped_entities: usize,
    dropped_attributes: usize,
    dropped_sources: usize,
}

#[derive(Debug, Deserialize)]
struct FixtureExpectedEntity {
    id: String,
    #[serde(rename = "entity_type")]
    kind: SemanticEntityType,
    attributes: BTreeMap<String, Vec<String>>,
    source_evidence_ids: Vec<String>,
}

const FIXTURES: &[&str] = &[
    include_str!("fixtures/semantic/rest_request_url_and_method.json"),
    include_str!("fixtures/semantic/response_header_concepts.json"),
    include_str!("fixtures/semantic/jwt_or_bearer_auth_artifact.json"),
    include_str!("fixtures/semantic/session_cookie_name_is_not_a_credential.json"),
    include_str!("fixtures/semantic/graphql_request_surface.json"),
    include_str!("fixtures/semantic/dns_domain_and_ip_are_distinct.json"),
    include_str!("fixtures/semantic/unsupported_query_parameter_contract.json"),
    include_str!("fixtures/semantic/technology_product_and_version_gap.json"),
    include_str!("fixtures/semantic/bounded_truncation_receipt.json"),
];

fn fixture(encoded: &str) -> FixtureCollection {
    serde_json::from_str(encoded).expect("fixture must deserialize")
}

fn build_evidence(raw: &FixtureEvidence) -> Evidence {
    let mut source = EvidenceSource::new(&raw.source_component, &raw.source_method)
        .expect("evidence source must be valid");
    if let Some(correlation_id) = raw.correlation_id.as_ref() {
        source = source
            .with_correlation_id(correlation_id)
            .expect("evidence correlation id must be valid");
    }

    Evidence::with_id_at(
        EvidenceId::parse(&raw.id).expect("evidence id must parse"),
        EntityId::new(&raw.subject).expect("subject must parse"),
        parse_kind(&raw.kind),
        KnowledgePredicate::new(&raw.predicate_namespace, &raw.predicate_name)
            .expect("fixture predicate must be valid"),
        EvidenceValue::Text(raw.value.clone()),
        source,
        ConfidenceScore::from_percent(raw.reliability_percent)
            .expect("confidence percent must be valid"),
        raw.observed_at_ms,
    )
}

fn parse_kind(raw: &str) -> EvidenceKind {
    match raw {
        "Http" => EvidenceKind::Http,
        "Network" => EvidenceKind::Network,
        "Dns" => EvidenceKind::Dns,
        "Authentication" => EvidenceKind::Authentication,
        "Technology" => EvidenceKind::Technology,
        "Content" => EvidenceKind::Content,
        "RateLimit" => EvidenceKind::RateLimit,
        "Timing" => EvidenceKind::Timing,
        "Tls" => EvidenceKind::Tls,
        _ => panic!("unsupported evidence kind in fixture: {raw}"),
    }
}

fn to_expected_entity(raw: &FixtureExpectedEntity) -> SemanticEntity {
    let mut attributes = BTreeMap::new();
    for (key, values) in &raw.attributes {
        attributes.insert(key.clone(), BTreeSet::from_iter(values.iter().cloned()));
    }
    let source_evidence_ids = raw
        .source_evidence_ids
        .iter()
        .map(|id| EvidenceId::parse(id).expect("expected source evidence id must parse"))
        .collect();

    SemanticEntity::new(
        EntityId::new(&raw.id).expect("expected entity id must parse"),
        raw.kind,
        attributes,
        source_evidence_ids,
    )
}

fn ensure_sorted_and_deduped_ids(entity: &SemanticEntity) {
    let ids = entity.source_evidence_ids();
    let mut sorted = ids.to_vec();
    sorted.sort();
    assert_eq!(sorted, ids, "{} source evidence ids must be sorted", entity.id());
    let deduped: Vec<_> = sorted.iter().collect::<BTreeSet<_>>().into_iter().cloned().collect();
    assert_eq!(deduped, ids, "{} source evidence ids must be deduplicated", entity.id());
}

fn fixture_evidence_by_name<'a>(
    fixture: &'a FixtureCollection,
    namespace: &str,
    name: &str,
) -> &'a FixtureEvidence {
    fixture
        .evidence
        .iter()
        .find(|e| e.predicate_namespace == namespace && e.predicate_name == name)
        .expect("required evidence should exist in fixture")
}

fn assert_fixture_contract_shape(fixture: &FixtureCollection) {
    assert_eq!(
        fixture.contract_class,
        ContractClass::expected_for_fixture(&fixture.name),
        "fixture {} has expected contract class",
        fixture.name
    );

    if fixture.contract_class != ContractClass::ProductionBacked {
        return;
    }

    match fixture.name.as_str() {
        "rest_request_url_and_method" => {
            let url = fixture_evidence_by_name(
                fixture,
                HttpEvidencePredicate::REQUEST_URL.namespace(),
                HttpEvidencePredicate::REQUEST_URL.name(),
            );
            assert_eq!(url.source_component, "http.evidence");
            assert_eq!(url.source_method, "request-url");

            let method = fixture_evidence_by_name(
                fixture,
                HttpEvidencePredicate::REQUEST_METHOD.namespace(),
                HttpEvidencePredicate::REQUEST_METHOD.name(),
            );
            assert_eq!(method.source_component, "http.evidence");
            assert_eq!(method.source_method, "request-method");
        }
        "response_header_concepts" => {
            let content_type = fixture_evidence_by_name(
                fixture,
                HttpEvidencePredicate::HEADER_CONTENT_TYPE.namespace(),
                HttpEvidencePredicate::HEADER_CONTENT_TYPE.name(),
            );
            let server = fixture_evidence_by_name(
                fixture,
                HttpEvidencePredicate::HEADER_SERVER.namespace(),
                HttpEvidencePredicate::HEADER_SERVER.name(),
            );

            assert_eq!(content_type.source_component, "http.evidence");
            assert_eq!(content_type.source_method, "response-header:content-type");
            assert_eq!(server.source_component, "http.evidence");
            assert_eq!(server.source_method, "response-header:server");
        }
        "session_cookie_name_is_not_a_credential" => {
            let cookie_name = fixture_evidence_by_name(
                fixture,
                HttpEvidencePredicate::COOKIE_NAME.namespace(),
                HttpEvidencePredicate::COOKIE_NAME.name(),
            );
            assert_eq!(cookie_name.source_component, "http.evidence");
            assert_eq!(cookie_name.source_method, "response-set-cookie-name");
        }
        _ => {}
    }
}

#[test]
fn semantic_fixtures_are_deterministic_and_match_expected() {
    for encoded in FIXTURES {
        let fixture = fixture(encoded);
        let extractor = fixture.limits.extractor();
        let evidence: Vec<Evidence> = fixture.evidence.iter().map(build_evidence).collect();
        let mut reversed = evidence.clone();
        reversed.reverse();

        let forward = extractor.extract_from_evidence(&evidence);
        let reversed = extractor.extract_from_evidence(&reversed);
        assert_fixture_contract_shape(&fixture);

        assert_eq!(
            forward,
            reversed,
            "fixture {} should be order independent on extraction",
            fixture.name
        );
        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reversed).unwrap(),
            "fixture {} should serialize byte-for-byte deterministically",
            fixture.name
        );

        let expected_entities: Vec<SemanticEntity> =
            fixture
                .expected
                .entities
                .iter()
                .map(to_expected_entity)
                .collect();
        assert_eq!(forward.entities, expected_entities, "fixture {} entities", fixture.name);
        assert_eq!(forward.truncated, fixture.expected.truncated, "fixture {} truncation", fixture.name);
        assert_eq!(
            forward.dropped_entities,
            fixture.expected.dropped_entities,
            "fixture {} dropped_entities",
            fixture.name
        );
        assert_eq!(
            forward.dropped_attributes,
            fixture.expected.dropped_attributes,
            "fixture {} dropped_attributes",
            fixture.name
        );
        assert_eq!(
            forward.dropped_sources,
            fixture.expected.dropped_sources,
            "fixture {} dropped_sources",
            fixture.name
        );

        for entity in &forward.entities {
            ensure_sorted_and_deduped_ids(entity);
            let encoded_entity = serde_json::to_string(entity).unwrap();
            let debug = format!("{entity:?}");
            assert!(!encoded_entity.contains(SECRET_AUTH_TOKEN), "fixture {} secret in entity json", fixture.name);
            assert!(!debug.contains(SECRET_AUTH_TOKEN), "fixture {} secret in entity debug", fixture.name);
        }

        match fixture.name.as_str() {
            "response_header_concepts" => {
                for entity in forward.entities {
                    assert_eq!(entity.attributes().len(), 1, "header entity has only name attribute");
                    assert!(entity.attributes().contains_key("name"));
                }
            },
            "unsupported_query_parameter_contract" => {
                assert!(
                    fixture.expected.entities.is_empty(),
                    "query parameter fixture must not produce entities"
                );
            },
            "session_cookie_name_is_not_a_credential" => {
                assert!(
                    !forward.entities.iter().any(|entity| entity.entity_type()
                        == SemanticEntityType::AuthArtifact),
                    "cookie names must not become auth artifacts"
                );
            },
            "jwt_or_bearer_auth_artifact" => {
                let auth = &forward.entities[0];
                assert_eq!(auth.entity_type(), SemanticEntityType::AuthArtifact);
                let auth_attrs = auth.attributes();
                assert_eq!(
                    auth_attrs
                        .get("auth_kind")
                        .expect("auth_kind must exist"),
                    &BTreeSet::from(["jwt".to_string()])
                );
                let hash = auth_attrs
                    .get("fingerprint")
                    .expect("fingerprint must exist")
                    .iter()
                    .next()
                    .expect("non-empty fingerprint")
                    .clone();
                assert_eq!(hash.len(), 64, "fingerprint remains stable length");
            },
            "bounded_truncation_receipt" => {
                assert!(forward.truncated);
                assert_eq!(forward.dropped_entities, 1);
                assert_eq!(forward.entities.len(), 1);
            }
            _ => {}
        }
    }
}
