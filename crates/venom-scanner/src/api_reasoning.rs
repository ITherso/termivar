//! Deterministic JSON, GraphQL, and paired-visibility reasoning.
//!
//! The profile is transport-neutral and opt-in. It recognizes disclosed API
//! representations and turns one already-paired visibility comparison into a
//! reviewable boundary hypothesis. It never combines independent principals,
//! responses, or UI/API observations and never declares a vulnerability.

use serde::Serialize;
use thiserror::Error;
use venom_core::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiResponseFormat, ApiSurfaceKind,
    ApiVisibilityBoundaryKind, ApiVisibilityDimension, ApiVisibilityPairKind, ApiVisibilityResult,
    ConceptId, EvidenceValue, HttpEvidencePredicate, HypothesisState, HypothesisStrength, Ontology,
    OntologyAxiom, OntologyConcept, OntologyError, PredicateDescriptor, Probability,
};

use crate::{
    knowledge::KnowledgeBase,
    rules::{
        EvidenceAggregation, EvidenceCalibration, EvidenceSelector, Expression,
        HypothesisConclusion, KnowledgeLayer, ReasoningRule, RuleEngine, RuleEngineError,
        RuleWrite,
    },
};

/// Number of concepts defined by [`StandardApiReasoning`].
pub const STANDARD_API_CONCEPT_COUNT: usize = 9;

/// Number of semantic axioms defined by [`StandardApiReasoning`].
pub const STANDARD_API_AXIOM_COUNT: usize = 6;

/// Number of deterministic rules defined by [`StandardApiReasoning`].
pub const STANDARD_API_RULE_COUNT: usize = 7;

/// Failures while constructing or installing the standard API profile.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardApiReasoningError {
    /// An ontology definition or relationship was invalid or conflicted.
    #[error(transparent)]
    Ontology(#[from] OntologyError),

    /// A reasoning rule was invalid or conflicted.
    #[error(transparent)]
    Rules(#[from] RuleEngineError),

    /// The shared vocabulary contains an API surface that this profile has not
    /// explicitly mapped to a deterministic rule.
    #[error("standard API reasoning profile does not support API surface `{surface}`")]
    UnsupportedApiSurface {
        /// Stable vocabulary value that was rejected.
        surface: String,
    },

    /// The shared vocabulary contains a visibility pair that this profile has
    /// not explicitly mapped to a deterministic boundary rule.
    #[error("standard API reasoning profile does not support visibility pair `{pair}`")]
    UnsupportedVisibilityPair {
        /// Stable vocabulary value that was rejected.
        pair: String,
    },
}

/// Counts of definitions added by one idempotent profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StandardApiInstallReport {
    concepts_inserted: usize,
    axioms_inserted: usize,
    rules_inserted: usize,
}

impl StandardApiInstallReport {
    /// Returns the number of newly registered concepts.
    pub const fn concepts_inserted(self) -> usize {
        self.concepts_inserted
    }

    /// Returns the number of newly registered semantic axioms.
    pub const fn axioms_inserted(self) -> usize {
        self.axioms_inserted
    }

    /// Returns the number of newly registered rules.
    pub const fn rules_inserted(self) -> usize {
        self.rules_inserted
    }
}

/// Validated deterministic JSON/GraphQL and visibility-boundary rule pack.
///
/// Generic JSON produces only a response-format hypothesis. GraphQL needs its
/// official response media type, a route signal, or an explicit paired
/// comparison. Visibility conclusions require exactly one atomic
/// [`venom_core::ApiVisibilityComparison`] evidence record.
///
/// # Examples
///
/// ```rust
/// use venom_scanner::{KnowledgeBase, RuleEngine, StandardApiReasoning};
///
/// let knowledge = KnowledgeBase::new();
/// let mut rules = RuleEngine::new();
/// let profile = StandardApiReasoning::new()?;
/// let installed = profile.install(&knowledge, &mut rules)?;
///
/// assert_eq!(installed.rules_inserted(), profile.rules().len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct StandardApiReasoning {
    concepts: Vec<OntologyConcept>,
    axioms: Vec<OntologyAxiom>,
    rules: Vec<ReasoningRule>,
}

impl StandardApiReasoning {
    /// Builds and validates the complete ontology and rule set.
    pub fn new() -> Result<Self, StandardApiReasoningError> {
        let concepts = standard_concepts()?;
        let axioms = standard_axioms()?;
        let rules = standard_rules()?;

        let mut validation = Ontology::new();
        for concept in &concepts {
            validation.add_concept(concept.clone())?;
        }
        for axiom in &axioms {
            validation.add_axiom(axiom.clone())?;
        }

        debug_assert_eq!(concepts.len(), STANDARD_API_CONCEPT_COUNT);
        debug_assert_eq!(axioms.len(), STANDARD_API_AXIOM_COUNT);
        debug_assert_eq!(rules.len(), STANDARD_API_RULE_COUNT);
        Ok(Self {
            concepts,
            axioms,
            rules,
        })
    }

    /// Installs the complete profile atomically and idempotently.
    ///
    /// Rule identities are preflighted on a clone before ontology state is
    /// changed. Ontology installation also uses a prospective clone, so a
    /// conflict leaves both registries unchanged.
    pub fn install(
        &self,
        knowledge: &KnowledgeBase,
        engine: &mut RuleEngine,
    ) -> Result<StandardApiInstallReport, StandardApiReasoningError> {
        let mut prospective_engine = engine.clone();
        let mut rules_inserted = 0;
        for rule in &self.rules {
            rules_inserted += usize::from(matches!(
                prospective_engine.register(rule.clone())?,
                RuleWrite::Inserted
            ));
        }

        let (concepts_inserted, axioms_inserted) =
            knowledge.install_ontology_definitions(&self.concepts, &self.axioms)?;
        *engine = prospective_engine;

        Ok(StandardApiInstallReport {
            concepts_inserted,
            axioms_inserted,
            rules_inserted,
        })
    }

    /// Returns concepts in stable declaration order.
    pub fn concepts(&self) -> &[OntologyConcept] {
        &self.concepts
    }

    /// Returns semantic axioms in stable declaration order.
    pub fn axioms(&self) -> &[OntologyAxiom] {
        &self.axioms
    }

    /// Returns rules in stable declaration order.
    pub fn rules(&self) -> &[ReasoningRule] {
        &self.rules
    }
}

fn standard_concepts() -> Result<Vec<OntologyConcept>, OntologyError> {
    [
        ("application-interface", "Application interface"),
        ("api-interface", "API interface"),
        ("api-response-format", "API response format"),
        ("json", "JSON response format"),
        ("json-http-api", "JSON HTTP API"),
        ("graphql-api", "GraphQL API"),
        ("visibility-boundary", "Visibility boundary"),
        ("ui-api-visibility-boundary", "UI/API visibility boundary"),
        (
            "authorization-context-visibility-boundary",
            "Authorization-context visibility boundary",
        ),
    ]
    .into_iter()
    .map(|(id, label)| OntologyConcept::new(ConceptId::new(id)?, label))
    .collect()
}

fn standard_axioms() -> Result<Vec<OntologyAxiom>, OntologyError> {
    let is_a = Ontology::relation_id(Ontology::IS_A)?;
    [
        ("api-interface", "application-interface"),
        ("json", "api-response-format"),
        ("json-http-api", "api-interface"),
        ("graphql-api", "api-interface"),
        ("ui-api-visibility-boundary", "visibility-boundary"),
        (
            "authorization-context-visibility-boundary",
            "visibility-boundary",
        ),
    ]
    .into_iter()
    .map(|(subject, object)| {
        Ok(OntologyAxiom::new(
            ConceptId::new(subject)?,
            is_a.clone(),
            ConceptId::new(object)?,
        ))
    })
    .collect()
}

fn standard_rules() -> Result<Vec<ReasoningRule>, StandardApiReasoningError> {
    Ok(vec![
        json_response_rule()?,
        graphql_media_type_rule()?,
        graphql_route_rule()?,
        comparison_surface_rule(ApiSurfaceKind::JsonHttp)?,
        comparison_surface_rule(ApiSurfaceKind::GraphQl)?,
        visibility_boundary_rule(ApiVisibilityPairKind::UiApi)?,
        visibility_boundary_rule(ApiVisibilityPairKind::AuthorizationContext)?,
    ])
}

fn json_response_rule() -> Result<ReasoningRule, RuleEngineError> {
    let json_compatible =
        HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge();
    ReasoningRule::new(
        "api.response.json.media-type",
        Expression::equals(
            KnowledgeLayer::Evidence,
            json_compatible.clone(),
            EvidenceValue::Boolean(true),
        ),
        HypothesisConclusion::new(
            ApiKnowledgePredicate::RESPONSE_FORMAT.into(),
            ApiResponseFormat::Json.into(),
            probability(20)?,
            HypothesisStrength::Weak,
            HypothesisState::Supported,
            vec![calibration(
                EvidenceSelector::equals(json_compatible, EvidenceValue::Boolean(true)),
                95,
                5,
                "Validated media type uses JSON or a +json structured suffix",
            )?],
        )?,
    )
}

fn graphql_media_type_rule() -> Result<ReasoningRule, RuleEngineError> {
    let media_type = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
    let graphql_media_type = EvidenceValue::Text("application/graphql-response+json".to_owned());
    ReasoningRule::new(
        "api.surface.graphql.response-media-type",
        Expression::equals(
            KnowledgeLayer::Evidence,
            media_type.clone(),
            graphql_media_type.clone(),
        ),
        HypothesisConclusion::new(
            ApiKnowledgePredicate::SURFACE_KIND.into(),
            ApiSurfaceKind::GraphQl.into(),
            probability(5)?,
            HypothesisStrength::Strong,
            HypothesisState::Supported,
            vec![calibration(
                EvidenceSelector::equals(media_type, graphql_media_type),
                99,
                1,
                "Content-Type uses the GraphQL response media type",
            )?],
        )?,
    )
}

fn graphql_route_rule() -> Result<ReasoningRule, RuleEngineError> {
    let path_segment = HttpEvidencePredicate::REQUEST_PATH_SEGMENT.into_knowledge();
    let graphql = EvidenceValue::Text("graphql".to_owned());
    ReasoningRule::new(
        "api.surface.graphql.route",
        Expression::equals(
            KnowledgeLayer::Evidence,
            path_segment.clone(),
            graphql.clone(),
        ),
        HypothesisConclusion::new(
            ApiKnowledgePredicate::SURFACE_KIND.into(),
            ApiSurfaceKind::GraphQl.into(),
            probability(5)?,
            HypothesisStrength::Weak,
            HypothesisState::Supported,
            vec![calibration(
                EvidenceSelector::equals(path_segment, graphql),
                75,
                25,
                "Request path uses a conventional GraphQL route token",
            )?],
        )?,
    )
}

fn comparison_surface_rule(
    surface: ApiSurfaceKind,
) -> Result<ReasoningRule, StandardApiReasoningError> {
    let predicates = comparison_predicates(surface);
    ReasoningRule::new(
        comparison_surface_rule_id(surface.as_str())?,
        any_comparison_dimension(&predicates)?,
        HypothesisConclusion::new(
            ApiKnowledgePredicate::SURFACE_KIND.into(),
            surface.into(),
            probability(20)?,
            HypothesisStrength::Strong,
            HypothesisState::Supported,
            comparison_calibrations(
                &predicates,
                99,
                1,
                "A host-paired comparison explicitly declares this API surface",
            )?,
        )?,
    )
    .map_err(Into::into)
}

fn comparison_surface_rule_id(surface: &str) -> Result<&'static str, StandardApiReasoningError> {
    match surface {
        "json-http-api" => Ok("api.surface.json.paired-comparison"),
        "graphql-api" => Ok("api.surface.graphql.paired-comparison"),
        _ => Err(StandardApiReasoningError::UnsupportedApiSurface {
            surface: surface.to_owned(),
        }),
    }
}

fn visibility_boundary_rule(
    pair: ApiVisibilityPairKind,
) -> Result<ReasoningRule, StandardApiReasoningError> {
    let predicates = [
        ApiEvidencePredicate::visibility(
            ApiSurfaceKind::JsonHttp,
            pair,
            ApiVisibilityResult::Different,
        ),
        ApiEvidencePredicate::visibility(
            ApiSurfaceKind::GraphQl,
            pair,
            ApiVisibilityResult::Different,
        ),
    ];
    let (id, boundary, likelihood_if_true, rationale) =
        visibility_boundary_rule_spec(pair.as_str())?;
    ReasoningRule::new(
        id,
        any_comparison_dimension(&predicates)?,
        HypothesisConclusion::new(
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into(),
            boundary.into(),
            probability(10)?,
            HypothesisStrength::Weak,
            HypothesisState::Supported,
            comparison_calibrations(
                &predicates,
                likelihood_if_true,
                100 - likelihood_if_true,
                rationale,
            )?,
        )?,
    )
    .map_err(Into::into)
}

fn visibility_boundary_rule_spec(
    pair: &str,
) -> Result<(&'static str, ApiVisibilityBoundaryKind, u8, &'static str), StandardApiReasoningError>
{
    match pair {
        "ui-api" => Ok((
            "api.visibility.ui-api.paired-difference",
            ApiVisibilityBoundaryKind::UiApi,
            98,
            "One atomic same-resource UI/API comparison observed a visibility difference",
        )),
        "authorization-context" => Ok((
            "api.visibility.authorization-context.paired-difference",
            ApiVisibilityBoundaryKind::AuthorizationContext,
            99,
            "One atomic same-resource authorization-context comparison observed a visibility difference",
        )),
        _ => Err(StandardApiReasoningError::UnsupportedVisibilityPair {
            pair: pair.to_owned(),
        }),
    }
}

fn comparison_predicates(surface: ApiSurfaceKind) -> Vec<PredicateDescriptor> {
    [
        ApiVisibilityPairKind::UiApi,
        ApiVisibilityPairKind::AuthorizationContext,
    ]
    .into_iter()
    .flat_map(|pair| {
        [
            ApiVisibilityResult::Different,
            ApiVisibilityResult::Equivalent,
        ]
        .iter()
        .map(move |result| ApiEvidencePredicate::visibility(surface, pair, *result))
    })
    .collect()
}

fn any_comparison_dimension(
    predicates: &[PredicateDescriptor],
) -> Result<Expression, RuleEngineError> {
    Expression::any(
        predicates
            .iter()
            .flat_map(|predicate| {
                ApiVisibilityDimension::all().into_iter().map(|dimension| {
                    Expression::equals(
                        KnowledgeLayer::Evidence,
                        predicate.into_knowledge(),
                        dimension.into(),
                    )
                })
            })
            .collect(),
    )
}

fn comparison_calibrations(
    predicates: &[PredicateDescriptor],
    likelihood_if_true: u8,
    likelihood_if_false: u8,
    rationale: &str,
) -> Result<Vec<EvidenceCalibration>, RuleEngineError> {
    predicates
        .iter()
        .flat_map(|predicate| {
            ApiVisibilityDimension::all().into_iter().map(|dimension| {
                calibration(
                    EvidenceSelector::equals(predicate.into_knowledge(), dimension.into()),
                    likelihood_if_true,
                    likelihood_if_false,
                    rationale,
                )
            })
        })
        .collect()
}

fn calibration(
    selector: EvidenceSelector,
    likelihood_if_true: u8,
    likelihood_if_false: u8,
    rationale: &str,
) -> Result<EvidenceCalibration, RuleEngineError> {
    Ok(EvidenceCalibration::new(
        selector,
        probability(likelihood_if_true)?,
        probability(likelihood_if_false)?,
        rationale,
    )?
    .with_aggregation(EvidenceAggregation::max_contributions(1)?))
}

fn probability(percent: u8) -> Result<Probability, RuleEngineError> {
    Ok(Probability::from_percent(percent)?)
}

#[cfg(test)]
mod tests {
    use venom_core::{
        ApiVisibilityComparison, ApiVisibilityDimension, ConfidenceScore, EntityId, Evidence,
        EvidenceKind, EvidenceSource, Hypothesis, KnowledgePredicate, OntologyConcept,
        OntologyWrite,
    };

    use super::*;
    use crate::{KnowledgeWrite, StandardWebReasoning};

    fn endpoint() -> EntityId {
        EntityId::new("endpoint:https://example.test/graphql").unwrap()
    }

    fn evidence(predicate: PredicateDescriptor, value: EvidenceValue) -> Evidence {
        Evidence::new(
            endpoint(),
            EvidenceKind::Http,
            predicate.into_knowledge(),
            value,
            EvidenceSource::new("http.evidence", "test-observation").unwrap(),
            ConfidenceScore::MAX,
        )
    }

    fn text_evidence(predicate: PredicateDescriptor, value: &str) -> Evidence {
        evidence(predicate, EvidenceValue::Text(value.to_owned()))
    }

    fn hypotheses(knowledge: &KnowledgeBase, subject: &EntityId) -> Vec<Hypothesis> {
        knowledge
            .snapshot_for_subject(subject)
            .hypotheses()
            .to_vec()
    }

    fn hypothesis(
        hypotheses: &[Hypothesis],
        predicate: PredicateDescriptor,
        value: EvidenceValue,
    ) -> Option<&Hypothesis> {
        hypotheses.iter().find(|hypothesis| {
            hypothesis.predicate() == &predicate.into_knowledge() && hypothesis.value() == &value
        })
    }

    fn apply(knowledge: &KnowledgeBase, subject: &EntityId) -> Vec<Hypothesis> {
        let mut engine = RuleEngine::new();
        StandardApiReasoning::new()
            .unwrap()
            .install(knowledge, &mut engine)
            .unwrap();
        engine.apply(knowledge, subject).unwrap();
        hypotheses(knowledge, subject)
    }

    #[test]
    fn profile_installs_idempotently_and_composes_with_web_profile() {
        for api_first in [true, false] {
            let knowledge = KnowledgeBase::new();
            let mut engine = RuleEngine::new();
            let api = StandardApiReasoning::new().unwrap();
            let web = StandardWebReasoning::new().unwrap();

            if api_first {
                api.install(&knowledge, &mut engine).unwrap();
                web.install(&knowledge, &mut engine).unwrap();
            } else {
                web.install(&knowledge, &mut engine).unwrap();
                api.install(&knowledge, &mut engine).unwrap();
            }
            let repeated = api.install(&knowledge, &mut engine).unwrap();

            assert_eq!(repeated, StandardApiInstallReport::default());
            assert_eq!(
                engine.len(),
                STANDARD_API_RULE_COUNT + crate::STANDARD_WEB_RULE_COUNT
            );
            assert!(knowledge
                .ontology_is_a(
                    &ConceptId::new("graphql-api").unwrap(),
                    &ConceptId::new("application-interface").unwrap(),
                )
                .unwrap());
        }
    }

    #[test]
    fn standard_api_profile_rule_manifest_is_exact() {
        let profile = StandardApiReasoning::new().unwrap();
        let rule_ids: Vec<_> = profile.rules().iter().map(ReasoningRule::id).collect();

        assert_eq!(
            rule_ids,
            [
                "api.response.json.media-type",
                "api.surface.graphql.response-media-type",
                "api.surface.graphql.route",
                "api.surface.json.paired-comparison",
                "api.surface.graphql.paired-comparison",
                "api.visibility.ui-api.paired-difference",
                "api.visibility.authorization-context.paired-difference",
            ]
        );
        assert_eq!(rule_ids.len(), STANDARD_API_RULE_COUNT);
    }

    #[test]
    fn every_standard_api_surface_has_one_stable_rule() {
        for (surface, expected_id) in [
            (
                ApiSurfaceKind::JsonHttp,
                "api.surface.json.paired-comparison",
            ),
            (
                ApiSurfaceKind::GraphQl,
                "api.surface.graphql.paired-comparison",
            ),
        ] {
            assert_eq!(comparison_surface_rule(surface).unwrap().id(), expected_id);
            assert_eq!(
                comparison_surface_rule_id(surface.as_str()).unwrap(),
                expected_id
            );
        }
    }

    #[test]
    fn every_standard_visibility_pair_has_one_stable_boundary_rule() {
        for (pair, expected_id) in [
            (
                ApiVisibilityPairKind::UiApi,
                "api.visibility.ui-api.paired-difference",
            ),
            (
                ApiVisibilityPairKind::AuthorizationContext,
                "api.visibility.authorization-context.paired-difference",
            ),
        ] {
            assert_eq!(visibility_boundary_rule(pair).unwrap().id(), expected_id);
            assert_eq!(
                visibility_boundary_rule_spec(pair.as_str()).unwrap().0,
                expected_id
            );
        }
    }

    #[test]
    fn unknown_surface_key_fails_closed_with_typed_error() {
        assert!(matches!(
            comparison_surface_rule_id("future-api-surface"),
            Err(StandardApiReasoningError::UnsupportedApiSurface { surface })
                if surface == "future-api-surface"
        ));
    }

    #[test]
    fn unknown_visibility_pair_key_fails_closed_with_typed_error() {
        assert!(matches!(
            visibility_boundary_rule_spec("future-visibility-pair"),
            Err(StandardApiReasoningError::UnsupportedVisibilityPair { pair })
                if pair == "future-visibility-pair"
        ));
    }

    #[test]
    fn generic_json_never_implies_graphql() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence(
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE,
                EvidenceValue::Boolean(true),
            ))
            .unwrap();

        let hypotheses = apply(&knowledge, &endpoint());

        assert!(hypothesis(
            &hypotheses,
            ApiKnowledgePredicate::RESPONSE_FORMAT,
            ApiResponseFormat::Json.into(),
        )
        .is_some());
        assert!(hypothesis(
            &hypotheses,
            ApiKnowledgePredicate::SURFACE_KIND,
            ApiSurfaceKind::GraphQl.into(),
        )
        .is_none());
    }

    #[test]
    fn graphql_media_type_is_strong_and_route_signal_is_weak() {
        let media_knowledge = KnowledgeBase::new();
        media_knowledge
            .insert_evidence(text_evidence(
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE,
                "application/graphql-response+json",
            ))
            .unwrap();
        let media = apply(&media_knowledge, &endpoint());
        assert_eq!(
            hypothesis(
                &media,
                ApiKnowledgePredicate::SURFACE_KIND,
                ApiSurfaceKind::GraphQl.into(),
            )
            .unwrap()
            .strength(),
            HypothesisStrength::Strong
        );

        let route_knowledge = KnowledgeBase::new();
        route_knowledge
            .insert_evidence(text_evidence(
                HttpEvidencePredicate::REQUEST_PATH_SEGMENT,
                "graphql",
            ))
            .unwrap();
        let route = apply(&route_knowledge, &endpoint());
        assert_eq!(
            hypothesis(
                &route,
                ApiKnowledgePredicate::SURFACE_KIND,
                ApiSurfaceKind::GraphQl.into(),
            )
            .unwrap()
            .strength(),
            HypothesisStrength::Weak
        );
    }

    #[test]
    fn raw_substrings_and_malformed_comparison_values_are_ignored() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![
                text_evidence(
                    HttpEvidencePredicate::HEADER_CONTENT_TYPE,
                    "application/jsonp; note=application/graphql-response+json",
                ),
                text_evidence(
                    HttpEvidencePredicate::REQUEST_URL,
                    "https://example.test/?next=/graphql",
                ),
                evidence(
                    ApiEvidencePredicate::JSON_UI_API_DIFFERENCE,
                    EvidenceValue::Boolean(true),
                ),
            ])
            .unwrap();

        assert!(apply(&knowledge, &endpoint()).is_empty());
    }

    fn comparison(
        pair: ApiVisibilityPairKind,
        result: ApiVisibilityResult,
        candidate: &str,
    ) -> ApiVisibilityComparison {
        ApiVisibilityComparison::new(
            "comparison-1",
            ApiSurfaceKind::JsonHttp,
            pair,
            result,
            ApiVisibilityDimension::Fields,
            "baseline",
            candidate,
            "account-record",
        )
        .unwrap()
    }

    #[test]
    fn one_atomic_difference_produces_only_the_matching_review_boundary() {
        let comparison = comparison(
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityResult::Different,
            "member",
        );
        let observation = comparison
            .to_observation("api.visibility", ConfidenceScore::MAX)
            .unwrap();
        let evidence_id = observation.evidence().id().clone();
        let subject = observation.evidence().subject().clone();
        let resource_scope = observation.resource_scope().clone();
        let (evidence, relation) = observation.into_parts();
        let knowledge = KnowledgeBase::new();
        assert_eq!(
            knowledge
                .insert_evidence_with_relation(evidence, relation)
                .unwrap(),
            (KnowledgeWrite::Inserted, KnowledgeWrite::Inserted)
        );

        let hypotheses = apply(&knowledge, &subject);
        let boundary = hypothesis(
            &hypotheses,
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY,
            ApiVisibilityBoundaryKind::AuthorizationContext.into(),
        )
        .unwrap();

        assert_eq!(boundary.state(), HypothesisState::Supported);
        assert_eq!(boundary.strength(), HypothesisStrength::Weak);
        assert_eq!(boundary.belief().evidence().len(), 1);
        assert_eq!(boundary.belief().evidence()[0].evidence_id(), &evidence_id);
        assert!(hypothesis(
            &hypotheses,
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY,
            ApiVisibilityBoundaryKind::UiApi.into(),
        )
        .is_none());
        assert!(knowledge.snapshot_for_subject(&subject).facts().is_empty());
        assert_eq!(knowledge.relations_from(&subject)[0].to(), &resource_scope);
    }

    #[test]
    fn equivalent_comparison_never_creates_a_negative_or_boundary_claim() {
        let comparison = comparison(
            ApiVisibilityPairKind::UiApi,
            ApiVisibilityResult::Equivalent,
            "api",
        );
        let evidence = comparison
            .to_evidence("api.visibility", ConfidenceScore::MAX)
            .unwrap();
        let subject = evidence.subject().clone();
        let knowledge = KnowledgeBase::new();
        knowledge.insert_evidence(evidence).unwrap();

        let hypotheses = apply(&knowledge, &subject);

        assert!(hypotheses.iter().all(|hypothesis| !matches!(
            hypothesis.state(),
            HypothesisState::Confirmed | HypothesisState::Rejected
        )));
        assert!(hypotheses.iter().all(|hypothesis| hypothesis.predicate()
            != &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()));
        assert!(hypothesis(
            &hypotheses,
            ApiKnowledgePredicate::SURFACE_KIND,
            ApiSurfaceKind::JsonHttp.into(),
        )
        .is_some());
    }

    #[test]
    fn comparison_subjects_isolate_principal_contexts() {
        let member = comparison(
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityResult::Different,
            "member",
        )
        .to_evidence("api.visibility", ConfidenceScore::MAX)
        .unwrap();
        let admin = comparison(
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityResult::Equivalent,
            "admin",
        )
        .to_evidence("api.visibility", ConfidenceScore::MAX)
        .unwrap();
        assert_ne!(member.subject(), admin.subject());
        let member_subject = member.subject().clone();
        let admin_subject = admin.subject().clone();
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![member, admin])
            .unwrap();

        let member_hypotheses = apply(&knowledge, &member_subject);
        let admin_hypotheses = apply(&knowledge, &admin_subject);

        assert!(hypothesis(
            &member_hypotheses,
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY,
            ApiVisibilityBoundaryKind::AuthorizationContext.into(),
        )
        .is_some());
        assert!(hypothesis(
            &admin_hypotheses,
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY,
            ApiVisibilityBoundaryKind::AuthorizationContext.into(),
        )
        .is_none());
    }

    #[test]
    fn rule_conflict_preflight_leaves_ontology_unchanged() {
        let knowledge = KnowledgeBase::new();
        let mut engine = RuleEngine::new();
        let profile = StandardApiReasoning::new().unwrap();
        let conflict_source = HttpEvidencePredicate::HEADER_SERVER.into_knowledge();
        engine
            .register(
                ReasoningRule::new(
                    profile.rules()[0].id(),
                    Expression::exists(KnowledgeLayer::Evidence, conflict_source.clone()),
                    HypothesisConclusion::new(
                        KnowledgePredicate::new("conflict", "claim").unwrap(),
                        EvidenceValue::Boolean(true),
                        probability(50).unwrap(),
                        HypothesisStrength::Weak,
                        HypothesisState::Supported,
                        vec![calibration(
                            EvidenceSelector::exists(conflict_source),
                            60,
                            40,
                            "test conflict",
                        )
                        .unwrap()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let rules_before = engine.len();

        assert!(profile.install(&knowledge, &mut engine).is_err());
        assert_eq!(engine.len(), rules_before);
        assert_eq!(knowledge.ontology_snapshot().stats().concepts, 0);
    }

    #[test]
    fn ontology_conflict_leaves_rule_registry_unchanged() {
        let knowledge = KnowledgeBase::new();
        assert_eq!(
            knowledge
                .register_concept(
                    OntologyConcept::new(
                        ConceptId::new("api-interface").unwrap(),
                        "Conflicting API label",
                    )
                    .unwrap(),
                )
                .unwrap(),
            OntologyWrite::Inserted
        );
        let mut engine = RuleEngine::new();

        assert!(StandardApiReasoning::new()
            .unwrap()
            .install(&knowledge, &mut engine)
            .is_err());
        assert!(engine.is_empty());
    }
}
