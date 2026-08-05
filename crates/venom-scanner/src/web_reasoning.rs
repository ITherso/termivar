//! Standard deterministic ontology and reasoning rules for web observations.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The profile is opt-in. It defines semantic vocabulary and Bayesian rules,
//! but performs no network I/O and never verifies a vulnerability.

use serde::Serialize;
use thiserror::Error;
use venom_core::{
    ConceptId, EvidenceValue, HttpEvidencePredicate, HypothesisState, HypothesisStrength,
    KnowledgePredicate, Ontology, OntologyAxiom, OntologyConcept, OntologyError, Probability,
    WebKnowledgePredicate,
};

use crate::{
    knowledge::KnowledgeBase,
    rules::{
        EvidenceCalibration, EvidenceSelector, Expression, HypothesisConclusion, KnowledgeLayer,
        ReasoningRule, RuleEngine, RuleEngineError, RuleWrite,
    },
};

/// Number of concepts defined by [`StandardWebReasoning`].
pub const STANDARD_WEB_CONCEPT_COUNT: usize = 14;

/// Number of semantic axioms defined by [`StandardWebReasoning`].
pub const STANDARD_WEB_AXIOM_COUNT: usize = 16;

/// Number of deterministic fingerprint rules defined by [`StandardWebReasoning`].
pub const STANDARD_WEB_RULE_COUNT: usize = 8;

/// Failures while constructing or installing the standard web profile.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebReasoningError {
    /// An ontology definition or relationship was invalid or conflicted.
    #[error(transparent)]
    Ontology(#[from] OntologyError),

    /// A reasoning rule was invalid or conflicted.
    #[error(transparent)]
    Rules(#[from] RuleEngineError),
}

/// Counts of new definitions installed by one idempotent profile operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StandardWebInstallReport {
    concepts_inserted: usize,
    axioms_inserted: usize,
    rules_inserted: usize,
}

impl StandardWebInstallReport {
    /// Returns the number of newly registered concepts.
    pub fn concepts_inserted(self) -> usize {
        self.concepts_inserted
    }

    /// Returns the number of newly registered semantic axioms.
    pub fn axioms_inserted(self) -> usize {
        self.axioms_inserted
    }

    /// Returns the number of newly registered reasoning rules.
    pub fn rules_inserted(self) -> usize {
        self.rules_inserted
    }
}

/// Validated web-domain ontology and deterministic fingerprint rule pack.
///
/// The profile recognizes disclosed nginx, Apache HTTP Server, PHP, Laravel,
/// Livewire, Sanctum, HTTP Basic, and HTTP Bearer signals. Conclusions remain
/// hypotheses: only verifier stages may mark them confirmed or rejected.
///
/// # Examples
///
/// ```rust
/// use venom_scanner::{KnowledgeBase, RuleEngine, StandardWebReasoning};
///
/// let knowledge = KnowledgeBase::new();
/// let mut rules = RuleEngine::new();
/// let profile = StandardWebReasoning::new()?;
/// let installed = profile.install(&knowledge, &mut rules)?;
///
/// assert_eq!(installed.rules_inserted(), profile.rules().len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct StandardWebReasoning {
    concepts: Vec<OntologyConcept>,
    axioms: Vec<OntologyAxiom>,
    rules: Vec<ReasoningRule>,
}

impl StandardWebReasoning {
    /// Builds and validates the standard vocabulary and rule definitions.
    pub fn new() -> Result<Self, StandardWebReasoningError> {
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

        debug_assert_eq!(concepts.len(), STANDARD_WEB_CONCEPT_COUNT);
        debug_assert_eq!(axioms.len(), STANDARD_WEB_AXIOM_COUNT);
        debug_assert_eq!(rules.len(), STANDARD_WEB_RULE_COUNT);
        Ok(Self {
            concepts,
            axioms,
            rules,
        })
    }

    /// Installs the complete profile idempotently into knowledge and rules.
    ///
    /// Definitions are first applied to owned clones, so a known identity or
    /// semantic conflict is detected before shared state is changed.
    pub fn install(
        &self,
        knowledge: &KnowledgeBase,
        engine: &mut RuleEngine,
    ) -> Result<StandardWebInstallReport, StandardWebReasoningError> {
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

        Ok(StandardWebInstallReport {
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

    /// Returns reasoning rules in stable declaration order.
    pub fn rules(&self) -> &[ReasoningRule] {
        &self.rules
    }
}

fn standard_concepts() -> Result<Vec<OntologyConcept>, OntologyError> {
    [
        ("technology", "Technology"),
        ("server-software", "Server software"),
        ("programming-language", "Programming language"),
        ("web-framework", "Web framework"),
        ("ui-framework", "UI framework"),
        ("authentication-mechanism", "Authentication mechanism"),
        ("nginx", "nginx"),
        ("apache-http-server", "Apache HTTP Server"),
        ("php", "PHP"),
        ("laravel", "Laravel"),
        ("livewire", "Livewire"),
        ("sanctum", "Laravel Sanctum"),
        ("http-basic", "HTTP Basic authentication"),
        ("http-bearer", "HTTP Bearer authentication"),
    ]
    .into_iter()
    .map(|(id, label)| OntologyConcept::new(ConceptId::new(id)?, label))
    .collect()
}

fn standard_axioms() -> Result<Vec<OntologyAxiom>, OntologyError> {
    let is_a = Ontology::relation_id(Ontology::IS_A)?;
    let implemented_in = Ontology::relation_id(Ontology::IMPLEMENTED_IN)?;
    let depends_on = Ontology::relation_id(Ontology::DEPENDS_ON)?;
    [
        ("server-software", &is_a, "technology"),
        ("programming-language", &is_a, "technology"),
        ("web-framework", &is_a, "technology"),
        ("ui-framework", &is_a, "technology"),
        ("authentication-mechanism", &is_a, "technology"),
        ("nginx", &is_a, "server-software"),
        ("apache-http-server", &is_a, "server-software"),
        ("php", &is_a, "programming-language"),
        ("laravel", &is_a, "web-framework"),
        ("livewire", &is_a, "ui-framework"),
        ("sanctum", &is_a, "authentication-mechanism"),
        ("http-basic", &is_a, "authentication-mechanism"),
        ("http-bearer", &is_a, "authentication-mechanism"),
        ("laravel", &implemented_in, "php"),
        ("livewire", &depends_on, "laravel"),
        ("sanctum", &depends_on, "laravel"),
    ]
    .into_iter()
    .map(|(subject, relation, object)| {
        Ok(OntologyAxiom::new(
            ConceptId::new(subject)?,
            relation.clone(),
            ConceptId::new(object)?,
        ))
    })
    .collect()
}

fn standard_rules() -> Result<Vec<ReasoningRule>, RuleEngineError> {
    Ok(vec![
        disclosed_product_rule(
            "web.server.apache.header",
            HttpEvidencePredicate::HEADER_SERVER.into(),
            "apache",
            WebKnowledgePredicate::TECHNOLOGY_WEB_SERVER.into(),
            "apache-http-server",
            20,
            94,
            6,
            HypothesisStrength::Weak,
            "Server header contains an Apache product token",
        )?,
        auth_header_rule("basic", "http-basic")?,
        auth_header_rule("bearer", "http-bearer")?,
        framework_laravel_rule()?,
        framework_livewire_rule()?,
        disclosed_product_rule(
            "web.server.nginx.header",
            HttpEvidencePredicate::HEADER_SERVER.into(),
            "nginx",
            WebKnowledgePredicate::TECHNOLOGY_WEB_SERVER.into(),
            "nginx",
            20,
            97,
            3,
            HypothesisStrength::Weak,
            "Server header contains the nginx product token",
        )?,
        disclosed_product_rule(
            "web.language.php.header",
            HttpEvidencePredicate::HEADER_X_POWERED_BY.into(),
            "php",
            WebKnowledgePredicate::TECHNOLOGY_LANGUAGE.into(),
            "php",
            20,
            96,
            4,
            HypothesisStrength::Weak,
            "X-Powered-By contains the PHP runtime token",
        )?,
        sanctum_cookie_rule()?,
    ])
}

#[allow(clippy::too_many_arguments)]
fn disclosed_product_rule(
    id: &str,
    source_predicate: KnowledgePredicate,
    token: &str,
    conclusion_predicate: KnowledgePredicate,
    conclusion_value: &str,
    prior: u8,
    likelihood_if_true: u8,
    likelihood_if_false: u8,
    strength: HypothesisStrength,
    rationale: &str,
) -> Result<ReasoningRule, RuleEngineError> {
    ReasoningRule::new(
        id,
        Expression::text_contains_ascii_case_insensitive(
            KnowledgeLayer::Evidence,
            source_predicate.clone(),
            token,
        )?,
        HypothesisConclusion::new(
            conclusion_predicate,
            EvidenceValue::Text(conclusion_value.to_owned()),
            probability(prior)?,
            strength,
            HypothesisState::Supported,
            vec![text_calibration(
                source_predicate,
                token,
                likelihood_if_true,
                likelihood_if_false,
                rationale,
            )?],
        )?,
    )
}

fn auth_header_rule(token: &str, value: &str) -> Result<ReasoningRule, RuleEngineError> {
    disclosed_product_rule(
        &format!("web.authentication.{token}.header"),
        HttpEvidencePredicate::HEADER_WWW_AUTHENTICATE.into(),
        token,
        WebKnowledgePredicate::AUTHENTICATION_MECHANISM.into(),
        value,
        15,
        99,
        1,
        HypothesisStrength::Strong,
        "WWW-Authenticate explicitly advertises this authentication scheme",
    )
}

fn framework_laravel_rule() -> Result<ReasoningRule, RuleEngineError> {
    let powered_by = HttpEvidencePredicate::HEADER_X_POWERED_BY.into_knowledge();
    let cookie_name = HttpEvidencePredicate::COOKIE_NAME.into_knowledge();
    let laravel_session = EvidenceValue::Text("laravel_session".to_owned());
    let xsrf_token = EvidenceValue::Text("XSRF-TOKEN".to_owned());
    let condition = Expression::any(vec![
        Expression::text_contains_ascii_case_insensitive(
            KnowledgeLayer::Evidence,
            powered_by.clone(),
            "laravel",
        )?,
        Expression::all(vec![
            Expression::equals(
                KnowledgeLayer::Evidence,
                cookie_name.clone(),
                laravel_session.clone(),
            ),
            Expression::equals(
                KnowledgeLayer::Evidence,
                cookie_name.clone(),
                xsrf_token.clone(),
            ),
        ])?,
    ])?;
    ReasoningRule::new(
        "web.framework.laravel",
        condition,
        HypothesisConclusion::new(
            WebKnowledgePredicate::TECHNOLOGY_FRAMEWORK.into(),
            EvidenceValue::Text("laravel".to_owned()),
            probability(5)?,
            HypothesisStrength::Strong,
            HypothesisState::Supported,
            vec![
                text_calibration(
                    powered_by,
                    "laravel",
                    99,
                    1,
                    "X-Powered-By explicitly names Laravel",
                )?,
                exact_calibration(
                    cookie_name.clone(),
                    laravel_session,
                    95,
                    3,
                    "Laravel session cookie is present",
                )?,
                exact_calibration(
                    cookie_name,
                    xsrf_token,
                    80,
                    20,
                    "Laravel-compatible XSRF cookie is present",
                )?,
            ],
        )?,
    )
}

fn framework_livewire_rule() -> Result<ReasoningRule, RuleEngineError> {
    let body_sample = HttpEvidencePredicate::RESPONSE_BODY_SAMPLE.into_knowledge();
    let markers = ["wire:id=", "wire:snapshot="];
    let conditions = markers
        .iter()
        .map(|marker| {
            Expression::text_contains_ascii_case_insensitive(
                KnowledgeLayer::Evidence,
                body_sample.clone(),
                *marker,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let calibrations = markers
        .iter()
        .map(|marker| {
            text_calibration(
                body_sample.clone(),
                marker,
                97,
                3,
                "Bounded response sample contains a Livewire DOM marker",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ReasoningRule::new(
        "web.framework.livewire.body",
        Expression::any(conditions)?,
        HypothesisConclusion::new(
            WebKnowledgePredicate::TECHNOLOGY_UI_FRAMEWORK.into(),
            EvidenceValue::Text("livewire".to_owned()),
            probability(5)?,
            HypothesisStrength::Weak,
            HypothesisState::Supported,
            calibrations,
        )?,
    )
}

fn sanctum_cookie_rule() -> Result<ReasoningRule, RuleEngineError> {
    let cookie_name = HttpEvidencePredicate::COOKIE_NAME.into_knowledge();
    let laravel_session = EvidenceValue::Text("laravel_session".to_owned());
    let xsrf_token = EvidenceValue::Text("XSRF-TOKEN".to_owned());
    ReasoningRule::new(
        "web.authentication.sanctum.cookies",
        Expression::all(vec![
            Expression::equals(
                KnowledgeLayer::Evidence,
                cookie_name.clone(),
                laravel_session.clone(),
            ),
            Expression::equals(
                KnowledgeLayer::Evidence,
                cookie_name.clone(),
                xsrf_token.clone(),
            ),
        ])?,
        HypothesisConclusion::new(
            WebKnowledgePredicate::AUTHENTICATION_MECHANISM.into(),
            EvidenceValue::Text("sanctum".to_owned()),
            probability(3)?,
            HypothesisStrength::Weak,
            HypothesisState::Supported,
            vec![
                exact_calibration(
                    cookie_name.clone(),
                    laravel_session,
                    75,
                    20,
                    "Stateful Laravel session is compatible with Sanctum SPA authentication",
                )?,
                exact_calibration(
                    cookie_name,
                    xsrf_token,
                    90,
                    10,
                    "XSRF cookie is compatible with Sanctum SPA authentication",
                )?,
            ],
        )?,
    )
}

fn text_calibration(
    predicate: KnowledgePredicate,
    token: &str,
    likelihood_if_true: u8,
    likelihood_if_false: u8,
    rationale: &str,
) -> Result<EvidenceCalibration, RuleEngineError> {
    EvidenceCalibration::new(
        EvidenceSelector::text_contains_ascii_case_insensitive(predicate, token)?,
        probability(likelihood_if_true)?,
        probability(likelihood_if_false)?,
        rationale,
    )
}

fn exact_calibration(
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    likelihood_if_true: u8,
    likelihood_if_false: u8,
    rationale: &str,
) -> Result<EvidenceCalibration, RuleEngineError> {
    EvidenceCalibration::new(
        EvidenceSelector::equals(predicate, value),
        probability(likelihood_if_true)?,
        probability(likelihood_if_false)?,
        rationale,
    )
}

fn probability(percent: u8) -> Result<Probability, RuleEngineError> {
    Ok(Probability::from_percent(percent)?)
}

#[cfg(test)]
mod tests {
    use venom_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, Hypothesis,
        RelationTypeId,
    };

    use super::*;

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn evidence(namespace: &str, name: &str, value: &str) -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new(namespace, name).unwrap(),
            EvidenceValue::Text(value.to_owned()),
            EvidenceSource::new("http.evidence", "test-observation").unwrap(),
            ConfidenceScore::MAX,
        )
    }

    fn hypothesis<'a>(hypotheses: &'a [Hypothesis], value: &str) -> Option<&'a Hypothesis> {
        hypotheses
            .iter()
            .find(|hypothesis| hypothesis.value() == &EvidenceValue::Text(value.to_owned()))
    }

    #[test]
    fn profile_installs_idempotently_and_defines_semantics() {
        let knowledge = KnowledgeBase::new();
        let mut engine = RuleEngine::new();
        let profile = StandardWebReasoning::new().unwrap();

        let first = profile.install(&knowledge, &mut engine).unwrap();
        let second = profile.install(&knowledge, &mut engine).unwrap();

        assert_eq!(first.concepts_inserted(), STANDARD_WEB_CONCEPT_COUNT);
        assert_eq!(first.axioms_inserted(), STANDARD_WEB_AXIOM_COUNT);
        assert_eq!(first.rules_inserted(), STANDARD_WEB_RULE_COUNT);
        assert_eq!(second, StandardWebInstallReport::default());
        assert!(knowledge
            .ontology_is_a(
                &ConceptId::new("laravel").unwrap(),
                &ConceptId::new("technology").unwrap(),
            )
            .unwrap());
        assert!(knowledge
            .ontology_is_related(
                &ConceptId::new("sanctum").unwrap(),
                &RelationTypeId::new(Ontology::DEPENDS_ON).unwrap(),
                &ConceptId::new("laravel").unwrap(),
            )
            .unwrap());
    }

    #[test]
    fn disclosed_headers_materialize_explainable_weak_hypotheses() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![
                evidence("http.header", "server", "NGINX/1.26.1"),
                evidence("http.header", "x-powered-by", "PHP/8.3.7"),
            ])
            .unwrap();
        let mut engine = RuleEngine::new();
        StandardWebReasoning::new()
            .unwrap()
            .install(&knowledge, &mut engine)
            .unwrap();

        let applications = engine.apply(&knowledge, &subject()).unwrap();
        let hypotheses = knowledge.hypotheses_for_subject(&subject());
        let nginx = hypothesis(&hypotheses, "nginx").unwrap();
        let php = hypothesis(&hypotheses, "php").unwrap();

        assert_eq!(nginx.strength(), HypothesisStrength::Weak);
        assert_eq!(php.strength(), HypothesisStrength::Weak);
        assert!(nginx.posterior() > Probability::from_percent(50).unwrap());
        assert!(php.posterior() > Probability::from_percent(50).unwrap());
        assert_eq!(nginx.belief().evidence().len(), 1);
        assert_eq!(
            applications
                .iter()
                .filter(|item| item.write().is_some())
                .count(),
            2
        );
    }

    #[test]
    fn cookie_pair_materializes_strong_laravel_and_weak_sanctum() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence_batch(vec![
                evidence("http.cookie", "name", "laravel_session"),
                evidence("http.cookie", "name", "XSRF-TOKEN"),
            ])
            .unwrap();
        let mut engine = RuleEngine::new();
        StandardWebReasoning::new()
            .unwrap()
            .install(&knowledge, &mut engine)
            .unwrap();

        engine.apply(&knowledge, &subject()).unwrap();
        let hypotheses = knowledge.hypotheses_for_subject(&subject());
        let laravel = hypothesis(&hypotheses, "laravel").unwrap();
        let sanctum = hypothesis(&hypotheses, "sanctum").unwrap();

        assert_eq!(laravel.strength(), HypothesisStrength::Strong);
        assert_eq!(sanctum.strength(), HypothesisStrength::Weak);
        assert_eq!(laravel.state(), HypothesisState::Supported);
        assert!(laravel.posterior() > Probability::from_percent(80).unwrap());
        assert!(sanctum.posterior() > Probability::from_percent(50).unwrap());
        assert_eq!(laravel.belief().evidence().len(), 2);
    }

    #[test]
    fn isolated_xsrf_cookie_does_not_overclaim_framework_or_authentication() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence("http.cookie", "name", "XSRF-TOKEN"))
            .unwrap();
        let mut engine = RuleEngine::new();
        StandardWebReasoning::new()
            .unwrap()
            .install(&knowledge, &mut engine)
            .unwrap();

        engine.apply(&knowledge, &subject()).unwrap();

        assert!(knowledge.hypotheses_for_subject(&subject()).is_empty());
    }
}
