//! Transport-neutral contracts for evidence-driven reasoning.
//!
//! These types deliberately contain no scheduling or detection behavior. A
//! scanner records [`Evidence`], materializes [`Fact`] values, evaluates
//! [`Hypothesis`] values, and connects [`KnowledgeEntity`] values through
//! [`KnowledgeRelation`] edges in higher-level crates.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

const MAX_CONFIDENCE_BASIS_POINTS: u16 = 10_000;
const MAX_PROBABILITY_PARTS_PER_MILLION: u32 = 1_000_000;

/// Validation errors for decision-engine domain contracts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ReasoningModelError {
    /// A required identifier or name was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// A confidence score exceeded the inclusive `0..=10_000` range.
    #[error("confidence score {0} exceeds 10,000 basis points")]
    ConfidenceOutOfRange(u16),

    /// A probability exceeded the inclusive `0..=1_000_000` range.
    #[error("probability {0} exceeds 1,000,000 parts per million")]
    ProbabilityOutOfRange(u32),

    /// Bayes' theorem had a zero denominator for the supplied observation.
    #[error("Bayesian posterior is undefined for the supplied likelihoods")]
    UndefinedPosterior,
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, ReasoningModelError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(ReasoningModelError::EmptyValue { field });
    }
    Ok(value)
}

fn deserialize_non_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    non_empty(value, "value").map_err(serde::de::Error::custom)
}

fn deserialize_optional_non_empty_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| non_empty(value, "optional value").map_err(serde::de::Error::custom))
        .transpose()
}

fn deserialize_non_empty_evidence_ids<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<EvidenceId>, D::Error>
where
    D: Deserializer<'de>,
{
    let evidence_ids = BTreeSet::<EvidenceId>::deserialize(deserializer)?;
    if evidence_ids.is_empty() {
        return Err(serde::de::Error::custom(
            "evidence_ids must contain at least one evidence id",
        ));
    }
    Ok(evidence_ids)
}

/// Stable identifier for an entity in the knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EntityId(String);

impl EntityId {
    /// Creates a non-empty entity identifier chosen by the host.
    pub fn new(value: impl Into<String>) -> Result<Self, ReasoningModelError> {
        Ok(Self(non_empty(value, "entity id")?))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EntityId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Unique identifier for one immutable evidence record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EvidenceId(String);

impl EvidenceId {
    /// Generates a new evidence identifier.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Parses a previously persisted non-empty evidence identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ReasoningModelError> {
        Ok(Self(non_empty(value, "evidence id")?))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EvidenceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EvidenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EvidenceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Unique identifier for one knowledge-graph relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RelationId(String);

impl RelationId {
    /// Generates a new relation identifier.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Parses a previously persisted non-empty relation identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ReasoningModelError> {
        Ok(Self(non_empty(value, "relation id")?))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// An ordinal evidence score represented in basis points.
///
/// `10_000` means maximum confidence and `0` means no confidence. This value
/// is not a statistical probability unless a future reasoner explicitly
/// calibrates it against measured outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConfidenceScore(u16);

impl ConfidenceScore {
    /// No confidence.
    pub const NONE: Self = Self(0);

    /// Maximum confidence.
    pub const MAX: Self = Self(MAX_CONFIDENCE_BASIS_POINTS);

    /// Creates a validated score from basis points.
    pub fn from_basis_points(value: u16) -> Result<Self, ReasoningModelError> {
        if value > MAX_CONFIDENCE_BASIS_POINTS {
            return Err(ReasoningModelError::ConfidenceOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// Creates a validated score from an integer percentage.
    pub fn from_percent(value: u8) -> Result<Self, ReasoningModelError> {
        Self::from_basis_points(u16::from(value) * 100)
    }

    /// Returns the score in basis points.
    pub const fn basis_points(self) -> u16 {
        self.0
    }

    /// Returns the score as a ratio in the inclusive `0.0..=1.0` range.
    pub fn ratio(self) -> f64 {
        f64::from(self.0) / f64::from(MAX_CONFIDENCE_BASIS_POINTS)
    }
}

impl<'de> Deserialize<'de> for ConfidenceScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::from_basis_points(value).map_err(serde::de::Error::custom)
    }
}

/// A calibrated probability represented as fixed-point parts per million.
///
/// Unlike [`ConfidenceScore`], this value has a statistical meaning. Decision
/// code uses integer arithmetic so the same prior and observations produce the
/// same posterior on every supported platform. Floating-point conversion is
/// provided only for display and analytics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Probability(u32);

impl Probability {
    /// An impossible event.
    pub const ZERO: Self = Self(0);

    /// A certain event.
    pub const ONE: Self = Self(MAX_PROBABILITY_PARTS_PER_MILLION);

    /// Creates a probability from fixed-point parts per million.
    pub fn from_parts_per_million(value: u32) -> Result<Self, ReasoningModelError> {
        if value > MAX_PROBABILITY_PARTS_PER_MILLION {
            return Err(ReasoningModelError::ProbabilityOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// Creates a probability from basis points.
    pub fn from_basis_points(value: u16) -> Result<Self, ReasoningModelError> {
        Self::from_parts_per_million(u32::from(value) * 100)
    }

    /// Creates a probability from an integer percentage.
    pub fn from_percent(value: u8) -> Result<Self, ReasoningModelError> {
        Self::from_parts_per_million(u32::from(value) * 10_000)
    }

    /// Returns the fixed-point value in parts per million.
    pub const fn parts_per_million(self) -> u32 {
        self.0
    }

    /// Returns the probability as a ratio for presentation or analytics.
    pub fn ratio(self) -> f64 {
        f64::from(self.0) / f64::from(MAX_PROBABILITY_PARTS_PER_MILLION)
    }

    /// Applies one Bayesian observation to this prior.
    ///
    /// `likelihood_if_true` is `P(E|H)` and `likelihood_if_false` is
    /// `P(E|not H)`. The result is rounded to the nearest part per million.
    pub fn update(
        self,
        likelihood_if_true: Self,
        likelihood_if_false: Self,
    ) -> Result<Self, ReasoningModelError> {
        let scale = u128::from(MAX_PROBABILITY_PARTS_PER_MILLION);
        let prior = u128::from(self.0);
        let true_weight = u128::from(likelihood_if_true.0) * prior;
        let false_weight = u128::from(likelihood_if_false.0) * (scale - prior);
        let denominator = true_weight + false_weight;

        if denominator == 0 {
            return Err(ReasoningModelError::UndefinedPosterior);
        }

        let rounded = (true_weight * scale + denominator / 2) / denominator;
        let value = u32::try_from(rounded).expect("posterior is bounded by the probability scale");
        Self::from_parts_per_million(value)
    }
}

impl<'de> Deserialize<'de> for Probability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::from_parts_per_million(value).map_err(serde::de::Error::custom)
    }
}

/// Namespaced predicate used by evidence, facts, and hypotheses.
///
/// Examples include `http.header.x-powered-by`, `service.port`, and
/// `technology.framework`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct KnowledgePredicate {
    namespace: String,
    name: String,
}

impl KnowledgePredicate {
    /// Creates a predicate from non-empty namespace and name components.
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            namespace: non_empty(namespace, "predicate namespace")?,
            name: non_empty(name, "predicate name")?,
        })
    }

    /// Returns the predicate namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the predicate name within its namespace.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the stable dotted form used in explanations.
    pub fn dotted(&self) -> String {
        format!("{}.{}", self.namespace, self.name)
    }
}

impl<'de> Deserialize<'de> for KnowledgePredicate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WirePredicate {
            namespace: String,
            name: String,
        }

        let wire = WirePredicate::deserialize(deserializer)?;
        Self::new(wire.namespace, wire.name).map_err(serde::de::Error::custom)
    }
}

/// Typed value carried by evidence and claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceValue {
    /// Boolean signal.
    Boolean(bool),
    /// Signed integer measurement.
    Signed(i64),
    /// Unsigned integer measurement.
    Unsigned(u64),
    /// UTF-8 text value.
    Text(String),
    /// Ordered collection of UTF-8 text values.
    TextList(Vec<String>),
}

/// Broad evidence category used for routing and policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceKind {
    /// Host, port, protocol, or service observation.
    Network,
    /// HTTP request or response observation.
    Http,
    /// TLS or certificate observation.
    Tls,
    /// DNS observation.
    Dns,
    /// Response body, script, robots, or sitemap observation.
    Content,
    /// Authentication or session observation.
    Authentication,
    /// Rate-limit or backpressure observation.
    RateLimit,
    /// Latency or timing observation.
    Timing,
    /// Technology fingerprint observation.
    Technology,
    /// Extension category with a stable namespaced identifier.
    Custom(String),
}

/// Provenance identifying who produced an evidence record and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSource {
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    component: String,
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    method: String,
    #[serde(default, deserialize_with = "deserialize_optional_non_empty_string")]
    correlation_id: Option<String>,
}

impl EvidenceSource {
    /// Creates a source from a component and observation method.
    pub fn new(
        component: impl Into<String>,
        method: impl Into<String>,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            component: non_empty(component, "evidence source component")?,
            method: non_empty(method, "evidence source method")?,
            correlation_id: None,
        })
    }

    /// Associates this source with a scan or request correlation ID.
    pub fn with_correlation_id(
        mut self,
        correlation_id: impl Into<String>,
    ) -> Result<Self, ReasoningModelError> {
        self.correlation_id = Some(non_empty(correlation_id, "correlation id")?);
        Ok(self)
    }

    /// Returns the producing component.
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Returns the observation method.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the optional scan or request correlation ID.
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }
}

/// Immutable observation recorded by discovery or execution code.
///
/// # Examples
///
/// ```rust
/// use venom_core::{
///     ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource,
///     EvidenceValue, KnowledgePredicate,
/// };
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let evidence = Evidence::new(
///     EntityId::new("endpoint:https://example.test")?,
///     EvidenceKind::Http,
///     KnowledgePredicate::new("http.header", "server")?,
///     EvidenceValue::Text("nginx".into()),
///     EvidenceSource::new("discovery.headers", "server-header")?,
///     ConfidenceScore::from_percent(85)?,
/// );
///
/// assert_eq!(evidence.reliability().basis_points(), 8_500);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    id: EvidenceId,
    subject: EntityId,
    kind: EvidenceKind,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    source: EvidenceSource,
    reliability: ConfidenceScore,
    observed_at_ms: u64,
}

impl Evidence {
    /// Records evidence with an explicit source reliability and a generated ID.
    pub fn new(
        subject: EntityId,
        kind: EvidenceKind,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        source: EvidenceSource,
        reliability: ConfidenceScore,
    ) -> Self {
        Self {
            id: EvidenceId::new(),
            subject,
            kind,
            predicate,
            value,
            source,
            reliability,
            observed_at_ms: now_ms(),
        }
    }

    /// Returns the evidence identifier.
    pub fn id(&self) -> &EvidenceId {
        &self.id
    }

    /// Returns the entity this observation describes.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the broad evidence category.
    pub fn kind(&self) -> &EvidenceKind {
        &self.kind
    }

    /// Returns the namespaced predicate.
    pub fn predicate(&self) -> &KnowledgePredicate {
        &self.predicate
    }

    /// Returns the typed observation value.
    pub fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Returns the observation provenance.
    pub fn source(&self) -> &EvidenceSource {
        &self.source
    }

    /// Returns the source reliability score.
    pub fn reliability(&self) -> ConfidenceScore {
        self.reliability
    }

    /// Returns the observation timestamp in Unix milliseconds.
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
}

/// Materialized claim backed by at least one evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    id: String,
    subject: EntityId,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    confidence: ConfidenceScore,
    #[serde(deserialize_with = "deserialize_non_empty_evidence_ids")]
    evidence_ids: BTreeSet<EvidenceId>,
    asserted_at_ms: u64,
}

impl Fact {
    /// Creates a fact backed by one evidence record.
    pub fn new(
        subject: EntityId,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        confidence: ConfidenceScore,
        evidence_id: EvidenceId,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            subject,
            predicate,
            value,
            confidence,
            evidence_ids: BTreeSet::from([evidence_id]),
            asserted_at_ms: now_ms(),
        }
    }

    /// Replaces the fact confidence score.
    pub fn with_confidence(mut self, confidence: ConfidenceScore) -> Self {
        self.confidence = confidence;
        self
    }

    /// Adds provenance without counting the same evidence twice.
    pub fn add_evidence(&mut self, evidence_id: EvidenceId) {
        self.evidence_ids.insert(evidence_id);
    }

    /// Returns the fact identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the claim subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the claim predicate.
    pub fn predicate(&self) -> &KnowledgePredicate {
        &self.predicate
    }

    /// Returns the claim value.
    pub fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Returns the confidence score.
    pub fn confidence(&self) -> ConfidenceScore {
        self.confidence
    }

    /// Returns the evidence records supporting this fact.
    pub fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence_ids
    }

    /// Returns when the fact was asserted in Unix milliseconds.
    pub fn asserted_at_ms(&self) -> u64 {
        self.asserted_at_ms
    }
}

/// Direction in which evidence affects a hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContributionDirection {
    /// Evidence supports the claim.
    Supporting,
    /// Evidence contradicts the claim.
    Contradicting,
}

/// Explainable weighted evidence attached to a hypothesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceContribution {
    evidence_id: EvidenceId,
    direction: ContributionDirection,
    weight: ConfidenceScore,
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    rationale: String,
}

impl EvidenceContribution {
    /// Creates a contribution with a non-empty explanation.
    pub fn new(
        evidence_id: EvidenceId,
        direction: ContributionDirection,
        weight: ConfidenceScore,
        rationale: impl Into<String>,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            evidence_id,
            direction,
            weight,
            rationale: non_empty(rationale, "evidence contribution rationale")?,
        })
    }

    /// Returns the referenced evidence identifier.
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// Returns whether this contribution supports or contradicts the claim.
    pub fn direction(&self) -> ContributionDirection {
        self.direction
    }

    /// Returns the ordinal contribution weight.
    pub fn weight(&self) -> ConfidenceScore {
        self.weight
    }

    /// Returns the human-readable reason for the contribution.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// Likelihoods contributed by one immutable evidence record.
///
/// # Example
///
/// ```rust
/// use venom_core::{BayesianEvidence, EvidenceId, Probability};
///
/// let observation = BayesianEvidence::new(
///     EvidenceId::parse("cookie-xsrf-token")?,
///     Probability::from_percent(80)?,
///     Probability::from_percent(20)?,
///     "XSRF-TOKEN is more likely when the framework is present",
/// )?;
///
/// assert_eq!(observation.likelihood_if_true().parts_per_million(), 800_000);
/// # Ok::<(), venom_core::ReasoningModelError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BayesianEvidence {
    evidence_id: EvidenceId,
    likelihood_if_true: Probability,
    likelihood_if_false: Probability,
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    rationale: String,
}

impl BayesianEvidence {
    /// Creates one explainable likelihood observation.
    pub fn new(
        evidence_id: EvidenceId,
        likelihood_if_true: Probability,
        likelihood_if_false: Probability,
        rationale: impl Into<String>,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            evidence_id,
            likelihood_if_true,
            likelihood_if_false,
            rationale: non_empty(rationale, "Bayesian evidence rationale")?,
        })
    }

    /// Returns the referenced evidence identifier.
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// Returns `P(E|H)`.
    pub fn likelihood_if_true(&self) -> Probability {
        self.likelihood_if_true
    }

    /// Returns `P(E|not H)`.
    pub fn likelihood_if_false(&self) -> Probability {
        self.likelihood_if_false
    }

    /// Returns the human-readable reason for these likelihoods.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// Result of adding evidence to a Bayesian belief.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BeliefWrite {
    /// A new evidence identifier was added.
    Inserted,
    /// Existing likelihoods for the evidence identifier were replaced.
    Replaced,
    /// The same evidence and likelihoods were already present.
    Unchanged,
}

/// One explainable step in a posterior calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BayesianUpdate {
    evidence_id: EvidenceId,
    prior: Probability,
    likelihood_if_true: Probability,
    likelihood_if_false: Probability,
    posterior: Probability,
    rationale: String,
}

impl BayesianUpdate {
    /// Returns the evidence applied in this step.
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// Returns the probability before this observation.
    pub fn prior(&self) -> Probability {
        self.prior
    }

    /// Returns `P(E|H)` for this observation.
    pub fn likelihood_if_true(&self) -> Probability {
        self.likelihood_if_true
    }

    /// Returns `P(E|not H)` for this observation.
    pub fn likelihood_if_false(&self) -> Probability {
        self.likelihood_if_false
    }

    /// Returns the probability after this observation.
    pub fn posterior(&self) -> Probability {
        self.posterior
    }

    /// Returns the explanation attached to this observation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// Deterministic Bayesian state for one hypothesis.
///
/// Evidence is stored and replayed in [`EvidenceId`] order. Inserting the same
/// set in a different arrival order therefore produces an identical posterior
/// and audit trail. Reusing an evidence identifier replaces its likelihoods
/// instead of double counting the observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BayesianBelief {
    prior: Probability,
    posterior: Probability,
    evidence: Vec<BayesianEvidence>,
    #[serde(skip)]
    updates: Vec<BayesianUpdate>,
}

impl BayesianBelief {
    /// Starts a belief at a calibrated prior.
    pub fn new(prior: Probability) -> Self {
        Self {
            prior,
            posterior: prior,
            evidence: Vec::new(),
            updates: Vec::new(),
        }
    }

    /// Adds or replaces one observation and recomputes the posterior.
    ///
    /// The operation is transactional: an undefined update leaves the belief
    /// unchanged.
    pub fn observe(
        &mut self,
        observation: BayesianEvidence,
    ) -> Result<BeliefWrite, ReasoningModelError> {
        let mut candidate = self.evidence.clone();
        let write = match candidate
            .binary_search_by(|existing| existing.evidence_id.cmp(&observation.evidence_id))
        {
            Ok(index) if candidate[index] == observation => return Ok(BeliefWrite::Unchanged),
            Ok(index) => {
                candidate[index] = observation;
                BeliefWrite::Replaced
            },
            Err(index) => {
                candidate.insert(index, observation);
                BeliefWrite::Inserted
            },
        };
        let (posterior, updates) = calculate_bayesian_updates(self.prior, &candidate)?;

        self.posterior = posterior;
        self.evidence = candidate;
        self.updates = updates;
        Ok(write)
    }

    /// Returns the initial probability before observations.
    pub fn prior(&self) -> Probability {
        self.prior
    }

    /// Returns the current posterior probability.
    pub fn posterior(&self) -> Probability {
        self.posterior
    }

    /// Returns observations in deterministic evidence-identifier order.
    pub fn evidence(&self) -> &[BayesianEvidence] {
        &self.evidence
    }

    /// Returns every intermediate Bayesian update in evaluation order.
    pub fn updates(&self) -> &[BayesianUpdate] {
        &self.updates
    }
}

impl<'de> Deserialize<'de> for BayesianBelief {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireBelief {
            prior: Probability,
            posterior: Probability,
            evidence: Vec<BayesianEvidence>,
        }

        let wire = WireBelief::deserialize(deserializer)?;
        let mut belief = Self::new(wire.prior);
        let mut evidence_ids = BTreeSet::new();
        for observation in wire.evidence {
            if !evidence_ids.insert(observation.evidence_id.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate Bayesian evidence id {}",
                    observation.evidence_id
                )));
            }
            belief
                .observe(observation)
                .map_err(serde::de::Error::custom)?;
        }
        if belief.posterior != wire.posterior {
            return Err(serde::de::Error::custom(format!(
                "serialized posterior {} does not match computed posterior {}",
                wire.posterior.parts_per_million(),
                belief.posterior.parts_per_million()
            )));
        }
        Ok(belief)
    }
}

fn calculate_bayesian_updates(
    prior: Probability,
    evidence: &[BayesianEvidence],
) -> Result<(Probability, Vec<BayesianUpdate>), ReasoningModelError> {
    let mut current = prior;
    let mut updates = Vec::with_capacity(evidence.len());
    for observation in evidence {
        let posterior = current.update(
            observation.likelihood_if_true,
            observation.likelihood_if_false,
        )?;
        updates.push(BayesianUpdate {
            evidence_id: observation.evidence_id.clone(),
            prior: current,
            likelihood_if_true: observation.likelihood_if_true,
            likelihood_if_false: observation.likelihood_if_false,
            posterior,
            rationale: observation.rationale.clone(),
        });
        current = posterior;
    }
    Ok((current, updates))
}

/// Lifecycle state for an evaluated hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HypothesisState {
    /// The claim has not accumulated meaningful evidence yet.
    Proposed,
    /// Current evidence supports the claim.
    Supported,
    /// Current evidence weakens or conflicts with the claim.
    Contradicted,
    /// A verifier confirmed the claim.
    Confirmed,
    /// A verifier rejected the claim.
    Rejected,
}

/// Rule-assigned evidence strength for a hypothesis.
///
/// Strength is intentionally separate from posterior probability. A rule can
/// require independent evidence sources before marking a highly probable claim
/// as strong.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HypothesisStrength {
    /// Evidence has not yet satisfied the rule's strong-evidence criteria.
    #[default]
    Weak,
    /// The rule considers the evidence sufficiently independent and specific.
    Strong,
}

/// Explainable claim whose belief is maintained by a reasoning engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    id: String,
    subject: EntityId,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    belief: BayesianBelief,
    strength: HypothesisStrength,
    state: HypothesisState,
    updated_at_ms: u64,
}

impl Hypothesis {
    /// Creates a weak, proposed claim at the supplied calibrated prior.
    pub fn new(
        subject: EntityId,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        prior: Probability,
    ) -> Self {
        Self::with_id(
            uuid::Uuid::new_v4().to_string(),
            subject,
            predicate,
            value,
            prior,
        )
        .expect("generated UUID is a non-empty hypothesis identifier")
    }

    /// Creates a hypothesis with a stable host-assigned identifier.
    ///
    /// Deterministic decision engines should use this constructor so repeated
    /// evaluation updates one hypothesis instead of creating duplicates.
    pub fn with_id(
        id: impl Into<String>,
        subject: EntityId,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        prior: Probability,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            id: non_empty(id, "hypothesis id")?,
            subject,
            predicate,
            value,
            belief: BayesianBelief::new(prior),
            strength: HypothesisStrength::Weak,
            state: HypothesisState::Proposed,
            updated_at_ms: now_ms(),
        })
    }

    /// Applies one observation to the Bayesian belief.
    pub fn observe(
        &mut self,
        observation: BayesianEvidence,
    ) -> Result<BeliefWrite, ReasoningModelError> {
        let write = self.belief.observe(observation)?;
        if write != BeliefWrite::Unchanged {
            self.updated_at_ms = now_ms();
        }
        Ok(write)
    }

    /// Replaces the strength assigned by a deterministic rule.
    pub fn set_strength(&mut self, strength: HypothesisStrength) {
        self.strength = strength;
        self.updated_at_ms = now_ms();
    }

    /// Replaces the lifecycle state assigned by the reasoning engine or verifier.
    pub fn set_state(&mut self, state: HypothesisState) {
        self.state = state;
        self.updated_at_ms = now_ms();
    }

    /// Returns the hypothesis identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the claim subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the claim predicate.
    pub fn predicate(&self) -> &KnowledgePredicate {
        &self.predicate
    }

    /// Returns the claim value.
    pub fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Returns the complete Bayesian belief and audit trail.
    pub fn belief(&self) -> &BayesianBelief {
        &self.belief
    }

    /// Returns the calibrated prior probability.
    pub fn prior(&self) -> Probability {
        self.belief.prior()
    }

    /// Returns the current posterior probability.
    pub fn posterior(&self) -> Probability {
        self.belief.posterior()
    }

    /// Returns the rule-assigned evidence strength.
    pub fn strength(&self) -> HypothesisStrength {
        self.strength
    }

    /// Returns the current evaluation state.
    pub fn state(&self) -> HypothesisState {
        self.state
    }

    /// Returns when the hypothesis last changed in Unix milliseconds.
    pub fn updated_at_ms(&self) -> u64 {
        self.updated_at_ms
    }

    /// Returns whether two records carry the same decision state.
    ///
    /// Wall-clock update timestamps are deliberately ignored so deterministic
    /// re-evaluation can remain idempotent.
    pub fn same_evaluation_as(&self, other: &Self) -> bool {
        self.id == other.id
            && self.subject == other.subject
            && self.predicate == other.predicate
            && self.value == other.value
            && self.belief == other.belief
            && self.strength == other.strength
            && self.state == other.state
    }
}

/// Entity categories understood by the knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntityKind {
    /// Network host or DNS name.
    Host,
    /// Protocol service exposed by a host.
    Service,
    /// Addressable application endpoint.
    Endpoint,
    /// Detected language, framework, server, or component.
    Technology,
    /// User, service account, or other principal.
    Identity,
    /// Authentication or application session.
    Session,
    /// Request or protocol input parameter.
    Parameter,
    /// Secret, token, key, or other credential material.
    Credential,
    /// Extension entity category with a stable identifier.
    Custom(String),
}

/// A typed node in the future knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeEntity {
    id: EntityId,
    kind: EntityKind,
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    label: String,
}

impl KnowledgeEntity {
    /// Creates an entity with a non-empty display label.
    pub fn new(
        id: EntityId,
        kind: EntityKind,
        label: impl Into<String>,
    ) -> Result<Self, ReasoningModelError> {
        Ok(Self {
            id,
            kind,
            label: non_empty(label, "entity label")?,
        })
    }

    /// Returns the entity identifier.
    pub fn id(&self) -> &EntityId {
        &self.id
    }

    /// Returns the entity category.
    pub fn kind(&self) -> &EntityKind {
        &self.kind
    }

    /// Returns the human-readable label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Relationship categories understood by the knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelationKind {
    /// A host exposes a service.
    Exposes,
    /// A service serves an endpoint or resource.
    Serves,
    /// One entity uses another.
    Uses,
    /// One entity depends on another.
    DependsOn,
    /// One entity contains another.
    Contains,
    /// An entity authenticates using another entity.
    AuthenticatesWith,
    /// An entity or claim was derived from another.
    DerivedFrom,
    /// Generic association when no stronger relation is known.
    RelatedTo,
    /// Extension relation category with a stable identifier.
    Custom(String),
}

/// Evidence-backed directed edge between two knowledge entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeRelation {
    id: RelationId,
    from: EntityId,
    to: EntityId,
    kind: RelationKind,
    confidence: ConfidenceScore,
    #[serde(deserialize_with = "deserialize_non_empty_evidence_ids")]
    evidence_ids: BTreeSet<EvidenceId>,
}

impl KnowledgeRelation {
    /// Creates a directed relation backed by one evidence record.
    pub fn new(
        from: EntityId,
        to: EntityId,
        kind: RelationKind,
        confidence: ConfidenceScore,
        evidence_id: EvidenceId,
    ) -> Self {
        Self {
            id: RelationId::new(),
            from,
            to,
            kind,
            confidence,
            evidence_ids: BTreeSet::from([evidence_id]),
        }
    }

    /// Adds provenance without counting the same evidence twice.
    pub fn add_evidence(&mut self, evidence_id: EvidenceId) {
        self.evidence_ids.insert(evidence_id);
    }

    /// Returns the relation identifier.
    pub fn id(&self) -> &RelationId {
        &self.id
    }

    /// Returns the source entity identifier.
    pub fn from(&self) -> &EntityId {
        &self.from
    }

    /// Returns the destination entity identifier.
    pub fn to(&self) -> &EntityId {
        &self.to
    }

    /// Returns the relation category.
    pub fn kind(&self) -> &RelationKind {
        &self.kind
    }

    /// Returns the relation confidence score.
    pub fn confidence(&self) -> ConfidenceScore {
        self.confidence
    }

    /// Returns the evidence records supporting this edge.
    pub fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence_ids
    }
}

fn now_ms() -> u64 {
    let milliseconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(milliseconds).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test/api").unwrap()
    }

    fn predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("technology", "framework").unwrap()
    }

    fn source() -> EvidenceSource {
        EvidenceSource::new("fingerprint.headers", "x-powered-by")
            .unwrap()
            .with_correlation_id("scan-42")
            .unwrap()
    }

    fn evidence() -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Technology,
            predicate(),
            EvidenceValue::Text("Laravel".into()),
            source(),
            ConfidenceScore::from_percent(90).unwrap(),
        )
    }

    #[test]
    fn confidence_rejects_out_of_range_values() {
        assert_eq!(
            ConfidenceScore::from_basis_points(10_001),
            Err(ReasoningModelError::ConfidenceOutOfRange(10_001))
        );
        assert_eq!(
            ConfidenceScore::from_percent(101),
            Err(ReasoningModelError::ConfidenceOutOfRange(10_100))
        );
    }

    #[test]
    fn confidence_rejects_invalid_wire_values() {
        assert!(serde_json::from_str::<ConfidenceScore>("10001").is_err());
        assert_eq!(
            serde_json::from_str::<ConfidenceScore>("8200").unwrap(),
            ConfidenceScore::from_percent(82).unwrap()
        );
    }

    #[test]
    fn probability_rejects_out_of_range_values() {
        assert_eq!(
            Probability::from_parts_per_million(1_000_001),
            Err(ReasoningModelError::ProbabilityOutOfRange(1_000_001))
        );
        assert_eq!(
            Probability::from_percent(101),
            Err(ReasoningModelError::ProbabilityOutOfRange(1_010_000))
        );
        assert!(serde_json::from_str::<Probability>("1000001").is_err());
    }

    #[test]
    fn probability_applies_bayes_theorem_with_fixed_point_rounding() {
        let posterior = Probability::from_percent(10)
            .unwrap()
            .update(
                Probability::from_percent(80).unwrap(),
                Probability::from_percent(20).unwrap(),
            )
            .unwrap();

        assert_eq!(posterior.parts_per_million(), 307_692);
        assert_eq!(
            Probability::ZERO.update(Probability::ZERO, Probability::ZERO),
            Err(ReasoningModelError::UndefinedPosterior)
        );
    }

    #[test]
    fn evidence_round_trip_preserves_provenance() {
        let evidence = evidence();
        let encoded = serde_json::to_string(&evidence).unwrap();
        let decoded: Evidence = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, evidence);
        assert_eq!(decoded.source().component(), "fingerprint.headers");
        assert_eq!(decoded.source().correlation_id(), Some("scan-42"));
        assert_eq!(decoded.reliability().basis_points(), 9_000);
    }

    #[test]
    fn fact_deduplicates_evidence_provenance() {
        let evidence = evidence();
        let evidence_id = evidence.id().clone();
        let mut fact = Fact::new(
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
            ConfidenceScore::from_percent(90).unwrap(),
            evidence_id.clone(),
        );

        fact.add_evidence(evidence_id);

        assert_eq!(fact.evidence_ids().len(), 1);
        assert_eq!(fact.confidence().basis_points(), 9_000);
    }

    #[test]
    fn hypothesis_uses_bayesian_belief_and_explicit_strength() {
        let evidence = evidence();
        let mut hypothesis = Hypothesis::new(
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
            Probability::from_percent(10).unwrap(),
        );
        assert_eq!(hypothesis.strength(), HypothesisStrength::Weak);
        assert_eq!(
            hypothesis
                .observe(
                    BayesianEvidence::new(
                        evidence.id().clone(),
                        Probability::from_percent(80).unwrap(),
                        Probability::from_percent(20).unwrap(),
                        "framework header observed",
                    )
                    .unwrap(),
                )
                .unwrap(),
            BeliefWrite::Inserted
        );
        assert_eq!(hypothesis.posterior().parts_per_million(), 307_692);
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);

        assert_eq!(hypothesis.belief().evidence().len(), 1);
        assert_eq!(hypothesis.belief().updates().len(), 1);
        assert_eq!(hypothesis.strength(), HypothesisStrength::Strong);
        assert_eq!(hypothesis.state(), HypothesisState::Supported);
    }

    #[test]
    fn hypothesis_stable_identity_ignores_wall_clock_for_idempotency() {
        let evidence = evidence();
        let first = Hypothesis::with_id(
            "rule:laravel:endpoint",
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
            Probability::from_percent(10).unwrap(),
        )
        .unwrap();
        let second = Hypothesis::with_id(
            "rule:laravel:endpoint",
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
            Probability::from_percent(10).unwrap(),
        )
        .unwrap();

        assert!(first.same_evaluation_as(&second));
        assert!(Hypothesis::with_id(
            " ",
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
            Probability::from_percent(10).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn bayesian_belief_is_idempotent_and_order_independent() {
        let first = BayesianEvidence::new(
            EvidenceId::parse("evidence:a").unwrap(),
            Probability::from_percent(80).unwrap(),
            Probability::from_percent(20).unwrap(),
            "specific cookie",
        )
        .unwrap();
        let second = BayesianEvidence::new(
            EvidenceId::parse("evidence:b").unwrap(),
            Probability::from_percent(70).unwrap(),
            Probability::from_percent(30).unwrap(),
            "framework header",
        )
        .unwrap();
        let mut forward = BayesianBelief::new(Probability::from_percent(10).unwrap());
        let mut reverse = BayesianBelief::new(Probability::from_percent(10).unwrap());

        assert_eq!(
            forward.observe(first.clone()).unwrap(),
            BeliefWrite::Inserted
        );
        assert_eq!(
            forward.observe(second.clone()).unwrap(),
            BeliefWrite::Inserted
        );
        assert_eq!(
            forward.observe(first.clone()).unwrap(),
            BeliefWrite::Unchanged
        );
        reverse.observe(second).unwrap();
        reverse.observe(first).unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(forward.evidence().len(), 2);
        assert_eq!(forward.updates()[0].evidence_id().as_str(), "evidence:a");
        assert_eq!(forward.updates()[1].evidence_id().as_str(), "evidence:b");
    }

    #[test]
    fn bayesian_belief_replaces_likelihoods_transactionally() {
        let evidence_id = EvidenceId::parse("evidence:cookie").unwrap();
        let mut belief = BayesianBelief::new(Probability::from_percent(10).unwrap());
        belief
            .observe(
                BayesianEvidence::new(
                    evidence_id.clone(),
                    Probability::from_percent(80).unwrap(),
                    Probability::from_percent(20).unwrap(),
                    "initial calibration",
                )
                .unwrap(),
            )
            .unwrap();
        let original = belief.clone();

        assert_eq!(
            belief
                .observe(
                    BayesianEvidence::new(
                        evidence_id.clone(),
                        Probability::from_percent(90).unwrap(),
                        Probability::from_percent(10).unwrap(),
                        "recalibrated",
                    )
                    .unwrap(),
                )
                .unwrap(),
            BeliefWrite::Replaced
        );
        assert_eq!(belief.evidence().len(), 1);
        assert_ne!(belief.posterior(), original.posterior());

        let before_invalid_update = belief.clone();
        assert_eq!(
            belief.observe(
                BayesianEvidence::new(
                    evidence_id,
                    Probability::ZERO,
                    Probability::ZERO,
                    "invalid calibration",
                )
                .unwrap()
            ),
            Err(ReasoningModelError::UndefinedPosterior)
        );
        assert_eq!(belief, before_invalid_update);
    }

    #[test]
    fn bayesian_belief_wire_format_recomputes_posterior() {
        let evidence = evidence();
        let mut belief = BayesianBelief::new(Probability::from_percent(10).unwrap());
        belief
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(80).unwrap(),
                    Probability::from_percent(20).unwrap(),
                    "framework header observed",
                )
                .unwrap(),
            )
            .unwrap();
        let encoded = serde_json::to_value(&belief).unwrap();
        let decoded: BayesianBelief = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, belief);

        let mut tampered = encoded;
        tampered["posterior"] = serde_json::json!(500_000);
        assert!(serde_json::from_value::<BayesianBelief>(tampered).is_err());

        let mut duplicated = serde_json::to_value(&belief).unwrap();
        let first_observation = duplicated["evidence"][0].clone();
        duplicated["evidence"]
            .as_array_mut()
            .unwrap()
            .push(first_observation);
        assert!(serde_json::from_value::<BayesianBelief>(duplicated).is_err());
    }

    #[test]
    fn relation_deduplicates_evidence_provenance() {
        let evidence = evidence();
        let evidence_id = evidence.id().clone();
        let mut relation = KnowledgeRelation::new(
            EntityId::new("technology:php").unwrap(),
            EntityId::new("technology:laravel").unwrap(),
            RelationKind::Uses,
            ConfidenceScore::from_percent(82).unwrap(),
            evidence_id.clone(),
        );

        relation.add_evidence(evidence_id);

        assert_eq!(relation.evidence_ids().len(), 1);
        assert_eq!(relation.confidence().basis_points(), 8_200);
    }

    #[test]
    fn required_names_reject_whitespace() {
        assert!(EntityId::new("   ").is_err());
        assert!(KnowledgePredicate::new("http", " ").is_err());
        assert!(EvidenceSource::new("", "header").is_err());
        assert!(EvidenceSource::new("http", "header")
            .unwrap()
            .with_correlation_id(" ")
            .is_err());
        assert!(KnowledgeEntity::new(subject(), EntityKind::Endpoint, " ").is_err());
    }

    #[test]
    fn wire_format_cannot_bypass_non_empty_invariants() {
        let evidence = evidence();
        let mut fact = Fact::new(
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
            ConfidenceScore::from_percent(90).unwrap(),
            evidence.id().clone(),
        );
        fact.evidence_ids.clear();
        assert!(serde_json::from_value::<Fact>(serde_json::to_value(fact).unwrap()).is_err());

        let invalid_entity = serde_json::json!({
            "id": "endpoint:test",
            "kind": "endpoint",
            "label": " "
        });
        assert!(serde_json::from_value::<KnowledgeEntity>(invalid_entity).is_err());

        let invalid_contribution = serde_json::json!({
            "evidence_id": evidence.id(),
            "direction": "supporting",
            "weight": 5_000,
            "rationale": " "
        });
        assert!(serde_json::from_value::<EvidenceContribution>(invalid_contribution).is_err());
    }
}
