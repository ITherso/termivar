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

/// Explainable claim whose score is maintained by a reasoning engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    id: String,
    subject: EntityId,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    confidence: ConfidenceScore,
    state: HypothesisState,
    contributions: Vec<EvidenceContribution>,
    updated_at_ms: u64,
}

impl Hypothesis {
    /// Creates a proposed claim with no confidence or evidence.
    pub fn new(subject: EntityId, predicate: KnowledgePredicate, value: EvidenceValue) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            subject,
            predicate,
            value,
            confidence: ConfidenceScore::NONE,
            state: HypothesisState::Proposed,
            contributions: Vec::new(),
            updated_at_ms: now_ms(),
        }
    }

    /// Replaces the score assigned by the reasoning engine.
    pub fn set_confidence(&mut self, confidence: ConfidenceScore) {
        self.confidence = confidence;
        self.updated_at_ms = now_ms();
    }

    /// Replaces the lifecycle state assigned by the reasoning engine or verifier.
    pub fn set_state(&mut self, state: HypothesisState) {
        self.state = state;
        self.updated_at_ms = now_ms();
    }

    /// Adds or replaces one evidence contribution.
    ///
    /// An evidence record can affect a hypothesis only once, preventing an
    /// accidental double count when a module reports the same observation
    /// repeatedly.
    pub fn add_contribution(&mut self, contribution: EvidenceContribution) {
        if let Some(existing) = self
            .contributions
            .iter_mut()
            .find(|existing| existing.evidence_id == contribution.evidence_id)
        {
            *existing = contribution;
        } else {
            self.contributions.push(contribution);
        }
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

    /// Returns the current confidence score.
    pub fn confidence(&self) -> ConfidenceScore {
        self.confidence
    }

    /// Returns the current evaluation state.
    pub fn state(&self) -> HypothesisState {
        self.state
    }

    /// Returns the explainable evidence contributions.
    pub fn contributions(&self) -> &[EvidenceContribution] {
        &self.contributions
    }

    /// Returns when the hypothesis last changed in Unix milliseconds.
    pub fn updated_at_ms(&self) -> u64 {
        self.updated_at_ms
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
    fn hypothesis_replaces_duplicate_contributions() {
        let evidence = evidence();
        let mut hypothesis = Hypothesis::new(
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
        );
        hypothesis.add_contribution(
            EvidenceContribution::new(
                evidence.id().clone(),
                ContributionDirection::Supporting,
                ConfidenceScore::from_percent(25).unwrap(),
                "framework header observed",
            )
            .unwrap(),
        );
        hypothesis.add_contribution(
            EvidenceContribution::new(
                evidence.id().clone(),
                ContributionDirection::Contradicting,
                ConfidenceScore::from_percent(10).unwrap(),
                "header may be forged",
            )
            .unwrap(),
        );
        hypothesis.set_confidence(ConfidenceScore::from_percent(15).unwrap());
        hypothesis.set_state(HypothesisState::Supported);

        assert_eq!(hypothesis.contributions().len(), 1);
        assert_eq!(
            hypothesis.contributions().first().unwrap().direction(),
            ContributionDirection::Contradicting
        );
        assert_eq!(hypothesis.confidence().basis_points(), 1_500);
        assert_eq!(hypothesis.state(), HypothesisState::Supported);
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
