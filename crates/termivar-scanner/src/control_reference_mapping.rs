//! Bounded, offline control-reference mapping for composed assessment items.
//!
//! The built-in catalogue deliberately contains only reviewed identifiers,
//! bibliographic metadata, and original Termivar mapping rationales. Mapping an
//! item supplies technical review context; it is not a control assessment,
//! compliance determination, certification, or legal conclusion.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::web_runtime::{AssessmentBasis, AssessmentItem};

/// Stable audit schema written by the reporting layer.
pub const CONTROL_REFERENCE_MAPPING_AUDIT_SCHEMA: &str =
    "security.control-reference-mapping-audit/v1";
/// Stable mapping-policy identity.
pub const CONTROL_REFERENCE_MAPPING_POLICY_ID: &str = "termivar.control-reference-mapping/v1";
/// Stable identity of the reviewed, built-in reference catalogue.
pub const CONTROL_REFERENCE_MAPPING_CATALOGUE_ID: &str = "termivar.reviewed-control-references";
/// Revision of the built-in catalogue used by this source tree.
pub const CONTROL_REFERENCE_MAPPING_CATALOGUE_REVISION: &str = "2026-09-20.1";
/// Date on which the primary source metadata was reviewed.
pub const CONTROL_REFERENCE_SOURCE_VERIFIED_AT: &str = "2026-09-20";

/// Maximum assessment items accepted by one mapping pass.
pub const MAX_CONTROL_REFERENCE_MAPPING_ITEMS: usize = 4_096;
/// Maximum retained mapped-item relationships.
pub const MAX_CONTROL_REFERENCE_MAPPING_RELATIONSHIPS: usize = 4_096;
/// Maximum control-reference links retained across one audit.
pub const MAX_CONTROL_REFERENCE_MAPPING_LINKS: usize = 16_384;
/// Maximum control-reference links retained for one assessment item.
pub const MAX_CONTROL_REFERENCE_LINKS_PER_ITEM: usize = 8;

const OWASP_SOURCE_ID: &str = "owasp-top-10-2025";
const PCI_SOURCE_ID: &str = "pci-dss-4.0.1";
const ISO_SOURCE_ID: &str = "iso-iec-27001-2022-amd-1-2024";
const KVKK_LAW_SOURCE_ID: &str = "kvkk-law-6698-article-12";
const KVKK_GUIDE_SOURCE_ID: &str = "kvkk-guide-72-2025-04";

const OWASP_A01: &str = "A01:2025";
const OWASP_A02: &str = "A02:2025";
const OWASP_A05: &str = "A05:2025";
const KVKK_ARTICLE_12: &str = "6698/Madde-12";
const KVKK_GUIDE_72: &str = "KVKK-Rehber-72/2025-04";

/// Authority class for a reviewed external reference source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceAuthorityKind {
    /// Open community security project.
    CommunitySecurityProject,
    /// Industry standards organization.
    IndustryStandardsBody,
    /// International standards organization.
    InternationalStandardsOrganization,
    /// Statutory text or regulator publication.
    StatutoryAuthority,
}

impl ControlReferenceAuthorityKind {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommunitySecurityProject => "community_security_project",
            Self::IndustryStandardsBody => "industry_standards_body",
            Self::InternationalStandardsOrganization => "international_standards_organization",
            Self::StatutoryAuthority => "statutory_authority",
        }
    }
}

/// Availability of control-level mappings from one source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceMappingAvailability {
    /// Reviewed identifiers and short titles can be mapped with attribution.
    ReviewedIdentifiersAndTitles,
    /// Only bibliographic source metadata is retained because rights review is deferred.
    BibliographicOnlyRightsDeferred,
    /// The source is used only as relevant technical context.
    RelevantTechnicalContextOnly,
}

impl ControlReferenceMappingAvailability {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewedIdentifiersAndTitles => "reviewed_identifiers_and_titles",
            Self::BibliographicOnlyRightsDeferred => "bibliographic_only_rights_deferred",
            Self::RelevantTechnicalContextOnly => "relevant_technical_context_only",
        }
    }
}

/// Rights posture for the metadata retained from one source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceRightsBasis {
    /// Identifiers and short titles retained with source attribution.
    IdentifiersAndTitlesWithAttribution,
    /// Only bibliographic metadata and an official source link are retained.
    BibliographicMetadataOnly,
    /// Only an official legal/regulator reference and original rationale are retained.
    OfficialReferenceOnly,
}

impl ControlReferenceRightsBasis {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentifiersAndTitlesWithAttribution => "identifiers_and_titles_with_attribution",
            Self::BibliographicMetadataOnly => "bibliographic_metadata_only",
            Self::OfficialReferenceOnly => "official_reference_only",
        }
    }
}

/// Typed assessment-item authority required by a mapping rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceItemBasisClass {
    /// Passive or structural observation.
    Observation,
    /// Matched control/candidate differential.
    Differential,
    /// Native verifier result.
    Verifier,
}

impl ControlReferenceItemBasisClass {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Differential => "differential",
            Self::Verifier => "verifier",
        }
    }

    fn from_basis(basis: &AssessmentBasis) -> Self {
        match basis {
            AssessmentBasis::Observation(_) => Self::Observation,
            AssessmentBasis::Differential(_) => Self::Differential,
            AssessmentBasis::Verifier(_) => Self::Verifier,
        }
    }
}

/// Exact matching inputs used by one mapping rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceMappingBasis {
    /// Exact capability, exact CWE, and exact assessment basis.
    ExactCapabilityCweAndAssessmentBasis,
    /// Exact capability, absent CWE, and exact assessment basis.
    ExactCapabilityAndAssessmentBasis,
}

impl ControlReferenceMappingBasis {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactCapabilityCweAndAssessmentBasis => {
                "exact_capability_cwe_and_assessment_basis"
            },
            Self::ExactCapabilityAndAssessmentBasis => "exact_capability_and_assessment_basis",
        }
    }
}

/// Applicability qualification attached to a control reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceApplicability {
    /// The reference is relevant only under the stated technical conditions.
    ConditionalTechnicalContext,
    /// Organizational/legal applicability was not established by the scan.
    ApplicabilityUnestablished,
}

impl ControlReferenceApplicability {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConditionalTechnicalContext => "conditional_technical_context",
            Self::ApplicabilityUnestablished => "applicability_unestablished",
        }
    }
}

/// Assurance of the mapping source and relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ControlReferenceMappingAssurance {
    /// Identifier/edition checked against the named official primary source.
    ReviewedPrimarySourceIdentifier,
    /// Relevant technical context only; applicability is not established.
    RelevantTechnicalContext,
}

impl ControlReferenceMappingAssurance {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewedPrimarySourceIdentifier => "reviewed_primary_source_identifier",
            Self::RelevantTechnicalContext => "relevant_technical_context",
        }
    }
}

/// Whether external source retrieval occurred while producing an audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlReferenceSourceRetrievalState {
    /// Mapping used only the built-in reviewed catalogue.
    NotPerformed,
}

impl ControlReferenceSourceRetrievalState {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPerformed => "not_performed",
        }
    }
}

/// Whether an actual framework control assessment was performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAssessmentState {
    /// No control assessment was performed.
    NotPerformed,
}

impl ControlAssessmentState {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPerformed => "not_performed",
        }
    }
}

/// State for compliance, certification, legal, and source-authentication claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlReferenceClaimState {
    /// The proposition was not established by this mapping operation.
    NotEstablished,
}

impl ControlReferenceClaimState {
    /// Stable wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotEstablished => "not_established",
        }
    }
}

/// Reviewed metadata for one reference source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlReferenceSource {
    source_id: &'static str,
    framework_id: &'static str,
    edition: &'static str,
    revision_or_amendment: Option<&'static str>,
    authority_kind: ControlReferenceAuthorityKind,
    source_url: &'static str,
    source_verified_at: &'static str,
    mapping_availability: ControlReferenceMappingAvailability,
    rights_basis: ControlReferenceRightsBasis,
}

impl ControlReferenceSource {
    /// Stable source identity.
    pub const fn source_id(&self) -> &'static str {
        self.source_id
    }

    /// Stable framework or legal-source identity.
    pub const fn framework_id(&self) -> &'static str {
        self.framework_id
    }

    /// Explicit source edition.
    pub const fn edition(&self) -> &'static str {
        self.edition
    }

    /// Explicit revision or amendment, when applicable.
    pub const fn revision_or_amendment(&self) -> Option<&'static str> {
        self.revision_or_amendment
    }

    /// Source authority class.
    pub const fn authority_kind(&self) -> ControlReferenceAuthorityKind {
        self.authority_kind
    }

    /// Official source URL; it is bibliographic data and is never fetched here.
    pub const fn source_url(&self) -> &'static str {
        self.source_url
    }

    /// Date on which the source metadata was reviewed.
    pub const fn source_verified_at(&self) -> &'static str {
        self.source_verified_at
    }

    /// Control-level mapping availability.
    pub const fn mapping_availability(&self) -> ControlReferenceMappingAvailability {
        self.mapping_availability
    }

    /// Rights posture governing retained source metadata.
    pub const fn rights_basis(&self) -> ControlReferenceRightsBasis {
        self.rights_basis
    }
}

const REVIEWED_SOURCES: [ControlReferenceSource; 5] = [
    ControlReferenceSource {
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        edition: "2025",
        revision_or_amendment: None,
        authority_kind: ControlReferenceAuthorityKind::CommunitySecurityProject,
        source_url: "https://top10.owasp.org/2025/0x00_2025-Introduction/",
        source_verified_at: CONTROL_REFERENCE_SOURCE_VERIFIED_AT,
        mapping_availability: ControlReferenceMappingAvailability::ReviewedIdentifiersAndTitles,
        rights_basis: ControlReferenceRightsBasis::IdentifiersAndTitlesWithAttribution,
    },
    ControlReferenceSource {
        source_id: PCI_SOURCE_ID,
        framework_id: "pci-dss",
        edition: "4.0.1",
        revision_or_amendment: Some("published-2024-06-11"),
        authority_kind: ControlReferenceAuthorityKind::IndustryStandardsBody,
        source_url: "https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1",
        source_verified_at: CONTROL_REFERENCE_SOURCE_VERIFIED_AT,
        mapping_availability:
            ControlReferenceMappingAvailability::BibliographicOnlyRightsDeferred,
        rights_basis: ControlReferenceRightsBasis::BibliographicMetadataOnly,
    },
    ControlReferenceSource {
        source_id: ISO_SOURCE_ID,
        framework_id: "iso-iec-27001",
        edition: "2022",
        revision_or_amendment: Some("Amd-1:2024"),
        authority_kind: ControlReferenceAuthorityKind::InternationalStandardsOrganization,
        source_url: "https://www.iso.org/standard/27001",
        source_verified_at: CONTROL_REFERENCE_SOURCE_VERIFIED_AT,
        mapping_availability:
            ControlReferenceMappingAvailability::BibliographicOnlyRightsDeferred,
        rights_basis: ControlReferenceRightsBasis::BibliographicMetadataOnly,
    },
    ControlReferenceSource {
        source_id: KVKK_LAW_SOURCE_ID,
        framework_id: "kvkk-law-6698",
        edition: "6698",
        revision_or_amendment: Some("Madde-12"),
        authority_kind: ControlReferenceAuthorityKind::StatutoryAuthority,
        source_url: "https://www.kvkk.gov.tr/Icerik/2040/Veri-Guvenligine-Iliskin-Yukumlulukler",
        source_verified_at: CONTROL_REFERENCE_SOURCE_VERIFIED_AT,
        mapping_availability:
            ControlReferenceMappingAvailability::RelevantTechnicalContextOnly,
        rights_basis: ControlReferenceRightsBasis::OfficialReferenceOnly,
    },
    ControlReferenceSource {
        source_id: KVKK_GUIDE_SOURCE_ID,
        framework_id: "kvkk-personal-data-security-guide",
        edition: "2025-04",
        revision_or_amendment: Some("KVKK-Yayinlari-No-72"),
        authority_kind: ControlReferenceAuthorityKind::StatutoryAuthority,
        source_url: "https://kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf",
        source_verified_at: CONTROL_REFERENCE_SOURCE_VERIFIED_AT,
        mapping_availability:
            ControlReferenceMappingAvailability::RelevantTechnicalContextOnly,
        rights_basis: ControlReferenceRightsBasis::OfficialReferenceOnly,
    },
];

/// One source-qualified control-reference link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReferenceLink {
    rule_id: &'static str,
    source_id: &'static str,
    framework_id: &'static str,
    control_reference: &'static str,
    control_title: Option<&'static str>,
    mapping_basis: ControlReferenceMappingBasis,
    applicability: ControlReferenceApplicability,
    applicability_condition: &'static str,
    assurance: ControlReferenceMappingAssurance,
    original_mapping_rationale: &'static str,
}

impl ControlReferenceLink {
    /// Stable mapping-rule identity.
    pub const fn rule_id(&self) -> &'static str {
        self.rule_id
    }

    /// Source identity for this reference.
    pub const fn source_id(&self) -> &'static str {
        self.source_id
    }

    /// Framework or legal-source identity.
    pub const fn framework_id(&self) -> &'static str {
        self.framework_id
    }

    /// Edition-qualified control reference.
    pub const fn control_reference(&self) -> &'static str {
        self.control_reference
    }

    /// Short title retained only when the reviewed source permits it.
    pub const fn control_title(&self) -> Option<&'static str> {
        self.control_title
    }

    /// Exact mapping inputs used by this rule.
    pub const fn mapping_basis(&self) -> ControlReferenceMappingBasis {
        self.mapping_basis
    }

    /// Applicability classification.
    pub const fn applicability(&self) -> ControlReferenceApplicability {
        self.applicability
    }

    /// Original, bounded applicability condition.
    pub const fn applicability_condition(&self) -> &'static str {
        self.applicability_condition
    }

    /// Mapping assurance classification.
    pub const fn assurance(&self) -> ControlReferenceMappingAssurance {
        self.assurance
    }

    /// Original Termivar rationale; no standards prose is copied here.
    pub const fn original_mapping_rationale(&self) -> &'static str {
        self.original_mapping_rationale
    }
}

/// One assessment item and its bounded control-reference links.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReferenceRelationship {
    item_fingerprint: String,
    capability_id: String,
    cwe: Option<String>,
    item_basis: ControlReferenceItemBasisClass,
    references: Vec<ControlReferenceLink>,
}

impl ControlReferenceRelationship {
    /// Stable assessment-item fingerprint.
    pub fn item_fingerprint(&self) -> &str {
        &self.item_fingerprint
    }

    /// Exact mapped capability identity.
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    /// Exact mapped CWE, when the rule requires one.
    pub fn cwe(&self) -> Option<&str> {
        self.cwe.as_deref()
    }

    /// Exact mapped assessment-item basis.
    pub const fn item_basis(&self) -> ControlReferenceItemBasisClass {
        self.item_basis
    }

    /// Stable, duplicate-free control-reference links.
    pub fn references(&self) -> &[ControlReferenceLink] {
        &self.references
    }
}

/// External-activity accounting for the pure mapping operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlReferenceExternalActivity {
    target_request_count: u64,
    provider_request_count: u64,
    source_retrieval: ControlReferenceSourceRetrievalState,
}

impl ControlReferenceExternalActivity {
    /// Target requests introduced by mapping.
    pub const fn target_request_count(&self) -> u64 {
        self.target_request_count
    }

    /// Provider requests introduced by mapping.
    pub const fn provider_request_count(&self) -> u64 {
        self.provider_request_count
    }

    /// External source-retrieval state.
    pub const fn source_retrieval(&self) -> ControlReferenceSourceRetrievalState {
        self.source_retrieval
    }
}

/// Explicit claim limits for a control-reference audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlReferenceClaimLimits {
    control_assessment: ControlAssessmentState,
    compliance: ControlReferenceClaimState,
    certification: ControlReferenceClaimState,
    legal_conclusion: ControlReferenceClaimState,
    source_authentication: ControlReferenceClaimState,
}

impl ControlReferenceClaimLimits {
    /// Whether an actual framework control assessment occurred.
    pub const fn control_assessment(&self) -> ControlAssessmentState {
        self.control_assessment
    }

    /// Compliance-conclusion state.
    pub const fn compliance(&self) -> ControlReferenceClaimState {
        self.compliance
    }

    /// Certification-conclusion state.
    pub const fn certification(&self) -> ControlReferenceClaimState {
        self.certification
    }

    /// Legal-conclusion state.
    pub const fn legal_conclusion(&self) -> ControlReferenceClaimState {
        self.legal_conclusion
    }

    /// Source-authentication state.
    pub const fn source_authentication(&self) -> ControlReferenceClaimState {
        self.source_authentication
    }
}

/// Complete bounded output of an offline mapping pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReferenceMappingAudit {
    selected: bool,
    sources: Vec<ControlReferenceSource>,
    relationships: Vec<ControlReferenceRelationship>,
    considered_item_count: usize,
    mapped_item_count: usize,
    unmapped_item_count: usize,
    reference_link_count: usize,
    omitted_item_count: usize,
    omitted_reference_link_count: usize,
    external_activity: ControlReferenceExternalActivity,
    claim_limits: ControlReferenceClaimLimits,
}

impl ControlReferenceMappingAudit {
    /// Stable audit schema.
    pub const fn schema(&self) -> &'static str {
        CONTROL_REFERENCE_MAPPING_AUDIT_SCHEMA
    }

    /// Stable mapping policy.
    pub const fn policy_id(&self) -> &'static str {
        CONTROL_REFERENCE_MAPPING_POLICY_ID
    }

    /// Built-in catalogue identity.
    pub const fn catalogue_id(&self) -> &'static str {
        CONTROL_REFERENCE_MAPPING_CATALOGUE_ID
    }

    /// Built-in catalogue revision.
    pub const fn catalogue_revision(&self) -> &'static str {
        CONTROL_REFERENCE_MAPPING_CATALOGUE_REVISION
    }

    /// The mapping option was explicitly selected.
    pub const fn selected(&self) -> bool {
        self.selected
    }

    /// Reviewed source metadata, including bibliographic-only sources.
    pub fn sources(&self) -> &[ControlReferenceSource] {
        &self.sources
    }

    /// Mapped item relationships, ordered by item fingerprint.
    pub fn relationships(&self) -> &[ControlReferenceRelationship] {
        &self.relationships
    }

    /// Input assessment items considered.
    pub const fn considered_item_count(&self) -> usize {
        self.considered_item_count
    }

    /// Distinct input items with at least one reference link.
    pub const fn mapped_item_count(&self) -> usize {
        self.mapped_item_count
    }

    /// Distinct input items with no applicable exact rule.
    pub const fn unmapped_item_count(&self) -> usize {
        self.unmapped_item_count
    }

    /// Number of mapped-item relationship rows.
    pub fn relationship_count(&self) -> usize {
        self.relationships.len()
    }

    /// Total retained reference links.
    pub const fn reference_link_count(&self) -> usize {
        self.reference_link_count
    }

    /// Items omitted from this bounded operation.
    pub const fn omitted_item_count(&self) -> usize {
        self.omitted_item_count
    }

    /// Links omitted from this bounded operation.
    pub const fn omitted_reference_link_count(&self) -> usize {
        self.omitted_reference_link_count
    }

    /// Number of reviewed source metadata rows.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// External-activity accounting.
    pub const fn external_activity(&self) -> ControlReferenceExternalActivity {
        self.external_activity
    }

    /// Explicit limits on conclusions supported by this audit.
    pub const fn claim_limits(&self) -> ControlReferenceClaimLimits {
        self.claim_limits
    }
}

/// Failure to produce a complete, bounded control-reference audit.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ControlReferenceMappingError {
    /// The assessment contains more items than the mapping bound.
    #[error("control-reference mapping item limit exceeded")]
    TooManyItems,
    /// Two assessment items have the same stable fingerprint.
    #[error("duplicate assessment-item fingerprint")]
    DuplicateItemFingerprint,
    /// The mapped-item relationship bound was exceeded.
    #[error("control-reference mapping relationship limit exceeded")]
    TooManyRelationships,
    /// One item maps to too many control references.
    #[error("per-item control-reference limit exceeded")]
    TooManyReferencesPerItem,
    /// The aggregate control-reference link bound was exceeded.
    #[error("control-reference mapping link limit exceeded")]
    TooManyReferenceLinks,
    /// A mapping rule produced the same control-reference link twice.
    #[error("duplicate control-reference link")]
    DuplicateControlReference,
    /// A mapping counter overflowed.
    #[error("control-reference mapping count overflow")]
    CountOverflow,
}

#[derive(Clone, Copy)]
struct MappingItemView<'a> {
    fingerprint: &'a str,
    capability_id: &'a str,
    cwe: Option<&'a str>,
    basis: ControlReferenceItemBasisClass,
}

impl<'a> From<&'a AssessmentItem> for MappingItemView<'a> {
    fn from(item: &'a AssessmentItem) -> Self {
        Self {
            fingerprint: item.fingerprint(),
            capability_id: item.capability_id(),
            cwe: item.cwe(),
            basis: ControlReferenceItemBasisClass::from_basis(item.basis()),
        }
    }
}

#[derive(Clone, Copy)]
struct MappingRule {
    capability_id: &'static str,
    cwe: Option<&'static str>,
    basis: ControlReferenceItemBasisClass,
    rule_id: &'static str,
    source_id: &'static str,
    framework_id: &'static str,
    control_reference: &'static str,
    control_title: Option<&'static str>,
    mapping_basis: ControlReferenceMappingBasis,
    applicability: ControlReferenceApplicability,
    applicability_condition: &'static str,
    assurance: ControlReferenceMappingAssurance,
    original_mapping_rationale: &'static str,
}

const RULES: [MappingRule; 24] = [
    MappingRule {
        capability_id: "web.review.sql.structural-differential@1",
        cwe: Some("CWE-89"),
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.sql-cwe-89-to-owasp-a05-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A05,
        control_title: Some("Injection"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityCweAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact bounded SQL structural differential with CWE-89 metadata.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact differential is relevant to review of injection-resistant query construction; it does not establish database access or exploitation.",
    },
    MappingRule {
        capability_id: "web.review.xss.structural-boundary@1",
        cwe: Some("CWE-79"),
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.xss-cwe-79-to-owasp-a05-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A05,
        control_title: Some("Injection"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityCweAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact non-executing XSS structural differential with CWE-79 metadata.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact parser-visible differential is relevant to injection review; script execution and exploitability remain untested.",
    },
    MappingRule {
        capability_id: "web.review.ssti.structural-evaluation@1",
        cwe: Some("CWE-1336"),
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.ssti-cwe-1336-to-owasp-a05-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A05,
        control_title: Some("Injection"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityCweAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact arithmetic template differential with CWE-1336 metadata.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact template-expression differential is relevant to injection review; engine identity, code execution, and impact remain untested.",
    },
    MappingRule {
        capability_id: "web.review.cors.credentialed-external-origin@1",
        cwe: Some("CWE-942"),
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.cors-cwe-942-to-owasp-a01-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A01,
        control_title: Some("Broken Access Control"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityCweAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact credentialed external-origin differential with CWE-942 metadata.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact cross-origin policy differential is relevant to access-control review; browser exploitability and data access remain untested.",
    },
    MappingRule {
        capability_id: "web.review.redirect.candidate-specific-external@1",
        cwe: Some("CWE-601"),
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.redirect-cwe-601-to-owasp-a01-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A01,
        control_title: Some("Broken Access Control"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityCweAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact candidate-specific external redirect differential with CWE-601 metadata.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact redirect differential is relevant to destination-control review; no redirect was followed and no downstream impact was tested.",
    },
    MappingRule {
        capability_id: "authorization.resource-cross-principal-equivalence@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.authorization-cross-principal-to-owasp-a01-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A01,
        control_title: Some("Broken Access Control"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact operator-policy-bound cross-principal equivalence differential and carries no CWE claim.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact cross-principal differential is relevant to access-control review; operator expectations and resource equivalence do not alone establish unauthorized access.",
    },
    MappingRule {
        capability_id: "ssrf.oast-repeated-outbound-interaction@1",
        cwe: Some("CWE-918"),
        basis: ControlReferenceItemBasisClass::Differential,
        rule_id: "termivar.mapping.ssrf-cwe-918-to-owasp-a01-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A01,
        control_title: Some("Broken Access Control"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityCweAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact repeated OAST interaction differential with CWE-918 metadata.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "OWASP Top 10:2025 places SSRF within A01; the mapped interaction remains review-level and does not establish exploitability or business impact.",
    },
    MappingRule {
        capability_id: "web.passive.hsts.missing@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.hsts-missing-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response HSTS-missing observation on an eligible HTTPS response.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact missing-header observation is relevant to transport-policy configuration review; it is not an organization-wide control assessment.",
    },
    MappingRule {
        capability_id: "web.passive.hsts.max-age-zero@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.hsts-max-age-zero-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response zero-max-age HSTS observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact zero-retention observation is relevant to transport-policy configuration review; intended deployment policy remains operator context.",
    },
    MappingRule {
        capability_id: "web.passive.hsts.nonconformant@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.hsts-nonconformant-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response nonconformant HSTS observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact malformed-policy observation is relevant to transport-policy configuration review; it does not establish broader configuration compliance.",
    },
    MappingRule {
        capability_id: "web.passive.csp.missing@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.csp-missing-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response CSP-missing observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact missing-policy observation is relevant to browser content-policy configuration review; it is not proof of executable injection or a control assessment.",
    },
    MappingRule {
        capability_id: "web.passive.csp.nonconformant@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.csp-nonconformant-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response nonconformant CSP observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact malformed-policy observation is relevant to browser content-policy configuration review; effective browser behavior and wider control coverage remain untested.",
    },
    MappingRule {
        capability_id: "web.passive.csp.unsafe-inline-declared@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.csp-unsafe-inline-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response CSP unsafe-inline declaration observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact directive observation is relevant to browser content-policy configuration review; it does not establish an injection path or script execution.",
    },
    MappingRule {
        capability_id: "web.passive.csp.unsafe-eval-declared@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.csp-unsafe-eval-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response CSP unsafe-eval declaration observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact directive observation is relevant to browser content-policy configuration review; it does not establish attacker-controlled evaluation or impact.",
    },
    MappingRule {
        capability_id: "web.passive.x-content-type-options.missing@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.x-content-type-options-missing-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response X-Content-Type-Options-missing observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact missing-header observation is relevant to response content-type configuration review; browser exploitation and organizational control coverage remain untested.",
    },
    MappingRule {
        capability_id: "web.passive.x-content-type-options.not-nosniff@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.x-content-type-options-not-nosniff-to-owasp-a02-2025@1",
        source_id: OWASP_SOURCE_ID,
        framework_id: "owasp-top-10",
        control_reference: OWASP_A02,
        control_title: Some("Security Misconfiguration"),
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ConditionalTechnicalContext,
        applicability_condition: "The mapped item is the exact complete-response X-Content-Type-Options not-nosniff observation.",
        assurance: ControlReferenceMappingAssurance::ReviewedPrimarySourceIdentifier,
        original_mapping_rationale: "The exact header-value observation is relevant to response content-type configuration review; browser exploitation and wider compliance remain untested.",
    },
    MappingRule {
        capability_id: "exposure.response-private-key-material@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.private-key-exposure-to-kvkk-article-12@1",
        source_id: KVKK_LAW_SOURCE_ID,
        framework_id: "kvkk-law-6698",
        control_reference: KVKK_ARTICLE_12,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted response observation may be relevant only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "Returned private-key-like material can be relevant technical security context, but ownership, validity, personal-data scope, and legal applicability were not established.",
    },
    MappingRule {
        capability_id: "exposure.response-aws-access-key-pair@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.aws-key-pair-exposure-to-kvkk-article-12@1",
        source_id: KVKK_LAW_SOURCE_ID,
        framework_id: "kvkk-law-6698",
        control_reference: KVKK_ARTICLE_12,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted paired-credential observation may be relevant only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "Returned paired credential material can be relevant technical security context, but validity, permissions, ownership, personal-data scope, and legal applicability were not established.",
    },
    MappingRule {
        capability_id: "exposure.response-stripe-live-secret@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.stripe-live-secret-exposure-to-kvkk-article-12@1",
        source_id: KVKK_LAW_SOURCE_ID,
        framework_id: "kvkk-law-6698",
        control_reference: KVKK_ARTICLE_12,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted provider-secret observation may be relevant only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "Returned live-secret-like material can be relevant technical security context, but validity, permissions, ownership, personal-data scope, and legal applicability were not established.",
    },
    MappingRule {
        capability_id: "exposure.response-bearer-authorization@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.bearer-authorization-exposure-to-kvkk-article-12@1",
        source_id: KVKK_LAW_SOURCE_ID,
        framework_id: "kvkk-law-6698",
        control_reference: KVKK_ARTICLE_12,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted bearer-material observation may be relevant only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "Returned bearer-material-like content can be relevant technical security context, but validity, permissions, ownership, personal-data scope, and legal applicability were not established.",
    },
    MappingRule {
        capability_id: "exposure.response-private-key-material@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.private-key-exposure-to-kvkk-guide-72-2025@1",
        source_id: KVKK_GUIDE_SOURCE_ID,
        framework_id: "kvkk-personal-data-security-guide",
        control_reference: KVKK_GUIDE_72,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted response observation is relevant technical context only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "The official KVKK security guide is relevant context for safeguarding data-processing environments; this observation does not establish personal-data scope, organizational control failure, or legal noncompliance.",
    },
    MappingRule {
        capability_id: "exposure.response-aws-access-key-pair@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.aws-key-pair-exposure-to-kvkk-guide-72-2025@1",
        source_id: KVKK_GUIDE_SOURCE_ID,
        framework_id: "kvkk-personal-data-security-guide",
        control_reference: KVKK_GUIDE_72,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted paired-credential observation is relevant technical context only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "The official KVKK security guide is relevant context for safeguarding data-processing environments; this paired-credential observation does not establish validity, personal-data scope, organizational control failure, or legal noncompliance.",
    },
    MappingRule {
        capability_id: "exposure.response-stripe-live-secret@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.stripe-live-secret-exposure-to-kvkk-guide-72-2025@1",
        source_id: KVKK_GUIDE_SOURCE_ID,
        framework_id: "kvkk-personal-data-security-guide",
        control_reference: KVKK_GUIDE_72,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted provider-secret observation is relevant technical context only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "The official KVKK security guide is relevant context for safeguarding data-processing environments; this provider-secret observation does not establish validity, personal-data scope, organizational control failure, or legal noncompliance.",
    },
    MappingRule {
        capability_id: "exposure.response-bearer-authorization@1",
        cwe: None,
        basis: ControlReferenceItemBasisClass::Observation,
        rule_id: "termivar.mapping.bearer-authorization-exposure-to-kvkk-guide-72-2025@1",
        source_id: KVKK_GUIDE_SOURCE_ID,
        framework_id: "kvkk-personal-data-security-guide",
        control_reference: KVKK_GUIDE_72,
        control_title: None,
        mapping_basis: ControlReferenceMappingBasis::ExactCapabilityAndAssessmentBasis,
        applicability: ControlReferenceApplicability::ApplicabilityUnestablished,
        applicability_condition: "The exact redacted bearer-material observation is relevant technical context only if applicable personal-data processing and organizational scope are independently established.",
        assurance: ControlReferenceMappingAssurance::RelevantTechnicalContext,
        original_mapping_rationale: "The official KVKK security guide is relevant context for safeguarding data-processing environments; this bearer-material observation does not establish validity, personal-data scope, organizational control failure, or legal noncompliance.",
    },
];

/// Maps composed assessment items through the closed, reviewed reference catalogue.
///
/// The operation is pure and transport-free. It neither mutates assessment items
/// nor changes their disposition, severity, evidence, or claim authority.
pub fn map_control_references(
    items: &[AssessmentItem],
) -> Result<ControlReferenceMappingAudit, ControlReferenceMappingError> {
    let views = items.iter().map(MappingItemView::from).collect::<Vec<_>>();
    map_item_views(&views)
}

fn map_item_views(
    items: &[MappingItemView<'_>],
) -> Result<ControlReferenceMappingAudit, ControlReferenceMappingError> {
    if items.len() > MAX_CONTROL_REFERENCE_MAPPING_ITEMS {
        return Err(ControlReferenceMappingError::TooManyItems);
    }

    let mut fingerprints = BTreeSet::new();
    for item in items {
        if !fingerprints.insert(item.fingerprint) {
            return Err(ControlReferenceMappingError::DuplicateItemFingerprint);
        }
    }

    let mut relationships = Vec::new();
    let mut reference_link_count = 0_usize;
    for item in items {
        let mut references = RULES
            .iter()
            .filter(|rule| {
                rule.capability_id == item.capability_id
                    && rule.cwe == item.cwe
                    && rule.basis == item.basis
            })
            .map(rule_to_link)
            .collect::<Vec<_>>();
        if references.is_empty() {
            continue;
        }
        references.sort_by(|left, right| {
            left.rule_id
                .cmp(right.rule_id)
                .then(left.source_id.cmp(right.source_id))
                .then(left.control_reference.cmp(right.control_reference))
        });
        validate_reference_links(&references)?;
        reference_link_count = reference_link_count
            .checked_add(references.len())
            .ok_or(ControlReferenceMappingError::CountOverflow)?;
        if reference_link_count > MAX_CONTROL_REFERENCE_MAPPING_LINKS {
            return Err(ControlReferenceMappingError::TooManyReferenceLinks);
        }
        relationships.push(ControlReferenceRelationship {
            item_fingerprint: item.fingerprint.to_owned(),
            capability_id: item.capability_id.to_owned(),
            cwe: item.cwe.map(str::to_owned),
            item_basis: item.basis,
            references,
        });
        if relationships.len() > MAX_CONTROL_REFERENCE_MAPPING_RELATIONSHIPS {
            return Err(ControlReferenceMappingError::TooManyRelationships);
        }
    }
    relationships.sort_by(|left, right| {
        left.item_fingerprint
            .cmp(&right.item_fingerprint)
            .then(left.capability_id.cmp(&right.capability_id))
    });

    let mapped_item_count = relationships.len();
    let unmapped_item_count = items
        .len()
        .checked_sub(mapped_item_count)
        .ok_or(ControlReferenceMappingError::CountOverflow)?;

    Ok(ControlReferenceMappingAudit {
        selected: true,
        sources: REVIEWED_SOURCES.to_vec(),
        relationships,
        considered_item_count: items.len(),
        mapped_item_count,
        unmapped_item_count,
        reference_link_count,
        omitted_item_count: 0,
        omitted_reference_link_count: 0,
        external_activity: ControlReferenceExternalActivity {
            target_request_count: 0,
            provider_request_count: 0,
            source_retrieval: ControlReferenceSourceRetrievalState::NotPerformed,
        },
        claim_limits: ControlReferenceClaimLimits {
            control_assessment: ControlAssessmentState::NotPerformed,
            compliance: ControlReferenceClaimState::NotEstablished,
            certification: ControlReferenceClaimState::NotEstablished,
            legal_conclusion: ControlReferenceClaimState::NotEstablished,
            source_authentication: ControlReferenceClaimState::NotEstablished,
        },
    })
}

fn rule_to_link(rule: &MappingRule) -> ControlReferenceLink {
    ControlReferenceLink {
        rule_id: rule.rule_id,
        source_id: rule.source_id,
        framework_id: rule.framework_id,
        control_reference: rule.control_reference,
        control_title: rule.control_title,
        mapping_basis: rule.mapping_basis,
        applicability: rule.applicability,
        applicability_condition: rule.applicability_condition,
        assurance: rule.assurance,
        original_mapping_rationale: rule.original_mapping_rationale,
    }
}

fn validate_reference_links(
    references: &[ControlReferenceLink],
) -> Result<(), ControlReferenceMappingError> {
    if references.len() > MAX_CONTROL_REFERENCE_LINKS_PER_ITEM {
        return Err(ControlReferenceMappingError::TooManyReferencesPerItem);
    }
    let mut identities = BTreeSet::new();
    for reference in references {
        if !identities.insert((
            reference.rule_id,
            reference.source_id,
            reference.control_reference,
        )) {
            return Err(ControlReferenceMappingError::DuplicateControlReference);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(
        fingerprint: &'a str,
        capability_id: &'a str,
        cwe: Option<&'a str>,
        basis: ControlReferenceItemBasisClass,
    ) -> MappingItemView<'a> {
        MappingItemView {
            fingerprint,
            capability_id,
            cwe,
            basis,
        }
    }

    fn positive_views() -> Vec<MappingItemView<'static>> {
        vec![
            view(
                "fp-03",
                "web.review.ssti.structural-evaluation@1",
                Some("CWE-1336"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-01",
                "web.review.sql.structural-differential@1",
                Some("CWE-89"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-02",
                "web.review.xss.structural-boundary@1",
                Some("CWE-79"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-04",
                "web.review.cors.credentialed-external-origin@1",
                Some("CWE-942"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-05",
                "web.review.redirect.candidate-specific-external@1",
                Some("CWE-601"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-06",
                "authorization.resource-cross-principal-equivalence@1",
                None,
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-07",
                "ssrf.oast-repeated-outbound-interaction@1",
                Some("CWE-918"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "fp-08",
                "web.passive.hsts.missing@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-09",
                "web.passive.hsts.max-age-zero@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-10",
                "web.passive.hsts.nonconformant@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-11",
                "exposure.response-private-key-material@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-12",
                "exposure.response-aws-access-key-pair@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-13",
                "exposure.response-stripe-live-secret@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-14",
                "exposure.response-bearer-authorization@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-15",
                "web.passive.csp.missing@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-16",
                "web.passive.csp.nonconformant@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-17",
                "web.passive.csp.unsafe-inline-declared@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-18",
                "web.passive.csp.unsafe-eval-declared@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-19",
                "web.passive.x-content-type-options.missing@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "fp-20",
                "web.passive.x-content-type-options.not-nosniff@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
        ]
    }

    #[test]
    fn exact_positive_matrix_maps_to_literal_independent_references() {
        let audit = map_item_views(&positive_views()).unwrap();
        let actual = audit
            .relationships()
            .iter()
            .map(|relationship| {
                let reference = &relationship.references()[0];
                (
                    relationship.item_fingerprint(),
                    relationship.capability_id(),
                    relationship.cwe(),
                    relationship.item_basis().as_str(),
                    reference.source_id(),
                    reference.control_reference(),
                    reference.control_title(),
                )
            })
            .collect::<Vec<_>>();
        let expected = vec![
            (
                "fp-01",
                "web.review.sql.structural-differential@1",
                Some("CWE-89"),
                "differential",
                OWASP_SOURCE_ID,
                "A05:2025",
                Some("Injection"),
            ),
            (
                "fp-02",
                "web.review.xss.structural-boundary@1",
                Some("CWE-79"),
                "differential",
                OWASP_SOURCE_ID,
                "A05:2025",
                Some("Injection"),
            ),
            (
                "fp-03",
                "web.review.ssti.structural-evaluation@1",
                Some("CWE-1336"),
                "differential",
                OWASP_SOURCE_ID,
                "A05:2025",
                Some("Injection"),
            ),
            (
                "fp-04",
                "web.review.cors.credentialed-external-origin@1",
                Some("CWE-942"),
                "differential",
                OWASP_SOURCE_ID,
                "A01:2025",
                Some("Broken Access Control"),
            ),
            (
                "fp-05",
                "web.review.redirect.candidate-specific-external@1",
                Some("CWE-601"),
                "differential",
                OWASP_SOURCE_ID,
                "A01:2025",
                Some("Broken Access Control"),
            ),
            (
                "fp-06",
                "authorization.resource-cross-principal-equivalence@1",
                None,
                "differential",
                OWASP_SOURCE_ID,
                "A01:2025",
                Some("Broken Access Control"),
            ),
            (
                "fp-07",
                "ssrf.oast-repeated-outbound-interaction@1",
                Some("CWE-918"),
                "differential",
                OWASP_SOURCE_ID,
                "A01:2025",
                Some("Broken Access Control"),
            ),
            (
                "fp-08",
                "web.passive.hsts.missing@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-09",
                "web.passive.hsts.max-age-zero@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-10",
                "web.passive.hsts.nonconformant@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-11",
                "exposure.response-private-key-material@1",
                None,
                "observation",
                KVKK_LAW_SOURCE_ID,
                "6698/Madde-12",
                None,
            ),
            (
                "fp-12",
                "exposure.response-aws-access-key-pair@1",
                None,
                "observation",
                KVKK_LAW_SOURCE_ID,
                "6698/Madde-12",
                None,
            ),
            (
                "fp-13",
                "exposure.response-stripe-live-secret@1",
                None,
                "observation",
                KVKK_LAW_SOURCE_ID,
                "6698/Madde-12",
                None,
            ),
            (
                "fp-14",
                "exposure.response-bearer-authorization@1",
                None,
                "observation",
                KVKK_LAW_SOURCE_ID,
                "6698/Madde-12",
                None,
            ),
            (
                "fp-15",
                "web.passive.csp.missing@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-16",
                "web.passive.csp.nonconformant@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-17",
                "web.passive.csp.unsafe-inline-declared@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-18",
                "web.passive.csp.unsafe-eval-declared@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-19",
                "web.passive.x-content-type-options.missing@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
            (
                "fp-20",
                "web.passive.x-content-type-options.not-nosniff@1",
                None,
                "observation",
                OWASP_SOURCE_ID,
                "A02:2025",
                Some("Security Misconfiguration"),
            ),
        ];
        assert_eq!(actual, expected);
        assert_eq!(audit.considered_item_count(), 20);
        assert_eq!(audit.mapped_item_count(), 20);
        assert_eq!(audit.unmapped_item_count(), 0);
        assert_eq!(audit.relationship_count(), 20);
        assert_eq!(audit.reference_link_count(), 24);
        assert_eq!(audit.omitted_item_count(), 0);
        assert_eq!(audit.omitted_reference_link_count(), 0);
    }

    #[test]
    fn capability_cwe_and_basis_near_misses_do_not_map() {
        let near_misses = vec![
            view(
                "wrong-capability",
                "web.review.sql.structural-differential@2",
                Some("CWE-89"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "wrong-cwe",
                "web.review.sql.structural-differential@1",
                Some("CWE-79"),
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "missing-cwe",
                "web.review.sql.structural-differential@1",
                None,
                ControlReferenceItemBasisClass::Differential,
            ),
            view(
                "wrong-basis",
                "web.review.sql.structural-differential@1",
                Some("CWE-89"),
                ControlReferenceItemBasisClass::Verifier,
            ),
            view(
                "extra-cwe",
                "web.passive.hsts.missing@1",
                Some("CWE-319"),
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "secret-differential",
                "exposure.response-private-key-material@1",
                None,
                ControlReferenceItemBasisClass::Differential,
            ),
        ];
        let audit = map_item_views(&near_misses).unwrap();
        assert!(audit.relationships().is_empty());
        assert_eq!(audit.considered_item_count(), 6);
        assert_eq!(audit.mapped_item_count(), 0);
        assert_eq!(audit.unmapped_item_count(), 6);
    }

    #[test]
    fn source_metadata_preserves_editions_rights_and_mapping_separation() {
        let audit = map_item_views(&[]).unwrap();
        let actual = audit
            .sources()
            .iter()
            .map(|source| {
                (
                    source.source_id(),
                    source.framework_id(),
                    source.edition(),
                    source.revision_or_amendment(),
                    source.mapping_availability().as_str(),
                    source.rights_basis().as_str(),
                    source.source_verified_at(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                (
                    OWASP_SOURCE_ID,
                    "owasp-top-10",
                    "2025",
                    None,
                    "reviewed_identifiers_and_titles",
                    "identifiers_and_titles_with_attribution",
                    "2026-09-20"
                ),
                (
                    PCI_SOURCE_ID,
                    "pci-dss",
                    "4.0.1",
                    Some("published-2024-06-11"),
                    "bibliographic_only_rights_deferred",
                    "bibliographic_metadata_only",
                    "2026-09-20"
                ),
                (
                    ISO_SOURCE_ID,
                    "iso-iec-27001",
                    "2022",
                    Some("Amd-1:2024"),
                    "bibliographic_only_rights_deferred",
                    "bibliographic_metadata_only",
                    "2026-09-20"
                ),
                (
                    KVKK_LAW_SOURCE_ID,
                    "kvkk-law-6698",
                    "6698",
                    Some("Madde-12"),
                    "relevant_technical_context_only",
                    "official_reference_only",
                    "2026-09-20"
                ),
                (
                    KVKK_GUIDE_SOURCE_ID,
                    "kvkk-personal-data-security-guide",
                    "2025-04",
                    Some("KVKK-Yayinlari-No-72"),
                    "relevant_technical_context_only",
                    "official_reference_only",
                    "2026-09-20"
                ),
            ]
        );
        assert_eq!(audit.source_count(), 5);
        assert!(audit
            .sources()
            .iter()
            .all(|source| source.source_url().starts_with("https://")));
        assert!(audit
            .sources()
            .iter()
            .filter(|source| matches!(source.source_id(), PCI_SOURCE_ID | ISO_SOURCE_ID))
            .all(|source| source.mapping_availability()
                == ControlReferenceMappingAvailability::BibliographicOnlyRightsDeferred));
        assert!(audit.relationships().is_empty());
    }

    #[test]
    fn selected_empty_is_complete_transport_free_and_claim_limited() {
        let audit = map_item_views(&[]).unwrap();
        assert_eq!(
            audit.schema(),
            "security.control-reference-mapping-audit/v1"
        );
        assert_eq!(audit.policy_id(), "termivar.control-reference-mapping/v1");
        assert_eq!(audit.catalogue_id(), "termivar.reviewed-control-references");
        assert_eq!(audit.catalogue_revision(), "2026-09-20.1");
        assert!(audit.selected());
        assert_eq!(audit.considered_item_count(), 0);
        assert_eq!(audit.mapped_item_count(), 0);
        assert_eq!(audit.unmapped_item_count(), 0);
        assert_eq!(audit.relationship_count(), 0);
        assert_eq!(audit.reference_link_count(), 0);
        assert_eq!(audit.external_activity().target_request_count(), 0);
        assert_eq!(audit.external_activity().provider_request_count(), 0);
        assert_eq!(
            audit.external_activity().source_retrieval(),
            ControlReferenceSourceRetrievalState::NotPerformed
        );
        assert_eq!(
            audit.claim_limits().control_assessment(),
            ControlAssessmentState::NotPerformed
        );
        assert_eq!(
            audit.claim_limits().compliance(),
            ControlReferenceClaimState::NotEstablished
        );
        assert_eq!(
            audit.claim_limits().certification(),
            ControlReferenceClaimState::NotEstablished
        );
        assert_eq!(
            audit.claim_limits().legal_conclusion(),
            ControlReferenceClaimState::NotEstablished
        );
        assert_eq!(
            audit.claim_limits().source_authentication(),
            ControlReferenceClaimState::NotEstablished
        );
    }

    #[test]
    fn order_is_independent_and_relationships_are_fingerprint_sorted() {
        let forward = positive_views();
        let mut reverse = forward.clone();
        reverse.reverse();
        let left = map_item_views(&forward).unwrap();
        let right = map_item_views(&reverse).unwrap();
        assert_eq!(left, right);
        let fingerprints = left
            .relationships()
            .iter()
            .map(ControlReferenceRelationship::item_fingerprint)
            .collect::<Vec<_>>();
        assert!(fingerprints.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn duplicate_input_fingerprints_are_rejected_before_mapping() {
        let items = vec![
            view(
                "duplicate",
                "web.passive.hsts.missing@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
            view(
                "duplicate",
                "unmapped.capability@1",
                None,
                ControlReferenceItemBasisClass::Observation,
            ),
        ];
        assert_eq!(
            map_item_views(&items),
            Err(ControlReferenceMappingError::DuplicateItemFingerprint)
        );
    }

    #[test]
    fn item_limit_is_rejected_instead_of_truncating() {
        let fingerprints = (0..=MAX_CONTROL_REFERENCE_MAPPING_ITEMS)
            .map(|index| format!("fp-{index:04}"))
            .collect::<Vec<_>>();
        let items = fingerprints
            .iter()
            .map(|fingerprint| {
                view(
                    fingerprint,
                    "unmapped.capability@1",
                    None,
                    ControlReferenceItemBasisClass::Observation,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            map_item_views(&items),
            Err(ControlReferenceMappingError::TooManyItems)
        );
    }

    #[test]
    fn duplicate_reference_links_and_per_item_limit_are_rejected() {
        let link = rule_to_link(&RULES[0]);
        assert_eq!(
            validate_reference_links(&[link.clone(), link]),
            Err(ControlReferenceMappingError::DuplicateControlReference)
        );
        let too_many = (0..=MAX_CONTROL_REFERENCE_LINKS_PER_ITEM)
            .map(|_| rule_to_link(&RULES[0]))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_reference_links(&too_many),
            Err(ControlReferenceMappingError::TooManyReferencesPerItem)
        );
    }

    #[test]
    fn kvkk_links_are_context_only_and_owasp_links_retain_exact_edition() {
        let audit = map_item_views(&positive_views()).unwrap();
        let secret = audit
            .relationships()
            .iter()
            .find(|row| row.item_fingerprint() == "fp-11")
            .unwrap();
        assert_eq!(secret.references().len(), 2);
        let link = &secret.references()[0];
        assert_eq!(
            link.applicability(),
            ControlReferenceApplicability::ApplicabilityUnestablished
        );
        assert_eq!(
            link.assurance(),
            ControlReferenceMappingAssurance::RelevantTechnicalContext
        );
        assert_eq!(link.control_title(), None);
        assert!(link
            .original_mapping_rationale()
            .contains("legal applicability were not established"));
        let guide = &secret.references()[1];
        assert_eq!(guide.source_id(), KVKK_GUIDE_SOURCE_ID);
        assert_eq!(guide.framework_id(), "kvkk-personal-data-security-guide");
        assert_eq!(guide.control_reference(), "KVKK-Rehber-72/2025-04");
        assert_eq!(guide.control_title(), None);
        assert_eq!(
            guide.applicability(),
            ControlReferenceApplicability::ApplicabilityUnestablished
        );
        assert_eq!(
            guide.assurance(),
            ControlReferenceMappingAssurance::RelevantTechnicalContext
        );
        assert!(guide
            .original_mapping_rationale()
            .contains("does not establish personal-data scope"));

        let sql = audit
            .relationships()
            .iter()
            .find(|row| row.item_fingerprint() == "fp-01")
            .unwrap();
        assert_eq!(sql.references()[0].control_reference(), "A05:2025");
        assert_ne!(sql.references()[0].control_reference(), "A03:2021");
    }
}
