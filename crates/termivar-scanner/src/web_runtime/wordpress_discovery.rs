//! Bounded, explicitly selected WordPress public-metadata discovery.
//!
//! This module owns neither a client nor a budget. Runtime construction lends
//! it the assessment's exact-origin broker, accounting authority, cancellation
//! token, and absolute deadline. Retained audit values deliberately omit URLs,
//! queries, response bodies, and request headers.

use std::collections::BTreeSet;

use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId,
    EvidenceKind, EvidenceSource, EvidenceValue, KnowledgePredicate,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    http_evidence::{
        HttpRequestBrokerError, WordPressMetadataRequestDescriptor, WordPressMetadataRequestSource,
        WordPressMetadataResourceKind, WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
    },
    wordpress_review::{
        WordPressComponentIdentity, WordPressComponentKind, WordPressComponentSignal,
        WordPressDiscoveryLayout, MAX_WORDPRESS_DISCOVERY_LAYOUT_BYTES,
    },
    DecisionActionOrigin, DecisionExecutionLimits, DecisionExecutionStage, RuntimeBudgetDimension,
};

use super::SharedWebRuntimeAuthority;

/// Deployment-aware discovery policy emitted by current assessments.
pub const WORDPRESS_DISCOVERY_POLICY_ID: &str = WORDPRESS_METADATA_DISCOVERY_POLICY_ID;
/// Maximum retained root-derived candidates before per-kind selection.
pub const MAX_WORDPRESS_DISCOVERY_CANDIDATES: usize = 32;
/// Maximum broker-owned wire attempts, including failed attempts.
pub const MAX_WORDPRESS_DISCOVERY_REQUESTS: u8 = 12;
/// Maximum advertised REST-index GETs.
pub const MAX_WORDPRESS_DISCOVERY_REST_REQUESTS: u8 = 1;
/// Maximum theme stylesheet GETs, including one-level parents.
pub const MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS: u8 = 3;
/// Maximum plugin readme GETs.
pub const MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS: u8 = 8;
/// Maximum distinct root and one-level parent identities considered together.
pub(super) const MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES: usize = 4_096;
pub(super) const MAX_WORDPRESS_DISCOVERY_OMITTED_CANDIDATES: u64 =
    (MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES - MAX_WORDPRESS_DISCOVERY_CANDIDATES) as u64;
/// Maximum retained REST response bytes before the smaller parent limit wins.
pub const MAX_WORDPRESS_DISCOVERY_REST_BYTES: usize = 512 * 1024;
/// Maximum retained bytes for one stylesheet or readme response.
pub const MAX_WORDPRESS_DISCOVERY_STATIC_BYTES: usize = 128 * 1024;
/// Maximum response bytes charged to discovery, subject to chunk overrun.
pub const MAX_WORDPRESS_DISCOVERY_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const WORDPRESS_DISCOVERY_ACTION_ID: &str = "web.review.wordpress.metadata-discovery@1";
const WORDPRESS_DISCOVERY_EVIDENCE_COMPONENT: &str = "wordpress.metadata-discovery";
const WORDPRESS_DISCOVERY_EVIDENCE_NAMESPACE: &str = "web.wordpress-discovery";
const MAX_METADATA_HEADER_BYTES: usize = 8 * 1024;
const MAX_METADATA_VALUE_BYTES: usize = 256;
const MAX_DISCOVERED_VERSION_BYTES: usize = 64;
const MAX_REST_NAMESPACES: usize = 64;
const MAX_REST_NAMESPACE_BYTES: usize = 128;
const MAX_REST_JSON_DEPTH: usize = 32;
const MAX_REST_JSON_NODES: usize = 32_768;
const MAX_REST_JSON_COLLECTION_LENGTH: usize = 4_096;
const MAX_REST_JSON_KEY_BYTES: usize = 256;
const MAX_REST_JSON_STRING_BYTES: usize = MAX_METADATA_VALUE_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::web_runtime) struct WordPressDiscoverySeed {
    url: Url,
    application_url: Url,
    role_base_url: Url,
    association: WordPressDiscoveryAssociation,
    kind: WordPressDiscoverySourceKind,
    component: Option<WordPressComponentIdentity>,
    parent_depth: u8,
    preflight_outcome: Option<WordPressDiscoverySourceOutcome>,
    source_evidence_ids: Vec<EvidenceId>,
}

impl WordPressDiscoverySeed {
    #[cfg(test)]
    pub(super) fn rest_index(url: Url) -> Self {
        let application_url = origin_directory(&url);
        Self {
            role_base_url: application_url.clone(),
            application_url,
            url,
            association: WordPressDiscoveryAssociation::StructuredAdvertisement,
            kind: WordPressDiscoverySourceKind::RestIndex,
            component: None,
            parent_depth: 0,
            preflight_outcome: None,
            source_evidence_ids: Vec::new(),
        }
    }

    pub(super) fn invalid_rest_index(document_url: Url) -> Self {
        Self {
            role_base_url: document_url.clone(),
            application_url: document_url.clone(),
            url: document_url,
            association: WordPressDiscoveryAssociation::InvalidAdvertisement,
            kind: WordPressDiscoverySourceKind::RestIndex,
            component: None,
            parent_depth: 0,
            preflight_outcome: Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement),
            source_evidence_ids: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn component(
        url: Url,
        component: WordPressComponentIdentity,
        parent_depth: u8,
    ) -> Self {
        let kind = match component.kind() {
            WordPressComponentKind::Theme => WordPressDiscoverySourceKind::ThemeStylesheet,
            WordPressComponentKind::Plugin => WordPressDiscoverySourceKind::PluginReadme,
            WordPressComponentKind::Core => WordPressDiscoverySourceKind::RestIndex,
        };
        let role_base_url =
            inferred_component_role_base(&url).unwrap_or_else(|| origin_directory(&url));
        Self {
            application_url: origin_directory(&url),
            role_base_url,
            url,
            association: WordPressDiscoveryAssociation::ObservedConventional,
            kind,
            component: Some(component),
            parent_depth,
            preflight_outcome: None,
            source_evidence_ids: Vec::new(),
        }
    }

    pub(super) fn admitted_rest_index(
        url: Url,
        application_url: Url,
        role_base_url: Url,
        association: WordPressDiscoveryAssociation,
    ) -> Self {
        Self {
            url,
            application_url,
            role_base_url,
            association,
            kind: WordPressDiscoverySourceKind::RestIndex,
            component: None,
            parent_depth: 0,
            preflight_outcome: None,
            source_evidence_ids: Vec::new(),
        }
    }

    pub(super) fn admitted_component(
        url: Url,
        application_url: Url,
        role_base_url: Url,
        association: WordPressDiscoveryAssociation,
        component: WordPressComponentIdentity,
        parent_depth: u8,
    ) -> Self {
        let kind = match component.kind() {
            WordPressComponentKind::Theme => WordPressDiscoverySourceKind::ThemeStylesheet,
            WordPressComponentKind::Plugin => WordPressDiscoverySourceKind::PluginReadme,
            WordPressComponentKind::Core => WordPressDiscoverySourceKind::RestIndex,
        };
        Self {
            url,
            application_url,
            role_base_url,
            association,
            kind,
            component: Some(component),
            parent_depth,
            preflight_outcome: None,
            source_evidence_ids: Vec::new(),
        }
    }

    pub(super) const fn kind(&self) -> WordPressDiscoverySourceKind {
        self.kind
    }

    pub(super) const fn url(&self) -> &Url {
        &self.url
    }

    pub(super) const fn component_identity(&self) -> Option<&WordPressComponentIdentity> {
        self.component.as_ref()
    }

    pub(super) const fn parent_depth(&self) -> u8 {
        self.parent_depth
    }

    pub(super) const fn preflight_outcome(&self) -> Option<WordPressDiscoverySourceOutcome> {
        self.preflight_outcome
    }

    pub(super) const fn association(&self) -> WordPressDiscoveryAssociation {
        self.association
    }

    pub(super) const fn role_base_url(&self) -> &Url {
        &self.role_base_url
    }

    pub(super) const fn application_url(&self) -> &Url {
        &self.application_url
    }

    pub(super) fn resource_reference(&self) -> String {
        opaque_url_reference("wordpress-discovery-resource", &self.url)
    }

    pub(super) fn role_reference(&self) -> Option<String> {
        self.preflight_outcome
            .is_none()
            .then(|| opaque_url_reference("wordpress-discovery-role", &self.role_base_url))
    }

    fn dispatch_contract_is_valid(&self) -> bool {
        if self.url.origin() != self.application_url.origin()
            || self.role_base_url.origin() != self.application_url.origin()
            || !safe_directory_url(&self.application_url)
            || !safe_directory_url(&self.role_base_url)
            || !safe_resource_url(&self.url)
        {
            return false;
        }
        if self.preflight_outcome.is_some() {
            return self.kind == WordPressDiscoverySourceKind::RestIndex
                && self.component.is_none()
                && self.parent_depth == 0
                && self.url == self.application_url
                && self.role_base_url == self.application_url
                && self.preflight_outcome
                    == Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement);
        }
        match self.kind {
            WordPressDiscoverySourceKind::RestIndex => {
                self.component.is_none()
                    && admitted_rest_resource(&self.application_url, &self.role_base_url, &self.url)
            },
            WordPressDiscoverySourceKind::ThemeStylesheet
            | WordPressDiscoverySourceKind::PluginReadme => {
                let Some(component) = self.component.as_ref() else {
                    return false;
                };
                let expected_kind = match self.kind {
                    WordPressDiscoverySourceKind::ThemeStylesheet => WordPressComponentKind::Theme,
                    WordPressDiscoverySourceKind::PluginReadme => WordPressComponentKind::Plugin,
                    WordPressDiscoverySourceKind::RestIndex => return false,
                };
                component.kind() == expected_kind
                    && resource_is_exact_role_child(
                        &self.role_base_url,
                        component.slug(),
                        match self.kind {
                            WordPressDiscoverySourceKind::ThemeStylesheet => "style.css",
                            WordPressDiscoverySourceKind::PluginReadme => "readme.txt",
                            WordPressDiscoverySourceKind::RestIndex => return false,
                        },
                        &self.url,
                    )
            },
        }
    }

    fn request_descriptor(
        &self,
        source_evidence_count: usize,
    ) -> Result<WordPressMetadataRequestDescriptor, WordPressDiscoveryExecutionError> {
        let resource_kind = match self.kind {
            WordPressDiscoverySourceKind::RestIndex => WordPressMetadataResourceKind::RestIndex,
            WordPressDiscoverySourceKind::ThemeStylesheet => {
                let component = self
                    .component
                    .as_ref()
                    .ok_or(WordPressDiscoveryExecutionError::EvidenceModel)?;
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: component.slug().to_owned(),
                }
            },
            WordPressDiscoverySourceKind::PluginReadme => {
                let component = self
                    .component
                    .as_ref()
                    .ok_or(WordPressDiscoveryExecutionError::EvidenceModel)?;
                WordPressMetadataResourceKind::PluginReadme {
                    slug: component.slug().to_owned(),
                }
            },
        };
        let source = match self.association {
            WordPressDiscoveryAssociation::StructuredAdvertisement => {
                WordPressMetadataRequestSource::StructuredAdvertisement
            },
            WordPressDiscoveryAssociation::OperatorQualifiedAdvertisement => {
                WordPressMetadataRequestSource::OperatorQualifiedAdvertisement
            },
            WordPressDiscoveryAssociation::ObservedConventional => {
                WordPressMetadataRequestSource::ObservedConventional
            },
            WordPressDiscoveryAssociation::ExplicitOperator => {
                WordPressMetadataRequestSource::ExplicitOperator
            },
            WordPressDiscoveryAssociation::SameThemeBaseParent => {
                WordPressMetadataRequestSource::SameThemeBaseParent
            },
            WordPressDiscoveryAssociation::InvalidAdvertisement => {
                return Err(WordPressDiscoveryExecutionError::EvidenceModel);
            },
        };
        WordPressMetadataRequestDescriptor::from_source_evidence(
            WORDPRESS_DISCOVERY_POLICY_ID,
            &self.application_url,
            &self.role_base_url,
            &self.url,
            resource_kind,
            source,
            source_evidence_count,
        )
        .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)
    }

    fn with_source_evidence(mut self, evidence_id: EvidenceId) -> Self {
        if !self.source_evidence_ids.contains(&evidence_id) {
            self.source_evidence_ids.push(evidence_id);
        }
        self
    }

    fn source_evidence_ids<'a>(&'a self, root: &'a [EvidenceId]) -> &'a [EvidenceId] {
        if self.source_evidence_ids.is_empty() {
            root
        } else {
            &self.source_evidence_ids
        }
    }

    pub(super) fn sort_key(&self) -> (u8, &str, &str, &str, &str) {
        let rank = match self.kind {
            WordPressDiscoverySourceKind::RestIndex => 0,
            WordPressDiscoverySourceKind::ThemeStylesheet => 1,
            WordPressDiscoverySourceKind::PluginReadme => 2,
        };
        let slug = self
            .component
            .as_ref()
            .map_or("", WordPressComponentIdentity::slug);
        let preflight = self
            .preflight_outcome
            .map_or("", |outcome| outcome.as_str());
        (
            rank,
            slug,
            self.role_base_url.as_str(),
            self.url.as_str(),
            preflight,
        )
    }
}

pub(super) fn discovery_seed_fingerprint(seed: &WordPressDiscoverySeed) -> [u8; 32] {
    let mut digest = Sha256::new();
    let component_kind = seed
        .component_identity()
        .map_or("", |component| match component.kind() {
            WordPressComponentKind::Core => "core",
            WordPressComponentKind::Plugin => "plugin",
            WordPressComponentKind::Theme => "theme",
        });
    for value in [
        seed.sort_key().0.to_string(),
        seed.url().as_str().to_owned(),
        seed.application_url.as_str().to_owned(),
        seed.role_base_url.as_str().to_owned(),
        component_kind.to_owned(),
        seed.component_identity()
            .map_or(String::new(), |component| component.slug().to_owned()),
        seed.preflight_outcome()
            .map_or(String::new(), |outcome| outcome.as_str().to_owned()),
    ] {
        digest.update(
            u64::try_from(value.len())
                .expect("bounded candidate identity length fits u64")
                .to_be_bytes(),
        );
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressDiscoveryAssociation {
    StructuredAdvertisement,
    OperatorQualifiedAdvertisement,
    ObservedConventional,
    ExplicitOperator,
    SameThemeBaseParent,
    InvalidAdvertisement,
}

impl WordPressDiscoveryAssociation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StructuredAdvertisement => "structured_advertisement",
            Self::OperatorQualifiedAdvertisement => "operator_qualified_advertisement",
            Self::ObservedConventional => "observed_conventional",
            Self::ExplicitOperator => "explicit_operator",
            Self::SameThemeBaseParent => "same_theme_base_parent",
            Self::InvalidAdvertisement => "invalid_advertisement",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressDiscoveryLayoutRole {
    Core,
    Themes,
    Plugins,
    RestIndex,
}

impl WordPressDiscoveryLayoutRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Themes => "themes",
            Self::Plugins => "plugins",
            Self::RestIndex => "rest_index",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressDiscoveryLayoutStatus {
    Exact,
    Ambiguous,
    Unresolved,
}

impl WordPressDiscoveryLayoutStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Ambiguous => "ambiguous",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressDiscoveryLayoutBasis {
    ConventionalAsset,
    StructuredAdvertisement,
    OperatorDeclaration,
    None,
}

impl WordPressDiscoveryLayoutBasis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConventionalAsset => "conventional_asset",
            Self::StructuredAdvertisement => "structured_advertisement",
            Self::OperatorDeclaration => "operator_declaration",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressDiscoveryLayoutRoleAudit {
    pub(super) role: WordPressDiscoveryLayoutRole,
    pub(super) status: WordPressDiscoveryLayoutStatus,
    pub(super) basis: WordPressDiscoveryLayoutBasis,
    pub(super) reference: Option<String>,
    pub(super) candidate_count: u16,
}

impl WordPressDiscoveryLayoutRoleAudit {
    pub const fn role(&self) -> WordPressDiscoveryLayoutRole {
        self.role
    }
    pub const fn status(&self) -> WordPressDiscoveryLayoutStatus {
        self.status
    }
    pub const fn basis(&self) -> WordPressDiscoveryLayoutBasis {
        self.basis
    }
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }
    pub const fn candidate_count(&self) -> u16 {
        self.candidate_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressDiscoveryLayoutDeclarationAudit {
    pub(super) byte_length: u64,
    pub(super) sha256: String,
}

impl WordPressDiscoveryLayoutDeclarationAudit {
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressDiscoveryLayoutAudit {
    pub(super) application_reference: String,
    pub(super) declaration: Option<WordPressDiscoveryLayoutDeclarationAudit>,
    pub(super) roles: Vec<WordPressDiscoveryLayoutRoleAudit>,
    pub(super) skipped_foreign_origin_count: u16,
    pub(super) skipped_sibling_application_count: u16,
    pub(super) conflicting_association_count: u16,
}

impl WordPressDiscoveryLayoutAudit {
    pub fn unresolved(application_url: &Url, layout: Option<&WordPressDiscoveryLayout>) -> Self {
        let declaration = layout.map(|layout| WordPressDiscoveryLayoutDeclarationAudit {
            byte_length: u64::try_from(layout.byte_length()).unwrap_or(u64::MAX),
            sha256: lowercase_sha256(layout.sha256()),
        });
        let roles = [
            WordPressDiscoveryLayoutRole::Core,
            WordPressDiscoveryLayoutRole::Themes,
            WordPressDiscoveryLayoutRole::Plugins,
            WordPressDiscoveryLayoutRole::RestIndex,
        ]
        .into_iter()
        .map(|role| {
            let declared = layout.and_then(|layout| match role {
                WordPressDiscoveryLayoutRole::Core => layout.core_base_url(),
                WordPressDiscoveryLayoutRole::Themes => layout.themes_base_url(),
                WordPressDiscoveryLayoutRole::Plugins => layout.plugins_base_url(),
                WordPressDiscoveryLayoutRole::RestIndex => None,
            });
            WordPressDiscoveryLayoutRoleAudit {
                role,
                status: if declared.is_some() {
                    WordPressDiscoveryLayoutStatus::Exact
                } else {
                    WordPressDiscoveryLayoutStatus::Unresolved
                },
                basis: if declared.is_some() {
                    WordPressDiscoveryLayoutBasis::OperatorDeclaration
                } else {
                    WordPressDiscoveryLayoutBasis::None
                },
                reference: declared
                    .map(|base| opaque_url_reference("wordpress-discovery-role", base)),
                candidate_count: u16::from(declared.is_some()),
            }
        })
        .collect();
        Self {
            application_reference: opaque_url_reference(
                "wordpress-selected-application",
                application_url,
            ),
            declaration,
            roles,
            skipped_foreign_origin_count: 0,
            skipped_sibling_application_count: 0,
            conflicting_association_count: 0,
        }
    }

    pub fn application_reference(&self) -> &str {
        &self.application_reference
    }
    pub const fn declaration(&self) -> Option<&WordPressDiscoveryLayoutDeclarationAudit> {
        self.declaration.as_ref()
    }
    pub fn roles(&self) -> &[WordPressDiscoveryLayoutRoleAudit] {
        &self.roles
    }
    pub const fn skipped_foreign_origin_count(&self) -> u16 {
        self.skipped_foreign_origin_count
    }
    pub const fn skipped_sibling_application_count(&self) -> u16 {
        self.skipped_sibling_application_count
    }
    pub const fn conflicting_association_count(&self) -> u16 {
        self.conflicting_association_count
    }

    pub(super) fn role_mut(
        &mut self,
        role: WordPressDiscoveryLayoutRole,
    ) -> &mut WordPressDiscoveryLayoutRoleAudit {
        self.roles
            .iter_mut()
            .find(|entry| entry.role == role)
            .expect("the closed layout audit always contains every role")
    }
}

fn lowercase_sha256(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn opaque_url_reference(domain: &str, url: &Url) -> String {
    let mut digest = Sha256::new();
    for value in [domain.as_bytes(), url.as_str().as_bytes()] {
        digest.update(
            u64::try_from(value.len())
                .expect("bounded URL reference length fits u64")
                .to_be_bytes(),
        );
        digest.update(value);
    }
    format!("sha256:{}", lowercase_sha256(&digest.finalize().into()))
}

#[cfg(test)]
fn origin_directory(url: &Url) -> Url {
    let mut origin = url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

#[cfg(test)]
fn inferred_component_role_base(url: &Url) -> Option<Url> {
    let mut segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.last().is_some_and(|segment| segment.is_empty()) {
        segments.pop();
    }
    if segments.len() < 3 {
        return None;
    }
    segments.truncate(segments.len().saturating_sub(2));
    directory_with_segments(url, &segments)
}

#[cfg(test)]
fn directory_with_segments(source: &Url, segments: &[&str]) -> Option<Url> {
    let mut url = origin_directory(source);
    let path = if segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}/", segments.join("/"))
    };
    url.set_path(&path);
    safe_directory_url(&url).then_some(url)
}

fn safe_directory_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().starts_with('/')
        && url.path().ends_with('/')
        && safe_normalized_path(url.path())
}

fn safe_resource_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && safe_normalized_path(url.path())
}

fn safe_normalized_path(path: &str) -> bool {
    !path.contains('\\')
        && !path.split('/').skip(1).enumerate().any(|(index, segment)| {
            (segment.is_empty() && index + 2 < path.split('/').count())
                || matches!(segment, "." | "..")
                || ["%2e", "%2f", "%5c", "%25"]
                    .iter()
                    .any(|encoded| segment.to_ascii_lowercase().contains(encoded))
        })
}

fn resource_is_exact_role_child(base: &Url, slug: &str, filename: &str, resource: &Url) -> bool {
    if resource.query().is_some() || resource.fragment().is_some() {
        return false;
    }
    let Some(expected) = base.join(&format!("{slug}/{filename}")).ok() else {
        return false;
    };
    expected == *resource
}

fn admitted_rest_resource(application: &Url, role_base: &Url, resource: &Url) -> bool {
    if resource.origin() != application.origin() || role_base.origin() != application.origin() {
        return false;
    }
    let pretty = role_base
        .join("wp-json/")
        .ok()
        .is_some_and(|expected| expected == *resource && resource.query().is_none());
    let plain_base = resource.path() == role_base.path()
        || role_base
            .join("index.php")
            .ok()
            .is_some_and(|expected| expected.path() == resource.path());
    pretty
        || (plain_base
            && resource
                .query()
                .is_some_and(crate::http_evidence::wordpress_rest_route_query_is_admitted))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WordPressDiscoveryStop {
    Complete,
    Cancelled,
    DeadlineExceeded,
    RuntimeLimit(RuntimeBudgetDimension),
    DiscoveryResponseLimit,
}

pub(super) struct WordPressDiscoveryExecution {
    pub(super) audit: WebAssessmentWordPressDiscoveryAudit,
    pub(super) signals: Vec<WordPressComponentSignal>,
    pub(super) stop: WordPressDiscoveryStop,
}

pub(super) struct WordPressDiscoveryExecutionInput {
    candidates: Vec<WordPressDiscoverySeed>,
    omitted_candidate_count: u64,
    considered_candidate_fingerprints: BTreeSet<[u8; 32]>,
    root_evidence_ids: Vec<EvidenceId>,
    subject: EntityId,
    layout: WordPressDiscoveryLayoutAudit,
}

impl WordPressDiscoveryExecutionInput {
    pub(super) fn new(
        candidates: Vec<WordPressDiscoverySeed>,
        omitted_candidate_count: u64,
        considered_candidate_fingerprints: BTreeSet<[u8; 32]>,
        root_evidence_ids: Vec<EvidenceId>,
        subject: EntityId,
        layout: WordPressDiscoveryLayoutAudit,
    ) -> Self {
        Self {
            candidates,
            omitted_candidate_count,
            considered_candidate_fingerprints,
            root_evidence_ids,
            subject,
            layout,
        }
    }
}

#[derive(Debug)]
pub(in crate::web_runtime) enum WordPressDiscoveryExecutionError {
    CandidateIdentityLimitExceeded,
    RootEvidenceUnavailable,
    EvidenceModel,
    EvidenceCommit,
}

/// Closed public-metadata source classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressDiscoverySourceKind {
    RestIndex,
    ThemeStylesheet,
    PluginReadme,
}

impl WordPressDiscoverySourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RestIndex => "rest_index",
            Self::ThemeStylesheet => "theme_stylesheet",
            Self::PluginReadme => "plugin_readme",
        }
    }
}

/// Bounded terminal state for one candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressDiscoverySourceOutcome {
    Observed,
    NoMetadata,
    NotFound,
    Unauthorized,
    RateLimited,
    RedirectObserved,
    UnsupportedContent,
    InvalidAdvertisement,
    Malformed,
    Truncated,
    RequestFailed,
    BudgetExhausted,
    Cancelled,
    DeadlineExceeded,
    NotSelectedByLimit,
    NotAttemptedAfterThrottle,
}

impl WordPressDiscoverySourceOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::NoMetadata => "no_metadata",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::RedirectObserved => "redirect_observed",
            Self::UnsupportedContent => "unsupported_content",
            Self::InvalidAdvertisement => "invalid_advertisement",
            Self::Malformed => "malformed",
            Self::Truncated => "truncated",
            Self::RequestFailed => "request_failed",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::NotSelectedByLimit => "not_selected_by_limit",
            Self::NotAttemptedAfterThrottle => "not_attempted_after_throttle",
        }
    }

    pub(crate) const fn is_completed_response(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::NoMetadata
                | Self::NotFound
                | Self::Unauthorized
                | Self::RateLimited
                | Self::RedirectObserved
                | Self::UnsupportedContent
                | Self::Malformed
                | Self::Truncated
        )
    }
}

/// Bounded fields retained from one theme stylesheet header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressThemeDiscoveryMetadata {
    pub(super) name: Option<String>,
    pub(super) version: Option<String>,
    pub(super) template: Option<String>,
    pub(super) requires_wordpress: Option<String>,
    pub(super) requires_php: Option<String>,
    pub(super) tested_up_to: Option<String>,
}

impl WordPressThemeDiscoveryMetadata {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    pub fn template(&self) -> Option<&str> {
        self.template.as_deref()
    }
    pub fn requires_wordpress(&self) -> Option<&str> {
        self.requires_wordpress.as_deref()
    }
    pub fn requires_php(&self) -> Option<&str> {
        self.requires_php.as_deref()
    }
    pub fn tested_up_to(&self) -> Option<&str> {
        self.tested_up_to.as_deref()
    }
}

/// Bounded fields retained from one plugin distribution readme.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressPluginDiscoveryMetadata {
    pub(super) name: Option<String>,
    pub(super) stable_tag: Option<String>,
    pub(super) requires_wordpress: Option<String>,
    pub(super) requires_php: Option<String>,
    pub(super) tested_up_to: Option<String>,
}

impl WordPressPluginDiscoveryMetadata {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn stable_tag(&self) -> Option<&str> {
        self.stable_tag.as_deref()
    }
    pub fn requires_wordpress(&self) -> Option<&str> {
        self.requires_wordpress.as_deref()
    }
    pub fn requires_php(&self) -> Option<&str> {
        self.requires_php.as_deref()
    }
    pub fn tested_up_to(&self) -> Option<&str> {
        self.tested_up_to.as_deref()
    }
}

/// Redaction-safe result for one deterministic metadata candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressDiscoverySourceAudit {
    pub(super) kind: WordPressDiscoverySourceKind,
    pub(super) component: Option<WordPressComponentIdentity>,
    pub(super) parent_depth: u8,
    pub(super) outcome: WordPressDiscoverySourceOutcome,
    pub(super) request_attempted: bool,
    pub(super) response_bytes: u64,
    pub(super) evidence_ids: Vec<EvidenceId>,
    pub(super) namespaces: Vec<String>,
    pub(super) theme: Option<WordPressThemeDiscoveryMetadata>,
    pub(super) plugin: Option<WordPressPluginDiscoveryMetadata>,
    pub(super) association: WordPressDiscoveryAssociation,
    pub(super) resource_reference: String,
    pub(super) role_reference: Option<String>,
}

impl WordPressDiscoverySourceAudit {
    pub const fn kind(&self) -> WordPressDiscoverySourceKind {
        self.kind
    }
    pub const fn component_kind(&self) -> Option<WordPressComponentKind> {
        match &self.component {
            Some(value) => Some(value.kind()),
            None => None,
        }
    }
    pub fn component_slug(&self) -> Option<&str> {
        self.component
            .as_ref()
            .map(WordPressComponentIdentity::slug)
    }
    pub const fn parent_depth(&self) -> u8 {
        self.parent_depth
    }
    pub const fn outcome(&self) -> WordPressDiscoverySourceOutcome {
        self.outcome
    }
    pub const fn request_attempted(&self) -> bool {
        self.request_attempted
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
    pub fn namespaces(&self) -> &[String] {
        &self.namespaces
    }
    pub const fn theme(&self) -> Option<&WordPressThemeDiscoveryMetadata> {
        self.theme.as_ref()
    }
    pub const fn plugin(&self) -> Option<&WordPressPluginDiscoveryMetadata> {
        self.plugin.as_ref()
    }
    pub const fn association(&self) -> WordPressDiscoveryAssociation {
        self.association
    }
    pub fn resource_reference(&self) -> &str {
        &self.resource_reference
    }
    pub fn role_reference(&self) -> Option<&str> {
        self.role_reference.as_deref()
    }
}

/// Versioned, redaction-safe discovery audit retained beside the legacy
/// transport-free WordPress review audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAssessmentWordPressDiscoveryAudit {
    pub(super) seed_count: u8,
    pub(super) candidate_count: u8,
    pub(super) candidate_limit_reached: bool,
    pub(super) omitted_candidate_count: u64,
    pub(super) attempted_request_count: u8,
    pub(super) completed_response_count: u8,
    pub(super) committed_response_count: u8,
    pub(super) response_bytes: u64,
    pub(super) sources: Vec<WordPressDiscoverySourceAudit>,
    pub(super) layout: WordPressDiscoveryLayoutAudit,
}

impl WebAssessmentWordPressDiscoveryAudit {
    pub const fn policy_id(&self) -> &'static str {
        WORDPRESS_DISCOVERY_POLICY_ID
    }
    pub const fn selected(&self) -> bool {
        true
    }
    pub const fn seed_count(&self) -> u8 {
        self.seed_count
    }
    pub const fn candidate_count(&self) -> u8 {
        self.candidate_count
    }
    /// True when at least one distinct admitted candidate was deliberately
    /// omitted by the fixed 32-candidate selection ceiling.
    pub const fn candidate_limit_reached(&self) -> bool {
        self.candidate_limit_reached
    }
    /// Exact number of distinct candidate details omitted by the fixed
    /// candidate ceiling during this bounded selection.
    pub const fn omitted_candidate_count(&self) -> u64 {
        self.omitted_candidate_count
    }
    pub const fn attempted_request_count(&self) -> u8 {
        self.attempted_request_count
    }
    pub const fn completed_response_count(&self) -> u8 {
        self.completed_response_count
    }
    pub const fn committed_response_count(&self) -> u8 {
        self.committed_response_count
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
    pub fn sources(&self) -> &[WordPressDiscoverySourceAudit] {
        &self.sources
    }
    pub const fn layout(&self) -> &WordPressDiscoveryLayoutAudit {
        &self.layout
    }

    pub(crate) fn is_internally_consistent(&self) -> bool {
        let source_bytes = self.sources.iter().try_fold(0_u64, |total, source| {
            total.checked_add(source.response_bytes)
        });
        let evidence_references = self.sources.iter().try_fold(0_usize, |total, source| {
            total.checked_add(source.evidence_ids.len())
        });
        let completed_sources = self
            .sources
            .iter()
            .filter(|source| source.outcome.is_completed_response())
            .count();
        let evidence_shape_valid = self.sources.iter().all(|source| {
            source.evidence_ids.len() == usize::from(source.outcome.is_completed_response())
        });
        let attempted_sources = self
            .sources
            .iter()
            .filter(|source| source.request_attempted)
            .count();
        let attempt_shape_valid = self.sources.iter().all(|source| {
            let completed_response_was_attempted =
                !source.outcome.is_completed_response() || source.request_attempted;
            let unattempted_source_has_no_response_bytes =
                source.request_attempted || source.response_bytes == 0;
            let definitely_not_dispatched = matches!(
                source.outcome,
                WordPressDiscoverySourceOutcome::InvalidAdvertisement
                    | WordPressDiscoverySourceOutcome::NotSelectedByLimit
                    | WordPressDiscoverySourceOutcome::NotAttemptedAfterThrottle
            );
            let dispatch_state_matches_outcome =
                !definitely_not_dispatched || !source.request_attempted;
            completed_response_was_attempted
                && unattempted_source_has_no_response_bytes
                && dispatch_state_matches_outcome
        });
        let unique_sources = self
            .sources
            .iter()
            .map(|source| source.resource_reference.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        usize::from(self.seed_count) <= MAX_WORDPRESS_DISCOVERY_CANDIDATES
            && usize::from(self.candidate_count) <= MAX_WORDPRESS_DISCOVERY_CANDIDATES
            && self.seed_count <= self.candidate_count
            && self.candidate_limit_reached == (self.omitted_candidate_count > 0)
            && self.omitted_candidate_count <= MAX_WORDPRESS_DISCOVERY_OMITTED_CANDIDATES
            && (self.omitted_candidate_count == 0
                || usize::from(self.candidate_count) == MAX_WORDPRESS_DISCOVERY_CANDIDATES)
            && self.attempted_request_count <= MAX_WORDPRESS_DISCOVERY_REQUESTS
            && self.attempted_request_count <= self.candidate_count
            && attempted_sources == usize::from(self.attempted_request_count)
            && attempted_request_classes_within_limits(&self.sources)
            && self.completed_response_count <= self.attempted_request_count
            && completed_sources == usize::from(self.completed_response_count)
            && self.committed_response_count == self.completed_response_count
            && usize::from(self.candidate_count) == self.sources.len()
            && unique_sources == self.sources.len()
            && source_bytes == Some(self.response_bytes)
            && evidence_shape_valid
            && attempt_shape_valid
            && evidence_references == Some(usize::from(self.committed_response_count))
            && discovery_layout_is_consistent(&self.layout, &self.sources)
    }
}

fn discovery_layout_is_consistent(
    layout: &WordPressDiscoveryLayoutAudit,
    sources: &[WordPressDiscoverySourceAudit],
) -> bool {
    let role_order = [
        WordPressDiscoveryLayoutRole::Core,
        WordPressDiscoveryLayoutRole::Themes,
        WordPressDiscoveryLayoutRole::Plugins,
        WordPressDiscoveryLayoutRole::RestIndex,
    ];
    let declaration_valid = layout.declaration.as_ref().is_none_or(|declaration| {
        declaration.byte_length > 0
            && declaration.byte_length
                <= u64::try_from(MAX_WORDPRESS_DISCOVERY_LAYOUT_BYTES).unwrap_or(u64::MAX)
            && valid_sha256_digest(&declaration.sha256)
    });
    if !valid_opaque_reference(&layout.application_reference)
        || !declaration_valid
        || layout.roles.len() != role_order.len()
        || layout
            .roles
            .iter()
            .zip(role_order)
            .any(|(entry, expected)| {
                entry.role != expected
                    || match entry.status {
                        WordPressDiscoveryLayoutStatus::Exact => {
                            entry
                                .reference
                                .as_deref()
                                .is_none_or(|reference| !valid_opaque_reference(reference))
                                || entry.candidate_count == 0
                                || entry.basis == WordPressDiscoveryLayoutBasis::None
                        },
                        WordPressDiscoveryLayoutStatus::Ambiguous => {
                            entry.reference.is_some()
                                || entry.candidate_count < 2
                                || entry.basis == WordPressDiscoveryLayoutBasis::None
                        },
                        WordPressDiscoveryLayoutStatus::Unresolved => {
                            entry.reference.is_some()
                                || entry.candidate_count != 0
                                || entry.basis != WordPressDiscoveryLayoutBasis::None
                        },
                    }
            })
    {
        return false;
    }
    sources.iter().all(|source| {
        let role = match source.kind {
            WordPressDiscoverySourceKind::RestIndex => WordPressDiscoveryLayoutRole::RestIndex,
            WordPressDiscoverySourceKind::ThemeStylesheet => WordPressDiscoveryLayoutRole::Themes,
            WordPressDiscoverySourceKind::PluginReadme => WordPressDiscoveryLayoutRole::Plugins,
        };
        let exact_role_binding = source.role_reference.as_deref().is_some_and(|reference| {
            layout.roles.iter().any(|entry| {
                entry.role == role
                    && entry.status == WordPressDiscoveryLayoutStatus::Exact
                    && entry.reference.as_deref() == Some(reference)
            }) && valid_opaque_reference(reference)
        });
        let binding_required = source.request_attempted
            || source.outcome.is_completed_response()
            || source.theme.is_some()
            || source.plugin.is_some()
            || !source.namespaces.is_empty();
        let association_valid = match source.association {
            WordPressDiscoveryAssociation::StructuredAdvertisement => {
                role == WordPressDiscoveryLayoutRole::RestIndex && source.role_reference.is_some()
            },
            WordPressDiscoveryAssociation::OperatorQualifiedAdvertisement => {
                role == WordPressDiscoveryLayoutRole::RestIndex && source.role_reference.is_some()
            },
            WordPressDiscoveryAssociation::ObservedConventional => {
                matches!(
                    role,
                    WordPressDiscoveryLayoutRole::Themes | WordPressDiscoveryLayoutRole::Plugins
                ) && source.role_reference.is_some()
            },
            WordPressDiscoveryAssociation::ExplicitOperator => {
                matches!(
                    role,
                    WordPressDiscoveryLayoutRole::Themes | WordPressDiscoveryLayoutRole::Plugins
                ) && source.role_reference.is_some()
            },
            WordPressDiscoveryAssociation::SameThemeBaseParent => {
                role == WordPressDiscoveryLayoutRole::Themes
                    && source.parent_depth == 1
                    && source.role_reference.is_some()
            },
            WordPressDiscoveryAssociation::InvalidAdvertisement => {
                role == WordPressDiscoveryLayoutRole::RestIndex
                    && source.outcome == WordPressDiscoverySourceOutcome::InvalidAdvertisement
                    && source.role_reference.is_none()
            },
        };
        association_valid
            && valid_opaque_reference(&source.resource_reference)
            && ((!binding_required && source.role_reference.is_none()) || exact_role_binding)
    })
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_opaque_reference(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn attempted_request_classes_within_limits(sources: &[WordPressDiscoverySourceAudit]) -> bool {
    let mut rest = 0_u8;
    let mut themes = 0_u8;
    let mut plugins = 0_u8;
    for source in sources {
        if !source.request_attempted {
            continue;
        }
        match source.kind {
            WordPressDiscoverySourceKind::RestIndex => rest = rest.saturating_add(1),
            WordPressDiscoverySourceKind::ThemeStylesheet => themes = themes.saturating_add(1),
            WordPressDiscoverySourceKind::PluginReadme => plugins = plugins.saturating_add(1),
        }
    }
    rest <= MAX_WORDPRESS_DISCOVERY_REST_REQUESTS
        && themes <= MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS
        && plugins <= MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS
}

pub(super) async fn execute_wordpress_discovery(
    input: WordPressDiscoveryExecutionInput,
    authority: &SharedWebRuntimeAuthority,
    deadline: Option<tokio::time::Instant>,
) -> Result<WordPressDiscoveryExecution, WordPressDiscoveryExecutionError> {
    let WordPressDiscoveryExecutionInput {
        mut candidates,
        mut omitted_candidate_count,
        mut considered_candidate_fingerprints,
        root_evidence_ids,
        subject,
        layout,
    } = input;
    if considered_candidate_fingerprints.len() > MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
        || candidates.iter().any(|candidate| {
            !considered_candidate_fingerprints.contains(&discovery_seed_fingerprint(candidate))
        })
        || u64::try_from(
            considered_candidate_fingerprints
                .len()
                .saturating_sub(candidates.len()),
        ) != Ok(omitted_candidate_count)
    {
        return Err(WordPressDiscoveryExecutionError::EvidenceModel);
    }
    if candidates.is_empty() {
        return Ok(WordPressDiscoveryExecution {
            audit: WebAssessmentWordPressDiscoveryAudit {
                seed_count: 0,
                candidate_count: 0,
                candidate_limit_reached: omitted_candidate_count > 0,
                omitted_candidate_count,
                attempted_request_count: 0,
                completed_response_count: 0,
                committed_response_count: 0,
                response_bytes: 0,
                sources: Vec::new(),
                layout,
            },
            signals: Vec::new(),
            stop: WordPressDiscoveryStop::Complete,
        });
    }
    if root_evidence_ids.is_empty()
        || root_evidence_ids.iter().any(|id| {
            authority
                .knowledge()
                .evidence(id)
                .is_none_or(|evidence| evidence.subject() != &subject)
        })
    {
        return Err(WordPressDiscoveryExecutionError::RootEvidenceUnavailable);
    }
    candidates.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    candidates.dedup_by(|left, right| {
        discovery_seed_fingerprint(left) == discovery_seed_fingerprint(right)
    });
    if candidates.len() > MAX_WORDPRESS_DISCOVERY_CANDIDATES {
        let original_count = candidates.len();
        retain_pending_request_quota_candidates(
            &mut candidates,
            MAX_WORDPRESS_DISCOVERY_CANDIDATES,
            usize::from(MAX_WORDPRESS_DISCOVERY_REST_REQUESTS),
            usize::from(MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS),
            usize::from(MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS),
        );
        let omitted = original_count.saturating_sub(candidates.len());
        omitted_candidate_count = omitted_candidate_count
            .checked_add(
                u64::try_from(omitted)
                    .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?,
            )
            .ok_or(WordPressDiscoveryExecutionError::EvidenceModel)?;
    }
    let seed_count = u8::try_from(candidates.len()).unwrap_or(u8::MAX);
    let mut sources = Vec::new();
    let mut pending_evidence = Vec::new();
    let mut signals = Vec::new();
    let mut rest_requests = 0_u8;
    let mut theme_requests = 0_u8;
    let mut plugin_requests = 0_u8;
    let mut attempted = 0_u8;
    let mut completed = 0_u8;
    let mut response_bytes = 0_u64;
    let mut stopped = WordPressDiscoveryStop::Complete;
    let mut throttled = false;
    let mut index = 0_usize;
    let evidence_reliability = authority.requests().policy().reliability().min(
        ConfidenceScore::from_percent(70)
            .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?,
    );

    while index < candidates.len() {
        let candidate = candidates[index].clone();
        index += 1;
        if throttled {
            sources.push(empty_source(
                &candidate,
                WordPressDiscoverySourceOutcome::NotAttemptedAfterThrottle,
                false,
                0,
            ));
            continue;
        }
        if let Some(outcome) = candidate.preflight_outcome() {
            sources.push(empty_source(&candidate, outcome, false, 0));
            continue;
        }
        if !candidate.dispatch_contract_is_valid() {
            return Err(WordPressDiscoveryExecutionError::EvidenceModel);
        }
        let kind_count = match candidate.kind() {
            WordPressDiscoverySourceKind::RestIndex => &mut rest_requests,
            WordPressDiscoverySourceKind::ThemeStylesheet => &mut theme_requests,
            WordPressDiscoverySourceKind::PluginReadme => &mut plugin_requests,
        };
        let kind_limit = match candidate.kind() {
            WordPressDiscoverySourceKind::RestIndex => MAX_WORDPRESS_DISCOVERY_REST_REQUESTS,
            WordPressDiscoverySourceKind::ThemeStylesheet => MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS,
            WordPressDiscoverySourceKind::PluginReadme => MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS,
        };
        if attempted >= MAX_WORDPRESS_DISCOVERY_REQUESTS || *kind_count >= kind_limit {
            sources.push(empty_source(
                &candidate,
                WordPressDiscoverySourceOutcome::NotSelectedByLimit,
                false,
                0,
            ));
            continue;
        }
        if authority.cancellation().is_cancelled() {
            sources.push(empty_source(
                &candidate,
                WordPressDiscoverySourceOutcome::Cancelled,
                false,
                0,
            ));
            stopped = WordPressDiscoveryStop::Cancelled;
            break;
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            sources.push(empty_source(
                &candidate,
                WordPressDiscoverySourceOutcome::DeadlineExceeded,
                false,
                0,
            ));
            stopped = WordPressDiscoveryStop::DeadlineExceeded;
            break;
        }
        if response_bytes >= MAX_WORDPRESS_DISCOVERY_RESPONSE_BYTES {
            sources.push(empty_source(
                &candidate,
                WordPressDiscoverySourceOutcome::BudgetExhausted,
                false,
                0,
            ));
            stopped = WordPressDiscoveryStop::DiscoveryResponseLimit;
            break;
        }

        let per_source_limit = match candidate.kind() {
            WordPressDiscoverySourceKind::RestIndex => MAX_WORDPRESS_DISCOVERY_REST_BYTES,
            WordPressDiscoverySourceKind::ThemeStylesheet
            | WordPressDiscoverySourceKind::PluginReadme => MAX_WORDPRESS_DISCOVERY_STATIC_BYTES,
        };
        let remaining = MAX_WORDPRESS_DISCOVERY_RESPONSE_BYTES.saturating_sub(response_bytes);
        let response_limit = u64::try_from(per_source_limit)
            .unwrap_or(u64::MAX)
            .min(remaining);
        let source_evidence_ids = candidate.source_evidence_ids(&root_evidence_ids);
        let request_descriptor = candidate.request_descriptor(source_evidence_ids.len())?;
        let before = authority.request_accounting().snapshot();
        let request = authority
            .requests()
            .collect_anonymous_wordpress_get_for_runtime(
                WORDPRESS_DISCOVERY_ACTION_ID,
                DecisionExecutionStage::Passive,
                Some(DecisionActionOrigin::Planned),
                DecisionExecutionLimits::new().with_max_response_body_bytes(response_limit),
                &request_descriptor,
            );
        let collected =
            await_bounded_request(request, authority.cancellation_token(), deadline).await;
        let after = authority.request_accounting().snapshot();
        let request_delta = after
            .total_requests()
            .saturating_sub(before.total_requests());
        if request_delta > 1 {
            return Err(WordPressDiscoveryExecutionError::EvidenceModel);
        }
        let request_attempted = request_delta == 1;
        let response_delta = after
            .response_bytes()
            .saturating_sub(before.response_bytes());
        attempted = attempted.saturating_add(u8::try_from(request_delta).unwrap_or(u8::MAX));
        *kind_count = (*kind_count).saturating_add(u8::try_from(request_delta).unwrap_or(u8::MAX));
        response_bytes = response_bytes.saturating_add(response_delta);

        let response = match collected {
            BoundedRequest::Cancelled => {
                sources.push(empty_source(
                    &candidate,
                    WordPressDiscoverySourceOutcome::Cancelled,
                    request_attempted,
                    response_delta,
                ));
                stopped = WordPressDiscoveryStop::Cancelled;
                break;
            },
            BoundedRequest::DeadlineExceeded => {
                sources.push(empty_source(
                    &candidate,
                    WordPressDiscoverySourceOutcome::DeadlineExceeded,
                    request_attempted,
                    response_delta,
                ));
                stopped = WordPressDiscoveryStop::DeadlineExceeded;
                break;
            },
            BoundedRequest::Completed(result) => match *result {
                Err(HttpRequestBrokerError::RuntimeLimit(limit)) => {
                    sources.push(empty_source(
                        &candidate,
                        WordPressDiscoverySourceOutcome::BudgetExhausted,
                        request_attempted,
                        response_delta,
                    ));
                    stopped = WordPressDiscoveryStop::RuntimeLimit(limit.dimension());
                    break;
                },
                Err(HttpRequestBrokerError::Http(_)) => {
                    sources.push(empty_source(
                        &candidate,
                        WordPressDiscoverySourceOutcome::RequestFailed,
                        request_attempted,
                        response_delta,
                    ));
                    continue;
                },
                Ok(response) => response,
            },
        };
        completed = completed.saturating_add(1);
        let (outcome, namespaces, theme, plugin) = classify_response(&candidate, &response);
        let evidence = response_evidence(
            &subject,
            source_evidence_ids,
            candidate.kind(),
            outcome,
            response.body(),
            sources.len(),
            evidence_reliability,
        )?;
        let evidence_id = evidence.id().clone();
        pending_evidence.push(evidence);

        if let (Some(component), Some(metadata)) = (candidate.component_identity(), theme.as_ref())
        {
            if let Some(version) = metadata.version() {
                let signal = WordPressComponentSignal::theme_stylesheet_declaration(
                    component.slug(),
                    version,
                )
                .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?;
                if !signals.contains(&signal) {
                    signals.push(signal);
                }
            }
            if candidate.parent_depth() == 0 {
                if let Some(template) = metadata.template() {
                    if let Some(parent) =
                        parent_theme_candidate(&candidate, template, evidence_id.clone())
                    {
                        let fingerprint = discovery_seed_fingerprint(&parent);
                        let pending_independent = candidates[index..]
                            .iter()
                            .position(|existing| {
                                discovery_seed_fingerprint(existing) == fingerprint
                            })
                            .map(|offset| index + offset);
                        let already_attempted = candidates[..index]
                            .iter()
                            .any(|existing| discovery_seed_fingerprint(existing) == fingerprint);
                        // A seed independently retained from the selected entry keeps that
                        // association. The child's Template declaration remains in its own
                        // metadata; rewriting a seed or committed source would misstate the
                        // request provenance used by the broker. Promote a matching pending
                        // seed so corroborating evidence cannot push the parent past the
                        // bounded theme quota.
                        if let Some(pending_index) = pending_independent {
                            let pending = candidates.remove(pending_index);
                            candidates.insert(index, pending);
                        } else if !already_attempted {
                            if !considered_candidate_fingerprints.contains(&fingerprint) {
                                if considered_candidate_fingerprints.len()
                                    == MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
                                {
                                    return Err(
                                        WordPressDiscoveryExecutionError::CandidateIdentityLimitExceeded,
                                    );
                                }
                                considered_candidate_fingerprints.insert(fingerprint);
                            }
                            let mut pending = candidates.split_off(index);
                            pending.push(parent);
                            retain_pending_request_quota_candidates(
                                &mut pending,
                                MAX_WORDPRESS_DISCOVERY_CANDIDATES.saturating_sub(index),
                                usize::from(
                                    MAX_WORDPRESS_DISCOVERY_REST_REQUESTS
                                        .saturating_sub(rest_requests),
                                ),
                                usize::from(
                                    MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS
                                        .saturating_sub(theme_requests),
                                ),
                                usize::from(
                                    MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS
                                        .saturating_sub(plugin_requests),
                                ),
                            );
                            candidates.extend(pending);
                            omitted_candidate_count = u64::try_from(
                                considered_candidate_fingerprints
                                    .len()
                                    .saturating_sub(candidates.len()),
                            )
                            .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?;
                        }
                    }
                }
            }
        }
        throttled = outcome == WordPressDiscoverySourceOutcome::RateLimited;
        sources.push(WordPressDiscoverySourceAudit {
            kind: candidate.kind(),
            component: candidate.component_identity().cloned(),
            parent_depth: candidate.parent_depth(),
            outcome,
            request_attempted,
            response_bytes: response_delta,
            evidence_ids: vec![evidence_id],
            namespaces,
            theme,
            plugin,
            association: candidate.association(),
            resource_reference: candidate.resource_reference(),
            role_reference: candidate.role_reference(),
        });
        if response_bytes >= MAX_WORDPRESS_DISCOVERY_RESPONSE_BYTES {
            stopped = WordPressDiscoveryStop::DiscoveryResponseLimit;
            break;
        }
    }

    let unattempted_outcome = match stopped {
        WordPressDiscoveryStop::Complete => None,
        WordPressDiscoveryStop::Cancelled => Some(WordPressDiscoverySourceOutcome::Cancelled),
        WordPressDiscoveryStop::DeadlineExceeded => {
            Some(WordPressDiscoverySourceOutcome::DeadlineExceeded)
        },
        WordPressDiscoveryStop::RuntimeLimit(_)
        | WordPressDiscoveryStop::DiscoveryResponseLimit => {
            Some(WordPressDiscoverySourceOutcome::BudgetExhausted)
        },
    };
    if let Some(outcome) = unattempted_outcome {
        for candidate in &candidates[index..] {
            sources.push(empty_source(candidate, outcome, false, 0));
        }
    }

    if !pending_evidence.is_empty() {
        authority
            .knowledge()
            .insert_evidence_batch(pending_evidence)
            .map_err(|_| WordPressDiscoveryExecutionError::EvidenceCommit)?;
    }
    let committed = sources
        .iter()
        .try_fold(0_usize, |count, source| {
            count.checked_add(source.evidence_ids.len())
        })
        .and_then(|count| u8::try_from(count).ok())
        .unwrap_or(u8::MAX);
    Ok(WordPressDiscoveryExecution {
        audit: WebAssessmentWordPressDiscoveryAudit {
            seed_count,
            candidate_count: u8::try_from(candidates.len()).unwrap_or(u8::MAX),
            candidate_limit_reached: omitted_candidate_count > 0,
            omitted_candidate_count,
            attempted_request_count: attempted,
            completed_response_count: completed,
            committed_response_count: committed,
            response_bytes,
            sources,
            layout,
        },
        signals,
        stop: stopped,
    })
}

fn retain_pending_request_quota_candidates(
    candidates: &mut Vec<WordPressDiscoverySeed>,
    capacity: usize,
    rest_limit: usize,
    theme_limit: usize,
    plugin_limit: usize,
) {
    candidates.sort_by(|left, right| {
        let left_parent_priority = u8::from(
            left.kind() != WordPressDiscoverySourceKind::ThemeStylesheet
                || left.parent_depth() == 0,
        );
        let right_parent_priority = u8::from(
            right.kind() != WordPressDiscoverySourceKind::ThemeStylesheet
                || right.parent_depth() == 0,
        );
        left.sort_key()
            .0
            .cmp(&right.sort_key().0)
            .then_with(|| left_parent_priority.cmp(&right_parent_priority))
            .then_with(|| left.sort_key().cmp(&right.sort_key()))
    });
    if candidates.len() <= capacity {
        return;
    }

    let mut selected = vec![false; candidates.len()];
    let mut selected_count = 0_usize;
    for (kind, limit) in [
        (WordPressDiscoverySourceKind::RestIndex, rest_limit),
        (WordPressDiscoverySourceKind::ThemeStylesheet, theme_limit),
        (WordPressDiscoverySourceKind::PluginReadme, plugin_limit),
    ] {
        let remaining_capacity = capacity.saturating_sub(selected_count);
        for (index, _) in candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                candidate.kind() == kind && candidate.preflight_outcome().is_none()
            })
            .take(limit.min(remaining_capacity))
        {
            selected[index] = true;
            selected_count += 1;
        }
    }
    for retained in &mut selected {
        if selected_count == capacity {
            break;
        }
        if !*retained {
            *retained = true;
            selected_count += 1;
        }
    }
    let mut index = 0_usize;
    candidates.retain(|_| {
        let retain = selected[index];
        index += 1;
        retain
    });
}

enum BoundedRequest {
    Completed(Box<Result<crate::http_evidence::CollectedHttpResponse, HttpRequestBrokerError>>),
    Cancelled,
    DeadlineExceeded,
}

async fn await_bounded_request(
    request: impl std::future::Future<
        Output = Result<crate::http_evidence::CollectedHttpResponse, HttpRequestBrokerError>,
    >,
    cancellation: CancellationToken,
    deadline: Option<tokio::time::Instant>,
) -> BoundedRequest {
    match deadline {
        Some(deadline) => {
            tokio::select! {
                _ = cancellation.cancelled() => BoundedRequest::Cancelled,
                result = tokio::time::timeout_at(deadline, request) => match result {
                    Ok(result) => BoundedRequest::Completed(Box::new(result)),
                    Err(_) => BoundedRequest::DeadlineExceeded,
                },
            }
        },
        None => {
            tokio::select! {
                _ = cancellation.cancelled() => BoundedRequest::Cancelled,
                result = request => BoundedRequest::Completed(Box::new(result)),
            }
        },
    }
}

fn empty_source(
    seed: &WordPressDiscoverySeed,
    outcome: WordPressDiscoverySourceOutcome,
    request_attempted: bool,
    response_bytes: u64,
) -> WordPressDiscoverySourceAudit {
    WordPressDiscoverySourceAudit {
        kind: seed.kind(),
        component: seed.component_identity().cloned(),
        parent_depth: seed.parent_depth(),
        outcome,
        request_attempted,
        response_bytes,
        evidence_ids: Vec::new(),
        namespaces: Vec::new(),
        theme: None,
        plugin: None,
        association: seed.association(),
        resource_reference: seed.resource_reference(),
        role_reference: seed.role_reference(),
    }
}

fn response_evidence(
    subject: &EntityId,
    parents: &[EvidenceId],
    kind: WordPressDiscoverySourceKind,
    outcome: WordPressDiscoverySourceOutcome,
    body: &[u8],
    sequence: usize,
    reliability: ConfidenceScore,
) -> Result<Evidence, WordPressDiscoveryExecutionError> {
    let source = EvidenceSource::new(WORDPRESS_DISCOVERY_EVIDENCE_COMPONENT, kind.as_str())
        .and_then(|source| {
            source.with_correlation_id(format!("wordpress-discovery-{}", sequence + 1))
        })
        .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?;
    let predicate = KnowledgePredicate::new(
        WORDPRESS_DISCOVERY_EVIDENCE_NAMESPACE,
        format!("{}-response", kind.as_str().replace('_', "-")),
    )
    .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?;
    let derivation = EvidenceDerivation::new(
        parents.iter().cloned(),
        DerivationAlgorithm::new("wordpress-public-metadata", 1)
            .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?,
    )
    .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?;
    Ok(Evidence::new(
        subject.clone(),
        EvidenceKind::Custom("wordpress-discovery".to_owned()),
        predicate,
        EvidenceValue::Text(format!(
            "{}:sha256:{:x}",
            outcome.as_str(),
            Sha256::digest(body)
        )),
        source,
        reliability,
    )
    .derived_from(derivation))
}

fn parent_theme_candidate(
    current: &WordPressDiscoverySeed,
    template: &str,
    source_evidence_id: EvidenceId,
) -> Option<WordPressDiscoverySeed> {
    let identity = WordPressComponentIdentity::new(WordPressComponentKind::Theme, template).ok()?;
    if current.kind() != WordPressDiscoverySourceKind::ThemeStylesheet
        || current.parent_depth() != 0
        || current
            .component_identity()
            .is_some_and(|component| component.slug() == template)
    {
        return None;
    }
    let url = current
        .role_base_url()
        .join(&format!("{template}/style.css"))
        .ok()?;
    Some(
        WordPressDiscoverySeed::admitted_component(
            url,
            current.application_url().clone(),
            current.role_base_url().clone(),
            WordPressDiscoveryAssociation::SameThemeBaseParent,
            identity,
            1,
        )
        .with_source_evidence(source_evidence_id),
    )
}

fn classify_response(
    candidate: &WordPressDiscoverySeed,
    response: &crate::http_evidence::CollectedHttpResponse,
) -> (
    WordPressDiscoverySourceOutcome,
    Vec<String>,
    Option<WordPressThemeDiscoveryMetadata>,
    Option<WordPressPluginDiscoveryMetadata>,
) {
    let status = response.status();
    if status == 429 {
        return (
            WordPressDiscoverySourceOutcome::RateLimited,
            Vec::new(),
            None,
            None,
        );
    }
    if matches!(status, 401 | 403) {
        return (
            WordPressDiscoverySourceOutcome::Unauthorized,
            Vec::new(),
            None,
            None,
        );
    }
    if status == 404 {
        return (
            WordPressDiscoverySourceOutcome::NotFound,
            Vec::new(),
            None,
            None,
        );
    }
    if (300..400).contains(&status) {
        return (
            WordPressDiscoverySourceOutcome::RedirectObserved,
            Vec::new(),
            None,
            None,
        );
    }
    if status == 206 || response.body_truncated() {
        return (
            WordPressDiscoverySourceOutcome::Truncated,
            Vec::new(),
            None,
            None,
        );
    }
    if status != 200 {
        return (
            WordPressDiscoverySourceOutcome::UnsupportedContent,
            Vec::new(),
            None,
            None,
        );
    }
    // Reaching the exact retention ceiling is not evidence that the response
    // ended there. Parse successful metadata only after the broker observed
    // EOF; otherwise a valid-looking retained prefix could mint metadata from
    // a longer response.
    if !response.body_complete() {
        return (
            WordPressDiscoverySourceOutcome::Truncated,
            Vec::new(),
            None,
            None,
        );
    }
    match candidate.kind() {
        WordPressDiscoverySourceKind::RestIndex => match parse_rest_namespaces(response) {
            Ok(namespaces) if namespaces.is_empty() => (
                WordPressDiscoverySourceOutcome::NoMetadata,
                namespaces,
                None,
                None,
            ),
            Ok(namespaces) => (
                WordPressDiscoverySourceOutcome::Observed,
                namespaces,
                None,
                None,
            ),
            Err(ParseMetadataError::Unsupported) => (
                WordPressDiscoverySourceOutcome::UnsupportedContent,
                Vec::new(),
                None,
                None,
            ),
            Err(ParseMetadataError::Malformed) => (
                WordPressDiscoverySourceOutcome::Malformed,
                Vec::new(),
                None,
                None,
            ),
            Err(ParseMetadataError::Truncated) => (
                WordPressDiscoverySourceOutcome::Truncated,
                Vec::new(),
                None,
                None,
            ),
        },
        WordPressDiscoverySourceKind::ThemeStylesheet => {
            if response.normalized_media_type().as_deref() != Some("text/css") {
                return (
                    WordPressDiscoverySourceOutcome::UnsupportedContent,
                    Vec::new(),
                    None,
                    None,
                );
            }
            match parse_theme_metadata(response.body()) {
                Ok(Some(theme)) => (
                    WordPressDiscoverySourceOutcome::Observed,
                    Vec::new(),
                    Some(theme),
                    None,
                ),
                Ok(None) => (
                    WordPressDiscoverySourceOutcome::NoMetadata,
                    Vec::new(),
                    None,
                    None,
                ),
                Err(error) => (
                    match error {
                        ParseMetadataError::Truncated => WordPressDiscoverySourceOutcome::Truncated,
                        ParseMetadataError::Unsupported => {
                            WordPressDiscoverySourceOutcome::UnsupportedContent
                        },
                        ParseMetadataError::Malformed => WordPressDiscoverySourceOutcome::Malformed,
                    },
                    Vec::new(),
                    None,
                    None,
                ),
            }
        },
        WordPressDiscoverySourceKind::PluginReadme => {
            if response.normalized_media_type().as_deref() != Some("text/plain") {
                return (
                    WordPressDiscoverySourceOutcome::UnsupportedContent,
                    Vec::new(),
                    None,
                    None,
                );
            }
            match parse_plugin_metadata(response.body()) {
                Ok(Some(plugin)) => (
                    WordPressDiscoverySourceOutcome::Observed,
                    Vec::new(),
                    None,
                    Some(plugin),
                ),
                Ok(None) => (
                    WordPressDiscoverySourceOutcome::NoMetadata,
                    Vec::new(),
                    None,
                    None,
                ),
                Err(error) => (
                    match error {
                        ParseMetadataError::Truncated => WordPressDiscoverySourceOutcome::Truncated,
                        ParseMetadataError::Unsupported => {
                            WordPressDiscoverySourceOutcome::UnsupportedContent
                        },
                        ParseMetadataError::Malformed => WordPressDiscoverySourceOutcome::Malformed,
                    },
                    Vec::new(),
                    None,
                    None,
                ),
            }
        },
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ParseMetadataError {
    Unsupported,
    Malformed,
    Truncated,
}

#[derive(Deserialize)]
struct RestIndexWire {
    #[serde(default)]
    namespaces: Vec<String>,
}

fn parse_rest_namespaces(
    response: &crate::http_evidence::CollectedHttpResponse,
) -> Result<Vec<String>, ParseMetadataError> {
    if !response.has_json_compatible_media_type() {
        return Err(ParseMetadataError::Unsupported);
    }
    parse_rest_namespaces_body(response.body())
}

fn parse_rest_namespaces_body(body: &[u8]) -> Result<Vec<String>, ParseMetadataError> {
    validate_rest_json_shape(body)?;
    let wire: RestIndexWire =
        serde_json::from_slice(body).map_err(|_| ParseMetadataError::Malformed)?;
    if wire.namespaces.len() > MAX_REST_NAMESPACES
        || wire.namespaces.iter().any(|namespace| {
            namespace.is_empty()
                || namespace.len() > MAX_REST_NAMESPACE_BYTES
                || !namespace.is_ascii()
                || namespace.chars().any(char::is_control)
        })
    {
        return Err(ParseMetadataError::Malformed);
    }
    let mut namespaces = wire.namespaces;
    namespaces.sort();
    namespaces.dedup();
    Ok(namespaces)
}

#[cfg(fuzzing)]
pub(super) fn fuzz_check_wordpress_discovery_parser(scenario: u8, data: &[u8]) {
    match scenario % 8 {
        0 | 1 => {},
        2 => {
            let first = parse_rest_namespaces_body(data);
            let repeated = parse_rest_namespaces_body(data);
            assert_eq!(
                first, repeated,
                "REST metadata parsing must be deterministic"
            );
            if let Ok(namespaces) = first {
                assert!(namespaces.len() <= MAX_REST_NAMESPACES);
                assert!(namespaces.windows(2).all(|pair| pair[0] < pair[1]));
                assert!(namespaces.iter().all(|namespace| {
                    !namespace.is_empty()
                        && namespace.len() <= MAX_REST_NAMESPACE_BYTES
                        && namespace.is_ascii()
                        && !namespace.chars().any(char::is_control)
                }));
            }
        },
        3 => fuzz_check_theme_metadata(data),
        4 => fuzz_check_plugin_metadata(data),
        5 => {
            let mut clipped = b"/*\nTheme Name: Fuzz Theme\nVersion: 1.2.3\n".to_vec();
            clipped.resize(MAX_METADATA_HEADER_BYTES + 1, b'x');
            assert_eq!(
                parse_theme_metadata(&clipped),
                Err(ParseMetadataError::Truncated)
            );
        },
        6 => {
            let mut clipped = b"=== Fuzz Plugin ===\nStable tag: 1.2.3\n".to_vec();
            clipped.resize(MAX_METADATA_HEADER_BYTES + 1, b'x');
            assert_eq!(
                parse_plugin_metadata(&clipped),
                Err(ParseMetadataError::Truncated)
            );
        },
        _ => {
            let prefix = b"=== Fuzz Plugin ===\nStable tag: 1.2.3\n\n";
            let mut clipped = prefix.to_vec();
            clipped.resize(MAX_METADATA_HEADER_BYTES - 1, b'x');
            clipped.extend_from_slice("é".as_bytes());
            let metadata = parse_plugin_metadata(&clipped)
                .expect("complete header before clipped UTF-8 must parse")
                .expect("fixed plugin header must retain metadata");
            assert_eq!(metadata.name(), Some("Fuzz Plugin"));
            assert_eq!(metadata.stable_tag(), Some("1.2.3"));
        },
    }
}

#[cfg(fuzzing)]
fn fuzz_check_theme_metadata(data: &[u8]) {
    let first = parse_theme_metadata(data);
    let repeated = parse_theme_metadata(data);
    assert_eq!(
        first, repeated,
        "theme metadata parsing must be deterministic"
    );
    if let Ok(Some(metadata)) = first {
        for value in [
            metadata.name(),
            metadata.template(),
            metadata.requires_wordpress(),
            metadata.requires_php(),
            metadata.tested_up_to(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(value.len() <= MAX_METADATA_VALUE_BYTES);
            assert!(!value.chars().any(char::is_control));
        }
        assert!(metadata
            .version()
            .is_none_or(|version| version.len() <= MAX_DISCOVERED_VERSION_BYTES));
    }
}

#[cfg(fuzzing)]
fn fuzz_check_plugin_metadata(data: &[u8]) {
    let first = parse_plugin_metadata(data);
    let repeated = parse_plugin_metadata(data);
    assert_eq!(
        first, repeated,
        "plugin metadata parsing must be deterministic"
    );
    if let Ok(Some(metadata)) = first {
        for value in [
            metadata.name(),
            metadata.stable_tag(),
            metadata.requires_wordpress(),
            metadata.requires_php(),
            metadata.tested_up_to(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(value.len() <= MAX_METADATA_VALUE_BYTES);
            assert!(!value.chars().any(char::is_control));
        }
    }
}

fn validate_rest_json_shape(bytes: &[u8]) -> Result<(), ParseMetadataError> {
    let mut nodes = 0_usize;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    RestJsonSeed {
        depth: 0,
        nodes: &mut nodes,
    }
    .deserialize(&mut decoder)
    .map_err(|error| {
        if error.to_string().contains("wordpress-rest-json-limit") {
            ParseMetadataError::Unsupported
        } else {
            ParseMetadataError::Malformed
        }
    })?;
    decoder.end().map_err(|_| ParseMetadataError::Malformed)
}

struct RestJsonSeed<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for RestJsonSeed<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        if self.depth > MAX_REST_JSON_DEPTH || *self.nodes == MAX_REST_JSON_NODES {
            return Err(de::Error::custom("wordpress-rest-json-limit"));
        }
        *self.nodes += 1;
        decoder.deserialize_any(RestJsonVisitor {
            depth: self.depth,
            nodes: self.nodes,
        })
    }
}

struct RestJsonVisitor<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> Visitor<'de> for RestJsonVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded WordPress REST JSON without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<(), E> {
        validate_rest_json_string::<E>(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        validate_rest_json_string::<E>(value)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<(), E> {
        validate_rest_json_string::<E>(&value)
    }

    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        RestJsonSeed {
            depth: self.depth + 1,
            nodes: self.nodes,
        }
        .deserialize(decoder)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        let mut length = 0_usize;
        loop {
            if length == MAX_REST_JSON_COLLECTION_LENGTH {
                if values
                    .next_element_seed(RestJsonSeed {
                        depth: self.depth + 1,
                        nodes: &mut *self.nodes,
                    })?
                    .is_some()
                {
                    return Err(de::Error::custom("wordpress-rest-json-limit"));
                }
                break;
            }
            let Some(()) = values.next_element_seed(RestJsonSeed {
                depth: self.depth + 1,
                nodes: &mut *self.nodes,
            })?
            else {
                break;
            };
            length += 1;
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        loop {
            if keys.len() == MAX_REST_JSON_COLLECTION_LENGTH {
                if let Some(key) = fields.next_key_seed(RestJsonKeySeed)? {
                    if keys.contains(&key) {
                        return Err(de::Error::custom("wordpress-rest-duplicate-key"));
                    }
                    return Err(de::Error::custom("wordpress-rest-json-limit"));
                }
                break;
            }
            let Some(key) = fields.next_key_seed(RestJsonKeySeed)? else {
                break;
            };
            if !keys.insert(key) {
                return Err(de::Error::custom("wordpress-rest-duplicate-key"));
            }
            fields.next_value_seed(RestJsonSeed {
                depth: self.depth + 1,
                nodes: &mut *self.nodes,
            })?;
        }
        Ok(())
    }
}

fn validate_rest_json_string<E: de::Error>(value: &str) -> Result<(), E> {
    if value.len() > MAX_REST_JSON_STRING_BYTES {
        Err(de::Error::custom("wordpress-rest-json-limit"))
    } else {
        Ok(())
    }
}

struct RestJsonKeySeed;

impl<'de> DeserializeSeed<'de> for RestJsonKeySeed {
    type Value = String;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_string(RestJsonKeyVisitor)
    }
}

struct RestJsonKeyVisitor;

impl<'de> Visitor<'de> for RestJsonKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded WordPress REST JSON object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        validate_rest_json_key(value)?;
        Ok(value.to_owned())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        validate_rest_json_key(value)?;
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        validate_rest_json_key(&value)?;
        Ok(value)
    }
}

fn validate_rest_json_key<E: de::Error>(value: &str) -> Result<(), E> {
    if value.len() > MAX_REST_JSON_KEY_BYTES {
        Err(de::Error::custom("wordpress-rest-json-limit"))
    } else {
        Ok(())
    }
}

fn parse_theme_metadata(
    body: &[u8],
) -> Result<Option<WordPressThemeDiscoveryMetadata>, ParseMetadataError> {
    let header = bounded_utf8_prefix(body)?;
    let text = header.text.trim_start_matches('\u{feff}').trim_start();
    let Some(text) = text.strip_prefix("/*") else {
        return Ok(None);
    };
    let Some(end) = text.find("*/") else {
        return Err(if header.clipped {
            ParseMetadataError::Truncated
        } else {
            ParseMetadataError::Malformed
        });
    };
    let fields = parse_header_fields(&text[..end])?;
    let Some(name) = field(&fields, "theme name") else {
        return Ok(None);
    };
    let metadata = WordPressThemeDiscoveryMetadata {
        name: Some(name),
        version: field(&fields, "version"),
        template: field(&fields, "template"),
        requires_wordpress: field(&fields, "requires at least"),
        requires_php: field(&fields, "requires php"),
        tested_up_to: field(&fields, "tested up to"),
    };
    Ok(Some(metadata))
}

fn parse_plugin_metadata(
    body: &[u8],
) -> Result<Option<WordPressPluginDiscoveryMetadata>, ParseMetadataError> {
    let header = bounded_utf8_prefix(body)?;
    let mut lines = header.text.split_inclusive('\n');
    let Some(title_line) = lines.next() else {
        return Ok(None);
    };
    if header.clipped && !title_line.ends_with('\n') {
        return Err(ParseMetadataError::Truncated);
    }
    let title = title_line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .trim();
    let name = title
        .strip_prefix("===")
        .and_then(|value| value.strip_suffix("==="))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let Some(name) = name else {
        return Ok(None);
    };
    if name.len() > MAX_METADATA_VALUE_BYTES || name.chars().any(char::is_control) {
        return Err(ParseMetadataError::Malformed);
    }
    let mut header_lines = String::new();
    let mut terminated = false;
    for raw_line in lines {
        let complete_line = raw_line.ends_with('\n') || !header.clipped;
        let line = raw_line.trim_end_matches('\n').trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with("==") {
            terminated = true;
            break;
        }
        if !complete_line {
            return Err(ParseMetadataError::Truncated);
        }
        header_lines.push_str(line);
        header_lines.push('\n');
    }
    if header.clipped && !terminated {
        return Err(ParseMetadataError::Truncated);
    }
    let fields = parse_header_fields(&header_lines)?;
    let stable_tag =
        field(&fields, "stable tag").filter(|value| !value.eq_ignore_ascii_case("trunk"));
    Ok(Some(WordPressPluginDiscoveryMetadata {
        name: Some(name),
        stable_tag,
        requires_wordpress: field(&fields, "requires at least"),
        requires_php: field(&fields, "requires php"),
        tested_up_to: field(&fields, "tested up to"),
    }))
}

struct BoundedUtf8Prefix<'a> {
    text: &'a str,
    clipped: bool,
}

fn bounded_utf8_prefix(body: &[u8]) -> Result<BoundedUtf8Prefix<'_>, ParseMetadataError> {
    let end = body.len().min(MAX_METADATA_HEADER_BYTES);
    let clipped = body.len() > end;
    match std::str::from_utf8(&body[..end]) {
        Ok(text) => Ok(BoundedUtf8Prefix { text, clipped }),
        Err(error) if clipped && error.error_len().is_none() => {
            let text = std::str::from_utf8(&body[..error.valid_up_to()])
                .map_err(|_| ParseMetadataError::Malformed)?;
            Ok(BoundedUtf8Prefix { text, clipped })
        },
        Err(_) => Err(ParseMetadataError::Malformed),
    }
}

fn parse_header_fields(
    input: &str,
) -> Result<std::collections::BTreeMap<String, String>, ParseMetadataError> {
    let mut fields = std::collections::BTreeMap::new();
    for raw_line in input.lines() {
        let line = raw_line
            .trim_end_matches('\r')
            .trim_start_matches(|character: char| {
                character.is_ascii_whitespace() || character == '*'
            })
            .trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "theme name"
                | "version"
                | "template"
                | "requires at least"
                | "requires php"
                | "tested up to"
                | "stable tag"
        ) {
            continue;
        }
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_METADATA_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ParseMetadataError::Malformed);
        }
        if name == "version" && value.len() > MAX_DISCOVERED_VERSION_BYTES {
            return Err(ParseMetadataError::Unsupported);
        }
        if fields.insert(name, value.to_owned()).is_some() {
            return Err(ParseMetadataError::Malformed);
        }
    }
    Ok(fields)
}

fn field(fields: &std::collections::BTreeMap<String, String>, name: &str) -> Option<String> {
    fields.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_failed_source(
        kind: WordPressDiscoverySourceKind,
        ordinal: usize,
    ) -> WordPressDiscoverySourceAudit {
        let application = Url::parse("https://example.test/").unwrap();
        let seed = match kind {
            WordPressDiscoverySourceKind::RestIndex => WordPressDiscoverySeed::admitted_rest_index(
                if ordinal == 0 {
                    Url::parse("https://example.test/wp-json/").unwrap()
                } else {
                    Url::parse("https://example.test/?rest_route=/").unwrap()
                },
                application.clone(),
                application,
                WordPressDiscoveryAssociation::StructuredAdvertisement,
            ),
            WordPressDiscoverySourceKind::ThemeStylesheet => {
                let role = Url::parse("https://example.test/wp-content/themes/").unwrap();
                let component = WordPressComponentIdentity::new(
                    WordPressComponentKind::Theme,
                    format!("quota-theme-{ordinal}"),
                )
                .unwrap();
                WordPressDiscoverySeed::admitted_component(
                    role.join(&format!("{}/style.css", component.slug()))
                        .unwrap(),
                    application,
                    role,
                    WordPressDiscoveryAssociation::ObservedConventional,
                    component,
                    0,
                )
            },
            WordPressDiscoverySourceKind::PluginReadme => {
                let role = Url::parse("https://example.test/wp-content/plugins/").unwrap();
                let component = WordPressComponentIdentity::new(
                    WordPressComponentKind::Plugin,
                    format!("quota-plugin-{ordinal}"),
                )
                .unwrap();
                WordPressDiscoverySeed::admitted_component(
                    role.join(&format!("{}/readme.txt", component.slug()))
                        .unwrap(),
                    application,
                    role,
                    WordPressDiscoveryAssociation::ObservedConventional,
                    component,
                    0,
                )
            },
        };
        empty_source(
            &seed,
            WordPressDiscoverySourceOutcome::RequestFailed,
            true,
            0,
        )
    }

    fn request_failed_audit(
        rest: usize,
        themes: usize,
        plugins: usize,
    ) -> WebAssessmentWordPressDiscoveryAudit {
        let sources = (0..rest)
            .map(|ordinal| request_failed_source(WordPressDiscoverySourceKind::RestIndex, ordinal))
            .chain((0..themes).map(|ordinal| {
                request_failed_source(WordPressDiscoverySourceKind::ThemeStylesheet, ordinal)
            }))
            .chain((0..plugins).map(|ordinal| {
                request_failed_source(WordPressDiscoverySourceKind::PluginReadme, ordinal)
            }))
            .collect::<Vec<_>>();
        let attempted_request_count = u8::try_from(sources.len()).unwrap();
        let application = Url::parse("https://example.test/").unwrap();
        let mut layout = WordPressDiscoveryLayoutAudit::unresolved(&application, None);
        for (role, count, base) in [
            (WordPressDiscoveryLayoutRole::RestIndex, rest, application),
            (
                WordPressDiscoveryLayoutRole::Themes,
                themes,
                Url::parse("https://example.test/wp-content/themes/").unwrap(),
            ),
            (
                WordPressDiscoveryLayoutRole::Plugins,
                plugins,
                Url::parse("https://example.test/wp-content/plugins/").unwrap(),
            ),
        ] {
            if count > 0 {
                let entry = layout.role_mut(role);
                entry.status = WordPressDiscoveryLayoutStatus::Exact;
                entry.basis = if role == WordPressDiscoveryLayoutRole::RestIndex {
                    WordPressDiscoveryLayoutBasis::StructuredAdvertisement
                } else {
                    WordPressDiscoveryLayoutBasis::ConventionalAsset
                };
                entry.reference = Some(opaque_url_reference("wordpress-discovery-role", &base));
                entry.candidate_count = 1;
            }
        }
        WebAssessmentWordPressDiscoveryAudit {
            seed_count: attempted_request_count,
            candidate_count: attempted_request_count,
            candidate_limit_reached: false,
            omitted_candidate_count: 0,
            attempted_request_count,
            completed_response_count: 0,
            committed_response_count: 0,
            response_bytes: 0,
            sources,
            layout,
        }
    }

    #[test]
    fn discovery_audit_enforces_each_request_class_ceiling() {
        assert!(request_failed_audit(1, 3, 8).is_internally_consistent());
        assert!(!attempted_request_classes_within_limits(
            &request_failed_audit(2, 2, 8).sources
        ));
        assert!(!request_failed_audit(0, 4, 8).is_internally_consistent());
        assert!(!request_failed_audit(0, 3, 9).is_internally_consistent());
    }

    #[test]
    fn theme_header_requires_theme_name_and_retains_bounded_fields() {
        assert!(parse_theme_metadata(b"/* Version: 9.9.9 */")
            .unwrap()
            .is_none());

        let metadata = parse_theme_metadata(
            b"/*\nTheme Name: Child Theme\nVersion: 1.2.3\nTemplate: parent-theme\nRequires at least: 6.5\nRequires PHP: 8.1\nTested up to: 6.9\n*/",
        )
        .unwrap()
        .unwrap();
        assert_eq!(metadata.name(), Some("Child Theme"));
        assert_eq!(metadata.version(), Some("1.2.3"));
        assert_eq!(metadata.template(), Some("parent-theme"));
        assert_eq!(metadata.requires_wordpress(), Some("6.5"));
        assert_eq!(metadata.requires_php(), Some("8.1"));
        assert_eq!(metadata.tested_up_to(), Some("6.9"));
    }

    #[test]
    fn plugin_stable_tag_is_metadata_not_a_component_version_signal() {
        let metadata = parse_plugin_metadata(
            b"=== Cache Tool ===\nStable tag: 4.5.6\nRequires at least: 6.4\nRequires PHP: 8.0\nTested up to: 6.9\n\nDescription",
        )
        .unwrap()
        .unwrap();
        assert_eq!(metadata.name(), Some("Cache Tool"));
        assert_eq!(metadata.stable_tag(), Some("4.5.6"));
        assert_eq!(metadata.requires_wordpress(), Some("6.4"));
        assert_eq!(metadata.requires_php(), Some("8.0"));
        assert_eq!(metadata.tested_up_to(), Some("6.9"));
    }

    #[test]
    fn duplicate_or_oversized_metadata_fields_fail_closed() {
        assert!(parse_theme_metadata(b"/* Theme Name: A\nTheme Name: B */").is_err());
        let oversized = format!("=== Plugin ===\nStable tag: {}", "a".repeat(257));
        assert!(parse_plugin_metadata(oversized.as_bytes()).is_err());
        let unsupported_version = format!(
            "/* Theme Name: Bounded\nVersion: {} */",
            "7".repeat(MAX_DISCOVERED_VERSION_BYTES + 1)
        );
        assert_eq!(
            parse_theme_metadata(unsupported_version.as_bytes()),
            Err(ParseMetadataError::Unsupported)
        );
    }

    #[test]
    fn clipped_metadata_requires_a_complete_header_boundary() {
        let mut theme = b"/*\nTheme Name: Bounded\nVersion: 1.2.3\n".to_vec();
        theme.resize(MAX_METADATA_HEADER_BYTES + 1, b'x');
        assert_eq!(
            parse_theme_metadata(&theme),
            Err(ParseMetadataError::Truncated)
        );

        let mut plugin = b"=== Bounded ===\nStable tag: ".to_vec();
        plugin.resize(MAX_METADATA_HEADER_BYTES + 1, b'7');
        assert_eq!(
            parse_plugin_metadata(&plugin),
            Err(ParseMetadataError::Truncated)
        );
    }

    #[test]
    fn clipped_utf8_after_a_complete_plugin_header_does_not_change_metadata() {
        let mut plugin = b"=== Bounded ===\nStable tag: 1.2.3\n\n".to_vec();
        plugin.resize(MAX_METADATA_HEADER_BYTES - 1, b'x');
        plugin.extend_from_slice("é".as_bytes());
        let metadata = parse_plugin_metadata(&plugin).unwrap().unwrap();
        assert_eq!(metadata.stable_tag(), Some("1.2.3"));
    }

    #[test]
    fn rest_json_rejects_duplicate_unknown_keys_at_every_object_depth() {
        assert_eq!(
            validate_rest_json_shape(br#"{"unknown":{"ordinary":true},"namespaces":[]}"#),
            Ok(())
        );
        for input in [
            br#"{"x":1,"x":2,"namespaces":[]}"#.as_slice(),
            br#"{"unknown":{"x":1,"x":2},"namespaces":[]}"#.as_slice(),
            br#"{"x":1,"\u0078":2,"namespaces":[]}"#.as_slice(),
        ] {
            assert_eq!(
                validate_rest_json_shape(input),
                Err(ParseMetadataError::Malformed)
            );
        }
    }

    #[test]
    fn rest_json_bounds_every_decoded_key_and_string() {
        let boundary_value = "v".repeat(MAX_REST_JSON_STRING_BYTES);
        let boundary_key = "k".repeat(MAX_REST_JSON_KEY_BYTES);
        assert_eq!(
            validate_rest_json_shape(
                format!(r#"{{"{boundary_key}":"{boundary_value}"}}"#).as_bytes()
            ),
            Ok(())
        );

        let oversized_value = "v".repeat(MAX_REST_JSON_STRING_BYTES + 1);
        let oversized_key = "k".repeat(MAX_REST_JSON_KEY_BYTES + 1);
        for input in [
            format!(r#"{{"value":"{oversized_value}"}}"#),
            format!(r#"{{"{oversized_key}":null}}"#),
            format!(
                r#"{{"{}":null}}"#,
                "\\u006b".repeat(MAX_REST_JSON_KEY_BYTES + 1)
            ),
            format!(
                r#"{{"value":"{}"}}"#,
                "\\u0076".repeat(MAX_REST_JSON_STRING_BYTES + 1)
            ),
        ] {
            assert_eq!(
                validate_rest_json_shape(input.as_bytes()),
                Err(ParseMetadataError::Unsupported)
            );
        }
    }

    #[test]
    fn rest_json_collection_limit_probes_remain_strictly_decoded() {
        let array_boundary = std::iter::repeat_n("null", MAX_REST_JSON_COLLECTION_LENGTH)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            validate_rest_json_shape(format!("[{array_boundary}]").as_bytes()),
            Ok(())
        );
        assert_eq!(
            validate_rest_json_shape(format!("[{array_boundary},null]").as_bytes()),
            Err(ParseMetadataError::Unsupported)
        );
        assert_eq!(
            validate_rest_json_shape(
                format!(r#"[{array_boundary},{{"duplicate":1,"duplicate":2}}]"#).as_bytes()
            ),
            Err(ParseMetadataError::Malformed),
            "the first over-limit element must still pass through the duplicate-key validator"
        );

        let map_boundary = (0..MAX_REST_JSON_COLLECTION_LENGTH)
            .map(|index| format!(r#""key-{index}":null"#))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            validate_rest_json_shape(format!("{{{map_boundary}}}").as_bytes()),
            Ok(())
        );
        assert_eq!(
            validate_rest_json_shape(format!(r#"{{{map_boundary},"extra":null}}"#).as_bytes()),
            Err(ParseMetadataError::Unsupported)
        );
        assert_eq!(
            validate_rest_json_shape(format!(r#"{{{map_boundary},"\u006bey-0":null}}"#).as_bytes()),
            Err(ParseMetadataError::Malformed),
            "the first over-limit key must still pass through bounded duplicate detection"
        );
    }

    #[test]
    fn rest_json_depth_boundary_is_preserved() {
        let nested = |depth: usize| {
            let mut value = "null".to_owned();
            for _ in 0..depth {
                value = format!("[{value}]");
            }
            value
        };
        assert_eq!(
            validate_rest_json_shape(nested(MAX_REST_JSON_DEPTH).as_bytes()),
            Ok(())
        );
        assert_eq!(
            validate_rest_json_shape(nested(MAX_REST_JSON_DEPTH + 1).as_bytes()),
            Err(ParseMetadataError::Unsupported)
        );
    }
}
