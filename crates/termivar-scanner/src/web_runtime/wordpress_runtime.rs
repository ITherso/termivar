//! WordPress interpretation bound to the existing root-response observation.
//!
//! This module owns no transport. It retains only bounded typed signals and
//! existing evidence references, then evaluates them with already-validated
//! local inputs at the assessment's normal projection boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use html5ever::{ns, parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{NodeData, RcDom};
use termivar_core::{EntityId, EvidenceId};
use url::Url;

use crate::{
    http_evidence::WordPressRestIndexAdvertisement,
    wordpress_review::{
        evaluate_wordpress_review, WordPressComponentKind, WordPressComponentSignal,
        WordPressDiscoveryLayout, WordPressReviewError, WordPressReviewInputs,
        WordPressReviewResult, MAX_WORDPRESS_SIGNALS,
    },
    KnowledgeBase,
};

use super::assessment_item::{
    AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
    AssessmentProjectionContext,
};

pub(super) use super::wordpress_discovery::WordPressDiscoveryStop;
use super::wordpress_discovery::{
    discovery_seed_fingerprint, execute_wordpress_discovery, WordPressDiscoveryAssociation,
    WordPressDiscoveryExecutionError, WordPressDiscoveryExecutionInput,
    WordPressDiscoveryLayoutAudit, WordPressDiscoveryLayoutBasis, WordPressDiscoveryLayoutRole,
    WordPressDiscoveryLayoutStatus, WordPressDiscoverySeed, MAX_WORDPRESS_DISCOVERY_CANDIDATES,
    MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES, MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS,
    MAX_WORDPRESS_DISCOVERY_REST_REQUESTS, MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS,
};
pub use super::wordpress_discovery::{
    WebAssessmentWordPressDiscoveryAudit, WordPressDiscoverySourceAudit,
    WordPressDiscoverySourceKind, WordPressDiscoverySourceOutcome,
    WordPressPluginDiscoveryMetadata, WordPressThemeDiscoveryMetadata,
};

/// Observation-only product item emitted when the root response carried at
/// least one supported structured WordPress hint.
pub const WORDPRESS_REVIEW_CAPABILITY_ID: &str = "technology.wordpress-surface-observed@1";
/// Observation-only item that retains document-local references for fetched
/// metadata without changing the root-surface item's meaning.
pub const WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID: &str =
    "technology.wordpress-metadata-source-response-observed@1";

static WORDPRESS_REVIEW_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        WORDPRESS_REVIEW_CAPABILITY_ID,
        "WordPress surface hints observed",
        "wordpress-surface",
        "The root response contained bounded structured WordPress hints; installation authenticity and advisory impact were not established.",
        600_000,
        "wordpress-inventory-review",
        "Confirm the component inventory and consult an appropriate authoritative advisory source before making a security decision.",
    );

static WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID,
        "WordPress metadata-source response outcome observed",
        "wordpress-metadata-source-response",
        "Bounded response evidence from selected public WordPress metadata sources was collected; usable metadata, installation authenticity, vulnerable-code reachability, and advisory impact were not established.",
        550_000,
        "wordpress-metadata-review",
        "Confirm the installation inventory and source-qualified metadata before making a security or remediation decision.",
    );

#[derive(Default)]
struct CollectedSignals {
    signals: Vec<WordPressComponentSignal>,
    discovery_seeds: Vec<WordPressDiscoverySeed>,
    discovery_candidate_fingerprints: BTreeSet<[u8; 32]>,
    evidence_ids: BTreeSet<EvidenceId>,
    discovery_seed_evidence_ids: BTreeSet<EvidenceId>,
    signal_limit_exceeded: bool,
    discovery_candidate_identity_limit_exceeded: bool,
    discovery_layout: Option<WordPressDiscoveryLayoutAudit>,
}

type WordPressDiscoverySnapshot = (
    Vec<WordPressDiscoverySeed>,
    Vec<EvidenceId>,
    u64,
    BTreeSet<[u8; 32]>,
    Option<WordPressDiscoveryLayoutAudit>,
);

#[derive(Default)]
pub(super) struct WordPressDiscoverySeedSelection {
    seeds: Vec<WordPressDiscoverySeed>,
    seen_candidate_fingerprints: BTreeSet<[u8; 32]>,
    candidate_identity_limit_exceeded: bool,
    omitted_candidate_count: u64,
    layout: Option<WordPressDiscoveryLayoutAudit>,
}

#[derive(Clone)]
pub(super) struct WordPressDiscoveryContext {
    application_url: Url,
    declared_layout: Option<WordPressDiscoveryLayout>,
}

impl WordPressDiscoveryContext {
    fn new(application_url: Url, declared_layout: Option<WordPressDiscoveryLayout>) -> Self {
        Self {
            application_url,
            declared_layout,
        }
    }

    pub(super) fn application_url(&self) -> &Url {
        &self.application_url
    }

    fn declared_layout(&self) -> Option<&WordPressDiscoveryLayout> {
        self.declared_layout.as_ref()
    }

    fn unresolved_audit(&self) -> WordPressDiscoveryLayoutAudit {
        WordPressDiscoveryLayoutAudit::unresolved(
            &self.application_url,
            self.declared_layout.as_ref(),
        )
    }
}

pub(super) struct WordPressEntryObservation {
    pub(super) signals: Vec<WordPressComponentSignal>,
    pub(super) discovery: WordPressDiscoverySeedSelection,
}

impl WordPressDiscoverySeedSelection {
    fn insert(&mut self, seed: WordPressDiscoverySeed) {
        let fingerprint = discovery_seed_fingerprint(&seed);
        if self.seen_candidate_fingerprints.contains(&fingerprint) {
            return;
        }
        if self.seen_candidate_fingerprints.len() == MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES {
            self.candidate_identity_limit_exceeded = true;
            return;
        }
        self.seen_candidate_fingerprints.insert(fingerprint);
        if insert_bounded_discovery_seed(&mut self.seeds, seed, &mut self.omitted_candidate_count)
            .is_err()
        {
            self.candidate_identity_limit_exceeded = true;
        }
    }

    #[cfg(test)]
    fn seeds(&self) -> &[WordPressDiscoverySeed] {
        &self.seeds
    }
}

/// One assessment-owned sink shared only with its root discovery observer.
#[derive(Clone, Default)]
pub(super) struct WordPressSignalCollector(Arc<Mutex<CollectedSignals>>);

impl WordPressSignalCollector {
    pub(super) fn record(
        &self,
        signals: impl IntoIterator<Item = WordPressComponentSignal>,
        mut discovery: WordPressDiscoverySeedSelection,
        evidence_ids: impl IntoIterator<Item = EvidenceId>,
    ) {
        let evidence_ids = evidence_ids.into_iter().collect::<Vec<_>>();
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.discovery_candidate_identity_limit_exceeded |=
            discovery.candidate_identity_limit_exceeded;
        if let Some(layout) = discovery.layout.take() {
            if state
                .discovery_layout
                .as_ref()
                .is_some_and(|existing| existing != &layout)
            {
                state.discovery_candidate_identity_limit_exceeded = true;
            } else {
                state.discovery_layout = Some(layout);
            }
        }
        let mut retained_signal = false;
        for signal in signals {
            if state.signals.contains(&signal) {
                retained_signal = true;
                continue;
            }
            if state.signals.len() == MAX_WORDPRESS_SIGNALS {
                state.signal_limit_exceeded = true;
                break;
            }
            state.signals.push(signal);
            retained_signal = true;
        }
        if let (Some(existing), Some(incoming)) = (
            state
                .discovery_seeds
                .iter()
                .find(|seed| seed.kind() == WordPressDiscoverySourceKind::RestIndex)
                .cloned(),
            discovery
                .seeds
                .iter()
                .find(|seed| seed.kind() == WordPressDiscoverySourceKind::RestIndex)
                .cloned(),
        ) {
            let conflicts = existing.preflight_outcome()
                == Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement)
                || incoming.preflight_outcome()
                    == Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement)
                || !same_discovery_seed(&existing, &incoming);
            if conflicts {
                state
                    .discovery_candidate_fingerprints
                    .remove(&discovery_seed_fingerprint(&existing));
                discovery
                    .seen_candidate_fingerprints
                    .remove(&discovery_seed_fingerprint(&incoming));
                state
                    .discovery_seeds
                    .retain(|seed| seed.kind() != WordPressDiscoverySourceKind::RestIndex);
                discovery
                    .seeds
                    .retain(|seed| seed.kind() != WordPressDiscoverySourceKind::RestIndex);
                let invalid = WordPressDiscoverySeed::invalid_rest_index(existing.url().clone());
                let invalid_fingerprint = discovery_seed_fingerprint(&invalid);
                if state.discovery_candidate_fingerprints.len()
                    == MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
                    && !state
                        .discovery_candidate_fingerprints
                        .contains(&invalid_fingerprint)
                {
                    state.discovery_candidate_identity_limit_exceeded = true;
                } else {
                    state
                        .discovery_candidate_fingerprints
                        .insert(invalid_fingerprint);
                    state.discovery_seeds.push(invalid);
                }
            }
        }
        for fingerprint in discovery.seen_candidate_fingerprints {
            if state
                .discovery_candidate_fingerprints
                .contains(&fingerprint)
            {
                continue;
            }
            if state.discovery_candidate_fingerprints.len()
                == MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
            {
                state.discovery_candidate_identity_limit_exceeded = true;
                break;
            }
            state.discovery_candidate_fingerprints.insert(fingerprint);
        }
        let mut retained_discovery_seed = false;
        for seed in discovery.seeds {
            let discovery_seeds = &mut state.discovery_seeds;
            let mut ignored_local_omissions = 0;
            match insert_bounded_discovery_seed(discovery_seeds, seed, &mut ignored_local_omissions)
            {
                Ok(true) => retained_discovery_seed = true,
                Ok(false) => {},
                Err(()) => {
                    state.signal_limit_exceeded = true;
                    break;
                },
            }
        }
        if !state.discovery_seeds.is_empty() {
            retained_discovery_seed = true;
        }
        if retained_signal {
            state.evidence_ids.extend(evidence_ids.iter().cloned());
        }
        if retained_discovery_seed {
            state.discovery_seed_evidence_ids.extend(evidence_ids);
        }
    }

    fn snapshot(
        &self,
    ) -> Result<(Vec<WordPressComponentSignal>, Vec<EvidenceId>), WordPressReviewError> {
        let state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.signal_limit_exceeded {
            return Err(WordPressReviewError::SignalLimitExceeded);
        }
        let mut signals = state.signals.clone();
        signals.sort_by(|left, right| {
            left.identity()
                .cmp(right.identity())
                .then_with(|| left.source().cmp(&right.source()))
                .then_with(|| left.version().cmp(&right.version()))
        });
        Ok((signals, state.evidence_ids.iter().cloned().collect()))
    }

    fn discovery_snapshot(&self) -> Result<WordPressDiscoverySnapshot, WordPressReviewError> {
        let state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.signal_limit_exceeded {
            return Err(WordPressReviewError::SignalLimitExceeded);
        }
        if state.discovery_candidate_identity_limit_exceeded {
            return Err(WordPressReviewError::DiscoveryCandidateIdentityLimitExceeded);
        }
        let mut seeds = state.discovery_seeds.clone();
        seeds.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        let omitted_candidate_count = u64::try_from(
            state
                .discovery_candidate_fingerprints
                .len()
                .saturating_sub(seeds.len()),
        )
        .map_err(|_| WordPressReviewError::DiscoveryCandidateIdentityLimitExceeded)?;
        Ok((
            seeds,
            state.discovery_seed_evidence_ids.iter().cloned().collect(),
            omitted_candidate_count,
            state.discovery_candidate_fingerprints.clone(),
            state.discovery_layout.clone(),
        ))
    }

    fn record_discovery(&self, signals: impl IntoIterator<Item = WordPressComponentSignal>) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for signal in signals {
            if state.signals.contains(&signal) {
                continue;
            }
            if state.signals.len() == MAX_WORDPRESS_SIGNALS {
                state.signal_limit_exceeded = true;
                break;
            }
            state.signals.push(signal);
        }
    }
}

pub(super) struct WordPressReviewBinding {
    inputs: WordPressReviewInputs,
    collector: WordPressSignalCollector,
    discovery_enabled: bool,
    discovery_audit: Option<WebAssessmentWordPressDiscoveryAudit>,
    discovery_context: WordPressDiscoveryContext,
}

#[derive(Debug)]
pub(super) enum WordPressReviewFinishError {
    DiscoveryNotExecuted,
    Review,
}

impl WordPressReviewBinding {
    pub(super) fn new(
        inputs: WordPressReviewInputs,
        discovery_enabled: bool,
        application_url: Url,
    ) -> Self {
        let discovery_context =
            WordPressDiscoveryContext::new(application_url, inputs.discovery_layout().cloned());
        Self {
            inputs,
            collector: WordPressSignalCollector::default(),
            discovery_enabled,
            discovery_audit: None,
            discovery_context,
        }
    }

    pub(super) fn collector(&self) -> WordPressSignalCollector {
        self.collector.clone()
    }

    pub(super) const fn discovery_enabled(&self) -> bool {
        self.discovery_enabled
    }

    pub(super) fn discovery_context(&self) -> WordPressDiscoveryContext {
        self.discovery_context.clone()
    }

    pub(super) async fn execute_discovery(
        &mut self,
        subject: EntityId,
        authority: &super::SharedWebRuntimeAuthority,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<WordPressDiscoveryStop, WordPressDiscoveryExecutionError> {
        if !self.discovery_enabled {
            return Ok(WordPressDiscoveryStop::Complete);
        }
        let (seeds, root_evidence_ids, omitted_candidate_count, candidate_fingerprints, layout) =
            self.collector
                .discovery_snapshot()
                .map_err(|error| match error {
                    WordPressReviewError::DiscoveryCandidateIdentityLimitExceeded => {
                        WordPressDiscoveryExecutionError::CandidateIdentityLimitExceeded
                    },
                    _ => WordPressDiscoveryExecutionError::EvidenceModel,
                })?;
        let execution = execute_wordpress_discovery(
            WordPressDiscoveryExecutionInput::new(
                seeds,
                omitted_candidate_count,
                candidate_fingerprints,
                root_evidence_ids,
                subject,
                layout.unwrap_or_else(|| self.discovery_context.unresolved_audit()),
            ),
            authority,
            deadline,
        )
        .await?;
        self.collector.record_discovery(execution.signals);
        let stop = execution.stop;
        self.discovery_audit = Some(execution.audit);
        Ok(stop)
    }

    pub(super) fn finish(
        self,
        subject: EntityId,
    ) -> Result<CommittedWordPressReview, WordPressReviewFinishError> {
        if self.discovery_enabled && self.discovery_audit.is_none() {
            return Err(WordPressReviewFinishError::DiscoveryNotExecuted);
        }
        let (signals, evidence_ids) = self
            .collector
            .snapshot()
            .map_err(|_| WordPressReviewFinishError::Review)?;
        let result = evaluate_wordpress_review(&signals, &self.inputs)
            .map_err(|_| WordPressReviewFinishError::Review)?;
        let audit = WebAssessmentWordPressAudit {
            result,
            signal_count: u16::try_from(signals.len())
                .map_err(|_| WordPressReviewFinishError::Review)?,
            evidence_reference_count: u16::try_from(evidence_ids.len())
                .map_err(|_| WordPressReviewFinishError::Review)?,
            item_projected: !signals.is_empty(),
            discovery: self.discovery_audit,
        };
        Ok(CommittedWordPressReview {
            subject,
            evidence_ids,
            audit,
        })
    }
}

/// Redaction-safe, transport-free WordPress interpretation retained by one
/// completed assessment. It deliberately has no Serde implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAssessmentWordPressAudit {
    result: WordPressReviewResult,
    signal_count: u16,
    evidence_reference_count: u16,
    item_projected: bool,
    discovery: Option<WebAssessmentWordPressDiscoveryAudit>,
}

impl WebAssessmentWordPressAudit {
    pub const fn result(&self) -> &WordPressReviewResult {
        &self.result
    }

    pub const fn signal_count(&self) -> u16 {
        self.signal_count
    }

    pub const fn evidence_reference_count(&self) -> u16 {
        self.evidence_reference_count
    }

    /// Returns zero for the legacy transport-free review and the exact broker-
    /// accounted attempt count for explicitly selected metadata discovery.
    pub const fn additional_request_count(&self) -> u8 {
        match &self.discovery {
            Some(discovery) => discovery.attempted_request_count(),
            None => 0,
        }
    }

    /// Returns the separately versioned, explicitly selected metadata audit.
    pub const fn discovery(&self) -> Option<&WebAssessmentWordPressDiscoveryAudit> {
        self.discovery.as_ref()
    }

    pub const fn item_projected(&self) -> bool {
        self.item_projected
    }
}

pub(super) struct CommittedWordPressReview {
    subject: EntityId,
    evidence_ids: Vec<EvidenceId>,
    audit: WebAssessmentWordPressAudit,
}

impl CommittedWordPressReview {
    pub(super) const fn audit(&self) -> &WebAssessmentWordPressAudit {
        &self.audit
    }
}

pub(super) fn project_wordpress_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedWordPressReview,
) -> Result<(), AssessmentItemProjectionError> {
    for evidence_id in &review.evidence_ids {
        if !context.has_evidence(evidence_id) {
            context.register_evidence(knowledge, evidence_id)?;
        }
    }
    let discovery_evidence_ids = review
        .audit
        .discovery()
        .map(|discovery| {
            discovery
                .sources()
                .iter()
                .flat_map(WordPressDiscoverySourceAudit::evidence_ids)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for evidence_id in &discovery_evidence_ids {
        if !context.has_evidence(evidence_id) {
            context.register_evidence(knowledge, evidence_id)?;
        }
    }
    if review.audit.item_projected {
        context.project_observation(
            &WORDPRESS_REVIEW_CAPABILITY,
            knowledge,
            &review.subject,
            &AssessmentItemTarget::subject(),
            &review.evidence_ids,
        )?;
    }
    if !discovery_evidence_ids.is_empty() {
        context.project_observation(
            &WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY,
            knowledge,
            &review.subject,
            &AssessmentItemTarget::subject(),
            &discovery_evidence_ids,
        )?;
    }
    Ok(())
}

/// Parses the committed entry representation once, then resolves component
/// signals and metadata candidates against the same selected application and
/// layout decision. A raw asset reference is never normalized into authority.
pub(super) fn extract_wordpress_entry_observation(
    context: &WordPressDiscoveryContext,
    document_url: &Url,
    html: &str,
    rest_header: &WordPressRestIndexAdvertisement,
    discovery_enabled: bool,
) -> WordPressEntryObservation {
    let mut selection = WordPressDiscoverySeedSelection {
        layout: Some(context.unresolved_audit()),
        ..WordPressDiscoverySeedSelection::default()
    };
    let mut signals = Vec::new();
    if document_url != context.application_url() {
        return WordPressEntryObservation {
            signals,
            discovery: selection,
        };
    }
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let resolution_base = effective_document_base(&dom.document, document_url);
    let mut assets = Vec::new();
    let mut asset_identities = BTreeSet::new();
    let mut skipped_foreign_origin_count = 0_u16;
    let mut rest_candidates = Vec::new();
    let rest_invalid = matches!(
        rest_header,
        WordPressRestIndexAdvertisement::InvalidOrAmbiguous
    );
    if let WordPressRestIndexAdvertisement::Candidate(url) = rest_header {
        rest_candidates.push(url.clone());
    }
    let mut pending = vec![dom.document.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) {
                let local = name.local.as_ref();
                if local == "meta"
                    && html_attribute(attrs, "name")
                        .is_some_and(|value| value.eq_ignore_ascii_case("generator"))
                {
                    if let Some(content) = html_attribute(attrs, "content") {
                        if let Some(version) = wordpress_generator_version(&content) {
                            if let Ok(signal) =
                                WordPressComponentSignal::generator_metadata(version)
                            {
                                push_bounded_signal(&mut signals, signal);
                            }
                        }
                    }
                }
                if local == "link" && link_has_relation(attrs, "https://api.w.org/") {
                    if let (Some(reference), Some(base)) =
                        (html_attribute(attrs, "href"), resolution_base.as_ref())
                    {
                        if let Some(url) = projected_rest_candidate(document_url, base, &reference)
                        {
                            rest_candidates.push(url);
                        }
                    }
                }
                let asset = match local {
                    "link" if link_relation_can_load_resource(attrs) => {
                        html_attribute(attrs, "href")
                    },
                    "script" | "img" | "source" => html_attribute(attrs, "src"),
                    _ => None,
                };
                if let (Some(reference), Some(base)) = (asset, resolution_base.as_ref()) {
                    if !crate::http_evidence::wordpress_reference_path_is_safe(&reference) {
                        pending.extend(handle.children.borrow().iter().rev().cloned());
                        continue;
                    }
                    if let Ok(url) = base.join(&reference) {
                        if safe_resource_shape(&url) && url.origin() != document_url.origin() {
                            skipped_foreign_origin_count =
                                skipped_foreign_origin_count.saturating_add(1);
                        } else if safe_observed_asset_url(document_url, &url)
                            && asset_is_layout_candidate(context, &url)
                        {
                            let identity = url.as_str().to_owned();
                            if asset_identities.insert(identity) {
                                if asset_identities.len()
                                    > MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
                                {
                                    selection.candidate_identity_limit_exceeded = true;
                                } else {
                                    assets.push(url);
                                }
                            }
                        }
                    }
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }

    rest_candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    rest_candidates.dedup();
    if asset_identities.len() > MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES {
        signals.retain(|signal| {
            signal.source() == crate::wordpress_review::WordPressEvidenceSource::GeneratorMetadata
        });
        return WordPressEntryObservation {
            signals,
            discovery: selection,
        };
    }
    resolve_entry_layout(
        EntryLayoutResolution {
            context,
            assets: &assets,
            rest_candidates: &rest_candidates,
            rest_invalid,
            skipped_foreign_origin_count,
            discovery_enabled,
        },
        &mut signals,
        &mut selection,
    );
    WordPressEntryObservation {
        signals,
        discovery: selection,
    }
}

/// Compatibility seam for the bounded signal fuzz/unit corpus. Production
/// entry handling calls `extract_wordpress_entry_observation` once instead.
#[cfg(any(test, fuzzing))]
pub(super) fn extract_wordpress_signals(
    document_url: &Url,
    html: &str,
) -> Vec<WordPressComponentSignal> {
    extract_wordpress_entry_observation(
        &WordPressDiscoveryContext::new(document_url.clone(), None),
        document_url,
        html,
        &WordPressRestIndexAdvertisement::Missing,
        false,
    )
    .signals
}

/// Compatibility seam for existing discovery candidate tests and fuzzing.
#[cfg(any(test, fuzzing))]
pub(super) fn extract_wordpress_discovery_seeds(
    document_url: &Url,
    html: &str,
    rest_header: &WordPressRestIndexAdvertisement,
) -> WordPressDiscoverySeedSelection {
    extract_wordpress_entry_observation(
        &WordPressDiscoveryContext::new(document_url.clone(), None),
        document_url,
        html,
        rest_header,
        true,
    )
    .discovery
}

#[derive(Clone)]
struct ObservedComponentAsset {
    resource: Url,
    content_base: Option<Url>,
    role_base: Url,
    component: crate::wordpress_review::WordPressComponentIdentity,
    association: WordPressDiscoveryAssociation,
}

#[derive(Clone)]
struct ObservedCoreAsset {
    core_base: Url,
}

struct EntryLayoutResolution<'a> {
    context: &'a WordPressDiscoveryContext,
    assets: &'a [Url],
    rest_candidates: &'a [Url],
    rest_invalid: bool,
    skipped_foreign_origin_count: u16,
    discovery_enabled: bool,
}

fn resolve_entry_layout(
    input: EntryLayoutResolution<'_>,
    signals: &mut Vec<WordPressComponentSignal>,
    selection: &mut WordPressDiscoverySeedSelection,
) {
    let EntryLayoutResolution {
        context,
        assets,
        rest_candidates,
        rest_invalid,
        skipped_foreign_origin_count,
        discovery_enabled,
    } = input;
    let mut layout = context.unresolved_audit();
    layout.skipped_foreign_origin_count = skipped_foreign_origin_count;
    let declared = context.declared_layout();
    let explicit_themes = declared.and_then(WordPressDiscoveryLayout::themes_base_url);
    let explicit_plugins = declared.and_then(WordPressDiscoveryLayout::plugins_base_url);
    let mut conventional = Vec::new();
    let mut core_assets = Vec::new();
    let mut conflicting = 0_u16;

    for asset in assets {
        let conventional_component = match conventional_component_asset(asset) {
            ConventionalComponentResult::Observed(observation) => {
                conventional.push(*observation);
                true
            },
            ConventionalComponentResult::MultipleContentMarkers => {
                conflicting = conflicting.saturating_add(1);
                true
            },
            ConventionalComponentResult::NotComponent => false,
        };
        let declared_component = [
            (WordPressComponentKind::Theme, explicit_themes),
            (WordPressComponentKind::Plugin, explicit_plugins),
        ]
        .into_iter()
        .any(|(kind, base)| {
            base.is_some_and(|base| component_under_role_base(asset, base, kind).is_some())
        });
        if !conventional_component && !declared_component {
            if let Some(core) = conventional_core_asset(asset) {
                core_assets.push(core);
            }
        }
    }

    let mut selected_components = Vec::new();
    let mut automatic_by_prefix: BTreeMap<String, Vec<ObservedComponentAsset>> = BTreeMap::new();

    for asset in assets {
        for (kind, base) in [
            (WordPressComponentKind::Theme, explicit_themes),
            (WordPressComponentKind::Plugin, explicit_plugins),
        ] {
            if let Some(base) = base {
                if let Some(component) = component_under_role_base(asset, base, kind) {
                    selected_components.push(ObservedComponentAsset {
                        resource: asset.clone(),
                        content_base: None,
                        role_base: base.clone(),
                        component,
                        association: WordPressDiscoveryAssociation::ExplicitOperator,
                    });
                }
            }
        }
    }

    for observation in conventional {
        if let Some(selected) = selected_components
            .iter()
            .find(|selected| selected.resource == observation.resource)
        {
            if selected.component != observation.component {
                conflicting = conflicting.saturating_add(1);
            }
            continue;
        }
        let role_is_declared = match observation.component.kind() {
            WordPressComponentKind::Theme => explicit_themes.is_some(),
            WordPressComponentKind::Plugin => explicit_plugins.is_some(),
            WordPressComponentKind::Core => true,
        };
        if role_is_declared {
            if !selected_components.iter().any(|selected| {
                selected.resource == observation.resource
                    && selected.component == observation.component
            }) {
                conflicting = conflicting.saturating_add(1);
            }
            continue;
        }
        let Some(content_base) = observation.content_base.as_ref() else {
            continue;
        };
        if !directory_is_within_application(context.application_url(), content_base) {
            layout.skipped_sibling_application_count =
                layout.skipped_sibling_application_count.saturating_add(1);
            continue;
        }
        automatic_by_prefix
            .entry(content_base.as_str().to_owned())
            .or_default()
            .push(observation);
    }

    match automatic_by_prefix.len() {
        0 => {},
        1 => {
            if let Some((_, observations)) = automatic_by_prefix.into_iter().next() {
                selected_components.extend(observations);
            }
        },
        count => {
            conflicting = conflicting.saturating_add(saturating_u16(count));
            for role in [
                WordPressDiscoveryLayoutRole::Themes,
                WordPressDiscoveryLayoutRole::Plugins,
            ] {
                if declared_role_base(declared, role).is_none() {
                    set_layout_role(
                        &mut layout,
                        role,
                        WordPressDiscoveryLayoutStatus::Ambiguous,
                        WordPressDiscoveryLayoutBasis::ConventionalAsset,
                        None,
                        saturating_u16(count),
                    );
                }
            }
        },
    }

    selected_components.sort_by(|left, right| {
        left.component
            .cmp(&right.component)
            .then_with(|| left.role_base.as_str().cmp(right.role_base.as_str()))
            .then_with(|| left.resource.as_str().cmp(right.resource.as_str()))
    });
    selected_components.dedup_by(|left, right| {
        left.component == right.component
            && left.role_base == right.role_base
            && left.resource == right.resource
    });

    for role in [
        WordPressDiscoveryLayoutRole::Themes,
        WordPressDiscoveryLayoutRole::Plugins,
    ] {
        let role_kind = match role {
            WordPressDiscoveryLayoutRole::Themes => WordPressComponentKind::Theme,
            WordPressDiscoveryLayoutRole::Plugins => WordPressComponentKind::Plugin,
            _ => continue,
        };
        let matching = selected_components
            .iter()
            .filter(|entry| entry.component.kind() == role_kind)
            .collect::<Vec<_>>();
        let bases = matching
            .iter()
            .map(|entry| entry.role_base.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(explicit) = declared_role_base(declared, role) {
            set_layout_role(
                &mut layout,
                role,
                WordPressDiscoveryLayoutStatus::Exact,
                WordPressDiscoveryLayoutBasis::OperatorDeclaration,
                Some(explicit),
                1,
            );
        } else if bases.len() == 1 {
            set_layout_role(
                &mut layout,
                role,
                WordPressDiscoveryLayoutStatus::Exact,
                WordPressDiscoveryLayoutBasis::ConventionalAsset,
                matching.first().map(|entry| &entry.role_base),
                1,
            );
        }
    }

    for observation in selected_components {
        let signal = WordPressComponentSignal::same_origin_asset(
            observation.component.kind(),
            observation.component.slug(),
        );
        if let Ok(signal) = signal {
            push_bounded_signal(signals, signal);
        }
        if discovery_enabled {
            let filename = match observation.component.kind() {
                WordPressComponentKind::Theme => "style.css",
                WordPressComponentKind::Plugin => "readme.txt",
                WordPressComponentKind::Core => continue,
            };
            if let Some(resource) = exact_role_resource(
                &observation.role_base,
                observation.component.slug(),
                filename,
            ) {
                selection.insert(WordPressDiscoverySeed::admitted_component(
                    resource,
                    context.application_url().clone(),
                    observation.role_base,
                    observation.association,
                    observation.component,
                    0,
                ));
            }
        }
    }

    resolve_core_layout(
        context,
        declared.and_then(WordPressDiscoveryLayout::core_base_url),
        &core_assets,
        signals,
        &mut layout,
        &mut conflicting,
    );
    resolve_rest_layout(
        context,
        rest_candidates,
        rest_invalid,
        discovery_enabled,
        selection,
        &mut layout,
        &mut conflicting,
    );
    layout.conflicting_association_count = conflicting;
    selection.layout = Some(layout);
}

fn declared_role_base(
    layout: Option<&WordPressDiscoveryLayout>,
    role: WordPressDiscoveryLayoutRole,
) -> Option<&Url> {
    layout.and_then(|layout| match role {
        WordPressDiscoveryLayoutRole::Core => layout.core_base_url(),
        WordPressDiscoveryLayoutRole::Themes => layout.themes_base_url(),
        WordPressDiscoveryLayoutRole::Plugins => layout.plugins_base_url(),
        WordPressDiscoveryLayoutRole::RestIndex => None,
    })
}

fn set_layout_role(
    layout: &mut WordPressDiscoveryLayoutAudit,
    role: WordPressDiscoveryLayoutRole,
    status: WordPressDiscoveryLayoutStatus,
    basis: WordPressDiscoveryLayoutBasis,
    base: Option<&Url>,
    candidate_count: u16,
) {
    let entry = layout.role_mut(role);
    entry.status = status;
    entry.basis = basis;
    entry.reference = base.map(|base| {
        super::wordpress_discovery::opaque_url_reference("wordpress-discovery-role", base)
    });
    entry.candidate_count = candidate_count;
}

fn resolve_core_layout(
    context: &WordPressDiscoveryContext,
    explicit: Option<&Url>,
    observations: &[ObservedCoreAsset],
    signals: &mut Vec<WordPressComponentSignal>,
    layout: &mut WordPressDiscoveryLayoutAudit,
    conflicting: &mut u16,
) {
    let mut candidates = observations
        .iter()
        .filter(|observation| {
            explicit.map_or_else(
                || {
                    directory_is_within_application(
                        context.application_url(),
                        &observation.core_base,
                    )
                },
                |base| base == &observation.core_base,
            )
        })
        .map(|observation| observation.core_base.clone())
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    candidates.dedup();
    let skipped = observations
        .iter()
        .filter(|observation| !candidates.contains(&observation.core_base))
        .count();
    *conflicting = conflicting.saturating_add(saturating_u16(skipped));
    if let Some(base) = explicit {
        set_layout_role(
            layout,
            WordPressDiscoveryLayoutRole::Core,
            WordPressDiscoveryLayoutStatus::Exact,
            WordPressDiscoveryLayoutBasis::OperatorDeclaration,
            Some(base),
            1,
        );
        if !candidates.is_empty() {
            push_bounded_signal(signals, WordPressComponentSignal::core_asset());
        }
    } else if candidates.len() == 1 {
        set_layout_role(
            layout,
            WordPressDiscoveryLayoutRole::Core,
            WordPressDiscoveryLayoutStatus::Exact,
            WordPressDiscoveryLayoutBasis::ConventionalAsset,
            candidates.first(),
            1,
        );
        push_bounded_signal(signals, WordPressComponentSignal::core_asset());
    } else if candidates.len() > 1 {
        set_layout_role(
            layout,
            WordPressDiscoveryLayoutRole::Core,
            WordPressDiscoveryLayoutStatus::Ambiguous,
            WordPressDiscoveryLayoutBasis::ConventionalAsset,
            None,
            saturating_u16(candidates.len()),
        );
    }
}

fn resolve_rest_layout(
    context: &WordPressDiscoveryContext,
    candidates: &[Url],
    invalid: bool,
    discovery_enabled: bool,
    selection: &mut WordPressDiscoverySeedSelection,
    layout: &mut WordPressDiscoveryLayoutAudit,
    conflicting: &mut u16,
) {
    let declared_core = context
        .declared_layout()
        .and_then(WordPressDiscoveryLayout::core_base_url);
    let mut admitted = Vec::new();
    for candidate in candidates {
        let Some(base) = rest_candidate_base(candidate) else {
            *conflicting = conflicting.saturating_add(1);
            continue;
        };
        let association = if &base == context.application_url() {
            Some(WordPressDiscoveryAssociation::StructuredAdvertisement)
        } else if declared_core == Some(&base) {
            Some(WordPressDiscoveryAssociation::OperatorQualifiedAdvertisement)
        } else {
            layout.skipped_sibling_application_count =
                layout.skipped_sibling_application_count.saturating_add(1);
            None
        };
        if let Some(association) = association {
            admitted.push((candidate.clone(), base, association));
        }
    }
    admitted.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    admitted.dedup_by(|left, right| left.0 == right.0);
    if admitted.len().saturating_add(usize::from(invalid)) > 1 {
        set_layout_role(
            layout,
            WordPressDiscoveryLayoutRole::RestIndex,
            WordPressDiscoveryLayoutStatus::Ambiguous,
            WordPressDiscoveryLayoutBasis::StructuredAdvertisement,
            None,
            saturating_u16(admitted.len().saturating_add(usize::from(invalid))),
        );
        if discovery_enabled {
            selection.insert(WordPressDiscoverySeed::invalid_rest_index(
                context.application_url().clone(),
            ));
        }
    } else if invalid {
        if discovery_enabled {
            selection.insert(WordPressDiscoverySeed::invalid_rest_index(
                context.application_url().clone(),
            ));
        }
    } else if let Some((resource, base, association)) = admitted.pop() {
        let basis = if association == WordPressDiscoveryAssociation::StructuredAdvertisement {
            WordPressDiscoveryLayoutBasis::StructuredAdvertisement
        } else {
            WordPressDiscoveryLayoutBasis::OperatorDeclaration
        };
        set_layout_role(
            layout,
            WordPressDiscoveryLayoutRole::RestIndex,
            WordPressDiscoveryLayoutStatus::Exact,
            basis,
            Some(&base),
            1,
        );
        if discovery_enabled {
            selection.insert(WordPressDiscoverySeed::admitted_rest_index(
                resource,
                context.application_url().clone(),
                base,
                association,
            ));
        }
    }
}

enum ConventionalComponentResult {
    Observed(Box<ObservedComponentAsset>),
    MultipleContentMarkers,
    NotComponent,
}

fn conventional_component_asset(url: &Url) -> ConventionalComponentResult {
    let segments = url_segments(url);
    let markers = segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| **segment == "wp-content")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [marker] = markers.as_slice() else {
        return if markers.len() > 1 {
            ConventionalComponentResult::MultipleContentMarkers
        } else {
            ConventionalComponentResult::NotComponent
        };
    };
    if segments.len() <= marker.saturating_add(3) {
        return ConventionalComponentResult::NotComponent;
    }
    let kind = match segments.get(marker.saturating_add(1)).copied() {
        Some("themes") => WordPressComponentKind::Theme,
        Some("plugins") => WordPressComponentKind::Plugin,
        _ => return ConventionalComponentResult::NotComponent,
    };
    let Some(slug) = segments.get(marker.saturating_add(2)).copied() else {
        return ConventionalComponentResult::NotComponent;
    };
    if segments
        .get(marker.saturating_add(3))
        .is_none_or(|segment| segment.is_empty())
    {
        return ConventionalComponentResult::NotComponent;
    }
    let Ok(component) = crate::wordpress_review::WordPressComponentIdentity::new(kind, slug) else {
        return ConventionalComponentResult::NotComponent;
    };
    let Some(content_base) = directory_from_segments(url, &segments[..=(*marker)]) else {
        return ConventionalComponentResult::NotComponent;
    };
    let Some(role_base) = directory_from_segments(url, &segments[..=marker.saturating_add(1)])
    else {
        return ConventionalComponentResult::NotComponent;
    };
    ConventionalComponentResult::Observed(Box::new(ObservedComponentAsset {
        resource: url.clone(),
        content_base: Some(content_base),
        role_base,
        component,
        association: WordPressDiscoveryAssociation::ObservedConventional,
    }))
}

fn conventional_core_asset(url: &Url) -> Option<ObservedCoreAsset> {
    let segments = url_segments(url);
    let markers = segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| matches!(**segment, "wp-includes" | "wp-admin"))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [marker] = markers.as_slice() else {
        return None;
    };
    if segments
        .get(marker.saturating_add(1))
        .is_none_or(|segment| segment.is_empty())
    {
        return None;
    }
    directory_from_segments(url, &segments[..*marker])
        .map(|core_base| ObservedCoreAsset { core_base })
}

fn component_under_role_base(
    resource: &Url,
    base: &Url,
    kind: WordPressComponentKind,
) -> Option<crate::wordpress_review::WordPressComponentIdentity> {
    if resource.origin() != base.origin() {
        return None;
    }
    let resource_segments = url_segments(resource);
    let base_segments = url_segments(base);
    if resource_segments.len() <= base_segments.len().saturating_add(1)
        || !base_segments
            .iter()
            .zip(&resource_segments)
            .all(|(base, resource)| base == resource)
    {
        return None;
    }
    let slug = resource_segments[base_segments.len()];
    (!resource_segments[base_segments.len().saturating_add(1)].is_empty())
        .then(|| crate::wordpress_review::WordPressComponentIdentity::new(kind, slug).ok())
        .flatten()
}

fn exact_role_resource(base: &Url, slug: &str, filename: &str) -> Option<Url> {
    let resource = base.join(&format!("{slug}/{filename}")).ok()?;
    safe_resource_shape(&resource).then_some(resource)
}

fn projected_rest_candidate(document_url: &Url, base: &Url, reference: &str) -> Option<Url> {
    if !crate::http_evidence::wordpress_reference_path_is_safe(reference) {
        return None;
    }
    let candidate = base.join(reference).ok()?;
    if !safe_observed_asset_url(document_url, &candidate) {
        return None;
    }
    rest_candidate_base(&candidate).map(|_| candidate)
}

fn rest_candidate_base(candidate: &Url) -> Option<Url> {
    let segments = url_segments(candidate);
    if candidate.query().is_none() && segments.last().copied() == Some("wp-json") {
        return directory_from_segments(candidate, &segments[..segments.len().saturating_sub(1)]);
    }
    if !candidate
        .query()
        .is_some_and(crate::http_evidence::wordpress_rest_route_query_is_admitted)
    {
        return None;
    }
    if segments.last().copied() == Some("index.php") {
        directory_from_segments(candidate, &segments[..segments.len().saturating_sub(1)])
    } else if candidate.path().ends_with('/') {
        directory_from_segments(candidate, &segments)
    } else {
        None
    }
}

fn safe_observed_asset_url(document_url: &Url, candidate: &Url) -> bool {
    safe_resource_shape(candidate) && candidate.origin() == document_url.origin()
}

fn safe_resource_shape(candidate: &Url) -> bool {
    matches!(candidate.scheme(), "http" | "https")
        && candidate.has_host()
        && candidate.username().is_empty()
        && candidate.password().is_none()
        && candidate.fragment().is_none()
        && !candidate.path().contains('\\')
        && !candidate
            .path()
            .split('/')
            .enumerate()
            .any(|(index, segment)| {
                matches!(segment, "." | "..")
                    || (segment.is_empty()
                        && index != 0
                        && index + 1 != candidate.path().split('/').count())
                    || ["%2e", "%2f", "%5c", "%25"]
                        .iter()
                        .any(|encoded| segment.to_ascii_lowercase().contains(encoded))
            })
}

fn asset_is_layout_candidate(context: &WordPressDiscoveryContext, resource: &Url) -> bool {
    if !matches!(
        conventional_component_asset(resource),
        ConventionalComponentResult::NotComponent
    ) || conventional_core_asset(resource).is_some()
    {
        return true;
    }
    let Some(layout) = context.declared_layout() else {
        return false;
    };
    [
        (WordPressComponentKind::Theme, layout.themes_base_url()),
        (WordPressComponentKind::Plugin, layout.plugins_base_url()),
    ]
    .into_iter()
    .any(|(kind, base)| {
        base.is_some_and(|base| component_under_role_base(resource, base, kind).is_some())
    })
}

fn directory_is_within_application(application: &Url, candidate: &Url) -> bool {
    if application.origin() != candidate.origin() {
        return false;
    }
    let application = url_segments(application);
    let candidate = url_segments(candidate);
    application.len() <= candidate.len()
        && application
            .iter()
            .zip(candidate.iter())
            .all(|(application, candidate)| application == candidate)
}

fn directory_from_segments(source: &Url, segments: &[&str]) -> Option<Url> {
    let mut directory = source.clone();
    let path = if segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}/", segments.join("/"))
    };
    directory.set_path(&path);
    directory.set_query(None);
    directory.set_fragment(None);
    safe_resource_shape(&directory).then_some(directory)
}

fn url_segments(url: &Url) -> Vec<&str> {
    url.path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
        .unwrap_or_default()
}

fn saturating_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn insert_bounded_discovery_seed(
    seeds: &mut Vec<WordPressDiscoverySeed>,
    seed: WordPressDiscoverySeed,
    omitted_candidate_count: &mut u64,
) -> Result<bool, ()> {
    if same_discovery_seed_is_retained(seeds, &seed) {
        return Ok(false);
    }
    let fingerprint = discovery_seed_fingerprint(&seed);
    seeds.push(seed);
    seeds.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    if seeds.len() > MAX_WORDPRESS_DISCOVERY_CANDIDATES {
        retain_request_quota_candidates(seeds);
        *omitted_candidate_count = omitted_candidate_count.checked_add(1).ok_or(())?;
    }
    Ok(seeds
        .iter()
        .any(|retained| discovery_seed_fingerprint(retained) == fingerprint))
}

/// Keeps enough deterministic candidates of every kind to exercise each
/// closed request quota before filling the remaining retention capacity in
/// ordinary stable order. The global 32-candidate bound therefore cannot be
/// consumed entirely by one high-cardinality source kind.
fn retain_request_quota_candidates(seeds: &mut Vec<WordPressDiscoverySeed>) {
    let mut selected = vec![false; seeds.len()];
    let mut selected_count = 0_usize;
    for (kind, limit) in [
        (
            WordPressDiscoverySourceKind::RestIndex,
            usize::from(MAX_WORDPRESS_DISCOVERY_REST_REQUESTS),
        ),
        (
            WordPressDiscoverySourceKind::ThemeStylesheet,
            usize::from(MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS),
        ),
        (
            WordPressDiscoverySourceKind::PluginReadme,
            usize::from(MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS),
        ),
    ] {
        for (index, _) in seeds
            .iter()
            .enumerate()
            .filter(|(_, seed)| seed.kind() == kind && seed.preflight_outcome().is_none())
            .take(limit)
        {
            selected[index] = true;
            selected_count += 1;
        }
    }
    for selected in &mut selected {
        if selected_count == MAX_WORDPRESS_DISCOVERY_CANDIDATES {
            break;
        }
        if !*selected {
            *selected = true;
            selected_count += 1;
        }
    }
    let mut index = 0_usize;
    seeds.retain(|_| {
        let retain = selected[index];
        index += 1;
        retain
    });
}

fn same_discovery_seed_is_retained(
    seeds: &[WordPressDiscoverySeed],
    seed: &WordPressDiscoverySeed,
) -> bool {
    seeds
        .iter()
        .any(|existing| same_discovery_seed(existing, seed))
}

fn same_discovery_seed(left: &WordPressDiscoverySeed, right: &WordPressDiscoverySeed) -> bool {
    discovery_seed_fingerprint(left) == discovery_seed_fingerprint(right)
}

#[cfg(fuzzing)]
pub(super) fn fuzz_check_discovery_candidate_admission(
    html: &[u8],
    rest_header: &WordPressRestIndexAdvertisement,
) {
    let origin =
        Url::parse("https://wordpress-fuzz.invalid/").expect("fixed fuzz origin must remain valid");
    let html = String::from_utf8_lossy(html);
    let first = extract_wordpress_discovery_seeds(&origin, &html, rest_header);
    let repeated = extract_wordpress_discovery_seeds(&origin, &html, rest_header);
    assert_eq!(first.seeds, repeated.seeds);
    assert_eq!(
        first.seen_candidate_fingerprints,
        repeated.seen_candidate_fingerprints
    );
    assert_eq!(
        first.candidate_identity_limit_exceeded,
        repeated.candidate_identity_limit_exceeded
    );
    assert_eq!(
        first.omitted_candidate_count,
        repeated.omitted_candidate_count
    );
    assert!(first.seeds.len() <= MAX_WORDPRESS_DISCOVERY_CANDIDATES);
    assert!(
        first.seen_candidate_fingerprints.len() <= MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
    );
    assert!(first
        .seeds
        .windows(2)
        .all(|pair| pair[0].sort_key() < pair[1].sort_key()));
    assert!(first.seeds.iter().all(|seed| {
        seed.url().origin() == origin.origin()
            && seed.url().username().is_empty()
            && seed.url().password().is_none()
            && seed.url().fragment().is_none()
            && seed.parent_depth() == 0
    }));
}

fn effective_document_base(
    document: &markup5ever_rcdom::Handle,
    document_url: &Url,
) -> Option<Url> {
    let mut pending = vec![document.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "base" {
                if let Some(reference) = html_attribute(attrs, "href") {
                    // An unusable first declared base makes relative asset
                    // association ambiguous, so V1 conservatively retains no
                    // asset-path signal from this document.
                    return crate::http_evidence::wordpress_reference_path_is_safe(&reference)
                        .then(|| document_url.join(&reference).ok())
                        .flatten();
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    Some(document_url.clone())
}

fn push_bounded_signal(
    signals: &mut Vec<WordPressComponentSignal>,
    signal: WordPressComponentSignal,
) {
    if !signals.contains(&signal) && signals.len() <= MAX_WORDPRESS_SIGNALS {
        signals.push(signal);
    }
}

fn wordpress_generator_version(content: &str) -> Option<Option<&str>> {
    let content = content.trim();
    if content == "WordPress" {
        return Some(None);
    }
    let version = content.strip_prefix("WordPress ")?.trim();
    (!version.is_empty() && !version.chars().any(char::is_whitespace)).then_some(Some(version))
}

fn html_attribute(
    attrs: &std::cell::RefCell<Vec<html5ever::Attribute>>,
    local_name: &str,
) -> Option<String> {
    attrs
        .borrow()
        .iter()
        .find(|attribute| attribute.name.ns == ns!() && attribute.name.local.as_ref() == local_name)
        .map(|attribute| attribute.value.to_string())
}

fn link_relation_can_load_resource(attrs: &std::cell::RefCell<Vec<html5ever::Attribute>>) -> bool {
    html_attribute(attrs, "rel").is_some_and(|relations| {
        relations.split_ascii_whitespace().any(|relation| {
            ["stylesheet", "icon", "preload", "modulepreload"]
                .iter()
                .any(|supported| relation.eq_ignore_ascii_case(supported))
        })
    })
}

fn link_has_relation(
    attrs: &std::cell::RefCell<Vec<html5ever::Attribute>>,
    expected: &str,
) -> bool {
    html_attribute(attrs, "rel").is_some_and(|relations| {
        relations
            .split_ascii_whitespace()
            .any(|relation| relation == expected)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordpress_review::{
        parse_wordpress_discovery_layout, WordPressComponentIdentity, WordPressEvidenceSource,
    };

    fn origin() -> Url {
        Url::parse("https://example.test/").unwrap()
    }

    fn seed_urls(selection: &WordPressDiscoverySeedSelection) -> Vec<&str> {
        selection
            .seeds()
            .iter()
            .map(|seed| seed.url().as_str())
            .collect()
    }

    #[test]
    fn selected_blog_application_preserves_component_and_rest_bases() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let observation = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<meta name="generator" content="WordPress 6.9.4">
                <link rel="https://api.w.org/" href="/blog/wp-json/">
                <link rel="stylesheet" href="/blog/wp-content/themes/child/assets/site.css">
                <script src="/blog/wp-content/plugins/cache-tool/assets/app.js"></script>
                <img src="/blog/wp-includes/images/blank.gif">
                <script src="/shop/wp-content/plugins/sibling/assets/app.js"></script>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
        );

        assert_eq!(
            seed_urls(&observation.discovery),
            vec![
                "https://example.test/blog/wp-json/",
                "https://example.test/blog/wp-content/themes/child/style.css",
                "https://example.test/blog/wp-content/plugins/cache-tool/readme.txt",
            ]
        );
        let identities = observation
            .signals
            .iter()
            .map(|signal| (signal.identity().kind(), signal.identity().slug()))
            .collect::<BTreeSet<_>>();
        assert!(identities.contains(&(WordPressComponentKind::Core, "wordpress")));
        assert!(identities.contains(&(WordPressComponentKind::Theme, "child")));
        assert!(identities.contains(&(WordPressComponentKind::Plugin, "cache-tool")));
        assert!(!identities.contains(&(WordPressComponentKind::Plugin, "sibling")));
        let layout = observation.discovery.layout.as_ref().unwrap();
        assert_eq!(layout.skipped_sibling_application_count(), 1);
    }

    #[test]
    fn root_application_preserves_one_observed_cms_content_prefix() {
        let application = origin();
        let observation = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<link rel="https://api.w.org/" href="/wp-json/">
                <link rel="stylesheet" href="/cms/wp-content/themes/child/assets/site.css">
                <script src="/cms/wp-content/plugins/cache-tool/assets/app.js"></script>
                <img src="/cms/wp-includes/images/blank.gif">"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
        );

        assert_eq!(
            seed_urls(&observation.discovery),
            vec![
                "https://example.test/wp-json/",
                "https://example.test/cms/wp-content/themes/child/style.css",
                "https://example.test/cms/wp-content/plugins/cache-tool/readme.txt",
            ]
        );
        let layout = observation.discovery.layout.as_ref().unwrap();
        let core = layout
            .roles()
            .iter()
            .find(|role| role.role() == WordPressDiscoveryLayoutRole::Core)
            .unwrap();
        assert_eq!(core.status(), WordPressDiscoveryLayoutStatus::Exact);
        assert_eq!(
            core.basis(),
            WordPressDiscoveryLayoutBasis::ConventionalAsset
        );
    }

    #[test]
    fn component_internal_core_named_paths_do_not_create_a_core_association() {
        let application = origin();
        let observation = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<script src="/wp-content/plugins/cache-tool/wp-includes/app.js"></script>
                <link rel="stylesheet" href="/wp-content/themes/child/wp-admin/editor.css">"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
        );

        assert_eq!(
            seed_urls(&observation.discovery),
            vec![
                "https://example.test/wp-content/themes/child/style.css",
                "https://example.test/wp-content/plugins/cache-tool/readme.txt",
            ]
        );
        assert!(!observation
            .signals
            .iter()
            .any(|signal| signal.identity().kind() == WordPressComponentKind::Core));
        let core = observation
            .discovery
            .layout
            .as_ref()
            .unwrap()
            .roles()
            .iter()
            .find(|role| role.role() == WordPressDiscoveryLayoutRole::Core)
            .unwrap();
        assert_eq!(core.status(), WordPressDiscoveryLayoutStatus::Unresolved);
    }

    #[test]
    fn operator_layout_qualifies_only_observed_custom_role_assets() {
        let bytes = br#"{
          "schema":"security.wordpress-layout/v1",
          "application_url":"https://example.test/blog/",
          "core_base_url":"https://example.test/cms/",
          "themes_base_url":"https://example.test/site-content/themes/",
          "plugins_base_url":"https://example.test/modules/"
        }"#;
        let declared = parse_wordpress_discovery_layout(bytes).unwrap();
        let application = Url::parse("https://example.test/blog/").unwrap();
        let observation = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), Some(declared)),
            &application,
            r#"<link rel="https://api.w.org/" href="/cms/wp-json/">
                <link rel="stylesheet" href="/site-content/themes/child/assets/site.css">
                <script src="/modules/cache-tool/assets/app.js"></script>
                <script src="/shop/wp-content/plugins/cache-tool/assets/decoy.js"></script>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
        );

        assert_eq!(
            seed_urls(&observation.discovery),
            vec![
                "https://example.test/cms/wp-json/",
                "https://example.test/site-content/themes/child/style.css",
                "https://example.test/modules/cache-tool/readme.txt",
            ]
        );
        assert!(observation
            .discovery
            .seeds()
            .iter()
            .all(|seed| seed.association() != WordPressDiscoveryAssociation::ObservedConventional));
        assert!(!observation
            .signals
            .iter()
            .any(|signal| signal.identity().slug() == "cache-tool"
                && signal.identity().kind() == WordPressComponentKind::Plugin
                && observation.discovery.seeds().iter().any(|seed| {
                    seed.url().path().starts_with("/shop/")
                        && seed.component_identity() == Some(signal.identity())
                })));
    }

    #[test]
    fn explicit_role_binding_excludes_cross_role_conventional_inference() {
        let application = origin();
        for (layout, html, expected_url, expected_kind) in [
            (
                br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","themes_base_url":"https://example.test/wp-content/plugins/"}"#.as_slice(),
                r#"<script src="/wp-content/plugins/cross-role/app.js"></script>"#,
                "https://example.test/wp-content/plugins/cross-role/style.css",
                WordPressComponentKind::Theme,
            ),
            (
                br#"{"schema":"security.wordpress-layout/v1","application_url":"https://example.test/","plugins_base_url":"https://example.test/wp-content/themes/"}"#.as_slice(),
                r#"<link rel="stylesheet" href="/wp-content/themes/cross-role/site.css">"#,
                "https://example.test/wp-content/themes/cross-role/readme.txt",
                WordPressComponentKind::Plugin,
            ),
        ] {
            let declared = parse_wordpress_discovery_layout(layout).unwrap();
            let observation = extract_wordpress_entry_observation(
                &WordPressDiscoveryContext::new(application.clone(), Some(declared)),
                &application,
                html,
                &WordPressRestIndexAdvertisement::Missing,
                true,
            );

            assert_eq!(seed_urls(&observation.discovery), vec![expected_url]);
            let seed = &observation.discovery.seeds()[0];
            assert_eq!(seed.component_identity().unwrap().kind(), expected_kind);
            assert_eq!(
                seed.association(),
                WordPressDiscoveryAssociation::ExplicitOperator
            );
            assert_eq!(
                observation
                    .discovery
                    .layout
                    .as_ref()
                    .unwrap()
                    .conflicting_association_count(),
                1
            );
        }
    }

    #[test]
    fn unrelated_assets_do_not_exhaust_wordpress_candidate_identity_budget() {
        let ordinary = (0..=MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES)
            .map(|index| format!(r#"<img src="/ordinary/image-{index}.png">"#))
            .collect::<String>();
        let observation = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(origin(), None),
            &origin(),
            &format!(
                r#"{ordinary}<script src="/wp-content/plugins/retained/assets/app.js"></script>"#
            ),
            &WordPressRestIndexAdvertisement::Missing,
            true,
        );

        assert!(!observation.discovery.candidate_identity_limit_exceeded);
        assert_eq!(
            seed_urls(&observation.discovery),
            vec!["https://example.test/wp-content/plugins/retained/readme.txt"]
        );
    }

    #[test]
    fn structured_generator_and_same_origin_assets_are_retained() {
        let signals = extract_wordpress_signals(
            &origin(),
            r#"<meta name="generator" content="WordPress 6.9.4">
                <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css?ver=99">
                <script src="/wp-content/plugins/cache-tool/app.js?ver=1.2.3"></script>
                <img src="/wp-includes/images/blank.gif">"#,
        );
        assert_eq!(signals.len(), 4);
        assert!(signals.iter().any(|signal| {
            signal.identity() == &WordPressComponentIdentity::core()
                && signal.version() == Some("6.9.4")
                && signal.source() == WordPressEvidenceSource::GeneratorMetadata
        }));
        let plugin = signals
            .iter()
            .find(|signal| signal.identity().slug() == "cache-tool")
            .unwrap();
        assert_eq!(plugin.version(), None, "asset queries are not versions");
    }

    #[test]
    fn generator_that_withholds_its_version_retains_only_the_core_hint() {
        let signals =
            extract_wordpress_signals(&origin(), r#"<meta name="generator" content="WordPress">"#);

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].identity(), &WordPressComponentIdentity::core());
        assert_eq!(signals[0].version(), None);
        assert_eq!(
            signals[0].source(),
            WordPressEvidenceSource::GeneratorMetadata
        );
    }

    #[test]
    fn prose_comments_scripts_anchors_and_foreign_assets_are_not_signals() {
        let signals = extract_wordpress_signals(
            &origin(),
            r#"WordPress 6.9.4<!-- <meta name='generator' content='WordPress 6.9.4'> -->
                <script>const x='/wp-content/plugins/not-installed/app.js';</script>
                <a href="/wp-content/plugins/linked-only/readme.txt">link</a>
                <link rel="canonical" href="/wp-content/plugins/canonical-only/readme.txt">
                <link rel="alternate" href="/wp-content/themes/feed-only/feed.xml">
                <script src="https://cdn.invalid/wp-content/plugins/foreign/app.js"></script>
                <meta name="description" content="WordPress 6.9.4">"#,
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn malformed_generator_and_component_paths_are_ignored() {
        let signals = extract_wordpress_signals(
            &origin(),
            r#"<meta name="generator" content="Powered by WordPress 6.9.4">
                <script src="/prefix/wp-content/plugins//app.js"></script>
                <script src="/wp-content/plugins/Word Press/app.js"></script>"#,
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn subpath_wordpress_sequences_are_not_bound_to_the_exact_root() {
        let signals = extract_wordpress_signals(
            &origin(),
            r#"<script src="/blog/wp-content/plugins/nested/app.js"></script>
                <link rel="stylesheet" href="/assets/wp-content/themes/nested/style.css">
                <img src="/assets/wp-includes/images/blank.gif">
                <script src="/nested/wp-admin/load-scripts.php"></script>"#,
        );

        assert!(signals.is_empty());
    }

    #[test]
    fn effective_base_and_root_asset_form_an_ambiguous_root_layout() {
        let signals = extract_wordpress_signals(
            &origin(),
            r#"<base href="/blog/">
                <script src="wp-content/plugins/nested/app.js"></script>
                <link rel="stylesheet" href="/wp-content/themes/root-theme/style.css">"#,
        );

        assert!(signals.is_empty());
    }

    #[test]
    fn whitespace_padded_references_are_not_normalized_into_discovery_authority() {
        let selection = extract_wordpress_discovery_seeds(
            &origin(),
            r#"<link rel="https://api.w.org/" href=" /wp-json/">
                <script src=" /wp-content/plugins/padded/app.js"></script>
                <link rel="stylesheet" href="/wp-content/themes/padded/style.css ">"#,
            &WordPressRestIndexAdvertisement::Missing,
        );
        assert!(selection.seeds().is_empty());

        let signals = extract_wordpress_signals(
            &origin(),
            r#"<base href=" /blog/">
                <script src="wp-content/plugins/padded/app.js"></script>"#,
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn distinct_header_and_html_rest_roots_are_rejected_as_ambiguous() {
        let rest = WordPressRestIndexAdvertisement::Candidate(
            Url::parse("https://example.test/index.php?rest_route=/").unwrap(),
        );
        let selection = extract_wordpress_discovery_seeds(
            &origin(),
            r#"<link rel="https://api.w.org/" href="/wp-json/">
                <script src="/wp-content/plugins/z-cache/assets/app.js?ver=secret"></script>
                <link rel="stylesheet" href="/wp-content/themes/a-theme/assets/app.css">
                <script src="https://foreign.invalid/wp-content/plugins/foreign/app.js"></script>
                <img src="/prefix/wp-content/themes/nested/image.png">"#,
            &rest,
        );

        let seeds = selection.seeds();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].kind(), WordPressDiscoverySourceKind::RestIndex);
        assert_eq!(
            seeds[0].preflight_outcome(),
            Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement)
        );
        assert!(seeds.iter().all(|seed| seed.url().query().is_none()
            || seed.kind() == WordPressDiscoverySourceKind::RestIndex));
    }

    #[test]
    fn equivalent_header_and_html_rest_roots_deduplicate() {
        let rest = WordPressRestIndexAdvertisement::Candidate(
            Url::parse("https://example.test/wp-json/").unwrap(),
        );
        let selection = extract_wordpress_discovery_seeds(
            &origin(),
            r#"<link rel="https://api.w.org/" href="/wp-json/">"#,
            &rest,
        );

        assert_eq!(selection.seeds().len(), 1);
        assert_eq!(selection.seeds()[0].preflight_outcome(), None);
        assert_eq!(
            selection.seeds()[0].url().as_str(),
            "https://example.test/wp-json/"
        );
    }

    #[test]
    fn html_rest_relation_uses_the_same_exact_raw_query_contract_as_headers() {
        for query in ["rest_route=/", "rest_route=%2F"] {
            let selection = extract_wordpress_discovery_seeds(
                &origin(),
                &format!(r#"<link rel="https://api.w.org/" href="/index.php?{query}">"#),
                &WordPressRestIndexAdvertisement::Missing,
            );
            assert_eq!(selection.seeds().len(), 1, "accepted query: {query}");
            assert_eq!(
                selection.seeds()[0].kind(),
                WordPressDiscoverySourceKind::RestIndex
            );
        }

        for query in [
            "rest_route=%2f",
            "%72est_route=%2F",
            "rest%5Froute=%2F",
            "rest_route=%252F",
            "rest_route=%2F&token=secret",
            "rest_route=%2F&rest_route=%2F",
            "REST_ROUTE=%2F",
        ] {
            let selection = extract_wordpress_discovery_seeds(
                &origin(),
                &format!(r#"<link rel="https://api.w.org/" href="/index.php?{query}">"#),
                &WordPressRestIndexAdvertisement::Missing,
            );
            assert!(selection.seeds().is_empty(), "rejected query: {query}");
        }
    }

    #[test]
    fn discovery_rejects_ambiguous_paths_and_nested_installations() {
        let selection = extract_wordpress_discovery_seeds(
            &origin(),
            r#"<link rel="https://api.w.org/" href="/index.php?rest_route=/&token=secret">
                <script src="/blog/wp-content/plugins/nested/app.js"></script>
                <script src="/shop/wp-content/plugins/nested/app.js"></script>
                <script src="/wp-content/plugins/../escape/app.js"></script>
                <script src="/wp-content/plugins/%2fescape/app.js"></script>
                <script src="/wp-content/plugins/decoy/%2e%2e/escape/app.js"></script>
                <script src="/wp-content/plugins/decoy/%252e%252e/escape/app.js"></script>
                <script src="\\wp-content\\plugins\\escape\\app.js"></script>"#,
            &WordPressRestIndexAdvertisement::InvalidOrAmbiguous,
        );

        let seeds = selection.seeds();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].kind(), WordPressDiscoverySourceKind::RestIndex);
        assert_eq!(
            seeds[0].preflight_outcome(),
            Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement)
        );
    }

    #[test]
    fn discovery_candidate_cap_is_order_independent_and_explicit() {
        fn html(indices: impl IntoIterator<Item = usize>) -> String {
            indices
                .into_iter()
                .map(|index| {
                    format!(
                        r#"<script src="/wp-content/plugins/plugin-{index:02}/asset.js"></script>"#
                    )
                })
                .collect()
        }

        let ascending = extract_wordpress_discovery_seeds(
            &origin(),
            &html(0..40),
            &WordPressRestIndexAdvertisement::Missing,
        );
        let descending = extract_wordpress_discovery_seeds(
            &origin(),
            &html((0..40).rev()),
            &WordPressRestIndexAdvertisement::Missing,
        );

        assert_eq!(ascending.omitted_candidate_count, 8);
        assert_eq!(descending.omitted_candidate_count, 8);
        assert_eq!(ascending.seeds, descending.seeds);
        assert_eq!(ascending.seeds.len(), MAX_WORDPRESS_DISCOVERY_CANDIDATES);
        assert_eq!(
            ascending
                .seeds
                .first()
                .unwrap()
                .component_identity()
                .unwrap()
                .slug(),
            "plugin-00"
        );
        assert_eq!(
            ascending
                .seeds
                .last()
                .unwrap()
                .component_identity()
                .unwrap()
                .slug(),
            "plugin-31"
        );

        let with_duplicates = extract_wordpress_discovery_seeds(
            &origin(),
            &format!("{}{}", html(0..40), html(std::iter::repeat_n(39, 16))),
            &WordPressRestIndexAdvertisement::Missing,
        );
        assert_eq!(with_duplicates.omitted_candidate_count, 8);
        assert_eq!(with_duplicates.seeds, ascending.seeds);
    }

    #[test]
    fn discovery_candidate_retention_reserves_every_closed_request_quota() {
        let themes = (0..31)
            .map(|index| {
                format!(
                    r#"<link rel="stylesheet" href="/wp-content/themes/theme-{index:02}/asset.css">"#
                )
            })
            .collect::<String>();
        let plugins = (0..8)
            .map(|index| {
                format!(r#"<script src="/wp-content/plugins/plugin-{index:02}/asset.js"></script>"#)
            })
            .collect::<String>();
        let selection = extract_wordpress_discovery_seeds(
            &origin(),
            &format!("{themes}{plugins}"),
            &WordPressRestIndexAdvertisement::Candidate(
                Url::parse("https://example.test/wp-json/").unwrap(),
            ),
        );

        assert_eq!(selection.seeds().len(), MAX_WORDPRESS_DISCOVERY_CANDIDATES);
        assert_eq!(selection.omitted_candidate_count, 8);
        assert_eq!(
            selection
                .seeds()
                .iter()
                .filter(|seed| seed.kind() == WordPressDiscoverySourceKind::RestIndex)
                .count(),
            1
        );
        assert!(
            selection
                .seeds()
                .iter()
                .filter(|seed| seed.kind() == WordPressDiscoverySourceKind::ThemeStylesheet)
                .count()
                >= usize::from(MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS)
        );
        assert_eq!(
            selection
                .seeds()
                .iter()
                .filter(|seed| seed.kind() == WordPressDiscoverySourceKind::PluginReadme)
                .count(),
            usize::from(MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS)
        );
    }

    #[test]
    fn discovery_collector_counts_distinct_omissions_across_repeated_observations() {
        let html = (0..40)
            .map(|index| {
                format!(r#"<script src="/wp-content/plugins/plugin-{index:02}/asset.js"></script>"#)
            })
            .collect::<String>();
        let collector = WordPressSignalCollector::default();
        for _ in 0..2 {
            collector.record(
                Vec::new(),
                extract_wordpress_discovery_seeds(
                    &origin(),
                    &html,
                    &WordPressRestIndexAdvertisement::Missing,
                ),
                Vec::new(),
            );
        }
        let (seeds, _, omitted, fingerprints, _) = collector.discovery_snapshot().unwrap();
        assert_eq!(seeds.len(), MAX_WORDPRESS_DISCOVERY_CANDIDATES);
        assert_eq!(omitted, 8);
        assert_eq!(fingerprints.len(), 40);
    }

    #[test]
    fn discovery_candidate_identity_accounting_is_bounded() {
        let mut selection = WordPressDiscoverySeedSelection::default();
        for index in 0..=MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES {
            let slug = format!("plugin-{index:04}");
            let identity =
                WordPressComponentIdentity::new(WordPressComponentKind::Plugin, &slug).unwrap();
            let url = Url::parse(&format!(
                "https://example.test/wp-content/plugins/{slug}/readme.txt"
            ))
            .unwrap();
            selection.insert(WordPressDiscoverySeed::component(url, identity, 0));
        }
        assert!(selection.candidate_identity_limit_exceeded);
        assert_eq!(
            selection.seen_candidate_fingerprints.len(),
            MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
        );
    }

    #[test]
    fn changing_root_rest_advertisements_collapse_to_one_invalid_candidate() {
        let collector = WordPressSignalCollector::default();
        let mut first = WordPressDiscoverySeedSelection::default();
        first.insert(WordPressDiscoverySeed::rest_index(
            Url::parse("https://example.test/wp-json/").unwrap(),
        ));
        collector.record(Vec::new(), first, Vec::new());

        let mut second = WordPressDiscoverySeedSelection::default();
        second.insert(WordPressDiscoverySeed::rest_index(
            Url::parse("https://example.test/?rest_route=/").unwrap(),
        ));
        collector.record(Vec::new(), second, Vec::new());

        let (seeds, _, omitted, fingerprints, _) = collector.discovery_snapshot().unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(omitted, 0);
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(seeds[0].kind(), WordPressDiscoverySourceKind::RestIndex);
        assert_eq!(
            seeds[0].preflight_outcome(),
            Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement)
        );
    }
}
