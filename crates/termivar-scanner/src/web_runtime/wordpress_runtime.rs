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
use sha2::Digest;
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    HttpEvidencePredicate, KnowledgePredicate,
};
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
use super::wordpress_fingerprint_runtime::{
    execute_wordpress_asset_fingerprints, WordPressAssetFingerprintAllowance,
    WordPressAssetFingerprintCollector, WordPressAssetFingerprintRuntimeError,
    WordPressAssetFingerprintStop, WordPressObservedAssetCandidate,
    MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES,
};
pub use super::wordpress_fingerprint_runtime::{
    WordPressAssetFingerprintAcquisition, WordPressAssetFingerprintExecution,
    WordPressAssetFingerprintResourceOutcome, WordPressAssetFingerprintResourceReceipt,
};

pub(super) use super::wordpress_discovery::WordPressDiscoveryStop;
use super::wordpress_discovery::{
    discovery_seed_fingerprint, execute_wordpress_discovery, WordPressDiscoveryAssociation,
    WordPressDiscoveryExecutionError, WordPressDiscoveryExecutionInput,
    WordPressDiscoveryLayoutAudit, WordPressDiscoveryLayoutBasis, WordPressDiscoveryLayoutRole,
    WordPressDiscoveryLayoutStatus, WordPressDiscoverySeed, MAX_WORDPRESS_DISCOVERY_CANDIDATES,
    MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES, MAX_WORDPRESS_DISCOVERY_PLUGIN_REQUESTS,
    MAX_WORDPRESS_DISCOVERY_REST_REQUESTS, MAX_WORDPRESS_DISCOVERY_THEME_REQUESTS,
    MAX_WORDPRESS_PAGE_CANDIDATES, MAX_WORDPRESS_PAGE_INTERPRETED_BYTES,
    MAX_WORDPRESS_PAGE_RESPONSE_BYTES, MAX_WORDPRESS_SELECTED_PAGES,
};
pub use super::wordpress_discovery::{
    WebAssessmentWordPressDiscoveryAudit, WordPressDiscoverySourceAudit,
    WordPressDiscoverySourceKind, WordPressDiscoverySourceOutcome, WordPressPageAcquisition,
    WordPressPageAssociation, WordPressPageAudit, WordPressPageOutcome, WordPressPageScope,
    WordPressPageScopeAudit, WordPressPluginDiscoveryMetadata, WordPressThemeDiscoveryMetadata,
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
    page_scope: Option<CollectedPageScope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WordPressPageCandidate {
    url: Url,
    page_reference: String,
}

#[derive(Clone, Default)]
pub(super) struct WordPressPageCandidateSelection {
    candidates: Vec<WordPressPageCandidate>,
    candidate_count: u16,
    omitted_candidate_count: u16,
    candidate_identity_limit_exceeded: bool,
}

#[derive(Clone, Default)]
pub(super) struct FrozenWordPressPageLayout {
    application_url: Option<Url>,
    themes: Option<FrozenWordPressRoleBinding>,
    plugins: Option<FrozenWordPressRoleBinding>,
}

#[derive(Clone)]
struct FrozenWordPressRoleBinding {
    base_url: Url,
    association: WordPressDiscoveryAssociation,
}

pub(super) struct PendingWordPressPageObservation {
    page: WordPressPageCandidate,
    signals: Vec<WordPressComponentSignal>,
    discovery: WordPressDiscoverySeedSelection,
    association: WordPressPageAssociation,
    outcome: WordPressPageOutcome,
    interpreted_response_bytes: u64,
    parent_evidence_ids: Vec<EvidenceId>,
    pub(super) asset_fingerprint_candidates: Vec<WordPressObservedAssetCandidate>,
    pub(super) asset_fingerprint_candidate_limit_exceeded: bool,
}

struct CollectedPageScope {
    mode: WordPressPageScope,
    entry_page_reference: String,
    selection: WordPressPageCandidateSelection,
    frozen_layout: FrozenWordPressPageLayout,
    pending_entry: Option<PendingWordPressEntryObservation>,
    pending: BTreeMap<String, PendingWordPressPageObservation>,
    pages: Vec<WordPressPageAudit>,
}

impl CollectedPageScope {
    fn new(mode: WordPressPageScope, application_url: &Url) -> Self {
        Self {
            mode,
            entry_page_reference: super::wordpress_discovery::opaque_url_reference(
                "wordpress-discovery-page",
                application_url,
            ),
            selection: WordPressPageCandidateSelection::default(),
            frozen_layout: FrozenWordPressPageLayout::default(),
            pending_entry: None,
            pending: BTreeMap::new(),
            pages: Vec::new(),
        }
    }
}

struct PendingWordPressEntryObservation {
    signals: Vec<WordPressComponentSignal>,
    discovery: WordPressDiscoverySeedSelection,
    page_candidates: WordPressPageCandidateSelection,
    frozen_page_layout: FrozenWordPressPageLayout,
    parent_evidence_ids: Vec<EvidenceId>,
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
    pub(super) page_candidates: WordPressPageCandidateSelection,
    pub(super) frozen_page_layout: FrozenWordPressPageLayout,
    pub(super) asset_fingerprint_candidates: Vec<WordPressObservedAssetCandidate>,
    pub(super) asset_fingerprint_candidate_limit_exceeded: bool,
}

#[derive(Clone)]
struct ObservedAssetReference {
    raw_reference: String,
    resolution_base: Url,
    resolved_url: Url,
}

impl WordPressDiscoverySeedSelection {
    fn insert(&mut self, seed: WordPressDiscoverySeed) {
        let fingerprint = discovery_seed_fingerprint(&seed);
        if self.seen_candidate_fingerprints.contains(&fingerprint) {
            if let Some(existing) = self
                .seeds
                .iter_mut()
                .find(|existing| discovery_seed_fingerprint(existing) == fingerprint)
            {
                existing.merge_source_provenance(&seed);
            }
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
    fn new(page_scope: Option<WordPressPageScope>, application_url: &Url) -> Self {
        let state = CollectedSignals {
            page_scope: page_scope.map(|mode| CollectedPageScope::new(mode, application_url)),
            ..CollectedSignals::default()
        };
        Self(Arc::new(Mutex::new(state)))
    }

    pub(super) fn stage_entry(
        &self,
        observation: WordPressEntryObservation,
        parent_evidence_ids: Vec<EvidenceId>,
    ) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(page_scope) = state.page_scope.as_mut() else {
            drop(state);
            self.record(
                observation.signals,
                observation.discovery,
                parent_evidence_ids,
            );
            return;
        };
        if page_scope.pending_entry.is_some() {
            state.discovery_candidate_identity_limit_exceeded = true;
            return;
        }
        page_scope.pending_entry = Some(PendingWordPressEntryObservation {
            signals: observation.signals,
            discovery: observation.discovery,
            page_candidates: observation.page_candidates,
            frozen_page_layout: observation.frozen_page_layout,
            parent_evidence_ids,
        });
    }

    pub(super) fn commit_staged_entry(
        &self,
        knowledge: &KnowledgeBase,
        expected_subject: &EntityId,
        expected_url: &Url,
    ) -> Result<(), WordPressReviewError> {
        let (signals, mut discovery, evidence_ids, entry_reference) = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(page_scope) = state.page_scope.as_mut() else {
                return Ok(());
            };
            let Some(pending) = page_scope.pending_entry.take() else {
                return Ok(());
            };
            if !committed_parent_evidence_is_valid(
                knowledge,
                &pending.parent_evidence_ids,
                expected_subject,
                expected_url,
            ) {
                return Err(WordPressReviewError::SignalLimitExceeded);
            }
            page_scope.selection = pending.page_candidates;
            page_scope.frozen_layout = pending.frozen_page_layout;
            (
                pending.signals,
                pending.discovery,
                pending.parent_evidence_ids,
                page_scope.entry_page_reference.clone(),
            )
        };
        for seed in &mut discovery.seeds {
            *seed = seed
                .clone()
                .with_source_page_reference(entry_reference.clone());
        }
        self.record(signals, discovery, evidence_ids);
        Ok(())
    }

    pub(super) fn selected_page(
        &self,
        url: &Url,
    ) -> Option<(WordPressPageCandidate, FrozenWordPressPageLayout)> {
        let state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let page_scope = state.page_scope.as_ref()?;
        let candidate = page_scope
            .selection
            .candidates
            .iter()
            .find(|candidate| &candidate.url == url)?;
        Some((candidate.clone(), page_scope.frozen_layout.clone()))
    }

    pub(super) fn stage_page(&self, observation: PendingWordPressPageObservation) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(page_scope) = state.page_scope.as_mut() else {
            return;
        };
        if page_scope
            .selection
            .candidates
            .iter()
            .any(|candidate| candidate == &observation.page)
        {
            page_scope
                .pending
                .entry(observation.page.url.as_str().to_owned())
                .or_insert(observation);
        }
    }

    pub(super) fn commit_staged_page(
        &self,
        knowledge: &KnowledgeBase,
        root_subject: &EntityId,
        page_subject: &EntityId,
        page_url: &Url,
    ) -> Result<(), WordPressReviewError> {
        let pending = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(page_scope) = state.page_scope.as_mut() else {
                return Ok(());
            };
            page_scope.pending.remove(page_url.as_str())
        };
        let Some(mut pending) = pending else {
            return Ok(());
        };
        if !committed_parent_evidence_is_valid(
            knowledge,
            &pending.parent_evidence_ids,
            page_subject,
            page_url,
        ) {
            return Err(WordPressReviewError::SignalLimitExceeded);
        }
        let already_interpreted = {
            let state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .page_scope
                .as_ref()
                .and_then(|page_scope| {
                    page_scope.pages.iter().try_fold(0_u64, |total, page| {
                        total.checked_add(page.interpreted_response_bytes)
                    })
                })
                .ok_or(WordPressReviewError::SignalLimitExceeded)?
        };
        if already_interpreted
            .checked_add(pending.interpreted_response_bytes)
            .is_none_or(|total| total > MAX_WORDPRESS_PAGE_INTERPRETED_BYTES)
        {
            pending.signals.clear();
            pending.discovery = WordPressDiscoverySeedSelection::default();
            pending.association = WordPressPageAssociation::Rejected;
            pending.outcome = WordPressPageOutcome::Truncated;
            pending.interpreted_response_bytes = 0;
        }
        let evidence = root_page_observation_evidence(
            root_subject,
            &pending.parent_evidence_ids,
            pending.page.page_reference.as_str(),
        )?;
        let evidence_id = evidence.id().clone();
        knowledge
            .insert_evidence_batch(vec![evidence])
            .map_err(|_| WordPressReviewError::SignalLimitExceeded)?;
        if pending.association == WordPressPageAssociation::Accepted {
            for seed in &mut pending.discovery.seeds {
                *seed = seed
                    .clone()
                    .with_source_evidence(evidence_id.clone())
                    .with_source_page_reference(pending.page.page_reference.clone());
            }
            self.record(pending.signals, pending.discovery, [evidence_id.clone()]);
        }
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let page_scope = state
            .page_scope
            .as_mut()
            .ok_or(WordPressReviewError::SignalLimitExceeded)?;
        if page_scope
            .pages
            .iter()
            .any(|page| page.page_reference == pending.page.page_reference)
        {
            return Err(WordPressReviewError::SignalLimitExceeded);
        }
        page_scope.pages.push(WordPressPageAudit {
            page_reference: pending.page.page_reference,
            acquisition: WordPressPageAcquisition::Reused,
            association: pending.association,
            outcome: pending.outcome,
            request_attempted: false,
            interpreted_response_bytes: pending.interpreted_response_bytes,
            response_bytes: 0,
            evidence_ids: vec![evidence_id],
        });
        Ok(())
    }

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
            let fingerprint = discovery_seed_fingerprint(&seed);
            if let Some(existing) = discovery_seeds
                .iter_mut()
                .find(|existing| discovery_seed_fingerprint(existing) == fingerprint)
            {
                existing.merge_source_provenance(&seed);
                retained_discovery_seed = true;
                continue;
            }
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
        if state
            .page_scope
            .as_ref()
            .is_some_and(|page_scope| page_scope.selection.candidate_identity_limit_exceeded)
        {
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

    fn finish_page_scope(&self) -> Result<Option<WordPressPageScopeAudit>, WordPressReviewError> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(page_scope) = state.page_scope.as_mut() else {
            return Ok(None);
        };
        if page_scope.pending_entry.is_some() || !page_scope.pending.is_empty() {
            return Err(WordPressReviewError::SignalLimitExceeded);
        }
        let mut pages_by_reference = page_scope
            .pages
            .drain(..)
            .map(|page| (page.page_reference.clone(), page))
            .collect::<BTreeMap<_, _>>();
        let mut pages = Vec::with_capacity(page_scope.selection.candidates.len());
        for candidate in &page_scope.selection.candidates {
            pages.push(
                pages_by_reference
                    .remove(&candidate.page_reference)
                    .unwrap_or(WordPressPageAudit {
                        page_reference: candidate.page_reference.clone(),
                        acquisition: WordPressPageAcquisition::NotObserved,
                        association: WordPressPageAssociation::NotEstablished,
                        outcome: WordPressPageOutcome::NotObserved,
                        request_attempted: false,
                        interpreted_response_bytes: 0,
                        response_bytes: 0,
                        evidence_ids: Vec::new(),
                    }),
            );
        }
        if !pages_by_reference.is_empty() {
            return Err(WordPressReviewError::SignalLimitExceeded);
        }
        let interpreted_response_bytes = pages.iter().try_fold(0_u64, |total, page| {
            total.checked_add(page.interpreted_response_bytes)
        });
        let response_bytes = pages
            .iter()
            .try_fold(0_u64, |total, page| total.checked_add(page.response_bytes));
        let count =
            |predicate: fn(&WordPressPageAudit) -> bool| -> Result<u8, WordPressReviewError> {
                u8::try_from(pages.iter().filter(|page| predicate(page)).count())
                    .map_err(|_| WordPressReviewError::SignalLimitExceeded)
            };
        let audit = WordPressPageScopeAudit {
            mode: page_scope.mode,
            entry_page_reference: page_scope.entry_page_reference.clone(),
            candidate_count: page_scope.selection.candidate_count,
            selected_count: u8::try_from(pages.len())
                .map_err(|_| WordPressReviewError::SignalLimitExceeded)?,
            omitted_candidate_count: page_scope.selection.omitted_candidate_count,
            reused_response_count: count(|page| {
                page.acquisition == WordPressPageAcquisition::Reused
            })?,
            fetched_response_count: count(|page| {
                page.acquisition == WordPressPageAcquisition::Fetched
            })?,
            not_observed_count: count(|page| {
                page.acquisition == WordPressPageAcquisition::NotObserved
            })?,
            rejected_response_count: count(|page| {
                page.association == WordPressPageAssociation::Rejected
            })?,
            accepted_association_count: count(|page| {
                page.association == WordPressPageAssociation::Accepted
            })?,
            rejected_association_count: count(|page| {
                page.association == WordPressPageAssociation::Rejected
            })?,
            attempted_request_count: count(|page| page.request_attempted)?,
            completed_response_count: count(|page| {
                page.acquisition != WordPressPageAcquisition::NotObserved
            })?,
            committed_response_count: u8::try_from(
                pages
                    .iter()
                    .filter(|page| !page.evidence_ids.is_empty())
                    .count(),
            )
            .map_err(|_| WordPressReviewError::SignalLimitExceeded)?,
            interpreted_response_bytes: interpreted_response_bytes
                .ok_or(WordPressReviewError::SignalLimitExceeded)?,
            response_bytes: response_bytes.ok_or(WordPressReviewError::SignalLimitExceeded)?,
            pages,
        };
        (audit.interpreted_response_bytes <= MAX_WORDPRESS_PAGE_INTERPRETED_BYTES)
            .then_some(Some(audit))
            .ok_or(WordPressReviewError::SignalLimitExceeded)
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

fn committed_parent_evidence_is_valid(
    knowledge: &KnowledgeBase,
    evidence_ids: &[EvidenceId],
    expected_subject: &EntityId,
    expected_url: &Url,
) -> bool {
    let exact_final_url = evidence_ids.iter().any(|id| {
        knowledge
            .inspect_evidence(id, |evidence| {
                evidence.predicate() == &HttpEvidencePredicate::RESPONSE_FINAL_URL.into_knowledge()
                    && evidence.value() == &EvidenceValue::Text(expected_url.to_string())
            })
            .unwrap_or(false)
    });
    let exact_request_url = evidence_ids.iter().any(|id| {
        knowledge
            .inspect_evidence(id, |evidence| {
                evidence.predicate() == &HttpEvidencePredicate::REQUEST_URL.into_knowledge()
                    && evidence.value() == &EvidenceValue::Text(expected_url.to_string())
            })
            .unwrap_or(false)
    });
    exact_final_url
        && exact_request_url
        && !evidence_ids.is_empty()
        && evidence_ids.len() <= 8
        && evidence_ids.iter().collect::<BTreeSet<_>>().len() == evidence_ids.len()
        && evidence_ids.iter().all(|id| {
            knowledge
                .inspect_evidence(id, |evidence| evidence.subject() == expected_subject)
                .unwrap_or(false)
        })
}

fn root_page_observation_evidence(
    root_subject: &EntityId,
    parents: &[EvidenceId],
    page_reference: &str,
) -> Result<Evidence, WordPressReviewError> {
    let predicate = KnowledgePredicate::new(
        "web.wordpress-page-discovery",
        "page-representation-observed",
    )
    .map_err(|_| WordPressReviewError::SignalLimitExceeded)?;
    let mut binding_digest = sha2::Sha256::new();
    binding_digest.update(page_reference.as_bytes());
    for parent in parents {
        binding_digest.update([0]);
        binding_digest.update(parent.to_string().as_bytes());
    }
    let source = EvidenceSource::new("wordpress.page-observation", "committed-html-response")
        .and_then(|source| source.with_correlation_id(page_reference.to_owned()))
        .map_err(|_| WordPressReviewError::SignalLimitExceeded)?;
    let reliability =
        ConfidenceScore::from_percent(70).map_err(|_| WordPressReviewError::SignalLimitExceeded)?;
    // The committed response evidence belongs to the secondary page subject,
    // while the existing WordPress discovery item belongs to the application
    // root. Knowledge derivations intentionally reject cross-subject parents,
    // so this sealed post-commit binding is a direct root-scoped fact. It is
    // minted only after the exact request/final URL and subject were verified.
    Ok(Evidence::new(
        root_subject.clone(),
        EvidenceKind::Content,
        predicate,
        EvidenceValue::Text(format!(
            "{page_reference}:sha256:{:x}",
            binding_digest.finalize()
        )),
        source,
        reliability,
    ))
}

pub(super) struct WordPressReviewBinding {
    inputs: WordPressReviewInputs,
    collector: WordPressSignalCollector,
    discovery_enabled: bool,
    discovery_audit: Option<WebAssessmentWordPressDiscoveryAudit>,
    discovery_context: WordPressDiscoveryContext,
    page_scope: Option<WordPressPageScope>,
    asset_fingerprint_collector: Option<WordPressAssetFingerprintCollector>,
    asset_fingerprint_audit: Option<WordPressAssetFingerprintExecution>,
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
        page_scope: Option<WordPressPageScope>,
        application_url: Url,
    ) -> Self {
        let collector = WordPressSignalCollector::new(page_scope, &application_url);
        let asset_fingerprint_collector = inputs
            .shared_asset_fingerprint_catalog()
            .map(WordPressAssetFingerprintCollector::new);
        let discovery_context =
            WordPressDiscoveryContext::new(application_url, inputs.discovery_layout().cloned());
        Self {
            inputs,
            collector,
            discovery_enabled,
            discovery_audit: None,
            discovery_context,
            page_scope,
            asset_fingerprint_collector,
            asset_fingerprint_audit: None,
        }
    }

    pub(super) fn collector(&self) -> WordPressSignalCollector {
        self.collector.clone()
    }

    pub(super) const fn discovery_enabled(&self) -> bool {
        self.discovery_enabled
    }

    pub(super) const fn page_scope(&self) -> Option<WordPressPageScope> {
        self.page_scope
    }

    pub(super) const fn asset_fingerprints_enabled(&self) -> bool {
        self.asset_fingerprint_collector.is_some()
    }

    pub(super) fn asset_fingerprint_collector(&self) -> Option<WordPressAssetFingerprintCollector> {
        self.asset_fingerprint_collector.clone()
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
        let mut execution = execute_wordpress_discovery(
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
        execution.audit.page_scope = self
            .collector
            .finish_page_scope()
            .map_err(|_| WordPressDiscoveryExecutionError::EvidenceModel)?;
        let stop = execution.stop;
        self.discovery_audit = Some(execution.audit);
        Ok(stop)
    }

    pub(super) async fn execute_asset_fingerprints(
        &mut self,
        subject: EntityId,
        authority: &super::SharedWebRuntimeAuthority,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<WordPressAssetFingerprintStop, WordPressAssetFingerprintRuntimeError> {
        let Some(collector) = self.asset_fingerprint_collector.as_ref() else {
            return Ok(WordPressAssetFingerprintStop::Complete);
        };
        if self.asset_fingerprint_audit.is_some() {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        let discovery = self
            .discovery_audit
            .as_ref()
            .ok_or(WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
        let page_attempts = discovery
            .page_scope()
            .map_or(0, WordPressPageScopeAudit::attempted_request_count);
        let page_bytes = discovery
            .page_scope()
            .map_or(0, WordPressPageScopeAudit::response_bytes);
        let prior_attempts = discovery
            .attempted_request_count()
            .checked_add(page_attempts)
            .ok_or(WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
        let prior_response_bytes = discovery
            .response_bytes()
            .checked_add(page_bytes)
            .ok_or(WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
        let allowance =
            WordPressAssetFingerprintAllowance::new(prior_attempts, prior_response_bytes, true)?;
        let execution = execute_wordpress_asset_fingerprints(
            collector.plan()?,
            authority,
            &subject,
            allowance,
            deadline,
        )
        .await?;
        let stop = execution.stop();
        self.asset_fingerprint_audit = Some(execution);
        Ok(stop)
    }

    pub(super) fn finish(
        self,
        subject: EntityId,
    ) -> Result<CommittedWordPressReview, WordPressReviewFinishError> {
        if self.discovery_enabled && self.discovery_audit.is_none()
            || self.asset_fingerprint_collector.is_some() && self.asset_fingerprint_audit.is_none()
        {
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
            asset_fingerprints: self.asset_fingerprint_audit,
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
    asset_fingerprints: Option<WordPressAssetFingerprintExecution>,
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
    pub fn additional_request_count(&self) -> u8 {
        let discovery = match &self.discovery {
            Some(discovery) => discovery.attempted_request_count().saturating_add(
                discovery
                    .page_scope()
                    .map_or(0, WordPressPageScopeAudit::attempted_request_count),
            ),
            None => 0,
        };
        discovery.saturating_add(self.asset_fingerprints.as_ref().map_or(
            0,
            WordPressAssetFingerprintExecution::attempted_request_count,
        ))
    }

    /// Returns the separately versioned, explicitly selected metadata audit.
    pub const fn discovery(&self) -> Option<&WebAssessmentWordPressDiscoveryAudit> {
        self.discovery.as_ref()
    }

    /// Returns the explicitly selected finite-catalogue byte-comparison audit.
    /// Candidate releases remain conditional matches, never installed versions.
    pub const fn asset_fingerprints(&self) -> Option<&WordPressAssetFingerprintExecution> {
        self.asset_fingerprints.as_ref()
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
    let mut discovery_evidence_ids = review
        .audit
        .discovery()
        .map(|discovery| {
            let mut evidence_ids = discovery
                .page_scope()
                .into_iter()
                .flat_map(WordPressPageScopeAudit::pages)
                .flat_map(WordPressPageAudit::evidence_ids)
                .cloned()
                .collect::<Vec<_>>();
            evidence_ids.extend(
                discovery
                    .sources()
                    .iter()
                    .flat_map(WordPressDiscoverySourceAudit::evidence_ids)
                    .cloned(),
            );
            evidence_ids
        })
        .unwrap_or_default();
    if let Some(fingerprints) = review.audit.asset_fingerprints() {
        discovery_evidence_ids.extend(
            fingerprints
                .resources()
                .iter()
                .flat_map(WordPressAssetFingerprintResourceReceipt::evidence_ids)
                .cloned(),
        );
    }
    discovery_evidence_ids.sort();
    discovery_evidence_ids.dedup();
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
#[cfg(any(test, fuzzing))]
pub(super) fn extract_wordpress_entry_observation(
    context: &WordPressDiscoveryContext,
    document_url: &Url,
    html: &str,
    rest_header: &WordPressRestIndexAdvertisement,
    discovery_enabled: bool,
    page_scope_selected: bool,
) -> WordPressEntryObservation {
    extract_wordpress_entry_observation_with_asset_fingerprints(
        context,
        document_url,
        html,
        rest_header,
        discovery_enabled,
        page_scope_selected,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn extract_wordpress_entry_observation_with_asset_fingerprints(
    context: &WordPressDiscoveryContext,
    document_url: &Url,
    html: &str,
    rest_header: &WordPressRestIndexAdvertisement,
    discovery_enabled: bool,
    page_scope_selected: bool,
    asset_fingerprints_selected: bool,
) -> WordPressEntryObservation {
    let mut selection = WordPressDiscoverySeedSelection {
        layout: Some(context.unresolved_audit()),
        ..WordPressDiscoverySeedSelection::default()
    };
    let mut signals = Vec::new();
    let mut page_candidate_urls = BTreeMap::<String, Url>::new();
    let mut page_candidate_identities = BTreeSet::<[u8; 32]>::new();
    let mut page_candidate_identity_limit_exceeded = false;
    if document_url != context.application_url() {
        return WordPressEntryObservation {
            signals,
            discovery: selection,
            page_candidates: WordPressPageCandidateSelection::default(),
            frozen_page_layout: FrozenWordPressPageLayout::default(),
            asset_fingerprint_candidates: Vec::new(),
            asset_fingerprint_candidate_limit_exceeded: false,
        };
    }
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let resolution_base = effective_document_base(&dom.document, document_url);
    let mut assets = Vec::new();
    let mut fingerprint_references = BTreeMap::<String, ObservedAssetReference>::new();
    let mut fingerprint_reference_limit_exceeded = false;
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
                if page_scope_selected && local == "a" && !html_has_attribute(attrs, "download") {
                    if let (Some(reference), Some(base)) =
                        (html_attribute(attrs, "href"), resolution_base.as_ref())
                    {
                        if let Some(candidate) = eligible_wordpress_page_candidate(
                            context,
                            document_url,
                            base,
                            &reference,
                        ) {
                            let fingerprint = page_url_fingerprint(&candidate);
                            if !page_candidate_identities.contains(&fingerprint) {
                                if page_candidate_identities.len()
                                    == MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
                                {
                                    page_candidate_identity_limit_exceeded = true;
                                } else {
                                    page_candidate_identities.insert(fingerprint);
                                    page_candidate_urls
                                        .insert(candidate.as_str().to_owned(), candidate);
                                    if page_candidate_urls.len() > MAX_WORDPRESS_PAGE_CANDIDATES {
                                        if let Some(last) =
                                            page_candidate_urls.keys().next_back().cloned()
                                        {
                                            page_candidate_urls.remove(&last);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                let fingerprint_reference = asset_fingerprints_selected
                    .then(|| match local {
                        "script" => html_attribute(attrs, "src"),
                        "link" if link_has_stylesheet_relation(attrs) => {
                            html_attribute(attrs, "href")
                        },
                        _ => None,
                    })
                    .flatten();
                if let (Some(reference), Some(base)) =
                    (fingerprint_reference, resolution_base.as_ref())
                {
                    if crate::http_evidence::wordpress_reference_path_is_safe(&reference) {
                        if let Ok(url) = base.join(&reference) {
                            if safe_observed_asset_url(document_url, &url)
                                && asset_is_layout_candidate(context, &url)
                            {
                                let identity = url.as_str().to_owned();
                                if let Some(existing) = fingerprint_references.get_mut(&identity) {
                                    if reference < existing.raw_reference {
                                        existing.raw_reference.clone_from(&reference);
                                        existing.resolution_base.clone_from(base);
                                    }
                                } else if fingerprint_references.len()
                                    == MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES
                                {
                                    fingerprint_reference_limit_exceeded = true;
                                } else {
                                    fingerprint_references.insert(
                                        identity,
                                        ObservedAssetReference {
                                            raw_reference: reference,
                                            resolution_base: base.clone(),
                                            resolved_url: url,
                                        },
                                    );
                                }
                            }
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
            page_candidates: WordPressPageCandidateSelection::default(),
            frozen_page_layout: FrozenWordPressPageLayout::default(),
            asset_fingerprint_candidates: Vec::new(),
            asset_fingerprint_candidate_limit_exceeded: fingerprint_reference_limit_exceeded,
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
    let frozen_page_layout = freeze_page_layout(context, &mut selection);
    let asset_fingerprint_candidates = if asset_fingerprints_selected {
        observed_asset_fingerprint_candidates(
            context.application_url(),
            document_url,
            &frozen_page_layout,
            super::wordpress_discovery::opaque_url_reference(
                "wordpress-discovery-page",
                document_url,
            ),
            fingerprint_references.into_values(),
        )
    } else {
        Vec::new()
    };
    let page_candidates = select_wordpress_page_candidates(
        page_candidate_urls.into_values(),
        page_candidate_identities.len(),
        page_candidate_identity_limit_exceeded,
    );
    WordPressEntryObservation {
        signals,
        discovery: selection,
        page_candidates,
        frozen_page_layout,
        asset_fingerprint_candidates,
        asset_fingerprint_candidate_limit_exceeded: fingerprint_reference_limit_exceeded,
    }
}

pub(super) fn extract_wordpress_page_observation_with_asset_fingerprints(
    page: WordPressPageCandidate,
    frozen: &FrozenWordPressPageLayout,
    html: &str,
    parent_evidence_ids: Vec<EvidenceId>,
    asset_fingerprints_selected: bool,
) -> PendingWordPressPageObservation {
    let mut observation = PendingWordPressPageObservation {
        page: page.clone(),
        signals: Vec::new(),
        discovery: WordPressDiscoverySeedSelection::default(),
        association: WordPressPageAssociation::NotEstablished,
        outcome: WordPressPageOutcome::NoComponentSignals,
        interpreted_response_bytes: u64::try_from(html.len()).unwrap_or(u64::MAX),
        parent_evidence_ids,
        asset_fingerprint_candidates: Vec::new(),
        asset_fingerprint_candidate_limit_exceeded: false,
    };
    if html.len() > MAX_WORDPRESS_PAGE_RESPONSE_BYTES
        || observation.interpreted_response_bytes > MAX_WORDPRESS_PAGE_INTERPRETED_BYTES
    {
        observation.outcome = WordPressPageOutcome::Truncated;
        observation.interpreted_response_bytes = 0;
        return observation;
    }
    let Some(application_url) = frozen.application_url.as_ref() else {
        observation.association = WordPressPageAssociation::Rejected;
        observation.outcome = WordPressPageOutcome::IncompatibleApplication;
        return observation;
    };
    if page.url.origin() != application_url.origin()
        || !directory_is_within_application(application_url, &page.url)
    {
        observation.association = WordPressPageAssociation::Rejected;
        observation.outcome = WordPressPageOutcome::IncompatibleApplication;
        return observation;
    }
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let resolution_base = effective_document_base(&dom.document, &page.url);
    let mut pending = vec![dom.document.clone()];
    let mut conflicting_application_signal = false;
    let mut soft_404 = false;
    let mut login_response = false;
    let mut assets = BTreeMap::<String, Url>::new();
    let mut fingerprint_references = BTreeMap::<String, ObservedAssetReference>::new();
    let mut fingerprint_reference_limit_exceeded = false;
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) {
                let local = name.local.as_ref();
                if let Some(classes) = html_attribute(attrs, "class") {
                    soft_404 |= classes
                        .split_ascii_whitespace()
                        .any(|class| matches!(class, "error404" | "error-404" | "not-found"));
                }
                if let Some(id) = html_attribute(attrs, "id") {
                    login_response |= matches!(id.as_str(), "login" | "loginform");
                }
                if local == "form"
                    && html_attribute(attrs, "action")
                        .is_some_and(|action| action.contains("wp-login.php"))
                {
                    login_response = true;
                }
                if local == "link" && link_has_relation(attrs, "https://api.w.org/") {
                    if let (Some(reference), Some(base)) =
                        (html_attribute(attrs, "href"), resolution_base.as_ref())
                    {
                        if let Some(candidate) =
                            projected_rest_candidate(&page.url, base, &reference)
                        {
                            conflicting_application_signal |= rest_candidate_base(&candidate)
                                .is_none_or(|base| base != *application_url);
                        }
                    }
                }
                let fingerprint_reference = asset_fingerprints_selected
                    .then(|| match local {
                        "script" => html_attribute(attrs, "src"),
                        "link" if link_has_stylesheet_relation(attrs) => {
                            html_attribute(attrs, "href")
                        },
                        _ => None,
                    })
                    .flatten();
                if let (Some(reference), Some(base)) =
                    (fingerprint_reference, resolution_base.as_ref())
                {
                    if crate::http_evidence::wordpress_reference_path_is_safe(&reference) {
                        if let Ok(url) = base.join(&reference) {
                            if safe_observed_asset_url(&page.url, &url)
                                && asset_is_component_candidate(&url, frozen)
                            {
                                let identity = url.as_str().to_owned();
                                if let Some(existing) = fingerprint_references.get_mut(&identity) {
                                    if reference < existing.raw_reference {
                                        existing.raw_reference.clone_from(&reference);
                                        existing.resolution_base.clone_from(base);
                                    }
                                } else if fingerprint_references.len()
                                    == MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES
                                {
                                    fingerprint_reference_limit_exceeded = true;
                                } else {
                                    fingerprint_references.insert(
                                        identity,
                                        ObservedAssetReference {
                                            raw_reference: reference,
                                            resolution_base: base.clone(),
                                            resolved_url: url,
                                        },
                                    );
                                }
                            }
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
                    if crate::http_evidence::wordpress_reference_path_is_safe(&reference) {
                        if let Ok(url) = base.join(&reference) {
                            if safe_observed_asset_url(&page.url, &url)
                                && asset_is_component_candidate(&url, frozen)
                            {
                                assets.insert(url.as_str().to_owned(), url);
                            }
                        }
                    }
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    if login_response {
        observation.association = WordPressPageAssociation::Rejected;
        observation.outcome = WordPressPageOutcome::LoginResponse;
        observation.interpreted_response_bytes = 0;
        return observation;
    }
    if soft_404 {
        observation.association = WordPressPageAssociation::Rejected;
        observation.outcome = WordPressPageOutcome::Soft404;
        observation.interpreted_response_bytes = 0;
        return observation;
    }
    for asset in assets.into_values() {
        let mut matched_bindings = Vec::new();
        for (kind, binding) in [
            (WordPressComponentKind::Theme, frozen.themes.as_ref()),
            (WordPressComponentKind::Plugin, frozen.plugins.as_ref()),
        ] {
            let Some(binding) = binding else {
                continue;
            };
            if let Some(component) = component_under_role_base(&asset, &binding.base_url, kind) {
                matched_bindings.push((component.clone(), binding.base_url.clone()));
                if let Ok(signal) =
                    WordPressComponentSignal::same_origin_asset(kind, component.slug())
                {
                    push_bounded_signal(&mut observation.signals, signal);
                }
                let filename = match kind {
                    WordPressComponentKind::Theme => "style.css",
                    WordPressComponentKind::Plugin => "readme.txt",
                    WordPressComponentKind::Core => continue,
                };
                if let Some(resource) =
                    exact_role_resource(&binding.base_url, component.slug(), filename)
                {
                    observation.discovery.insert(
                        WordPressDiscoverySeed::admitted_component(
                            resource,
                            application_url.clone(),
                            binding.base_url.clone(),
                            binding.association,
                            component,
                            0,
                        )
                        .with_source_page_reference(page.page_reference.clone()),
                    );
                }
            }
        }
        match conventional_component_asset(&asset) {
            ConventionalComponentResult::MultipleContentMarkers => {
                conflicting_application_signal = true;
            },
            ConventionalComponentResult::Observed(observation) => {
                if !matched_bindings.contains(&(observation.component, observation.role_base)) {
                    conflicting_application_signal = true;
                }
            },
            ConventionalComponentResult::NotComponent => {},
        }
    }
    if conflicting_application_signal {
        observation.signals.clear();
        observation.discovery = WordPressDiscoverySeedSelection::default();
        observation.association = WordPressPageAssociation::Rejected;
        observation.outcome = WordPressPageOutcome::IncompatibleApplication;
    } else if observation.signals.is_empty() {
        observation.association = WordPressPageAssociation::NotEstablished;
        observation.outcome = WordPressPageOutcome::NoComponentSignals;
    } else {
        observation.association = WordPressPageAssociation::Accepted;
        observation.outcome = WordPressPageOutcome::Accepted;
        if asset_fingerprints_selected {
            observation.asset_fingerprint_candidates = observed_asset_fingerprint_candidates(
                application_url,
                &page.url,
                frozen,
                page.page_reference,
                fingerprint_references.into_values(),
            );
            observation.asset_fingerprint_candidate_limit_exceeded =
                fingerprint_reference_limit_exceeded;
        }
    }
    observation
}

fn asset_is_component_candidate(url: &Url, frozen: &FrozenWordPressPageLayout) -> bool {
    !matches!(
        conventional_component_asset(url),
        ConventionalComponentResult::NotComponent
    ) || [
        (WordPressComponentKind::Theme, frozen.themes.as_ref()),
        (WordPressComponentKind::Plugin, frozen.plugins.as_ref()),
    ]
    .into_iter()
    .any(|(kind, binding)| {
        binding.is_some_and(|binding| {
            component_under_role_base(url, &binding.base_url, kind).is_some()
        })
    })
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
        false,
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

fn observed_asset_fingerprint_candidates(
    application_url: &Url,
    document_url: &Url,
    frozen: &FrozenWordPressPageLayout,
    source_page_reference: String,
    references: impl IntoIterator<Item = ObservedAssetReference>,
) -> Vec<WordPressObservedAssetCandidate> {
    let mut candidates = Vec::new();
    for reference in references {
        for (kind, binding) in [
            (WordPressComponentKind::Theme, frozen.themes.as_ref()),
            (WordPressComponentKind::Plugin, frozen.plugins.as_ref()),
        ] {
            let Some(binding) = binding else {
                continue;
            };
            let Some(component) =
                component_under_role_base(&reference.resolved_url, &binding.base_url, kind)
            else {
                continue;
            };
            let Some(relative_path) = component_relative_asset_path(
                &reference.resolved_url,
                &binding.base_url,
                component.slug(),
            ) else {
                continue;
            };
            if let Ok(candidate) = WordPressObservedAssetCandidate::from_html_reference(
                application_url,
                &binding.base_url,
                component,
                binding.association,
                document_url,
                &reference.resolution_base,
                &reference.raw_reference,
                &reference.resolved_url,
                relative_path,
                source_page_reference.clone(),
            ) {
                candidates.push(candidate);
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn component_relative_asset_path(resource: &Url, base: &Url, slug: &str) -> Option<String> {
    if resource.origin() != base.origin() {
        return None;
    }
    let resource_segments = url_segments(resource);
    let base_segments = url_segments(base);
    if resource_segments.get(base_segments.len()).copied() != Some(slug) {
        return None;
    }
    let relative = resource_segments.get(base_segments.len().saturating_add(1)..)?;
    (!relative.is_empty()).then(|| relative.join("/"))
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

fn page_url_fingerprint(url: &Url) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"termivar.wordpress-page-candidate/v1");
    digest.update(
        u64::try_from(url.as_str().len())
            .expect("bounded page URL length fits u64")
            .to_be_bytes(),
    );
    digest.update(url.as_str().as_bytes());
    digest.finalize().into()
}

fn eligible_wordpress_page_candidate(
    context: &WordPressDiscoveryContext,
    document_url: &Url,
    resolution_base: &Url,
    reference: &str,
) -> Option<Url> {
    const MAX_RAW_PAGE_REFERENCE_BYTES: usize = 2_048;
    if reference.is_empty()
        || reference.len() > MAX_RAW_PAGE_REFERENCE_BYTES
        || reference != reference.trim()
        || reference.contains(['?', '#', '\\'])
        || reference.starts_with("//")
        || !crate::http_evidence::wordpress_reference_path_is_safe(reference)
    {
        return None;
    }
    let candidate = resolution_base.join(reference).ok()?;
    if candidate == *document_url
        || candidate.origin() != context.application_url().origin()
        || candidate.query().is_some()
        || candidate.fragment().is_some()
        || !safe_resource_shape(&candidate)
        || !directory_is_within_application(context.application_url(), &candidate)
    {
        return None;
    }
    let segments = url_segments(&candidate);
    if segments.is_empty()
        || segments.iter().any(|segment| {
            matches!(
                segment.to_ascii_lowercase().as_str(),
                "wp-admin"
                    | "wp-login.php"
                    | "wp-json"
                    | "xmlrpc.php"
                    | "logout"
                    | "login"
                    | "feed"
                    | "download"
                    | "downloads"
                    | "action"
                    | "actions"
            )
        })
    {
        return None;
    }
    let final_segment = segments.last().copied().unwrap_or_default();
    let lower = final_segment.to_ascii_lowercase();
    if [
        ".css", ".js", ".json", ".xml", ".txt", ".pdf", ".zip", ".gz", ".jpg", ".jpeg", ".png",
        ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
        ".webm",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
    {
        return None;
    }
    Some(candidate)
}

fn select_wordpress_page_candidates(
    candidates: impl IntoIterator<Item = Url>,
    distinct_candidate_count: usize,
    candidate_identity_limit_exceeded: bool,
) -> WordPressPageCandidateSelection {
    let mut candidates = candidates.into_iter().collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    candidates.dedup();
    candidates.truncate(MAX_WORDPRESS_SELECTED_PAGES);
    let candidate_count = u16::try_from(distinct_candidate_count).unwrap_or(u16::MAX);
    let selected_count = u16::try_from(candidates.len()).unwrap_or(u16::MAX);
    WordPressPageCandidateSelection {
        candidates: candidates
            .into_iter()
            .map(|url| WordPressPageCandidate {
                page_reference: super::wordpress_discovery::opaque_url_reference(
                    "wordpress-discovery-page",
                    &url,
                ),
                url,
            })
            .collect(),
        candidate_count,
        omitted_candidate_count: candidate_count.saturating_sub(selected_count),
        candidate_identity_limit_exceeded,
    }
}

fn freeze_page_layout(
    context: &WordPressDiscoveryContext,
    selection: &mut WordPressDiscoverySeedSelection,
) -> FrozenWordPressPageLayout {
    let mut frozen = FrozenWordPressPageLayout {
        application_url: Some(context.application_url().clone()),
        themes: context
            .declared_layout()
            .and_then(WordPressDiscoveryLayout::themes_base_url)
            .cloned()
            .map(|base_url| FrozenWordPressRoleBinding {
                base_url,
                association: WordPressDiscoveryAssociation::ExplicitOperator,
            }),
        plugins: context
            .declared_layout()
            .and_then(WordPressDiscoveryLayout::plugins_base_url)
            .cloned()
            .map(|base_url| FrozenWordPressRoleBinding {
                base_url,
                association: WordPressDiscoveryAssociation::ExplicitOperator,
            }),
    };
    for seed in &selection.seeds {
        match seed.kind() {
            WordPressDiscoverySourceKind::ThemeStylesheet if frozen.themes.is_none() => {
                frozen.themes = Some(FrozenWordPressRoleBinding {
                    base_url: seed.role_base_url().clone(),
                    association: seed.association(),
                });
            },
            WordPressDiscoverySourceKind::PluginReadme if frozen.plugins.is_none() => {
                frozen.plugins = Some(FrozenWordPressRoleBinding {
                    base_url: seed.role_base_url().clone(),
                    association: seed.association(),
                });
            },
            _ => {},
        }
    }
    let conventional_content_base = selection
        .seeds
        .iter()
        .filter_map(|seed| {
            let role = match seed.kind() {
                WordPressDiscoverySourceKind::ThemeStylesheet => "themes",
                WordPressDiscoverySourceKind::PluginReadme => "plugins",
                WordPressDiscoverySourceKind::RestIndex => return None,
            };
            let url = seed.role_base_url();
            let mut segments = url_segments(url);
            let role_matches = segments.pop() == Some(role);
            let content_matches = segments.last().copied() == Some("wp-content");
            (role_matches
                && content_matches
                && directory_is_within_application(context.application_url(), url))
            .then(|| directory_from_segments(url, &segments))?
        })
        .collect::<BTreeSet<_>>();
    if conventional_content_base.len() == 1 {
        let content_base = conventional_content_base.iter().next().expect("one base");
        if frozen.themes.is_none() {
            frozen.themes =
                content_base
                    .join("themes/")
                    .ok()
                    .map(|base_url| FrozenWordPressRoleBinding {
                        base_url,
                        association: WordPressDiscoveryAssociation::ObservedConventional,
                    });
            if let (Some(layout), Some(binding)) =
                (selection.layout.as_mut(), frozen.themes.as_ref())
            {
                set_layout_role(
                    layout,
                    WordPressDiscoveryLayoutRole::Themes,
                    WordPressDiscoveryLayoutStatus::Exact,
                    WordPressDiscoveryLayoutBasis::ConventionalAsset,
                    Some(&binding.base_url),
                    1,
                );
            }
        }
        if frozen.plugins.is_none() {
            frozen.plugins =
                content_base
                    .join("plugins/")
                    .ok()
                    .map(|base_url| FrozenWordPressRoleBinding {
                        base_url,
                        association: WordPressDiscoveryAssociation::ObservedConventional,
                    });
            if let (Some(layout), Some(binding)) =
                (selection.layout.as_mut(), frozen.plugins.as_ref())
            {
                set_layout_role(
                    layout,
                    WordPressDiscoveryLayoutRole::Plugins,
                    WordPressDiscoveryLayoutStatus::Exact,
                    WordPressDiscoveryLayoutBasis::ConventionalAsset,
                    Some(&binding.base_url),
                    1,
                );
            }
        }
    }
    frozen
}

fn html_has_attribute(
    attrs: &std::cell::RefCell<Vec<html5ever::Attribute>>,
    local_name: &str,
) -> bool {
    attrs
        .borrow()
        .iter()
        .any(|attribute| attribute.name.ns == ns!() && attribute.name.local.as_ref() == local_name)
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

fn link_has_stylesheet_relation(attrs: &std::cell::RefCell<Vec<html5ever::Attribute>>) -> bool {
    html_attribute(attrs, "rel").is_some_and(|relations| {
        relations
            .split_ascii_whitespace()
            .any(|relation| relation.eq_ignore_ascii_case("stylesheet"))
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
            false,
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
            false,
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
            false,
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
            false,
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
                false,
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
            false,
        );

        assert!(!observation.discovery.candidate_identity_limit_exceeded);
        assert_eq!(
            seed_urls(&observation.discovery),
            vec!["https://example.test/wp-content/plugins/retained/readme.txt"]
        );
    }

    #[test]
    fn page_candidates_are_anchor_only_query_free_and_application_scoped() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let observation = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<a href="/blog/contact">contact</a>
                <a href="/blog/gallery/">gallery</a>
                <a href="/blog/contact#team">fragment</a>
                <a href="/blog/?page_id=123">query</a>
                <a href="/blog/download/file">download route</a>
                <a href="/blog/wp-admin/edit.php">admin</a>
                <a href="/blogger/contact">sibling prefix</a>
                <a href="https://other.test/blog/contact">foreign</a>
                <a href="/blog/ignored" download>download attribute</a>
                <form action="/blog/form-only"></form>
                <script src="/blog/asset-only"></script>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );

        assert_eq!(observation.page_candidates.candidate_count, 2);
        assert_eq!(observation.page_candidates.omitted_candidate_count, 0);
        assert_eq!(
            observation
                .page_candidates
                .candidates
                .iter()
                .map(|candidate| candidate.url.as_str())
                .collect::<Vec<_>>(),
            [
                "https://example.test/blog/contact",
                "https://example.test/blog/gallery/",
            ]
        );
    }

    #[test]
    fn page_candidate_top_k_is_stable_and_identity_overflow_fails_closed() {
        let ordered = (0..40)
            .rev()
            .map(|index| format!(r#"<a href="/page-{index:04}">page</a>"#))
            .collect::<String>();
        let first = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(origin(), None),
            &origin(),
            &ordered,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        let ascending = (0..40)
            .map(|index| format!(r#"<a href="/page-{index:04}">page</a>"#))
            .collect::<String>();
        let second = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(origin(), None),
            &origin(),
            &ascending,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        assert_eq!(first.page_candidates.candidate_count, 40);
        assert_eq!(first.page_candidates.omitted_candidate_count, 37);
        assert_eq!(
            first.page_candidates.candidates,
            second.page_candidates.candidates
        );
        assert_eq!(
            first
                .page_candidates
                .candidates
                .iter()
                .map(|candidate| candidate.url.path())
                .collect::<Vec<_>>(),
            ["/page-0000", "/page-0001", "/page-0002"]
        );

        let over_limit = (0..=MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES)
            .map(|index| format!(r#"<a href="/candidate-{index}">page</a>"#))
            .collect::<String>();
        let over_limit = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(origin(), None),
            &origin(),
            &over_limit,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        assert!(over_limit.page_candidates.candidate_identity_limit_exceeded);
        assert_eq!(
            usize::from(over_limit.page_candidates.candidate_count),
            MAX_WORDPRESS_DISCOVERY_CANDIDATE_IDENTITIES
        );
    }

    #[test]
    fn secondary_page_cannot_replace_the_frozen_application_layout() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let entry = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<a href="/blog/contact">contact</a>
                <script src="/blog/wp-content/plugins/entry-plugin/app.js"></script>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        let candidate = entry.page_candidates.candidates[0].clone();
        let page = extract_wordpress_page_observation_with_asset_fingerprints(
            candidate,
            &entry.frozen_page_layout,
            r#"<meta name="generator" content="WordPress 99.0">
                <link rel="https://api.w.org/" href="/shop/wp-json/">
                <script src="/shop/wp-content/plugins/sibling/app.js"></script>
                <script src="/blog/wp-content/plugins/tempting/app.js"></script>"#,
            Vec::new(),
            true,
        );

        assert_eq!(page.association, WordPressPageAssociation::Rejected);
        assert_eq!(page.outcome, WordPressPageOutcome::IncompatibleApplication);
        assert!(page.signals.is_empty());
        assert!(page.discovery.seeds.is_empty());
        assert!(page.asset_fingerprint_candidates.is_empty());
    }

    #[test]
    fn secondary_pages_preserve_declared_custom_role_bindings() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let declared = parse_wordpress_discovery_layout(
            br#"{
              "schema":"security.wordpress-layout/v1",
              "application_url":"https://example.test/blog/",
              "themes_base_url":"https://example.test/site-content/themes/",
              "plugins_base_url":"https://example.test/modules/"
            }"#,
        )
        .unwrap();
        let entry = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), Some(declared)),
            &application,
            r#"<a href="/blog/contact/">contact</a>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        let candidate = entry.page_candidates.candidates[0].clone();
        let html = r#"<script src="/modules/conditional/assets/fingerprint.js?ver=cache-42"></script>
            <link rel="stylesheet" href="/modules/conditional/assets/fingerprint.css?ver=cache-42">"#;

        let without_fingerprints = extract_wordpress_page_observation_with_asset_fingerprints(
            candidate.clone(),
            &entry.frozen_page_layout,
            html,
            Vec::new(),
            false,
        );
        assert_eq!(
            without_fingerprints.association,
            WordPressPageAssociation::Accepted
        );
        assert_eq!(without_fingerprints.discovery.seeds().len(), 1);
        assert_eq!(
            without_fingerprints.discovery.seeds()[0].association(),
            WordPressDiscoveryAssociation::ExplicitOperator
        );
        assert_eq!(
            without_fingerprints.discovery.seeds()[0].url().as_str(),
            "https://example.test/modules/conditional/readme.txt"
        );
        assert!(without_fingerprints.asset_fingerprint_candidates.is_empty());

        let with_fingerprints = extract_wordpress_page_observation_with_asset_fingerprints(
            candidate,
            &entry.frozen_page_layout,
            html,
            Vec::new(),
            true,
        );
        assert_eq!(
            with_fingerprints.association,
            WordPressPageAssociation::Accepted
        );
        assert_eq!(with_fingerprints.discovery.seeds().len(), 1);
        assert_eq!(
            with_fingerprints.discovery.seeds()[0].association(),
            WordPressDiscoveryAssociation::ExplicitOperator
        );
        assert_eq!(with_fingerprints.asset_fingerprint_candidates.len(), 2);
        assert!(with_fingerprints
            .asset_fingerprint_candidates
            .iter()
            .all(|candidate| candidate.component().slug() == "conditional"));
    }

    #[test]
    fn secondary_custom_roles_require_a_frozen_binding_and_retain_conflicts() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let unresolved = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<a href="/blog/contact/">contact</a>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        let unresolved_page = extract_wordpress_page_observation_with_asset_fingerprints(
            unresolved.page_candidates.candidates[0].clone(),
            &unresolved.frozen_page_layout,
            r#"<script src="/modules/conditional/assets/app.js"></script>"#,
            Vec::new(),
            true,
        );
        assert_eq!(
            unresolved_page.association,
            WordPressPageAssociation::NotEstablished
        );
        assert!(unresolved_page.discovery.seeds().is_empty());
        assert!(unresolved_page.asset_fingerprint_candidates.is_empty());

        let declared = parse_wordpress_discovery_layout(
            br#"{
              "schema":"security.wordpress-layout/v1",
              "application_url":"https://example.test/blog/",
              "plugins_base_url":"https://example.test/modules/"
            }"#,
        )
        .unwrap();
        let frozen = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), Some(declared)),
            &application,
            r#"<a href="/blog/contact/">contact</a>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        let lookalike = extract_wordpress_page_observation_with_asset_fingerprints(
            frozen.page_candidates.candidates[0].clone(),
            &frozen.frozen_page_layout,
            r#"<script src="/modules-evil/conditional/assets/app.js"></script>"#,
            Vec::new(),
            true,
        );
        assert_eq!(
            lookalike.association,
            WordPressPageAssociation::NotEstablished
        );
        assert!(lookalike.discovery.seeds().is_empty());

        let conflicting = extract_wordpress_page_observation_with_asset_fingerprints(
            frozen.page_candidates.candidates[0].clone(),
            &frozen.frozen_page_layout,
            r#"<script src="/modules/conditional/assets/app.js"></script>
                <script src="/blog/wp-content/plugins/sibling/assets/app.js"></script>"#,
            Vec::new(),
            true,
        );
        assert_eq!(conflicting.association, WordPressPageAssociation::Rejected);
        assert_eq!(
            conflicting.outcome,
            WordPressPageOutcome::IncompatibleApplication
        );
        assert!(conflicting.signals.is_empty());
        assert!(conflicting.discovery.seeds().is_empty());
        assert!(conflicting.asset_fingerprint_candidates.is_empty());

        let nested_conflict = extract_wordpress_page_observation_with_asset_fingerprints(
            frozen.page_candidates.candidates[0].clone(),
            &frozen.frozen_page_layout,
            r#"<script src="/modules/conditional/vendor/wp-content/plugins/sibling/app.js"></script>"#,
            Vec::new(),
            true,
        );
        assert_eq!(
            nested_conflict.association,
            WordPressPageAssociation::Rejected
        );
        assert_eq!(
            nested_conflict.outcome,
            WordPressPageOutcome::IncompatibleApplication
        );
        assert!(nested_conflict.signals.is_empty());
        assert!(nested_conflict.discovery.seeds().is_empty());
        assert!(nested_conflict.asset_fingerprint_candidates.is_empty());

        let same_slug_nested_base = extract_wordpress_page_observation_with_asset_fingerprints(
            frozen.page_candidates.candidates[0].clone(),
            &frozen.frozen_page_layout,
            r#"<script src="/modules/conditional/vendor/wp-content/plugins/conditional/app.js"></script>"#,
            Vec::new(),
            true,
        );
        assert_eq!(
            same_slug_nested_base.association,
            WordPressPageAssociation::Rejected
        );
        assert_eq!(
            same_slug_nested_base.outcome,
            WordPressPageOutcome::IncompatibleApplication
        );
        assert!(same_slug_nested_base.signals.is_empty());
        assert!(same_slug_nested_base.discovery.seeds().is_empty());
        assert!(same_slug_nested_base
            .asset_fingerprint_candidates
            .is_empty());

        let declared_theme = parse_wordpress_discovery_layout(
            br#"{
              "schema":"security.wordpress-layout/v1",
              "application_url":"https://example.test/blog/",
              "themes_base_url":"https://example.test/site-content/themes/"
            }"#,
        )
        .unwrap();
        let theme_entry = extract_wordpress_entry_observation(
            &WordPressDiscoveryContext::new(application.clone(), Some(declared_theme)),
            &application,
            r#"<a href="/blog/contact/">contact</a>
                <link rel="stylesheet" href="/site-content/themes/child/assets/site.css">"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            true,
        );
        let invented_sibling = extract_wordpress_page_observation_with_asset_fingerprints(
            theme_entry.page_candidates.candidates[0].clone(),
            &theme_entry.frozen_page_layout,
            r#"<script src="/site-content/plugins/not-declared/assets/app.js"></script>"#,
            Vec::new(),
            false,
        );
        assert_eq!(
            invented_sibling.association,
            WordPressPageAssociation::NotEstablished
        );
        assert!(invented_sibling.discovery.seeds().is_empty());
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
    fn fingerprint_candidates_are_only_observed_script_and_stylesheet_resources() {
        let application = origin();
        let observation = extract_wordpress_entry_observation_with_asset_fingerprints(
            &WordPressDiscoveryContext::new(application.clone(), None),
            &application,
            r#"<script src="/wp-content/plugins/cache-tool/assets/app.js?ver=cache-42"></script>
                <link rel="stylesheet preload" href="/wp-content/themes/child/assets/site.css">
                <link rel="icon" href="/wp-content/plugins/cache-tool/assets/icon.css">
                <img src="/wp-content/plugins/cache-tool/assets/image.js">
                <script src="/wp-content/plugins/cache-tool/assets/bad.js?ver=1&amp;x=2"></script>
                <script src="https://other.test/wp-content/plugins/cache-tool/assets/foreign.js"></script>"#,
            &WordPressRestIndexAdvertisement::Missing,
            true,
            false,
            true,
        );

        let actual = observation
            .asset_fingerprint_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.component().kind(),
                    candidate.component().slug(),
                    candidate.relative_path(),
                    candidate.target_url().as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual,
            BTreeSet::from([
                (
                    WordPressComponentKind::Plugin,
                    "cache-tool",
                    "assets/app.js",
                    "https://example.test/wp-content/plugins/cache-tool/assets/app.js?ver=cache-42",
                ),
                (
                    WordPressComponentKind::Theme,
                    "child",
                    "assets/site.css",
                    "https://example.test/wp-content/themes/child/assets/site.css",
                ),
            ])
        );
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
