//! WordPress interpretation bound to the existing root-response observation.
//!
//! This module owns no transport. It retains only bounded typed signals and
//! existing evidence references, then evaluates them with already-validated
//! local inputs at the assessment's normal projection boundary.

use std::{
    collections::BTreeSet,
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
        WordPressReviewError, WordPressReviewInputs, WordPressReviewResult, MAX_WORDPRESS_SIGNALS,
    },
    KnowledgeBase,
};

use super::assessment_item::{
    AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
    AssessmentProjectionContext,
};

pub(super) use super::wordpress_discovery::WordPressDiscoveryStop;
use super::wordpress_discovery::{
    discovery_seed_fingerprint, execute_wordpress_discovery, WordPressDiscoveryExecutionError,
    WordPressDiscoverySeed, MAX_WORDPRESS_DISCOVERY_CANDIDATES,
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
}

type WordPressDiscoverySnapshot = (
    Vec<WordPressDiscoverySeed>,
    Vec<EvidenceId>,
    u64,
    BTreeSet<[u8; 32]>,
);

#[derive(Default)]
pub(super) struct WordPressDiscoverySeedSelection {
    seeds: Vec<WordPressDiscoverySeed>,
    seen_candidate_fingerprints: BTreeSet<[u8; 32]>,
    candidate_identity_limit_exceeded: bool,
    omitted_candidate_count: u64,
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
}

#[derive(Debug)]
pub(super) enum WordPressReviewFinishError {
    DiscoveryNotExecuted,
    Review,
}

impl WordPressReviewBinding {
    pub(super) fn new(inputs: WordPressReviewInputs, discovery_enabled: bool) -> Self {
        Self {
            inputs,
            collector: WordPressSignalCollector::default(),
            discovery_enabled,
            discovery_audit: None,
        }
    }

    pub(super) fn collector(&self) -> WordPressSignalCollector {
        self.collector.clone()
    }

    pub(super) const fn discovery_enabled(&self) -> bool {
        self.discovery_enabled
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
        let (seeds, root_evidence_ids, omitted_candidate_count, candidate_fingerprints) = self
            .collector
            .discovery_snapshot()
            .map_err(|error| match error {
                WordPressReviewError::DiscoveryCandidateIdentityLimitExceeded => {
                    WordPressDiscoveryExecutionError::CandidateIdentityLimitExceeded
                },
                _ => WordPressDiscoveryExecutionError::EvidenceModel,
            })?;
        let execution = execute_wordpress_discovery(
            seeds,
            omitted_candidate_count,
            candidate_fingerprints,
            root_evidence_ids,
            subject,
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

/// Extracts only structured generator metadata and exact-origin asset-path
/// hints from the already bounded root HTML body.
pub(super) fn extract_wordpress_signals(
    document_url: &Url,
    html: &str,
) -> Vec<WordPressComponentSignal> {
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    // Keep the RcDom root owned while traversing its shared handles. Moving
    // `document` out drops the remaining tree state and makes valid elements
    // appear childless.
    let mut pending = vec![dom.document.clone()];
    let resolution_base = effective_document_base(&dom.document, document_url);
    let mut signals = Vec::new();
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
                let asset = match local {
                    "link" if link_relation_can_load_resource(attrs) => {
                        html_attribute(attrs, "href")
                    },
                    "script" | "img" | "source" => html_attribute(attrs, "src"),
                    _ => None,
                };
                if let (Some(reference), Some(resolution_base)) = (asset, resolution_base.as_ref())
                {
                    for signal in asset_signals(document_url, resolution_base, &reference) {
                        push_bounded_signal(&mut signals, signal);
                    }
                }
            }
        }
        if signals.len() > MAX_WORDPRESS_SIGNALS {
            break;
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    signals
}

/// Extracts only exact, closed metadata candidates from the same already
/// bounded root representation used by the transport-free signal collector.
pub(super) fn extract_wordpress_discovery_seeds(
    document_url: &Url,
    html: &str,
    rest_header: &WordPressRestIndexAdvertisement,
) -> WordPressDiscoverySeedSelection {
    let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let resolution_base = effective_document_base(&dom.document, document_url);
    let mut selection = WordPressDiscoverySeedSelection::default();
    let mut rest_seed = match rest_header {
        WordPressRestIndexAdvertisement::Candidate(url) => {
            Some(WordPressDiscoverySeed::rest_index(url.clone()))
        },
        _ => None,
    };
    let mut rest_ambiguous = matches!(
        rest_header,
        WordPressRestIndexAdvertisement::InvalidOrAmbiguous
    );
    let mut pending = vec![dom.document.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) {
                let local = name.local.as_ref();
                if local == "link" && link_has_relation(attrs, "https://api.w.org/") {
                    if let (Some(reference), Some(base)) =
                        (html_attribute(attrs, "href"), resolution_base.as_ref())
                    {
                        if let Some(url) = admitted_rest_index(document_url, base, &reference) {
                            let candidate = WordPressDiscoverySeed::rest_index(url);
                            if rest_seed
                                .as_ref()
                                .is_some_and(|existing| !same_discovery_seed(existing, &candidate))
                            {
                                rest_ambiguous = true;
                            } else if rest_seed.is_none() {
                                rest_seed = Some(candidate);
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
                    if let Some(seed) = asset_discovery_seed(document_url, base, &reference) {
                        selection.insert(seed);
                    }
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    if rest_ambiguous {
        selection.insert(WordPressDiscoverySeed::invalid_rest_index(
            document_url.clone(),
        ));
    } else if let Some(rest_seed) = rest_seed {
        selection.insert(rest_seed);
    }
    selection
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
    left.kind() == right.kind()
        && left.url() == right.url()
        && left.component_identity() == right.component_identity()
        && left.preflight_outcome() == right.preflight_outcome()
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

fn asset_discovery_seed(
    document_url: &Url,
    resolution_base: &Url,
    reference: &str,
) -> Option<WordPressDiscoverySeed> {
    let reference = reference.trim();
    if !crate::http_evidence::wordpress_reference_path_is_safe(reference) {
        return None;
    }
    let url = resolution_base.join(reference).ok()?;
    if !safe_same_origin_url(document_url, &url) {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    let (kind, slug, filename) = match segments.as_slice() {
        ["wp-content", "themes", slug, ..] => (WordPressComponentKind::Theme, *slug, "style.css"),
        ["wp-content", "plugins", slug, ..] => {
            (WordPressComponentKind::Plugin, *slug, "readme.txt")
        },
        _ => return None,
    };
    let component = crate::wordpress_review::WordPressComponentIdentity::new(kind, slug).ok()?;
    let mut candidate = document_url.clone();
    candidate.set_path(&format!(
        "/wp-content/{}/{slug}/{filename}",
        match kind {
            WordPressComponentKind::Theme => "themes",
            WordPressComponentKind::Plugin => "plugins",
            WordPressComponentKind::Core => return None,
        }
    ));
    candidate.set_query(None);
    candidate.set_fragment(None);
    safe_same_origin_url(document_url, &candidate)
        .then(|| WordPressDiscoverySeed::component(candidate, component, 0))
}

fn admitted_rest_index(document_url: &Url, resolution_base: &Url, reference: &str) -> Option<Url> {
    let reference = reference.trim();
    if !crate::http_evidence::wordpress_reference_path_is_safe(reference) {
        return None;
    }
    let candidate = resolution_base.join(reference).ok()?;
    if !safe_same_origin_url(document_url, &candidate) {
        return None;
    }
    if candidate.path() == "/wp-json/" && candidate.query().is_none() {
        return Some(candidate);
    }
    if !matches!(candidate.path(), "/" | "/index.php") || candidate.fragment().is_some() {
        return None;
    }
    let raw_query = candidate.query()?;
    crate::http_evidence::wordpress_rest_route_query_is_admitted(raw_query).then_some(candidate)
}

fn safe_same_origin_url(document_url: &Url, candidate: &Url) -> bool {
    matches!(candidate.scheme(), "http" | "https")
        && candidate.username().is_empty()
        && candidate.password().is_none()
        && candidate.fragment().is_none()
        && candidate.origin() == document_url.origin()
        && !candidate.path().contains('\\')
        && !candidate.path().split('/').any(|segment| {
            segment == "."
                || segment == ".."
                || segment.contains("%2f")
                || segment.contains("%2F")
                || segment.contains("%5c")
                || segment.contains("%5C")
        })
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
                    let reference = reference.trim();
                    return crate::http_evidence::wordpress_reference_path_is_safe(reference)
                        .then(|| document_url.join(reference).ok())
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

fn asset_signals(
    document_url: &Url,
    resolution_base: &Url,
    reference: &str,
) -> Vec<WordPressComponentSignal> {
    let Ok(url) = resolution_base.join(reference.trim()) else {
        return Vec::new();
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.origin() != document_url.origin()
    {
        return Vec::new();
    }
    let Some(segments) = url.path_segments() else {
        return Vec::new();
    };
    let segments = segments.collect::<Vec<_>>();
    let mut signals = Vec::new();
    if segments.len() >= 2 && matches!(segments.first(), Some(&"wp-includes" | &"wp-admin")) {
        if let Ok(signal) =
            WordPressComponentSignal::same_origin_asset(WordPressComponentKind::Core, "wordpress")
        {
            signals.push(signal);
        }
    }
    if segments.len() >= 4 {
        let kind = match segments.as_slice() {
            ["wp-content", "plugins", _, ..] => Some(WordPressComponentKind::Plugin),
            ["wp-content", "themes", _, ..] => Some(WordPressComponentKind::Theme),
            _ => None,
        };
        if let Some(kind) = kind {
            if let Ok(signal) = WordPressComponentSignal::same_origin_asset(kind, segments[2]) {
                signals.push(signal);
            }
        }
    }
    signals
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
    use crate::wordpress_review::{WordPressComponentIdentity, WordPressEvidenceSource};

    fn origin() -> Url {
        Url::parse("https://example.test/").unwrap()
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
    fn effective_base_cannot_rebind_nested_relative_assets_to_the_root() {
        let signals = extract_wordpress_signals(
            &origin(),
            r#"<base href="/blog/">
                <script src="wp-content/plugins/nested/app.js"></script>
                <link rel="stylesheet" href="/wp-content/themes/root-theme/style.css">"#,
        );

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].identity().kind(), WordPressComponentKind::Theme);
        assert_eq!(signals[0].identity().slug(), "root-theme");
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
        assert_eq!(seeds.len(), 3);
        assert_eq!(seeds[0].kind(), WordPressDiscoverySourceKind::RestIndex);
        assert_eq!(
            seeds[0].preflight_outcome(),
            Some(WordPressDiscoverySourceOutcome::InvalidAdvertisement)
        );
        assert_eq!(
            seeds[1].url().as_str(),
            "https://example.test/wp-content/themes/a-theme/style.css"
        );
        assert_eq!(
            seeds[2].url().as_str(),
            "https://example.test/wp-content/plugins/z-cache/readme.txt"
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
        let (seeds, _, omitted, fingerprints) = collector.discovery_snapshot().unwrap();
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

        let (seeds, _, omitted, fingerprints) = collector.discovery_snapshot().unwrap();
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
