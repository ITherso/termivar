//! Bounded runtime admission and collection for observed WordPress asset
//! fingerprints.
//!
//! The runtime is intentionally separate from catalogue parsing and report
//! rendering. It turns only committed HTML nominations or complete anonymous
//! response observations into pure matcher inputs.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId,
    EvidenceKind, EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
    PredicateDescriptor,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    http_evidence::{
        wordpress_asset_request_binding_value, CompleteHttpResponseObservation, HttpEvidenceError,
        HttpProbeMethod, HttpRequestBrokerError, WordPressAssetRequestDescriptor,
        WORDPRESS_ASSET_FINGERPRINT_POLICY_ID, WORDPRESS_ASSET_NOMINATION_COMPONENT,
        WORDPRESS_ASSET_NOMINATION_METHOD, WORDPRESS_ASSET_NOMINATION_NAMESPACE,
        WORDPRESS_ASSET_NOMINATION_PREDICATE,
    },
    wordpress_review::{
        match_wordpress_asset_fingerprint_component, valid_wordpress_asset_fingerprint_path,
        WordPressAssetFingerprintCatalog, WordPressAssetFingerprintComponentMatch,
        WordPressAssetFingerprintError, WordPressComponentIdentity, WordPressComponentKind,
        WordPressObservedAssetFingerprint, MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES,
    },
    DecisionActionOrigin, DecisionExecutionLimits, DecisionExecutionStage, KnowledgeBase,
};

use super::{wordpress_discovery::opaque_url_reference, SharedWebRuntimeAuthority};

pub const WORDPRESS_ASSET_FINGERPRINT_ACTION_ID: &str = "web.review.wordpress.asset-fingerprint@1";
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_REQUESTS: u8 = 4;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_COMPONENTS: usize = 2;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_PATHS_PER_COMPONENT: usize = 2;
const MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATES: usize = 32;
pub(super) const MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES: usize = 256;
const MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_EVIDENCE: usize = 8;
const MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_PAGES: usize = 4;
const MAX_WORDPRESS_ASSET_FINGERPRINT_OBSERVATIONS_PER_PATH: usize = 8;
const MAX_RAW_ASSET_REFERENCE_BYTES: usize = 2_048;
const WORDPRESS_TOTAL_REQUEST_LIMIT: u8 = 12;
const WORDPRESS_TOTAL_RESPONSE_BYTES: u64 = 2 * 1_024 * 1_024;
const ASSET_EVIDENCE_NAMESPACE: &str = "web.wordpress-asset-fingerprint";
const ASSET_REPRESENTATION_PREDICATE: &str = "identity-content-bytes-observed";
const ASSET_RESPONSE_DERIVATION: &str = "wordpress-asset-identity-content-bytes";
const ASSET_FETCHED_ROOT_DERIVATION: &str = "wordpress-asset-owned-get-root-binding";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WordPressAssetFingerprintRuntimeError {
    #[error("observed WordPress asset violated its frozen admission contract")]
    InvalidCandidate,
    #[error("WordPress asset fingerprint evidence model is inconsistent")]
    EvidenceModel,
    #[error("WordPress asset fingerprint evidence could not be committed")]
    EvidenceCommit,
    #[error("WordPress asset fingerprint matching failed: {0}")]
    Match(#[from] WordPressAssetFingerprintError),
}

/// One exact JS/CSS URL admitted from the same DOM traversal as ordinary
/// WordPress discovery. It carries no request authority until its source HTML
/// evidence is committed and revalidated by the collector.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct WordPressObservedAssetCandidate {
    application_url: Url,
    role_base_url: Url,
    document_url: Url,
    target_url: Url,
    component: WordPressComponentIdentity,
    relative_path: String,
    source_page_reference: String,
}

impl WordPressObservedAssetCandidate {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_html_reference(
        application_url: &Url,
        role_base_url: &Url,
        component: WordPressComponentIdentity,
        document_url: &Url,
        resolution_base: &Url,
        raw_reference: &str,
        resolved_url: &Url,
        relative_path: impl Into<String>,
        source_page_reference: impl Into<String>,
    ) -> Result<Self, WordPressAssetFingerprintRuntimeError> {
        let relative_path = relative_path.into();
        let source_page_reference = source_page_reference.into();
        if raw_reference.is_empty()
            || raw_reference.len() > MAX_RAW_ASSET_REFERENCE_BYTES
            || !raw_reference.is_ascii()
            || raw_reference != raw_reference.trim()
            || raw_reference.starts_with("//")
            || raw_reference.bytes().any(|byte| byte.is_ascii_control())
            || !crate::http_evidence::wordpress_reference_path_is_safe(raw_reference)
            || !valid_wordpress_asset_fingerprint_path(&relative_path)
            || document_url.origin() != application_url.origin()
            || resolution_base.origin() != application_url.origin()
            || !resolution_base
                .join(raw_reference)
                .is_ok_and(|joined| joined == *resolved_url)
            || source_page_reference
                != opaque_url_reference("wordpress-discovery-page", document_url)
        {
            return Err(WordPressAssetFingerprintRuntimeError::InvalidCandidate);
        }
        WordPressAssetRequestDescriptor::validate_candidate_shape(
            WORDPRESS_ASSET_FINGERPRINT_POLICY_ID,
            application_url,
            role_base_url,
            resolved_url,
            &component,
            &relative_path,
            1,
        )
        .map_err(|_| WordPressAssetFingerprintRuntimeError::InvalidCandidate)?;
        Ok(Self {
            application_url: application_url.clone(),
            role_base_url: role_base_url.clone(),
            document_url: document_url.clone(),
            target_url: resolved_url.clone(),
            component,
            relative_path,
            source_page_reference,
        })
    }

    #[cfg(test)]
    pub(super) fn target_url(&self) -> &Url {
        &self.target_url
    }

    pub(super) fn component(&self) -> &WordPressComponentIdentity {
        &self.component
    }

    pub(super) fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AssetPathKey {
    component: WordPressComponentIdentity,
    relative_path: String,
}

impl AssetPathKey {
    fn of(candidate: &WordPressObservedAssetCandidate) -> Self {
        Self {
            component: candidate.component.clone(),
            relative_path: candidate.relative_path.clone(),
        }
    }
}

#[derive(Clone)]
struct CommittedCandidate {
    candidate: WordPressObservedAssetCandidate,
    root_evidence_ids: BTreeSet<EvidenceId>,
    source_page_references: BTreeSet<String>,
}

#[derive(Clone)]
struct PendingCandidateBatch {
    candidates: Vec<WordPressObservedAssetCandidate>,
    parent_evidence_ids: Vec<EvidenceId>,
    source_limit_exceeded: bool,
}

#[derive(Clone)]
struct PendingRepresentation {
    selected: WordPressSelectedObservedAsset,
    observation: WordPressObservedAssetFingerprint,
    endpoint_evidence_id: EvidenceId,
    parent_evidence_ids: Vec<EvidenceId>,
    evidence_value: String,
    media_type: String,
}

#[derive(Clone)]
struct CommittedRepresentation {
    selected: WordPressSelectedObservedAsset,
    observation: WordPressObservedAssetFingerprint,
    root_evidence_id: EvidenceId,
}

struct CollectedFingerprintState {
    catalog: Arc<WordPressAssetFingerprintCatalog>,
    pending_candidates: BTreeMap<String, PendingCandidateBatch>,
    candidates: BTreeMap<AssetPathKey, BTreeMap<String, CommittedCandidate>>,
    seen_candidate_fingerprints: BTreeSet<[u8; 32]>,
    observed_variant_fingerprints: BTreeMap<AssetPathKey, BTreeSet<[u8; 32]>>,
    seen_resource_keys: BTreeSet<AssetPathKey>,
    candidate_count: u64,
    pending_representations: BTreeMap<String, PendingRepresentation>,
    representations: Vec<CommittedRepresentation>,
    ordinary_get_attempts: BTreeSet<String>,
    ordinary_get_attempt_history_complete: bool,
    candidate_identity_limit_exceeded: bool,
    source_page_limit_exceeded: bool,
}

/// Assessment-owned, bounded staging sink. Clones share only this assessment's
/// inert catalogue, nominated URLs, and completed fingerprint facts.
#[derive(Clone)]
pub(super) struct WordPressAssetFingerprintCollector(Arc<Mutex<CollectedFingerprintState>>);

impl WordPressAssetFingerprintCollector {
    pub(super) fn new(catalog: Arc<WordPressAssetFingerprintCatalog>) -> Self {
        Self(Arc::new(Mutex::new(CollectedFingerprintState {
            catalog,
            pending_candidates: BTreeMap::new(),
            candidates: BTreeMap::new(),
            seen_candidate_fingerprints: BTreeSet::new(),
            observed_variant_fingerprints: BTreeMap::new(),
            seen_resource_keys: BTreeSet::new(),
            candidate_count: 0,
            pending_representations: BTreeMap::new(),
            representations: Vec::new(),
            ordinary_get_attempts: BTreeSet::new(),
            ordinary_get_attempt_history_complete: true,
            candidate_identity_limit_exceeded: false,
            source_page_limit_exceeded: false,
        })))
    }

    pub(super) fn stage_candidates(
        &self,
        document_url: &Url,
        mut candidates: Vec<WordPressObservedAssetCandidate>,
        parent_evidence_ids: Vec<EvidenceId>,
        source_limit_exceeded: bool,
    ) -> Result<(), WordPressAssetFingerprintRuntimeError> {
        if candidates.is_empty() && !source_limit_exceeded {
            return Ok(());
        }
        candidates.sort();
        candidates.dedup();
        let source_limit_exceeded = source_limit_exceeded
            || candidates.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES;
        if candidates.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES {
            candidates.truncate(MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES);
        }
        if candidates
            .iter()
            .any(|candidate| candidate.document_url != *document_url)
            || parent_evidence_ids.is_empty()
            || parent_evidence_ids.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_EVIDENCE
            || parent_evidence_ids.iter().collect::<BTreeSet<_>>().len()
                != parent_evidence_ids.len()
        {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .pending_candidates
            .insert(
                document_url.as_str().to_owned(),
                PendingCandidateBatch {
                    candidates,
                    parent_evidence_ids,
                    source_limit_exceeded,
                },
            )
            .is_some()
        {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        Ok(())
    }

    /// Revalidates the complete source-HTML evidence after the decision
    /// transaction commits, then mints one root-scoped nomination binding.
    /// Catalogue entries are only a filter here and never nominate a URL.
    pub(super) fn commit_staged_candidates(
        &self,
        knowledge: &KnowledgeBase,
        root_subject: &EntityId,
        page_subject: &EntityId,
        page_url: &Url,
    ) -> Result<(), WordPressAssetFingerprintRuntimeError> {
        let pending = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.pending_candidates.remove(page_url.as_str())
        };
        let Some(mut pending) = pending else {
            return Ok(());
        };
        if !committed_html_response_is_valid(
            knowledge,
            &pending.parent_evidence_ids,
            page_subject,
            page_url,
        ) {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }

        if pending.source_limit_exceeded {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.candidate_identity_limit_exceeded = true;
            return Ok(());
        }

        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let catalog = state.catalog.clone();
        pending.candidates.retain(|candidate| {
            catalog
                .component(candidate.component())
                .is_some_and(|component| {
                    component
                        .releases()
                        .iter()
                        .any(|release| release.file(candidate.relative_path()).is_some())
                })
        });
        if pending.candidates.is_empty() {
            return Ok(());
        }
        if !candidate_identity_capacity_allows(
            &state.seen_candidate_fingerprints,
            &pending.candidates,
        ) {
            state.candidate_identity_limit_exceeded = true;
            return Ok(());
        }
        pending.candidates.retain(|candidate| {
            !state
                .seen_candidate_fingerprints
                .contains(&candidate_fingerprint(candidate))
        });
        if pending.candidates.is_empty() {
            return Ok(());
        }
        if !source_page_capacity_allows(&state.candidates, &pending.candidates) {
            state.source_page_limit_exceeded = true;
            return Ok(());
        }
        let bindings = pending
            .candidates
            .iter()
            .map(|candidate| candidate_binding_evidence(root_subject, candidate))
            .collect::<Result<Vec<_>, _>>()?;
        let binding_ids = bindings
            .iter()
            .map(|binding| binding.id().clone())
            .collect::<Vec<_>>();
        knowledge
            .insert_evidence_batch(bindings)
            .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceCommit)?;
        for (candidate, binding_id) in pending.candidates.into_iter().zip(binding_ids) {
            let key = AssetPathKey::of(&candidate);
            let candidate_fingerprint = candidate_fingerprint(&candidate);
            if !state
                .seen_candidate_fingerprints
                .contains(&candidate_fingerprint)
            {
                state
                    .seen_candidate_fingerprints
                    .insert(candidate_fingerprint);
            }
            let target_variant_fingerprint = target_variant_fingerprint(&candidate);
            state
                .observed_variant_fingerprints
                .entry(key.clone())
                .or_default()
                .insert(target_variant_fingerprint);
            if state.seen_resource_keys.insert(key.clone()) {
                state.candidate_count = state
                    .candidate_count
                    .checked_add(1)
                    .ok_or(WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
            }
            let target = candidate.target_url.as_str().to_owned();
            if let Some(existing) = state
                .candidates
                .get_mut(&key)
                .and_then(|variants| variants.get_mut(&target))
            {
                existing.root_evidence_ids.insert(binding_id.clone());
                existing
                    .source_page_references
                    .insert(candidate.source_page_reference.clone());
                continue;
            }
            let retained_candidate_count =
                state.candidates.values().map(BTreeMap::len).sum::<usize>();
            if retained_candidate_count == MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATES {
                let greatest = state
                    .candidates
                    .iter()
                    .next_back()
                    .and_then(|(key, variants)| {
                        variants
                            .keys()
                            .next_back()
                            .map(|target| (key.clone(), target.clone()))
                    });
                let incoming = (key.clone(), target.clone());
                if greatest
                    .as_ref()
                    .is_none_or(|greatest| incoming >= *greatest)
                {
                    continue;
                }
                if let Some((greatest_key, greatest_target)) = greatest {
                    let remove_key = if let Some(variants) = state.candidates.get_mut(&greatest_key)
                    {
                        variants.remove(&greatest_target);
                        variants.is_empty()
                    } else {
                        false
                    };
                    if remove_key {
                        state.candidates.remove(&greatest_key);
                    }
                }
            }
            state.candidates.entry(key).or_default().insert(
                target,
                CommittedCandidate {
                    source_page_references: BTreeSet::from([candidate
                        .source_page_reference
                        .clone()]),
                    candidate,
                    root_evidence_ids: BTreeSet::from([binding_id]),
                },
            );
        }
        Ok(())
    }

    /// Returns one currently selected exact representation, if the URL was
    /// admitted from HTML and its component/path survives the bounded stable
    /// selection. All query variants of a selected path remain observable so
    /// conflicting bytes cannot be hidden by choosing a favourite response.
    pub(super) fn selected_observed_asset(
        &self,
        url: &Url,
    ) -> Option<WordPressSelectedObservedAsset> {
        let state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        selected_assets(&state)
            .into_iter()
            .find(|selected| selected.target_url() == url)
    }

    /// Records an ordinary same-run GET attempt. A failed or incompatible GET
    /// suppresses a later fingerprint-owned retry for the same selected path.
    pub(super) fn mark_ordinary_get_attempted(
        &self,
        url: &Url,
    ) -> Result<(), WordPressAssetFingerprintRuntimeError> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.ordinary_get_attempts.contains(url.as_str())
            && state.ordinary_get_attempts.len()
                == super::web_assessment::HARD_MAX_WEB_ASSESSMENT_SUBJECTS
        {
            state.ordinary_get_attempt_history_complete = false;
            return Ok(());
        }
        state.ordinary_get_attempts.insert(url.as_str().to_owned());
        Ok(())
    }

    /// Projects one eligible ordinary GET into a derived endpoint-scoped
    /// evidence record. The complete bytes are borrowed only long enough to
    /// hash; the staged state retains length/digest and exact evidence IDs.
    pub(super) fn observe_selected_response(
        &self,
        observation: &CompleteHttpResponseObservation<'_>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let Some(selected) = self.selected_observed_asset(observation.requested_url()) else {
            return Ok(Vec::new());
        };
        if observation.method() != HttpProbeMethod::Get
            || observation.status() != 200
            || !observation.response_final_url_matches_request()
            || !observation.response_content_encoding_absent()
            || !observation.response_content_length_consistent()
            || !asset_media_type_is_supported(selected.relative_path(), observation.media_type())
        {
            return Ok(Vec::new());
        }
        let Some(body) = observation.complete_identity_content_body() else {
            return Ok(Vec::new());
        };
        let byte_length = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if byte_length != observation.response_body_bytes()
            || byte_length > MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES
            || looks_like_html(body)
        {
            return Ok(Vec::new());
        }
        let parent_evidence_ids = complete_asset_parent_evidence_ids(observation)?;
        if parent_evidence_ids.len() != 8
            || parent_evidence_ids.iter().collect::<BTreeSet<_>>().len()
                != parent_evidence_ids.len()
        {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "asset fingerprint requires eight distinct complete-response parents",
            });
        }
        let digest: [u8; 32] = Sha256::digest(body).into();
        let observed = WordPressObservedAssetFingerprint::new(
            selected.component().clone(),
            selected.relative_path(),
            byte_length,
            digest,
        )
        .map_err(|_| HttpEvidenceError::AssessmentObserverInvariant {
            invariant: "asset fingerprint matcher input must remain bounded",
        })?;
        let value = representation_evidence_value(
            selected.resource_reference(),
            observed.byte_length(),
            observed.sha256(),
        );
        let derivation = EvidenceDerivation::new(
            parent_evidence_ids.iter().cloned(),
            DerivationAlgorithm::new(ASSET_RESPONSE_DERIVATION, 1)?,
        )?;
        let source = EvidenceSource::new(
            "wordpress.asset-fingerprint",
            "committed-ordinary-get-identity-bytes",
        )?
        .with_correlation_id(observation.case_id())?;
        let evidence = Evidence::new(
            observation.subject().clone(),
            EvidenceKind::Content,
            KnowledgePredicate::new(ASSET_EVIDENCE_NAMESPACE, ASSET_REPRESENTATION_PREDICATE)?,
            EvidenceValue::Text(value.clone()),
            source,
            observation.reliability(),
        )
        .derived_from(derivation);
        let pending = PendingRepresentation {
            selected,
            observation: observed,
            endpoint_evidence_id: evidence.id().clone(),
            parent_evidence_ids,
            evidence_value: value,
            media_type: observation.media_type().unwrap_or_default().to_owned(),
        };
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .pending_representations
            .insert(observation.requested_url().as_str().to_owned(), pending)
            .is_some()
        {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "asset fingerprint response may be staged only once",
            });
        }
        Ok(vec![evidence])
    }

    /// Confirms that the derived endpoint evidence and all eight base response
    /// facts committed unchanged, then creates one bounded root-scoped binding.
    /// The raw response bytes are no longer needed after this point.
    pub(super) fn commit_staged_response(
        &self,
        knowledge: &KnowledgeBase,
        root_subject: &EntityId,
        response_subject: &EntityId,
        response_url: &Url,
    ) -> Result<(), WordPressAssetFingerprintRuntimeError> {
        let pending = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.pending_representations.remove(response_url.as_str())
        };
        let Some(pending) = pending else {
            return Ok(());
        };
        if !committed_asset_response_is_valid(knowledge, &pending, response_subject, response_url) {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.representations.iter().any(|existing| {
            existing.selected.target_url() == pending.selected.target_url()
                && existing.observation == pending.observation
        }) {
            return Ok(());
        }
        if state
            .representations
            .iter()
            .filter(|existing| {
                existing.selected.component() == pending.selected.component()
                    && existing.selected.relative_path() == pending.selected.relative_path()
            })
            .count()
            == MAX_WORDPRESS_ASSET_FINGERPRINT_OBSERVATIONS_PER_PATH
        {
            // The candidate ledger already retains the true variant count.
            // Additional complete observations are deliberately not projected,
            // but their existence keeps this path from becoming a strong
            // single-representation candidate.
            return Ok(());
        }
        let root_evidence = root_representation_binding_evidence(
            root_subject,
            &pending.selected,
            &pending.observation,
            &pending.endpoint_evidence_id,
            "reused-complete-response",
        )?;
        let root_evidence_id = root_evidence.id().clone();
        knowledge
            .insert_evidence_batch(vec![root_evidence])
            .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceCommit)?;
        state.representations.push(CommittedRepresentation {
            selected: pending.selected,
            observation: pending.observation,
            root_evidence_id,
        });
        Ok(())
    }

    pub(super) fn plan(
        &self,
    ) -> Result<WordPressAssetFingerprintPlan, WordPressAssetFingerprintRuntimeError> {
        let state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending_candidates.is_empty() || !state.pending_representations.is_empty() {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        let selected_variants = selected_assets(&state);
        let mut selected_paths =
            BTreeMap::<AssetPathKey, Vec<WordPressSelectedObservedAsset>>::new();
        for selected in selected_variants {
            selected_paths
                .entry(AssetPathKey {
                    component: selected.component.clone(),
                    relative_path: selected.relative_path.clone(),
                })
                .or_default()
                .push(selected);
        }
        let selected_resource_count = selected_paths.len();
        let candidate_path_counts = state.seen_resource_keys.iter().fold(
            BTreeMap::<WordPressComponentIdentity, usize>::new(),
            |mut counts, key| {
                *counts.entry(key.component.clone()).or_default() += 1;
                counts
            },
        );
        let omitted_resource_count = usize::try_from(state.candidate_count)
            .unwrap_or(usize::MAX)
            .saturating_sub(selected_resource_count);
        let selected = selected_paths
            .into_iter()
            .map(|(key, mut variants)| {
                let observed_variant_count = state
                    .observed_variant_fingerprints
                    .get(&key)
                    .map(BTreeSet::len)
                    .ok_or(WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
                if observed_variant_count < variants.len()
                    || observed_variant_count > MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES
                {
                    return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
                }
                variants
                    .sort_by(|left, right| left.target_url.as_str().cmp(right.target_url.as_str()));
                let source_page_references = variants
                    .iter()
                    .flat_map(|variant| variant.source_page_references.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                if source_page_references.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_PAGES
                    || variants.iter().any(|variant| {
                        variant.source_evidence_ids.is_empty()
                            || variant.source_evidence_ids.len()
                                > MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_PAGES
                            || variant.source_evidence_ids.len()
                                != variant.source_page_references.len()
                    })
                {
                    return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
                }
                for variant in &mut variants {
                    variant.source_page_references = source_page_references.clone();
                }
                Ok(WordPressAssetFingerprintPlannedPath {
                    variants,
                    observed_variant_count,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WordPressAssetFingerprintPlan {
            catalog: state.catalog.clone(),
            candidate_count: state.candidate_count,
            selected_resource_count,
            omitted_resource_count,
            candidate_path_counts,
            selected,
            reused: state.representations.clone(),
            ordinary_get_attempts: state.ordinary_get_attempts.clone(),
            ordinary_get_attempt_history_complete: state.ordinary_get_attempt_history_complete,
            candidate_identity_limit_exceeded: state.candidate_identity_limit_exceeded,
            source_page_limit_exceeded: state.source_page_limit_exceeded,
        })
    }
}

/// Exact committed candidate exposed to the generic response observer and the
/// later acquisition phase. Target queries remain private and are never
/// copied into report-facing values.
#[derive(Clone)]
pub(super) struct WordPressSelectedObservedAsset {
    application_url: Url,
    role_base_url: Url,
    target_url: Url,
    component: WordPressComponentIdentity,
    relative_path: String,
    resource_reference: String,
    source_page_references: Vec<String>,
    source_evidence_ids: Vec<EvidenceId>,
}

impl WordPressSelectedObservedAsset {
    pub(super) fn target_url(&self) -> &Url {
        &self.target_url
    }

    pub(super) fn component(&self) -> &WordPressComponentIdentity {
        &self.component
    }

    pub(super) fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub(super) fn resource_reference(&self) -> &str {
        &self.resource_reference
    }

    fn request_descriptor(
        &self,
        root_subject: &EntityId,
        knowledge: &KnowledgeBase,
    ) -> Result<WordPressAssetRequestDescriptor, WordPressAssetFingerprintRuntimeError> {
        WordPressAssetRequestDescriptor::from_committed_source_evidence(
            WORDPRESS_ASSET_FINGERPRINT_POLICY_ID,
            &self.application_url,
            &self.role_base_url,
            &self.target_url,
            self.component.clone(),
            self.relative_path.clone(),
            root_subject,
            self.source_evidence_ids.clone(),
            knowledge,
        )
        .map_err(|_| WordPressAssetFingerprintRuntimeError::InvalidCandidate)
    }
}

#[derive(Clone)]
struct WordPressAssetFingerprintPlannedPath {
    variants: Vec<WordPressSelectedObservedAsset>,
    observed_variant_count: usize,
}

#[derive(Clone)]
pub(super) struct WordPressAssetFingerprintPlan {
    catalog: Arc<WordPressAssetFingerprintCatalog>,
    candidate_count: u64,
    selected_resource_count: usize,
    omitted_resource_count: usize,
    candidate_path_counts: BTreeMap<WordPressComponentIdentity, usize>,
    selected: Vec<WordPressAssetFingerprintPlannedPath>,
    reused: Vec<CommittedRepresentation>,
    ordinary_get_attempts: BTreeSet<String>,
    ordinary_get_attempt_history_complete: bool,
    candidate_identity_limit_exceeded: bool,
    source_page_limit_exceeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressAssetFingerprintAcquisition {
    Reused,
    Fetched,
    NotAcquired,
}

impl WordPressAssetFingerprintAcquisition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reused => "reused",
            Self::Fetched => "fetched",
            Self::NotAcquired => "not_acquired",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressAssetFingerprintResourceOutcome {
    Observed,
    ConflictingRepresentations,
    OrdinaryResponseIneligible,
    BudgetExhausted,
    RequestFailed,
    Cancelled,
    DeadlineExceeded,
    RateLimited,
    Unauthorized,
    NotFound,
    RedirectObserved,
    PartialOrIncomplete,
    UnsupportedMediaType,
    UnsupportedContentEncoding,
    InconsistentContentLength,
}

impl WordPressAssetFingerprintResourceOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::ConflictingRepresentations => "conflicting_representations",
            Self::OrdinaryResponseIneligible => "ordinary_response_ineligible",
            Self::BudgetExhausted => "budget_exhausted",
            Self::RequestFailed => "request_failed",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::RateLimited => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::RedirectObserved => "redirect_observed",
            Self::PartialOrIncomplete => "partial_or_incomplete",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UnsupportedContentEncoding => "unsupported_content_encoding",
            Self::InconsistentContentLength => "inconsistent_content_length",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressAssetFingerprintStop {
    Complete,
    Cancelled,
    DeadlineExceeded,
    RequestLimit,
    ResponseLimit,
    RuntimeLimit,
    RateLimited,
}

impl WordPressAssetFingerprintStop {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::RequestLimit => "request_limit",
            Self::ResponseLimit => "response_limit",
            Self::RuntimeLimit => "runtime_limit",
            Self::RateLimited => "rate_limited",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WordPressAssetFingerprintAllowance {
    prior_wordpress_attempts: u8,
    prior_wordpress_response_bytes: u64,
    dispatch_allowed: bool,
}

impl WordPressAssetFingerprintAllowance {
    pub(super) fn new(
        prior_wordpress_attempts: u8,
        prior_wordpress_response_bytes: u64,
        dispatch_allowed: bool,
    ) -> Result<Self, WordPressAssetFingerprintRuntimeError> {
        if prior_wordpress_attempts > WORDPRESS_TOTAL_REQUEST_LIMIT
            || prior_wordpress_response_bytes > WORDPRESS_TOTAL_RESPONSE_BYTES
        {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        Ok(Self {
            prior_wordpress_attempts,
            prior_wordpress_response_bytes,
            dispatch_allowed,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintResourceReceipt {
    component: WordPressComponentIdentity,
    relative_path: String,
    resource_reference: String,
    source_page_references: Vec<String>,
    observed_variant_count: usize,
    acquisition: WordPressAssetFingerprintAcquisition,
    outcome: WordPressAssetFingerprintResourceOutcome,
    request_attempted: bool,
    interpreted_response_bytes: u64,
    response_bytes: u64,
    observation: Option<WordPressObservedAssetFingerprint>,
    evidence_ids: Vec<EvidenceId>,
}

impl WordPressAssetFingerprintResourceReceipt {
    pub const fn component(&self) -> &WordPressComponentIdentity {
        &self.component
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn resource_reference(&self) -> &str {
        &self.resource_reference
    }

    pub fn source_page_references(&self) -> &[String] {
        &self.source_page_references
    }

    pub const fn observed_variant_count(&self) -> usize {
        self.observed_variant_count
    }

    pub const fn acquisition(&self) -> WordPressAssetFingerprintAcquisition {
        self.acquisition
    }

    pub const fn outcome(&self) -> WordPressAssetFingerprintResourceOutcome {
        self.outcome
    }

    pub const fn request_attempted(&self) -> bool {
        self.request_attempted
    }

    pub const fn interpreted_response_bytes(&self) -> u64 {
        self.interpreted_response_bytes
    }

    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub const fn observation(&self) -> Option<&WordPressObservedAssetFingerprint> {
        self.observation.as_ref()
    }

    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintExecution {
    catalog: Arc<WordPressAssetFingerprintCatalog>,
    candidate_count: u64,
    selected_resource_count: usize,
    omitted_resource_count: usize,
    attempted_request_count: u8,
    reused_response_count: usize,
    fetched_response_count: usize,
    response_bytes: u64,
    resources: Vec<WordPressAssetFingerprintResourceReceipt>,
    component_matches: Vec<WordPressAssetFingerprintComponentMatch>,
    stop: WordPressAssetFingerprintStop,
}

impl WordPressAssetFingerprintExecution {
    pub fn catalog(&self) -> &WordPressAssetFingerprintCatalog {
        self.catalog.as_ref()
    }

    pub const fn candidate_count(&self) -> u64 {
        self.candidate_count
    }

    pub const fn selected_resource_count(&self) -> usize {
        self.selected_resource_count
    }

    pub const fn omitted_resource_count(&self) -> usize {
        self.omitted_resource_count
    }

    pub const fn attempted_request_count(&self) -> u8 {
        self.attempted_request_count
    }

    pub const fn reused_response_count(&self) -> usize {
        self.reused_response_count
    }

    pub const fn fetched_response_count(&self) -> usize {
        self.fetched_response_count
    }

    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub fn resources(&self) -> &[WordPressAssetFingerprintResourceReceipt] {
        &self.resources
    }

    pub fn component_matches(&self) -> &[WordPressAssetFingerprintComponentMatch] {
        &self.component_matches
    }

    pub const fn stop(&self) -> WordPressAssetFingerprintStop {
        self.stop
    }
}

pub(super) async fn execute_wordpress_asset_fingerprints(
    plan: WordPressAssetFingerprintPlan,
    authority: &SharedWebRuntimeAuthority,
    root_subject: &EntityId,
    allowance: WordPressAssetFingerprintAllowance,
    deadline: Option<tokio::time::Instant>,
) -> Result<WordPressAssetFingerprintExecution, WordPressAssetFingerprintRuntimeError> {
    let WordPressAssetFingerprintPlan {
        catalog,
        candidate_count,
        selected_resource_count,
        omitted_resource_count,
        candidate_path_counts,
        selected,
        reused,
        ordinary_get_attempts,
        ordinary_get_attempt_history_complete,
        candidate_identity_limit_exceeded,
        source_page_limit_exceeded,
    } = plan;
    let selected_keys = selected
        .iter()
        .filter_map(|path| path.variants.first())
        .map(|asset| AssetPathKey {
            component: asset.component.clone(),
            relative_path: asset.relative_path.clone(),
        })
        .collect::<BTreeSet<_>>();
    let selected_targets = selected
        .iter()
        .flat_map(|path| path.variants.iter())
        .map(|asset| {
            (
                AssetPathKey {
                    component: asset.component.clone(),
                    relative_path: asset.relative_path.clone(),
                },
                asset.target_url.to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut reused_by_path = BTreeMap::<AssetPathKey, Vec<CommittedRepresentation>>::new();
    for representation in reused {
        let key = AssetPathKey {
            component: representation.selected.component.clone(),
            relative_path: representation.selected.relative_path.clone(),
        };
        if selected_targets.contains(&(key.clone(), representation.selected.target_url.to_string()))
        {
            reused_by_path.entry(key).or_default().push(representation);
        }
    }
    let mut resources = Vec::new();
    let mut match_observations =
        BTreeMap::<WordPressComponentIdentity, Vec<WordPressObservedAssetFingerprint>>::new();
    let selected_path_counts = selected_keys.iter().fold(
        BTreeMap::<WordPressComponentIdentity, usize>::new(),
        |mut counts, key| {
            *counts.entry(key.component.clone()).or_default() += 1;
            counts
        },
    );
    let mut completely_interpreted_path_counts =
        BTreeMap::<WordPressComponentIdentity, usize>::new();
    let mut attempted = 0_u8;
    let mut response_bytes = 0_u64;
    let mut stop = if candidate_identity_limit_exceeded || source_page_limit_exceeded {
        WordPressAssetFingerprintStop::RuntimeLimit
    } else if allowance.dispatch_allowed {
        WordPressAssetFingerprintStop::Complete
    } else {
        WordPressAssetFingerprintStop::RuntimeLimit
    };

    for planned_path in selected {
        let Some(selected_asset) = planned_path.variants.first() else {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        };
        let variant_count = planned_path.observed_variant_count;
        let path_key = AssetPathKey {
            component: selected_asset.component.clone(),
            relative_path: selected_asset.relative_path.clone(),
        };
        if let Some(reused_representations) = reused_by_path.remove(&path_key) {
            let all_selected_variants_interpreted = selected_variants_completely_interpreted(
                &planned_path.variants,
                &reused_representations,
                variant_count,
            );
            let (receipt_target_url, observations, evidence_ids) =
                summarize_reused_representations(reused_representations);
            let receipt_asset = planned_path
                .variants
                .iter()
                .find(|variant| variant.target_url == receipt_target_url)
                .unwrap_or(selected_asset);
            match_observations
                .entry(receipt_asset.component.clone())
                .or_default()
                .extend(observations.iter().cloned());
            if all_selected_variants_interpreted {
                *completely_interpreted_path_counts
                    .entry(receipt_asset.component.clone())
                    .or_default() += 1;
            }
            let (outcome, observation, evidence_ids) = if observations.len() == 1 {
                (
                    WordPressAssetFingerprintResourceOutcome::Observed,
                    observations.into_iter().next(),
                    evidence_ids,
                )
            } else {
                (
                    WordPressAssetFingerprintResourceOutcome::ConflictingRepresentations,
                    None,
                    evidence_ids,
                )
            };
            resources.push(resource_receipt(
                receipt_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::Reused,
                outcome,
                false,
                0,
                observation,
                evidence_ids,
            ));
            continue;
        }
        let prior_attempt_for_path = !ordinary_get_attempt_history_complete
            || planned_path
                .variants
                .iter()
                .any(|variant| ordinary_get_attempts.contains(variant.target_url.as_str()));
        if prior_attempt_for_path {
            resources.push(resource_receipt(
                selected_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::NotAcquired,
                WordPressAssetFingerprintResourceOutcome::OrdinaryResponseIneligible,
                false,
                0,
                None,
                Vec::new(),
            ));
            continue;
        }
        if stop != WordPressAssetFingerprintStop::Complete {
            resources.push(resource_receipt(
                selected_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::NotAcquired,
                stop_resource_outcome(stop),
                false,
                0,
                None,
                Vec::new(),
            ));
            continue;
        }
        if attempted >= MAX_WORDPRESS_ASSET_FINGERPRINT_REQUESTS
            || allowance.prior_wordpress_attempts.saturating_add(attempted)
                >= WORDPRESS_TOTAL_REQUEST_LIMIT
        {
            stop = WordPressAssetFingerprintStop::RequestLimit;
            resources.push(resource_receipt(
                selected_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::NotAcquired,
                WordPressAssetFingerprintResourceOutcome::BudgetExhausted,
                false,
                0,
                None,
                Vec::new(),
            ));
            continue;
        }
        if authority.cancellation().is_cancelled() {
            stop = WordPressAssetFingerprintStop::Cancelled;
            resources.push(resource_receipt(
                selected_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::NotAcquired,
                WordPressAssetFingerprintResourceOutcome::Cancelled,
                false,
                0,
                None,
                Vec::new(),
            ));
            continue;
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            stop = WordPressAssetFingerprintStop::DeadlineExceeded;
            resources.push(resource_receipt(
                selected_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::NotAcquired,
                WordPressAssetFingerprintResourceOutcome::DeadlineExceeded,
                false,
                0,
                None,
                Vec::new(),
            ));
            continue;
        }
        let total_response_bytes = allowance
            .prior_wordpress_response_bytes
            .saturating_add(response_bytes);
        if total_response_bytes >= WORDPRESS_TOTAL_RESPONSE_BYTES {
            stop = WordPressAssetFingerprintStop::ResponseLimit;
            resources.push(resource_receipt(
                selected_asset,
                variant_count,
                WordPressAssetFingerprintAcquisition::NotAcquired,
                WordPressAssetFingerprintResourceOutcome::BudgetExhausted,
                false,
                0,
                None,
                Vec::new(),
            ));
            continue;
        }
        let response_limit = WORDPRESS_TOTAL_RESPONSE_BYTES
            .saturating_sub(total_response_bytes)
            .min(MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES.saturating_add(1));
        let descriptor = selected_asset.request_descriptor(root_subject, authority.knowledge())?;
        let before = authority.request_accounting().snapshot();
        let request = authority
            .requests()
            .collect_anonymous_wordpress_asset_get_for_runtime(
                WORDPRESS_ASSET_FINGERPRINT_ACTION_ID,
                DecisionExecutionStage::Passive,
                Some(DecisionActionOrigin::Planned),
                DecisionExecutionLimits::new().with_max_response_body_bytes(response_limit),
                &descriptor,
                authority.knowledge(),
            );
        let collected =
            await_asset_request(request, authority.cancellation_token(), deadline).await;
        let after = authority.request_accounting().snapshot();
        let request_delta = after
            .total_requests()
            .saturating_sub(before.total_requests());
        let response_delta = after
            .response_bytes()
            .saturating_sub(before.response_bytes());
        if request_delta > 1 {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        attempted = attempted.saturating_add(u8::try_from(request_delta).unwrap_or(u8::MAX));
        response_bytes = response_bytes.saturating_add(response_delta);
        let request_attempted = request_delta == 1;
        let (outcome, observation, evidence_ids, next_stop) = match collected {
            BoundedAssetRequest::Cancelled => (
                WordPressAssetFingerprintResourceOutcome::Cancelled,
                None,
                Vec::new(),
                Some(WordPressAssetFingerprintStop::Cancelled),
            ),
            BoundedAssetRequest::DeadlineExceeded => (
                WordPressAssetFingerprintResourceOutcome::DeadlineExceeded,
                None,
                Vec::new(),
                Some(WordPressAssetFingerprintStop::DeadlineExceeded),
            ),
            BoundedAssetRequest::Completed(result) => match *result {
                Err(HttpRequestBrokerError::RuntimeLimit(_)) => (
                    WordPressAssetFingerprintResourceOutcome::BudgetExhausted,
                    None,
                    Vec::new(),
                    Some(WordPressAssetFingerprintStop::RuntimeLimit),
                ),
                Err(HttpRequestBrokerError::Http(_)) => (
                    WordPressAssetFingerprintResourceOutcome::RequestFailed,
                    None,
                    Vec::new(),
                    None,
                ),
                Ok(response) => {
                    let outcome = classify_asset_response(selected_asset, &response);
                    let observation =
                        if outcome == WordPressAssetFingerprintResourceOutcome::Observed {
                            let body = response
                                .complete_identity_content_body()
                                .ok_or(WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
                            let fingerprint = WordPressObservedAssetFingerprint::new(
                                selected_asset.component.clone(),
                                selected_asset.relative_path.clone(),
                                u64::try_from(body.len()).unwrap_or(u64::MAX),
                                Sha256::digest(body).into(),
                            )?;
                            Some(fingerprint)
                        } else {
                            None
                        };
                    let evidence_ids = if let Some(observation) = observation.as_ref() {
                        let evidence = fetched_representation_evidence(
                            root_subject,
                            selected_asset,
                            observation,
                            authority.requests().policy().reliability(),
                        )?;
                        let id = evidence.id().clone();
                        authority
                            .knowledge()
                            .insert_evidence_batch(vec![evidence])
                            .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceCommit)?;
                        vec![id]
                    } else {
                        Vec::new()
                    };
                    let next_stop = (outcome
                        == WordPressAssetFingerprintResourceOutcome::RateLimited)
                        .then_some(WordPressAssetFingerprintStop::RateLimited);
                    (outcome, observation, evidence_ids, next_stop)
                },
            },
        };
        if let Some(next_stop) = next_stop {
            stop = next_stop;
        }
        if allowance
            .prior_wordpress_response_bytes
            .saturating_add(response_bytes)
            > WORDPRESS_TOTAL_RESPONSE_BYTES
        {
            stop = WordPressAssetFingerprintStop::ResponseLimit;
        }
        if let Some(observation) = observation.as_ref() {
            match_observations
                .entry(selected_asset.component.clone())
                .or_default()
                .push(observation.clone());
            if variant_count == 1 {
                *completely_interpreted_path_counts
                    .entry(selected_asset.component.clone())
                    .or_default() += 1;
            }
        }
        resources.push(resource_receipt(
            selected_asset,
            variant_count,
            if request_attempted {
                WordPressAssetFingerprintAcquisition::Fetched
            } else {
                WordPressAssetFingerprintAcquisition::NotAcquired
            },
            outcome,
            request_attempted,
            response_delta,
            observation,
            evidence_ids,
        ));
    }

    resources.sort_by(|left, right| {
        left.component
            .cmp(&right.component)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
            .then_with(|| left.resource_reference.cmp(&right.resource_reference))
    });
    let selected_components = selected_keys
        .iter()
        .map(|key| key.component.clone())
        .collect::<BTreeSet<_>>();
    let mut component_matches = Vec::with_capacity(selected_components.len());
    for component in selected_components {
        let matched = match_wordpress_asset_fingerprint_component(
            &catalog,
            &component,
            match_observations
                .get(&component)
                .map_or(&[], Vec::as_slice),
        )?;
        let selected_path_count = selected_path_counts.get(&component).copied().unwrap_or(0);
        let candidate_path_count = candidate_path_counts.get(&component).copied().unwrap_or(0);
        let completely_interpreted_path_count = completely_interpreted_path_counts
            .get(&component)
            .copied()
            .unwrap_or(0);
        if candidate_path_count < selected_path_count
            || selected_path_count < completely_interpreted_path_count
        {
            return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
        }
        component_matches.push(matched.with_collection_coverage(
            candidate_path_count,
            selected_path_count,
            completely_interpreted_path_count,
        ));
    }
    let reused_response_count = resources
        .iter()
        .filter(|resource| resource.acquisition == WordPressAssetFingerprintAcquisition::Reused)
        .count();
    let fetched_response_count = resources
        .iter()
        .filter(|resource| {
            resource.acquisition == WordPressAssetFingerprintAcquisition::Fetched
                && resource.outcome == WordPressAssetFingerprintResourceOutcome::Observed
        })
        .count();
    Ok(WordPressAssetFingerprintExecution {
        catalog,
        candidate_count,
        selected_resource_count,
        omitted_resource_count,
        attempted_request_count: attempted,
        reused_response_count,
        fetched_response_count,
        response_bytes,
        resources,
        component_matches,
        stop,
    })
}

enum BoundedAssetRequest {
    Completed(Box<Result<crate::http_evidence::CollectedHttpResponse, HttpRequestBrokerError>>),
    Cancelled,
    DeadlineExceeded,
}

async fn await_asset_request(
    request: impl std::future::Future<
        Output = Result<crate::http_evidence::CollectedHttpResponse, HttpRequestBrokerError>,
    >,
    cancellation: CancellationToken,
    deadline: Option<tokio::time::Instant>,
) -> BoundedAssetRequest {
    match deadline {
        Some(deadline) => {
            tokio::select! {
                _ = cancellation.cancelled() => BoundedAssetRequest::Cancelled,
                result = tokio::time::timeout_at(deadline, request) => match result {
                    Ok(result) => BoundedAssetRequest::Completed(Box::new(result)),
                    Err(_) => BoundedAssetRequest::DeadlineExceeded,
                },
            }
        },
        None => {
            tokio::select! {
                _ = cancellation.cancelled() => BoundedAssetRequest::Cancelled,
                result = request => BoundedAssetRequest::Completed(Box::new(result)),
            }
        },
    }
}

fn classify_asset_response(
    selected: &WordPressSelectedObservedAsset,
    response: &crate::http_evidence::CollectedHttpResponse,
) -> WordPressAssetFingerprintResourceOutcome {
    match response.status() {
        429 => return WordPressAssetFingerprintResourceOutcome::RateLimited,
        401 | 403 => return WordPressAssetFingerprintResourceOutcome::Unauthorized,
        404 => return WordPressAssetFingerprintResourceOutcome::NotFound,
        300..=399 => return WordPressAssetFingerprintResourceOutcome::RedirectObserved,
        206 => return WordPressAssetFingerprintResourceOutcome::PartialOrIncomplete,
        200 => {},
        _ => return WordPressAssetFingerprintResourceOutcome::RequestFailed,
    }
    if response.final_url() != selected.target_url() {
        return WordPressAssetFingerprintResourceOutcome::RedirectObserved;
    }
    if response.body_truncated() || !response.body_complete() {
        return WordPressAssetFingerprintResourceOutcome::PartialOrIncomplete;
    }
    if !response.content_encoding_is_absent() {
        return WordPressAssetFingerprintResourceOutcome::UnsupportedContentEncoding;
    }
    if !response.content_length_is_consistent() {
        return WordPressAssetFingerprintResourceOutcome::InconsistentContentLength;
    }
    if !asset_media_type_is_supported(
        selected.relative_path(),
        response.normalized_media_type().as_deref(),
    ) {
        return WordPressAssetFingerprintResourceOutcome::UnsupportedMediaType;
    }
    let Some(body) = response.complete_identity_content_body() else {
        return WordPressAssetFingerprintResourceOutcome::PartialOrIncomplete;
    };
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES
        || looks_like_html(body)
    {
        return WordPressAssetFingerprintResourceOutcome::UnsupportedMediaType;
    }
    WordPressAssetFingerprintResourceOutcome::Observed
}

fn asset_media_type_is_supported(relative_path: &str, media_type: Option<&str>) -> bool {
    let Some(media_type) = media_type else {
        return false;
    };
    if relative_path.ends_with(".css") {
        media_type == "text/css"
    } else if relative_path.ends_with(".js") {
        matches!(
            media_type,
            "text/javascript"
                | "application/javascript"
                | "application/ecmascript"
                | "text/ecmascript"
        )
    } else {
        false
    }
}

fn looks_like_html(body: &[u8]) -> bool {
    let body = body.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(body);
    let body = body
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&[][..], |start| &body[start..]);
    [b"<!doctype html".as_slice(), b"<html".as_slice()]
        .iter()
        .any(|prefix| {
            body.get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
}

#[allow(clippy::too_many_arguments)]
fn resource_receipt(
    selected: &WordPressSelectedObservedAsset,
    observed_variant_count: usize,
    acquisition: WordPressAssetFingerprintAcquisition,
    outcome: WordPressAssetFingerprintResourceOutcome,
    request_attempted: bool,
    response_bytes: u64,
    observation: Option<WordPressObservedAssetFingerprint>,
    evidence_ids: Vec<EvidenceId>,
) -> WordPressAssetFingerprintResourceReceipt {
    let interpreted_response_bytes = observation
        .as_ref()
        .map_or(0, WordPressObservedAssetFingerprint::byte_length);
    WordPressAssetFingerprintResourceReceipt {
        component: selected.component.clone(),
        relative_path: selected.relative_path.clone(),
        resource_reference: selected.resource_reference.clone(),
        source_page_references: selected.source_page_references.clone(),
        observed_variant_count,
        acquisition,
        outcome,
        request_attempted,
        interpreted_response_bytes,
        response_bytes,
        observation,
        evidence_ids,
    }
}

const fn stop_resource_outcome(
    stop: WordPressAssetFingerprintStop,
) -> WordPressAssetFingerprintResourceOutcome {
    match stop {
        WordPressAssetFingerprintStop::Cancelled => {
            WordPressAssetFingerprintResourceOutcome::Cancelled
        },
        WordPressAssetFingerprintStop::DeadlineExceeded => {
            WordPressAssetFingerprintResourceOutcome::DeadlineExceeded
        },
        WordPressAssetFingerprintStop::RateLimited => {
            WordPressAssetFingerprintResourceOutcome::RateLimited
        },
        WordPressAssetFingerprintStop::Complete
        | WordPressAssetFingerprintStop::RequestLimit
        | WordPressAssetFingerprintStop::ResponseLimit
        | WordPressAssetFingerprintStop::RuntimeLimit => {
            WordPressAssetFingerprintResourceOutcome::BudgetExhausted
        },
    }
}

fn selected_assets(state: &CollectedFingerprintState) -> Vec<WordPressSelectedObservedAsset> {
    let selected_components = state
        .candidates
        .keys()
        .map(|key| key.component.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_WORDPRESS_ASSET_FINGERPRINT_COMPONENTS)
        .collect::<BTreeSet<_>>();
    let mut paths_per_component = BTreeMap::<WordPressComponentIdentity, usize>::new();
    let mut selected = Vec::new();
    for (key, variants) in &state.candidates {
        if !selected_components.contains(&key.component) {
            continue;
        }
        let retained_paths = paths_per_component
            .entry(key.component.clone())
            .or_default();
        if *retained_paths == MAX_WORDPRESS_ASSET_FINGERPRINT_PATHS_PER_COMPONENT {
            continue;
        }
        *retained_paths += 1;
        for committed in variants.values() {
            selected.push(WordPressSelectedObservedAsset {
                application_url: committed.candidate.application_url.clone(),
                role_base_url: committed.candidate.role_base_url.clone(),
                target_url: committed.candidate.target_url.clone(),
                component: committed.candidate.component.clone(),
                relative_path: committed.candidate.relative_path.clone(),
                resource_reference: asset_path_reference(
                    &committed.candidate.application_url,
                    &committed.candidate.component,
                    &committed.candidate.relative_path,
                ),
                source_page_references: committed.source_page_references.iter().cloned().collect(),
                source_evidence_ids: committed.root_evidence_ids.iter().cloned().collect(),
            });
        }
    }
    selected
}

fn asset_path_reference(
    application_url: &Url,
    component: &WordPressComponentIdentity,
    relative_path: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordpress-asset-resource-path/v1\0");
    for value in [
        application_url.as_str(),
        component_kind_name(component.kind()),
        component.slug(),
        relative_path,
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn selected_variants_completely_interpreted(
    selected: &[WordPressSelectedObservedAsset],
    representations: &[CommittedRepresentation],
    observed_variant_count: usize,
) -> bool {
    let represented_urls = representations
        .iter()
        .map(|representation| representation.selected.target_url.as_str())
        .collect::<BTreeSet<_>>();
    observed_variant_count == 1
        && selected.len() == 1
        && selected
            .iter()
            .all(|variant| represented_urls.contains(variant.target_url.as_str()))
}

fn summarize_reused_representations(
    mut representations: Vec<CommittedRepresentation>,
) -> (Url, Vec<WordPressObservedAssetFingerprint>, Vec<EvidenceId>) {
    representations.sort_by(|left, right| {
        left.selected
            .target_url
            .as_str()
            .cmp(right.selected.target_url.as_str())
            .then_with(|| left.root_evidence_id.cmp(&right.root_evidence_id))
    });
    let receipt_target_url = representations[0].selected.target_url.clone();
    let receipt_evidence_id = representations[0].root_evidence_id.clone();
    let mut distinct = BTreeMap::<(u64, [u8; 32]), WordPressObservedAssetFingerprint>::new();
    let mut evidence_ids = BTreeSet::new();
    for representation in representations {
        let key = (
            representation.observation.byte_length(),
            *representation.observation.sha256(),
        );
        distinct.entry(key).or_insert(representation.observation);
        evidence_ids.insert(representation.root_evidence_id);
    }
    let observations = distinct.into_values().collect::<Vec<_>>();
    let evidence_ids = if observations.len() == 1 {
        vec![receipt_evidence_id]
    } else {
        evidence_ids.into_iter().collect()
    };
    (receipt_target_url, observations, evidence_ids)
}

fn target_variant_fingerprint(candidate: &WordPressObservedAssetCandidate) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordpress-observed-asset-target-variant/v1\0");
    for value in [
        component_kind_name(candidate.component.kind()),
        candidate.component.slug(),
        candidate.relative_path.as_str(),
        candidate.target_url.as_str(),
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

fn candidate_fingerprint(candidate: &WordPressObservedAssetCandidate) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordpress-observed-asset-candidate/v1\0");
    for value in [
        candidate.application_url.as_str(),
        candidate.role_base_url.as_str(),
        candidate.document_url.as_str(),
        candidate.target_url.as_str(),
        component_kind_name(candidate.component.kind()),
        candidate.component.slug(),
        candidate.relative_path.as_str(),
        candidate.source_page_reference.as_str(),
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

fn candidate_identity_capacity_allows(
    existing: &BTreeSet<[u8; 32]>,
    candidates: &[WordPressObservedAssetCandidate],
) -> bool {
    let new_identities = candidates
        .iter()
        .map(candidate_fingerprint)
        .filter(|fingerprint| !existing.contains(fingerprint))
        .collect::<BTreeSet<_>>();
    existing
        .len()
        .checked_add(new_identities.len())
        .is_some_and(|count| count <= MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES)
}

fn source_page_capacity_allows(
    existing: &BTreeMap<AssetPathKey, BTreeMap<String, CommittedCandidate>>,
    candidates: &[WordPressObservedAssetCandidate],
) -> bool {
    let mut pages_by_resource = existing
        .iter()
        .map(|(key, variants)| {
            let pages = variants
                .values()
                .flat_map(|committed| committed.source_page_references.iter().cloned())
                .collect::<BTreeSet<_>>();
            (key.clone(), pages)
        })
        .collect::<BTreeMap<_, _>>();
    for candidate in candidates {
        let pages = pages_by_resource
            .entry(AssetPathKey::of(candidate))
            .or_default();
        pages.insert(candidate.source_page_reference.clone());
        if pages.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_PAGES {
            return false;
        }
    }
    true
}

fn component_kind_name(kind: WordPressComponentKind) -> &'static str {
    match kind {
        WordPressComponentKind::Core => "core",
        WordPressComponentKind::Plugin => "plugin",
        WordPressComponentKind::Theme => "theme",
    }
}

fn candidate_binding_evidence(
    root_subject: &EntityId,
    candidate: &WordPressObservedAssetCandidate,
) -> Result<Evidence, WordPressAssetFingerprintRuntimeError> {
    let binding_value = wordpress_asset_request_binding_value(
        &candidate.application_url,
        &candidate.role_base_url,
        &candidate.target_url,
        &candidate.component,
        &candidate.relative_path,
        &candidate.source_page_reference,
    );
    let source = EvidenceSource::new(
        WORDPRESS_ASSET_NOMINATION_COMPONENT,
        WORDPRESS_ASSET_NOMINATION_METHOD,
    )
    .and_then(|source| source.with_correlation_id(candidate.source_page_reference.clone()))
    .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    let predicate = KnowledgePredicate::new(
        WORDPRESS_ASSET_NOMINATION_NAMESPACE,
        WORDPRESS_ASSET_NOMINATION_PREDICATE,
    )
    .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    let reliability = ConfidenceScore::from_percent(70)
        .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    // The committed HTML response may belong to a secondary page subject,
    // while the fingerprint audit belongs to the application root. Knowledge
    // derivations deliberately reject cross-subject parents, so this sealed
    // binding is a direct root-scoped fact minted only after the exact page
    // subject, URL, and complete-response parents were revalidated.
    Ok(Evidence::new(
        root_subject.clone(),
        EvidenceKind::Content,
        predicate,
        EvidenceValue::Text(binding_value),
        source,
        reliability,
    ))
}

fn representation_evidence_value(
    resource_reference: &str,
    byte_length: u64,
    sha256: &[u8; 32],
) -> String {
    format!(
        "{resource_reference}:bytes:{byte_length}:sha256:{}",
        hex_sha256(sha256)
    )
}

fn hex_sha256(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut value = String::with_capacity(64);
    for byte in digest {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn root_representation_binding_evidence(
    root_subject: &EntityId,
    selected: &WordPressSelectedObservedAsset,
    observation: &WordPressObservedAssetFingerprint,
    endpoint_evidence_id: &EvidenceId,
    method: &'static str,
) -> Result<Evidence, WordPressAssetFingerprintRuntimeError> {
    let source = EvidenceSource::new("wordpress.asset-fingerprint", method)
        .and_then(|source| source.with_correlation_id(selected.resource_reference.clone()))
        .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    let predicate =
        KnowledgePredicate::new(ASSET_EVIDENCE_NAMESPACE, ASSET_REPRESENTATION_PREDICATE)
            .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    let reliability = ConfidenceScore::from_percent(70)
        .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    // The ordinary response evidence belongs to the asset endpoint subject.
    // Its complete exact representation was revalidated before this direct
    // root-scoped binding was minted, avoiding an invalid cross-subject
    // KnowledgeBase derivation while retaining the evidence ID in the sealed
    // value below.
    let mut binding_digest = Sha256::new();
    binding_digest.update(endpoint_evidence_id.to_string().as_bytes());
    binding_digest.update(observation.byte_length().to_be_bytes());
    binding_digest.update(observation.sha256());
    Ok(Evidence::new(
        root_subject.clone(),
        EvidenceKind::Content,
        predicate,
        EvidenceValue::Text(format!(
            "{}:source-binding:sha256:{:x}",
            representation_evidence_value(
                selected.resource_reference(),
                observation.byte_length(),
                observation.sha256(),
            ),
            binding_digest.finalize()
        )),
        source,
        reliability,
    ))
}

fn fetched_representation_evidence(
    root_subject: &EntityId,
    selected: &WordPressSelectedObservedAsset,
    observation: &WordPressObservedAssetFingerprint,
    reliability: ConfidenceScore,
) -> Result<Evidence, WordPressAssetFingerprintRuntimeError> {
    if selected.source_evidence_ids.is_empty()
        || selected.source_evidence_ids.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_SOURCE_EVIDENCE
    {
        return Err(WordPressAssetFingerprintRuntimeError::EvidenceModel);
    }
    let source = EvidenceSource::new(
        "wordpress.asset-fingerprint",
        "fingerprint-owned-identity-get",
    )
    .and_then(|source| source.with_correlation_id(selected.resource_reference.clone()))
    .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    let predicate =
        KnowledgePredicate::new(ASSET_EVIDENCE_NAMESPACE, ASSET_REPRESENTATION_PREDICATE)
            .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    let derivation = EvidenceDerivation::new(
        selected.source_evidence_ids.iter().cloned(),
        DerivationAlgorithm::new(ASSET_FETCHED_ROOT_DERIVATION, 1)
            .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?,
    )
    .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?;
    Ok(Evidence::new(
        root_subject.clone(),
        EvidenceKind::Content,
        predicate,
        EvidenceValue::Text(representation_evidence_value(
            selected.resource_reference(),
            observation.byte_length(),
            observation.sha256(),
        )),
        source,
        reliability.min(
            ConfidenceScore::from_percent(70)
                .map_err(|_| WordPressAssetFingerprintRuntimeError::EvidenceModel)?,
        ),
    )
    .derived_from(derivation))
}

fn complete_asset_parent_evidence_ids(
    observation: &CompleteHttpResponseObservation<'_>,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    [
        (observation.request_method_evidence_id(), "request method"),
        (observation.request_url_evidence_id(), "request URL"),
        (observation.response_status_evidence_id(), "response status"),
        (
            observation.response_final_url_evidence_id(),
            "response final URL",
        ),
        (
            observation.response_media_type_evidence_id(),
            "response media type",
        ),
        (
            observation.response_body_bytes_evidence_id(),
            "response body byte count",
        ),
        (
            observation.response_body_truncated_evidence_id(),
            "response truncation",
        ),
        (
            observation.response_body_digest_evidence_id(),
            "response body digest",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect()
}

fn committed_html_response_is_valid(
    knowledge: &KnowledgeBase,
    evidence_ids: &[EvidenceId],
    expected_subject: &EntityId,
    expected_url: &Url,
) -> bool {
    committed_response_base_is_valid(
        knowledge,
        evidence_ids,
        expected_subject,
        expected_url,
        |media_type| media_type == "text/html",
        None,
        None,
    )
}

fn committed_asset_response_is_valid(
    knowledge: &KnowledgeBase,
    pending: &PendingRepresentation,
    expected_subject: &EntityId,
    expected_url: &Url,
) -> bool {
    if !committed_response_base_is_valid(
        knowledge,
        &pending.parent_evidence_ids,
        expected_subject,
        expected_url,
        |media_type| media_type == pending.media_type,
        Some(pending.observation.byte_length()),
        Some(pending.observation.sha256()),
    ) {
        return false;
    }
    knowledge
        .inspect_evidence(&pending.endpoint_evidence_id, |evidence| {
            evidence.subject() == expected_subject
                && evidence.predicate()
                    == &KnowledgePredicate::new(
                        ASSET_EVIDENCE_NAMESPACE,
                        ASSET_REPRESENTATION_PREDICATE,
                    )
                    .expect("fixed fingerprint predicate")
                && evidence.value() == &EvidenceValue::Text(pending.evidence_value.clone())
                && evidence.origin().derivation().is_some_and(|derivation| {
                    derivation.algorithm().name() == ASSET_RESPONSE_DERIVATION
                        && derivation.algorithm().version() == 1
                        && derivation.parents()
                            == pending
                                .parent_evidence_ids
                                .iter()
                                .cloned()
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .collect::<Vec<_>>()
                })
        })
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn committed_response_base_is_valid(
    knowledge: &KnowledgeBase,
    evidence_ids: &[EvidenceId],
    expected_subject: &EntityId,
    expected_url: &Url,
    media_type_is_valid: impl Fn(&str) -> bool,
    expected_body_bytes: Option<u64>,
    expected_sha256: Option<&[u8; 32]>,
) -> bool {
    if evidence_ids.len() != 8
        || evidence_ids.iter().collect::<BTreeSet<_>>().len() != evidence_ids.len()
        || evidence_ids.iter().any(|id| {
            knowledge
                .inspect_evidence(id, |evidence| evidence.subject() != expected_subject)
                .unwrap_or(true)
        })
    {
        return false;
    }
    let unique_value = |predicate: PredicateDescriptor| {
        let predicate = predicate.into_knowledge();
        let mut values = evidence_ids.iter().filter_map(|id| {
            knowledge.inspect_evidence(id, |evidence| {
                (evidence.predicate() == &predicate).then(|| evidence.value().clone())
            })?
        });
        let value = values.next();
        (values.next().is_none()).then_some(value).flatten()
    };
    if unique_value(HttpEvidencePredicate::REQUEST_METHOD)
        != Some(EvidenceValue::Text("GET".to_owned()))
        || unique_value(HttpEvidencePredicate::REQUEST_URL)
            != Some(EvidenceValue::Text(expected_url.to_string()))
        || unique_value(HttpEvidencePredicate::RESPONSE_STATUS)
            != Some(EvidenceValue::Unsigned(200))
        || unique_value(HttpEvidencePredicate::RESPONSE_FINAL_URL)
            != Some(EvidenceValue::Text(expected_url.to_string()))
        || unique_value(HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED)
            != Some(EvidenceValue::Boolean(false))
    {
        return false;
    }
    let media_type = unique_value(HttpEvidencePredicate::RESPONSE_MEDIA_TYPE);
    if !matches!(media_type, Some(EvidenceValue::Text(ref value)) if media_type_is_valid(value)) {
        return false;
    }
    let body_bytes = unique_value(HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED);
    let Some(EvidenceValue::Unsigned(body_bytes)) = body_bytes else {
        return false;
    };
    if expected_body_bytes.is_some_and(|expected| expected != body_bytes) {
        return false;
    }
    let digest = unique_value(HttpEvidencePredicate::RESPONSE_BODY_SHA256);
    let Some(EvidenceValue::Text(digest)) = digest else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && expected_sha256.is_none_or(|expected| digest == hex_sha256(expected))
}

#[cfg(test)]
mod tests {
    use termivar_core::EvidenceValue;

    use super::{
        asset_media_type_is_supported, asset_path_reference, candidate_binding_evidence,
        fetched_representation_evidence, looks_like_html, opaque_url_reference,
        root_representation_binding_evidence, selected_variants_completely_interpreted,
        source_page_capacity_allows, summarize_reused_representations, CommittedRepresentation,
        WordPressAssetFingerprintCollector, WordPressAssetFingerprintRuntimeError,
        WordPressComponentIdentity, WordPressComponentKind, WordPressObservedAssetCandidate,
        WordPressObservedAssetFingerprint, WordPressSelectedObservedAsset,
        ASSET_FETCHED_ROOT_DERIVATION, MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES,
    };
    use crate::wordpress_review::parse_wordpress_asset_fingerprint_catalog;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use termivar_core::{ConfidenceScore, EntityId, EvidenceId};
    use url::Url;

    #[test]
    fn observed_asset_candidate_preserves_exact_safe_query_and_frozen_binding() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let role = application.join("wp-content/plugins/").unwrap();
        let document = application.join("contact/").unwrap();
        let target = role
            .join("sample-plugin/assets/app.js?ver=release-1_2")
            .unwrap();
        let component =
            WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "sample-plugin")
                .unwrap();
        let page_reference = opaque_url_reference("wordpress-discovery-page", &document);
        let candidate = WordPressObservedAssetCandidate::from_html_reference(
            &application,
            &role,
            component.clone(),
            &document,
            &document,
            "/blog/wp-content/plugins/sample-plugin/assets/app.js?ver=release-1_2",
            &target,
            "assets/app.js",
            page_reference,
        )
        .unwrap();
        assert_eq!(candidate.target_url(), &target);
        assert_eq!(candidate.component(), &component);
        assert_eq!(candidate.relative_path(), "assets/app.js");

        let forged = WordPressObservedAssetCandidate::from_html_reference(
            &application,
            &role,
            component,
            &document,
            &document,
            "/blog/wp-content/plugins/sample-plugin/assets/app.js?ver=release-1_2",
            &role.join("sample-plugin/assets/other.js").unwrap(),
            "assets/app.js",
            opaque_url_reference("wordpress-discovery-page", &document),
        );
        assert_eq!(
            forged,
            Err(WordPressAssetFingerprintRuntimeError::InvalidCandidate)
        );
    }

    #[test]
    fn staging_limit_plus_one_records_incomplete_candidate_identity_coverage() {
        let catalogue = parse_wordpress_asset_fingerprint_catalog(include_bytes!(
            "../../../../docs/examples/wordpress-review/asset-fingerprints/catalogue.synthetic.json"
        ))
        .unwrap();
        let collector = WordPressAssetFingerprintCollector::new(Arc::new(catalogue));
        let application = Url::parse("https://example.test/").unwrap();
        let role = application.join("wp-content/plugins/").unwrap();
        let component = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fingerprint-lab",
        )
        .unwrap();
        let candidates = (0..=MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES)
            .map(|ordinal| {
                let raw = format!(
                    "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.js?ver=v{ordinal}"
                );
                let target = application.join(&raw).unwrap();
                WordPressObservedAssetCandidate::from_html_reference(
                    &application,
                    &role,
                    component.clone(),
                    &application,
                    &application,
                    &raw,
                    &target,
                    "assets/fingerprint.js",
                    opaque_url_reference("wordpress-discovery-page", &application),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        collector
            .stage_candidates(&application, candidates, vec![EvidenceId::new()], false)
            .unwrap();

        let state = collector
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let staged = state.pending_candidates.get(application.as_str()).unwrap();
        assert_eq!(
            staged.candidates.len(),
            MAX_WORDPRESS_ASSET_FINGERPRINT_CANDIDATE_IDENTITIES
        );
        assert!(staged.source_limit_exceeded);
    }

    #[test]
    fn asset_representation_requires_closed_mime_and_rejects_obvious_html() {
        assert!(asset_media_type_is_supported("asset.css", Some("text/css")));
        assert!(asset_media_type_is_supported(
            "asset.js",
            Some("text/javascript")
        ));
        assert!(asset_media_type_is_supported(
            "asset.js",
            Some("application/javascript")
        ));
        assert!(!asset_media_type_is_supported(
            "asset.css",
            Some("text/html")
        ));
        assert!(!asset_media_type_is_supported(
            "asset.js",
            Some("application/octet-stream")
        ));
        assert!(!asset_media_type_is_supported("asset.js", None));

        assert!(looks_like_html(b" \r\n<!DOCTYPE HTML><html>"));
        assert!(looks_like_html(b"\xef\xbb\xbf<HTML><body>login</body>"));
        assert!(!looks_like_html(b"const marker = '<html>';"));
        assert!(!looks_like_html(b"body { content: '<html>'; }"));
    }

    #[test]
    fn query_variant_ambiguity_prevents_complete_path_interpretation() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let role = application.join("wp-content/plugins/").unwrap();
        let component =
            WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "sample-plugin")
                .unwrap();
        let selected = |query: &str| WordPressSelectedObservedAsset {
            application_url: application.clone(),
            role_base_url: role.clone(),
            target_url: role
                .join(&format!("sample-plugin/assets/app.js?ver={query}"))
                .unwrap(),
            component: component.clone(),
            relative_path: "assets/app.js".to_owned(),
            resource_reference: format!("resource-{query}"),
            source_page_references: vec![format!("page-{query}")],
            source_evidence_ids: vec![EvidenceId::new()],
        };
        let first = selected("one");
        let second = selected("two");
        let representation = |selected: WordPressSelectedObservedAsset| CommittedRepresentation {
            observation: WordPressObservedAssetFingerprint::new(
                component.clone(),
                "assets/app.js",
                3,
                [7; 32],
            )
            .unwrap(),
            selected,
            root_evidence_id: EvidenceId::new(),
        };

        assert!(selected_variants_completely_interpreted(
            std::slice::from_ref(&first),
            &[representation(first.clone())],
            1,
        ));

        assert!(!selected_variants_completely_interpreted(
            &[first.clone(), second.clone()],
            &[representation(first.clone())],
            2,
        ));
        assert!(!selected_variants_completely_interpreted(
            &[first.clone(), second.clone()],
            &[representation(first), representation(second)],
            2,
        ));
        assert!(!selected_variants_completely_interpreted(
            &[selected("one"), selected("two")],
            &[
                representation(selected("one")),
                representation(selected("two")),
            ],
            33,
        ));
    }

    #[test]
    fn reused_receipt_keeps_its_target_and_evidence_witness_atomic() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let role = application.join("wp-content/plugins/").unwrap();
        let component =
            WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "sample-plugin")
                .unwrap();
        let selected = |query: &str| WordPressSelectedObservedAsset {
            application_url: application.clone(),
            role_base_url: role.clone(),
            target_url: role
                .join(&format!("sample-plugin/assets/app.js?ver={query}"))
                .unwrap(),
            component: component.clone(),
            relative_path: "assets/app.js".to_owned(),
            resource_reference: "resource-path".to_owned(),
            source_page_references: vec![format!("page-{query}")],
            source_evidence_ids: vec![EvidenceId::new()],
        };
        let observation = || {
            WordPressObservedAssetFingerprint::new(component.clone(), "assets/app.js", 3, [7; 32])
                .unwrap()
        };
        let first_target = selected("a");
        let expected_target = first_target.target_url.clone();
        let representations = vec![
            CommittedRepresentation {
                selected: first_target,
                observation: observation(),
                root_evidence_id: EvidenceId::parse("z-evidence").unwrap(),
            },
            CommittedRepresentation {
                selected: selected("z"),
                observation: observation(),
                root_evidence_id: EvidenceId::parse("a-evidence").unwrap(),
            },
        ];

        let (receipt_target, observations, evidence_ids) =
            summarize_reused_representations(representations);
        assert_eq!(receipt_target, expected_target);
        assert_eq!(observations.len(), 1);
        assert_eq!(evidence_ids.len(), 1);
        assert_eq!(evidence_ids[0].as_str(), "z-evidence");
    }

    #[test]
    fn root_asset_bindings_respect_the_same_subject_derivation_boundary() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let role = application.join("wp-content/plugins/").unwrap();
        let document = application.join("contact/").unwrap();
        let target = role.join("sample-plugin/assets/app.js?ver=one").unwrap();
        let component =
            WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "sample-plugin")
                .unwrap();
        let candidate = WordPressObservedAssetCandidate::from_html_reference(
            &application,
            &role,
            component.clone(),
            &document,
            &document,
            "/blog/wp-content/plugins/sample-plugin/assets/app.js?ver=one",
            &target,
            "assets/app.js",
            opaque_url_reference("wordpress-discovery-page", &document),
        )
        .unwrap();
        let root = EntityId::new("endpoint:https://example.test/blog/").unwrap();
        let nomination = candidate_binding_evidence(&root, &candidate).unwrap();
        assert_eq!(nomination.subject(), &root);
        assert!(nomination.origin().derivation().is_none());
        assert_eq!(
            nomination.source().method(),
            "committed-html-resource-nomination"
        );

        let nomination_parents = vec![EvidenceId::new(), EvidenceId::new()];
        let selected = WordPressSelectedObservedAsset {
            application_url: application,
            role_base_url: role,
            target_url: target,
            component: component.clone(),
            relative_path: "assets/app.js".to_owned(),
            resource_reference: "resource-one".to_owned(),
            source_page_references: vec!["page-one".to_owned()],
            source_evidence_ids: nomination_parents.clone(),
        };
        let observation =
            WordPressObservedAssetFingerprint::new(component, "assets/app.js", 3, [7; 32]).unwrap();
        let endpoint_parent = EvidenceId::new();
        let reused = root_representation_binding_evidence(
            &root,
            &selected,
            &observation,
            &endpoint_parent,
            "reused-complete-response",
        )
        .unwrap();
        assert_eq!(reused.subject(), &root);
        assert!(reused.origin().derivation().is_none());
        assert_eq!(reused.source().method(), "reused-complete-response");
        assert!(
            matches!(reused.value(), EvidenceValue::Text(value) if value.contains("source-binding:sha256:"))
        );

        let fetched = fetched_representation_evidence(
            &root,
            &selected,
            &observation,
            ConfidenceScore::from_percent(80).unwrap(),
        )
        .unwrap();
        let fetched_derivation = fetched.origin().derivation().unwrap();
        assert_eq!(
            fetched_derivation.algorithm().name(),
            ASSET_FETCHED_ROOT_DERIVATION
        );
        assert_eq!(
            fetched_derivation
                .parents()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            nomination_parents.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn one_resource_has_a_closed_source_page_binding_limit() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let role = application.join("wp-content/plugins/").unwrap();
        let target = role.join("sample-plugin/assets/app.js").unwrap();
        let component =
            WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "sample-plugin")
                .unwrap();
        let candidates = (0..9)
            .map(|ordinal| {
                let document = application.join(&format!("page-{ordinal}/")).unwrap();
                WordPressObservedAssetCandidate::from_html_reference(
                    &application,
                    &role,
                    component.clone(),
                    &document,
                    &document,
                    "/blog/wp-content/plugins/sample-plugin/assets/app.js",
                    &target,
                    "assets/app.js",
                    opaque_url_reference("wordpress-discovery-page", &document),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let existing = std::collections::BTreeMap::new();

        assert!(source_page_capacity_allows(&existing, &candidates[..4]));
        for count in [5, 8, 9] {
            assert!(
                !source_page_capacity_allows(&existing, &candidates[..count]),
                "{count} distinct page bindings must stop before report projection"
            );
        }

        let query_variants = (0..5)
            .map(|ordinal| {
                let document = application
                    .join(&format!("variant-page-{ordinal}/"))
                    .unwrap();
                let query = if ordinal % 2 == 0 { "one" } else { "two" };
                let variant_target = role
                    .join(&format!("sample-plugin/assets/app.js?ver={query}"))
                    .unwrap();
                WordPressObservedAssetCandidate::from_html_reference(
                    &application,
                    &role,
                    component.clone(),
                    &document,
                    &document,
                    &format!("/blog/wp-content/plugins/sample-plugin/assets/app.js?ver={query}"),
                    &variant_target,
                    "assets/app.js",
                    opaque_url_reference("wordpress-discovery-page", &document),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(source_page_capacity_allows(&existing, &query_variants[..4]));
        assert!(!source_page_capacity_allows(&existing, &query_variants));
    }

    #[test]
    fn resource_reference_identifies_the_scoped_path_not_a_query_variant() {
        let application = Url::parse("https://example.test/blog/").unwrap();
        let component =
            WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "sample-plugin")
                .unwrap();
        let reference = asset_path_reference(&application, &component, "assets/app.js");

        assert!(reference.starts_with("sha256:"));
        assert_eq!(reference.len(), 71);
        assert_eq!(
            reference,
            asset_path_reference(&application, &component, "assets/app.js")
        );
        assert_ne!(
            reference,
            asset_path_reference(&application, &component, "assets/app.css")
        );
        assert_ne!(
            reference,
            asset_path_reference(
                &Url::parse("https://example.test/other/").unwrap(),
                &component,
                "assets/app.js"
            )
        );
    }
}
