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

/// Observation-only product item emitted when the root response carried at
/// least one supported structured WordPress hint.
pub const WORDPRESS_REVIEW_CAPABILITY_ID: &str = "technology.wordpress-surface-observed@1";

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

#[derive(Default)]
struct CollectedSignals {
    signals: Vec<WordPressComponentSignal>,
    evidence_ids: BTreeSet<EvidenceId>,
    limit_exceeded: bool,
}

/// One assessment-owned sink shared only with its root discovery observer.
#[derive(Clone, Default)]
pub(super) struct WordPressSignalCollector(Arc<Mutex<CollectedSignals>>);

impl WordPressSignalCollector {
    pub(super) fn record(
        &self,
        signals: impl IntoIterator<Item = WordPressComponentSignal>,
        evidence_ids: impl IntoIterator<Item = EvidenceId>,
    ) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut retained_signal = false;
        for signal in signals {
            if state.signals.contains(&signal) {
                retained_signal = true;
                continue;
            }
            if state.signals.len() == MAX_WORDPRESS_SIGNALS {
                state.limit_exceeded = true;
                break;
            }
            state.signals.push(signal);
            retained_signal = true;
        }
        if retained_signal {
            state.evidence_ids.extend(evidence_ids);
        }
    }

    fn snapshot(
        &self,
    ) -> Result<(Vec<WordPressComponentSignal>, Vec<EvidenceId>), WordPressReviewError> {
        let state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.limit_exceeded {
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
}

pub(super) struct WordPressReviewBinding {
    inputs: WordPressReviewInputs,
    collector: WordPressSignalCollector,
}

impl WordPressReviewBinding {
    pub(super) fn new(inputs: WordPressReviewInputs) -> Self {
        Self {
            inputs,
            collector: WordPressSignalCollector::default(),
        }
    }

    pub(super) fn collector(&self) -> WordPressSignalCollector {
        self.collector.clone()
    }

    pub(super) fn finish(
        self,
        subject: EntityId,
    ) -> Result<CommittedWordPressReview, WordPressReviewError> {
        let (signals, evidence_ids) = self.collector.snapshot()?;
        let result = evaluate_wordpress_review(&signals, &self.inputs)?;
        let audit = WebAssessmentWordPressAudit {
            result,
            signal_count: u16::try_from(signals.len())
                .map_err(|_| WordPressReviewError::SignalLimitExceeded)?,
            evidence_reference_count: u16::try_from(evidence_ids.len())
                .map_err(|_| WordPressReviewError::SignalLimitExceeded)?,
            item_projected: !signals.is_empty(),
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

    /// WordPress interpretation adds no target or provider request.
    pub const fn additional_request_count(&self) -> u8 {
        0
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
    if review.audit.item_projected {
        context.project_observation(
            &WORDPRESS_REVIEW_CAPABILITY,
            knowledge,
            &review.subject,
            &AssessmentItemTarget::subject(),
            &review.evidence_ids,
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
                    return document_url.join(reference.trim()).ok();
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
}
