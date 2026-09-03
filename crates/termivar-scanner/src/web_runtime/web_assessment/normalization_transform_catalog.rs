//! Closed metadata-first catalog for normalization-resilience review.
//!
//! Selection is complete before one payload seed is materialized. Catalog
//! breadth therefore cannot increase request breadth: V1 selects at most one
//! executable transform with a chain depth of exactly one.

use std::{cmp::Reverse, collections::BTreeSet, fmt};

use crate::{
    payload_strategies::normalization_resilience_query_pair::{
        ExecutableNormalizationTransform, NormalizationProbeFamily, NormalizationProbeQuote,
        NormalizationProbeSeed, NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
        NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
    },
    payload_strategy::PayloadStrategyRef,
    DefenseProduct,
};

use super::{AttributeQuoteMode, XssProbeFamily, XssProbeSelection};

pub(in crate::web_runtime) const NORMALIZATION_V1_MAX_SELECTED_TRANSFORMS: usize = 1;
pub(in crate::web_runtime) const NORMALIZATION_V1_MAX_CHAIN_DEPTH: u8 = 1;
/// One shared-authority child bootstrap, one transformed candidate, one replay.
pub(in crate::web_runtime) const NORMALIZATION_V1_MAX_CHILD_REQUESTS: u8 = 3;
/// The replay leg is the one active verification in the selected child pair.
pub(in crate::web_runtime) const NORMALIZATION_V1_MAX_CHILD_ACTIVE_VERIFICATIONS: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::web_runtime) struct NormalizationTransformRef {
    id: &'static str,
    revision: u32,
}

impl NormalizationTransformRef {
    pub(in crate::web_runtime) const fn id(self) -> &'static str {
        self.id
    }

    pub(in crate::web_runtime) const fn revision(self) -> u32 {
        self.revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum NormalizationTransformLayer {
    HtmlSyntax,
    QueryWireEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum NormalizationExecutionAvailability {
    Executable,
    MetadataOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum NormalizationSemanticVerifier {
    ExactHtmlNodeBoundary,
    ExactHtmlAttributeBoundary,
    ExplicitDecodeDepthUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum NormalizationMaximumAuthority {
    KnowledgeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NormalizationTransformFamily {
    HtmlTokenCase,
    HtmlInterTokenTab,
    QueryPercentDecodeDepthOne,
    QueryPercentDecodeDepthTwo,
}

impl NormalizationTransformFamily {
    const fn all() -> [Self; 4] {
        [
            Self::HtmlTokenCase,
            Self::HtmlInterTokenTab,
            Self::QueryPercentDecodeDepthOne,
            Self::QueryPercentDecodeDepthTwo,
        ]
    }

    const fn transform_ref(self) -> NormalizationTransformRef {
        let id = match self {
            Self::HtmlTokenCase => "xss.html-token-case",
            Self::HtmlInterTokenTab => "xss.html-inter-token-tab",
            Self::QueryPercentDecodeDepthOne => "query.percent-decode-depth-one",
            Self::QueryPercentDecodeDepthTwo => "query.percent-decode-depth-two",
        };
        NormalizationTransformRef { id, revision: 1 }
    }

    const fn layer(self) -> NormalizationTransformLayer {
        match self {
            Self::HtmlTokenCase | Self::HtmlInterTokenTab => {
                NormalizationTransformLayer::HtmlSyntax
            },
            Self::QueryPercentDecodeDepthOne | Self::QueryPercentDecodeDepthTwo => {
                NormalizationTransformLayer::QueryWireEncoding
            },
        }
    }

    const fn availability(self) -> NormalizationExecutionAvailability {
        match self {
            Self::HtmlTokenCase | Self::HtmlInterTokenTab => {
                NormalizationExecutionAvailability::Executable
            },
            Self::QueryPercentDecodeDepthOne | Self::QueryPercentDecodeDepthTwo => {
                NormalizationExecutionAvailability::MetadataOnly
            },
        }
    }

    const fn semantic_verifier(self) -> NormalizationSemanticVerifier {
        match self {
            Self::HtmlTokenCase => NormalizationSemanticVerifier::ExactHtmlNodeBoundary,
            Self::HtmlInterTokenTab => NormalizationSemanticVerifier::ExactHtmlAttributeBoundary,
            Self::QueryPercentDecodeDepthOne | Self::QueryPercentDecodeDepthTwo => {
                NormalizationSemanticVerifier::ExplicitDecodeDepthUnavailable
            },
        }
    }

    const fn compatible_parent(self, family: XssProbeFamily) -> bool {
        match self {
            Self::HtmlTokenCase => matches!(family, XssProbeFamily::HtmlTextBoundary),
            Self::HtmlInterTokenTab => matches!(
                family,
                XssProbeFamily::AttributeValueBoundary
                    | XssProbeFamily::UriAttributeBoundary
                    | XssProbeFamily::EventHandlerAttributeBoundary
            ),
            Self::QueryPercentDecodeDepthOne | Self::QueryPercentDecodeDepthTwo => matches!(
                family,
                XssProbeFamily::HtmlTextBoundary
                    | XssProbeFamily::AttributeValueBoundary
                    | XssProbeFamily::UriAttributeBoundary
                    | XssProbeFamily::EventHandlerAttributeBoundary
            ),
        }
    }

    const fn operational_risk_basis_points(self) -> u16 {
        match self {
            Self::HtmlTokenCase | Self::HtmlInterTokenTab => 100,
            Self::QueryPercentDecodeDepthOne | Self::QueryPercentDecodeDepthTwo => 200,
        }
    }

    const fn request_cost(self) -> u8 {
        let _ = self;
        2
    }

    const fn active_verification_cost(self) -> u8 {
        let _ = self;
        1
    }

    const fn max_chain_depth(self) -> u8 {
        let _ = self;
        1
    }

    const fn maximum_authority(self) -> NormalizationMaximumAuthority {
        let _ = self;
        NormalizationMaximumAuthority::KnowledgeOnly
    }

    /// V1 ships no product-specific transform promise. This function remains
    /// the deterministic tie-break seam for later reviewed metadata.
    const fn product_affinity(self, _product: DefenseProduct) -> bool {
        let _ = self;
        false
    }

    const fn executable_transform(self) -> Option<ExecutableNormalizationTransform> {
        match self {
            Self::HtmlTokenCase => Some(ExecutableNormalizationTransform::HtmlTokenCase),
            Self::HtmlInterTokenTab => Some(ExecutableNormalizationTransform::HtmlInterTokenTab),
            Self::QueryPercentDecodeDepthOne | Self::QueryPercentDecodeDepthTwo => None,
        }
    }

    const fn candidate_shape_id(self) -> &'static str {
        match self {
            Self::HtmlTokenCase => "html-scanner-token-case@1",
            Self::HtmlInterTokenTab => "html-first-scanner-separator-tab@1",
            Self::QueryPercentDecodeDepthOne => "query-percent-depth-one@1",
            Self::QueryPercentDecodeDepthTwo => "query-percent-depth-two@1",
        }
    }
}

/// Metadata-selected transform retaining the exact typed parent selection.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) struct NormalizationTransformSelection {
    transform: NormalizationTransformFamily,
    parent: XssProbeSelection,
}

impl NormalizationTransformSelection {
    pub(in crate::web_runtime) const fn transform_ref(&self) -> NormalizationTransformRef {
        self.transform.transform_ref()
    }

    pub(in crate::web_runtime) const fn parent_family(&self) -> XssProbeFamily {
        self.parent.family()
    }

    pub(in crate::web_runtime) const fn parent_selection(&self) -> &XssProbeSelection {
        &self.parent
    }

    pub(in crate::web_runtime) fn strategy_ref(&self) -> PayloadStrategyRef {
        PayloadStrategyRef::new(
            NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
            NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
        )
        .expect("the normalization-resilience strategy identity is static and valid")
    }

    pub(in crate::web_runtime) const fn semantic_verifier(&self) -> NormalizationSemanticVerifier {
        self.transform.semantic_verifier()
    }

    pub(in crate::web_runtime) const fn layer(&self) -> NormalizationTransformLayer {
        self.transform.layer()
    }

    pub(in crate::web_runtime) const fn maximum_authority(&self) -> NormalizationMaximumAuthority {
        self.transform.maximum_authority()
    }

    /// Rechecks the executable V1 metadata contract before materialization.
    /// Selection already applies these predicates; retaining the check on the
    /// typed value prevents metadata-only or verifier-incompatible entries
    /// from crossing a later execution boundary.
    pub(in crate::web_runtime) fn is_executable_v1_contract(&self) -> bool {
        self.maximum_authority() == NormalizationMaximumAuthority::KnowledgeOnly
            && self.layer() == NormalizationTransformLayer::HtmlSyntax
            && matches!(
                (self.parent_family(), self.semantic_verifier()),
                (
                    XssProbeFamily::HtmlTextBoundary,
                    NormalizationSemanticVerifier::ExactHtmlNodeBoundary,
                ) | (
                    XssProbeFamily::AttributeValueBoundary
                        | XssProbeFamily::UriAttributeBoundary
                        | XssProbeFamily::EventHandlerAttributeBoundary,
                    NormalizationSemanticVerifier::ExactHtmlAttributeBoundary,
                )
            )
    }

    /// Builds the bounded typed strategy seed after metadata selection.
    pub(in crate::web_runtime) fn strategy_seed(
        &self,
        transformed_identity: &str,
        replay_identity: &str,
    ) -> Option<String> {
        let family = match self.parent.family() {
            XssProbeFamily::HtmlTextBoundary => NormalizationProbeFamily::HtmlText,
            XssProbeFamily::AttributeValueBoundary => NormalizationProbeFamily::AttributeValue,
            XssProbeFamily::UriAttributeBoundary => NormalizationProbeFamily::UriAttribute,
            XssProbeFamily::EventHandlerAttributeBoundary => {
                NormalizationProbeFamily::EventHandlerAttribute
            },
            XssProbeFamily::UriAttributeStructure
            | XssProbeFamily::EventHandlerStructure
            | XssProbeFamily::ScriptContentStructure
            | XssProbeFamily::ScriptSingleQuotedStringBoundary
            | XssProbeFamily::ScriptDoubleQuotedStringBoundary
            | XssProbeFamily::ScriptTemplateLiteralBoundary
            | XssProbeFamily::ScriptExpressionStructure
            | XssProbeFamily::ScriptTemplateExpressionStructure
            | XssProbeFamily::ScriptLineCommentStructure
            | XssProbeFamily::ScriptBlockCommentStructure
            | XssProbeFamily::ScriptRegexStructure => return None,
        };
        let quote = match self.parent.quote_mode() {
            None => NormalizationProbeQuote::NotApplicable,
            Some(AttributeQuoteMode::DoubleQuoted) => NormalizationProbeQuote::DoubleQuoted,
            Some(AttributeQuoteMode::SingleQuoted) => NormalizationProbeQuote::SingleQuoted,
            Some(AttributeQuoteMode::Unquoted) => NormalizationProbeQuote::Unquoted,
        };
        NormalizationProbeSeed::new(
            self.transform.executable_transform()?,
            family,
            quote,
            transformed_identity,
            replay_identity,
        )
        .map(|seed| seed.encode())
    }
}

impl fmt::Debug for NormalizationTransformSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizationTransformSelection")
            .field("transform", &self.transform_ref())
            .field("parent_family", &self.parent.family().stable_id())
            .field("quote_mode", &self.parent.quote_mode())
            .finish()
    }
}

/// Selects at most one executable, exact-family-compatible transform.
///
/// A product hint contributes only a ranking bit after compatibility and
/// executability are established. V1 deliberately declares no such affinity,
/// so fingerprints cannot change its selected transform.
pub(in crate::web_runtime) fn select_normalization_transform(
    parent: &XssProbeSelection,
    product_hint: Option<DefenseProduct>,
) -> Option<NormalizationTransformSelection> {
    let mut compatible = NormalizationTransformFamily::all()
        .into_iter()
        .filter(|transform| {
            transform.availability() == NormalizationExecutionAvailability::Executable
                && transform.compatible_parent(parent.family())
                && transform.max_chain_depth() <= NORMALIZATION_V1_MAX_CHAIN_DEPTH
                && transform.request_cost().saturating_add(1) <= NORMALIZATION_V1_MAX_CHILD_REQUESTS
                && transform.active_verification_cost()
                    <= NORMALIZATION_V1_MAX_CHILD_ACTIVE_VERIFICATIONS
                && transform.maximum_authority() == NormalizationMaximumAuthority::KnowledgeOnly
        })
        .collect::<Vec<_>>();
    compatible.sort_by_key(|transform| {
        (
            Reverse(product_hint.is_some_and(|product| transform.product_affinity(product))),
            transform.operational_risk_basis_points(),
            transform.request_cost(),
            transform.transform_ref().id(),
        )
    });

    let mut candidate_shapes = BTreeSet::new();
    compatible
        .into_iter()
        .filter(|transform| {
            candidate_shapes.insert((
                parent.family(),
                parent.quote_mode(),
                transform.candidate_shape_id(),
            ))
        })
        .take(NORMALIZATION_V1_MAX_SELECTED_TRANSFORMS)
        .next()
        .map(|transform| NormalizationTransformSelection {
            transform,
            parent: parent.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        payload_strategies::normalization_resilience_query_pair::NormalizationResilienceQueryPairStrategy,
        payload_strategy::{
            PayloadSeed, PayloadStrategy, PayloadStrategyLimits, PayloadVariantRole,
        },
        FingerprintConfidence,
    };

    use super::super::{
        classify_exact_html_reflection, cross_validate_attribute_reflection_source,
        match_exact_xss_attribute_boundary_document, select_xss_probe_families,
        validate_exact_xss_html_boundary_fragment, AttributeSourceResult,
        ExactHtmlReflectionContext, ExactXssAttributeBoundaryMatch, ExactXssBoundaryMatch,
        JavaScriptSourceResult,
    };

    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";
    const TRANSFORMED_ID: &str = "0123456789abcdef0123456789abcdef";
    const REPLAY_ID: &str = "fedcba9876543210fedcba9876543210";
    const SECRET: &str = "VENOM-NORMALIZATION-RESILIENCE-MUST-NOT-LEAK-SECRET-123";

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::new(512, 512).unwrap()
    }

    fn html_parent() -> XssProbeSelection {
        select_xss_probe_families(
            ExactHtmlReflectionContext::HtmlText,
            &AttributeSourceResult::Absent,
            &JavaScriptSourceResult::Absent,
        )
        .pop()
        .unwrap()
    }

    fn attribute_parent(
        element: &str,
        attribute: &str,
        quote: AttributeQuoteMode,
    ) -> (String, AttributeSourceResult, XssProbeSelection) {
        let source_value = match quote {
            AttributeQuoteMode::DoubleQuoted => format!("\"{MARKER}\""),
            AttributeQuoteMode::SingleQuoted => format!("'{MARKER}'"),
            AttributeQuoteMode::Unquoted => MARKER.to_owned(),
        };
        let source = format!("<{element} {attribute}={source_value}></{element}>");
        let context = classify_exact_html_reflection(&source, MARKER);
        let attribute_source = cross_validate_attribute_reflection_source(&source, MARKER, context);
        let selection =
            select_xss_probe_families(context, &attribute_source, &JavaScriptSourceResult::Absent)
                .pop()
                .unwrap();
        (source, attribute_source, selection)
    }

    fn derive(
        selection: &NormalizationTransformSelection,
        role: PayloadVariantRole,
    ) -> crate::PayloadArtifact {
        let seed = PayloadSeed::new(
            selection
                .strategy_seed(TRANSFORMED_ID, REPLAY_ID)
                .unwrap()
                .into_bytes(),
            limits(),
        )
        .unwrap();
        NormalizationResilienceQueryPairStrategy::new()
            .derive_one(role, &seed, limits())
            .unwrap()
    }

    #[test]
    fn catalog_is_closed_versioned_metadata_first_and_bounded() {
        let mut identities = BTreeSet::new();
        for transform in NormalizationTransformFamily::all() {
            let reference = transform.transform_ref();
            assert!(identities.insert((reference.id(), reference.revision())));
            assert_eq!(reference.revision(), 1);
            assert_eq!(
                transform.max_chain_depth(),
                NORMALIZATION_V1_MAX_CHAIN_DEPTH
            );
            assert_eq!(
                transform.request_cost() + 1,
                NORMALIZATION_V1_MAX_CHILD_REQUESTS
            );
            assert_eq!(
                transform.active_verification_cost(),
                NORMALIZATION_V1_MAX_CHILD_ACTIVE_VERIFICATIONS
            );
            assert_eq!(
                transform.maximum_authority(),
                NormalizationMaximumAuthority::KnowledgeOnly
            );
        }
        assert_eq!(identities.len(), 4);
        assert_eq!(NORMALIZATION_V1_MAX_SELECTED_TRANSFORMS, 1);
        assert_eq!(NORMALIZATION_V1_MAX_CHAIN_DEPTH, 1);
        assert_eq!(NORMALIZATION_V1_MAX_CHILD_REQUESTS, 3);
        assert_eq!(NORMALIZATION_V1_MAX_CHILD_ACTIVE_VERIFICATIONS, 1);
    }

    #[test]
    fn exact_parent_compatibility_selects_one_and_fingerprint_never_authorizes() {
        let html = html_parent();
        let selected = select_normalization_transform(&html, None).unwrap();
        assert_eq!(selected.transform_ref().id(), "xss.html-token-case");
        assert_eq!(selected.parent_selection(), &html);
        assert_eq!(selected.parent_family(), XssProbeFamily::HtmlTextBoundary);
        assert_eq!(selected.layer(), NormalizationTransformLayer::HtmlSyntax);
        assert_eq!(
            selected.semantic_verifier(),
            NormalizationSemanticVerifier::ExactHtmlNodeBoundary
        );
        assert_eq!(
            selected.maximum_authority(),
            NormalizationMaximumAuthority::KnowledgeOnly
        );
        assert!(selected.is_executable_v1_contract());
        assert_eq!(
            selected.strategy_ref().to_string(),
            "web.review.normalization-resilience@1"
        );

        for product in [DefenseProduct::Cloudflare, DefenseProduct::ModSecurity] {
            assert_eq!(
                select_normalization_transform(&html, Some(product)),
                Some(selected.clone())
            );
        }
        let (_, _, attribute) = attribute_parent("a", "href", AttributeQuoteMode::DoubleQuoted);
        assert_eq!(
            select_normalization_transform(&attribute, Some(DefenseProduct::Cloudflare))
                .unwrap()
                .transform_ref()
                .id(),
            "xss.html-inter-token-tab"
        );

        // A confidence value belongs to the caller's evidence gate. Merely
        // having one cannot make either metadata-only percent family execute.
        let _weak = FingerprintConfidence::Weak;
        assert!(NormalizationTransformFamily::QueryPercentDecodeDepthOne
            .executable_transform()
            .is_none());
        assert!(NormalizationTransformFamily::QueryPercentDecodeDepthTwo
            .executable_transform()
            .is_none());
    }

    #[test]
    fn html_token_case_preserves_the_exact_existing_dom_semantics() {
        let selected = select_normalization_transform(&html_parent(), None).unwrap();
        let transformed = derive(&selected, PayloadVariantRole::Control);
        let replay = derive(&selected, PayloadVariantRole::Candidate);
        assert_eq!(
            validate_exact_xss_html_boundary_fragment(
                std::str::from_utf8(transformed.as_bytes()).unwrap(),
                TRANSFORMED_ID,
            ),
            ExactXssBoundaryMatch::Matched
        );
        assert_eq!(
            validate_exact_xss_html_boundary_fragment(
                std::str::from_utf8(replay.as_bytes()).unwrap(),
                REPLAY_ID,
            ),
            ExactXssBoundaryMatch::Matched
        );
        for artifact in [&transformed, &replay] {
            let value = std::str::from_utf8(artifact.as_bytes()).unwrap();
            assert!(!value.contains(SECRET));
            assert!(!value
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0')));
            let debug = format!("{artifact:?}");
            assert!(!debug.contains(value));
            assert!(!debug.contains(TRANSFORMED_ID));
            assert!(!debug.contains(REPLAY_ID));
        }
    }

    #[test]
    fn html_tab_transform_preserves_each_attribute_parent_semantics() {
        for (element, attribute, quote) in [
            ("div", "title", AttributeQuoteMode::DoubleQuoted),
            ("a", "href", AttributeQuoteMode::SingleQuoted),
            ("button", "onclick", AttributeQuoteMode::Unquoted),
        ] {
            let (source, attribute_source, parent) = attribute_parent(element, attribute, quote);
            let selected = select_normalization_transform(&parent, None).unwrap();
            assert_eq!(selected.transform_ref().id(), "xss.html-inter-token-tab");
            let transformed = derive(&selected, PayloadVariantRole::Control);
            let value = std::str::from_utf8(transformed.as_bytes()).unwrap();
            assert_eq!(value.bytes().filter(|byte| *byte == b'\t').count(), 1);
            assert!(!value
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0')));
            assert!(!value.contains(SECRET));
            let document = source.replace(MARKER, value);
            let anchor = attribute_source.exact_anchor().unwrap();
            assert_eq!(
                match_exact_xss_attribute_boundary_document(&document, TRANSFORMED_ID, anchor,),
                ExactXssAttributeBoundaryMatch::Matched
            );
        }
    }

    #[test]
    fn selection_is_deterministic_and_precedes_distinct_identity_materialization() {
        let parent = html_parent();
        let first = select_normalization_transform(&parent, None).unwrap();
        for _ in 0..1_000 {
            assert_eq!(
                select_normalization_transform(&parent, None),
                Some(first.clone())
            );
        }
        assert!(first
            .strategy_seed(TRANSFORMED_ID, TRANSFORMED_ID)
            .is_none());
        let seed = first.strategy_seed(TRANSFORMED_ID, REPLAY_ID).unwrap();
        assert!(!format!("{first:?}").contains(TRANSFORMED_ID));
        assert!(seed.contains(TRANSFORMED_ID));
        assert!(seed.contains(REPLAY_ID));
        let candidate = derive(&first, PayloadVariantRole::Control);
        let replay = derive(&first, PayloadVariantRole::Candidate);
        assert_ne!(candidate.as_bytes(), replay.as_bytes());
        assert_ne!(candidate.receipt().sha256(), replay.receipt().sha256());
    }
}
