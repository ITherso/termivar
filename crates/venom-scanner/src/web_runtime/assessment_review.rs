//! Bounded native web-review evidence and committed matched-pair replay.
//!
//! The HTTP executor lends this module only a fixed-vocabulary response
//! projection and, for reflection review, a complete bounded body. Raw
//! headers, payload bytes, and partial bodies never cross the retained evidence
//! boundary. Product projection must consume [`AssessmentReviewCandidate`]
//! values rather than interpreting action success as a vulnerability.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use html5ever::{parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use venom_core::{
    DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId, EvidenceKind,
    EvidenceOrigin, EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
    OutcomeStatus, VerificationStage,
};

use crate::{
    http_evidence::{
        CompleteHttpResponseObservation, CompleteHttpResponseObserver,
        CorsAllowCredentialsRelation, CorsAllowOriginRelation, LocationRelation,
        VaryOriginRelation,
    },
    payload_strategies::{
        ExternalUrlQueryPairStrategy, XssAttributeBoundaryQueryPairStrategy,
        XssJavascriptLexicalBoundaryQueryPairStrategy, XssJavascriptLexicalProbeTokens,
        XssStructuralQueryPairStrategy, CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION,
        EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION,
        REFLECTION_MARKER_QUERY_PAIR_ID, REFLECTION_MARKER_QUERY_PAIR_REVISION,
        SQL_QUOTE_BALANCE_QUERY_PAIR_ID, SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        SSTI_ARITHMETIC_EXPRESSION_PAIR_ID, SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID, XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
        XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION, XSS_STRUCTURAL_QUERY_PAIR_ID,
        XSS_STRUCTURAL_QUERY_PAIR_REVISION,
    },
    web_actions::{
        NativeWebReviewActionKind, NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE,
        NATIVE_WEB_REVIEW_RESPONSE_MARKER,
    },
    DecisionEvidenceReceipt, DecisionExecutionStage, DecisionOutcomeReport, HttpEvidenceError,
    HttpProbeMethod, KnowledgeBase, KnowledgeWrite, PayloadSeed, PayloadStrategy,
    PayloadStrategyLimits, PayloadStrategyRef, PayloadVariantRole,
};

#[cfg(feature = "normalization-resilience")]
use crate::DefensePosture;

#[cfg(feature = "normalization-resilience")]
use super::assessment_defense::{AssessmentDefenseBodyCoverage, CommittedAssessmentDefenseLedger};
use super::web_assessment::{
    classify_exact_html_reflection, cross_validate_attribute_reflection_source,
    cross_validate_javascript_reflection_source, match_exact_xss_attribute_boundary_document,
    match_exact_xss_html_boundary_document, match_exact_xss_javascript_boundary_document,
    validate_exact_xss_html_boundary_fragment, validate_exact_xss_javascript_boundary_candidate,
    AttributeSourceResult, ExactHtmlReflectionContext, ExactJavaScriptBoundaryMatch,
    ExactXssAttributeBoundaryMatch, ExactXssBoundaryMatch, JavaScriptSourceResult, XssProbeFamily,
    XssProbeSelection,
};
#[cfg(feature = "normalization-resilience")]
use super::web_assessment::{NormalizationTransformRef, NormalizationTransformSelection};
use super::web_review_execution::NativeWebReviewSeeds;
#[cfg(feature = "normalization-resilience")]
use crate::payload_strategies::normalization_resilience_query_pair::{
    NormalizationResilienceQueryPairStrategy, NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
    NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
};
use crate::payload_strategies::ssti_arithmetic_expression_pair::SstiArithmeticProbe;

const ASSESSMENT_REVIEW_CATEGORY: &str = "web-review-observation";
const ASSESSMENT_REVIEW_ALGORITHM: &str = "web.review.bounded-response-relations";
const ASSESSMENT_REVIEW_ALGORITHM_VERSION: u32 = 1;
const MAX_REVIEW_QUERY_PARAMETER_BYTES: usize = 64;
const MAX_REVIEW_CANDIDATE_BYTES: usize = 2_048;
const MAX_REVIEW_OBSERVATIONS: usize = crate::web_actions::NATIVE_WEB_REVIEW_ACTION_COUNT * 2;
const MAX_SQL_STRUCTURE_NODES: usize = 256;

const CORS_ALLOW_ORIGIN_RELATION: &str = "cors-allow-origin-relation";
const CORS_ALLOW_CREDENTIALS_RELATION: &str = "cors-allow-credentials-relation";
const CORS_VARY_ORIGIN_RELATION: &str = "cors-vary-origin-relation";
const CORS_HTTP_STATUS_CLASS: &str = "cors-http-status-class";
const REDIRECT_STATUS_RELATION: &str = "redirect-status-relation";
const REDIRECT_LOCATION_RELATION: &str = "redirect-location-relation";
const HTML_REFLECTION_CONTEXT: &str = "html-reflection-context";
const HTML_ATTRIBUTE_SOURCE_STATUS: &str = "html-attribute-source-status";
const HTML_ATTRIBUTE_SOURCE_QUOTE_MODE: &str = "html-attribute-source-quote-mode";
const HTML_ATTRIBUTE_SOURCE_ELEMENT: &str = "html-attribute-source-element";
const HTML_ATTRIBUTE_SOURCE_NAME: &str = "html-attribute-source-name";
const HTML_ATTRIBUTE_SOURCE_CONTEXT: &str = "html-attribute-source-context";
const JAVASCRIPT_SOURCE_STATUS: &str = "javascript-source-status";
const JAVASCRIPT_SOURCE_SCRIPT_KIND: &str = "javascript-source-script-kind";
const JAVASCRIPT_SOURCE_CONTEXT: &str = "javascript-source-context";
const JAVASCRIPT_SOURCE_SCRIPT_ORDINAL: &str = "javascript-source-script-ordinal";
const SQL_HTTP_STATUS_CLASS: &str = "sql-http-status-class";
const SQL_BODY_STRUCTURE: &str = "sql-body-structure";
const SSTI_HTTP_STATUS_CLASS: &str = "ssti-http-status-class";
const SSTI_EVALUATION_RELATION: &str = "ssti-evaluation-relation";
const XSS_PROBE_FAMILY: &str = "xss-probe-family";
const XSS_PROBE_VARIANT: &str = "xss-probe-variant";
const XSS_STRUCTURAL_RELATION: &str = "xss-structural-relation";

const CORS_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.cors-policy-pair.pair-complete@1";
const REDIRECT_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.redirect-reflection-query-pair.pair-complete@1";
const REFLECTION_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.reflection-context-query-pair.pair-complete@1";
const SQL_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.sql-structural-query-pair.pair-complete@1";
const SQL_REPLAY_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.sql-structural-query-replay-pair.pair-complete@1";
const SSTI_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.ssti-structural-query-pair.pair-complete@1";
const SSTI_REPLAY_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.ssti-structural-query-replay-pair.pair-complete@1";
const XSS_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.xss-structural-query-pair.pair-complete@1";
const XSS_ATTRIBUTE_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.xss-attribute-boundary-query-pair.pair-complete@1";
const XSS_SCRIPT_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.xss-script-lexical-boundary-query-pair.pair-complete@1";
#[cfg(feature = "normalization-resilience")]
const NORMALIZATION_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.normalization-resilience-query-pair.pair-complete@1";
#[cfg(feature = "authorization-review")]
const AUTHORIZATION_ACTIVE_VERIFIER_RULE_ID: &str =
    "web.review.verify.active.authorization-resource-differential.pair-complete@1";

/// Returns the one verifier identity authorized to classify pair completion.
///
/// This verifier remains knowledge-only. Its `Success` is workflow truth, not
/// claim confirmation.
pub(crate) const fn native_review_active_verifier_rule_id(
    kind: NativeWebReviewActionKind,
) -> &'static str {
    match kind {
        NativeWebReviewActionKind::CorsPolicyPair => CORS_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::RedirectReflectionQueryPair => REDIRECT_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::ReflectionContextQueryPair => REFLECTION_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::SqlStructuralQueryPair => SQL_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::SqlStructuralQueryReplayPair => {
            SQL_REPLAY_ACTIVE_VERIFIER_RULE_ID
        },
        NativeWebReviewActionKind::SstiStructuralQueryPair => SSTI_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::SstiStructuralQueryReplayPair => {
            SSTI_REPLAY_ACTIVE_VERIFIER_RULE_ID
        },
        NativeWebReviewActionKind::XssStructuralQueryPair => XSS_ACTIVE_VERIFIER_RULE_ID,
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => {
            XSS_ATTRIBUTE_ACTIVE_VERIFIER_RULE_ID
        },
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => {
            XSS_SCRIPT_ACTIVE_VERIFIER_RULE_ID
        },
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => {
            NORMALIZATION_ACTIVE_VERIFIER_RULE_ID
        },
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => {
            AUTHORIZATION_ACTIVE_VERIFIER_RULE_ID
        },
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => "web.review.verify.openapi-replay@1",
    }
}

/// Invalid host composition for a sealed native-review observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum AssessmentReviewObserverError {
    #[error("native review requires one canonical query-free HTTP(S) root")]
    Root,
    #[error("native redirect review requires one bounded canonical query parameter name")]
    QueryParameter,
    #[error("native redirect review requires one bounded inert external candidate")]
    Candidate,
}

#[derive(Clone, PartialEq, Eq)]
struct RedirectReflectionContract {
    query_parameter: String,
    candidate_url: Url,
    candidate_value: String,
}

#[derive(Clone, PartialEq, Eq)]
struct ReflectionContextContract {
    query_parameter: String,
    control_url: Url,
    candidate_url: Url,
    candidate_value: String,
}

#[derive(Clone, PartialEq, Eq)]
struct SqlStructuralContract {
    query_parameter: String,
    control_url: Url,
    candidate_url: Url,
}

#[derive(Clone, PartialEq, Eq)]
struct SstiProbeContract {
    probe: SstiArithmeticProbe,
    control_url: Url,
    candidate_url: Url,
}

#[derive(Clone, PartialEq, Eq)]
struct SstiStructuralContract {
    query_parameter: String,
    primary: SstiProbeContract,
    replay: SstiProbeContract,
}

#[derive(Clone, PartialEq, Eq)]
struct XssStructuralProbeParts {
    selection: XssProbeSelection,
    control_identity: String,
    candidate_identity: String,
    control_value: String,
    candidate_value: String,
}

impl XssStructuralProbeParts {
    fn derive_values(
        selection: XssProbeSelection,
        identity: &str,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let limits = PayloadStrategyLimits::new(256, 256)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let seed = PayloadSeed::new(selection.strategy_seed(identity).into_bytes(), limits)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let strategy: Box<dyn PayloadStrategy> = match selection.action_kind() {
            NativeWebReviewActionKind::XssStructuralQueryPair => {
                Box::new(XssStructuralQueryPairStrategy::new())
            },
            NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => {
                Box::new(XssAttributeBoundaryQueryPairStrategy::new())
            },
            NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => {
                Box::new(XssJavascriptLexicalBoundaryQueryPairStrategy::new())
            },
            _ => return Err(AssessmentReviewObserverError::Candidate),
        };
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let control_value = std::str::from_utf8(control.as_bytes())
            .map_err(|_| AssessmentReviewObserverError::Candidate)?
            .to_owned();
        let candidate_value = std::str::from_utf8(candidate.as_bytes())
            .map_err(|_| AssessmentReviewObserverError::Candidate)?
            .to_owned();
        Ok(Self {
            selection,
            control_identity: identity.to_owned(),
            candidate_identity: identity.to_owned(),
            control_value,
            candidate_value,
        })
    }

    fn validate(self) -> Result<XssStructuralProbe, AssessmentReviewObserverError> {
        self.validate_structural_value(&self.candidate_value, &self.candidate_identity)?;
        Ok(XssStructuralProbe(self))
    }

    fn validate_structural_value(
        &self,
        value: &str,
        identity: &str,
    ) -> Result<(), AssessmentReviewObserverError> {
        match self.selection.family() {
            XssProbeFamily::HtmlTextBoundary => {
                if validate_exact_xss_html_boundary_fragment(value, identity)
                    != ExactXssBoundaryMatch::Matched
                {
                    return Err(AssessmentReviewObserverError::Candidate);
                }
            },
            XssProbeFamily::AttributeValueBoundary
            | XssProbeFamily::UriAttributeBoundary
            | XssProbeFamily::EventHandlerAttributeBoundary => {
                let anchor = self
                    .selection
                    .attribute_anchor()
                    .ok_or(AssessmentReviewObserverError::Candidate)?;
                let quote = match anchor.quote_mode() {
                    super::web_assessment::AttributeQuoteMode::DoubleQuoted => "\"",
                    super::web_assessment::AttributeQuoteMode::SingleQuoted => "'",
                    super::web_assessment::AttributeQuoteMode::Unquoted => "",
                };
                let document = format!(
                    "<{} {}={quote}{}{quote}></{}>",
                    anchor.element_local_name(),
                    anchor.attribute_local_name(),
                    value,
                    anchor.element_local_name(),
                );
                if match_exact_xss_attribute_boundary_document(&document, identity, anchor)
                    != ExactXssAttributeBoundaryMatch::Matched
                {
                    return Err(AssessmentReviewObserverError::Candidate);
                }
            },
            XssProbeFamily::ScriptSingleQuotedStringBoundary
            | XssProbeFamily::ScriptDoubleQuotedStringBoundary
            | XssProbeFamily::ScriptTemplateLiteralBoundary => {
                let anchor = self
                    .selection
                    .javascript_anchor()
                    .ok_or(AssessmentReviewObserverError::Candidate)?;
                let tokens = XssJavascriptLexicalProbeTokens::from_identity(identity)
                    .ok_or(AssessmentReviewObserverError::Candidate)?;
                if validate_exact_xss_javascript_boundary_candidate(
                    value,
                    tokens.boundary_comment(),
                    tokens.tail_comment(),
                    anchor.context(),
                ) != ExactJavaScriptBoundaryMatch::Matched
                {
                    return Err(AssessmentReviewObserverError::Candidate);
                }
            },
            XssProbeFamily::UriAttributeStructure
            | XssProbeFamily::EventHandlerStructure
            | XssProbeFamily::ScriptContentStructure
            | XssProbeFamily::ScriptExpressionStructure
            | XssProbeFamily::ScriptTemplateExpressionStructure
            | XssProbeFamily::ScriptLineCommentStructure
            | XssProbeFamily::ScriptBlockCommentStructure
            | XssProbeFamily::ScriptRegexStructure => {
                return Err(AssessmentReviewObserverError::Candidate);
            },
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct XssStructuralProbe(XssStructuralProbeParts);

impl XssStructuralProbe {
    fn derive(
        selection: XssProbeSelection,
        identity: &str,
    ) -> Result<Self, AssessmentReviewObserverError> {
        XssStructuralProbeParts::derive_values(selection, identity)?.validate()
    }

    #[cfg(feature = "normalization-resilience")]
    fn derive_normalization(
        selection: &NormalizationTransformSelection,
        transformed_identity: &str,
        replay_identity: &str,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let limits = PayloadStrategyLimits::new(256, 256)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let encoded_seed = selection
            .strategy_seed(transformed_identity, replay_identity)
            .ok_or(AssessmentReviewObserverError::Candidate)?;
        let seed = PayloadSeed::new(encoded_seed.into_bytes(), limits)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let strategy = NormalizationResilienceQueryPairStrategy::new();
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits)
            .map_err(|_| AssessmentReviewObserverError::Candidate)?;
        let parts = XssStructuralProbeParts {
            selection: selection.parent_selection().clone(),
            control_identity: transformed_identity.to_owned(),
            candidate_identity: replay_identity.to_owned(),
            control_value: std::str::from_utf8(control.as_bytes())
                .map_err(|_| AssessmentReviewObserverError::Candidate)?
                .to_owned(),
            candidate_value: std::str::from_utf8(candidate.as_bytes())
                .map_err(|_| AssessmentReviewObserverError::Candidate)?
                .to_owned(),
        };
        parts.validate_structural_value(&parts.control_value, &parts.control_identity)?;
        parts.validate_structural_value(&parts.candidate_value, &parts.candidate_identity)?;
        Ok(Self(parts))
    }

    const fn parts(&self) -> &XssStructuralProbeParts {
        &self.0
    }
}

impl fmt::Debug for XssStructuralProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XssStructuralProbe")
            .field("family", &self.parts().selection.family().stable_id())
            .field("variant", &self.parts().selection.variant_id())
            .field(
                "identity_bytes",
                &(
                    self.parts().control_identity.len(),
                    self.parts().candidate_identity.len(),
                ),
            )
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct XssStructuralContract {
    query_parameter: String,
    probe: XssStructuralProbe,
    action_kind: NativeWebReviewActionKind,
    variant_id: String,
    #[cfg(feature = "normalization-resilience")]
    normalization_transform: Option<NormalizationTransformRef>,
    control_url: Url,
    candidate_url: Url,
    source_evidence_ids: Vec<EvidenceId>,
    #[cfg(feature = "normalization-resilience")]
    normalization_parent: Option<NormalizationParentEvidence>,
}

/// Exact committed parent authority for one optional normalization child.
///
/// This value is derived only from the sealed XSS review and defense ledgers.
/// It contains no payload, response body, query value, or credential material.
#[cfg(feature = "normalization-resilience")]
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) struct NormalizationParentEvidence {
    root: Url,
    subject: EntityId,
    query_parameter: String,
    selection: XssProbeSelection,
    parent_case: crate::VerificationCase,
    control_evidence_ids: Vec<EvidenceId>,
    canonical_candidate_evidence_ids: Vec<EvidenceId>,
    source_evidence_ids: Vec<EvidenceId>,
}

#[cfg(feature = "normalization-resilience")]
impl fmt::Debug for NormalizationParentEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizationParentEvidence")
            .field("root", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("query_parameter", &"<redacted>")
            .field("parent_family", &self.selection.family().stable_id())
            .field("parent_case", &"<redacted>")
            .field("control_evidence_count", &self.control_evidence_ids.len())
            .field(
                "canonical_candidate_evidence_count",
                &self.canonical_candidate_evidence_ids.len(),
            )
            .finish()
    }
}

#[cfg(feature = "normalization-resilience")]
impl NormalizationParentEvidence {
    pub(in crate::web_runtime) fn selection(&self) -> &XssProbeSelection {
        &self.selection
    }

    pub(in crate::web_runtime) fn query_parameter(&self) -> &str {
        &self.query_parameter
    }

    pub(in crate::web_runtime) fn root(&self) -> &Url {
        &self.root
    }

    pub(in crate::web_runtime) fn subject(&self) -> &EntityId {
        &self.subject
    }

    fn control_evidence_ids(&self) -> &[EvidenceId] {
        &self.control_evidence_ids
    }

    fn canonical_candidate_evidence_ids(&self) -> &[EvidenceId] {
        &self.canonical_candidate_evidence_ids
    }

    fn source_evidence_ids(&self) -> &[EvidenceId] {
        &self.source_evidence_ids
    }
}

fn canonical_xss_source_evidence_ids(
    mut ids: Vec<EvidenceId>,
    required: bool,
) -> Result<Vec<EvidenceId>, AssessmentReviewObserverError> {
    let supplied = ids.len();
    ids.sort();
    ids.dedup();
    let valid_len =
        (!required && ids.is_empty()) || ids.len() == REFLECTION_REVIEW_PROPERTIES.len();
    if ids.len() != supplied || !valid_len {
        return Err(AssessmentReviewObserverError::Candidate);
    }
    Ok(ids)
}

#[derive(Clone, Copy)]
struct ReviewContracts<'a> {
    redirect: Option<&'a RedirectReflectionContract>,
    reflection: Option<&'a ReflectionContextContract>,
    sql: Option<&'a SqlStructuralContract>,
    ssti: Option<&'a SstiStructuralContract>,
    xss: Option<&'a XssStructuralContract>,
}

impl fmt::Debug for SstiStructuralContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SstiStructuralContract")
            .field("query_parameter", &"<redacted>")
            .field("family", &"web.review.ssti.family.brace-arithmetic@1")
            .field("urls", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for XssStructuralContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XssStructuralContract")
            .field("query_parameter", &"<redacted>")
            .field("family", &self.probe.parts().selection.family().stable_id())
            .field("variant", &self.variant_id)
            .field("action", &self.action_kind.action_id())
            .field("source_evidence_count", &self.source_evidence_ids.len())
            .field("urls", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for SqlStructuralContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqlStructuralContract")
            .field("query_parameter", &"<redacted>")
            .field("urls", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for RedirectReflectionContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectReflectionContract")
            .field("query_parameter", &"<redacted>")
            .field("candidate_url", &"<redacted>")
            .field("candidate_value", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ReflectionContextContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReflectionContextContract")
            .field("query_parameter", &"<redacted>")
            .field("urls", &"<redacted>")
            .field("candidate_value", &"<redacted>")
            .finish()
    }
}

/// Stateless composite complete-response observer for the enabled native actions.
///
/// A fresh instance is bound to the exact executor/strategy catalog, one root
/// subject, the shared non-secret seed plan, and (optionally) one discovered
/// redirect parameter. It retains no response.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AssessmentReviewObserverSet {
    root: Url,
    subject: EntityId,
    seeds: NativeWebReviewSeeds,
    redirect: Option<RedirectReflectionContract>,
    reflection: Option<ReflectionContextContract>,
    sql: Option<SqlStructuralContract>,
    ssti: Option<SstiStructuralContract>,
    xss: Option<XssStructuralContract>,
}

impl fmt::Debug for AssessmentReviewObserverSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentReviewObserverSet")
            .field("root", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("seeds", &self.seeds)
            .field("redirect", &self.redirect.as_ref().map(|_| "<configured>"))
            .field(
                "reflection",
                &self.reflection.as_ref().map(|_| "<configured>"),
            )
            .field("sql", &self.sql.as_ref().map(|_| "<configured>"))
            .field("ssti", &self.ssti.as_ref().map(|_| "<configured>"))
            .field("xss", &self.xss.as_ref().map(|_| "<configured>"))
            .finish()
    }
}

impl AssessmentReviewObserverSet {
    /// Binds CORS and an optional redirect/reflection pair to one exact root.
    #[cfg(test)]
    pub(crate) fn new(
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<&str>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        Self::new_with_sql(
            root,
            seeds,
            redirect_query_parameter,
            redirect_query_parameter,
            None,
            None,
        )
    }

    pub(crate) fn new_with_sql(
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<&str>,
        reflection_query_parameter: Option<&str>,
        sql_query_parameter: Option<&str>,
        ssti_query_parameter: Option<&str>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let subject = review_root_subject(&root)?;
        let expected_seeds = NativeWebReviewSeeds::from_authorized_origin(&root)
            .map_err(|_| AssessmentReviewObserverError::Root)?;
        if seeds != expected_seeds {
            return Err(AssessmentReviewObserverError::Candidate);
        }
        validate_external_candidate(seeds.external_url())?;
        let redirect = redirect_query_parameter
            .map(|query_parameter| {
                if !valid_query_parameter(query_parameter) {
                    return Err(AssessmentReviewObserverError::QueryParameter);
                }
                let mut candidate_url = root.clone();
                candidate_url
                    .query_pairs_mut()
                    .append_pair(query_parameter, seeds.external_url());
                Ok(RedirectReflectionContract {
                    query_parameter: query_parameter.to_owned(),
                    candidate_url,
                    candidate_value: seeds.external_url().to_owned(),
                })
            })
            .transpose()?;
        let reflection = reflection_query_parameter
            .map(|query_parameter| {
                if !valid_query_parameter(query_parameter) {
                    return Err(AssessmentReviewObserverError::QueryParameter);
                }
                let mut control_url = root.clone();
                control_url
                    .query_pairs_mut()
                    .append_pair(query_parameter, &seeds.reflection_control_marker());
                let mut candidate_url = root.clone();
                candidate_url
                    .query_pairs_mut()
                    .append_pair(query_parameter, &seeds.reflection_candidate_marker());
                Ok(ReflectionContextContract {
                    query_parameter: query_parameter.to_owned(),
                    control_url,
                    candidate_url,
                    candidate_value: seeds.reflection_candidate_marker(),
                })
            })
            .transpose()?;
        let sql = sql_query_parameter
            .map(|query_parameter| {
                if !valid_query_parameter(query_parameter) {
                    return Err(AssessmentReviewObserverError::QueryParameter);
                }
                let mut control_url = root.clone();
                control_url
                    .query_pairs_mut()
                    .append_pair(query_parameter, seeds.sql_token());
                let mut candidate_value = seeds.sql_token().to_owned();
                candidate_value.push('\'');
                let mut candidate_url = root.clone();
                candidate_url
                    .query_pairs_mut()
                    .append_pair(query_parameter, &candidate_value);
                Ok(SqlStructuralContract {
                    query_parameter: query_parameter.to_owned(),
                    control_url,
                    candidate_url,
                })
            })
            .transpose()?;
        let ssti = ssti_query_parameter
            .map(|query_parameter| {
                if !valid_query_parameter(query_parameter) {
                    return Err(AssessmentReviewObserverError::QueryParameter);
                }
                let build_probe = |probe: &SstiArithmeticProbe| {
                    let mut control_url = root.clone();
                    control_url
                        .query_pairs_mut()
                        .append_pair(query_parameter, &probe.control_value());
                    let mut candidate_url = root.clone();
                    candidate_url
                        .query_pairs_mut()
                        .append_pair(query_parameter, &probe.candidate_value());
                    SstiProbeContract {
                        probe: probe.clone(),
                        control_url,
                        candidate_url,
                    }
                };
                let primary = build_probe(seeds.ssti_primary_probe());
                let replay = build_probe(seeds.ssti_replay_probe());
                if primary.probe.expected_value() == replay.probe.expected_value() {
                    return Err(AssessmentReviewObserverError::Candidate);
                }
                Ok(SstiStructuralContract {
                    query_parameter: query_parameter.to_owned(),
                    primary,
                    replay,
                })
            })
            .transpose()?;
        Ok(Self {
            root,
            subject,
            seeds,
            redirect,
            reflection,
            sql,
            ssti,
            xss: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_xss(
        root: Url,
        seeds: NativeWebReviewSeeds,
        query_parameter: &str,
        selection: XssProbeSelection,
    ) -> Result<Self, AssessmentReviewObserverError> {
        Self::new_xss_internal(root, seeds, query_parameter, selection, Vec::new(), false)
    }

    pub(crate) fn new_xss_with_source_evidence(
        root: Url,
        seeds: NativeWebReviewSeeds,
        query_parameter: &str,
        selection: XssProbeSelection,
        source_evidence_ids: Vec<EvidenceId>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        Self::new_xss_internal(
            root,
            seeds,
            query_parameter,
            selection,
            source_evidence_ids,
            true,
        )
    }

    fn new_xss_internal(
        root: Url,
        seeds: NativeWebReviewSeeds,
        query_parameter: &str,
        selection: XssProbeSelection,
        source_evidence_ids: Vec<EvidenceId>,
        require_source_evidence: bool,
    ) -> Result<Self, AssessmentReviewObserverError> {
        if !valid_query_parameter(query_parameter) {
            return Err(AssessmentReviewObserverError::QueryParameter);
        }
        let source_evidence_ids =
            canonical_xss_source_evidence_ids(source_evidence_ids, require_source_evidence)?;
        let mut observer = Self::new_with_sql(root, seeds, None, None, None, None)?;
        let probe = XssStructuralProbe::derive(selection, observer.seeds.reflection_identity())?;
        let mut control_url = observer.root.clone();
        control_url
            .query_pairs_mut()
            .append_pair(query_parameter, &probe.parts().control_value);
        let mut candidate_url = observer.root.clone();
        candidate_url
            .query_pairs_mut()
            .append_pair(query_parameter, &probe.parts().candidate_value);
        observer.xss = Some(XssStructuralContract {
            query_parameter: query_parameter.to_owned(),
            action_kind: probe.parts().selection.action_kind(),
            variant_id: probe.parts().selection.variant_id().to_owned(),
            #[cfg(feature = "normalization-resilience")]
            normalization_transform: None,
            probe,
            control_url,
            candidate_url,
            source_evidence_ids,
            #[cfg(feature = "normalization-resilience")]
            normalization_parent: None,
        });
        Ok(observer)
    }

    /// Binds one metadata-selected transformed candidate/replay pair to the
    /// exact parent subject and parameter without resending the parent pair.
    #[cfg(feature = "normalization-resilience")]
    pub(in crate::web_runtime) fn new_normalization(
        root: Url,
        seeds: NativeWebReviewSeeds,
        selection: NormalizationTransformSelection,
        parent: &NormalizationParentEvidence,
    ) -> Result<Self, AssessmentReviewObserverError> {
        if parent.root() != &root
            || !valid_query_parameter(parent.query_parameter())
            || selection.parent_selection() != parent.selection()
        {
            return Err(AssessmentReviewObserverError::Candidate);
        }
        let mut observer = Self::new_with_sql(root, seeds, None, None, None, None)?;
        if &observer.subject != parent.subject() {
            return Err(AssessmentReviewObserverError::Candidate);
        }
        let transformed_identity = observer.seeds.normalization_candidate_identity();
        let replay_identity = observer.seeds.normalization_replay_identity();
        let probe = XssStructuralProbe::derive_normalization(
            &selection,
            &transformed_identity,
            &replay_identity,
        )?;
        let mut control_url = observer.root.clone();
        control_url
            .query_pairs_mut()
            .append_pair(parent.query_parameter(), &probe.parts().control_value);
        let mut candidate_url = observer.root.clone();
        candidate_url
            .query_pairs_mut()
            .append_pair(parent.query_parameter(), &probe.parts().candidate_value);
        let transform = selection.transform_ref();
        observer.xss = Some(XssStructuralContract {
            query_parameter: parent.query_parameter().to_owned(),
            probe,
            action_kind: NativeWebReviewActionKind::NormalizationResilienceQueryPair,
            variant_id: format!("{}@{}", transform.id(), transform.revision()),
            normalization_transform: Some(transform),
            control_url,
            candidate_url,
            source_evidence_ids: parent.source_evidence_ids().to_vec(),
            normalization_parent: Some(parent.clone()),
        });
        Ok(observer)
    }

    fn expected_url(
        &self,
        kind: NativeWebReviewActionKind,
        stage: DecisionExecutionStage,
    ) -> Option<&Url> {
        match (kind, stage) {
            (NativeWebReviewActionKind::CorsPolicyPair, _)
            | (
                NativeWebReviewActionKind::RedirectReflectionQueryPair,
                DecisionExecutionStage::Passive,
            ) => Some(&self.root),
            (
                NativeWebReviewActionKind::RedirectReflectionQueryPair,
                DecisionExecutionStage::Active,
            ) => self
                .redirect
                .as_ref()
                .map(|contract| &contract.candidate_url),
            (NativeWebReviewActionKind::ReflectionContextQueryPair, stage) => {
                self.reflection.as_ref().map(|contract| match stage {
                    DecisionExecutionStage::Passive => &contract.control_url,
                    DecisionExecutionStage::Active => &contract.candidate_url,
                })
            },
            (
                NativeWebReviewActionKind::SqlStructuralQueryPair
                | NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
                DecisionExecutionStage::Passive,
            ) => self.sql.as_ref().map(|contract| &contract.control_url),
            (
                NativeWebReviewActionKind::SqlStructuralQueryPair
                | NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
                DecisionExecutionStage::Active,
            ) => self.sql.as_ref().map(|contract| &contract.candidate_url),
            (NativeWebReviewActionKind::SstiStructuralQueryPair, stage) => {
                self.ssti.as_ref().map(|contract| match stage {
                    DecisionExecutionStage::Passive => &contract.primary.control_url,
                    DecisionExecutionStage::Active => &contract.primary.candidate_url,
                })
            },
            (NativeWebReviewActionKind::SstiStructuralQueryReplayPair, stage) => {
                self.ssti.as_ref().map(|contract| match stage {
                    DecisionExecutionStage::Passive => &contract.replay.control_url,
                    DecisionExecutionStage::Active => &contract.replay.candidate_url,
                })
            },
            (
                NativeWebReviewActionKind::XssStructuralQueryPair
                | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
                | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
                stage,
            ) => self.xss.as_ref().map(|contract| match stage {
                DecisionExecutionStage::Passive => &contract.control_url,
                DecisionExecutionStage::Active => &contract.candidate_url,
            }),
            #[cfg(feature = "normalization-resilience")]
            (NativeWebReviewActionKind::NormalizationResilienceQueryPair, stage) => {
                self.xss.as_ref().map(|contract| match stage {
                    DecisionExecutionStage::Passive => &contract.control_url,
                    DecisionExecutionStage::Active => &contract.candidate_url,
                })
            },
            #[cfg(feature = "authorization-review")]
            (NativeWebReviewActionKind::ResourceAuthorizationDifferential, _) => None,
            #[cfg(feature = "openapi-review")]
            (NativeWebReviewActionKind::OpenApiDocumentReplay, _) => None,
        }
    }

    fn validate_recognized(
        &self,
        kind: NativeWebReviewActionKind,
        observation: &CompleteHttpResponseObservation<'_>,
    ) -> Result<(), HttpEvidenceError> {
        let expected_strategy = native_review_strategy_ref(kind);
        if observation.action_id() != kind.action_id()
            || observation.executor_id() != kind.executor_id()
            || observation.subject() != &self.subject
            || observation.method() != HttpProbeMethod::Get
            || observation.expected_url_mismatch(self.expected_url(kind, observation.stage()))
            || observation.case_id().is_empty()
            || observation.hypothesis_id().is_empty()
            || !observation.has_payload_strategy()
            || observation.payload_strategy() != Some(&expected_strategy)
            || observation.applies_hypothesis_transition()
        {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "native-review-action-contract",
            });
        }
        Ok(())
    }

    fn project(
        &self,
        kind: NativeWebReviewActionKind,
        observation: &CompleteHttpResponseObservation<'_>,
    ) -> Vec<(ReviewProperty, String)> {
        let marker = match observation.stage() {
            DecisionExecutionStage::Passive => "passive-control",
            DecisionExecutionStage::Active => "active-candidate",
        };
        let projection = observation.review_response_projection();
        let mut records = vec![(ReviewProperty::ResponseMarker, marker.to_owned())];
        match kind {
            NativeWebReviewActionKind::CorsPolicyPair => records.extend(
                [
                    (
                        ReviewProperty::CorsHttpStatusClass,
                        http_status_class_slug(classify_http_status(observation.status())),
                    ),
                    (
                        ReviewProperty::CorsAllowOrigin,
                        cors_allow_origin_slug(projection.access_control_allow_origin()),
                    ),
                    (
                        ReviewProperty::CorsAllowCredentials,
                        cors_allow_credentials_slug(projection.access_control_allow_credentials()),
                    ),
                    (
                        ReviewProperty::CorsVaryOrigin,
                        vary_origin_slug(projection.vary_origin()),
                    ),
                ]
                .map(|(property, value)| (property, value.to_owned())),
            ),
            NativeWebReviewActionKind::RedirectReflectionQueryPair => records.extend(
                [
                    (
                        ReviewProperty::RedirectStatus,
                        if is_redirect_status(observation.status()) {
                            "redirect"
                        } else {
                            "other"
                        },
                    ),
                    (
                        ReviewProperty::RedirectLocation,
                        location_slug(projection.location()),
                    ),
                ]
                .map(|(property, value)| (property, value.to_owned())),
            ),
            NativeWebReviewActionKind::ReflectionContextQueryPair => {
                let candidate = self
                    .reflection
                    .as_ref()
                    .expect("enabled reflection observer retains its bounded contract")
                    .candidate_value
                    .as_str();
                let classification = classify_observation_reflection(observation, candidate);
                records.extend([
                    (
                        ReviewProperty::HtmlReflection,
                        classification.context.stable_id().to_owned(),
                    ),
                    (
                        ReviewProperty::HtmlAttributeSourceStatus,
                        classification.attribute_source.status_id().to_owned(),
                    ),
                    (
                        ReviewProperty::HtmlAttributeSourceQuoteMode,
                        classification.attribute_source.quote_mode_id().to_owned(),
                    ),
                    (
                        ReviewProperty::HtmlAttributeSourceElement,
                        classification.attribute_source.element_name_id().to_owned(),
                    ),
                    (
                        ReviewProperty::HtmlAttributeSourceName,
                        classification
                            .attribute_source
                            .attribute_name_id()
                            .to_owned(),
                    ),
                    (
                        ReviewProperty::HtmlAttributeSourceContext,
                        classification.attribute_source.context_id().to_owned(),
                    ),
                    (
                        ReviewProperty::JavaScriptSourceStatus,
                        classification.javascript_source.status_id().to_owned(),
                    ),
                    (
                        ReviewProperty::JavaScriptSourceScriptKind,
                        classification.javascript_source.script_kind_id().to_owned(),
                    ),
                    (
                        ReviewProperty::JavaScriptSourceContext,
                        classification.javascript_source.context_id().to_owned(),
                    ),
                    (
                        ReviewProperty::JavaScriptSourceScriptOrdinal,
                        classification.javascript_source.script_ordinal_id(),
                    ),
                ]);
            },
            NativeWebReviewActionKind::SqlStructuralQueryPair
            | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => {
                records.push((
                    ReviewProperty::SqlHttpStatusClass,
                    http_status_class_slug(classify_http_status(observation.status())).to_owned(),
                ));
                records.push((
                    ReviewProperty::SqlBodyStructure,
                    sql_body_structure(observation),
                ));
            },
            NativeWebReviewActionKind::SstiStructuralQueryPair
            | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => {
                let contract = self
                    .ssti
                    .as_ref()
                    .expect("enabled SSTI observer retains its bounded contract");
                let probe = if kind == NativeWebReviewActionKind::SstiStructuralQueryPair {
                    &contract.primary.probe
                } else {
                    &contract.replay.probe
                };
                records.push((
                    ReviewProperty::SstiHttpStatusClass,
                    http_status_class_slug(classify_http_status(observation.status())).to_owned(),
                ));
                records.push((
                    ReviewProperty::SstiEvaluation,
                    ssti_evaluation_slug(classify_ssti_evaluation(observation, probe)).to_owned(),
                ));
            },
            NativeWebReviewActionKind::XssStructuralQueryPair
            | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
            | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => {
                self.append_xss_projection(observation, &mut records);
            },
            #[cfg(feature = "normalization-resilience")]
            NativeWebReviewActionKind::NormalizationResilienceQueryPair => {
                self.append_xss_projection(observation, &mut records);
            },
            #[cfg(feature = "authorization-review")]
            NativeWebReviewActionKind::ResourceAuthorizationDifferential => return Vec::new(),
            #[cfg(feature = "openapi-review")]
            NativeWebReviewActionKind::OpenApiDocumentReplay => return Vec::new(),
        }
        records
    }

    fn append_xss_projection(
        &self,
        observation: &CompleteHttpResponseObservation<'_>,
        records: &mut Vec<(ReviewProperty, String)>,
    ) {
        let contract = self
            .xss
            .as_ref()
            .expect("enabled XSS observer retains its bounded contract");
        records.push((
            ReviewProperty::XssProbeFamily,
            contract
                .probe
                .parts()
                .selection
                .family()
                .stable_id()
                .to_owned(),
        ));
        records.push((ReviewProperty::XssProbeVariant, contract.variant_id.clone()));
        let javascript_anchor = contract.probe.parts().selection.javascript_anchor();
        records.extend([
            (
                ReviewProperty::JavaScriptSourceStatus,
                javascript_anchor
                    .map_or("absent", |_| "exact-script-anchor")
                    .to_owned(),
            ),
            (
                ReviewProperty::JavaScriptSourceScriptKind,
                javascript_anchor
                    .map_or("none", |anchor| anchor.script_kind().stable_id())
                    .to_owned(),
            ),
            (
                ReviewProperty::JavaScriptSourceContext,
                javascript_anchor
                    .map_or("none", |anchor| anchor.context().stable_id())
                    .to_owned(),
            ),
            (
                ReviewProperty::JavaScriptSourceScriptOrdinal,
                javascript_anchor.map_or_else(
                    || "none".to_owned(),
                    |anchor| anchor.script_ordinal().to_string(),
                ),
            ),
        ]);
        records.push((
            ReviewProperty::XssStructuralRelation,
            xss_structural_relation_slug(classify_xss_structural_relation(observation, contract))
                .to_owned(),
        ));
    }
}

// This tiny extension avoids exposing requested-URL comparison outside the
// observer while keeping the validation expression readable.
trait ObservationUrlContract {
    fn expected_url_mismatch(&self, expected: Option<&Url>) -> bool;
}

impl ObservationUrlContract for CompleteHttpResponseObservation<'_> {
    fn expected_url_mismatch(&self, expected: Option<&Url>) -> bool {
        expected.is_none_or(|expected| self.requested_url() != expected)
    }
}

impl CompleteHttpResponseObserver for AssessmentReviewObserverSet {
    fn observe(
        &self,
        observation: CompleteHttpResponseObservation<'_>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let Some(kind) = NativeWebReviewActionKind::all()
            .into_iter()
            .find(|kind| observation.action_id() == kind.action_id())
        else {
            return Ok(Vec::new());
        };
        self.validate_recognized(kind, &observation)?;

        let mut parents = review_projection_parents(&observation, kind)?;
        if is_xss_response_action(kind) {
            parents.extend(
                self.xss
                    .as_ref()
                    .expect("enabled XSS observer retains its bounded contract")
                    .source_evidence_ids
                    .iter()
                    .cloned(),
            );
        }
        let derivation = EvidenceDerivation::new(
            parents,
            DerivationAlgorithm::new(
                ASSESSMENT_REVIEW_ALGORITHM,
                ASSESSMENT_REVIEW_ALGORITHM_VERSION,
            )?,
        )?;
        let source = EvidenceSource::new(
            kind.executor_id(),
            review_source_method(kind, observation.stage()),
        )?
        .with_correlation_id(observation.case_id())?;
        self.project(kind, &observation)
            .into_iter()
            .map(|(property, value)| {
                Ok(Evidence::new(
                    observation.subject().clone(),
                    EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned()),
                    property.predicate(),
                    EvidenceValue::Text(value.to_owned()),
                    source.clone(),
                    observation.reliability(),
                )
                .derived_from(derivation.clone()))
            })
            .collect()
    }
}

fn review_root_subject(root: &Url) -> Result<EntityId, AssessmentReviewObserverError> {
    if !matches!(root.scheme(), "http" | "https")
        || root.query().is_some()
        || root.fragment().is_some()
        || !root.username().is_empty()
        || root.password().is_some()
        || root.host_str().is_none()
    {
        return Err(AssessmentReviewObserverError::Root);
    }
    EntityId::new(format!("endpoint:{root}")).map_err(|_| AssessmentReviewObserverError::Root)
}

fn valid_query_parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REVIEW_QUERY_PARAMETER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn validate_external_candidate(value: &str) -> Result<(), AssessmentReviewObserverError> {
    if value.is_empty() || value.len() > MAX_REVIEW_CANDIDATE_BYTES {
        return Err(AssessmentReviewObserverError::Candidate);
    }
    let limits = PayloadStrategyLimits::default();
    let seed = PayloadSeed::new(value.as_bytes().to_vec(), limits)
        .map_err(|_| AssessmentReviewObserverError::Candidate)?;
    ExternalUrlQueryPairStrategy::new()
        .derive_one(PayloadVariantRole::Candidate, &seed, limits)
        .map(|_| ())
        .map_err(|_| AssessmentReviewObserverError::Candidate)
}

fn native_review_strategy_ref(kind: NativeWebReviewActionKind) -> PayloadStrategyRef {
    let (id, revision) = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => {
            (CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            (EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
        },
        NativeWebReviewActionKind::ReflectionContextQueryPair => (
            REFLECTION_MARKER_QUERY_PAIR_ID,
            REFLECTION_MARKER_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => (
            SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
            SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => (
            SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
            SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssStructuralQueryPair => (
            XSS_STRUCTURAL_QUERY_PAIR_ID,
            XSS_STRUCTURAL_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => (
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => (
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => (
            NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
            NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => {
            unreachable!("authorization review owns no generic payload strategy")
        },
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => {
            unreachable!("OpenAPI review owns no generic payload strategy")
        },
    };
    PayloadStrategyRef::new(id, revision)
        .expect("native review strategies have valid static references")
}

fn review_projection_parents(
    observation: &CompleteHttpResponseObservation<'_>,
    kind: NativeWebReviewActionKind,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    let mut parents = [
        (
            observation.request_method_evidence_id(),
            "native-review-request-method-evidence",
        ),
        (
            observation.request_url_evidence_id(),
            "native-review-request-url-evidence",
        ),
        (
            observation.response_status_evidence_id(),
            "native-review-response-status-evidence",
        ),
        (
            observation.response_final_url_evidence_id(),
            "native-review-response-final-url-evidence",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect::<Result<Vec<_>, _>>()?;
    if is_xss_response_action(kind)
        || matches!(
            kind,
            NativeWebReviewActionKind::ReflectionContextQueryPair
                | NativeWebReviewActionKind::SqlStructuralQueryPair
                | NativeWebReviewActionKind::SqlStructuralQueryReplayPair
                | NativeWebReviewActionKind::SstiStructuralQueryPair
                | NativeWebReviewActionKind::SstiStructuralQueryReplayPair
        )
    {
        if observation.media_type().is_some() {
            parents.push(
                observation
                    .response_media_type_evidence_id()
                    .cloned()
                    .ok_or(HttpEvidenceError::AssessmentObserverInvariant {
                        invariant: "native-review-response-media-type-evidence",
                    })?,
            );
        }
        parents.extend([
            observation
                .response_body_truncated_evidence_id()
                .cloned()
                .ok_or(HttpEvidenceError::AssessmentObserverInvariant {
                    invariant: "native-review-response-body-truncation-evidence",
                })?,
            observation
                .response_body_digest_evidence_id()
                .cloned()
                .ok_or(HttpEvidenceError::AssessmentObserverInvariant {
                    invariant: "native-review-response-body-digest-evidence",
                })?,
        ]);
    }
    Ok(parents)
}

struct ReflectionObservationClassification {
    context: ExactHtmlReflectionContext,
    attribute_source: AttributeSourceResult,
    javascript_source: JavaScriptSourceResult,
}

fn classify_observation_reflection(
    observation: &CompleteHttpResponseObservation<'_>,
    candidate: &str,
) -> ReflectionObservationClassification {
    match observation.media_type() {
        Some("text/html") => {},
        Some(_) => {
            return ReflectionObservationClassification {
                context: ExactHtmlReflectionContext::NotApplicable,
                attribute_source: AttributeSourceResult::Unsupported,
                javascript_source: JavaScriptSourceResult::Unsupported(
                    super::web_assessment::JavaScriptScriptKind::Unsupported,
                ),
            };
        },
        None => {
            return ReflectionObservationClassification {
                context: ExactHtmlReflectionContext::Incomplete,
                attribute_source: AttributeSourceResult::Incomplete,
                javascript_source: JavaScriptSourceResult::Incomplete,
            };
        },
    }
    let Some(body) = observation.complete_body() else {
        return ReflectionObservationClassification {
            context: ExactHtmlReflectionContext::Incomplete,
            attribute_source: AttributeSourceResult::Incomplete,
            javascript_source: JavaScriptSourceResult::Incomplete,
        };
    };
    let Ok(html) = std::str::from_utf8(body) else {
        return ReflectionObservationClassification {
            context: ExactHtmlReflectionContext::Incomplete,
            attribute_source: AttributeSourceResult::Incomplete,
            javascript_source: JavaScriptSourceResult::Incomplete,
        };
    };
    let context = classify_exact_html_reflection(html, candidate);
    ReflectionObservationClassification {
        context,
        attribute_source: cross_validate_attribute_reflection_source(html, candidate, context),
        javascript_source: cross_validate_javascript_reflection_source(html, candidate, context),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XssStructuralRelation {
    EncodedOrInert,
    ReflectedSameContext,
    StructuralBoundaryObserved,
    Unsupported,
    Incomplete,
}

fn classify_xss_structural_relation(
    observation: &CompleteHttpResponseObservation<'_>,
    contract: &XssStructuralContract,
) -> XssStructuralRelation {
    match observation.media_type() {
        Some("text/html") => {},
        Some(_) => return XssStructuralRelation::Unsupported,
        None => return XssStructuralRelation::Incomplete,
    }
    let Some(body) = observation.complete_body() else {
        return XssStructuralRelation::Incomplete;
    };
    let Ok(html) = std::str::from_utf8(body) else {
        return XssStructuralRelation::Incomplete;
    };
    #[cfg(feature = "normalization-resilience")]
    let normalization =
        contract.action_kind == NativeWebReviewActionKind::NormalizationResilienceQueryPair;
    #[cfg(not(feature = "normalization-resilience"))]
    let normalization = false;
    let (identity, expected_value) = if normalization {
        match observation.stage() {
            DecisionExecutionStage::Passive => (
                contract.probe.parts().control_identity.as_str(),
                contract.probe.parts().control_value.as_str(),
            ),
            DecisionExecutionStage::Active => (
                contract.probe.parts().candidate_identity.as_str(),
                contract.probe.parts().candidate_value.as_str(),
            ),
        }
    } else {
        // Preserve the established XSS V1 control semantics: both legs are
        // classified against the candidate boundary identity/value, so a
        // benign reflected control remains `EncodedOrInert`.
        (
            contract.probe.parts().candidate_identity.as_str(),
            contract.probe.parts().candidate_value.as_str(),
        )
    };
    let boundary = match contract.probe.parts().selection.family() {
        XssProbeFamily::HtmlTextBoundary => {
            match match_exact_xss_html_boundary_document(html, identity) {
                ExactXssBoundaryMatch::Absent => ExactXssAttributeBoundaryMatch::Absent,
                ExactXssBoundaryMatch::Matched => ExactXssAttributeBoundaryMatch::Matched,
                ExactXssBoundaryMatch::Ambiguous => ExactXssAttributeBoundaryMatch::Ambiguous,
                ExactXssBoundaryMatch::Incomplete => ExactXssAttributeBoundaryMatch::Incomplete,
            }
        },
        XssProbeFamily::AttributeValueBoundary
        | XssProbeFamily::UriAttributeBoundary
        | XssProbeFamily::EventHandlerAttributeBoundary => {
            let Some(anchor) = contract.probe.parts().selection.attribute_anchor() else {
                return XssStructuralRelation::Incomplete;
            };
            match_exact_xss_attribute_boundary_document(html, identity, anchor)
        },
        XssProbeFamily::ScriptSingleQuotedStringBoundary
        | XssProbeFamily::ScriptDoubleQuotedStringBoundary
        | XssProbeFamily::ScriptTemplateLiteralBoundary => {
            let Some(anchor) = contract.probe.parts().selection.javascript_anchor() else {
                return XssStructuralRelation::Incomplete;
            };
            let Some(tokens) = XssJavascriptLexicalProbeTokens::from_identity(identity) else {
                return XssStructuralRelation::Incomplete;
            };
            return match (
                observation.stage(),
                match_exact_xss_javascript_boundary_document(
                    html,
                    tokens.boundary_comment(),
                    tokens.tail_comment(),
                    anchor,
                ),
            ) {
                (_, ExactJavaScriptBoundaryMatch::Matched) if normalization => {
                    XssStructuralRelation::StructuralBoundaryObserved
                },
                (DecisionExecutionStage::Active, ExactJavaScriptBoundaryMatch::Matched) => {
                    XssStructuralRelation::StructuralBoundaryObserved
                },
                (DecisionExecutionStage::Passive, ExactJavaScriptBoundaryMatch::Matched) => {
                    XssStructuralRelation::ReflectedSameContext
                },
                (_, ExactJavaScriptBoundaryMatch::Absent) if html.contains(expected_value) => {
                    XssStructuralRelation::ReflectedSameContext
                },
                (_, ExactJavaScriptBoundaryMatch::Absent) => XssStructuralRelation::EncodedOrInert,
                (
                    _,
                    ExactJavaScriptBoundaryMatch::Ambiguous
                    | ExactJavaScriptBoundaryMatch::Incomplete,
                ) => XssStructuralRelation::Incomplete,
            };
        },
        XssProbeFamily::UriAttributeStructure
        | XssProbeFamily::EventHandlerStructure
        | XssProbeFamily::ScriptContentStructure
        | XssProbeFamily::ScriptExpressionStructure
        | XssProbeFamily::ScriptTemplateExpressionStructure
        | XssProbeFamily::ScriptLineCommentStructure
        | XssProbeFamily::ScriptBlockCommentStructure
        | XssProbeFamily::ScriptRegexStructure => return XssStructuralRelation::Unsupported,
    };
    match (observation.stage(), boundary) {
        (_, ExactXssAttributeBoundaryMatch::Matched) if normalization => {
            XssStructuralRelation::StructuralBoundaryObserved
        },
        (DecisionExecutionStage::Active, ExactXssAttributeBoundaryMatch::Matched) => {
            XssStructuralRelation::StructuralBoundaryObserved
        },
        (DecisionExecutionStage::Passive, ExactXssAttributeBoundaryMatch::Matched) => {
            XssStructuralRelation::ReflectedSameContext
        },
        (_, ExactXssAttributeBoundaryMatch::Absent) if html.contains(expected_value) => {
            XssStructuralRelation::ReflectedSameContext
        },
        (_, ExactXssAttributeBoundaryMatch::Absent) => XssStructuralRelation::EncodedOrInert,
        (
            _,
            ExactXssAttributeBoundaryMatch::Ambiguous | ExactXssAttributeBoundaryMatch::Incomplete,
        ) => XssStructuralRelation::Incomplete,
    }
}

const fn xss_structural_relation_slug(relation: XssStructuralRelation) -> &'static str {
    match relation {
        XssStructuralRelation::EncodedOrInert => "encoded-or-inert",
        XssStructuralRelation::ReflectedSameContext => "reflected-same-context",
        XssStructuralRelation::StructuralBoundaryObserved => "structural-boundary-observed",
        XssStructuralRelation::Unsupported => "unsupported",
        XssStructuralRelation::Incomplete => "incomplete",
    }
}

fn classify_ssti_evaluation(
    observation: &CompleteHttpResponseObservation<'_>,
    probe: &SstiArithmeticProbe,
) -> SstiEvaluationRelation {
    match observation.media_type() {
        Some("text/html" | "application/json") => {},
        Some(value) if value.starts_with("text/") => {},
        Some(_) => return SstiEvaluationRelation::Unsupported,
        None => return SstiEvaluationRelation::Incomplete,
    }
    let Some(body) = observation.complete_body() else {
        return SstiEvaluationRelation::Incomplete;
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return SstiEvaluationRelation::Incomplete;
    };
    if observation.stage() == DecisionExecutionStage::Active
        && body.contains(&probe.candidate_value())
    {
        return SstiEvaluationRelation::LiteralReflection;
    }
    if body.contains(&probe.expected_value()) {
        if observation.stage() == DecisionExecutionStage::Passive {
            SstiEvaluationRelation::ExpectedPresentInControl
        } else {
            SstiEvaluationRelation::ExpectedEvaluation
        }
    } else {
        SstiEvaluationRelation::Absent
    }
}

const fn ssti_evaluation_slug(relation: SstiEvaluationRelation) -> &'static str {
    match relation {
        SstiEvaluationRelation::Absent => "absent",
        SstiEvaluationRelation::ExpectedPresentInControl => "expected-present-in-control",
        SstiEvaluationRelation::LiteralReflection => "literal-reflection",
        SstiEvaluationRelation::ExpectedEvaluation => "expected-evaluation",
        SstiEvaluationRelation::Unsupported => "unsupported",
        SstiEvaluationRelation::Incomplete => "incomplete",
    }
}

fn sql_body_structure(observation: &CompleteHttpResponseObservation<'_>) -> String {
    let Some(media_type) = observation.media_type() else {
        return "incomplete".to_owned();
    };
    let Some(body) = observation.complete_body() else {
        return "incomplete".to_owned();
    };
    let mut shape = Vec::new();
    match media_type {
        "text/html" => {
            let Ok(html) = std::str::from_utf8(body) else {
                return "incomplete".to_owned();
            };
            let dom = parse_document(RcDom::default(), ParseOpts::default()).one(html);
            if !append_html_shape(&dom.document, &mut shape) {
                return "incomplete".to_owned();
            }
        },
        "application/json" => {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                return "incomplete".to_owned();
            };
            if !append_json_shape(&value, &mut shape) {
                return "incomplete".to_owned();
            }
        },
        value if value.starts_with("text/") => shape.extend_from_slice(b"text"),
        _ => shape.extend_from_slice(b"binary"),
    }
    let digest = Sha256::digest(&shape);
    format!("sha256:{digest:x}")
}

fn append_html_shape(handle: &Handle, output: &mut Vec<u8>) -> bool {
    if let NodeData::Element { name, .. } = &handle.data {
        if output.len() >= MAX_SQL_STRUCTURE_NODES.saturating_mul(32) {
            return false;
        }
        output.extend_from_slice(name.local.as_bytes());
        output.push(0);
    }
    for child in handle.children.borrow().iter() {
        if !append_html_shape(child, output) {
            return false;
        }
    }
    true
}

fn append_json_shape(value: &serde_json::Value, output: &mut Vec<u8>) -> bool {
    if output.len() >= MAX_SQL_STRUCTURE_NODES {
        return false;
    }
    output.push(match value {
        serde_json::Value::Null => b'n',
        serde_json::Value::Bool(_) => b'b',
        serde_json::Value::Number(_) => b'd',
        serde_json::Value::String(_) => b's',
        serde_json::Value::Array(_) => b'a',
        serde_json::Value::Object(_) => b'o',
    });
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                if !append_json_shape(value, output) {
                    return false;
                }
            }
        },
        serde_json::Value::Object(values) => {
            for value in values.values() {
                if !append_json_shape(value, output) {
                    return false;
                }
            }
        },
        _ => {},
    }
    true
}

fn review_source_method(
    kind: NativeWebReviewActionKind,
    stage: DecisionExecutionStage,
) -> &'static str {
    match (kind, stage) {
        (NativeWebReviewActionKind::CorsPolicyPair, DecisionExecutionStage::Passive) => {
            "cors-control-response"
        },
        (NativeWebReviewActionKind::CorsPolicyPair, DecisionExecutionStage::Active) => {
            "cors-candidate-response"
        },
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Passive,
        ) => "redirect-reflection-control-response",
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Active,
        ) => "redirect-reflection-candidate-response",
        (
            NativeWebReviewActionKind::ReflectionContextQueryPair,
            DecisionExecutionStage::Passive,
        ) => "reflection-context-control-response",
        (NativeWebReviewActionKind::ReflectionContextQueryPair, DecisionExecutionStage::Active) => {
            "reflection-context-candidate-response"
        },
        (NativeWebReviewActionKind::SqlStructuralQueryPair, DecisionExecutionStage::Passive) => {
            "sql-structural-control-response"
        },
        (NativeWebReviewActionKind::SqlStructuralQueryPair, DecisionExecutionStage::Active) => {
            "sql-structural-candidate-response"
        },
        (
            NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
            DecisionExecutionStage::Passive,
        ) => "sql-structural-replay-control-response",
        (
            NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
            DecisionExecutionStage::Active,
        ) => "sql-structural-replay-candidate-response",
        (NativeWebReviewActionKind::SstiStructuralQueryPair, DecisionExecutionStage::Passive) => {
            "ssti-structural-control-response"
        },
        (NativeWebReviewActionKind::SstiStructuralQueryPair, DecisionExecutionStage::Active) => {
            "ssti-structural-candidate-response"
        },
        (
            NativeWebReviewActionKind::SstiStructuralQueryReplayPair,
            DecisionExecutionStage::Passive,
        ) => "ssti-structural-replay-control-response",
        (
            NativeWebReviewActionKind::SstiStructuralQueryReplayPair,
            DecisionExecutionStage::Active,
        ) => "ssti-structural-replay-candidate-response",
        (NativeWebReviewActionKind::XssStructuralQueryPair, DecisionExecutionStage::Passive) => {
            "xss-structural-control-response"
        },
        (NativeWebReviewActionKind::XssStructuralQueryPair, DecisionExecutionStage::Active) => {
            "xss-structural-candidate-response"
        },
        (
            NativeWebReviewActionKind::XssAttributeBoundaryQueryPair,
            DecisionExecutionStage::Passive,
        ) => "xss-attribute-boundary-control-response",
        (
            NativeWebReviewActionKind::XssAttributeBoundaryQueryPair,
            DecisionExecutionStage::Active,
        ) => "xss-attribute-boundary-candidate-response",
        (
            NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
            DecisionExecutionStage::Passive,
        ) => "xss-script-lexical-boundary-control-response",
        (
            NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
            DecisionExecutionStage::Active,
        ) => "xss-script-lexical-boundary-candidate-response",
        #[cfg(feature = "normalization-resilience")]
        (
            NativeWebReviewActionKind::NormalizationResilienceQueryPair,
            DecisionExecutionStage::Passive,
        ) => "normalization-transformed-candidate-response",
        #[cfg(feature = "normalization-resilience")]
        (
            NativeWebReviewActionKind::NormalizationResilienceQueryPair,
            DecisionExecutionStage::Active,
        ) => "normalization-transformed-replay-response",
        #[cfg(feature = "authorization-review")]
        (NativeWebReviewActionKind::ResourceAuthorizationDifferential, _) => {
            "authorization-review-invalid-generic-source"
        },
        #[cfg(feature = "openapi-review")]
        (NativeWebReviewActionKind::OpenApiDocumentReplay, _) => {
            "openapi-review-invalid-generic-source"
        },
    }
}

fn cors_allow_origin_slug(relation: CorsAllowOriginRelation) -> &'static str {
    match relation {
        CorsAllowOriginRelation::Missing => "missing",
        CorsAllowOriginRelation::ExactRequestOrigin => "exact-request-origin",
        CorsAllowOriginRelation::Wildcard => "wildcard",
        CorsAllowOriginRelation::Other => "other",
        CorsAllowOriginRelation::InvalidOrMultiple => "invalid-or-multiple",
    }
}

fn cors_allow_credentials_slug(relation: CorsAllowCredentialsRelation) -> &'static str {
    match relation {
        CorsAllowCredentialsRelation::Missing => "missing",
        CorsAllowCredentialsRelation::True => "true",
        CorsAllowCredentialsRelation::Other => "other",
        CorsAllowCredentialsRelation::InvalidOrMultiple => "invalid-or-multiple",
    }
}

fn vary_origin_slug(relation: VaryOriginRelation) -> &'static str {
    match relation {
        VaryOriginRelation::Missing => "missing",
        VaryOriginRelation::ContainsOrigin => "contains-origin",
        VaryOriginRelation::Wildcard => "wildcard",
        VaryOriginRelation::Other => "other",
        VaryOriginRelation::Invalid => "invalid",
    }
}

const fn classify_http_status(status: u16) -> ReviewHttpStatusClass {
    match status {
        100..=199 => ReviewHttpStatusClass::Informational,
        200..=299 => ReviewHttpStatusClass::Successful,
        300..=399 => ReviewHttpStatusClass::Redirection,
        400..=499 => ReviewHttpStatusClass::ClientError,
        500..=599 => ReviewHttpStatusClass::ServerError,
        _ => ReviewHttpStatusClass::Other,
    }
}

const fn http_status_class_slug(status: ReviewHttpStatusClass) -> &'static str {
    match status {
        ReviewHttpStatusClass::Informational => "informational",
        ReviewHttpStatusClass::Successful => "successful",
        ReviewHttpStatusClass::Redirection => "redirection",
        ReviewHttpStatusClass::ClientError => "client-error",
        ReviewHttpStatusClass::ServerError => "server-error",
        ReviewHttpStatusClass::Other => "other",
    }
}

const fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn location_slug(relation: LocationRelation) -> &'static str {
    match relation {
        LocationRelation::Missing => "missing",
        LocationRelation::ExactExternalQueryValue => "exact-external-query-value",
        LocationRelation::Other => "other",
        LocationRelation::InvalidOrMultiple => "invalid-or-multiple",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReviewProperty {
    ResponseMarker,
    CorsHttpStatusClass,
    CorsAllowOrigin,
    CorsAllowCredentials,
    CorsVaryOrigin,
    RedirectStatus,
    RedirectLocation,
    HtmlReflection,
    HtmlAttributeSourceStatus,
    HtmlAttributeSourceQuoteMode,
    HtmlAttributeSourceElement,
    HtmlAttributeSourceName,
    HtmlAttributeSourceContext,
    JavaScriptSourceStatus,
    JavaScriptSourceScriptKind,
    JavaScriptSourceContext,
    JavaScriptSourceScriptOrdinal,
    SqlHttpStatusClass,
    SqlBodyStructure,
    SstiHttpStatusClass,
    SstiEvaluation,
    XssProbeFamily,
    XssProbeVariant,
    XssStructuralRelation,
}

impl ReviewProperty {
    const fn name(self) -> &'static str {
        match self {
            Self::ResponseMarker => NATIVE_WEB_REVIEW_RESPONSE_MARKER,
            Self::CorsHttpStatusClass => CORS_HTTP_STATUS_CLASS,
            Self::CorsAllowOrigin => CORS_ALLOW_ORIGIN_RELATION,
            Self::CorsAllowCredentials => CORS_ALLOW_CREDENTIALS_RELATION,
            Self::CorsVaryOrigin => CORS_VARY_ORIGIN_RELATION,
            Self::RedirectStatus => REDIRECT_STATUS_RELATION,
            Self::RedirectLocation => REDIRECT_LOCATION_RELATION,
            Self::HtmlReflection => HTML_REFLECTION_CONTEXT,
            Self::HtmlAttributeSourceStatus => HTML_ATTRIBUTE_SOURCE_STATUS,
            Self::HtmlAttributeSourceQuoteMode => HTML_ATTRIBUTE_SOURCE_QUOTE_MODE,
            Self::HtmlAttributeSourceElement => HTML_ATTRIBUTE_SOURCE_ELEMENT,
            Self::HtmlAttributeSourceName => HTML_ATTRIBUTE_SOURCE_NAME,
            Self::HtmlAttributeSourceContext => HTML_ATTRIBUTE_SOURCE_CONTEXT,
            Self::JavaScriptSourceStatus => JAVASCRIPT_SOURCE_STATUS,
            Self::JavaScriptSourceScriptKind => JAVASCRIPT_SOURCE_SCRIPT_KIND,
            Self::JavaScriptSourceContext => JAVASCRIPT_SOURCE_CONTEXT,
            Self::JavaScriptSourceScriptOrdinal => JAVASCRIPT_SOURCE_SCRIPT_ORDINAL,
            Self::SqlHttpStatusClass => SQL_HTTP_STATUS_CLASS,
            Self::SqlBodyStructure => SQL_BODY_STRUCTURE,
            Self::SstiHttpStatusClass => SSTI_HTTP_STATUS_CLASS,
            Self::SstiEvaluation => SSTI_EVALUATION_RELATION,
            Self::XssProbeFamily => XSS_PROBE_FAMILY,
            Self::XssProbeVariant => XSS_PROBE_VARIANT,
            Self::XssStructuralRelation => XSS_STRUCTURAL_RELATION,
        }
    }

    fn predicate(self) -> KnowledgePredicate {
        KnowledgePredicate::new(NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE, self.name())
            .expect("native review properties have valid static identities")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewStatusRelation {
    Redirect,
    Other,
}

/// Fixed-vocabulary HTTP response class retained for CORS pair comparison.
///
/// Exact status values are deliberately not copied into native-review
/// evidence. Only two successful legs can establish the one product-facing
/// relationship; a generic error response never strengthens a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewHttpStatusClass {
    Informational,
    Successful,
    Redirection,
    ClientError,
    ServerError,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SstiEvaluationRelation {
    Absent,
    ExpectedPresentInControl,
    LiteralReflection,
    ExpectedEvaluation,
    Unsupported,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommittedReviewResponse {
    Cors {
        status: ReviewHttpStatusClass,
        allow_origin: CorsAllowOriginRelation,
        allow_credentials: CorsAllowCredentialsRelation,
        vary_origin: VaryOriginRelation,
    },
    Redirect {
        status: ReviewStatusRelation,
        location: LocationRelation,
    },
    Reflection {
        reflection: ExactHtmlReflectionContext,
        attribute_source: AttributeSourceResult,
        javascript_source: JavaScriptSourceResult,
    },
    SqlStructural {
        status: ReviewHttpStatusClass,
        body_structure: String,
    },
    SstiStructural {
        status: ReviewHttpStatusClass,
        evaluation: SstiEvaluationRelation,
    },
    XssStructural {
        family: XssProbeFamily,
        variant: String,
        relation: XssStructuralRelation,
    },
}

/// One response reconstructed from exact committed value-free evidence.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CommittedAssessmentReviewObservation {
    kind: NativeWebReviewActionKind,
    subject: EntityId,
    case_id: String,
    hypothesis_id: String,
    stage: DecisionExecutionStage,
    response: CommittedReviewResponse,
    evidence_ids: Vec<EvidenceId>,
    property_evidence: BTreeMap<ReviewProperty, EvidenceId>,
    active_pair_success: bool,
}

impl fmt::Debug for CommittedAssessmentReviewObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAssessmentReviewObservation")
            .field("kind", &self.kind)
            .field("subject", &"<redacted>")
            .field("case_id", &"<redacted>")
            .field("hypothesis_id", &"<redacted>")
            .field("stage", &self.stage)
            .field("response", &self.response)
            .field("evidence_count", &self.evidence_ids.len())
            .field("active_pair_success", &self.active_pair_success)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReviewReceiptKey {
    kind: NativeWebReviewActionKind,
    case_id: String,
    stage: DecisionExecutionStage,
}

/// Fail-closed committed receipt replay reason. The variants intentionally
/// carry no response, URL, credential, or candidate text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum AssessmentReviewLedgerError {
    #[error("native review receipt authority was invalid")]
    ReceiptAuthority,
    #[error("native review receipt evidence was not committed exactly")]
    EvidenceCommit,
    #[error("native review evidence projection was malformed")]
    EvidenceProjection,
    #[error("native review verifier proof was invalid")]
    VerifierProof,
    #[error("native review ledger capacity was exhausted")]
    Capacity,
    #[error("native review receipt replay conflicted with an earlier record")]
    ReplayConflict,
}

/// Bounded assessment-owned ledger for the two native review pairs.
#[derive(PartialEq, Eq)]
pub(crate) struct CommittedAssessmentReviewLedger {
    root: Url,
    subject: EntityId,
    seeds: NativeWebReviewSeeds,
    redirect: Option<RedirectReflectionContract>,
    reflection: Option<ReflectionContextContract>,
    sql: Option<SqlStructuralContract>,
    ssti: Option<SstiStructuralContract>,
    xss: Option<XssStructuralContract>,
    observations: BTreeMap<ReviewReceiptKey, CommittedAssessmentReviewObservation>,
    #[cfg(feature = "normalization-resilience")]
    normalization_candidate: Option<NormalizationReviewCandidate>,
}

impl fmt::Debug for CommittedAssessmentReviewLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CommittedAssessmentReviewLedger");
        debug
            .field("root", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("seeds", &self.seeds)
            .field("redirect", &self.redirect.as_ref().map(|_| "<configured>"))
            .field(
                "reflection",
                &self.reflection.as_ref().map(|_| "<configured>"),
            )
            .field("sql", &self.sql.as_ref().map(|_| "<configured>"))
            .field("ssti", &self.ssti.as_ref().map(|_| "<configured>"))
            .field("xss", &self.xss.as_ref().map(|_| "<configured>"))
            .field("observation_count", &self.observations.len());
        #[cfg(feature = "normalization-resilience")]
        debug.field(
            "normalization_candidate",
            &self.normalization_candidate.as_ref().map(|_| "<committed>"),
        );
        debug.finish()
    }
}

/// Typed terminal audit result for one explicitly enabled normalization child.
///
/// Only [`Self::SemanticNormalizationGapObserved`] can create a product item;
/// every other state remains internal, conservative audit truth.
#[cfg(feature = "normalization-resilience")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum NormalizationReviewOutcome {
    SemanticNormalizationGapObserved,
    VariantStillBlocked,
    VariantAcceptedSemanticsUnknown,
    ReplayMismatch,
    Incomplete,
}

impl CommittedAssessmentReviewLedger {
    #[cfg(test)]
    pub(crate) fn new(
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<&str>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        Self::new_with_sql(
            root,
            seeds,
            redirect_query_parameter,
            redirect_query_parameter,
            None,
            None,
        )
    }

    pub(crate) fn new_with_sql(
        root: Url,
        seeds: NativeWebReviewSeeds,
        redirect_query_parameter: Option<&str>,
        reflection_query_parameter: Option<&str>,
        sql_query_parameter: Option<&str>,
        ssti_query_parameter: Option<&str>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let observer = AssessmentReviewObserverSet::new_with_sql(
            root,
            seeds,
            redirect_query_parameter,
            reflection_query_parameter,
            sql_query_parameter,
            ssti_query_parameter,
        )?;
        Ok(Self {
            root: observer.root,
            subject: observer.subject,
            seeds: observer.seeds,
            redirect: observer.redirect,
            reflection: observer.reflection,
            sql: observer.sql,
            ssti: observer.ssti,
            xss: observer.xss,
            observations: BTreeMap::new(),
            #[cfg(feature = "normalization-resilience")]
            normalization_candidate: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_xss(
        root: Url,
        seeds: NativeWebReviewSeeds,
        query_parameter: &str,
        selection: XssProbeSelection,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let observer =
            AssessmentReviewObserverSet::new_xss(root, seeds, query_parameter, selection)?;
        Ok(Self::from_xss_observer(observer))
    }

    pub(crate) fn new_xss_with_source_evidence(
        root: Url,
        seeds: NativeWebReviewSeeds,
        query_parameter: &str,
        selection: XssProbeSelection,
        source_evidence_ids: Vec<EvidenceId>,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let observer = AssessmentReviewObserverSet::new_xss_with_source_evidence(
            root,
            seeds,
            query_parameter,
            selection,
            source_evidence_ids,
        )?;
        Ok(Self::from_xss_observer(observer))
    }

    fn from_xss_observer(observer: AssessmentReviewObserverSet) -> Self {
        Self {
            root: observer.root,
            subject: observer.subject,
            seeds: observer.seeds,
            redirect: observer.redirect,
            reflection: observer.reflection,
            sql: observer.sql,
            ssti: observer.ssti,
            xss: observer.xss,
            observations: BTreeMap::new(),
            #[cfg(feature = "normalization-resilience")]
            normalization_candidate: None,
        }
    }

    #[cfg(feature = "normalization-resilience")]
    pub(in crate::web_runtime) fn new_normalization(
        root: Url,
        seeds: NativeWebReviewSeeds,
        selection: NormalizationTransformSelection,
        parent: &NormalizationParentEvidence,
    ) -> Result<Self, AssessmentReviewObserverError> {
        let observer =
            AssessmentReviewObserverSet::new_normalization(root, seeds, selection, parent)?;
        Ok(Self::from_xss_observer(observer))
    }

    pub(crate) fn observations(
        &self,
    ) -> impl ExactSizeIterator<Item = &CommittedAssessmentReviewObservation> {
        self.observations.values()
    }

    pub(crate) fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Derives a normalization parent only from one complete XSS pair and its
    /// exact candidate-specific defense transition.
    ///
    /// A fingerprint, a bare status code, a standing block, rate limiting, or
    /// incomplete response coverage cannot produce this value.
    #[cfg(feature = "normalization-resilience")]
    pub(in crate::web_runtime) fn normalization_parent_evidence(
        &self,
        defense: &CommittedAssessmentDefenseLedger,
    ) -> Result<Option<NormalizationParentEvidence>, AssessmentReviewLedgerError> {
        let Some(contract) = self.xss.as_ref() else {
            return Ok(None);
        };
        if contract.source_evidence_ids.len() != REFLECTION_REVIEW_PROPERTIES.len() {
            return Ok(None);
        }
        if !matches!(
            contract.probe.parts().selection.family(),
            XssProbeFamily::HtmlTextBoundary
                | XssProbeFamily::AttributeValueBoundary
                | XssProbeFamily::UriAttributeBoundary
                | XssProbeFamily::EventHandlerAttributeBoundary
        ) {
            return Ok(None);
        }
        let parent_kind = contract.probe.parts().selection.action_kind();
        let Some((control, candidate)) = exact_pair(&self.observations, parent_kind) else {
            return Ok(None);
        };

        let mut matching = defense.transitions().iter().filter(|transition| {
            let case = transition.case();
            case.id() == control.case_id
                && case.subject() == &control.subject
                && case.action_id() == parent_kind.action_id()
                && case.hypothesis_id() == control.hypothesis_id
                && case.payload_strategy() == Some(&native_review_strategy_ref(parent_kind))
        });
        let Some(transition) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some()
            || !transition.candidate_block_status_appeared()
            || !transition.suppression_newly_blocking()
            || transition.newly_rate_limited()
        {
            return Ok(None);
        }
        let Some((defense_control, defense_candidate)) =
            defense.exact_observation_pair(transition.case())
        else {
            return Ok(None);
        };
        if defense_control.body_coverage() != AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            || defense_candidate.body_coverage()
                != AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            || defense_control.input_limit_reached()
            || defense_candidate.input_limit_reached()
            || defense_control.state().is_rate_limited()
            || defense_candidate.state().is_rate_limited()
        {
            return Ok(None);
        }

        let mut control_ids = control
            .evidence_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        control_ids.extend(transition.control_evidence_ids().iter().cloned());
        let mut candidate_ids = candidate
            .evidence_ids
            .iter()
            .cloned()
            .chain(contract.source_evidence_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        candidate_ids.extend(transition.candidate_evidence_ids().iter().cloned());
        if control_ids.is_empty()
            || candidate_ids.is_empty()
            || control_ids.iter().any(|id| candidate_ids.contains(id))
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        Ok(Some(NormalizationParentEvidence {
            root: self.root.clone(),
            subject: self.subject.clone(),
            query_parameter: contract.query_parameter.clone(),
            selection: contract.probe.parts().selection.clone(),
            parent_case: transition.case().clone(),
            control_evidence_ids: control_ids.into_iter().collect(),
            canonical_candidate_evidence_ids: candidate_ids.into_iter().collect(),
            source_evidence_ids: contract.source_evidence_ids.clone(),
        }))
    }

    /// Returns whether an enabled HTML-reflection leg could not be classified
    /// within its complete-body, UTF-8, DOM, or occurrence boundary.
    pub(crate) fn has_incomplete_reflection_observation(&self) -> bool {
        self.observations.values().any(|observation| {
            matches!(
                observation.response,
                CommittedReviewResponse::Reflection {
                    reflection: ExactHtmlReflectionContext::Incomplete,
                    ..
                }
            )
        })
    }

    /// Returns whether this ledger contains exactly one case-correlated,
    /// evidence-disjoint control/candidate pair for the requested capability.
    pub(crate) fn pair_is_complete(&self, kind: NativeWebReviewActionKind) -> bool {
        let mut controls = self.observations.values().filter(|observation| {
            observation.kind == kind && observation.stage == DecisionExecutionStage::Passive
        });
        let Some(control) = controls.next() else {
            return false;
        };
        if controls.next().is_some() {
            return false;
        }

        let mut candidates = self.observations.values().filter(|observation| {
            observation.kind == kind && observation.stage == DecisionExecutionStage::Active
        });
        let Some(candidate) = candidates.next() else {
            return false;
        };
        candidates.next().is_none() && observations_form_exact_pair(control, candidate)
    }

    /// Finalizes one normalization child against its separately committed
    /// defense observations.
    ///
    /// The passive child leg is the transformed candidate and the active leg
    /// is its distinct replay. Both must reproduce the exact inert structural
    /// semantic and both must be complete, non-blocked, and non-rate-limited.
    /// The canonical parent evidence is retained independently from the child
    /// evidence so a 403-to-200 status change alone can never create an item.
    #[cfg(feature = "normalization-resilience")]
    pub(in crate::web_runtime) fn finalize_normalization(
        &mut self,
        defense: &CommittedAssessmentDefenseLedger,
    ) -> Result<NormalizationReviewOutcome, AssessmentReviewLedgerError> {
        let Some(contract) = self.xss.as_ref() else {
            return Ok(NormalizationReviewOutcome::Incomplete);
        };
        if contract.action_kind != NativeWebReviewActionKind::NormalizationResilienceQueryPair {
            return Ok(NormalizationReviewOutcome::Incomplete);
        }
        let Some(transform) = contract.normalization_transform else {
            return Err(AssessmentReviewLedgerError::ReceiptAuthority);
        };
        let Some(parent) = contract.normalization_parent.as_ref() else {
            return Err(AssessmentReviewLedgerError::ReceiptAuthority);
        };
        let Some((transformed, replay)) = exact_pair(
            &self.observations,
            NativeWebReviewActionKind::NormalizationResilienceQueryPair,
        ) else {
            return Ok(NormalizationReviewOutcome::Incomplete);
        };
        let child_defense = exact_normalization_defense_pair(defense, transformed, replay)?;
        let Some((transformed_defense, replay_defense)) = child_defense else {
            return Ok(NormalizationReviewOutcome::Incomplete);
        };
        if [transformed_defense, replay_defense]
            .into_iter()
            .any(|item| {
                item.body_coverage() != AssessmentDefenseBodyCoverage::CompleteUtf8Prefix
                    || item.input_limit_reached()
            })
        {
            return Ok(NormalizationReviewOutcome::Incomplete);
        }
        if [transformed_defense, replay_defense]
            .into_iter()
            .any(|item| {
                item.state().posture() == DefensePosture::Blocking
                    || item.state().is_challenged()
                    || item.state().is_rate_limited()
            })
        {
            return Ok(NormalizationReviewOutcome::VariantStillBlocked);
        }

        let expected_family = contract.probe.parts().selection.family();
        let expected_variant = contract.variant_id.as_str();
        let transformed_semantic =
            normalization_semantic_matches(transformed, expected_family, expected_variant)?;
        let replay_semantic =
            normalization_semantic_matches(replay, expected_family, expected_variant)?;
        let (Some(transformed_semantic), Some(replay_semantic)) =
            (transformed_semantic, replay_semantic)
        else {
            return Ok(NormalizationReviewOutcome::Incomplete);
        };
        match (transformed_semantic, replay_semantic) {
            (false, _) => {
                return Ok(NormalizationReviewOutcome::VariantAcceptedSemanticsUnknown);
            },
            (true, false) => return Ok(NormalizationReviewOutcome::ReplayMismatch),
            (true, true) => {},
        }

        let control_evidence_ids = parent
            .control_evidence_ids()
            .iter()
            .chain(parent.canonical_candidate_evidence_ids())
            .cloned()
            .collect::<BTreeSet<_>>();
        let candidate_evidence_ids = transformed
            .evidence_ids
            .iter()
            .chain(&replay.evidence_ids)
            .chain(transformed_defense.evidence_ids())
            .chain(replay_defense.evidence_ids())
            .cloned()
            .collect::<BTreeSet<_>>();
        if control_evidence_ids.is_empty()
            || candidate_evidence_ids.is_empty()
            || control_evidence_ids
                .iter()
                .any(|id| candidate_evidence_ids.contains(id))
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        let candidate = NormalizationReviewCandidate {
            subject: self.subject.clone(),
            case_id: transformed.case_id.clone(),
            family: expected_family,
            transform,
            query_parameter: contract.query_parameter.clone(),
            control_evidence_ids: control_evidence_ids.into_iter().collect(),
            candidate_evidence_ids: candidate_evidence_ids.into_iter().collect(),
        };
        if let Some(existing) = self.normalization_candidate.as_ref() {
            if existing != &candidate {
                return Err(AssessmentReviewLedgerError::ReplayConflict);
            }
        } else {
            self.normalization_candidate = Some(candidate);
        }
        Ok(NormalizationReviewOutcome::SemanticNormalizationGapObserved)
    }

    /// Replays one outcome only after both its receipt batch and verifier audit
    /// are validated against the authoritative knowledge store.
    pub(crate) fn ingest_outcome(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        decision: &DecisionOutcomeReport,
        knowledge: &KnowledgeBase,
    ) -> Result<Option<&CommittedAssessmentReviewObservation>, AssessmentReviewLedgerError> {
        let kind = review_kind(receipt.case().action_id())
            .ok_or(AssessmentReviewLedgerError::ReceiptAuthority)?;
        let contracts = ReviewContracts {
            redirect: self.redirect.as_ref(),
            reflection: self.reflection.as_ref(),
            sql: self.sql.as_ref(),
            ssti: self.ssti.as_ref(),
            xss: self.xss.as_ref(),
        };
        validate_receipt_authority(
            receipt,
            decision,
            &self.root,
            &self.subject,
            contracts,
            kind,
        )?;
        validate_committed_batch(receipt, knowledge)?;
        if is_xss_response_action(kind) {
            validate_xss_source_evidence(
                self.xss
                    .as_ref()
                    .ok_or(AssessmentReviewLedgerError::ReceiptAuthority)?,
                &self.subject,
                knowledge,
            )?;
        }
        let mut parsed = parse_review_receipt(receipt, &self.root, contracts, kind)?;
        parsed.active_pair_success =
            validate_verifier_proof(receipt, decision, knowledge, &parsed)?;
        let key = ReviewReceiptKey {
            kind,
            case_id: receipt.case().id().to_owned(),
            stage: receipt.stage(),
        };
        if let Some(existing) = self.observations.get(&key) {
            return if existing == &parsed {
                Ok(None)
            } else {
                Err(AssessmentReviewLedgerError::ReplayConflict)
            };
        }
        if self.observations.len() >= MAX_REVIEW_OBSERVATIONS {
            return Err(AssessmentReviewLedgerError::Capacity);
        }
        self.observations.insert(key.clone(), parsed);
        Ok(self.observations.get(&key))
    }

    /// Returns only matched pairs that satisfy their closed claim boundary.
    /// There is deliberately no `Confirmed` candidate variant.
    pub(crate) fn candidates(&self) -> Vec<AssessmentReviewCandidate> {
        let mut candidates = Vec::new();
        for kind in [
            NativeWebReviewActionKind::CorsPolicyPair,
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            NativeWebReviewActionKind::ReflectionContextQueryPair,
        ] {
            let passive = self
                .observations
                .values()
                .filter(|item| item.kind == kind && item.stage == DecisionExecutionStage::Passive);
            for control in passive {
                let Some(candidate) = self.observations.values().find(|item| {
                    item.kind == kind
                        && item.stage == DecisionExecutionStage::Active
                        && item.case_id == control.case_id
                        && item.hypothesis_id == control.hypothesis_id
                        && item.subject == control.subject
                }) else {
                    continue;
                };
                append_pair_candidates(
                    control,
                    candidate,
                    match kind {
                        NativeWebReviewActionKind::RedirectReflectionQueryPair => self
                            .redirect
                            .as_ref()
                            .map(|contract| contract.query_parameter.as_str()),
                        NativeWebReviewActionKind::ReflectionContextQueryPair => self
                            .reflection
                            .as_ref()
                            .map(|contract| contract.query_parameter.as_str()),
                        _ => None,
                    },
                    &mut candidates,
                );
            }
        }
        if let Some(contract) = self.sql.as_ref() {
            let first = exact_pair(
                &self.observations,
                NativeWebReviewActionKind::SqlStructuralQueryPair,
            );
            let replay = exact_pair(
                &self.observations,
                NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
            );
            if let (Some((control, candidate)), Some((replay_control, replay_candidate))) =
                (first, replay)
            {
                append_sql_candidate(
                    control,
                    candidate,
                    replay_control,
                    replay_candidate,
                    &contract.query_parameter,
                    &mut candidates,
                );
            }
        }
        if let Some(contract) = self.ssti.as_ref() {
            let first = exact_pair(
                &self.observations,
                NativeWebReviewActionKind::SstiStructuralQueryPair,
            );
            let replay = exact_pair(
                &self.observations,
                NativeWebReviewActionKind::SstiStructuralQueryReplayPair,
            );
            if let (Some((control, candidate)), Some((replay_control, replay_candidate))) =
                (first, replay)
            {
                append_ssti_candidate(
                    control,
                    candidate,
                    replay_control,
                    replay_candidate,
                    &contract.query_parameter,
                    &mut candidates,
                );
            }
        }
        if let Some(contract) = self
            .xss
            .as_ref()
            .filter(|contract| !is_normalization_action(contract.action_kind))
        {
            if let Some((control, candidate)) = exact_pair(&self.observations, contract.action_kind)
            {
                if let (
                    CommittedReviewResponse::XssStructural {
                        family: control_family,
                        variant: control_variant,
                        relation: XssStructuralRelation::EncodedOrInert,
                    },
                    CommittedReviewResponse::XssStructural {
                        family: candidate_family,
                        variant: candidate_variant,
                        relation: XssStructuralRelation::StructuralBoundaryObserved,
                    },
                ) = (&control.response, &candidate.response)
                {
                    if control_family == candidate_family
                        && control_variant == candidate_variant
                        && *candidate_family == contract.probe.parts().selection.family()
                        && candidate_variant == &contract.variant_id
                    {
                        candidates.push(AssessmentReviewCandidate::XssStructural(
                            XssStructuralReviewCandidate {
                                subject: control.subject.clone(),
                                case_id: control.case_id.clone(),
                                family: contract.probe.parts().selection.family(),
                                query_parameter: contract.query_parameter.clone(),
                                control_evidence_ids: ids_for(
                                    control,
                                    &[
                                        ReviewProperty::ResponseMarker,
                                        ReviewProperty::XssProbeFamily,
                                        ReviewProperty::XssProbeVariant,
                                        ReviewProperty::XssStructuralRelation,
                                    ],
                                ),
                                candidate_evidence_ids: ids_for(
                                    candidate,
                                    &[
                                        ReviewProperty::ResponseMarker,
                                        ReviewProperty::XssProbeFamily,
                                        ReviewProperty::XssProbeVariant,
                                        ReviewProperty::XssStructuralRelation,
                                    ],
                                )
                                .into_iter()
                                .chain(contract.source_evidence_ids.iter().cloned())
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .collect(),
                            },
                        ));
                    }
                }
            }
        }
        #[cfg(feature = "normalization-resilience")]
        if let Some(candidate) = self.normalization_candidate.clone() {
            candidates.push(AssessmentReviewCandidate::Normalization(candidate));
        }
        candidates
    }

    /// Returns candidate-specific complete reflection contexts only. This is
    /// the metadata boundary consumed before XSS payload materialization.
    pub(crate) fn xss_selection_inputs(&self) -> Vec<XssSelectionInput> {
        self.candidates()
            .into_iter()
            .filter_map(|candidate| match candidate {
                AssessmentReviewCandidate::Reflection(candidate) => Some(XssSelectionInput {
                    query_parameter: candidate.query_parameter,
                    context: match candidate.context {
                        ReviewReflectionContext::HtmlComment => {
                            ExactHtmlReflectionContext::HtmlComment
                        },
                        ReviewReflectionContext::HtmlText => ExactHtmlReflectionContext::HtmlText,
                        ReviewReflectionContext::AttributeValue => {
                            ExactHtmlReflectionContext::AttributeValue
                        },
                        ReviewReflectionContext::UriAttribute => {
                            ExactHtmlReflectionContext::UriAttribute
                        },
                        ReviewReflectionContext::StyleAttribute => {
                            ExactHtmlReflectionContext::StyleAttribute
                        },
                        ReviewReflectionContext::StyleElementContent => {
                            ExactHtmlReflectionContext::StyleElementContent
                        },
                        ReviewReflectionContext::EventHandlerAttribute => {
                            ExactHtmlReflectionContext::EventHandlerAttribute
                        },
                        ReviewReflectionContext::ScriptElementContent => {
                            ExactHtmlReflectionContext::ScriptElementContent
                        },
                        ReviewReflectionContext::EmbeddedHtmlAttribute => {
                            ExactHtmlReflectionContext::EmbeddedHtmlAttribute
                        },
                    },
                    attribute_source: candidate.attribute_source,
                    javascript_source: candidate.javascript_source,
                    source_evidence_ids: candidate.candidate_evidence_ids,
                }),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn has_incomplete_sql_observation(&self) -> bool {
        self.observations.values().any(|observation| {
            matches!(
                &observation.response,
                CommittedReviewResponse::SqlStructural { body_structure, .. }
                    if body_structure == "incomplete"
            )
        })
    }

    pub(crate) fn has_incomplete_ssti_observation(&self) -> bool {
        self.observations.values().any(|observation| {
            matches!(
                observation.response,
                CommittedReviewResponse::SstiStructural {
                    evaluation: SstiEvaluationRelation::Incomplete,
                    ..
                }
            )
        })
    }

    pub(crate) fn has_incomplete_xss_observation(&self) -> bool {
        self.observations.values().any(|observation| {
            matches!(
                observation.response,
                CommittedReviewResponse::XssStructural {
                    relation: XssStructuralRelation::Incomplete,
                    ..
                }
            )
        })
    }
}

fn exact_pair(
    observations: &BTreeMap<ReviewReceiptKey, CommittedAssessmentReviewObservation>,
    kind: NativeWebReviewActionKind,
) -> Option<(
    &CommittedAssessmentReviewObservation,
    &CommittedAssessmentReviewObservation,
)> {
    let mut controls = observations
        .values()
        .filter(|item| item.kind == kind && item.stage == DecisionExecutionStage::Passive);
    let control = controls.next()?;
    if controls.next().is_some() {
        return None;
    }
    let mut candidates = observations
        .values()
        .filter(|item| item.kind == kind && item.stage == DecisionExecutionStage::Active);
    let candidate = candidates.next()?;
    if candidates.next().is_some() || !observations_form_exact_pair(control, candidate) {
        return None;
    }
    Some((control, candidate))
}

#[cfg(feature = "normalization-resilience")]
fn exact_normalization_defense_pair<'a>(
    defense: &'a CommittedAssessmentDefenseLedger,
    transformed: &CommittedAssessmentReviewObservation,
    replay: &CommittedAssessmentReviewObservation,
) -> Result<
    Option<(
        &'a super::assessment_defense::CommittedAssessmentDefenseObservation,
        &'a super::assessment_defense::CommittedAssessmentDefenseObservation,
    )>,
    AssessmentReviewLedgerError,
> {
    if !observations_form_exact_pair(transformed, replay) {
        return Err(AssessmentReviewLedgerError::ReceiptAuthority);
    }
    let expected_strategy =
        native_review_strategy_ref(NativeWebReviewActionKind::NormalizationResilienceQueryPair);
    let matching = |stage| {
        defense
            .observations()
            .iter()
            .filter(|observation| observation.stage() == stage)
            .filter(|observation| {
                let case = observation.case();
                case.id() == transformed.case_id
                    && case.subject() == &transformed.subject
                    && case.action_id()
                        == NativeWebReviewActionKind::NormalizationResilienceQueryPair.action_id()
                    && case.hypothesis_id() == transformed.hypothesis_id
                    && case.payload_strategy() == Some(&expected_strategy)
                    && !case.applies_hypothesis_transition()
            })
            .collect::<Vec<_>>()
    };
    let passive = matching(DecisionExecutionStage::Passive);
    let active = matching(DecisionExecutionStage::Active);
    match (passive.as_slice(), active.as_slice()) {
        ([passive], [active]) => Ok(Some((*passive, *active))),
        ([], _) | (_, []) => Ok(None),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

#[cfg(feature = "normalization-resilience")]
fn normalization_semantic_matches(
    observation: &CommittedAssessmentReviewObservation,
    expected_family: XssProbeFamily,
    expected_variant: &str,
) -> Result<Option<bool>, AssessmentReviewLedgerError> {
    let CommittedReviewResponse::XssStructural {
        family,
        variant,
        relation,
    } = &observation.response
    else {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    };
    if *family != expected_family || variant != expected_variant {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }
    Ok(match relation {
        XssStructuralRelation::StructuralBoundaryObserved => Some(true),
        XssStructuralRelation::Incomplete => None,
        XssStructuralRelation::EncodedOrInert
        | XssStructuralRelation::ReflectedSameContext
        | XssStructuralRelation::Unsupported => Some(false),
    })
}

fn validate_receipt_authority(
    receipt: &DecisionEvidenceReceipt,
    decision: &DecisionOutcomeReport,
    root: &Url,
    subject: &EntityId,
    contracts: ReviewContracts<'_>,
    kind: NativeWebReviewActionKind,
) -> Result<(), AssessmentReviewLedgerError> {
    let case = receipt.case();
    let verification = decision.verification();
    let outcome = verification.outcome();
    if receipt.executor_id() != kind.executor_id()
        || case.subject() != subject
        || case.action_id() != kind.action_id()
        || case.payload_strategy() != Some(&native_review_strategy_ref(kind))
        || case.applies_hypothesis_transition()
        || case.id().is_empty()
        || case.hypothesis_id().is_empty()
        || verification.case() != case
        || outcome.case_id() != case.id()
        || outcome.subject() != case.subject()
        || outcome.action_id() != case.action_id()
        || outcome.hypothesis_id() != case.hypothesis_id()
        || decision.hypothesis_write().is_some()
        || receipt.evidence().len() != receipt.writes().len()
        || !execution_and_verification_stage_match(receipt.stage(), verification.stage())
        || verification.stage() != outcome.stage()
        || !receipt_url_matches_contract(receipt, root, contracts, kind)
    {
        return Err(AssessmentReviewLedgerError::ReceiptAuthority);
    }
    Ok(())
}

fn validate_committed_batch(
    receipt: &DecisionEvidenceReceipt,
    knowledge: &KnowledgeBase,
) -> Result<(), AssessmentReviewLedgerError> {
    for (evidence, write) in receipt.write_set() {
        if !matches!(write, KnowledgeWrite::Inserted | KnowledgeWrite::Unchanged)
            || evidence.subject() != receipt.case().subject()
            || evidence.source().component() != receipt.executor_id()
            || evidence.source().correlation_id() != Some(receipt.case().id())
            || knowledge.evidence(evidence.id()).as_ref() != Some(evidence)
        {
            return Err(AssessmentReviewLedgerError::EvidenceCommit);
        }
    }
    Ok(())
}

fn validate_xss_source_evidence(
    contract: &XssStructuralContract,
    subject: &EntityId,
    knowledge: &KnowledgeBase,
) -> Result<(), AssessmentReviewLedgerError> {
    // Unit-level observer/ledger tests can bind a child contract without an
    // originating reflection run. Production composition always uses the
    // source-evidence constructor, which requires the complete closed set.
    if contract.source_evidence_ids.is_empty() {
        return Ok(());
    }
    if contract.source_evidence_ids.len() != REFLECTION_REVIEW_PROPERTIES.len() {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }

    let reflection_kind = NativeWebReviewActionKind::ReflectionContextQueryPair;
    let expected_method = review_source_method(reflection_kind, DecisionExecutionStage::Active);
    let mut correlation_id: Option<String> = None;
    let mut values = BTreeMap::new();
    for id in &contract.source_evidence_ids {
        let evidence = knowledge
            .evidence(id)
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
        let property = REFLECTION_REVIEW_PROPERTIES
            .iter()
            .copied()
            .find(|property| evidence.predicate() == &property.predicate())
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
        let EvidenceValue::Text(value) = evidence.value() else {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        };
        let source_correlation = evidence
            .source()
            .correlation_id()
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
        if evidence.kind() != &EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned())
            || evidence.subject() != subject
            || evidence.source().component() != reflection_kind.executor_id()
            || evidence.source().method() != expected_method
            || correlation_id
                .as_deref()
                .is_some_and(|expected| expected != source_correlation)
            || values.insert(property, value.clone()).is_some()
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        correlation_id.get_or_insert_with(|| source_correlation.to_owned());
    }
    if values.len() != REFLECTION_REVIEW_PROPERTIES.len()
        || values
            .get(&ReviewProperty::ResponseMarker)
            .map(String::as_str)
            != Some(stage_marker(DecisionExecutionStage::Active))
        || values
            .get(&ReviewProperty::HtmlReflection)
            .map(String::as_str)
            != Some(
                contract
                    .probe
                    .parts()
                    .selection
                    .family()
                    .compatible_context()
                    .stable_id(),
            )
    {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }

    let attribute_source = AttributeSourceResult::from_evidence_fields(
        value_text(&values, ReviewProperty::HtmlAttributeSourceStatus)?,
        value_text(&values, ReviewProperty::HtmlAttributeSourceQuoteMode)?,
        value_text(&values, ReviewProperty::HtmlAttributeSourceElement)?,
        value_text(&values, ReviewProperty::HtmlAttributeSourceName)?,
        value_text(&values, ReviewProperty::HtmlAttributeSourceContext)?,
    )
    .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
    let javascript_source = JavaScriptSourceResult::from_evidence_fields(
        value_text(&values, ReviewProperty::JavaScriptSourceStatus)?,
        value_text(&values, ReviewProperty::JavaScriptSourceScriptKind)?,
        value_text(&values, ReviewProperty::JavaScriptSourceContext)?,
        value_text(&values, ReviewProperty::JavaScriptSourceScriptOrdinal)?,
    )
    .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
    if attribute_source.exact_anchor() != contract.probe.parts().selection.attribute_anchor()
        || javascript_source.exact_anchor() != contract.probe.parts().selection.javascript_anchor()
    {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }
    Ok(())
}

fn value_text(
    values: &BTreeMap<ReviewProperty, String>,
    property: ReviewProperty,
) -> Result<&str, AssessmentReviewLedgerError> {
    values
        .get(&property)
        .map(String::as_str)
        .ok_or(AssessmentReviewLedgerError::EvidenceProjection)
}

fn parse_review_receipt(
    receipt: &DecisionEvidenceReceipt,
    root: &Url,
    contracts: ReviewContracts<'_>,
    kind: NativeWebReviewActionKind,
) -> Result<CommittedAssessmentReviewObservation, AssessmentReviewLedgerError> {
    let expected = expected_properties(kind);
    let review = receipt
        .evidence()
        .iter()
        .filter(|item| item.predicate().namespace() == NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE)
        .collect::<Vec<_>>();
    if receipt.evidence().iter().any(|item| {
        item.predicate().namespace().starts_with("web.review")
            && item.predicate().namespace() != NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE
    }) || review.len() != expected.len()
    {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }

    let parents = expected_review_parent_ids(receipt, root, contracts, kind)?;
    let source_method = review_source_method(kind, receipt.stage());
    let mut property_evidence = BTreeMap::new();
    let mut values = BTreeMap::new();
    let mut evidence_ids = Vec::with_capacity(review.len());
    for (index, (item, property)) in review.iter().zip(expected.iter().copied()).enumerate() {
        if item.predicate().name() != property.name()
            || item.kind() != &EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned())
            || item.source().component() != kind.executor_id()
            || item.source().method() != source_method
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.subject() != receipt.case().subject()
            || property_evidence
                .insert(property, item.id().clone())
                .is_some()
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        let EvidenceOrigin::Derived(derivation) = item.origin() else {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        };
        if derivation.algorithm().name() != ASSESSMENT_REVIEW_ALGORITHM
            || derivation.algorithm().version() != ASSESSMENT_REVIEW_ALGORITHM_VERSION
            || derivation.parents() != parents
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        let EvidenceValue::Text(value) = item.value() else {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        };
        if index == 0 && value != stage_marker(receipt.stage()) {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        values.insert(property, value.as_str());
        evidence_ids.push(item.id().clone());
    }

    let response = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => CommittedReviewResponse::Cors {
            status: parse_http_status_class(value(&values, ReviewProperty::CorsHttpStatusClass)?)?,
            allow_origin: parse_cors_allow_origin(value(
                &values,
                ReviewProperty::CorsAllowOrigin,
            )?)?,
            allow_credentials: parse_cors_allow_credentials(value(
                &values,
                ReviewProperty::CorsAllowCredentials,
            )?)?,
            vary_origin: parse_vary_origin(value(&values, ReviewProperty::CorsVaryOrigin)?)?,
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            CommittedReviewResponse::Redirect {
                status: parse_status_relation(value(&values, ReviewProperty::RedirectStatus)?)?,
                location: parse_location(value(&values, ReviewProperty::RedirectLocation)?)?,
            }
        },
        NativeWebReviewActionKind::ReflectionContextQueryPair => {
            let reflection = parse_reflection(value(&values, ReviewProperty::HtmlReflection)?)?;
            let attribute_source = AttributeSourceResult::from_evidence_fields(
                value(&values, ReviewProperty::HtmlAttributeSourceStatus)?,
                value(&values, ReviewProperty::HtmlAttributeSourceQuoteMode)?,
                value(&values, ReviewProperty::HtmlAttributeSourceElement)?,
                value(&values, ReviewProperty::HtmlAttributeSourceName)?,
                value(&values, ReviewProperty::HtmlAttributeSourceContext)?,
            )
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
            if attribute_source
                .exact_anchor()
                .is_some_and(|anchor| anchor.context() != reflection)
            {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            let javascript_source = JavaScriptSourceResult::from_evidence_fields(
                value(&values, ReviewProperty::JavaScriptSourceStatus)?,
                value(&values, ReviewProperty::JavaScriptSourceScriptKind)?,
                value(&values, ReviewProperty::JavaScriptSourceContext)?,
                value(&values, ReviewProperty::JavaScriptSourceScriptOrdinal)?,
            )
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
            if javascript_source.exact_anchor().is_some()
                && reflection != ExactHtmlReflectionContext::ScriptElementContent
            {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            if reflection == ExactHtmlReflectionContext::ScriptElementContent
                && matches!(javascript_source, JavaScriptSourceResult::Absent)
            {
                // The observer upgrades this impossible disagreement to
                // `Incomplete`; accepting `Absent` here would let a forged
                // receipt bypass the fixed source/DOM cross-check vocabulary.
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            CommittedReviewResponse::Reflection {
                reflection,
                attribute_source,
                javascript_source,
            }
        },
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => {
            let body_structure = value(&values, ReviewProperty::SqlBodyStructure)?;
            if body_structure != "incomplete"
                && !(body_structure.len() == 71
                    && body_structure.starts_with("sha256:")
                    && body_structure[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
            {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            CommittedReviewResponse::SqlStructural {
                status: parse_http_status_class(value(
                    &values,
                    ReviewProperty::SqlHttpStatusClass,
                )?)?,
                body_structure: body_structure.to_owned(),
            }
        },
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => {
            CommittedReviewResponse::SstiStructural {
                status: parse_http_status_class(value(
                    &values,
                    ReviewProperty::SstiHttpStatusClass,
                )?)?,
                evaluation: parse_ssti_evaluation(value(&values, ReviewProperty::SstiEvaluation)?)?,
            }
        },
        NativeWebReviewActionKind::XssStructuralQueryPair
        | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
        | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => {
            let contract = contracts
                .xss
                .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
            let family = value(&values, ReviewProperty::XssProbeFamily)?;
            let variant = value(&values, ReviewProperty::XssProbeVariant)?;
            if kind != contract.action_kind
                || family != contract.probe.parts().selection.family().stable_id()
                || variant != contract.variant_id
            {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            let javascript_source = JavaScriptSourceResult::from_evidence_fields(
                value(&values, ReviewProperty::JavaScriptSourceStatus)?,
                value(&values, ReviewProperty::JavaScriptSourceScriptKind)?,
                value(&values, ReviewProperty::JavaScriptSourceContext)?,
                value(&values, ReviewProperty::JavaScriptSourceScriptOrdinal)?,
            )
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
            if javascript_source.exact_anchor()
                != contract.probe.parts().selection.javascript_anchor()
                || (contract
                    .probe
                    .parts()
                    .selection
                    .javascript_anchor()
                    .is_none()
                    && !matches!(javascript_source, JavaScriptSourceResult::Absent))
            {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            CommittedReviewResponse::XssStructural {
                family: contract.probe.parts().selection.family(),
                variant: contract.variant_id.clone(),
                relation: parse_xss_structural_relation(value(
                    &values,
                    ReviewProperty::XssStructuralRelation,
                )?)?,
            }
        },
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => {
            let contract = contracts
                .xss
                .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
            let family = value(&values, ReviewProperty::XssProbeFamily)?;
            let variant = value(&values, ReviewProperty::XssProbeVariant)?;
            if kind != contract.action_kind
                || family != contract.probe.parts().selection.family().stable_id()
                || variant != contract.variant_id
                || contract.normalization_transform.is_none()
                || contract.normalization_parent.is_none()
                || contract
                    .probe
                    .parts()
                    .selection
                    .javascript_anchor()
                    .is_some()
            {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            let javascript_source = JavaScriptSourceResult::from_evidence_fields(
                value(&values, ReviewProperty::JavaScriptSourceStatus)?,
                value(&values, ReviewProperty::JavaScriptSourceScriptKind)?,
                value(&values, ReviewProperty::JavaScriptSourceContext)?,
                value(&values, ReviewProperty::JavaScriptSourceScriptOrdinal)?,
            )
            .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?;
            if !matches!(javascript_source, JavaScriptSourceResult::Absent) {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            CommittedReviewResponse::XssStructural {
                family: contract.probe.parts().selection.family(),
                variant: contract.variant_id.clone(),
                relation: parse_xss_structural_relation(value(
                    &values,
                    ReviewProperty::XssStructuralRelation,
                )?)?,
            }
        },
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        },
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        },
    };
    Ok(CommittedAssessmentReviewObservation {
        kind,
        subject: receipt.case().subject().clone(),
        case_id: receipt.case().id().to_owned(),
        hypothesis_id: receipt.case().hypothesis_id().to_owned(),
        stage: receipt.stage(),
        response,
        evidence_ids,
        property_evidence,
        active_pair_success: false,
    })
}

fn validate_verifier_proof(
    receipt: &DecisionEvidenceReceipt,
    decision: &DecisionOutcomeReport,
    knowledge: &KnowledgeBase,
    parsed: &CommittedAssessmentReviewObservation,
) -> Result<bool, AssessmentReviewLedgerError> {
    let verification = decision.verification();
    let outcome = verification.outcome();
    match receipt.stage() {
        DecisionExecutionStage::Passive => {
            if outcome.status() != OutcomeStatus::Unknown
                || outcome.verifier_rule_id().is_some()
                || !outcome.evidence_ids().is_empty()
                || verification
                    .evaluations()
                    .iter()
                    .any(|evaluation| evaluation.selected())
            {
                return Err(AssessmentReviewLedgerError::VerifierProof);
            }
            Ok(false)
        },
        DecisionExecutionStage::Active => {
            let selected = verification
                .evaluations()
                .iter()
                .filter(|evaluation| evaluation.selected())
                .collect::<Vec<_>>();
            let marker = parsed
                .property_evidence
                .get(&ReviewProperty::ResponseMarker)
                .ok_or(AssessmentReviewLedgerError::VerifierProof)?;
            if outcome.status() != OutcomeStatus::Success
                || outcome.verifier_rule_id()
                    != Some(native_review_active_verifier_rule_id(parsed.kind))
                || selected.len() != 1
                || selected[0].rule_id() != native_review_active_verifier_rule_id(parsed.kind)
                || selected[0].stage() != VerificationStage::Active
                || !selected[0].action_matched()
                || !selected[0].eligible()
                || selected[0].condition().evidence_ids() != outcome.evidence_ids()
                || selected[0].fresh_evidence_ids().is_empty()
                || !selected[0].fresh_evidence_ids().contains(marker)
                || !selected[0]
                    .fresh_evidence_ids()
                    .is_subset(outcome.evidence_ids())
            {
                return Err(AssessmentReviewLedgerError::VerifierProof);
            }
            for id in outcome.evidence_ids() {
                let committed = knowledge
                    .evidence(id)
                    .ok_or(AssessmentReviewLedgerError::VerifierProof)?;
                if committed.subject() != receipt.case().subject()
                    || committed.source().correlation_id() != Some(receipt.case().id())
                {
                    return Err(AssessmentReviewLedgerError::VerifierProof);
                }
            }
            for id in selected[0].fresh_evidence_ids() {
                let receipt_item = receipt.evidence().iter().find(|item| item.id() == id);
                let committed = knowledge.evidence(id);
                if receipt_item.is_none()
                    || committed.as_ref() != receipt_item
                    || receipt_item.is_some_and(|item| {
                        item.subject() != receipt.case().subject()
                            || item.source().correlation_id() != Some(receipt.case().id())
                    })
                {
                    return Err(AssessmentReviewLedgerError::VerifierProof);
                }
            }
            Ok(true)
        },
    }
}

fn expected_review_parent_ids(
    receipt: &DecisionEvidenceReceipt,
    root: &Url,
    contracts: ReviewContracts<'_>,
    kind: NativeWebReviewActionKind,
) -> Result<Vec<EvidenceId>, AssessmentReviewLedgerError> {
    let method = unique_base(receipt, HttpEvidencePredicate::REQUEST_METHOD)?;
    let requested = unique_base(receipt, HttpEvidencePredicate::REQUEST_URL)?;
    let status = unique_base(receipt, HttpEvidencePredicate::RESPONSE_STATUS)?;
    let final_url = unique_base(receipt, HttpEvidencePredicate::RESPONSE_FINAL_URL)?;
    if method.value() != &EvidenceValue::Text("GET".to_owned())
        || !requested_url_value_matches_with_sql(
            requested.value(),
            root,
            contracts,
            receipt.stage(),
            kind,
        )
        || status_u16(status.value()).is_none()
        || requested.value() != final_url.value()
    {
        return Err(AssessmentReviewLedgerError::EvidenceProjection);
    }
    let mut items = vec![method, requested, status, final_url];
    if is_xss_response_action(kind)
        || matches!(
            kind,
            NativeWebReviewActionKind::ReflectionContextQueryPair
                | NativeWebReviewActionKind::SqlStructuralQueryPair
                | NativeWebReviewActionKind::SqlStructuralQueryReplayPair
                | NativeWebReviewActionKind::SstiStructuralQueryPair
                | NativeWebReviewActionKind::SstiStructuralQueryReplayPair
        )
    {
        let media = optional_unique_base(receipt, HttpEvidencePredicate::RESPONSE_MEDIA_TYPE)?;
        if let Some(media) = media {
            if !matches!(media.value(), EvidenceValue::Text(value) if !value.is_empty()) {
                return Err(AssessmentReviewLedgerError::EvidenceProjection);
            }
            items.push(media);
        }
        let truncated = unique_base(receipt, HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED)?;
        let digest = unique_base(receipt, HttpEvidencePredicate::RESPONSE_BODY_SHA256)?;
        if !matches!(truncated.value(), EvidenceValue::Boolean(_))
            || !matches!(digest.value(), EvidenceValue::Text(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
        items.extend([truncated, digest]);
    }
    let reliability = items[0].reliability();
    for item in &items {
        if item.kind() == &EvidenceKind::Custom(ASSESSMENT_REVIEW_CATEGORY.to_owned())
            || item.subject() != receipt.case().subject()
            || item.source().component() != receipt.executor_id()
            || item.source().correlation_id() != Some(receipt.case().id())
            || item.reliability() != reliability
        {
            return Err(AssessmentReviewLedgerError::EvidenceProjection);
        }
    }
    let mut ids = items
        .into_iter()
        .map(|item| item.id().clone())
        .collect::<Vec<_>>();
    if is_xss_response_action(kind) {
        ids.extend(
            contracts
                .xss
                .ok_or(AssessmentReviewLedgerError::EvidenceProjection)?
                .source_evidence_ids
                .iter()
                .cloned(),
        );
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn unique_base(
    receipt: &DecisionEvidenceReceipt,
    predicate: venom_core::PredicateDescriptor,
) -> Result<&Evidence, AssessmentReviewLedgerError> {
    optional_unique_base(receipt, predicate)?.ok_or(AssessmentReviewLedgerError::EvidenceProjection)
}

fn optional_unique_base(
    receipt: &DecisionEvidenceReceipt,
    predicate: venom_core::PredicateDescriptor,
) -> Result<Option<&Evidence>, AssessmentReviewLedgerError> {
    let predicate = predicate.into_knowledge();
    let mut matches = receipt
        .evidence()
        .iter()
        .filter(|item| item.predicate() == &predicate);
    let first = matches.next();
    if matches.next().is_some() {
        Err(AssessmentReviewLedgerError::EvidenceProjection)
    } else {
        Ok(first)
    }
}

fn receipt_url_matches_contract(
    receipt: &DecisionEvidenceReceipt,
    root: &Url,
    contracts: ReviewContracts<'_>,
    kind: NativeWebReviewActionKind,
) -> bool {
    unique_base(receipt, HttpEvidencePredicate::REQUEST_URL)
        .ok()
        .is_some_and(|evidence| {
            requested_url_value_matches_with_sql(
                evidence.value(),
                root,
                contracts,
                receipt.stage(),
                kind,
            )
        })
}

fn requested_url_value_matches_with_sql(
    value: &EvidenceValue,
    root: &Url,
    contracts: ReviewContracts<'_>,
    stage: DecisionExecutionStage,
    kind: NativeWebReviewActionKind,
) -> bool {
    let EvidenceValue::Text(value) = value else {
        return false;
    };
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    match (kind, stage) {
        (NativeWebReviewActionKind::CorsPolicyPair, _) => &url == root,
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Passive,
        ) => contracts.redirect.is_some() && &url == root,
        (
            NativeWebReviewActionKind::RedirectReflectionQueryPair,
            DecisionExecutionStage::Active,
        ) => contracts
            .redirect
            .is_some_and(|contract| url == contract.candidate_url),
        (NativeWebReviewActionKind::ReflectionContextQueryPair, stage) => {
            contracts.reflection.is_some_and(|contract| match stage {
                DecisionExecutionStage::Passive => url == contract.control_url,
                DecisionExecutionStage::Active => url == contract.candidate_url,
            })
        },
        (
            NativeWebReviewActionKind::SqlStructuralQueryPair
            | NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
            DecisionExecutionStage::Passive,
        ) => contracts
            .sql
            .is_some_and(|contract| url == contract.control_url),
        (
            NativeWebReviewActionKind::SqlStructuralQueryPair
            | NativeWebReviewActionKind::SqlStructuralQueryReplayPair,
            DecisionExecutionStage::Active,
        ) => contracts
            .sql
            .is_some_and(|contract| url == contract.candidate_url),
        (NativeWebReviewActionKind::SstiStructuralQueryPair, stage) => {
            contracts.ssti.is_some_and(|contract| match stage {
                DecisionExecutionStage::Passive => url == contract.primary.control_url,
                DecisionExecutionStage::Active => url == contract.primary.candidate_url,
            })
        },
        (NativeWebReviewActionKind::SstiStructuralQueryReplayPair, stage) => {
            contracts.ssti.is_some_and(|contract| match stage {
                DecisionExecutionStage::Passive => url == contract.replay.control_url,
                DecisionExecutionStage::Active => url == contract.replay.candidate_url,
            })
        },
        (
            NativeWebReviewActionKind::XssStructuralQueryPair
            | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
            | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair,
            stage,
        ) => contracts.xss.is_some_and(|contract| match stage {
            DecisionExecutionStage::Passive => url == contract.control_url,
            DecisionExecutionStage::Active => url == contract.candidate_url,
        }),
        #[cfg(feature = "normalization-resilience")]
        (NativeWebReviewActionKind::NormalizationResilienceQueryPair, stage) => {
            contracts.xss.is_some_and(|contract| match stage {
                DecisionExecutionStage::Passive => url == contract.control_url,
                DecisionExecutionStage::Active => url == contract.candidate_url,
            })
        },
        #[cfg(feature = "authorization-review")]
        (NativeWebReviewActionKind::ResourceAuthorizationDifferential, _) => false,
        #[cfg(feature = "openapi-review")]
        (NativeWebReviewActionKind::OpenApiDocumentReplay, _) => false,
    }
}

fn execution_and_verification_stage_match(
    execution: DecisionExecutionStage,
    verification: VerificationStage,
) -> bool {
    matches!(
        (execution, verification),
        (DecisionExecutionStage::Passive, VerificationStage::Passive)
            | (DecisionExecutionStage::Active, VerificationStage::Active)
    )
}

fn review_kind(action_id: &str) -> Option<NativeWebReviewActionKind> {
    NativeWebReviewActionKind::all()
        .into_iter()
        .find(|kind| kind.action_id() == action_id)
}

const fn is_normalization_action(kind: NativeWebReviewActionKind) -> bool {
    #[cfg(feature = "normalization-resilience")]
    {
        matches!(
            kind,
            NativeWebReviewActionKind::NormalizationResilienceQueryPair
        )
    }
    #[cfg(not(feature = "normalization-resilience"))]
    {
        let _ = kind;
        false
    }
}

const fn is_xss_response_action(kind: NativeWebReviewActionKind) -> bool {
    match kind {
        NativeWebReviewActionKind::XssStructuralQueryPair
        | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
        | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => true,
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => true,
        NativeWebReviewActionKind::CorsPolicyPair
        | NativeWebReviewActionKind::RedirectReflectionQueryPair
        | NativeWebReviewActionKind::ReflectionContextQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair
        | NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => false,
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => false,
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => false,
    }
}

const CORS_REVIEW_PROPERTIES: [ReviewProperty; 5] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::CorsHttpStatusClass,
    ReviewProperty::CorsAllowOrigin,
    ReviewProperty::CorsAllowCredentials,
    ReviewProperty::CorsVaryOrigin,
];

const REDIRECT_REVIEW_PROPERTIES: [ReviewProperty; 3] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::RedirectStatus,
    ReviewProperty::RedirectLocation,
];

const REFLECTION_REVIEW_PROPERTIES: [ReviewProperty; 11] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::HtmlReflection,
    ReviewProperty::HtmlAttributeSourceStatus,
    ReviewProperty::HtmlAttributeSourceQuoteMode,
    ReviewProperty::HtmlAttributeSourceElement,
    ReviewProperty::HtmlAttributeSourceName,
    ReviewProperty::HtmlAttributeSourceContext,
    ReviewProperty::JavaScriptSourceStatus,
    ReviewProperty::JavaScriptSourceScriptKind,
    ReviewProperty::JavaScriptSourceContext,
    ReviewProperty::JavaScriptSourceScriptOrdinal,
];

const SQL_REVIEW_PROPERTIES: [ReviewProperty; 3] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::SqlHttpStatusClass,
    ReviewProperty::SqlBodyStructure,
];

const SSTI_REVIEW_PROPERTIES: [ReviewProperty; 3] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::SstiHttpStatusClass,
    ReviewProperty::SstiEvaluation,
];

const XSS_REVIEW_PROPERTIES: [ReviewProperty; 8] = [
    ReviewProperty::ResponseMarker,
    ReviewProperty::XssProbeFamily,
    ReviewProperty::XssProbeVariant,
    ReviewProperty::JavaScriptSourceStatus,
    ReviewProperty::JavaScriptSourceScriptKind,
    ReviewProperty::JavaScriptSourceContext,
    ReviewProperty::JavaScriptSourceScriptOrdinal,
    ReviewProperty::XssStructuralRelation,
];

fn expected_properties(kind: NativeWebReviewActionKind) -> &'static [ReviewProperty] {
    match kind {
        NativeWebReviewActionKind::CorsPolicyPair => &CORS_REVIEW_PROPERTIES,
        NativeWebReviewActionKind::RedirectReflectionQueryPair => &REDIRECT_REVIEW_PROPERTIES,
        NativeWebReviewActionKind::ReflectionContextQueryPair => &REFLECTION_REVIEW_PROPERTIES,
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => &SQL_REVIEW_PROPERTIES,
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => &SSTI_REVIEW_PROPERTIES,
        NativeWebReviewActionKind::XssStructuralQueryPair
        | NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
        | NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => &XSS_REVIEW_PROPERTIES,
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => &XSS_REVIEW_PROPERTIES,
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => &[],
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => &[],
    }
}

fn value<'a>(
    values: &'a BTreeMap<ReviewProperty, &'a str>,
    property: ReviewProperty,
) -> Result<&'a str, AssessmentReviewLedgerError> {
    values
        .get(&property)
        .copied()
        .ok_or(AssessmentReviewLedgerError::EvidenceProjection)
}

fn stage_marker(stage: DecisionExecutionStage) -> &'static str {
    match stage {
        DecisionExecutionStage::Passive => "passive-control",
        DecisionExecutionStage::Active => "active-candidate",
    }
}

fn parse_cors_allow_origin(
    value: &str,
) -> Result<CorsAllowOriginRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(CorsAllowOriginRelation::Missing),
        "exact-request-origin" => Ok(CorsAllowOriginRelation::ExactRequestOrigin),
        "wildcard" => Ok(CorsAllowOriginRelation::Wildcard),
        "other" => Ok(CorsAllowOriginRelation::Other),
        "invalid-or-multiple" => Ok(CorsAllowOriginRelation::InvalidOrMultiple),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_cors_allow_credentials(
    value: &str,
) -> Result<CorsAllowCredentialsRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(CorsAllowCredentialsRelation::Missing),
        "true" => Ok(CorsAllowCredentialsRelation::True),
        "other" => Ok(CorsAllowCredentialsRelation::Other),
        "invalid-or-multiple" => Ok(CorsAllowCredentialsRelation::InvalidOrMultiple),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_vary_origin(value: &str) -> Result<VaryOriginRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(VaryOriginRelation::Missing),
        "contains-origin" => Ok(VaryOriginRelation::ContainsOrigin),
        "wildcard" => Ok(VaryOriginRelation::Wildcard),
        "other" => Ok(VaryOriginRelation::Other),
        "invalid" => Ok(VaryOriginRelation::Invalid),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_status_relation(value: &str) -> Result<ReviewStatusRelation, AssessmentReviewLedgerError> {
    match value {
        "redirect" => Ok(ReviewStatusRelation::Redirect),
        "other" => Ok(ReviewStatusRelation::Other),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_http_status_class(
    value: &str,
) -> Result<ReviewHttpStatusClass, AssessmentReviewLedgerError> {
    match value {
        "informational" => Ok(ReviewHttpStatusClass::Informational),
        "successful" => Ok(ReviewHttpStatusClass::Successful),
        "redirection" => Ok(ReviewHttpStatusClass::Redirection),
        "client-error" => Ok(ReviewHttpStatusClass::ClientError),
        "server-error" => Ok(ReviewHttpStatusClass::ServerError),
        "other" => Ok(ReviewHttpStatusClass::Other),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_location(value: &str) -> Result<LocationRelation, AssessmentReviewLedgerError> {
    match value {
        "missing" => Ok(LocationRelation::Missing),
        "exact-external-query-value" => Ok(LocationRelation::ExactExternalQueryValue),
        "other" => Ok(LocationRelation::Other),
        "invalid-or-multiple" => Ok(LocationRelation::InvalidOrMultiple),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn parse_reflection(
    value: &str,
) -> Result<ExactHtmlReflectionContext, AssessmentReviewLedgerError> {
    match value {
        "absent" => Ok(ExactHtmlReflectionContext::Absent),
        "html-comment" => Ok(ExactHtmlReflectionContext::HtmlComment),
        "html-text" => Ok(ExactHtmlReflectionContext::HtmlText),
        "attribute-value" => Ok(ExactHtmlReflectionContext::AttributeValue),
        "uri-attribute" => Ok(ExactHtmlReflectionContext::UriAttribute),
        "style-attribute" => Ok(ExactHtmlReflectionContext::StyleAttribute),
        "style-element-content" => Ok(ExactHtmlReflectionContext::StyleElementContent),
        "event-handler-attribute" => Ok(ExactHtmlReflectionContext::EventHandlerAttribute),
        "script-element-content" => Ok(ExactHtmlReflectionContext::ScriptElementContent),
        "embedded-html-attribute" => Ok(ExactHtmlReflectionContext::EmbeddedHtmlAttribute),
        "not-applicable" => Ok(ExactHtmlReflectionContext::NotApplicable),
        "incomplete" => Ok(ExactHtmlReflectionContext::Incomplete),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

fn status_u16(value: &EvidenceValue) -> Option<u16> {
    let EvidenceValue::Unsigned(value) = value else {
        return None;
    };
    u16::try_from(*value).ok()
}

/// Strongest product disposition a native review candidate can request.
/// Confirmation is intentionally not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeReviewDisposition {
    Informational,
    NeedsReview,
}

/// Closed CORS control/candidate status relationship admitted to projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorsStatusRelationship {
    MatchedSuccessful,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CorsReviewCandidate {
    subject: EntityId,
    case_id: String,
    status_relationship: CorsStatusRelationship,
    vary_origin: VaryOriginRelation,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RedirectReviewCandidate {
    subject: EntityId,
    case_id: String,
    query_parameter: String,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewReflectionContext {
    HtmlComment,
    HtmlText,
    AttributeValue,
    UriAttribute,
    StyleAttribute,
    StyleElementContent,
    EventHandlerAttribute,
    ScriptElementContent,
    EmbeddedHtmlAttribute,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReflectionReviewCandidate {
    subject: EntityId,
    case_id: String,
    query_parameter: String,
    context: ReviewReflectionContext,
    attribute_source: AttributeSourceResult,
    javascript_source: JavaScriptSourceResult,
    disposition: NativeReviewDisposition,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[cfg(test)]
fn requested_url_value_matches(
    value: &EvidenceValue,
    root: &Url,
    redirect: Option<&RedirectReflectionContract>,
    stage: DecisionExecutionStage,
    kind: NativeWebReviewActionKind,
) -> bool {
    requested_url_value_matches_with_sql(
        value,
        root,
        ReviewContracts {
            redirect,
            reflection: None,
            sql: None,
            ssti: None,
            xss: None,
        },
        stage,
        kind,
    )
}

fn parse_ssti_evaluation(
    value: &str,
) -> Result<SstiEvaluationRelation, AssessmentReviewLedgerError> {
    match value {
        "absent" => Ok(SstiEvaluationRelation::Absent),
        "expected-present-in-control" => Ok(SstiEvaluationRelation::ExpectedPresentInControl),
        "literal-reflection" => Ok(SstiEvaluationRelation::LiteralReflection),
        "expected-evaluation" => Ok(SstiEvaluationRelation::ExpectedEvaluation),
        "unsupported" => Ok(SstiEvaluationRelation::Unsupported),
        "incomplete" => Ok(SstiEvaluationRelation::Incomplete),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct XssSelectionInput {
    pub(crate) query_parameter: String,
    pub(crate) context: ExactHtmlReflectionContext,
    pub(crate) attribute_source: AttributeSourceResult,
    pub(crate) javascript_source: JavaScriptSourceResult,
    pub(crate) source_evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for XssSelectionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XssSelectionInput")
            .field("query_parameter", &"<redacted>")
            .field("context", &self.context)
            .field("attribute_source", &self.attribute_source.status_id())
            .field("javascript_source", &self.javascript_source.status_id())
            .field("source_evidence_count", &self.source_evidence_ids.len())
            .finish()
    }
}

fn parse_xss_structural_relation(
    value: &str,
) -> Result<XssStructuralRelation, AssessmentReviewLedgerError> {
    match value {
        "encoded-or-inert" => Ok(XssStructuralRelation::EncodedOrInert),
        "reflected-same-context" => Ok(XssStructuralRelation::ReflectedSameContext),
        "structural-boundary-observed" => Ok(XssStructuralRelation::StructuralBoundaryObserved),
        "unsupported" => Ok(XssStructuralRelation::Unsupported),
        "incomplete" => Ok(XssStructuralRelation::Incomplete),
        _ => Err(AssessmentReviewLedgerError::EvidenceProjection),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SqlStructuralReviewCandidate {
    subject: EntityId,
    case_id: String,
    query_parameter: String,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SstiStructuralReviewCandidate {
    subject: EntityId,
    case_id: String,
    query_parameter: String,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct XssStructuralReviewCandidate {
    subject: EntityId,
    case_id: String,
    family: XssProbeFamily,
    query_parameter: String,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

/// One independently replayed normalization gap. The transform reference is
/// retained as typed stable identity; no transformed bytes are retained.
#[cfg(feature = "normalization-resilience")]
#[derive(Clone, PartialEq, Eq)]
pub(in crate::web_runtime) struct NormalizationReviewCandidate {
    subject: EntityId,
    case_id: String,
    family: XssProbeFamily,
    transform: NormalizationTransformRef,
    query_parameter: String,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

/// Typed output from the matched-pair ledger. No variant can assert a
/// confirmed vulnerability.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AssessmentReviewCandidate {
    Cors(CorsReviewCandidate),
    Redirect(RedirectReviewCandidate),
    Reflection(ReflectionReviewCandidate),
    SqlStructural(SqlStructuralReviewCandidate),
    SstiStructural(SstiStructuralReviewCandidate),
    XssStructural(XssStructuralReviewCandidate),
    #[cfg(feature = "normalization-resilience")]
    Normalization(NormalizationReviewCandidate),
}

macro_rules! redacted_candidate_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($name)
                    .field("subject", &"<redacted>")
                    .field("case_id", &"<redacted>")
                    .field("control_evidence_count", &self.control_evidence_ids.len())
                    .field(
                        "candidate_evidence_count",
                        &self.candidate_evidence_ids.len(),
                    )
                    .finish()
            }
        }
    };
}

redacted_candidate_debug!(CorsReviewCandidate, "CorsReviewCandidate");
redacted_candidate_debug!(RedirectReviewCandidate, "RedirectReviewCandidate");
redacted_candidate_debug!(SqlStructuralReviewCandidate, "SqlStructuralReviewCandidate");
redacted_candidate_debug!(
    SstiStructuralReviewCandidate,
    "SstiStructuralReviewCandidate"
);
redacted_candidate_debug!(XssStructuralReviewCandidate, "XssStructuralReviewCandidate");
#[cfg(feature = "normalization-resilience")]
redacted_candidate_debug!(NormalizationReviewCandidate, "NormalizationReviewCandidate");

impl fmt::Debug for ReflectionReviewCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReflectionReviewCandidate")
            .field("subject", &"<redacted>")
            .field("case_id", &"<redacted>")
            .field("context", &self.context)
            .field("attribute_source", &self.attribute_source.status_id())
            .field("disposition", &self.disposition)
            .field("control_evidence_count", &self.control_evidence_ids.len())
            .field(
                "candidate_evidence_count",
                &self.candidate_evidence_ids.len(),
            )
            .finish()
    }
}

impl fmt::Debug for AssessmentReviewCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cors(value) => value.fmt(formatter),
            Self::Redirect(value) => value.fmt(formatter),
            Self::Reflection(value) => value.fmt(formatter),
            Self::SqlStructural(value) => value.fmt(formatter),
            Self::SstiStructural(value) => value.fmt(formatter),
            Self::XssStructural(value) => value.fmt(formatter),
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(value) => value.fmt(formatter),
        }
    }
}

impl AssessmentReviewCandidate {
    pub(crate) const fn disposition(&self) -> NativeReviewDisposition {
        match self {
            Self::Cors(_)
            | Self::Redirect(_)
            | Self::SqlStructural(_)
            | Self::SstiStructural(_) => NativeReviewDisposition::NeedsReview,
            Self::XssStructural(_) => NativeReviewDisposition::NeedsReview,
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(_) => NativeReviewDisposition::NeedsReview,
            Self::Reflection(candidate) => candidate.disposition,
        }
    }

    pub(crate) fn subject(&self) -> &EntityId {
        match self {
            Self::Cors(candidate) => &candidate.subject,
            Self::Redirect(candidate) => &candidate.subject,
            Self::Reflection(candidate) => &candidate.subject,
            Self::SqlStructural(candidate) => &candidate.subject,
            Self::SstiStructural(candidate) => &candidate.subject,
            Self::XssStructural(candidate) => &candidate.subject,
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(candidate) => &candidate.subject,
        }
    }

    pub(crate) fn control_evidence_ids(&self) -> &[EvidenceId] {
        match self {
            Self::Cors(candidate) => &candidate.control_evidence_ids,
            Self::Redirect(candidate) => &candidate.control_evidence_ids,
            Self::Reflection(candidate) => &candidate.control_evidence_ids,
            Self::SqlStructural(candidate) => &candidate.control_evidence_ids,
            Self::SstiStructural(candidate) => &candidate.control_evidence_ids,
            Self::XssStructural(candidate) => &candidate.control_evidence_ids,
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(candidate) => &candidate.control_evidence_ids,
        }
    }

    pub(crate) fn candidate_evidence_ids(&self) -> &[EvidenceId] {
        match self {
            Self::Cors(candidate) => &candidate.candidate_evidence_ids,
            Self::Redirect(candidate) => &candidate.candidate_evidence_ids,
            Self::Reflection(candidate) => &candidate.candidate_evidence_ids,
            Self::SqlStructural(candidate) => &candidate.candidate_evidence_ids,
            Self::SstiStructural(candidate) => &candidate.candidate_evidence_ids,
            Self::XssStructural(candidate) => &candidate.candidate_evidence_ids,
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(candidate) => &candidate.candidate_evidence_ids,
        }
    }

    pub(crate) const fn reflection_context(&self) -> Option<ReviewReflectionContext> {
        match self {
            Self::Reflection(candidate) => Some(candidate.context),
            Self::Cors(_)
            | Self::Redirect(_)
            | Self::SqlStructural(_)
            | Self::SstiStructural(_) => None,
            Self::XssStructural(_) => None,
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(_) => None,
        }
    }

    /// Returns the only status relationship permitted for a CORS review item.
    pub(crate) const fn cors_status_relationship(&self) -> Option<CorsStatusRelationship> {
        match self {
            Self::Cors(candidate) => Some(candidate.status_relationship),
            Self::Redirect(_)
            | Self::Reflection(_)
            | Self::SqlStructural(_)
            | Self::SstiStructural(_) => None,
            Self::XssStructural(_) => None,
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(_) => None,
        }
    }

    pub(crate) fn query_parameter(&self) -> Option<&str> {
        match self {
            Self::Redirect(candidate) => Some(&candidate.query_parameter),
            Self::Reflection(candidate) => Some(&candidate.query_parameter),
            Self::SqlStructural(candidate) => Some(&candidate.query_parameter),
            Self::SstiStructural(candidate) => Some(&candidate.query_parameter),
            Self::XssStructural(candidate) => Some(&candidate.query_parameter),
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(candidate) => Some(&candidate.query_parameter),
            Self::Cors(_) => None,
        }
    }

    pub(crate) const fn xss_family(&self) -> Option<XssProbeFamily> {
        match self {
            Self::XssStructural(candidate) => Some(candidate.family),
            #[cfg(feature = "normalization-resilience")]
            Self::Normalization(candidate) => Some(candidate.family),
            _ => None,
        }
    }

    #[cfg(feature = "normalization-resilience")]
    pub(crate) const fn normalization_transform(&self) -> Option<NormalizationTransformRef> {
        match self {
            Self::Normalization(candidate) => Some(candidate.transform),
            _ => None,
        }
    }
}

fn append_pair_candidates(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
    query_parameter: Option<&str>,
    output: &mut Vec<AssessmentReviewCandidate>,
) {
    if !observations_form_exact_pair(control, candidate) {
        return;
    }
    match (&control.response, &candidate.response) {
        (
            CommittedReviewResponse::Cors {
                status: ReviewHttpStatusClass::Successful,
                allow_origin: CorsAllowOriginRelation::Missing,
                ..
            },
            CommittedReviewResponse::Cors {
                status: ReviewHttpStatusClass::Successful,
                allow_origin: CorsAllowOriginRelation::ExactRequestOrigin,
                allow_credentials: CorsAllowCredentialsRelation::True,
                vary_origin,
            },
        ) => output.push(AssessmentReviewCandidate::Cors(CorsReviewCandidate {
            subject: control.subject.clone(),
            case_id: control.case_id.clone(),
            status_relationship: CorsStatusRelationship::MatchedSuccessful,
            vary_origin: *vary_origin,
            control_evidence_ids: ids_for(
                control,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::CorsHttpStatusClass,
                    ReviewProperty::CorsAllowOrigin,
                ],
            ),
            candidate_evidence_ids: ids_for(
                candidate,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::CorsHttpStatusClass,
                    ReviewProperty::CorsAllowOrigin,
                    ReviewProperty::CorsAllowCredentials,
                    ReviewProperty::CorsVaryOrigin,
                ],
            ),
        })),
        (
            CommittedReviewResponse::Redirect {
                status: _,
                location: LocationRelation::Missing,
            },
            CommittedReviewResponse::Redirect {
                status: ReviewStatusRelation::Redirect,
                location: LocationRelation::ExactExternalQueryValue,
            },
        ) => {
            let Some(query_parameter) = query_parameter else {
                return;
            };
            output.push(AssessmentReviewCandidate::Redirect(
                RedirectReviewCandidate {
                    subject: control.subject.clone(),
                    case_id: control.case_id.clone(),
                    query_parameter: query_parameter.to_owned(),
                    control_evidence_ids: ids_for(
                        control,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::RedirectStatus,
                            ReviewProperty::RedirectLocation,
                        ],
                    ),
                    candidate_evidence_ids: ids_for(
                        candidate,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::RedirectStatus,
                            ReviewProperty::RedirectLocation,
                        ],
                    ),
                },
            ));
        },
        (
            CommittedReviewResponse::Reflection {
                reflection: control_reflection,
                attribute_source: _,
                javascript_source: _,
            },
            CommittedReviewResponse::Reflection {
                reflection: candidate_reflection,
                attribute_source: candidate_attribute_source,
                javascript_source: candidate_javascript_source,
            },
        ) => {
            let Some(query_parameter) = query_parameter else {
                return;
            };
            append_reflection_candidate(
                control,
                candidate,
                *control_reflection,
                *candidate_reflection,
                ReflectionSourceIntelligence {
                    attribute: candidate_attribute_source.clone(),
                    javascript: candidate_javascript_source.clone(),
                },
                query_parameter,
                output,
            )
        },
        _ => {},
    }
}

fn append_sql_candidate(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
    replay_control: &CommittedAssessmentReviewObservation,
    replay_candidate: &CommittedAssessmentReviewObservation,
    query_parameter: &str,
    output: &mut Vec<AssessmentReviewCandidate>,
) {
    if control.subject != replay_control.subject
        || candidate.subject != replay_candidate.subject
        || control.hypothesis_id != replay_control.hypothesis_id
        || control.case_id == replay_control.case_id
        || !disjoint(&control.evidence_ids, &candidate.evidence_ids)
        || !disjoint(&control.evidence_ids, &replay_control.evidence_ids)
        || !disjoint(&control.evidence_ids, &replay_candidate.evidence_ids)
        || !disjoint(&candidate.evidence_ids, &replay_control.evidence_ids)
        || !disjoint(&candidate.evidence_ids, &replay_candidate.evidence_ids)
        || !disjoint(&replay_control.evidence_ids, &replay_candidate.evidence_ids)
    {
        return;
    }
    let (
        CommittedReviewResponse::SqlStructural {
            status: control_status,
            body_structure: control_structure,
        },
        CommittedReviewResponse::SqlStructural {
            status: candidate_status,
            body_structure: candidate_structure,
        },
        CommittedReviewResponse::SqlStructural {
            status: replay_control_status,
            body_structure: replay_control_structure,
        },
        CommittedReviewResponse::SqlStructural {
            status: replay_candidate_status,
            body_structure: replay_candidate_structure,
        },
    ) = (
        &control.response,
        &candidate.response,
        &replay_control.response,
        &replay_candidate.response,
    )
    else {
        return;
    };
    if control_structure == "incomplete"
        || candidate_structure == "incomplete"
        || control_status != replay_control_status
        || control_structure != replay_control_structure
        || candidate_status != replay_candidate_status
        || candidate_structure != replay_candidate_structure
        || control_status == candidate_status
        || control_structure == candidate_structure
    {
        return;
    }
    output.push(AssessmentReviewCandidate::SqlStructural(
        SqlStructuralReviewCandidate {
            subject: control.subject.clone(),
            case_id: control.case_id.clone(),
            query_parameter: query_parameter.to_owned(),
            control_evidence_ids: [control, replay_control]
                .into_iter()
                .flat_map(|observation| {
                    ids_for(
                        observation,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::SqlHttpStatusClass,
                            ReviewProperty::SqlBodyStructure,
                        ],
                    )
                })
                .collect(),
            candidate_evidence_ids: [candidate, replay_candidate]
                .into_iter()
                .flat_map(|observation| {
                    ids_for(
                        observation,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::SqlHttpStatusClass,
                            ReviewProperty::SqlBodyStructure,
                        ],
                    )
                })
                .collect(),
        },
    ));
}

fn append_ssti_candidate(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
    replay_control: &CommittedAssessmentReviewObservation,
    replay_candidate: &CommittedAssessmentReviewObservation,
    query_parameter: &str,
    output: &mut Vec<AssessmentReviewCandidate>,
) {
    if control.subject != replay_control.subject
        || candidate.subject != replay_candidate.subject
        || control.hypothesis_id != replay_control.hypothesis_id
        || control.case_id == replay_control.case_id
        || !disjoint(&control.evidence_ids, &candidate.evidence_ids)
        || !disjoint(&control.evidence_ids, &replay_control.evidence_ids)
        || !disjoint(&control.evidence_ids, &replay_candidate.evidence_ids)
        || !disjoint(&candidate.evidence_ids, &replay_control.evidence_ids)
        || !disjoint(&candidate.evidence_ids, &replay_candidate.evidence_ids)
        || !disjoint(&replay_control.evidence_ids, &replay_candidate.evidence_ids)
    {
        return;
    }
    let (
        CommittedReviewResponse::SstiStructural {
            status: ReviewHttpStatusClass::Successful,
            evaluation: SstiEvaluationRelation::Absent,
        },
        CommittedReviewResponse::SstiStructural {
            status: ReviewHttpStatusClass::Successful,
            evaluation: SstiEvaluationRelation::ExpectedEvaluation,
        },
        CommittedReviewResponse::SstiStructural {
            status: ReviewHttpStatusClass::Successful,
            evaluation: SstiEvaluationRelation::Absent,
        },
        CommittedReviewResponse::SstiStructural {
            status: ReviewHttpStatusClass::Successful,
            evaluation: SstiEvaluationRelation::ExpectedEvaluation,
        },
    ) = (
        &control.response,
        &candidate.response,
        &replay_control.response,
        &replay_candidate.response,
    )
    else {
        return;
    };
    output.push(AssessmentReviewCandidate::SstiStructural(
        SstiStructuralReviewCandidate {
            subject: control.subject.clone(),
            case_id: control.case_id.clone(),
            query_parameter: query_parameter.to_owned(),
            control_evidence_ids: [control, replay_control]
                .into_iter()
                .flat_map(|observation| {
                    ids_for(
                        observation,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::SstiHttpStatusClass,
                            ReviewProperty::SstiEvaluation,
                        ],
                    )
                })
                .collect(),
            candidate_evidence_ids: [candidate, replay_candidate]
                .into_iter()
                .flat_map(|observation| {
                    ids_for(
                        observation,
                        &[
                            ReviewProperty::ResponseMarker,
                            ReviewProperty::SstiHttpStatusClass,
                            ReviewProperty::SstiEvaluation,
                        ],
                    )
                })
                .collect(),
        },
    ));
}

fn observations_form_exact_pair(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
) -> bool {
    control.stage == DecisionExecutionStage::Passive
        && candidate.stage == DecisionExecutionStage::Active
        && !control.active_pair_success
        && candidate.active_pair_success
        && control.kind == candidate.kind
        && control.subject == candidate.subject
        && control.case_id == candidate.case_id
        && control.hypothesis_id == candidate.hypothesis_id
        && disjoint(&control.evidence_ids, &candidate.evidence_ids)
}

fn append_reflection_candidate(
    control: &CommittedAssessmentReviewObservation,
    candidate: &CommittedAssessmentReviewObservation,
    control_context: ExactHtmlReflectionContext,
    candidate_context: ExactHtmlReflectionContext,
    source: ReflectionSourceIntelligence,
    query_parameter: &str,
    output: &mut Vec<AssessmentReviewCandidate>,
) {
    if control_context != ExactHtmlReflectionContext::Absent {
        return;
    }
    let (context, disposition) = match candidate_context {
        ExactHtmlReflectionContext::HtmlComment => (
            ReviewReflectionContext::HtmlComment,
            NativeReviewDisposition::Informational,
        ),
        ExactHtmlReflectionContext::HtmlText => (
            ReviewReflectionContext::HtmlText,
            NativeReviewDisposition::Informational,
        ),
        ExactHtmlReflectionContext::AttributeValue => (
            ReviewReflectionContext::AttributeValue,
            NativeReviewDisposition::Informational,
        ),
        ExactHtmlReflectionContext::UriAttribute => (
            ReviewReflectionContext::UriAttribute,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::StyleAttribute => (
            ReviewReflectionContext::StyleAttribute,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::StyleElementContent => (
            ReviewReflectionContext::StyleElementContent,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::EventHandlerAttribute => (
            ReviewReflectionContext::EventHandlerAttribute,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::ScriptElementContent => (
            ReviewReflectionContext::ScriptElementContent,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::EmbeddedHtmlAttribute => (
            ReviewReflectionContext::EmbeddedHtmlAttribute,
            NativeReviewDisposition::NeedsReview,
        ),
        ExactHtmlReflectionContext::Absent
        | ExactHtmlReflectionContext::NotApplicable
        | ExactHtmlReflectionContext::Incomplete => return,
    };
    output.push(AssessmentReviewCandidate::Reflection(
        ReflectionReviewCandidate {
            subject: control.subject.clone(),
            case_id: control.case_id.clone(),
            query_parameter: query_parameter.to_owned(),
            context,
            attribute_source: source.attribute,
            javascript_source: source.javascript,
            disposition,
            control_evidence_ids: ids_for(
                control,
                &[
                    ReviewProperty::ResponseMarker,
                    ReviewProperty::HtmlReflection,
                ],
            ),
            candidate_evidence_ids: ids_for(candidate, &REFLECTION_REVIEW_PROPERTIES),
        },
    ));
}

struct ReflectionSourceIntelligence {
    attribute: AttributeSourceResult,
    javascript: JavaScriptSourceResult,
}

fn ids_for(
    observation: &CommittedAssessmentReviewObservation,
    properties: &[ReviewProperty],
) -> Vec<EvidenceId> {
    properties
        .iter()
        .filter_map(|property| observation.property_evidence.get(property).cloned())
        .collect()
}

fn disjoint(left: &[EvidenceId], right: &[EvidenceId]) -> bool {
    let left = left.iter().collect::<BTreeSet<_>>();
    right.iter().all(|id| !left.contains(id))
}

#[cfg(test)]
#[path = "assessment_review_tests.rs"]
mod tests;
