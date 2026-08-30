use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use venom_core::{EntityId, RelationId};

use crate::{
    api_observation::{
        cursor::ApiVisibilityReviewCursor,
        model::ApiObservationError,
        review::{project_api_visibility_review, ApiVisibilityReview},
        DEFAULT_API_VISIBILITY_REVIEW_SCAN_LIMIT, HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT,
    },
    knowledge::{KnowledgeBase, MAX_KNOWLEDGE_RELATION_ID_BYTES},
};

/// Bounded cursor for one resource-scoped API visibility review page.
///
/// The scan limit counts incoming relations inspected, including malformed or
/// unrelated relations that the projection rejects. This prevents a resource
/// with many noncanonical edges from forcing an unbounded clone or scan.
///
/// Relation cursors are opaque continuation capabilities, not authenticated
/// pagination tokens. A cursor can identify the last relation inspected even
/// when that relation was omitted from the review page. Hosts must authorize
/// access to the resource before accepting a query, use non-secret relation
/// identifiers, scope a cursor to the same resource, and avoid logging it.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityReviewQuery {
    after_relation_id: Option<RelationId>,
    scan_limit: u16,
}

impl fmt::Debug for ApiVisibilityReviewQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityReviewQuery")
            .field(
                "after_relation_id",
                &self.after_relation_id.as_ref().map(|_| "<redacted>"),
            )
            .field("scan_limit", &self.scan_limit)
            .finish()
    }
}

impl ApiVisibilityReviewQuery {
    /// Creates a query with a positive scan limit under the compiled ceiling.
    pub fn new(scan_limit: u16) -> Result<Self, ApiObservationError> {
        if scan_limit == 0 {
            return Err(ApiObservationError::ZeroReviewScanLimit);
        }
        if scan_limit > HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT {
            return Err(ApiObservationError::ReviewScanLimitExceeded {
                actual: scan_limit,
                maximum: HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT,
            });
        }
        Ok(Self {
            after_relation_id: None,
            scan_limit,
        })
    }

    /// Starts after one previously scanned opaque, non-secret relation cursor.
    ///
    /// The host must reuse this cursor only for the resource and authorization
    /// context from which it was returned. Reusing it with another resource is
    /// not rejected, but has no defined traversal meaning.
    pub fn after_relation_id(
        mut self,
        relation_id: RelationId,
    ) -> Result<Self, ApiObservationError> {
        if relation_id.as_str().len() > MAX_KNOWLEDGE_RELATION_ID_BYTES {
            return Err(ApiObservationError::ReviewCursorTooLong {
                actual: relation_id.as_str().len(),
                maximum: MAX_KNOWLEDGE_RELATION_ID_BYTES,
            });
        }
        self.after_relation_id = Some(relation_id);
        Ok(self)
    }

    /// Returns the exclusive opaque relation cursor, when this is a later page.
    pub fn after(&self) -> Option<&RelationId> {
        self.after_relation_id.as_ref()
    }

    /// Returns the maximum incoming relations inspected by this page.
    pub const fn scan_limit(&self) -> u16 {
        self.scan_limit
    }
}

impl Default for ApiVisibilityReviewQuery {
    fn default() -> Self {
        Self {
            after_relation_id: None,
            scan_limit: DEFAULT_API_VISIBILITY_REVIEW_SCAN_LIMIT,
        }
    }
}

impl<'de> Deserialize<'de> for ApiVisibilityReviewQuery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireQuery {
            after_relation_id: Option<RelationId>,
            scan_limit: u16,
        }

        let wire = WireQuery::deserialize(deserializer)?;
        let mut query = Self::new(wire.scan_limit).map_err(serde::de::Error::custom)?;
        if let Some(relation_id) = wire.after_relation_id {
            query = query
                .after_relation_id(relation_id)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(query)
    }
}

/// One bounded page of canonical reviews for a logical resource.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityReviewPage {
    resource_scope: EntityId,
    reviews: Vec<ApiVisibilityReview>,
    scanned_relations: u16,
    next_after_relation_id: Option<RelationId>,
}

impl fmt::Debug for ApiVisibilityReviewPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityReviewPage")
            .field("resource_scope", &"<redacted>")
            .field("reviews", &self.reviews)
            .field("scanned_relations", &self.scanned_relations)
            .field(
                "next_after_relation_id",
                &self.next_after_relation_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ApiVisibilityReviewPage {
    /// Returns the resource whose incoming relations were scanned.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns canonical reviews found inside this bounded relation window.
    pub fn reviews(&self) -> &[ApiVisibilityReview] {
        &self.reviews
    }

    /// Returns the number of incoming relations consumed from the scan budget.
    pub const fn scanned_relations(&self) -> u16 {
        self.scanned_relations
    }

    /// Returns the exclusive opaque cursor for the next page when more relations exist.
    ///
    /// This may identify an inspected relation that was structurally rejected
    /// and therefore absent from [`Self::reviews`]. Treat it as a non-secret,
    /// capability-scoped continuation value rather than domain data.
    pub fn next_after_relation_id(&self) -> Option<&RelationId> {
        self.next_after_relation_id.as_ref()
    }

    /// Derives the resource-bound v2 continuation token for the next page.
    ///
    /// The returned token is deterministic and redacted from `Debug` and
    /// `Display`, but is not signed. A transport may authenticate its serialized
    /// form before exposing it outside a trusted host boundary.
    pub fn next_cursor(&self) -> Result<Option<ApiVisibilityReviewCursor>, ApiObservationError> {
        self.next_after_relation_id
            .as_ref()
            .map(|relation_id| {
                ApiVisibilityReviewCursor::new(&self.resource_scope, relation_id.clone())
            })
            .transpose()
    }

    /// Takes the canonical reviews without cloning them.
    pub fn into_reviews(self) -> Vec<ApiVisibilityReview> {
        self.reviews
    }
}

/// Projects one bounded review page using a resource-bound v2 cursor.
///
/// A cursor is checked against the caller-authorized resource before the
/// knowledge store is scanned. The legacy [`ApiVisibilityReviewQuery`] and
/// [`api_visibility_reviews_for_resource`] contracts remain available for
/// trusted in-process continuation, while this entry point prevents accidental
/// cross-resource cursor reuse. This cursor is deterministic, not authenticated;
/// transports may sign or MAC its serialized representation.
pub fn api_visibility_reviews_for_resource_v2(
    knowledge: &KnowledgeBase,
    resource_scope: &EntityId,
    cursor: Option<&ApiVisibilityReviewCursor>,
    scan_limit: u16,
) -> Result<ApiVisibilityReviewPage, ApiObservationError> {
    let mut query = ApiVisibilityReviewQuery::new(scan_limit)?;
    if let Some(cursor) = cursor {
        if !cursor.matches_resource(resource_scope) {
            return Err(ApiObservationError::ResourceBoundReviewCursorMismatch);
        }
        query = query.after_relation_id(cursor.after_relation_id().clone())?;
    }
    Ok(api_visibility_reviews_for_resource(
        knowledge,
        resource_scope,
        &query,
    ))
}

/// Projects canonical API visibility comparisons associated with one resource.
///
/// The query clones at most its explicit relation limit; whether another page
/// exists is checked against the borrowed relation index without cloning the
/// look-ahead record. Referenced evidence and hypotheses are also inspected
/// while borrowed and cloned only after their variable review fields satisfy
/// compiled byte ceilings. Results are ordered by stable relation identity.
/// Structurally unrelated or forged-looking incoming relations consume scan
/// budget but are omitted. These checks are a read-model hygiene boundary, not
/// cryptographic attestation.
///
/// Pagination is not a database snapshot. Concurrent inserts sort according to
/// their stable relation IDs; a new ID at or before an already consumed cursor
/// is not returned by later pages. Hosts that require a frozen export must
/// provide an external snapshot or quiesce writes for that resource.
pub fn api_visibility_reviews_for_resource(
    knowledge: &KnowledgeBase,
    resource_scope: &EntityId,
    query: &ApiVisibilityReviewQuery,
) -> ApiVisibilityReviewPage {
    let scan_limit = usize::from(query.scan_limit());
    let (relations, has_more) =
        knowledge.relations_to_page_with_more(resource_scope, query.after(), scan_limit);
    let scanned_relations =
        u16::try_from(relations.len()).expect("validated review scan limits always fit in u16");
    let next_after_relation_id = has_more
        .then(|| relations.last().map(|relation| relation.id().clone()))
        .flatten();

    let mut reviews = Vec::new();
    for relation in relations {
        if let Some(review) = project_api_visibility_review(knowledge, resource_scope, &relation) {
            reviews.push(review);
        }
    }
    ApiVisibilityReviewPage {
        resource_scope: resource_scope.clone(),
        reviews,
        scanned_relations,
        next_after_relation_id,
    }
}
