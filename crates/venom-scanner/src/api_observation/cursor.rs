use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use venom_core::{EntityId, RelationId};

use crate::knowledge::MAX_KNOWLEDGE_RELATION_ID_BYTES;

use super::{
    model::ApiObservationError, API_VISIBILITY_REVIEW_CURSOR_DOMAIN,
    API_VISIBILITY_REVIEW_CURSOR_PREFIX, API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES,
    MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES,
};

/// Opaque v2 continuation token bound to one resource and relation position.
///
/// The token contains a versioned, domain-separated resource digest and the
/// last scanned relation ID encoded as lowercase hexadecimal bytes. It never
/// embeds the clear-text resource identifier. The digest is pseudonymous, not
/// confidential: low-entropy resource IDs remain susceptible to dictionary
/// attacks. The token is deterministic but is not authenticated or encrypted;
/// a transport may sign or MAC its serialized form before exposing it outside
/// a trusted boundary.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVisibilityReviewCursor {
    encoded: String,
    resource_digest: [u8; 32],
    after_relation_id: RelationId,
}

impl ApiVisibilityReviewCursor {
    /// Creates a canonical v2 cursor for one resource and relation position.
    pub fn new(
        resource_scope: &EntityId,
        after_relation_id: RelationId,
    ) -> Result<Self, ApiObservationError> {
        let actual = after_relation_id.as_str().len();
        if actual > MAX_KNOWLEDGE_RELATION_ID_BYTES {
            return Err(ApiObservationError::ReviewCursorTooLong {
                actual,
                maximum: MAX_KNOWLEDGE_RELATION_ID_BYTES,
            });
        }
        let resource_digest = review_cursor_resource_digest(resource_scope);
        let encoded = format!(
            "{API_VISIBILITY_REVIEW_CURSOR_PREFIX}{}:{}",
            encode_cursor_hex(&resource_digest),
            encode_cursor_hex(after_relation_id.as_str().as_bytes())
        );
        debug_assert!(encoded.len() <= MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES);
        Ok(Self {
            encoded,
            resource_digest,
            after_relation_id,
        })
    }

    /// Parses and validates one canonical serialized v2 cursor.
    pub fn parse(encoded: impl Into<String>) -> Result<Self, ApiObservationError> {
        let encoded = encoded.into();
        if encoded.len() > MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES {
            return Err(ApiObservationError::ResourceBoundReviewCursorTooLong {
                actual: encoded.len(),
                maximum: MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES,
            });
        }
        let Some(payload) = encoded.strip_prefix(API_VISIBILITY_REVIEW_CURSOR_PREFIX) else {
            if encoded.starts_with("venom-api-review-v") {
                return Err(ApiObservationError::UnsupportedResourceBoundReviewCursorVersion);
            }
            return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "cursor prefix is malformed",
            });
        };
        let Some((resource_digest, relation_id)) = payload.split_once(':') else {
            return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "cursor payload is incomplete",
            });
        };
        if resource_digest.len() != API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES {
            return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "resource digest must contain 64 lowercase hexadecimal characters",
            });
        }
        let resource_digest: [u8; 32] =
            decode_cursor_hex(resource_digest)?
                .try_into()
                .map_err(|_| ApiObservationError::InvalidResourceBoundReviewCursor {
                    reason: "resource digest must contain exactly 32 bytes",
                })?;
        let relation_id = decode_cursor_hex(relation_id)?;
        if relation_id.len() > MAX_KNOWLEDGE_RELATION_ID_BYTES {
            return Err(ApiObservationError::ReviewCursorTooLong {
                actual: relation_id.len(),
                maximum: MAX_KNOWLEDGE_RELATION_ID_BYTES,
            });
        }
        let relation_id = String::from_utf8(relation_id).map_err(|_| {
            ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "relation identifier is not valid UTF-8",
            }
        })?;
        let after_relation_id = RelationId::parse(relation_id).map_err(|_| {
            ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "relation identifier is empty",
            }
        })?;
        Ok(Self {
            encoded,
            resource_digest,
            after_relation_id,
        })
    }

    /// Returns the canonical transport representation.
    ///
    /// Callers should avoid logging this value and may wrap it in an
    /// authenticated transport token before returning it to an untrusted peer.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Returns this token's stable wire version.
    pub const fn version(&self) -> u8 {
        2
    }

    pub(super) fn matches_resource(&self, resource_scope: &EntityId) -> bool {
        self.resource_digest == review_cursor_resource_digest(resource_scope)
    }

    pub(super) fn after_relation_id(&self) -> &RelationId {
        &self.after_relation_id
    }
}

impl fmt::Debug for ApiVisibilityReviewCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiVisibilityReviewCursor(<redacted>)")
    }
}

impl fmt::Display for ApiVisibilityReviewCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for ApiVisibilityReviewCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encoded)
    }
}

impl<'de> Deserialize<'de> for ApiVisibilityReviewCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CursorVisitor;

        impl Visitor<'_> for CursorVisitor {
            type Value = ApiVisibilityReviewCursor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded resource-bound API visibility review cursor")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ApiVisibilityReviewCursor::parse(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ApiVisibilityReviewCursor::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(CursorVisitor)
    }
}

fn review_cursor_resource_digest(resource_scope: &EntityId) -> [u8; 32] {
    let bytes = resource_scope.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(API_VISIBILITY_REVIEW_CURSOR_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_cursor_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_cursor_hex(value: &str) -> Result<Vec<u8>, ApiObservationError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
            reason: "hexadecimal payload must be non-empty and byte-aligned",
        });
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in pairs {
        let high = decode_cursor_hex_nibble(pair[0])?;
        let low = decode_cursor_hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn decode_cursor_hex_nibble(value: u8) -> Result<u8, ApiObservationError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ApiObservationError::InvalidResourceBoundReviewCursor {
            reason: "cursor payload must use lowercase hexadecimal",
        }),
    }
}
