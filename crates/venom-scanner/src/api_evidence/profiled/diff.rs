//! Bounded, redacted path fingerprints and visibility explanations.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{
    de::{IgnoredAny, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use venom_core::ApiVisibilityDimension;

use crate::api_evidence::profiled::{
    policy::{
        deserialize_digest, encode_digest, update_framed, JsonPathPattern,
        HARD_MAX_API_VISIBILITY_DIFF_PATHS,
    },
    ProfiledApiVisibilityError,
};

const PATH_DIGEST_DOMAIN: &[u8] = b"venom.api-visibility.path.v2\0";

/// Pseudonymous digest of one structural JSON path.
///
/// The digest contains no clear-text field names. Hosts with a safe path
/// allowlist can hash a [`JsonPathPattern`] locally to resolve explanations.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathDigest([u8; 32]);

impl PathDigest {
    /// Computes the digest used for a canonical path pattern.
    pub fn for_pattern(pattern: &JsonPathPattern) -> Self {
        digest_path(&pattern.tokens)
    }

    /// Returns the raw SHA-256 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a lowercase hexadecimal representation.
    pub fn to_hex(self) -> String {
        encode_digest(self.0)
    }
}

impl fmt::Debug for PathDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PathDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for PathDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for PathDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PathDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_digest(deserializer).map(Self)
    }
}

/// Bounded path-only explanation for one visibility comparison.
///
/// Digests are sorted, unique, and mutually exclusive across categories. The
/// combined vector length never exceeds the profile's global quota. Scalar
/// values and clear-text paths are not retained.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RedactedVisibilityDiff {
    added_path_hashes: Vec<PathDigest>,
    removed_path_hashes: Vec<PathDigest>,
    changed_type_path_hashes: Vec<PathDigest>,
    changed_value_path_hashes: Vec<PathDigest>,
    omitted_diff_count: u32,
}

impl RedactedVisibilityDiff {
    /// Returns paths present only in the candidate view.
    pub fn added_path_hashes(&self) -> &[PathDigest] {
        &self.added_path_hashes
    }

    /// Returns paths present only in the baseline view.
    pub fn removed_path_hashes(&self) -> &[PathDigest] {
        &self.removed_path_hashes
    }

    /// Returns shared paths whose JSON type set changed.
    pub fn changed_type_path_hashes(&self) -> &[PathDigest] {
        &self.changed_type_path_hashes
    }

    /// Returns shared scalar paths whose value digest changed.
    pub fn changed_value_path_hashes(&self) -> &[PathDigest] {
        &self.changed_value_path_hashes
    }

    /// Returns the exact number of differences excluded by the global quota.
    pub const fn omitted_diff_count(&self) -> u32 {
        self.omitted_diff_count
    }

    /// Returns the number of path differences retained in this explanation.
    ///
    /// This count excludes [`Self::omitted_diff_count`]. The compiled global
    /// path ceiling guarantees that the result fits in `u16`.
    pub fn retained_diff_count(&self) -> u16 {
        let retained = self
            .added_path_hashes
            .len()
            .saturating_add(self.removed_path_hashes.len())
            .saturating_add(self.changed_type_path_hashes.len())
            .saturating_add(self.changed_value_path_hashes.len());
        u16::try_from(retained).expect("bounded API visibility path count fits in u16")
    }

    /// Returns whether no path-level difference was observed or retained.
    pub fn is_empty(&self) -> bool {
        self.added_path_hashes.is_empty()
            && self.removed_path_hashes.is_empty()
            && self.changed_type_path_hashes.is_empty()
            && self.changed_value_path_hashes.is_empty()
            && self.omitted_diff_count == 0
    }

    fn from_parts(
        mut added_path_hashes: Vec<PathDigest>,
        mut removed_path_hashes: Vec<PathDigest>,
        mut changed_type_path_hashes: Vec<PathDigest>,
        mut changed_value_path_hashes: Vec<PathDigest>,
        omitted_diff_count: u32,
    ) -> Result<Self, ProfiledApiVisibilityError> {
        for values in [
            &mut added_path_hashes,
            &mut removed_path_hashes,
            &mut changed_type_path_hashes,
            &mut changed_value_path_hashes,
        ] {
            values.sort_unstable();
            values.dedup();
        }

        let total = added_path_hashes
            .len()
            .saturating_add(removed_path_hashes.len())
            .saturating_add(changed_type_path_hashes.len())
            .saturating_add(changed_value_path_hashes.len());
        if total > usize::from(HARD_MAX_API_VISIBILITY_DIFF_PATHS) {
            return Err(ProfiledApiVisibilityError::TooManyDiffPaths {
                maximum: HARD_MAX_API_VISIBILITY_DIFF_PATHS,
            });
        }

        let mut unique = BTreeSet::new();
        if [
            &added_path_hashes,
            &removed_path_hashes,
            &changed_type_path_hashes,
            &changed_value_path_hashes,
        ]
        .into_iter()
        .flatten()
        .any(|digest| !unique.insert(*digest))
        {
            return Err(ProfiledApiVisibilityError::OverlappingDiffCategories);
        }

        Ok(Self {
            added_path_hashes,
            removed_path_hashes,
            changed_type_path_hashes,
            changed_value_path_hashes,
            omitted_diff_count,
        })
    }

    fn from_wire_parts(
        added_path_hashes: Vec<PathDigest>,
        removed_path_hashes: Vec<PathDigest>,
        changed_type_path_hashes: Vec<PathDigest>,
        changed_value_path_hashes: Vec<PathDigest>,
        omitted_diff_count: u32,
    ) -> Result<Self, ProfiledApiVisibilityError> {
        if [
            &added_path_hashes,
            &removed_path_hashes,
            &changed_type_path_hashes,
            &changed_value_path_hashes,
        ]
        .into_iter()
        .any(|values| !strictly_sorted_unique(values))
        {
            return Err(ProfiledApiVisibilityError::NonCanonicalDiffPathOrder);
        }
        Self::from_parts(
            added_path_hashes,
            removed_path_hashes,
            changed_type_path_hashes,
            changed_value_path_hashes,
            omitted_diff_count,
        )
    }
}

impl fmt::Debug for RedactedVisibilityDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedVisibilityDiff")
            .field("added_path_count", &self.added_path_hashes.len())
            .field("removed_path_count", &self.removed_path_hashes.len())
            .field(
                "changed_type_path_count",
                &self.changed_type_path_hashes.len(),
            )
            .field(
                "changed_value_path_count",
                &self.changed_value_path_hashes.len(),
            )
            .field("omitted_diff_count", &self.omitted_diff_count)
            .finish()
    }
}

impl<'de> Deserialize<'de> for RedactedVisibilityDiff {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDiff {
            #[serde(deserialize_with = "deserialize_path_digests")]
            added_path_hashes: Vec<PathDigest>,
            #[serde(deserialize_with = "deserialize_path_digests")]
            removed_path_hashes: Vec<PathDigest>,
            #[serde(deserialize_with = "deserialize_path_digests")]
            changed_type_path_hashes: Vec<PathDigest>,
            #[serde(deserialize_with = "deserialize_path_digests")]
            changed_value_path_hashes: Vec<PathDigest>,
            omitted_diff_count: u32,
        }

        let wire = WireDiff::deserialize(deserializer)?;
        Self::from_wire_parts(
            wire.added_path_hashes,
            wire.removed_path_hashes,
            wire.changed_type_path_hashes,
            wire.changed_value_path_hashes,
            wire.omitted_diff_count,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PathFingerprint {
    type_mask: u8,
    scalar_value_digests: Vec<[u8; 32]>,
}

impl PathFingerprint {
    pub(super) fn new(type_mask: u8, scalar_value_digest: Option<[u8; 32]>) -> Self {
        Self {
            type_mask,
            scalar_value_digests: scalar_value_digest.into_iter().collect(),
        }
    }

    pub(super) fn merge(&mut self, other: Self) {
        self.type_mask |= other.type_mask;
        self.scalar_value_digests.extend(other.scalar_value_digests);
    }

    pub(super) fn canonicalize(&mut self) {
        // Preserve duplicate digests: array multiplicity is part of the
        // comparison contract even when element order is ignored. Sorting once
        // after capture avoids repeatedly re-sorting the growing aggregate for
        // every element that shares one structural path.
        self.scalar_value_digests.sort_unstable();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DiffKind {
    Added,
    Removed,
    ChangedType,
    ChangedValue,
}

pub(super) fn visibility_diff(
    dimension: ApiVisibilityDimension,
    baseline: &BTreeMap<PathDigest, PathFingerprint>,
    candidate: &BTreeMap<PathDigest, PathFingerprint>,
    max_diff_paths: u16,
) -> Result<RedactedVisibilityDiff, ProfiledApiVisibilityError> {
    if dimension == ApiVisibilityDimension::Status {
        return RedactedVisibilityDiff::from_parts(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        );
    }

    let mut differences = Vec::new();
    for (path, baseline_fingerprint) in baseline {
        match candidate.get(path) {
            None => differences.push((*path, DiffKind::Removed)),
            Some(candidate_fingerprint)
                if baseline_fingerprint.type_mask != candidate_fingerprint.type_mask =>
            {
                differences.push((*path, DiffKind::ChangedType));
            },
            Some(candidate_fingerprint)
                if dimension == ApiVisibilityDimension::Resources
                    && baseline_fingerprint.scalar_value_digests
                        != candidate_fingerprint.scalar_value_digests
                    && (!baseline_fingerprint.scalar_value_digests.is_empty()
                        || !candidate_fingerprint.scalar_value_digests.is_empty()) =>
            {
                differences.push((*path, DiffKind::ChangedValue));
            },
            Some(_) => {},
        }
    }
    for path in candidate.keys() {
        if !baseline.contains_key(path) {
            differences.push((*path, DiffKind::Added));
        }
    }
    differences.sort_unstable();

    let retained = differences.len().min(usize::from(max_diff_paths));
    let omitted_diff_count =
        u32::try_from(differences.len().saturating_sub(retained)).unwrap_or(u32::MAX);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed_type = Vec::new();
    let mut changed_value = Vec::new();
    for (path, kind) in differences.into_iter().take(retained) {
        match kind {
            DiffKind::Added => added.push(path),
            DiffKind::Removed => removed.push(path),
            DiffKind::ChangedType => changed_type.push(path),
            DiffKind::ChangedValue => changed_value.push(path),
        }
    }
    RedactedVisibilityDiff::from_parts(
        added,
        removed,
        changed_type,
        changed_value,
        omitted_diff_count,
    )
}

pub(super) fn fingerprint(value: &Value) -> (u8, Option<[u8; 32]>) {
    let (mask, scalar): (u8, Option<Vec<u8>>) = match value {
        Value::Null => (1 << 0, Some(b"null".to_vec())),
        Value::Bool(value) => (
            1 << 1,
            Some(if *value {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            }),
        ),
        Value::Number(value) if value.is_i64() || value.is_u64() => {
            (1 << 2, Some(value.to_string().into_bytes()))
        },
        Value::Number(value) => (1 << 3, Some(value.to_string().into_bytes())),
        Value::String(value) => (1 << 4, Some(value.as_bytes().to_vec())),
        Value::Array(_) => (1 << 5, None),
        Value::Object(_) => (1 << 6, None),
    };
    let digest = scalar.map(|value| {
        let mut hasher = Sha256::new();
        hasher.update(b"venom.api-visibility.scalar-value.v2\0");
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value);
        hasher.finalize().into()
    });
    (mask, digest)
}

pub(super) fn digest_path(tokens: &[String]) -> PathDigest {
    let mut hasher = Sha256::new();
    hasher.update(PATH_DIGEST_DOMAIN);
    hasher.update(
        u64::try_from(tokens.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for token in tokens {
        update_framed(&mut hasher, token.as_bytes());
    }
    PathDigest(hasher.finalize().into())
}

fn strictly_sorted_unique(values: &[PathDigest]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn deserialize_path_digests<'de, D>(deserializer: D) -> Result<Vec<PathDigest>, D::Error>
where
    D: Deserializer<'de>,
{
    struct DigestVisitor;

    impl<'de> Visitor<'de> for DigestVisitor {
        type Value = Vec<PathDigest>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {HARD_MAX_API_VISIBILITY_DIFF_PATHS} path digests"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut digests = Vec::new();
            while digests.len() < usize::from(HARD_MAX_API_VISIBILITY_DIFF_PATHS) {
                match sequence.next_element()? {
                    Some(digest) => digests.push(digest),
                    None => return Ok(digests),
                }
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "API visibility path-digest list exceeds compiled limit",
                ));
            }
            Ok(digests)
        }
    }

    deserializer.deserialize_seq(DigestVisitor)
}
