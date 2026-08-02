//! Projection-policy validation, versioning, and stable identifiers.

use std::fmt;

use serde::{
    de::{IgnoredAny, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};

use super::ProfiledApiVisibilityError;

const PROFILE_ID_DOMAIN: &[u8] = b"venom.api-visibility.projection-policy.v2\0";

/// Hard ceiling for the number of path patterns in one projection profile.
pub const HARD_MAX_API_COMPARISON_PROFILE_PATHS: usize = 256;
/// Hard ceiling for one canonical RFC 6901 path-pattern string.
pub const HARD_MAX_API_COMPARISON_PATH_BYTES: usize = 512;
/// Hard ceiling for decoded path-pattern segments.
pub const HARD_MAX_API_COMPARISON_PATH_DEPTH: usize = 128;
/// Hard ceiling for path digests retained by one comparison explanation.
pub const HARD_MAX_API_VISIBILITY_DIFF_PATHS: u16 = 1_024;
/// Default number of path digests retained by one comparison explanation.
pub const DEFAULT_API_VISIBILITY_DIFF_PATHS: u16 = 64;

/// Current deterministic comparator algorithm.
pub const CURRENT_API_COMPARISON_ALGORITHM_VERSION: ComparisonAlgorithmVersion =
    ComparisonAlgorithmVersion::V2;
/// Current deterministic canonicalization format.
pub const CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION: CanonicalizationVersion =
    CanonicalizationVersion::V2;

/// Version of the high-level projection and comparison algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ComparisonAlgorithmVersion {
    /// Profiled comparator with deterministic path projection and explanation.
    V2,
}

impl ComparisonAlgorithmVersion {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "v2",
        }
    }
}

/// Version of the canonical tree-hash encoding used by profiled views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CanonicalizationVersion {
    /// Domain-separated Merkle-style JSON tree hashing with typed leaves.
    V2,
}

impl CanonicalizationVersion {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "v2",
        }
    }
}

/// Validated RFC 6901 JSON Pointer pattern.
///
/// An empty string addresses the document root. A segment equal to `*` is a
/// deterministic wildcard extension used primarily for array members. Other
/// segments use standard `~0` and `~1` escaping. A selected pattern names a
/// subtree; an ignored pattern removes a subtree; and an unordered-array
/// pattern must match the array path itself.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPathPattern {
    canonical: String,
    pub(super) tokens: Vec<String>,
}

impl JsonPathPattern {
    /// Parses and canonicalizes one bounded pattern.
    pub fn new(value: impl Into<String>) -> Result<Self, ProfiledApiVisibilityError> {
        let value = value.into();
        if value.len() > HARD_MAX_API_COMPARISON_PATH_BYTES {
            return Err(ProfiledApiVisibilityError::PathTooLong {
                maximum: HARD_MAX_API_COMPARISON_PATH_BYTES,
            });
        }
        if !value.is_empty() && !value.starts_with('/') {
            return Err(ProfiledApiVisibilityError::InvalidPathPattern {
                reason: "non-root patterns must start with '/'",
            });
        }

        let tokens = if value.is_empty() {
            Vec::new()
        } else {
            value
                .split('/')
                .skip(1)
                .map(decode_pointer_token)
                .collect::<Result<Vec<_>, _>>()?
        };
        if tokens.len() > HARD_MAX_API_COMPARISON_PATH_DEPTH {
            return Err(ProfiledApiVisibilityError::PathTooDeep {
                maximum: HARD_MAX_API_COMPARISON_PATH_DEPTH,
            });
        }

        let canonical = encode_pointer(&tokens);
        if canonical.len() > HARD_MAX_API_COMPARISON_PATH_BYTES {
            return Err(ProfiledApiVisibilityError::PathTooLong {
                maximum: HARD_MAX_API_COMPARISON_PATH_BYTES,
            });
        }
        Ok(Self { canonical, tokens })
    }

    /// Returns the canonical RFC 6901 representation.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    fn matches_prefix_of(&self, path: &[String]) -> bool {
        self.tokens.len() <= path.len() && tokens_match(&self.tokens, &path[..self.tokens.len()])
    }

    fn path_is_prefix(&self, path: &[String]) -> bool {
        path.len() <= self.tokens.len() && tokens_match(&self.tokens[..path.len()], path)
    }

    fn matches_exactly(&self, path: &[String]) -> bool {
        self.tokens.len() == path.len() && tokens_match(&self.tokens, path)
    }
}

impl fmt::Debug for JsonPathPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JsonPathPattern(<redacted>)")
    }
}

impl Serialize for JsonPathPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical)
    }
}

impl<'de> Deserialize<'de> for JsonPathPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Stable digest of a complete projection policy.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionPolicyId([u8; 32]);

impl ProjectionPolicyId {
    /// Returns the raw SHA-256 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a lowercase hexadecimal representation.
    pub fn to_hex(self) -> String {
        encode_digest(self.0)
    }
}

impl fmt::Debug for ProjectionPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProjectionPolicyId")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for ProjectionPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for ProjectionPolicyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ProjectionPolicyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_digest(deserializer).map(Self)
    }
}

/// Deterministic projection and explanation policy for comparator v2.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiComparisonProfile {
    algorithm_version: ComparisonAlgorithmVersion,
    selected_paths: Vec<JsonPathPattern>,
    ignored_paths: Vec<JsonPathPattern>,
    unordered_arrays: Vec<JsonPathPattern>,
    max_diff_paths: u16,
    #[serde(skip)]
    projection_policy_id: ProjectionPolicyId,
}

impl ApiComparisonProfile {
    /// Creates a validated current-version profile.
    ///
    /// Empty `selected_paths` means the complete document. Patterns are sorted
    /// and deduplicated before the policy ID is calculated. Ignore rules take
    /// precedence over selection rules.
    pub fn new(
        selected_paths: Vec<JsonPathPattern>,
        ignored_paths: Vec<JsonPathPattern>,
        unordered_arrays: Vec<JsonPathPattern>,
        max_diff_paths: u16,
    ) -> Result<Self, ProfiledApiVisibilityError> {
        if max_diff_paths > HARD_MAX_API_VISIBILITY_DIFF_PATHS {
            return Err(ProfiledApiVisibilityError::TooManyDiffPaths {
                maximum: HARD_MAX_API_VISIBILITY_DIFF_PATHS,
            });
        }

        let selected_paths = normalized_subtrees(selected_paths);
        let ignored_paths = normalized_subtrees(ignored_paths);
        let unordered_arrays = normalized_patterns(unordered_arrays);
        let total = selected_paths
            .len()
            .saturating_add(ignored_paths.len())
            .saturating_add(unordered_arrays.len());
        if total > HARD_MAX_API_COMPARISON_PROFILE_PATHS {
            return Err(ProfiledApiVisibilityError::TooManyProfilePaths {
                maximum: HARD_MAX_API_COMPARISON_PROFILE_PATHS,
            });
        }
        if selected_paths.iter().any(|selected| {
            ignored_paths
                .iter()
                .any(|ignored| ignored.matches_prefix_of(&selected.tokens))
        }) {
            return Err(ProfiledApiVisibilityError::ConflictingPathPolicy);
        }

        let algorithm_version = CURRENT_API_COMPARISON_ALGORITHM_VERSION;
        let projection_policy_id = projection_policy_id(
            algorithm_version,
            &selected_paths,
            &ignored_paths,
            &unordered_arrays,
            max_diff_paths,
        );
        Ok(Self {
            algorithm_version,
            selected_paths,
            ignored_paths,
            unordered_arrays,
            max_diff_paths,
            projection_policy_id,
        })
    }

    /// Returns the deterministic comparison algorithm version.
    pub const fn algorithm_version(&self) -> ComparisonAlgorithmVersion {
        self.algorithm_version
    }

    /// Returns the selected subtree patterns; an empty slice selects all.
    pub fn selected_paths(&self) -> &[JsonPathPattern] {
        &self.selected_paths
    }

    /// Returns the ignored subtree patterns.
    pub fn ignored_paths(&self) -> &[JsonPathPattern] {
        &self.ignored_paths
    }

    /// Returns array paths whose element order is semantically irrelevant.
    pub fn unordered_arrays(&self) -> &[JsonPathPattern] {
        &self.unordered_arrays
    }

    /// Returns the combined explanation-path limit.
    pub const fn max_diff_paths(&self) -> u16 {
        self.max_diff_paths
    }

    /// Returns the stable digest of this complete projection policy.
    pub const fn projection_policy_id(&self) -> ProjectionPolicyId {
        self.projection_policy_id
    }

    pub(super) fn is_ignored(&self, path: &[String]) -> bool {
        self.ignored_paths
            .iter()
            .any(|pattern| pattern.matches_prefix_of(path))
    }

    pub(super) fn is_relevant(&self, path: &[String]) -> bool {
        self.selected_paths.is_empty()
            || self
                .selected_paths
                .iter()
                .any(|pattern| pattern.matches_prefix_of(path) || pattern.path_is_prefix(path))
    }

    pub(super) fn is_unordered_array(&self, path: &[String]) -> bool {
        self.unordered_arrays
            .iter()
            .any(|pattern| pattern.matches_exactly(path))
    }
}

impl Default for ApiComparisonProfile {
    fn default() -> Self {
        Self::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DEFAULT_API_VISIBILITY_DIFF_PATHS,
        )
        .expect("compiled default API comparison profile is valid")
    }
}

impl fmt::Debug for ApiComparisonProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiComparisonProfile")
            .field("algorithm_version", &self.algorithm_version)
            .field("selected_path_count", &self.selected_paths.len())
            .field("ignored_path_count", &self.ignored_paths.len())
            .field("unordered_array_count", &self.unordered_arrays.len())
            .field("max_diff_paths", &self.max_diff_paths)
            .field("projection_policy_id", &self.projection_policy_id)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ApiComparisonProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireProfile {
            algorithm_version: ComparisonAlgorithmVersion,
            #[serde(deserialize_with = "deserialize_patterns")]
            selected_paths: Vec<JsonPathPattern>,
            #[serde(deserialize_with = "deserialize_patterns")]
            ignored_paths: Vec<JsonPathPattern>,
            #[serde(deserialize_with = "deserialize_patterns")]
            unordered_arrays: Vec<JsonPathPattern>,
            max_diff_paths: u16,
        }

        let wire = WireProfile::deserialize(deserializer)?;
        if wire.algorithm_version != CURRENT_API_COMPARISON_ALGORITHM_VERSION {
            return Err(serde::de::Error::custom(
                "unsupported API comparison algorithm version",
            ));
        }
        Self::new(
            wire.selected_paths,
            wire.ignored_paths,
            wire.unordered_arrays,
            wire.max_diff_paths,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn normalized_patterns(mut patterns: Vec<JsonPathPattern>) -> Vec<JsonPathPattern> {
    patterns.sort_unstable();
    patterns.dedup();
    patterns
}

fn normalized_subtrees(patterns: Vec<JsonPathPattern>) -> Vec<JsonPathPattern> {
    let patterns = normalized_patterns(patterns);
    let mut normalized = Vec::<JsonPathPattern>::new();
    for pattern in patterns {
        if normalized
            .iter()
            .any(|ancestor| ancestor.matches_prefix_of(&pattern.tokens))
        {
            continue;
        }
        normalized.push(pattern);
    }
    normalized
}

fn projection_policy_id(
    algorithm_version: ComparisonAlgorithmVersion,
    selected_paths: &[JsonPathPattern],
    ignored_paths: &[JsonPathPattern],
    unordered_arrays: &[JsonPathPattern],
    max_diff_paths: u16,
) -> ProjectionPolicyId {
    let mut hasher = Sha256::new();
    hasher.update(PROFILE_ID_DOMAIN);
    update_framed(&mut hasher, algorithm_version.as_str().as_bytes());
    update_framed(
        &mut hasher,
        CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION
            .as_str()
            .as_bytes(),
    );
    update_pattern_list(&mut hasher, b"selected", selected_paths);
    update_pattern_list(&mut hasher, b"ignored", ignored_paths);
    update_pattern_list(&mut hasher, b"unordered", unordered_arrays);
    hasher.update(max_diff_paths.to_be_bytes());
    ProjectionPolicyId(hasher.finalize().into())
}

fn update_pattern_list(hasher: &mut Sha256, name: &[u8], patterns: &[JsonPathPattern]) {
    update_framed(hasher, name);
    hasher.update(
        u64::try_from(patterns.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for pattern in patterns {
        update_framed(hasher, pattern.canonical.as_bytes());
    }
}

pub(super) fn update_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn tokens_match(pattern: &[String], path: &[String]) -> bool {
    pattern
        .iter()
        .zip(path)
        .all(|(expected, actual)| expected == "*" || expected == actual)
}

fn decode_pointer_token(token: &str) -> Result<String, ProfiledApiVisibilityError> {
    let mut decoded = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => {
                return Err(ProfiledApiVisibilityError::InvalidPathPattern {
                    reason: "'~' escapes must be ~0 or ~1",
                });
            },
        }
    }
    Ok(decoded)
}

fn encode_pointer(tokens: &[String]) -> String {
    let mut encoded = String::new();
    for token in tokens {
        encoded.push('/');
        encoded.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    encoded
}

pub(super) fn deserialize_digest<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 64 {
        return Err(serde::de::Error::custom(
            "API visibility digest must contain 64 hexadecimal characters",
        ));
    }
    decode_digest(&value).map_err(serde::de::Error::custom)
}

pub(super) fn encode_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn decode_digest(value: &str) -> Result<[u8; 32], &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err("API visibility digest must contain exactly 32 bytes");
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("API visibility digest must use lowercase hexadecimal"),
    }
}

fn deserialize_patterns<'de, D>(deserializer: D) -> Result<Vec<JsonPathPattern>, D::Error>
where
    D: Deserializer<'de>,
{
    struct PatternVisitor;

    impl<'de> Visitor<'de> for PatternVisitor {
        type Value = Vec<JsonPathPattern>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {HARD_MAX_API_COMPARISON_PROFILE_PATHS} JSON path patterns"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut patterns = Vec::new();
            while patterns.len() < HARD_MAX_API_COMPARISON_PROFILE_PATHS {
                match sequence.next_element()? {
                    Some(pattern) => patterns.push(pattern),
                    None => return Ok(patterns),
                }
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "API comparison path-pattern list exceeds compiled limit",
                ));
            }
            Ok(patterns)
        }
    }

    deserializer.deserialize_seq(PatternVisitor)
}
