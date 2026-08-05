//! Deterministic, bounded contracts for planner-selected payload strategies.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (planner-selected payload strategy contracts).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! A planner may select a stable [`PayloadStrategyRef`], but it never sees raw
//! payload bytes or a transport client. A capability executor resolves that
//! reference, derives exactly one control or candidate artifact for the
//! current execution turn, and remains responsible for dispatching it through
//! a host-owned accounting broker.

use std::{collections::BTreeMap, fmt::Write as _, sync::Arc};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum accepted strategy identifier length.
pub const HARD_MAX_PAYLOAD_STRATEGY_ID_BYTES: usize = 128;
/// Maximum seed or derived artifact size accepted by this contract.
pub const HARD_MAX_PAYLOAD_ARTIFACT_BYTES: u32 = 64 * 1024;
/// Default seed and artifact limit for one execution turn.
pub const DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES: u32 = 4 * 1024;

/// Validation and resolution failures for deterministic payload strategies.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PayloadStrategyError {
    /// A stable strategy identity was empty.
    #[error("payload strategy id must not be empty")]
    EmptyStrategyId,

    /// A strategy identity exceeded the bounded wire contract.
    #[error("payload strategy id length {actual} exceeds maximum {maximum}")]
    StrategyIdTooLong { actual: usize, maximum: usize },

    /// A strategy identity was not a canonical, log-safe ASCII slug.
    #[error("payload strategy id must contain only ASCII letters, digits, '.', '-', '_', or ':'")]
    InvalidStrategyId,

    /// Revision zero is reserved for invalid or unspecified strategies.
    #[error("payload strategy revision must be greater than zero")]
    ZeroRevision,

    /// A configured byte limit exceeded the hard safety ceiling.
    #[error("payload artifact limit {actual} exceeds maximum {maximum}")]
    ArtifactLimitTooLarge { actual: u32, maximum: u32 },

    /// A seed exceeded the per-turn byte allowance.
    #[error("payload seed length {actual} exceeds limit {maximum}")]
    SeedTooLarge { actual: usize, maximum: u32 },

    /// A derived artifact exceeded the per-turn byte allowance.
    #[error("derived payload length {actual} exceeds limit {maximum}")]
    ArtifactTooLarge { actual: usize, maximum: u32 },

    /// A strategy reference was registered more than once.
    #[error("payload strategy {strategy} is already registered")]
    StrategyIdentityConflict { strategy: PayloadStrategyRef },

    /// No implementation was registered for the planner-selected reference.
    #[error("payload strategy {strategy} is not registered")]
    UnknownStrategy { strategy: PayloadStrategyRef },

    /// An implementation returned an artifact for another strategy reference.
    #[error("payload strategy implementation returned mismatched provenance")]
    StrategyProvenanceMismatch,

    /// An implementation returned the opposite control/candidate role.
    #[error("payload strategy implementation returned mismatched variant role")]
    VariantRoleMismatch,

    /// A strategy could not derive an artifact.
    ///
    /// This variant deliberately carries no free-form diagnostic because a
    /// strategy has access to raw seed bytes and errors are routinely logged.
    #[error("payload strategy derivation failed")]
    DerivationFailed,
}

/// Stable, versioned identity selected by a planner action.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PayloadStrategyRef {
    id: String,
    revision: u32,
}

impl PayloadStrategyRef {
    /// Creates a validated strategy reference.
    pub fn new(id: impl Into<String>, revision: u32) -> Result<Self, PayloadStrategyError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(PayloadStrategyError::EmptyStrategyId);
        }
        if id.len() > HARD_MAX_PAYLOAD_STRATEGY_ID_BYTES {
            return Err(PayloadStrategyError::StrategyIdTooLong {
                actual: id.len(),
                maximum: HARD_MAX_PAYLOAD_STRATEGY_ID_BYTES,
            });
        }
        if !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
        {
            return Err(PayloadStrategyError::InvalidStrategyId);
        }
        if revision == 0 {
            return Err(PayloadStrategyError::ZeroRevision);
        }
        Ok(Self { id, revision })
    }

    /// Returns the stable strategy identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the deterministic implementation revision.
    pub const fn revision(&self) -> u32 {
        self.revision
    }
}

impl std::fmt::Debug for PayloadStrategyRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayloadStrategyRef")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .finish()
    }
}

impl std::fmt::Display for PayloadStrategyRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}@{}", self.id, self.revision)
    }
}

impl<'de> Deserialize<'de> for PayloadStrategyRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRef {
            id: String,
            revision: u32,
        }

        let wire = WireRef::deserialize(deserializer)?;
        Self::new(wire.id, wire.revision).map_err(serde::de::Error::custom)
    }
}

/// Role of the single artifact derived for an execution turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PayloadVariantRole {
    /// Stable control input used by passive evidence collection.
    Control,
    /// Candidate input used by an explicit active verification turn.
    Candidate,
}

/// Per-turn byte envelope applied before and after strategy derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PayloadStrategyLimits {
    max_seed_bytes: u32,
    max_artifact_bytes: u32,
}

impl PayloadStrategyLimits {
    /// Creates a bounded per-turn envelope. Zero is a valid fail-closed value.
    pub fn new(max_seed_bytes: u32, max_artifact_bytes: u32) -> Result<Self, PayloadStrategyError> {
        for actual in [max_seed_bytes, max_artifact_bytes] {
            if actual > HARD_MAX_PAYLOAD_ARTIFACT_BYTES {
                return Err(PayloadStrategyError::ArtifactLimitTooLarge {
                    actual,
                    maximum: HARD_MAX_PAYLOAD_ARTIFACT_BYTES,
                });
            }
        }
        Ok(Self {
            max_seed_bytes,
            max_artifact_bytes,
        })
    }

    /// Returns the largest accepted seed.
    pub const fn max_seed_bytes(self) -> u32 {
        self.max_seed_bytes
    }

    /// Returns the largest accepted derived artifact.
    pub const fn max_artifact_bytes(self) -> u32 {
        self.max_artifact_bytes
    }
}

impl Default for PayloadStrategyLimits {
    fn default() -> Self {
        Self {
            max_seed_bytes: DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES,
            max_artifact_bytes: DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES,
        }
    }
}

impl<'de> Deserialize<'de> for PayloadStrategyLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct WireLimits {
            max_seed_bytes: u32,
            max_artifact_bytes: u32,
        }

        impl Default for WireLimits {
            fn default() -> Self {
                let limits = PayloadStrategyLimits::default();
                Self {
                    max_seed_bytes: limits.max_seed_bytes,
                    max_artifact_bytes: limits.max_artifact_bytes,
                }
            }
        }

        let wire = WireLimits::deserialize(deserializer)?;
        Self::new(wire.max_seed_bytes, wire.max_artifact_bytes).map_err(serde::de::Error::custom)
    }
}

/// Raw seed owned by a capability executor and hidden from serialization.
#[derive(Clone, PartialEq, Eq)]
pub struct PayloadSeed(Vec<u8>);

impl PayloadSeed {
    /// Validates and stores one raw seed under the supplied byte envelope.
    pub fn new(
        value: impl Into<Vec<u8>>,
        limits: PayloadStrategyLimits,
    ) -> Result<Self, PayloadStrategyError> {
        let value = value.into();
        if value.len() > usize::try_from(limits.max_seed_bytes).unwrap_or(usize::MAX) {
            return Err(PayloadStrategyError::SeedTooLarge {
                actual: value.len(),
                maximum: limits.max_seed_bytes,
            });
        }
        Ok(Self(value))
    }

    /// Returns raw bytes only to the in-process strategy implementation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the seed length without exposing its content.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this is an empty, deliberately fail-closed seed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for PayloadSeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayloadSeed")
            .field("bytes", &self.0.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// One bounded raw artifact derived for one control or candidate turn.
#[derive(Clone, PartialEq, Eq)]
pub struct PayloadArtifact {
    strategy: PayloadStrategyRef,
    role: PayloadVariantRole,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl PayloadArtifact {
    /// Creates a bounded artifact with immutable provenance.
    pub fn new(
        strategy: PayloadStrategyRef,
        role: PayloadVariantRole,
        bytes: impl Into<Vec<u8>>,
        limits: PayloadStrategyLimits,
    ) -> Result<Self, PayloadStrategyError> {
        let bytes = bytes.into();
        if bytes.len() > usize::try_from(limits.max_artifact_bytes).unwrap_or(usize::MAX) {
            return Err(PayloadStrategyError::ArtifactTooLarge {
                actual: bytes.len(),
                maximum: limits.max_artifact_bytes,
            });
        }
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            strategy,
            role,
            bytes,
            digest,
        })
    }

    /// Returns the selected strategy reference.
    pub const fn strategy(&self) -> &PayloadStrategyRef {
        &self.strategy
    }

    /// Returns whether this is the control or candidate artifact.
    pub const fn role(&self) -> PayloadVariantRole {
        self.role
    }

    /// Returns raw bytes only to the capability executor that will dispatch them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a raw-value-free receipt suitable for audit output.
    pub fn receipt(&self) -> PayloadArtifactReceipt {
        PayloadArtifactReceipt {
            strategy: self.strategy.clone(),
            role: self.role,
            byte_length: u32::try_from(self.bytes.len()).unwrap_or(u32::MAX),
            sha256: encode_digest(self.digest),
        }
    }
}

impl std::fmt::Debug for PayloadArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayloadArtifact")
            .field("strategy", &self.strategy)
            .field("role", &self.role)
            .field("byte_length", &self.bytes.len())
            .field("sha256", &encode_digest(self.digest))
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Raw-value-free provenance for a derived artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayloadArtifactReceipt {
    strategy: PayloadStrategyRef,
    role: PayloadVariantRole,
    byte_length: u32,
    sha256: String,
}

impl PayloadArtifactReceipt {
    /// Returns the selected strategy reference.
    pub const fn strategy(&self) -> &PayloadStrategyRef {
        &self.strategy
    }

    /// Returns the artifact role.
    pub const fn role(&self) -> PayloadVariantRole {
        self.role
    }

    /// Returns the exact derived byte length.
    pub const fn byte_length(&self) -> u32 {
        self.byte_length
    }

    /// Returns the lowercase SHA-256 digest without exposing raw bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Pure strategy contract implemented by native capability executors.
///
/// Implementations must derive the same bytes for the same reference, role,
/// seed, and limits. They must not read clocks, randomness, knowledge stores,
/// or network state. The registry validates provenance, role, and output size
/// after every call.
pub trait PayloadStrategy: Send + Sync {
    /// Returns the stable strategy identity and implementation revision.
    fn strategy_ref(&self) -> &PayloadStrategyRef;

    /// Derives exactly one bounded artifact for this execution turn.
    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError>;
}

/// Native strategy implementations keyed by planner-selected references.
#[derive(Clone, Default)]
pub struct PayloadStrategyRegistry {
    strategies: BTreeMap<PayloadStrategyRef, Arc<dyn PayloadStrategy>>,
}

impl PayloadStrategyRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one exact strategy revision.
    pub fn register(
        &mut self,
        strategy: Arc<dyn PayloadStrategy>,
    ) -> Result<(), PayloadStrategyError> {
        let reference = strategy.strategy_ref().clone();
        if self.strategies.contains_key(&reference) {
            return Err(PayloadStrategyError::StrategyIdentityConflict {
                strategy: reference,
            });
        }
        self.strategies.insert(reference, strategy);
        Ok(())
    }

    /// Returns whether an exact strategy revision is registered.
    pub fn contains(&self, reference: &PayloadStrategyRef) -> bool {
        self.strategies.contains_key(reference)
    }

    /// Returns the number of registered strategy revisions.
    pub fn len(&self) -> usize {
        self.strategies.len()
    }

    /// Returns whether no strategies are registered.
    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }

    /// Resolves and derives one artifact, then revalidates its provenance.
    pub fn derive_one(
        &self,
        reference: &PayloadStrategyRef,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        if seed.len() > usize::try_from(limits.max_seed_bytes()).unwrap_or(usize::MAX) {
            return Err(PayloadStrategyError::SeedTooLarge {
                actual: seed.len(),
                maximum: limits.max_seed_bytes(),
            });
        }
        let strategy = self.strategies.get(reference).ok_or_else(|| {
            PayloadStrategyError::UnknownStrategy {
                strategy: reference.clone(),
            }
        })?;
        let artifact = strategy.derive_one(role, seed, limits)?;
        if artifact.strategy() != reference {
            return Err(PayloadStrategyError::StrategyProvenanceMismatch);
        }
        if artifact.role() != role {
            return Err(PayloadStrategyError::VariantRoleMismatch);
        }
        if artifact.as_bytes().len()
            > usize::try_from(limits.max_artifact_bytes()).unwrap_or(usize::MAX)
        {
            return Err(PayloadStrategyError::ArtifactTooLarge {
                actual: artifact.as_bytes().len(),
                maximum: limits.max_artifact_bytes(),
            });
        }
        Ok(artifact)
    }
}

impl std::fmt::Debug for PayloadStrategyRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayloadStrategyRegistry")
            .field("strategies", &self.strategies.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn encode_digest(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PrefixStrategy {
        reference: PayloadStrategyRef,
    }

    impl PayloadStrategy for PrefixStrategy {
        fn strategy_ref(&self) -> &PayloadStrategyRef {
            &self.reference
        }

        fn derive_one(
            &self,
            role: PayloadVariantRole,
            seed: &PayloadSeed,
            limits: PayloadStrategyLimits,
        ) -> Result<PayloadArtifact, PayloadStrategyError> {
            let prefix = match role {
                PayloadVariantRole::Control => b"control:".as_slice(),
                PayloadVariantRole::Candidate => b"candidate:".as_slice(),
            };
            let mut bytes = Vec::with_capacity(prefix.len().saturating_add(seed.len()));
            bytes.extend_from_slice(prefix);
            bytes.extend_from_slice(seed.as_bytes());
            PayloadArtifact::new(self.reference.clone(), role, bytes, limits)
        }
    }

    fn reference() -> PayloadStrategyRef {
        PayloadStrategyRef::new("differential.fixture", 1).unwrap()
    }

    #[test]
    fn strategy_reference_and_limits_validate_wire_input() {
        assert!(matches!(
            PayloadStrategyRef::new("", 1),
            Err(PayloadStrategyError::EmptyStrategyId)
        ));
        assert!(matches!(
            PayloadStrategyRef::new("valid", 0),
            Err(PayloadStrategyError::ZeroRevision)
        ));
        for invalid in [" leading", "trailing ", "line\nbreak", "non-ascii-ş"] {
            assert!(matches!(
                PayloadStrategyRef::new(invalid, 1),
                Err(PayloadStrategyError::InvalidStrategyId)
            ));
        }
        assert!(
            serde_json::from_value::<PayloadStrategyRef>(serde_json::json!({
                "id": "valid",
                "revision": 0
            }))
            .is_err()
        );
        assert!(PayloadStrategyLimits::new(0, 0).is_ok());
        assert!(PayloadStrategyLimits::new(HARD_MAX_PAYLOAD_ARTIFACT_BYTES + 1, 1).is_err());
    }

    #[test]
    fn same_input_produces_same_artifact_and_receipt() {
        let reference = reference();
        let strategy = Arc::new(PrefixStrategy {
            reference: reference.clone(),
        });
        let mut registry = PayloadStrategyRegistry::new();
        registry.register(strategy).unwrap();
        let limits = PayloadStrategyLimits::default();
        let seed = PayloadSeed::new(b"fixture".to_vec(), limits).unwrap();

        let first = registry
            .derive_one(&reference, PayloadVariantRole::Candidate, &seed, limits)
            .unwrap();
        let second = registry
            .derive_one(&reference, PayloadVariantRole::Candidate, &seed, limits)
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.receipt(), second.receipt());
        assert_eq!(first.as_bytes(), b"candidate:fixture");
    }

    #[test]
    fn raw_seed_and_artifact_never_enter_debug_or_receipt_json() {
        let secret = b"not-for-logs".to_vec();
        let limits = PayloadStrategyLimits::default();
        let seed = PayloadSeed::new(secret.clone(), limits).unwrap();
        let artifact =
            PayloadArtifact::new(reference(), PayloadVariantRole::Control, secret, limits).unwrap();
        let output = format!(
            "{seed:?} {artifact:?} {}",
            serde_json::to_string(&artifact.receipt()).unwrap()
        );

        assert!(!output.contains("not-for-logs"));
        assert!(output.contains("<redacted>"));
        assert_eq!(artifact.receipt().sha256().len(), 64);
    }

    #[test]
    fn seed_and_derived_output_limits_fail_closed() {
        let limits = PayloadStrategyLimits::new(3, 8).unwrap();
        assert!(matches!(
            PayloadSeed::new(b"four".to_vec(), limits),
            Err(PayloadStrategyError::SeedTooLarge { .. })
        ));

        let reference = reference();
        let mut registry = PayloadStrategyRegistry::new();
        registry
            .register(Arc::new(PrefixStrategy {
                reference: reference.clone(),
            }))
            .unwrap();
        let seed = PayloadSeed::new(b"abc".to_vec(), limits).unwrap();
        assert!(matches!(
            registry.derive_one(&reference, PayloadVariantRole::Candidate, &seed, limits),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));

        let wider = PayloadStrategyLimits::new(4, 16).unwrap();
        let narrower = PayloadStrategyLimits::new(3, 16).unwrap();
        let seed = PayloadSeed::new(b"four".to_vec(), wider).unwrap();
        assert!(matches!(
            registry.derive_one(&reference, PayloadVariantRole::Control, &seed, narrower),
            Err(PayloadStrategyError::SeedTooLarge {
                actual: 4,
                maximum: 3
            })
        ));
    }

    #[test]
    fn registry_rejects_unknown_and_duplicate_strategy_revisions() {
        let reference = reference();
        let strategy = Arc::new(PrefixStrategy {
            reference: reference.clone(),
        });
        let mut registry = PayloadStrategyRegistry::new();
        registry.register(strategy.clone()).unwrap();
        assert!(matches!(
            registry.register(strategy),
            Err(PayloadStrategyError::StrategyIdentityConflict { .. })
        ));

        let missing = PayloadStrategyRef::new("missing", 1).unwrap();
        let seed = PayloadSeed::new(Vec::new(), PayloadStrategyLimits::default()).unwrap();
        assert!(matches!(
            registry.derive_one(
                &missing,
                PayloadVariantRole::Control,
                &seed,
                PayloadStrategyLimits::default()
            ),
            Err(PayloadStrategyError::UnknownStrategy { .. })
        ));
    }
}
