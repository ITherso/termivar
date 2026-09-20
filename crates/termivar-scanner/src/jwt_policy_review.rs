//! Bounded, transport-free review of one explicitly supplied compact JWT.
//!
//! This module deliberately supports only compact JWS objects signed with
//! ES256 and one explicitly supplied local P-256 public JWK. It never follows
//! key URLs or trusts token-carried key material. Parsing, local policy
//! consistency, local signature verification, and target acceptance are four
//! separate states; this module performs no target request.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use serde::{
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Stable identifier for the initial local JWT policy evaluator.
pub const JWT_POLICY_REVIEW_POLICY_ID: &str = "termivar.jwt-local-policy/es256-v1";
/// Stable schema identifier for the value-free audit outcome.
pub const JWT_POLICY_REVIEW_AUDIT_SCHEMA: &str = "security.jwt-policy-review-audit/v1";
/// Maximum accepted compact JWT bytes.
pub const MAX_COMPACT_JWT_BYTES: usize = 4 * 1024;
/// Maximum accepted local public JWK bytes.
pub const MAX_LOCAL_PUBLIC_JWK_BYTES: usize = 2 * 1024;
/// Maximum decoded protected-header bytes.
pub const MAX_JWT_HEADER_BYTES: usize = 1024;
/// Maximum decoded claims bytes.
pub const MAX_JWT_CLAIMS_BYTES: usize = 3 * 1024;
/// ES256 uses a fixed-width `R || S` signature.
pub const ES256_SIGNATURE_BYTES: usize = 64;
/// Maximum required claim names in one policy.
pub const MAX_REQUIRED_CLAIMS: usize = 16;
/// Maximum allowed clock-skew declaration.
pub const MAX_CLOCK_SKEW_SECONDS: u32 = 3600;

const MAX_EXPECTED_TYPE_BYTES: usize = 128;
const MAX_EXPECTED_STRING_BYTES: usize = 512;
const MAX_CLAIM_NAME_BYTES: usize = 128;
const MAX_POLICY_REFERENCE_BYTES: usize = 64;
const MAX_JSON_DEPTH: usize = 8;
const MAX_JSON_NODES: usize = 256;
const MAX_JSON_MEMBERS: usize = 128;
const MAX_JSON_ARRAY_ITEMS: usize = 64;
const MAX_JSON_STRING_BYTES: usize = 1024;
const JSON_DUPLICATE_SENTINEL: &str = "termivar-jwt-json-duplicate";
const JSON_LIMIT_SENTINEL: &str = "termivar-jwt-json-limit";

/// Move-only compact JWT bytes. The original token is wiped on drop and is
/// never serializable or printable through `Debug`.
pub struct SecretCompactJwt {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretCompactJwt {
    /// Takes ownership of one bounded compact JWT.
    pub fn new(bytes: Vec<u8>) -> Result<Self, JwtInputError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(JwtInputError::EmptyToken);
        }
        if bytes.len() > MAX_COMPACT_JWT_BYTES {
            return Err(JwtInputError::TokenTooLarge);
        }
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Redaction-safe compact-token input failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtInputError {
    /// No compact token bytes were supplied.
    #[error("JWT input is empty")]
    EmptyToken,
    /// The compact token exceeded the fixed source ceiling.
    #[error("JWT input exceeds its compiled byte limit")]
    TokenTooLarge,
}

/// One explicitly supplied local ES256 verification key.
///
/// The retained bytes are only the uncompressed public P-256 point. The raw
/// JWK, key identifier, and any source path are not retained or reported.
pub struct Es256LocalPublicKey {
    sec1_public_point: [u8; 65],
    public_key_sha256: String,
}

impl Es256LocalPublicKey {
    /// Parses the strict public-JWK subset accepted by this evaluator.
    ///
    /// Exactly `kty`, `crv`, `alg`, `x`, and `y` are accepted. Private
    /// material and remote or embedded key-selection metadata are rejected.
    /// This intake validates the closed JWK shape and canonical fixed-width
    /// coordinate encodings. Curve membership is deliberately not inferred
    /// from those declarations; the Ring ES256 verifier checks the encoded
    /// point together with the signature and reports one coarse invalid local
    /// verification outcome on either failure.
    pub fn from_jwk_json(bytes: Vec<u8>) -> Result<Self, Es256PublicJwkError> {
        // A purportedly public JWK can still contain an accidentally supplied
        // private `d` member. Own and wipe the entire source on every path,
        // including the empty and oversized rejection paths.
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(Es256PublicJwkError::Malformed);
        }
        if bytes.len() > MAX_LOCAL_PUBLIC_JWK_BYTES {
            return Err(Es256PublicJwkError::TooLarge);
        }

        let document = parse_private_json(bytes.as_slice()).map_err(|failure| match failure {
            JsonFailure::DuplicateKey => Es256PublicJwkError::DuplicateKey,
            JsonFailure::LimitExceeded => Es256PublicJwkError::LimitExceeded,
            JsonFailure::Malformed => Es256PublicJwkError::Malformed,
        })?;
        let object = document.as_object().ok_or(Es256PublicJwkError::Malformed)?;

        for (name, _) in object {
            match name.as_str() {
                "kty" | "crv" | "alg" | "x" | "y" => {},
                "d" => return Err(Es256PublicJwkError::PrivateMaterialProhibited),
                "jku" | "x5u" | "jwk" | "x5c" => {
                    return Err(Es256PublicJwkError::KeyMetadataProhibited)
                },
                _ => return Err(Es256PublicJwkError::UnsupportedMember),
            }
        }
        if object.len() != 5 {
            return Err(Es256PublicJwkError::MissingMember);
        }
        if document.string_member("kty") != Some("EC")
            || document.string_member("crv") != Some("P-256")
            || document.string_member("alg") != Some("ES256")
        {
            return Err(Es256PublicJwkError::UnsupportedKey);
        }

        let x = decode_canonical_coordinate(
            document
                .string_member("x")
                .ok_or(Es256PublicJwkError::InvalidCoordinate)?,
        )?;
        let y = decode_canonical_coordinate(
            document
                .string_member("y")
                .ok_or(Es256PublicJwkError::InvalidCoordinate)?,
        )?;
        let mut sec1_public_point = [0_u8; 65];
        sec1_public_point[0] = 0x04;
        sec1_public_point[1..33].copy_from_slice(&x);
        sec1_public_point[33..].copy_from_slice(&y);
        let public_key_sha256 = sha256_reference(&sec1_public_point);
        Ok(Self {
            sec1_public_point,
            public_key_sha256,
        })
    }

    fn as_sec1_bytes(&self) -> &[u8] {
        &self.sec1_public_point
    }

    fn public_key_sha256(&self) -> &str {
        &self.public_key_sha256
    }
}

fn sha256_reference(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_canonical_coordinate(value: &str) -> Result<[u8; 32], Es256PublicJwkError> {
    if !is_unpadded_base64url(value.as_bytes()) {
        return Err(Es256PublicJwkError::InvalidCoordinate);
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| Es256PublicJwkError::InvalidCoordinate)?,
    );
    let coordinate: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| Es256PublicJwkError::InvalidCoordinate)?;
    if URL_SAFE_NO_PAD.encode(coordinate) != value {
        return Err(Es256PublicJwkError::InvalidCoordinate);
    }
    Ok(coordinate)
}

/// Redaction-safe local public-JWK rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Es256PublicJwkError {
    /// The local JWK exceeded its fixed source ceiling.
    #[error("local ES256 public JWK exceeds its compiled byte limit")]
    TooLarge,
    /// The JWK was not one bounded JSON object.
    #[error("local ES256 public JWK is malformed")]
    Malformed,
    /// A JSON object contained a duplicate key.
    #[error("local ES256 public JWK contains a duplicate JSON key")]
    DuplicateKey,
    /// JSON structural limits were exceeded.
    #[error("local ES256 public JWK exceeds JSON structural limits")]
    LimitExceeded,
    /// One of the five required public members was absent.
    #[error("local ES256 public JWK is missing a required member")]
    MissingMember,
    /// A member outside the closed V1 public subset was supplied.
    #[error("local ES256 public JWK contains an unsupported member")]
    UnsupportedMember,
    /// A private EC scalar was supplied.
    #[error("local ES256 public JWK must not contain private key material")]
    PrivateMaterialProhibited,
    /// Remote or embedded key-selection metadata was supplied.
    #[error("local ES256 public JWK must not contain key-selection metadata")]
    KeyMetadataProhibited,
    /// The declared key type, curve, or algorithm is outside V1.
    #[error("local public JWK is not an ES256 P-256 verification key")]
    UnsupportedKey,
    /// A coordinate was padded, non-canonical, malformed, or not 32 bytes.
    #[error("local ES256 public JWK coordinate is invalid")]
    InvalidCoordinate,
}

/// Non-secret local policy. Expected values are kept private, wiped on drop,
/// and never included in the audit outcome or `Debug` output.
pub struct JwtLocalPolicy {
    operator_policy_reference: String,
    operator_policy_revision: String,
    expected_type: Zeroizing<String>,
    expected_issuer: Zeroizing<String>,
    expected_audience: Zeroizing<String>,
    required_claims: Vec<Zeroizing<String>>,
    require_expiration: bool,
    allowed_clock_skew_seconds: u32,
}

impl JwtLocalPolicy {
    /// Constructs one bounded policy. String comparisons are exact and
    /// case-sensitive; no URI or version normalization is performed.
    pub fn new(
        operator_policy_identity: (&str, &str),
        expected_type: &str,
        expected_issuer: &str,
        expected_audience: &str,
        required_claims: &[&str],
        require_expiration: bool,
        allowed_clock_skew_seconds: u32,
    ) -> Result<Self, JwtPolicyError> {
        let (operator_policy_reference, operator_policy_revision) = operator_policy_identity;
        if !valid_policy_reference(operator_policy_reference) {
            return Err(JwtPolicyError::InvalidPolicyReference);
        }
        if !valid_policy_reference(operator_policy_revision) {
            return Err(JwtPolicyError::InvalidPolicyRevision);
        }
        if allowed_clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
            return Err(JwtPolicyError::ClockSkewTooLarge);
        }
        let expected_type = copy_expected(expected_type, MAX_EXPECTED_TYPE_BYTES)?;
        let expected_issuer = copy_expected(expected_issuer, MAX_EXPECTED_STRING_BYTES)?;
        let expected_audience = copy_expected(expected_audience, MAX_EXPECTED_STRING_BYTES)?;
        if required_claims.len() > MAX_REQUIRED_CLAIMS {
            return Err(JwtPolicyError::TooManyRequiredClaims);
        }
        let mut copied_claims: Vec<Zeroizing<String>> = Vec::with_capacity(required_claims.len());
        for claim in required_claims {
            if !valid_claim_name(claim) {
                return Err(JwtPolicyError::InvalidRequiredClaim);
            }
            if copied_claims.iter().any(|known| known.as_str() == *claim) {
                return Err(JwtPolicyError::DuplicateRequiredClaim);
            }
            copied_claims.push(Zeroizing::new((*claim).to_owned()));
        }
        Ok(Self {
            operator_policy_reference: operator_policy_reference.to_owned(),
            operator_policy_revision: operator_policy_revision.to_owned(),
            expected_type,
            expected_issuer,
            expected_audience,
            required_claims: copied_claims,
            require_expiration,
            allowed_clock_skew_seconds,
        })
    }
}

fn valid_policy_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_POLICY_REFERENCE_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn copy_expected(value: &str, maximum: usize) -> Result<Zeroizing<String>, JwtPolicyError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(JwtPolicyError::InvalidExpectedValue);
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn valid_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLAIM_NAME_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

/// Redaction-safe local policy construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtPolicyError {
    /// The safe non-secret operator policy slug was absent or malformed.
    #[error("JWT operator policy reference is invalid")]
    InvalidPolicyReference,
    /// The safe non-secret operator revision slug was absent or malformed.
    #[error("JWT operator policy revision is invalid")]
    InvalidPolicyRevision,
    /// An expected type, issuer, or audience was empty, too long, or contained controls.
    #[error("JWT policy expected value is invalid")]
    InvalidExpectedValue,
    /// More required claims were supplied than the fixed V1 ceiling.
    #[error("JWT policy has too many required claims")]
    TooManyRequiredClaims,
    /// A required claim name violated the bounded ASCII-name contract.
    #[error("JWT policy required claim name is invalid")]
    InvalidRequiredClaim,
    /// A required claim name was repeated.
    #[error("JWT policy required claim name is duplicated")]
    DuplicateRequiredClaim,
    /// The permitted time skew exceeded the V1 ceiling.
    #[error("JWT policy clock skew exceeds its compiled limit")]
    ClockSkewTooLarge,
}

/// Caller-supplied local evaluation time. It is evidence about this process's
/// clock, not an observed target decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwtEvaluationTime {
    /// Unix time in whole seconds.
    pub unix_seconds: i64,
}

/// Value-free outcome of one bounded local review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtPolicyReviewAudit {
    /// Compact syntax and supported-profile status.
    parsing: JwtParsingStatus,
    /// Local expected-claim and time-policy status.
    policy_status: JwtPolicyStatus,
    /// Signature state against the explicitly supplied local public key.
    local_signature: JwtLocalSignatureStatus,
    /// Target-server acceptance is outside this transport-free evaluator.
    target_acceptance: JwtTargetAcceptanceStatus,
    /// Safe, value-free policy selection and local-clock facts.
    methodology: JwtPolicyMethodology,
    /// Explicit proof that this local evaluator did not perform network work.
    external_activity: JwtExternalActivity,
    /// Bounded value-free reasons for a policy-inconsistent result.
    policy_violations: Vec<JwtPolicyViolation>,
}

/// Value-free local methodology facts needed by strict saved reports and
/// semantic comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtPolicyMethodology {
    /// Bounded non-secret ASCII slug supplied by the operator policy.
    operator_policy_reference: String,
    /// Bounded non-secret revision slug that the operator must change whenever
    /// the private expected-value policy semantics change.
    operator_policy_revision: String,
    /// SHA-256 over the exact uncompressed public P-256 point. This identifies
    /// supplied public key bytes; it is not a signature or source attestation.
    local_public_key_sha256: String,
    /// Whether exact protected-token type comparison was selected.
    expected_type_selected: bool,
    /// Whether exact issuer comparison was selected.
    expected_issuer_selected: bool,
    /// Whether exact audience membership comparison was selected.
    expected_audience_selected: bool,
    /// Number of additionally required claim names; names are not reported.
    required_claim_count: u8,
    /// Whether absence of `exp` is policy-inconsistent.
    require_expiration: bool,
    /// Caller-selected allowance applied to `exp` and `nbf`.
    allowed_clock_skew_seconds: u32,
    /// Caller-supplied local evaluation instant.
    evaluation_time_unix_seconds: i64,
    /// Assurance limitation for the supplied clock value.
    clock_assurance: JwtClockAssurance,
}

/// Assurance attached to the local evaluation clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtClockAssurance {
    /// The process used a caller-supplied local-system time that this module
    /// did not independently validate against an external clock.
    LocalSystemClockNotIndependentlyVerified,
}

/// Network activity facts for the transport-free review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwtExternalActivity {
    /// Target requests made by this evaluator; fixed at zero.
    target_request_count: u8,
    /// Retrieval of `jku`, `x5u`, or any other remote key source.
    remote_key_retrieval: JwtExternalOperationStatus,
    /// Forwarding or replaying the supplied token to a target.
    token_forwarding: JwtExternalOperationStatus,
}

/// Closed status for network operations excluded from this local slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtExternalOperationStatus {
    /// The operation was not performed.
    NotPerformed,
}

/// Compact syntax/profile status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtParsingStatus {
    /// The token is a supported compact ES256 JWS with bounded JSON claims.
    Parsed,
    /// The compact input was malformed or outside the closed local profile.
    Rejected(JwtParseRejection),
}

/// Static reason a compact input was not parsed into the supported profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtParseRejection {
    /// A five-segment JWE compact object is outside this JWS-only profile.
    EncryptedTokenUnsupported,
    /// The compact input did not contain exactly three segments.
    InvalidSegmentCount,
    /// One required compact segment was empty.
    EmptySegment,
    /// Compact segments must use unpadded base64url only.
    InvalidBase64Url,
    /// A decoded header or claims object exceeded its byte ceiling.
    DecodedSegmentTooLarge,
    /// Protected header or claims JSON was malformed or not an object.
    MalformedJson,
    /// Any duplicate JSON object key is rejected, including in nested values.
    DuplicateJsonKey,
    /// JSON depth, nodes, members, arrays, or strings exceeded a bound.
    JsonLimitExceeded,
    /// The protected header omitted or mistyped a required parameter.
    MalformedProtectedHeader,
    /// `alg=none` is never accepted by this policy.
    UnsecuredAlgorithmUnsupported,
    /// Only exact `ES256` is supported by V1.
    AlgorithmUnsupported,
    /// The closed V1 profile does not process any `crit` member.
    CriticalHeaderUnsupported,
    /// The closed V1 profile does not process a `b64` extension member.
    UnencodedPayloadUnsupported,
    /// Compressed JOSE content is outside this profile.
    CompressionUnsupported,
    /// Nested JWT/JWS content is outside this profile.
    NestedTokenUnsupported,
    /// Token-carried remote or embedded key selection is prohibited.
    KeyMetadataUnsupported,
    /// The ES256 signature was not exactly 64 decoded bytes.
    InvalidSignatureLength,
}

/// Local policy relationship, independent of signature and target behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtPolicyStatus {
    /// Parsing failed, so claim policy was not evaluated.
    NotEvaluated,
    /// Every selected local claim and time condition was satisfied.
    Consistent,
    /// One or more selected local conditions was not satisfied.
    Inconsistent,
}

/// Signature relationship to the one explicitly supplied local public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtLocalSignatureStatus {
    /// Parsing failed before a supported signing input was available.
    NotEvaluated,
    /// ES256 verification succeeded against the supplied public key.
    Verified,
    /// Verification failed against the supplied public key.
    Invalid,
}

/// Target behavior state for this transport-free slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtTargetAcceptanceStatus {
    /// No target request or server acceptance check was performed.
    NotPerformed,
}

/// Value-free local policy inconsistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtPolicyViolation {
    /// A protected `typ` value required by policy was absent.
    MissingType,
    /// The protected `typ` value differed from policy.
    TypeMismatch,
    /// A required issuer was absent.
    MissingIssuer,
    /// The issuer claim was not a string.
    InvalidIssuerType,
    /// The issuer differed from policy.
    IssuerMismatch,
    /// A required audience was absent.
    MissingAudience,
    /// Audience was neither a string nor an array of strings.
    InvalidAudienceType,
    /// No declared audience exactly matched policy.
    AudienceMismatch,
    /// One required claim name was absent. The ordinal refers only to the
    /// caller's policy order and does not expose the name or value.
    MissingRequiredClaim { ordinal: u8 },
    /// Expiration was required but absent.
    MissingExpiration,
    /// `exp` was not an integral NumericDate representable as `i64`.
    InvalidExpiration,
    /// The token was expired at the caller-supplied time and skew.
    Expired,
    /// `nbf` was not an integral NumericDate representable as `i64`.
    InvalidNotBefore,
    /// The token was not yet valid at the caller-supplied time and skew.
    NotYetValid,
}

impl JwtPolicyReviewAudit {
    /// Stable audit schema used by the report projection.
    pub const fn schema(&self) -> &'static str {
        JWT_POLICY_REVIEW_AUDIT_SCHEMA
    }

    /// Stable local interpretation policy identifier.
    pub const fn policy(&self) -> &'static str {
        JWT_POLICY_REVIEW_POLICY_ID
    }

    /// An audit value exists only after explicit operator selection.
    pub const fn selected(&self) -> bool {
        true
    }

    /// Compact syntax and supported-profile status.
    pub const fn parsing_status(&self) -> JwtParsingStatus {
        self.parsing
    }

    /// Local expected-claim and time-policy status.
    pub const fn policy_status(&self) -> JwtPolicyStatus {
        self.policy_status
    }

    /// Signature relationship to the explicitly supplied local public key.
    pub const fn local_signature_status(&self) -> JwtLocalSignatureStatus {
        self.local_signature
    }

    /// Target acceptance is deliberately outside this transport-free slice.
    pub const fn target_acceptance_status(&self) -> JwtTargetAcceptanceStatus {
        self.target_acceptance
    }

    /// Value-free policy-selection and local-clock facts.
    pub const fn methodology(&self) -> &JwtPolicyMethodology {
        &self.methodology
    }

    /// Explicit external-activity accounting for this evaluator.
    pub const fn external_activity(&self) -> JwtExternalActivity {
        self.external_activity
    }

    /// Bounded value-free local policy violations.
    pub fn policy_violations(&self) -> &[JwtPolicyViolation] {
        &self.policy_violations
    }

    fn rejected(
        reason: JwtParseRejection,
        key: &Es256LocalPublicKey,
        policy: &JwtLocalPolicy,
        evaluation_time: JwtEvaluationTime,
    ) -> Self {
        Self {
            parsing: JwtParsingStatus::Rejected(reason),
            policy_status: JwtPolicyStatus::NotEvaluated,
            local_signature: JwtLocalSignatureStatus::NotEvaluated,
            target_acceptance: JwtTargetAcceptanceStatus::NotPerformed,
            methodology: methodology(key, policy, evaluation_time),
            external_activity: no_external_activity(),
            policy_violations: Vec::new(),
        }
    }
}

impl JwtPolicyMethodology {
    pub fn operator_policy_reference(&self) -> &str {
        &self.operator_policy_reference
    }

    pub fn operator_policy_revision(&self) -> &str {
        &self.operator_policy_revision
    }

    pub fn local_public_key_sha256(&self) -> &str {
        &self.local_public_key_sha256
    }

    pub const fn expected_type_selected(&self) -> bool {
        self.expected_type_selected
    }

    pub const fn expected_issuer_selected(&self) -> bool {
        self.expected_issuer_selected
    }

    pub const fn expected_audience_selected(&self) -> bool {
        self.expected_audience_selected
    }

    pub const fn required_claim_count(&self) -> u8 {
        self.required_claim_count
    }

    pub const fn require_expiration(&self) -> bool {
        self.require_expiration
    }

    pub const fn allowed_clock_skew_seconds(&self) -> u32 {
        self.allowed_clock_skew_seconds
    }

    pub const fn evaluation_time_unix_seconds(&self) -> i64 {
        self.evaluation_time_unix_seconds
    }

    pub const fn clock_assurance(&self) -> JwtClockAssurance {
        self.clock_assurance
    }
}

impl JwtExternalActivity {
    pub const fn target_request_count(self) -> u8 {
        self.target_request_count
    }

    pub const fn remote_key_retrieval(self) -> JwtExternalOperationStatus {
        self.remote_key_retrieval
    }

    pub const fn token_forwarding(self) -> JwtExternalOperationStatus {
        self.token_forwarding
    }
}

/// Reviews one compact JWS without any network or filesystem activity.
pub fn review_compact_jwt(
    token: &SecretCompactJwt,
    key: &Es256LocalPublicKey,
    policy: &JwtLocalPolicy,
    evaluation_time: JwtEvaluationTime,
) -> JwtPolicyReviewAudit {
    match review_parsed(token, key, policy, evaluation_time) {
        Ok((local_signature, policy_violations)) => JwtPolicyReviewAudit {
            parsing: JwtParsingStatus::Parsed,
            policy_status: if policy_violations.is_empty() {
                JwtPolicyStatus::Consistent
            } else {
                JwtPolicyStatus::Inconsistent
            },
            local_signature,
            target_acceptance: JwtTargetAcceptanceStatus::NotPerformed,
            methodology: methodology(key, policy, evaluation_time),
            external_activity: no_external_activity(),
            policy_violations,
        },
        Err(reason) => JwtPolicyReviewAudit::rejected(reason, key, policy, evaluation_time),
    }
}

fn methodology(
    key: &Es256LocalPublicKey,
    policy: &JwtLocalPolicy,
    evaluation_time: JwtEvaluationTime,
) -> JwtPolicyMethodology {
    JwtPolicyMethodology {
        operator_policy_reference: policy.operator_policy_reference.clone(),
        operator_policy_revision: policy.operator_policy_revision.clone(),
        local_public_key_sha256: key.public_key_sha256().to_owned(),
        expected_type_selected: true,
        expected_issuer_selected: true,
        expected_audience_selected: true,
        required_claim_count: u8::try_from(policy.required_claims.len())
            .expect("required-claim ceiling fits u8"),
        require_expiration: policy.require_expiration,
        allowed_clock_skew_seconds: policy.allowed_clock_skew_seconds,
        evaluation_time_unix_seconds: evaluation_time.unix_seconds,
        clock_assurance: JwtClockAssurance::LocalSystemClockNotIndependentlyVerified,
    }
}

const fn no_external_activity() -> JwtExternalActivity {
    JwtExternalActivity {
        target_request_count: 0,
        remote_key_retrieval: JwtExternalOperationStatus::NotPerformed,
        token_forwarding: JwtExternalOperationStatus::NotPerformed,
    }
}

fn review_parsed(
    token: &SecretCompactJwt,
    key: &Es256LocalPublicKey,
    policy: &JwtLocalPolicy,
    evaluation_time: JwtEvaluationTime,
) -> Result<(JwtLocalSignatureStatus, Vec<JwtPolicyViolation>), JwtParseRejection> {
    let bytes = token.as_bytes();
    let segments: Vec<&[u8]> = bytes.split(|byte| *byte == b'.').collect();
    if segments.len() == 5 {
        return Err(JwtParseRejection::EncryptedTokenUnsupported);
    }
    if segments.len() != 3 {
        return Err(JwtParseRejection::InvalidSegmentCount);
    }
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(JwtParseRejection::EmptySegment);
    }
    if segments
        .iter()
        .any(|segment| !is_unpadded_base64url(segment))
    {
        return Err(JwtParseRejection::InvalidBase64Url);
    }

    let header_bytes = decode_segment(segments[0], MAX_JWT_HEADER_BYTES)?;
    let claims_bytes = decode_segment(segments[1], MAX_JWT_CLAIMS_BYTES)?;
    let signature = decode_segment(segments[2], ES256_SIGNATURE_BYTES)?;
    if signature.len() != ES256_SIGNATURE_BYTES {
        return Err(JwtParseRejection::InvalidSignatureLength);
    }

    let header = parse_private_json(header_bytes.as_slice()).map_err(map_json_failure)?;
    let claims = parse_private_json(claims_bytes.as_slice()).map_err(map_json_failure)?;
    if header.as_object().is_none() || claims.as_object().is_none() {
        return Err(JwtParseRejection::MalformedJson);
    }
    validate_protected_header(&header)?;

    let signing_input_length = segments[0]
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(segments[1].len()))
        .ok_or(JwtParseRejection::InvalidSegmentCount)?;
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.as_sec1_bytes());
    let local_signature = if verifier
        .verify(&bytes[..signing_input_length], signature.as_slice())
        .is_ok()
    {
        JwtLocalSignatureStatus::Verified
    } else {
        JwtLocalSignatureStatus::Invalid
    };
    let violations = evaluate_policy(&header, &claims, policy, evaluation_time);
    Ok((local_signature, violations))
}

fn is_unpadded_base64url(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_segment(segment: &[u8], maximum: usize) -> Result<Zeroizing<Vec<u8>>, JwtParseRejection> {
    // `decode_vec` writes into an already guarded owner, so malformed or
    // non-canonical input cannot drop a partially decoded secret allocation
    // outside `Zeroizing` on the error path.
    let mut decoded = Zeroizing::new(Vec::new());
    URL_SAFE_NO_PAD
        .decode_vec(segment, &mut decoded)
        .map_err(|_| JwtParseRejection::InvalidBase64Url)?;
    if decoded.len() > maximum {
        return Err(JwtParseRejection::DecodedSegmentTooLarge);
    }
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if canonical.as_bytes() != segment {
        return Err(JwtParseRejection::InvalidBase64Url);
    }
    Ok(decoded)
}

fn map_json_failure(failure: JsonFailure) -> JwtParseRejection {
    match failure {
        JsonFailure::Malformed => JwtParseRejection::MalformedJson,
        JsonFailure::DuplicateKey => JwtParseRejection::DuplicateJsonKey,
        JsonFailure::LimitExceeded => JwtParseRejection::JsonLimitExceeded,
    }
}

fn validate_protected_header(header: &PrivateJsonValue) -> Result<(), JwtParseRejection> {
    match header.string_member("alg") {
        Some("ES256") => {},
        Some("none") => return Err(JwtParseRejection::UnsecuredAlgorithmUnsupported),
        Some(_) => return Err(JwtParseRejection::AlgorithmUnsupported),
        None => return Err(JwtParseRejection::MalformedProtectedHeader),
    }
    if header.object_member("enc").is_some() {
        return Err(JwtParseRejection::EncryptedTokenUnsupported);
    }
    if header.object_member("zip").is_some() {
        return Err(JwtParseRejection::CompressionUnsupported);
    }
    if ["jku", "x5u", "jwk", "x5c"]
        .iter()
        .any(|name| header.object_member(name).is_some())
    {
        return Err(JwtParseRejection::KeyMetadataUnsupported);
    }
    if let Some(content_type) = header.object_member("cty") {
        let content_type = content_type
            .as_str()
            .ok_or(JwtParseRejection::MalformedProtectedHeader)?;
        if content_type.eq_ignore_ascii_case("jwt")
            || content_type.eq_ignore_ascii_case("application/jwt")
        {
            return Err(JwtParseRejection::NestedTokenUnsupported);
        }
    }
    if header.object_member("b64").is_some() {
        return Err(JwtParseRejection::UnencodedPayloadUnsupported);
    }
    if header.object_member("crit").is_some() {
        return Err(JwtParseRejection::CriticalHeaderUnsupported);
    }
    if let Some(token_type) = header.object_member("typ") {
        if token_type.as_str().is_none() {
            return Err(JwtParseRejection::MalformedProtectedHeader);
        }
    }
    Ok(())
}

fn evaluate_policy(
    header: &PrivateJsonValue,
    claims: &PrivateJsonValue,
    policy: &JwtLocalPolicy,
    evaluation_time: JwtEvaluationTime,
) -> Vec<JwtPolicyViolation> {
    let mut violations = Vec::new();
    match header.string_member("typ") {
        None => violations.push(JwtPolicyViolation::MissingType),
        Some(actual) if actual != policy.expected_type.as_str() => {
            violations.push(JwtPolicyViolation::TypeMismatch)
        },
        Some(_) => {},
    }
    match claims.object_member("iss") {
        None => violations.push(JwtPolicyViolation::MissingIssuer),
        Some(PrivateJsonValue::String(actual))
            if actual.as_str() == policy.expected_issuer.as_str() => {},
        Some(PrivateJsonValue::String(_)) => violations.push(JwtPolicyViolation::IssuerMismatch),
        Some(_) => violations.push(JwtPolicyViolation::InvalidIssuerType),
    }
    match claims.object_member("aud") {
        None => violations.push(JwtPolicyViolation::MissingAudience),
        Some(PrivateJsonValue::String(actual))
            if actual.as_str() == policy.expected_audience.as_str() => {},
        Some(PrivateJsonValue::String(_)) => {
            violations.push(JwtPolicyViolation::AudienceMismatch)
        }
        Some(PrivateJsonValue::Array(values)) => {
            if values.iter().any(|value| {
                matches!(value, PrivateJsonValue::String(actual) if actual.as_str() == policy.expected_audience.as_str())
            }) {
                if values
                    .iter()
                    .any(|value| !matches!(value, PrivateJsonValue::String(_)))
                {
                    violations.push(JwtPolicyViolation::InvalidAudienceType);
                }
            } else if values
                .iter()
                .any(|value| !matches!(value, PrivateJsonValue::String(_)))
            {
                violations.push(JwtPolicyViolation::InvalidAudienceType);
            } else {
                violations.push(JwtPolicyViolation::AudienceMismatch);
            }
        }
        Some(_) => violations.push(JwtPolicyViolation::InvalidAudienceType),
    }
    for (ordinal, required) in policy.required_claims.iter().enumerate() {
        if claims.object_member(required.as_str()).is_none() {
            violations.push(JwtPolicyViolation::MissingRequiredClaim {
                ordinal: u8::try_from(ordinal).expect("required-claim ceiling fits u8"),
            });
        }
    }

    match claims.object_member("exp") {
        None if policy.require_expiration => violations.push(JwtPolicyViolation::MissingExpiration),
        None => {},
        Some(value) => match value.numeric_date() {
            Some(expiration)
                if evaluation_time.unix_seconds
                    >= expiration.saturating_add(i64::from(policy.allowed_clock_skew_seconds)) =>
            {
                violations.push(JwtPolicyViolation::Expired);
            },
            Some(_) => {},
            None => violations.push(JwtPolicyViolation::InvalidExpiration),
        },
    }
    if let Some(value) = claims.object_member("nbf") {
        match value.numeric_date() {
            Some(not_before)
                if evaluation_time
                    .unix_seconds
                    .saturating_add(i64::from(policy.allowed_clock_skew_seconds))
                    < not_before =>
            {
                violations.push(JwtPolicyViolation::NotYetValid);
            },
            Some(_) => {},
            None => violations.push(JwtPolicyViolation::InvalidNotBefore),
        }
    }
    violations
}

enum PrivateJsonValue {
    Null,
    Bool,
    I64(i64),
    U64(u64),
    F64,
    String(Zeroizing<String>),
    Array(Vec<Self>),
    Object(Vec<(Zeroizing<String>, Self)>),
}

impl PrivateJsonValue {
    fn as_object(&self) -> Option<&[(Zeroizing<String>, Self)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    fn object_member(&self, name: &str) -> Option<&Self> {
        self.as_object()?.iter().find_map(|(key, value)| {
            if key.as_str() == name {
                Some(value)
            } else {
                None
            }
        })
    }

    fn string_member(&self, name: &str) -> Option<&str> {
        self.object_member(name)?.as_str()
    }

    fn numeric_date(&self) -> Option<i64> {
        match self {
            Self::I64(value) => Some(*value),
            Self::U64(value) => i64::try_from(*value).ok(),
            _ => None,
        }
    }
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
    members: usize,
}

impl JsonBudget {
    fn enter<E: serde::de::Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > MAX_JSON_DEPTH || self.nodes >= MAX_JSON_NODES {
            return Err(E::custom(JSON_LIMIT_SENTINEL));
        }
        self.nodes += 1;
        Ok(())
    }

    fn member<E: serde::de::Error>(&mut self) -> Result<(), E> {
        if self.members >= MAX_JSON_MEMBERS {
            return Err(E::custom(JSON_LIMIT_SENTINEL));
        }
        self.members += 1;
        Ok(())
    }
}

struct PrivateJsonSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for PrivateJsonSeed<'_> {
    type Value = PrivateJsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.budget.enter::<D::Error>(self.depth)?;
        deserializer.deserialize_any(PrivateJsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct PrivateJsonVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for PrivateJsonVisitor<'_> {
    type Value = PrivateJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(PrivateJsonValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(PrivateJsonValue::Null)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(PrivateJsonValue::Bool)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(PrivateJsonValue::I64(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(PrivateJsonValue::U64(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(PrivateJsonValue::F64)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom(JSON_LIMIT_SENTINEL));
        }
        Ok(PrivateJsonValue::String(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let value = Zeroizing::new(value);
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom(JSON_LIMIT_SENTINEL));
        }
        Ok(PrivateJsonValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(PrivateJsonSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if values.len() >= MAX_JSON_ARRAY_ITEMS {
                return Err(A::Error::custom(JSON_LIMIT_SENTINEL));
            }
            values.push(value);
        }
        Ok(PrivateJsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries: Vec<(Zeroizing<String>, PrivateJsonValue)> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            if key.len() > MAX_JSON_STRING_BYTES {
                return Err(A::Error::custom(JSON_LIMIT_SENTINEL));
            }
            if entries
                .iter()
                .any(|(known, _)| known.as_str() == key.as_str())
            {
                return Err(A::Error::custom(JSON_DUPLICATE_SENTINEL));
            }
            self.budget.member::<A::Error>()?;
            let value = map.next_value_seed(PrivateJsonSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            entries.push((key, value));
        }
        Ok(PrivateJsonValue::Object(entries))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonFailure {
    Malformed,
    DuplicateKey,
    LimitExceeded,
}

fn parse_private_json(bytes: &[u8]) -> Result<PrivateJsonValue, JsonFailure> {
    let mut budget = JsonBudget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = PrivateJsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(parsed)
}

fn classify_json_error(error: serde_json::Error) -> JsonFailure {
    let message = error.to_string();
    if message.contains(JSON_DUPLICATE_SENTINEL) {
        JsonFailure::DuplicateKey
    } else if message.contains(JSON_LIMIT_SENTINEL) {
        JsonFailure::LimitExceeded
    } else {
        JsonFailure::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC7515_PUBLIC_JWK: &[u8] = br#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    const RFC7515_ES256_JWS: &str = concat!(
        "eyJhbGciOiJFUzI1NiJ9.",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.",
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
        "pmWQxfKTUJqPP3-Kg6NU1Q"
    );

    fn key() -> Es256LocalPublicKey {
        Es256LocalPublicKey::from_jwk_json(RFC7515_PUBLIC_JWK.to_vec()).expect("RFC public key")
    }

    fn rfc_policy() -> JwtLocalPolicy {
        JwtLocalPolicy::new(
            ("rfc7515-example", "rfc7515-example-v1"),
            "JWT",
            "joe",
            "termivar-fixture",
            &["http://example.com/is_root"],
            true,
            0,
        )
        .expect("policy")
    }

    fn review_literal(token: &str, policy: &JwtLocalPolicy, now: i64) -> JwtPolicyReviewAudit {
        let token = SecretCompactJwt::new(token.as_bytes().to_vec()).expect("bounded token");
        review_compact_jwt(
            &token,
            &key(),
            policy,
            JwtEvaluationTime { unix_seconds: now },
        )
    }

    fn unsigned_test_token(header: &str, claims: &str) -> String {
        let signature = [0_u8; ES256_SIGNATURE_BYTES];
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.as_bytes()),
            URL_SAFE_NO_PAD.encode(claims.as_bytes()),
            URL_SAFE_NO_PAD.encode(signature)
        )
    }

    #[test]
    fn rfc7515_es256_vector_separates_all_four_states() {
        let audit = review_literal(RFC7515_ES256_JWS, &rfc_policy(), 1_300_819_300);
        assert_eq!(audit.parsing, JwtParsingStatus::Parsed);
        assert_eq!(audit.policy_status, JwtPolicyStatus::Inconsistent);
        assert_eq!(audit.local_signature, JwtLocalSignatureStatus::Verified);
        assert_eq!(
            audit.target_acceptance,
            JwtTargetAcceptanceStatus::NotPerformed
        );
        assert_eq!(
            audit.methodology,
            JwtPolicyMethodology {
                operator_policy_reference: "rfc7515-example".to_owned(),
                operator_policy_revision: "rfc7515-example-v1".to_owned(),
                local_public_key_sha256:
                    "sha256:dcd2446ca98830c843c493a672364ba971d674fbef5ce87d697165b31e90300a"
                        .to_owned(),
                expected_type_selected: true,
                expected_issuer_selected: true,
                expected_audience_selected: true,
                required_claim_count: 1,
                require_expiration: true,
                allowed_clock_skew_seconds: 0,
                evaluation_time_unix_seconds: 1_300_819_300,
                clock_assurance: JwtClockAssurance::LocalSystemClockNotIndependentlyVerified,
            }
        );
        assert_eq!(audit.external_activity, no_external_activity());
        assert_eq!(
            audit.methodology.local_public_key_sha256,
            "sha256:dcd2446ca98830c843c493a672364ba971d674fbef5ce87d697165b31e90300a"
        );
        assert_eq!(
            audit.policy_violations,
            vec![
                JwtPolicyViolation::MissingType,
                JwtPolicyViolation::MissingAudience,
            ]
        );
    }

    #[test]
    fn wrong_public_key_does_not_change_parsing_or_policy() {
        let wrong_jwk = br#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEQ","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        let wrong_key =
            Es256LocalPublicKey::from_jwk_json(wrong_jwk.to_vec()).expect("bounded public JWK");
        let token = SecretCompactJwt::new(RFC7515_ES256_JWS.as_bytes().to_vec()).expect("token");
        let audit = review_compact_jwt(
            &token,
            &wrong_key,
            &rfc_policy(),
            JwtEvaluationTime {
                unix_seconds: 1_300_819_300,
            },
        );
        assert_eq!(audit.parsing, JwtParsingStatus::Parsed);
        assert_eq!(audit.policy_status, JwtPolicyStatus::Inconsistent);
        assert_eq!(audit.local_signature, JwtLocalSignatureStatus::Invalid);
    }

    #[test]
    fn malformed_duplicate_and_wrong_compact_shapes_are_rejected() {
        let policy = rfc_policy();
        let malformed = unsigned_test_token("not-json", r#"{"iss":"joe"}"#);
        assert_eq!(
            review_literal(&malformed, &policy, 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::MalformedJson)
        );
        let duplicate_header = unsigned_test_token(
            r#"{"alg":"ES256","alg":"ES256"}"#,
            r#"{"iss":"joe","exp":2000000000,"http://example.com/is_root":true}"#,
        );
        assert_eq!(
            review_literal(&duplicate_header, &policy, 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::DuplicateJsonKey)
        );
        let duplicate_claim = unsigned_test_token(
            r#"{"alg":"ES256"}"#,
            r#"{"iss":"joe","iss":"joe","exp":2000000000}"#,
        );
        assert_eq!(
            review_literal(&duplicate_claim, &policy, 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::DuplicateJsonKey)
        );
        assert_eq!(
            review_literal("a.b.c.d.e", &policy, 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::EncryptedTokenUnsupported)
        );
        assert_eq!(
            review_literal("a.b", &policy, 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::InvalidSegmentCount)
        );
    }

    #[test]
    fn issuer_audience_and_type_checks_use_exact_values() {
        let token = unsigned_test_token(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"iss":"issuer-b","aud":["api-b","api-c"],"exp":2000000000,"scope":"read"}"#,
        );
        let policy = JwtLocalPolicy::new(
            ("exact-claim-policy", "exact-claim-policy-v1"),
            "at+jwt",
            "issuer-a",
            "api-a",
            &["scope", "tenant"],
            true,
            0,
        )
        .expect("policy");
        let audit = review_literal(&token, &policy, 1_900_000_000);
        assert_eq!(audit.parsing, JwtParsingStatus::Parsed);
        assert_eq!(audit.policy_status, JwtPolicyStatus::Inconsistent);
        assert_eq!(audit.local_signature, JwtLocalSignatureStatus::Invalid);
        assert_eq!(
            audit.policy_violations,
            vec![
                JwtPolicyViolation::TypeMismatch,
                JwtPolicyViolation::IssuerMismatch,
                JwtPolicyViolation::AudienceMismatch,
                JwtPolicyViolation::MissingRequiredClaim { ordinal: 1 },
            ]
        );
    }

    #[test]
    fn expiration_not_before_and_skew_are_integral_and_bounded() {
        let token = unsigned_test_token(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"iss":"issuer","aud":"audience","exp":100,"nbf":110}"#,
        );
        let no_skew = JwtLocalPolicy::new(
            ("no-skew", "no-skew-v1"),
            "JWT",
            "issuer",
            "audience",
            &[],
            true,
            0,
        )
        .expect("policy");
        assert_eq!(
            review_literal(&token, &no_skew, 100).policy_violations,
            vec![JwtPolicyViolation::Expired, JwtPolicyViolation::NotYetValid]
        );
        let with_skew = JwtLocalPolicy::new(
            ("with-skew", "with-skew-v1"),
            "JWT",
            "issuer",
            "audience",
            &[],
            true,
            11,
        )
        .expect("policy");
        assert_eq!(
            review_literal(&token, &with_skew, 100).policy_status,
            JwtPolicyStatus::Consistent
        );
        let invalid = unsigned_test_token(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"iss":"issuer","aud":"audience","exp":100.5,"nbf":true}"#,
        );
        assert_eq!(
            review_literal(&invalid, &no_skew, 0).policy_violations,
            vec![
                JwtPolicyViolation::InvalidExpiration,
                JwtPolicyViolation::InvalidNotBefore,
            ]
        );
    }

    #[test]
    fn unsupported_jose_forms_are_rejected_without_key_authority() {
        let cases = [
            (
                r#"{"alg":"none"}"#,
                JwtParseRejection::UnsecuredAlgorithmUnsupported,
            ),
            (
                r#"{"alg":"HS256"}"#,
                JwtParseRejection::AlgorithmUnsupported,
            ),
            (
                r#"{"alg":"ES256","crit":["unknown"]}"#,
                JwtParseRejection::CriticalHeaderUnsupported,
            ),
            (
                r#"{"alg":"ES256","b64":false,"crit":["b64"]}"#,
                JwtParseRejection::UnencodedPayloadUnsupported,
            ),
            (
                r#"{"alg":"ES256","b64":true}"#,
                JwtParseRejection::UnencodedPayloadUnsupported,
            ),
            (
                r#"{"alg":"ES256","zip":"DEF"}"#,
                JwtParseRejection::CompressionUnsupported,
            ),
            (
                r#"{"alg":"ES256","cty":"JWT"}"#,
                JwtParseRejection::NestedTokenUnsupported,
            ),
            (
                r#"{"alg":"ES256","jku":"https://keys.invalid/jwks"}"#,
                JwtParseRejection::KeyMetadataUnsupported,
            ),
            (
                r#"{"alg":"ES256","x5u":"https://keys.invalid/cert"}"#,
                JwtParseRejection::KeyMetadataUnsupported,
            ),
            (
                r#"{"alg":"ES256","jwk":{"kty":"EC"}}"#,
                JwtParseRejection::KeyMetadataUnsupported,
            ),
            (
                r#"{"alg":"ES256","x5c":[]}"#,
                JwtParseRejection::KeyMetadataUnsupported,
            ),
        ];
        for (header, expected) in cases {
            let token = unsigned_test_token(header, r#"{}"#);
            assert_eq!(
                review_literal(&token, &rfc_policy(), 0).parsing,
                JwtParsingStatus::Rejected(expected)
            );
        }
    }

    #[test]
    fn token_key_id_is_inert_under_the_single_explicit_local_key_policy() {
        let without_key_id = unsigned_test_token(r#"{"alg":"ES256"}"#, r#"{}"#);
        let with_hostile_key_id = unsigned_test_token(
            r#"{"alg":"ES256","kid":"../../untrusted-key?source=remote"}"#,
            r#"{}"#,
        );
        let baseline = review_literal(&without_key_id, &rfc_policy(), 0);
        let key_id = review_literal(&with_hostile_key_id, &rfc_policy(), 0);
        assert_eq!(baseline.parsing, JwtParsingStatus::Parsed);
        assert_eq!(key_id.parsing, JwtParsingStatus::Parsed);
        assert_eq!(key_id.policy_status, baseline.policy_status);
        assert_eq!(key_id.local_signature, baseline.local_signature);
        assert_eq!(key_id.external_activity, no_external_activity());
        assert_eq!(
            key_id.target_acceptance,
            JwtTargetAcceptanceStatus::NotPerformed
        );
    }

    #[test]
    fn local_jwk_is_a_strict_public_es256_subset() {
        let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        for (document, expected) in [
            (
                format!(r#"{{"kty":"RSA","crv":"P-256","alg":"ES256","x":"{x}","y":"{y}"}}"#),
                Es256PublicJwkError::UnsupportedKey,
            ),
            (
                format!(r#"{{"kty":"EC","crv":"P-384","alg":"ES256","x":"{x}","y":"{y}"}}"#),
                Es256PublicJwkError::UnsupportedKey,
            ),
            (
                format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#),
                Es256PublicJwkError::MissingMember,
            ),
            (
                format!(
                    r#"{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{x}","x":"{x}","y":"{y}"}}"#
                ),
                Es256PublicJwkError::DuplicateKey,
            ),
            (
                format!(
                    r#"{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{x}","y":"{y}","kid":"ignored-nowhere"}}"#
                ),
                Es256PublicJwkError::UnsupportedMember,
            ),
        ] {
            assert_eq!(
                Es256LocalPublicKey::from_jwk_json(document.into_bytes()).err(),
                Some(expected)
            );
        }
        assert_eq!(
            Es256LocalPublicKey::from_jwk_json(
                br#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"private"}"#.to_vec()
            )
            .err(),
            Some(Es256PublicJwkError::PrivateMaterialProhibited)
        );
        assert_eq!(
            Es256LocalPublicKey::from_jwk_json(
                br#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","jku":"https://invalid"}"#.to_vec()
            )
            .err(),
            Some(Es256PublicJwkError::KeyMetadataProhibited)
        );
        assert_eq!(
            Es256LocalPublicKey::from_jwk_json(
                br#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU=","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#.to_vec()
            )
            .err(),
            Some(Es256PublicJwkError::InvalidCoordinate)
        );
    }

    #[test]
    fn canonical_coordinates_do_not_claim_curve_membership_before_verification() {
        let zero = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        let document =
            format!(r#"{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{zero}","y":"{zero}"}}"#);
        let structurally_bounded = Es256LocalPublicKey::from_jwk_json(document.into_bytes())
            .expect("closed JWK shape and canonical coordinates");
        let token = SecretCompactJwt::new(RFC7515_ES256_JWS.as_bytes().to_vec()).expect("token");
        let audit = review_compact_jwt(
            &token,
            &structurally_bounded,
            &rfc_policy(),
            JwtEvaluationTime {
                unix_seconds: 1_300_819_300,
            },
        );
        assert_eq!(audit.parsing, JwtParsingStatus::Parsed);
        assert_eq!(audit.policy_status, JwtPolicyStatus::Inconsistent);
        assert_eq!(audit.local_signature, JwtLocalSignatureStatus::Invalid);
        assert_eq!(audit.external_activity, no_external_activity());
    }

    #[test]
    fn oversize_and_structural_limits_fail_closed() {
        assert_eq!(
            SecretCompactJwt::new(vec![b'a'; MAX_COMPACT_JWT_BYTES + 1]).err(),
            Some(JwtInputError::TokenTooLarge)
        );
        let deep_claims = r#"{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}"#;
        let token = unsigned_test_token(r#"{"alg":"ES256"}"#, deep_claims);
        assert_eq!(
            review_literal(&token, &rfc_policy(), 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::JsonLimitExceeded)
        );
    }

    #[test]
    fn policy_reference_and_compact_base64url_are_canonical() {
        assert_eq!(
            JwtLocalPolicy::new(
                ("Uppercase", "uppercase-v1"),
                "JWT",
                "issuer",
                "audience",
                &[],
                false,
                0,
            )
            .err(),
            Some(JwtPolicyError::InvalidPolicyReference)
        );
        assert_eq!(
            JwtLocalPolicy::new(
                ("valid-policy", "Invalid Revision"),
                "JWT",
                "issuer",
                "audience",
                &[],
                false,
                0,
            )
            .err(),
            Some(JwtPolicyError::InvalidPolicyRevision)
        );
        for (expected_type, expected_issuer, expected_audience) in [
            ("", "issuer", "audience"),
            ("JWT", "", "audience"),
            ("JWT", "issuer", ""),
        ] {
            assert_eq!(
                JwtLocalPolicy::new(
                    ("required-bindings", "required-bindings-v1"),
                    expected_type,
                    expected_issuer,
                    expected_audience,
                    &[],
                    true,
                    0,
                )
                .err(),
                Some(JwtPolicyError::InvalidExpectedValue)
            );
        }
        let mut token = unsigned_test_token(r#"{"alg":"ES256"}"#, r#"{}"#);
        let final_character = token.pop().expect("signature segment");
        assert_eq!(final_character, 'A');
        token.push('B');
        assert_eq!(
            review_literal(&token, &rfc_policy(), 0).parsing,
            JwtParsingStatus::Rejected(JwtParseRejection::InvalidBase64Url)
        );
    }

    #[test]
    fn audit_and_errors_never_retain_token_key_or_claim_canaries() {
        const CANARY: &str = "TERMIVAR-JWT-SECRET-CANARY-7d21";
        let token = unsigned_test_token(
            r#"{"alg":"ES256","typ":"wrong"}"#,
            &format!(r#"{{"iss":"{CANARY}","exp":0}}"#),
        );
        let policy = JwtLocalPolicy::new(
            ("canary-redaction", "canary-redaction-v1"),
            CANARY,
            "expected-issuer",
            "expected-audience",
            &[],
            true,
            0,
        )
        .expect("policy");
        let audit = review_literal(&token, &policy, 1);
        // The authoritative audit is intentionally not serializable. Public
        // report bytes are produced only by the bounded reporting projection;
        // this core check locks the remaining diagnostic surface.
        let encoded = format!("{audit:?}");
        assert!(!encoded.contains(CANARY));
        assert!(!encoded.contains("expected-issuer"));
        assert!(!encoded.contains(&token));
        assert_eq!(
            audit.target_acceptance,
            JwtTargetAcceptanceStatus::NotPerformed
        );
    }
}
