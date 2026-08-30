//! Capability-bound executor request and trait contracts.

use super::{
    async_trait, DecisionActionOrigin, DecisionExecutorError, Deserialize, Evidence, KnowledgeBase,
    KnowledgeSnapshot, PayloadStrategyRef, Serialize, VerificationCase,
};

/// Verification stage whose evidence an executor must collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionExecutionStage {
    /// Evidence collected by the action selected by planning or adaptation.
    Passive,
    /// Fresh evidence collected by an explicit verification probe.
    Active,
}

impl std::fmt::Display for DecisionExecutionStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Passive => "passive",
            Self::Active => "active",
        })
    }
}

/// Host-owned resource allowance attached to one isolated execution.
///
/// Executors may impose stricter policy limits. The allowance can only reduce
/// resource use; it never expands an executor's own security policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionExecutionLimits {
    max_response_body_bytes: Option<u64>,
}

impl DecisionExecutionLimits {
    /// Creates an unrestricted per-execution allowance.
    pub const fn new() -> Self {
        Self {
            max_response_body_bytes: None,
        }
    }

    /// Restricts the response body buffered by this execution.
    pub const fn with_max_response_body_bytes(mut self, limit: u64) -> Self {
        self.max_response_body_bytes = Some(limit);
        self
    }

    /// Returns the optional host-owned response buffer allowance.
    pub const fn max_response_body_bytes(self) -> Option<u64> {
        self.max_response_body_bytes
    }

    fn is_unrestricted(&self) -> bool {
        self.max_response_body_bytes.is_none()
    }
}

/// Immutable, transport-neutral request passed to one action executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionExecutionRequest {
    case: VerificationCase,
    stage: DecisionExecutionStage,
    origin: Option<DecisionActionOrigin>,
    delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "DecisionExecutionLimits::is_unrestricted")]
    limits: DecisionExecutionLimits,
}

impl DecisionExecutionRequest {
    pub(super) fn new(
        case: VerificationCase,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        delay_ms: Option<u64>,
        limits: DecisionExecutionLimits,
    ) -> Self {
        Self {
            case,
            stage,
            origin,
            delay_ms,
            limits,
        }
    }

    /// Returns the verification identity attached by the decision loop.
    pub fn case(&self) -> &VerificationCase {
        &self.case
    }

    /// Returns whether passive or active evidence is requested.
    pub fn stage(&self) -> DecisionExecutionStage {
        self.stage
    }

    /// Returns the source of a passive action request.
    pub fn origin(&self) -> Option<DecisionActionOrigin> {
        self.origin
    }

    /// Returns the scheduler delay already honored by the adapter.
    pub fn delay_ms(&self) -> Option<u64> {
        self.delay_ms
    }

    /// Returns host-owned resource allowances for this execution.
    pub const fn limits(&self) -> DecisionExecutionLimits {
        self.limits
    }

    /// Returns the exact planner-selected strategy revision, when present.
    pub const fn payload_strategy(&self) -> Option<&PayloadStrategyRef> {
        self.case.payload_strategy()
    }
}

/// How a semantic action is executed: by touching the network, or purely from
/// already-committed immutable knowledge.
///
/// The runtime uses this to decide whether transport accounting and HTTP
/// response telemetry apply. It is declared explicitly by each executor and is
/// never inferred from executor IDs, action names, request methods, or whether a
/// broker happened to dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionExecutionClass {
    /// The executor performs transport I/O (an HTTP probe) to observe evidence.
    TransportBound,
    /// The executor performs no transport I/O and derives evidence solely from
    /// an immutable, subject-scoped knowledge snapshot.
    LocalKnowledge,
}

/// Narrow execution API implemented by native collectors and plugin bridges.
///
/// The contract for what an executor may read is deliberately minimal:
///
/// - A [`DecisionExecutionClass::TransportBound`] executor (the default) runs
///   through [`execute`](Self::execute) and receives **no** reasoning state — no
///   `KnowledgeBase`, no snapshot, no decision policy.
/// - A [`DecisionExecutionClass::LocalKnowledge`] executor runs through
///   [`execute_with_snapshot`](Self::execute_with_snapshot) and may read **only**
///   an immutable, subject-scoped [`KnowledgeSnapshot`]. It never receives a
///   mutable `KnowledgeBase`: the runner remains the sole authority that
///   validates provenance and atomically commits any derived evidence.
#[async_trait]
pub trait DecisionActionExecutor: Send + Sync {
    /// Returns the stable identity used by planner executor fields and routes.
    fn id(&self) -> &str;

    /// Returns how this executor is driven. Defaults to
    /// [`DecisionExecutionClass::TransportBound`] so existing executors keep
    /// their current transport-accounted execution path unchanged.
    fn execution_class(&self) -> DecisionExecutionClass {
        DecisionExecutionClass::TransportBound
    }

    /// Returns whether this executor can materialize an exact strategy revision.
    ///
    /// The fail-closed default prevents a legacy executor from silently
    /// ignoring planner-selected strategy semantics.
    fn supports_payload_strategy(&self, _strategy: &PayloadStrategyRef) -> bool {
        false
    }

    /// Executes one semantic action request and returns immutable observations only.
    ///
    /// Every returned observation must describe `request.case().subject()`,
    /// identify this executor as its source component, and carry the case ID as
    /// its source correlation ID. The adapter rejects the complete batch when
    /// any observation violates that contract.
    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError>;

    /// Executes a [`DecisionExecutionClass::LocalKnowledge`] action from an
    /// immutable subject-scoped snapshot, returning immutable observations under
    /// the same provenance contract as [`execute`](Self::execute).
    ///
    /// This is additive: transport-bound executors never receive this call, so
    /// they need not implement it. It is deliberately **fail-closed** — the
    /// default returns a deterministic error rather than delegating to
    /// [`execute`](Self::execute). An executor that declares
    /// [`DecisionExecutionClass::LocalKnowledge`] but forgets to override this
    /// method therefore cannot silently run transport work while the runtime has
    /// already skipped request preflight, response accounting, and HTTP
    /// telemetry validation for it.
    async fn execute_with_snapshot(
        &self,
        request: &DecisionExecutionRequest,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let _ = (request, snapshot);
        Err(DecisionExecutorError::new(
            "local-knowledge executor did not implement snapshot execution",
        ))
    }
}
