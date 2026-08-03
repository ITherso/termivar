//! Composable scanning contracts and execution behavior for Venom.
//!
//! The crate exposes two extension surfaces:
//!
//! - [`ScannerSdk`] composes application-defined [`ScanPhase`] values;
//! - `Plugin` defines the source-level Preview plugin contract when the
//!   `plugins` feature is enabled.
//!
//! [`KnowledgeBase`] separates ontology, instance knowledge, and observations
//! without coupling evidence producers to decision policy.
//!
//! The runner owns ordering, timeouts, cancellation, event publication, and
//! finding aggregation. Extensions own detection behavior.
//!
//! # Scanner SDK
//!
//! ```rust,no_run
//! use venom_scanner::ScannerSdk;
//!
//! # async fn run() -> venom_scanner::Result<()> {
//! let scanner = ScannerSdk::builder().build();
//! let report = scanner.scan("https://example.test").await?;
//! assert!(report.findings.is_empty());
//! # Ok(())
//! # }
//! ```

#![deny(rustdoc::broken_intra_doc_links)]

// Core modules (always compiled)
pub mod api;
pub mod api_evidence;
pub mod api_gateway;
pub mod api_observation;
pub mod api_reasoning;
pub mod auth;
pub mod cache;
pub mod config;
pub mod config_loader;
pub mod context;
pub mod contracts;
pub mod defense;
pub mod error;
pub mod experience;
pub mod knowledge;
pub mod logging;
pub mod metrics;
pub mod payload_strategies;
pub mod payload_strategy;
pub mod planner;
pub mod rules;
pub mod verification;
pub mod web_actions;
pub mod web_planning;
pub mod web_reasoning;
pub mod web_verification;

// Scanning engine (feature: scanning)
#[cfg(feature = "scanning")]
pub mod phases;

#[cfg(feature = "scanning")]
pub mod runner;

#[cfg(feature = "scanning")]
pub mod sdk;

#[cfg(feature = "scanning")]
pub mod waf;

#[cfg(feature = "scanning")]
pub mod adaptive;

#[cfg(feature = "scanning")]
pub mod decision_loop;

#[cfg(feature = "scanning")]
pub mod decision_runner;

#[cfg(feature = "scanning")]
pub mod http_evidence;

#[cfg(feature = "scanning")]
pub mod runtime_budget;

#[cfg(feature = "scanning")]
pub mod web_execution;

#[cfg(feature = "scanning")]
pub mod web_decision;

#[cfg(feature = "scanning")]
pub mod web_runtime;

// Detection capabilities (feature: detection)
#[cfg(feature = "detection")]
pub mod advanced_detection;

#[cfg(feature = "detection")]
pub mod anomaly;

// Machine learning (feature: ml)
#[cfg(feature = "ml")]
pub mod ml;

// Distributed scaling (feature: distributed)
#[cfg(feature = "distributed")]
pub mod distributed;

// Monitoring (feature: monitoring)
#[cfg(feature = "monitoring")]
pub mod monitoring;

// Compliance (feature: compliance)
#[cfg(feature = "compliance")]
pub mod compliance;

// Threat intelligence (feature: threat-intel)
#[cfg(feature = "threat-intel")]
pub mod threat_intelligence;

// Post-exploitation (included with scanning)
#[cfg(feature = "scanning")]
pub mod post_exploitation;

// Plugin system (feature: plugins)
#[cfg(feature = "plugins")]
pub mod plugin;

#[cfg(feature = "plugins")]
pub mod plugins;

#[cfg(feature = "plugins")]
pub mod lua_engine;

// Persistence & reporting (included with scanning)
#[cfg(feature = "scanning")]
pub mod persistence;

#[cfg(feature = "scanning")]
pub mod reporting;

#[cfg(feature = "scanning")]
pub mod realtime;

#[cfg(feature = "scanning")]
pub mod dashboard;

// Event bus (included with core for observability)
pub mod event_bus;

// Core exports (always available)
pub use api::{
    ApiEndpoints, ApiError, ApiResponse, ScanResultResponse, ScanStatus, ScanStatusType,
    StartScanRequest,
};
pub use api_evidence::{
    ApiComparisonProfile, ApiVisibilityComparator, ApiVisibilityEvidenceError, ApiVisibilityLimits,
    ApiVisibilityView, CanonicalizationVersion, ComparisonAlgorithmVersion, JsonPathPattern,
    PathDigest, ProfiledApiVisibilityComparison, ProfiledApiVisibilityError,
    ProfiledApiVisibilityView, ProjectionPolicyId, RedactedVisibilityDiff,
    VisibilityExplanationDisposition, CURRENT_API_COMPARISON_ALGORITHM_VERSION,
    CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION, DEFAULT_API_VISIBILITY_CANONICAL_BYTES,
    DEFAULT_API_VISIBILITY_DEPTH, DEFAULT_API_VISIBILITY_DIFF_PATHS, DEFAULT_API_VISIBILITY_FIELDS,
    DEFAULT_API_VISIBILITY_NODES, HARD_MAX_API_COMPARISON_PATH_BYTES,
    HARD_MAX_API_COMPARISON_PATH_DEPTH, HARD_MAX_API_COMPARISON_PROFILE_PATHS,
    HARD_MAX_API_VISIBILITY_CANONICAL_BYTES, HARD_MAX_API_VISIBILITY_DEPTH,
    HARD_MAX_API_VISIBILITY_DIFF_PATHS, HARD_MAX_API_VISIBILITY_FIELDS,
    HARD_MAX_API_VISIBILITY_NODES,
};
pub use api_gateway::{
    ApiGateway, ApiQuota, QuotaManager, RateLimitPolicy, RateLimitStatus, RateLimitStrategy,
    RateLimiter, RequestValidationResult, RouteConfig, TokenBucket,
};
pub use api_observation::{
    api_visibility_reviews_for_resource, api_visibility_reviews_for_resource_v2,
    ingest_api_visibility_observation, ApiObservationCommitReceipt, ApiObservationError,
    ApiObservationReceipt, ApiVisibilityReview, ApiVisibilityReviewCursor,
    ApiVisibilityReviewDisposition, ApiVisibilityReviewPage, ApiVisibilityReviewQuery,
    DEFAULT_API_VISIBILITY_REVIEW_SCAN_LIMIT, HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT,
    MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES, MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES,
    MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES,
};
pub use api_reasoning::{
    StandardApiInstallReport, StandardApiReasoning, StandardApiReasoningError,
    STANDARD_API_AXIOM_COUNT, STANDARD_API_CONCEPT_COUNT, STANDARD_API_RULE_COUNT,
};
pub use auth::{AuthToken, LoginRequest, LoginResponse, User, UserInfo, UserManager, UserRole};
pub use cache::{CacheEntry, CacheStats, LruCache, ResponseCache};
pub use config::{ScanConfig, ScanIntensity};
pub use config_loader::{ConfigLoader, ScanProfile as ScanningProfile};
pub use context::ScanContext;
pub use contracts::{ScanFinding, ScanPhase};
pub use defense::{
    DefenseFingerprint, DefensePosture, DefenseProduct, DefenseResponse, DefenseState,
    DefenseStatusSignal, DefenseTransition, DefenseTransitionKind, FingerprintConfidence,
    PostureShift, MAX_FINGERPRINT_BODY_SCAN_BYTES,
};
pub use error::{Result, ScannerError};
pub use event_bus::{Event, EventBuilder, EventBus, EventHandler, EventSeverity, EventType};
pub use experience::{
    ExperienceAssessment, ExperienceDisposition, ExperiencePolicy, ExperienceRecommendation,
    ExperienceRecord, ExperienceStore, ExperienceStoreError, ExperienceWrite,
};
#[allow(deprecated)]
pub use knowledge::{
    KnowledgeBase, KnowledgeBaseError, KnowledgeBaseStats, KnowledgeRecordKind, KnowledgeSnapshot,
    KnowledgeStore, KnowledgeStoreError, KnowledgeStoreStats, KnowledgeWrite,
    MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES, MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS,
    MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES, MAX_KNOWLEDGE_RELATION_ID_BYTES,
    MAX_KNOWLEDGE_RELATION_KIND_BYTES,
};
pub use logging::{LogEntry, LogLevel, Logger};
pub use metrics::{MetricsCollector, MetricsSummary, PhaseMetrics};
pub use payload_strategies::{
    standard_payload_strategies, ApiAuthorizationContextPairStrategy,
    HttpHeaderControlPairStrategy, API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME,
    API_AUTHORIZATION_CONTEXT_PAIR_ID, API_AUTHORIZATION_CONTEXT_PAIR_REVISION,
    HTTP_HEADER_CONTROL_PAIR_HEADER_NAME, HTTP_HEADER_CONTROL_PAIR_ID,
    HTTP_HEADER_CONTROL_PAIR_REVISION,
};
pub use payload_strategy::{
    PayloadArtifact, PayloadArtifactReceipt, PayloadSeed, PayloadStrategy, PayloadStrategyError,
    PayloadStrategyLimits, PayloadStrategyRef, PayloadStrategyRegistry, PayloadVariantRole,
    DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES, HARD_MAX_PAYLOAD_ARTIFACT_BYTES,
    HARD_MAX_PAYLOAD_STRATEGY_ID_BYTES,
};
pub use planner::{
    ActionCost, AttackAction, AttackPlan, AttackPlanner, BenefitScore, ExcludedAction,
    ExclusionReason, HypothesisSelector, PlanStep, PlannerError, PlannerWrite, PlanningContext,
    RequiredStrength, RiskScore, UtilityBreakdown, UtilityScore,
};
pub use rules::{
    EvidenceAggregation, EvidenceCalibration, EvidenceSelector, Expression, ExpressionEvaluation,
    ExpressionTrace, HypothesisConclusion, KnowledgeLayer, ReasoningRule, RuleApplication,
    RuleEngine, RuleEngineError, RuleEvaluation, RuleWrite,
};
pub use venom_core::{
    ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityObservation,
    ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId, Outcome, OutcomeError,
    OutcomeStatus, VerificationStage,
};
pub use verification::{
    apply_outcome, ActiveVerifier, PassiveVerifier, VerificationCase, VerificationError,
    VerificationPipeline, VerificationPipelineReport, VerificationReport, VerificationRule,
    VerificationRuleEvaluation, VerifierWrite,
};
pub use web_actions::{
    StandardWebActionKind, STANDARD_WEB_ACTION_COUNT, STANDARD_WEB_DISCOVERY_ACTIONS,
    STANDARD_WEB_DISCOVERY_ACTION_COUNT,
};
pub use web_planning::{
    StandardWebAttackInstallReport, StandardWebAttackProfile, StandardWebPlanningError,
};
pub use web_reasoning::{
    StandardWebInstallReport, StandardWebReasoning, StandardWebReasoningError,
    STANDARD_WEB_AXIOM_COUNT, STANDARD_WEB_CONCEPT_COUNT, STANDARD_WEB_RULE_COUNT,
};
pub use web_verification::{
    StandardWebVerificationError, StandardWebVerificationInstallReport,
    StandardWebVerificationProfile, STANDARD_WEB_VERIFICATION_RULE_COUNT,
};

// Scanning engine exports (feature: scanning)
// Note: phases module is re-exported automatically

#[cfg(feature = "scanning")]
pub use runner::ScanRunner;

#[cfg(feature = "scanning")]
pub use sdk::{ScanReport, ScannerBuilder, ScannerSdk};

#[cfg(feature = "scanning")]
pub use waf::{EvisionTechnique, PayloadEncoder, WafDetector, WafProduct};

#[cfg(feature = "scanning")]
pub use adaptive::{
    AdaptationLedger, AdaptationLimits, AdaptationRule, AdaptationRuleEvaluation,
    AdaptationStrategy, AdaptiveDecision, AdaptiveEngine, AdaptivePipeline, AdaptivePipelineError,
    AdaptiveRuleWrite, DetectionPattern, OutcomeSelector, PayloadMutator, PipelineDirective,
    ResponseMetrics,
};

#[cfg(feature = "scanning")]
pub use decision_loop::{
    DecisionActionOrigin, DecisionLoop, DecisionLoopCommand, DecisionLoopConfig, DecisionLoopError,
    DecisionLoopState, DecisionOutcomeReport, DecisionPlanningReport,
    DecisionReasoningCommitReceipt, DecisionSession, DecisionSessionSummary,
    DecisionSessionTransition, DecisionStopReason,
};

#[cfg(feature = "scanning")]
pub use decision_runner::{
    DecisionActionExecutor, DecisionEvidenceReceipt, DecisionExecutionFailureKind,
    DecisionExecutionFailureReceipt, DecisionExecutionLimits, DecisionExecutionRequest,
    DecisionExecutionStage, DecisionExecutorError, DecisionExecutorRegistry, DecisionRunnerAdapter,
    DecisionRunnerError, DecisionRunnerTurn,
};

#[cfg(feature = "scanning")]
pub use runtime_budget::{
    RuntimeBudget, RuntimeBudgetDimension, RuntimeLimitExceeded, RuntimeUsage,
    TransportDispatchAudit, TransportDispatchOutcome, TransportDispatchReceipt,
    DEFAULT_MAX_ACTIVE_VERIFICATIONS, DEFAULT_MAX_CONSECUTIVE_NO_PROGRESS_TURNS,
    DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_SAME_ACTION_ATTEMPTS,
    DEFAULT_MAX_TOTAL_REQUESTS, DEFAULT_MAX_WALL_TIME_MS, HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS,
};

#[cfg(feature = "scanning")]
pub use http_evidence::{
    HttpBodyCapture, HttpEvidenceError, HttpEvidenceExecutor, HttpEvidencePolicy,
    HttpHeaderPayloadBinding, HttpProbe, HttpProbeMethod, HttpProbeProvider,
    SubjectHttpProbeProvider, DEFAULT_HTTP_BODY_LIMIT, HTTP_EVIDENCE_EXECUTOR_ID,
    MAX_HTTP_BODY_LIMIT,
};

#[cfg(feature = "scanning")]
pub use web_execution::{
    StandardWebDiscoveryExecutorProfile, StandardWebDiscoveryInstallReport,
    StandardWebExecutionError, STANDARD_WEB_DISCOVERY_EXECUTOR_COUNT,
};

#[cfg(feature = "scanning")]
pub use web_decision::{
    StandardWebDecisionError, StandardWebDecisionInstallReport, StandardWebDecisionProfile,
};

#[cfg(feature = "scanning")]
pub use web_runtime::{
    ApiVisibilityContextProbe, ApiVisibilityDifferentialAudit,
    ApiVisibilityDifferentialDisposition, ApiVisibilityDifferentialRequest,
    ApiVisibilityDifferentialRequestError, ApiVisibilityInconclusiveReason, ApiVisibilityLeg,
    ApiVisibilityLegReceipt, RuntimeApiVisibilityError, RuntimeApiVisibilityExecutionError,
    RuntimeApiVisibilityRunReport, StandardWebDecisionFailureReceipt, StandardWebDecisionRunReport,
    StandardWebDecisionRuntime, StandardWebDecisionRuntimeBuilder, StandardWebDecisionRuntimeError,
    StandardWebDecisionRuntimeTurn,
};

#[cfg(all(feature = "scanning", feature = "plugins"))]
pub use decision_runner::{PluginDecisionExecutor, PluginExecutionInput, PluginInputProvider};

#[cfg(feature = "scanning")]
pub use persistence::{
    ColumnDef, ConnectionPool, DbConfig, EndpointRecord, EntityType, FindingRecord, IndexDef,
    QueryBuilder, QueryResult, ScanRecord, SchemaManager, TableSchema, Transaction,
    TransactionManager, TransactionStatus,
};

#[cfg(feature = "scanning")]
pub use post_exploitation::{
    ExploitPayload, LateralTarget, PayloadType, PersistenceMechanism, PersistenceTechnique,
    PostExploitSession, PostExploitationManager, PrivilegeLevel, ReverseShell, Webshell,
};

#[cfg(feature = "scanning")]
pub use reporting::{ReportFormat, ReportGenerator, VulnerabilityReport};

#[cfg(feature = "scanning")]
pub use realtime::{ConnectionManager, EventStream, RealtimeEvent, Subscription};

#[cfg(feature = "scanning")]
pub use dashboard::{
    DashboardConfig, DashboardOverview, DashboardService, FindingCard, FindingStatus, ScanCard,
    WidgetType,
};

// Detection exports (feature: detection)
#[cfg(feature = "detection")]
pub use advanced_detection::{
    BehaviorIndicator, BehavioralAnalysisData, BehavioralAnalyzer, BehavioralSignature,
    BypassCategory, ComparisonOperator, DetectionResult, EversionRule, EversionType, IndicatorType,
    SignatureEvasionEngine, WafBypassSelector, WafBypassTechnique,
};

#[cfg(feature = "detection")]
pub use anomaly::{AnomalyDetector, AnomalyInterpreter, AnomalyScore, ResponseData, SeverityClass};

// Machine learning exports (feature: ml)
#[cfg(feature = "ml")]
pub use ml::{
    AnomalyClassifier, AnomalyPattern, AnomalyType, ClusterResult, ExploitBuilder, ExploitStage,
    ExploitationChain, PatternLearner, VulnerabilityPattern,
};

// Distributed scaling exports (feature: distributed)
#[cfg(feature = "distributed")]
pub use distributed::{
    ResultAggregator, ScanTask, TaskPriority, TaskQueue, TaskStatus, WorkerNode, WorkerPool,
    WorkerStatus,
};

// Monitoring exports (feature: monitoring)
#[cfg(feature = "monitoring")]
pub use monitoring::{
    BenchmarkResult, BenchmarkSuite, OptimizationRecommendation, PerformanceAnalyzer, PhaseProfile,
    RecommendationCategory, ResourceMetrics, ScanComparison, ScanProfile,
};

// Compliance exports (feature: compliance)
#[cfg(feature = "compliance")]
pub use compliance::{
    AuditEventType, AuditLogEntry, AuditLogger, ComplianceAssessment, ComplianceAssessor,
    ComplianceFramework, ComplianceReport, ComplianceReporter, ComplianceRequirement,
    DataClassification, DataProtectionManager, DataProtectionRecord,
};

// Threat intelligence exports (feature: threat-intel)
#[cfg(feature = "threat-intel")]
pub use threat_intelligence::{
    AlertAction, AlertEngine, AlertRule, CVECorrelator, CVERecord, SecurityAlert,
    ThreatActorProfile, ThreatFeedEntry, ThreatFeedManager, ThreatFeedSource,
    ThreatIntelligenceRepo, ThreatSeverity,
};

// Plugin system exports (feature: plugins)
#[cfg(feature = "plugins")]
pub use plugin::{
    Plugin, PluginCategory, PluginConfig, PluginError, PluginExecutionResult, PluginMetadata,
    PluginRegistry, PLUGIN_API_VERSION,
};

#[cfg(feature = "plugins")]
pub use plugins::{LFIPlugin, SQLiPlugin, SSRFPlugin, SSTIPlugin, XSSPlugin, XXEPlugin};

#[cfg(feature = "plugins")]
pub use lua_engine::{
    LuaContext, LuaExecutionResult, LuaScript, LuaScriptRegistry, LuaScriptStatus,
};
