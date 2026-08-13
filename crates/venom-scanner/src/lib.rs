//! Deterministic evidence, reasoning, planning, execution, and verification for
//! Venom's scanner runtime.
//!
//! The default `scanning` feature contains the bounded decision runtime used by
//! `venom scan`. The historical ordered phase runner and Scanner SDK are
//! available only through the non-default `legacy-scanner` feature. Native
//! plugins remain a separate source-level Preview contract under `plugins`.
//!
//! [`KnowledgeBase`] separates ontology, instance knowledge, and observations
//! without coupling evidence producers to decision policy.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(all(feature = "legacy-scanner", panic = "abort"))]
const _: () = panic!(
    "the legacy-scanner feature requires panic=unwind so panics while polling phase execution become typed run failures"
);

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
#[cfg(feature = "legacy-scanner")]
pub mod context;
#[cfg(feature = "legacy-scanner")]
pub mod contracts;
pub mod defense;
#[cfg(feature = "legacy-scanner")]
pub mod error;
pub mod experience;
pub mod knowledge;
#[cfg(feature = "legacy-scanner")]
mod legacy_discovery;
pub mod logging;
pub mod metrics;
pub mod payload_strategies;
pub mod payload_strategy;
pub mod planner;
pub mod rules;
pub mod semantic;
pub mod verification;
pub mod web_actions;
pub mod web_planning;
pub mod web_reasoning;
pub mod web_verification;

pub use semantic::{
    AuthArtifactKind, EntityExtractor, LimitsError, SemanticEntity, SemanticEntityType,
    SemanticExtractionLimits, SemanticExtractionResult,
};

// Historical ordered scanner (feature: legacy-scanner)
#[cfg(feature = "legacy-scanner")]
pub mod phases;

#[cfg(feature = "legacy-scanner")]
pub mod runner;

#[cfg(feature = "legacy-scanner")]
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
#[cfg(feature = "legacy-scanner")]
pub use context::ScanContext;
#[cfg(feature = "legacy-scanner")]
pub use contracts::ScanPhase;
pub use defense::{
    defense_aware_plan, defense_aware_shadow_plan, DefenseAwareShadowPlan, DefenseFingerprint,
    DefenseInteractionClass, DefenseObservationContext, DefensePlanningPolicy, DefensePosture,
    DefenseProduct, DefenseResponse, DefenseState, DefenseStatusSignal, DefenseTransition,
    DefenseTransitionKind, FingerprintConfidence, InteractionDecision, ObservedOutcome,
    PlanAdjustment, PostureShift, ResourceDefenseObservation, ResourceDefenseSignal,
    ShadowPlanDelta, SuppressedAction, MAX_FINGERPRINT_BODY_SCAN_BYTES,
};
#[cfg(feature = "legacy-scanner")]
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
#[cfg(feature = "legacy-scanner")]
pub use legacy_discovery::{DiscoveryForm, DiscoveryFormMethod, DiscoveryLimits};
pub use logging::{LogEntry, LogLevel, Logger};
pub use metrics::{MetricsCollector, MetricsSummary, PhaseMetrics};
pub use payload_strategies::{
    standard_payload_strategies, ApiAuthorizationContextPairStrategy, EvasionTechnique,
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
    RequiredStrength, ResolvedVerificationTarget, RiskScore, UtilityBreakdown, UtilityScore,
    VerificationTarget,
};
pub use rules::{
    EvidenceAggregation, EvidenceCalibration, EvidenceSelector, Expression, ExpressionEvaluation,
    ExpressionTrace, HypothesisConclusion, KnowledgeLayer, ReasoningRule, RuleApplication,
    RuleEngine, RuleEngineError, RuleEvaluation, RuleWrite,
};
pub use venom_core::{
    ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityObservation,
    ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId, Outcome, OutcomeError,
    OutcomeStatus, ResourceAccounting, ResourceAccountingMode, RunAccounting, RunOutcomeRecord,
    RunReport, RunReportError, RunReportInput, RunStatus, RunStepReport, RunStepStatus,
    RunStopCode, RunStopReason, ScanFinding, SecuritySeverity, VerificationStage,
    MAX_RUN_REPORT_EVIDENCE_IDS, MAX_RUN_REPORT_OUTCOMES, MAX_RUN_REPORT_STEPS,
    MAX_RUN_REPORT_TEXT_BYTES, RUN_REPORT_SCHEMA,
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

// Historical ordered scanner exports (feature: legacy-scanner)
// Note: phases module is re-exported automatically

#[cfg(feature = "legacy-scanner")]
pub use runner::ScanRunner;

#[cfg(feature = "legacy-scanner")]
pub use sdk::{ScannerBuilder, ScannerSdk};

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
    DecisionActionExecutor, DecisionEvidenceReceipt, DecisionExecutionClass,
    DecisionExecutionFailureKind, DecisionExecutionFailureReceipt, DecisionExecutionLimits,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionExecutorError,
    DecisionExecutorRegistry, DecisionRunnerAdapter, DecisionRunnerError, DecisionRunnerTurn,
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
