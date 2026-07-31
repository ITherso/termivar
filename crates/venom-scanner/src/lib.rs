// VENOM Scanner - Professional multi-phase vulnerability scanner
//!
//! A sophisticated, multi-phase vulnerability detection and exploitation framework
//! built in Rust for maximum performance and safety.
//!
//! ## Architecture
//! - **10 Phases**: Sequential vulnerability detection across different categories
//! - **Async/Await**: Native Tokio-based concurrency for high-throughput scanning
//! - **Zero-Copy**: DashMap for efficient, lock-free inter-phase communication
//! - **Type-Safe**: Compile-time guarantees eliminate entire classes of bugs

// Core modules (always compiled)
pub mod api;
pub mod api_gateway;
pub mod auth;
pub mod cache;
pub mod config;
pub mod config_loader;
pub mod context;
pub mod contracts;
pub mod error;
pub mod logging;
pub mod metrics;

// Scanning engine (feature: scanning)
#[cfg(feature = "scanning")]
pub mod phases;

#[cfg(feature = "scanning")]
pub mod runner;

#[cfg(feature = "scanning")]
pub mod waf;

#[cfg(feature = "scanning")]
pub mod adaptive;

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
pub use api_gateway::{
    ApiGateway, ApiQuota, QuotaManager, RateLimitPolicy, RateLimitStatus, RateLimitStrategy,
    RateLimiter, RequestValidationResult, RouteConfig, TokenBucket,
};
pub use auth::{AuthToken, LoginRequest, LoginResponse, User, UserInfo, UserManager, UserRole};
pub use cache::{CacheEntry, CacheStats, LruCache, ResponseCache};
pub use config::{ScanConfig, ScanIntensity};
pub use config_loader::{ConfigLoader, ScanProfile as ScanningProfile};
pub use context::ScanContext;
pub use contracts::{ScanFinding, ScanPhase};
pub use error::{Result, ScannerError};
pub use event_bus::{Event, EventBuilder, EventBus, EventHandler, EventSeverity, EventType};
pub use logging::{LogEntry, LogLevel, Logger};
pub use metrics::{MetricsCollector, MetricsSummary, PhaseMetrics};

// Scanning engine exports (feature: scanning)
// Note: phases module is re-exported automatically

#[cfg(feature = "scanning")]
pub use runner::ScanRunner;

#[cfg(feature = "scanning")]
pub use waf::{EvisionTechnique, PayloadEncoder, WafDetector, WafProduct};

#[cfg(feature = "scanning")]
pub use adaptive::{
    AdaptationStrategy, AdaptiveEngine, DetectionPattern, PayloadMutator, ResponseMetrics,
};

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
    PluginRegistry,
};

#[cfg(feature = "plugins")]
pub use plugins::{LFIPlugin, SQLiPlugin, SSRFPlugin, SSTIPlugin, XSSPlugin, XXEPlugin};

#[cfg(feature = "plugins")]
pub use lua_engine::{
    LuaContext, LuaExecutionResult, LuaScript, LuaScriptRegistry, LuaScriptStatus,
};
