//! Scanner feature and platform-surface quarantine policy.
//!
//! The default scanner is the deterministic reasoning/runtime product. Unwired
//! platform models, opt-in reporting, Lua execution, distributed coordination,
//! and the historical ordered scanner must remain explicit opt-ins. This check
//! binds the Cargo feature graph to the corresponding `lib.rs` module gates so a
//! manifest edit cannot silently pull an unsupported surface back into default
//! builds.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs, io,
    path::Path,
};

use cargo_metadata::{DependencyKind, MetadataCommand};
use proc_macro2::{TokenStream, TokenTree};
use syn::{
    visit::Visit, Attribute, Fields, ImplItem, Item, ItemMod, Meta, Path as SynPath, UseTree,
    Visibility,
};

const DEFAULT_SCANNER_FEATURES: &[&str] = &["core", "scanning"];
const EXACT_CORE_FEATURES: &[&str] = &["default", "legacy-contracts"];
const QUARANTINED_FEATURES: &[&str] = &[
    "distributed",
    "legacy-scanner",
    "lua",
    "platform-models",
    "plugins",
    "reporting",
];

const EXACT_SCANNER_FEATURES: &[&str] = &[
    "compliance",
    "core",
    "default",
    "detection",
    "distributed",
    "enterprise",
    "full",
    "legacy-scanner",
    "lua",
    "minimal",
    "ml",
    "monitoring",
    "platform-models",
    "plugins",
    "reporting",
    "research",
    "scanning",
    "threat-intel",
];

const FULL_AGGREGATE_FEATURES: &[&str] = &[
    "compliance",
    "core",
    "detection",
    "distributed",
    "legacy-scanner",
    "lua",
    "ml",
    "monitoring",
    "platform-models",
    "plugins",
    "reporting",
    "scanning",
    "threat-intel",
];

const ENTERPRISE_AGGREGATE_FEATURES: &[&str] = &[
    "compliance",
    "core",
    "detection",
    "distributed",
    "legacy-scanner",
    "lua",
    "ml",
    "monitoring",
    "platform-models",
    "plugins",
    "reporting",
    "scanning",
];

const FEATURE_OWNED_DEPENDENCIES: &[&str] = &[
    "async-trait",
    "chrono",
    "dashmap",
    "futures",
    "html5ever",
    "markup5ever_rcdom",
    "mlua",
    "regex",
    "reqwest",
    "tokio",
    "tokio-util",
    "uuid",
];

const REQUIRED_SCANNER_DEPENDENCIES: &[&str] = &[
    "base64",
    "serde",
    "serde_json",
    "sha2",
    "thiserror",
    "url",
    "venom-core",
];

const REQUIRED_CORE_DEPENDENCIES: &[&str] =
    &["chrono", "hex", "serde", "sha2", "thiserror", "uuid"];
const FEATURE_OWNED_CORE_DEPENDENCIES: &[&str] = &["serde_json", "toml"];

const REQUIRED_CLI_DEPENDENCIES: &[&str] = &[
    "clap",
    "serde",
    "serde_json",
    "tokio",
    "url",
    "venom-core",
    "venom-scanner",
];

const OPTIONAL_CLI_DEPENDENCIES: &[&str] =
    &["reqwest", "venom-api", "venom-artifact", "venom-proxy"];
const REQUIRED_API_DEPENDENCIES: &[&str] = &["axum"];
const REQUIRED_PROXY_DEPENDENCIES: &[&str] = &["tokio"];

const EXACT_CORE_MODULE_GATES: &[(&str, &str)] = &[
    ("config", "feature=\"legacy-contracts\""),
    ("error", "feature=\"legacy-contracts\""),
    ("events", "feature=\"legacy-contracts\""),
    ("models", "feature=\"legacy-contracts\""),
];

const LEGACY_CORE_MODEL_SYMBOLS: &[&str] = &[
    "HttpRequest",
    "HttpResponse",
    "ScanFinding",
    "ScanResult",
    "Vulnerability",
];

const EXACT_MODULE_GATES: &[(&str, &str)] = &[
    ("adaptive", "feature=\"scanning\""),
    ("advanced_detection", "feature=\"detection\""),
    ("anomaly", "feature=\"detection\""),
    ("api", "feature=\"platform-models\""),
    ("api_gateway", "feature=\"platform-models\""),
    ("auth", "feature=\"platform-models\""),
    ("cache", "feature=\"platform-models\""),
    ("compliance", "feature=\"compliance\""),
    ("config", "feature=\"platform-models\""),
    ("config_loader", "feature=\"platform-models\""),
    ("context", "feature=\"legacy-scanner\""),
    ("contracts", "feature=\"legacy-scanner\""),
    ("dashboard", "feature=\"platform-models\""),
    ("distributed", "feature=\"distributed\""),
    ("event_bus", "feature=\"legacy-scanner\""),
    ("error", "feature=\"legacy-scanner\""),
    ("legacy_discovery", "feature=\"legacy-scanner\""),
    ("logging", "feature=\"legacy-scanner\""),
    (
        "lua_config",
        "any(feature=\"platform-models\",feature=\"lua\")",
    ),
    ("lua_engine", "feature=\"lua\""),
    ("metrics", "feature=\"platform-models\""),
    ("ml", "feature=\"ml\""),
    ("monitoring", "feature=\"monitoring\""),
    ("persistence", "feature=\"platform-models\""),
    ("plugin", "feature=\"plugins\""),
    ("post_exploitation", "feature=\"platform-models\""),
    ("phases", "feature=\"legacy-scanner\""),
    ("realtime", "feature=\"platform-models\""),
    ("reporting", "feature=\"reporting\""),
    ("runner", "feature=\"legacy-scanner\""),
    ("sdk", "feature=\"legacy-scanner\""),
    ("threat_intelligence", "feature=\"threat-intel\""),
];

const FORBIDDEN_SCANNER_MODULES: &[&str] = &["waf"];

const RETIRED_ADAPTIVE_MODULES: &[&str] = &["payloads", "scoring", "strategy"];

const FORBIDDEN_ADAPTIVE_API: ForbiddenSurfaceApi = ForbiddenSurfaceApi {
    module: "adaptive",
    public_symbols: &[
        "AdaptiveEngine",
        "CaseTransformer",
        "CommentTransformer",
        "CompositeTransformer",
        "DecoyTransformer",
        "EncodingTransformer",
        "PayloadMutator",
        "PayloadTransformer",
        "PollutionTransformer",
        "ReductionTransformer",
        "ScoringEngine",
        "StrategySelector",
    ],
    public_methods: &[
        "add_decoys",
        "analyze_detection_pattern",
        "apply_encoding_mutation",
        "apply_parameter_pollution",
        "case_mutate",
        "detection_probability",
        "inject_comment",
        "mutate",
        "recommend_strategy",
        "reduce_payload",
        "score_breakdown",
        "should_adjust_payload",
    ],
    public_fields: &[],
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Lifecycle {
    Experimental,
    Preview,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ImplementationClaim {
    Scaffold,
    Implemented,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HostContract {
    /// No executable repository caller or explicit external-host execution contract.
    NoExecution,
    /// A source-level library host contract, named by its public boundary.
    Library(&'static str),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct SurfaceContract {
    module: &'static str,
    feature: &'static str,
    lifecycle: Lifecycle,
    implementation: ImplementationClaim,
    host: HostContract,
}

const EXPECTED_QUARANTINED_PUBLIC_MODULES: &[&str] = &[
    "advanced_detection",
    "anomaly",
    "api",
    "api_gateway",
    "auth",
    "cache",
    "compliance",
    "config",
    "config_loader",
    "dashboard",
    "distributed",
    "lua_engine",
    "metrics",
    "ml",
    "monitoring",
    "persistence",
    "plugin",
    "post_exploitation",
    "realtime",
    "reporting",
    "threat_intelligence",
];

const QUARANTINED_PUBLIC_FEATURES: &[&str] = &[
    "compliance",
    "detection",
    "distributed",
    "lua",
    "ml",
    "monitoring",
    "platform-models",
    "plugins",
    "reporting",
    "threat-intel",
];

/// Executable host contracts whose implementation modules stay private while
/// their exact root re-exports form the public boundary.
const PRIVATE_FACADE_SURFACES: &[&str] = &["distributed", "lua_engine"];

/// Exact machine-readable lifecycle and host inventory for public quarantined
/// scanner modules most likely to be mistaken for product runtime surfaces.
const QUARANTINED_PUBLIC_SURFACES: &[SurfaceContract] = &[
    SurfaceContract {
        module: "api",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "api_gateway",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "auth",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "cache",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("bounded in-memory cache API"),
    },
    SurfaceContract {
        module: "config",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "config_loader",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("in-memory profile registry API"),
    },
    SurfaceContract {
        module: "dashboard",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "metrics",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("in-memory measurement collector API"),
    },
    SurfaceContract {
        module: "persistence",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("in-memory schema catalog API"),
    },
    SurfaceContract {
        module: "post_exploitation",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "realtime",
        feature: "platform-models",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("in-process event journal API"),
    },
    SurfaceContract {
        module: "advanced_detection",
        feature: "detection",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("validated signal and technique catalog API"),
    },
    SurfaceContract {
        module: "anomaly",
        feature: "detection",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("deviation validation and text-marker API"),
    },
    SurfaceContract {
        module: "ml",
        feature: "ml",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::NoExecution,
    },
    SurfaceContract {
        module: "reporting",
        feature: "reporting",
        lifecycle: Lifecycle::Preview,
        implementation: ImplementationClaim::Implemented,
        host: HostContract::Library("bounded RunReport renderer API"),
    },
    SurfaceContract {
        module: "distributed",
        feature: "distributed",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Implemented,
        host: HostContract::Library("bounded deterministic in-process coordinator API"),
    },
    SurfaceContract {
        module: "monitoring",
        feature: "monitoring",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("measurement comparison API"),
    },
    SurfaceContract {
        module: "compliance",
        feature: "compliance",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("record catalog and arithmetic API"),
    },
    SurfaceContract {
        module: "threat_intelligence",
        feature: "threat-intel",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("record catalog and severity-predicate API"),
    },
    SurfaceContract {
        module: "lua_engine",
        feature: "lua",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Implemented,
        host: HostContract::Library("bounded cooperative Lua execution API"),
    },
    SurfaceContract {
        module: "plugin",
        feature: "plugins",
        lifecycle: Lifecycle::Preview,
        implementation: ImplementationClaim::Implemented,
        host: HostContract::Library("PluginContext and PluginDecisionExecutor"),
    },
];

#[derive(Debug, Clone, Copy)]
struct ForbiddenSurfaceApi {
    module: &'static str,
    public_symbols: &'static [&'static str],
    public_methods: &'static [&'static str],
    public_fields: &'static [&'static str],
}

/// Retired facades whose names encoded execution or security conclusions that
/// their implementations did not provide. Narrow method/field guards also stop
/// the same behavior from returning under a cosmetically renamed wrapper.
const FORBIDDEN_SURFACE_APIS: &[ForbiddenSurfaceApi] = &[
    ForbiddenSurfaceApi {
        module: "api",
        public_symbols: &["ApiEndpoints"],
        public_methods: &[],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "api_gateway",
        public_symbols: &[
            "ApiGateway",
            "QuotaManager",
            "RateLimiter",
            "RequestValidationResult",
            "TokenBucket",
        ],
        public_methods: &[
            "add_policy",
            "is_allowed",
            "record_request",
            "register_route",
            "remaining_tokens",
            "reset_daily_quota",
            "try_consume",
            "validate_request",
        ],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "auth",
        public_symbols: &[
            "AuthToken",
            "LoginRequest",
            "LoginResponse",
            "UserInfo",
            "UserManager",
        ],
        public_methods: &[
            "generate_api_key",
            "generate_token",
            "record_login",
            "revoke_token",
            "validate_token",
        ],
        public_fields: &[
            "api_key",
            "password",
            "password_hash",
            "refresh_token",
            "secret",
            "session_token",
            "token",
        ],
    },
    ForbiddenSurfaceApi {
        module: "cache",
        public_symbols: &["ResponseCache"],
        public_methods: &["cache_response", "get_response"],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "dashboard",
        public_symbols: &["DashboardService"],
        public_methods: &["calculate_success_rate"],
        public_fields: &["success_rate"],
    },
    ForbiddenSurfaceApi {
        module: "metrics",
        public_symbols: &[],
        public_methods: &[
            "average_response_time",
            "overall_success_rate",
            "success_rate",
        ],
        public_fields: &["success_rate"],
    },
    ForbiddenSurfaceApi {
        module: "persistence",
        public_symbols: &[
            "ConnectionPool",
            "DbConfig",
            "QueryBuilder",
            "QueryResult",
            "Transaction",
            "TransactionManager",
            "TransactionStatus",
        ],
        public_methods: &[
            "begin_transaction",
            "build",
            "commit",
            "default_sqlite",
            "execute_query",
            "generate_create_statement",
            "rollback",
        ],
        public_fields: &["connection_string", "sql"],
    },
    ForbiddenSurfaceApi {
        module: "realtime",
        public_symbols: &["ConnectionManager", "WebSocketMessage"],
        public_methods: &["broadcast", "subscribe", "unsubscribe"],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "post_exploitation",
        public_symbols: &[
            "ExploitPayload",
            "LateralTarget",
            "PayloadType",
            "PersistenceMechanism",
            "PersistenceTechnique",
            "PostExploitSession",
            "PostExploitationManager",
            "PrivilegeLevel",
            "ReverseShell",
            "Webshell",
        ],
        public_methods: &[
            "create_payload",
            "create_session",
            "get_active_sessions",
            "get_uncompromised_targets",
            "register_target",
        ],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "advanced_detection",
        public_symbols: &[
            "BehavioralAnalyzer",
            "BypassCategory",
            "DetectionResult",
            "EversionRule",
            "EversionType",
            "SignatureEvasionEngine",
            "WafBypassSelector",
            "WafBypassTechnique",
            "WafDetector",
        ],
        public_methods: &[
            "analyze",
            "apply_evasion",
            "get_best_rule",
            "get_metric",
            "rank_by_effectiveness",
            "select_best",
        ],
        public_fields: &["severity"],
    },
    ForbiddenSurfaceApi {
        module: "waf",
        public_symbols: &[
            "EvasionTechnique",
            "EvisionTechnique",
            "PayloadEncoder",
            "WafDetector",
        ],
        public_methods: &["apply_evasion"],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "payload_strategies/encoding",
        public_symbols: &["EvasionTechnique", "EvisionTechnique", "PayloadEncoder"],
        public_methods: &["apply_evasion"],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "anomaly",
        public_symbols: &[
            "AnomalyDetector",
            "AnomalyInterpreter",
            "AnomalyScore",
            "Baseline",
            "Confidence",
            "ConfidenceLevel",
            "ResponseData",
            "SeverityClass",
            "StatusWhitelist",
        ],
        public_methods: &[
            "analyze",
            "classify_severity",
            "describe_anomaly",
            "is_anomalous",
            "is_reportable",
            "record_response",
            "suggest_investigation",
        ],
        public_fields: &["severity"],
    },
    ForbiddenSurfaceApi {
        module: "ml",
        public_symbols: &["AnomalyClassifier", "ExploitBuilder", "PatternLearner"],
        public_methods: &["classify", "cluster_patterns", "estimate_success_rate"],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "reporting",
        public_symbols: &["VulnerabilityReport"],
        public_methods: &["phase_stats", "risk_score", "severity_stats"],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "monitoring",
        public_symbols: &["OptimizationRecommendation", "RecommendationCategory"],
        public_methods: &[
            "analyze",
            "detect_regressions",
            "most_productive_phase",
            "overall_success_rate",
            "slowest_phase",
            "success_rate",
        ],
        public_fields: &["success_rate"],
    },
    ForbiddenSurfaceApi {
        module: "compliance",
        public_symbols: &[
            "AuditLogger",
            "ComplianceAssessor",
            "ComplianceReporter",
            "DataProtectionManager",
        ],
        public_methods: &[
            "create_assessment",
            "generate_report",
            "get_framework_score",
            "is_compliant",
        ],
        public_fields: &[],
    },
    ForbiddenSurfaceApi {
        module: "threat_intelligence",
        public_symbols: &[
            "AlertEngine",
            "CVECorrelator",
            "SecurityAlert",
            "ThreatFeedManager",
            "ThreatIntelligenceRepo",
        ],
        public_methods: &[
            "get_active_alerts",
            "get_alerts_by_severity",
            "process_alert",
            "register_cve",
        ],
        public_fields: &["triggered"],
    },
];

#[derive(Debug, Clone, Eq, PartialEq)]
struct DependencyContract {
    optional: bool,
    uses_default_features: bool,
    features: BTreeSet<String>,
}

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let mut violations = Vec::new();
    let workspace_members: BTreeSet<_> = metadata.workspace_members.iter().collect();
    let default_members: BTreeSet<_> = metadata.workspace_default_members.iter().collect();
    if workspace_members != default_members {
        violations.push(
            "the virtual workspace must not narrow `default-members`; root Cargo gates cover every workspace package"
                .to_owned(),
        );
    }

    let packages = metadata.workspace_packages();
    let core = packages
        .iter()
        .copied()
        .find(|package| package.name.as_str() == "venom-core")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "workspace package `venom-core` is missing",
            )
        })?;
    violations.extend(core_feature_violations(&core.features));
    violations.extend(dependency_inventory_violations(
        "venom-core",
        &dependency_contracts(core),
        REQUIRED_CORE_DEPENDENCIES,
        FEATURE_OWNED_CORE_DEPENDENCIES,
    ));
    let scanner = packages
        .iter()
        .copied()
        .find(|package| package.name.as_str() == "venom-scanner")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "workspace package `venom-scanner` is missing",
            )
        })?;

    let scanner_dependencies = dependency_contracts(scanner);
    violations.extend(feature_violations(&scanner.features));
    violations.extend(scanner_dependency_violations(&scanner_dependencies));
    violations.extend(dependency_inventory_violations(
        "venom-scanner",
        &scanner_dependencies,
        REQUIRED_SCANNER_DEPENDENCIES,
        FEATURE_OWNED_DEPENDENCIES,
    ));
    violations.extend(exact_dependency_contract_violations(
        "venom-scanner",
        &scanner_dependencies,
        "venom-core",
        false,
        false,
        &[],
    ));
    violations.extend(exact_dependency_contract_violations(
        "venom-scanner",
        &scanner_dependencies,
        "reqwest",
        true,
        false,
        &["rustls-tls"],
    ));
    violations.extend(exact_dependency_contract_violations(
        "venom-scanner",
        &scanner_dependencies,
        "mlua",
        true,
        false,
        &["lua54", "vendored"],
    ));
    let mlua_requirement = scanner
        .dependencies
        .iter()
        .find(|dependency| dependency.name.as_str() == "mlua")
        .map(|dependency| dependency.req.to_string());
    violations.extend(exact_dependency_requirement_violations(
        "venom-scanner",
        "mlua",
        mlua_requirement.as_deref(),
        "^0.9",
    ));
    let cli = packages
        .iter()
        .copied()
        .find(|package| package.name.as_str() == "venom-cli")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "workspace package `venom-cli` is missing",
            )
        })?;
    let cli_dependencies = dependency_contracts(cli);
    violations.extend(cli_feature_violations(&cli.features, &cli_dependencies));
    violations.extend(dependency_inventory_violations(
        "venom-cli",
        &cli_dependencies,
        REQUIRED_CLI_DEPENDENCIES,
        OPTIONAL_CLI_DEPENDENCIES,
    ));
    violations.extend(exact_dependency_contract_violations(
        "venom-cli",
        &cli_dependencies,
        "reqwest",
        true,
        false,
        &["rustls-tls"],
    ));
    let api = packages
        .iter()
        .copied()
        .find(|package| package.name.as_str() == "venom-api")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "workspace package `venom-api` is missing",
            )
        })?;
    let api_dependencies = dependency_contracts(api);
    violations.extend(dependency_inventory_violations(
        "venom-api",
        &api_dependencies,
        REQUIRED_API_DEPENDENCIES,
        &[],
    ));
    violations.extend(exact_dependency_contract_violations(
        "venom-api",
        &api_dependencies,
        "axum",
        false,
        false,
        &[],
    ));
    let proxy = packages
        .iter()
        .copied()
        .find(|package| package.name.as_str() == "venom-proxy")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "workspace package `venom-proxy` is missing",
            )
        })?;
    violations.extend(dependency_inventory_violations(
        "venom-proxy",
        &dependency_contracts(proxy),
        REQUIRED_PROXY_DEPENDENCIES,
        &[],
    ));
    violations.extend(core_surface_violations(workspace_root)?);
    let source = fs::read_to_string(workspace_root.join("crates/venom-scanner/src/lib.rs"))?;
    violations.extend(module_gate_violations(&source)?);
    violations.extend(scanner_legacy_reexport_violations(&source)?);
    violations.extend(private_facade_reexport_violations(
        &source,
        "distributed",
        "feature=\"distributed\"",
        EXACT_DISTRIBUTED_REEXPORTS,
    )?);
    violations.extend(private_facade_reexport_violations(
        &source,
        "lua_engine",
        "feature=\"lua\"",
        EXACT_LUA_REEXPORTS,
    )?);
    violations.extend(private_facade_reexport_violations(
        &source,
        "lua_config",
        "any(feature=\"platform-models\",feature=\"lua\")",
        EXACT_LUA_CONFIG_REEXPORTS,
    )?);
    let web_runtime_source =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/web_runtime.rs"))?;
    violations.extend(private_natural_child_module_violations(
        &web_runtime_source,
        "scan_profile",
    )?);
    violations.extend(private_facade_reexport_violations(
        &web_runtime_source,
        "scan_profile",
        "feature=\"scanning\"",
        EXACT_SCAN_PROFILE_REEXPORTS,
    )?);
    violations.extend(host_surface_cfg_facade_violations(&source)?);
    violations.extend(reporting_reexport_violations(&source)?);
    violations.extend(reporting_whole_crate_closure_violations(
        &workspace_root.join("crates/venom-scanner/src"),
    )?);
    violations.extend(surface_contract_violations(
        QUARANTINED_PUBLIC_SURFACES,
        &source,
    )?);
    violations.extend(forbidden_surface_source_violations(workspace_root)?);
    let scanner_source = workspace_root.join("crates/venom-scanner/src");
    let distributed_source_storage =
        read_ordered_sources(&scanner_source, DISTRIBUTED_PRODUCTION_SOURCE_PATHS)?;
    let distributed_sources = borrowed_sources(&distributed_source_storage);
    violations.extend(distributed_public_api_violations(&distributed_sources)?);
    violations.extend(distributed_source_authority_violations(
        &distributed_sources,
    )?);
    violations.extend(distributed_production_inventory_violations(
        &distributed_sources,
    ));
    let lua_engine_source_storage =
        read_ordered_sources(&scanner_source, LUA_ENGINE_PRODUCTION_SOURCE_PATHS)?;
    let lua_engine_sources = borrowed_sources(&lua_engine_source_storage);
    let lua_config_source =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/lua_config.rs"))?;
    violations.extend(lua_public_api_violations(
        &lua_engine_sources,
        &lua_config_source,
    )?);
    violations.extend(lua_source_authority_violations(&lua_engine_sources)?);
    violations.extend(lua_production_inventory_violations(
        &lua_engine_sources,
        &lua_config_source,
    ));
    let reporting_source =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/reporting.rs"))?;
    violations.extend(reporting_source_import_violations(&reporting_source)?);
    violations.extend(reporting_source_violations(&reporting_source)?);
    violations.extend(reporting_public_api_violations(&reporting_source)?);
    violations.extend(reporting_document_contract_violations(&reporting_source)?);
    violations.extend(reporting_production_body_inventory_violations(
        &reporting_source,
    ));
    violations.extend(adaptive_surface_violations(workspace_root)?);
    Ok(violations)
}

fn core_feature_violations(features: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let actual_names: BTreeSet<_> = features.keys().map(String::as_str).collect();
    let expected_names: BTreeSet<_> = EXACT_CORE_FEATURES.iter().copied().collect();
    let mut violations = Vec::new();
    if actual_names != expected_names {
        violations.push(format!(
            "venom-core feature names must be exactly {expected_names:?}, found {actual_names:?}"
        ));
    }
    for feature in EXACT_CORE_FEATURES {
        let members: BTreeSet<_> = features
            .get(*feature)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<_> = match *feature {
            "legacy-contracts" => ["dep:serde_json", "dep:toml"].into_iter().collect(),
            _ => BTreeSet::new(),
        };
        if members != expected {
            violations.push(format!(
                "venom-core `{feature}` members must be exactly {expected:?}, found {members:?}"
            ));
        }
    }
    violations
}

fn dependency_contracts(package: &cargo_metadata::Package) -> BTreeMap<String, DependencyContract> {
    package
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind == DependencyKind::Normal)
        .map(|dependency| {
            (
                dependency.name.to_string(),
                DependencyContract {
                    optional: dependency.optional,
                    uses_default_features: dependency.uses_default_features,
                    features: dependency.features.iter().cloned().collect(),
                },
            )
        })
        .collect()
}

fn dependency_inventory_violations(
    package: &str,
    dependencies: &BTreeMap<String, DependencyContract>,
    required: &[&str],
    optional: &[&str],
) -> Vec<String> {
    let expected: BTreeSet<_> = required.iter().chain(optional).copied().collect();
    let actual: BTreeSet<_> = dependencies.keys().map(String::as_str).collect();
    let mut violations = Vec::new();
    for missing in expected.difference(&actual) {
        violations.push(format!(
            "{package} classified dependency `{missing}` is missing"
        ));
    }
    for unknown in actual.difference(&expected) {
        violations.push(format!(
            "{package} dependency `{unknown}` is unclassified; add it to the exact required/optional architecture inventory"
        ));
    }
    for dependency in required {
        if dependencies
            .get(*dependency)
            .is_some_and(|contract| contract.optional)
        {
            violations.push(format!(
                "{package} required dependency `{dependency}` must not be optional"
            ));
        }
    }
    for dependency in optional {
        if dependencies
            .get(*dependency)
            .is_some_and(|contract| !contract.optional)
        {
            violations.push(format!(
                "{package} feature-owned dependency `{dependency}` must remain optional"
            ));
        }
    }
    violations
}

fn exact_dependency_contract_violations(
    package: &str,
    dependencies: &BTreeMap<String, DependencyContract>,
    dependency: &str,
    optional: bool,
    uses_default_features: bool,
    features: &[&str],
) -> Vec<String> {
    let expected_features: BTreeSet<_> = features
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect();
    let Some(actual) = dependencies.get(dependency) else {
        return vec![format!(
            "{package} dependency `{dependency}` is missing from its exact contract"
        )];
    };
    if actual.optional == optional
        && actual.uses_default_features == uses_default_features
        && actual.features == expected_features
    {
        Vec::new()
    } else {
        vec![format!(
            "{package} dependency `{dependency}` must use optional={optional}, default-features={uses_default_features}, and exactly {expected_features:?}; found {actual:?}"
        )]
    }
}

fn exact_dependency_requirement_violations(
    package: &str,
    dependency: &str,
    actual: Option<&str>,
    expected: &str,
) -> Vec<String> {
    if actual == Some(expected) {
        Vec::new()
    } else {
        vec![format!(
            "{package} dependency `{dependency}` version requirement must remain exactly `{expected}`, found {actual:?}"
        )]
    }
}

fn cli_feature_violations(
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &BTreeMap<String, DependencyContract>,
) -> Vec<String> {
    let mut violations = Vec::new();
    if features
        .get("default")
        .is_none_or(|features| !features.is_empty())
    {
        violations.push("venom-cli default features must remain empty".to_owned());
    }
    for (feature, expected) in [
        ("api-adapter", &["dep:venom-api"][..]),
        ("artifact-adapter", &["dep:venom-artifact"][..]),
        (
            "legacy-scanner",
            &["dep:reqwest", "venom-scanner/legacy-scanner"][..],
        ),
        ("proxy-adapter", &["dep:venom-proxy"][..]),
    ] {
        let actual: BTreeSet<_> = features
            .get(feature)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<_> = expected.iter().copied().collect();
        if actual != expected {
            violations.push(format!(
                "venom-cli `{feature}` members must be exactly {expected:?}, found {actual:?}"
            ));
        }
    }

    for dependency in ["reqwest", "venom-api", "venom-artifact", "venom-proxy"] {
        if dependencies
            .get(dependency)
            .is_none_or(|contract| !contract.optional)
        {
            violations.push(format!(
                "venom-cli dependency `{dependency}` must remain optional"
            ));
        }
    }
    let expected_scanner_features = BTreeSet::from(["reporting".to_owned(), "scanning".to_owned()]);
    match dependencies.get("venom-scanner") {
        Some(contract)
            if !contract.optional
                && !contract.uses_default_features
                && contract.features == expected_scanner_features => {},
        Some(contract) => violations.push(format!(
            "venom-cli must use non-optional venom-scanner with default-features=false and exactly [reporting, scanning], found {contract:?}"
        )),
        None => violations.push("venom-cli dependency `venom-scanner` is missing".to_owned()),
    }
    violations
}

fn feature_violations(features: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut violations = Vec::new();
    let actual_feature_names: BTreeSet<_> = features.keys().map(String::as_str).collect();
    let expected_feature_names: BTreeSet<_> = EXACT_SCANNER_FEATURES.iter().copied().collect();
    if actual_feature_names != expected_feature_names {
        violations.push(format!(
            "venom-scanner feature names must be exactly {expected_feature_names:?}, found {actual_feature_names:?}"
        ));
    }

    let default: BTreeSet<_> = features
        .get("default")
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<_> = DEFAULT_SCANNER_FEATURES.iter().copied().collect();
    if default != expected {
        violations.push(format!(
            "venom-scanner default features must be exactly {expected:?}, found {default:?}"
        ));
    }

    for feature in QUARANTINED_FEATURES {
        if !features.contains_key(*feature) {
            violations.push(format!(
                "venom-scanner must declare the explicit `{feature}` feature"
            ));
        }
    }

    for (feature, expected_members) in exact_raw_feature_closures() {
        let actual = raw_feature_closure(features, feature);
        let expected: BTreeSet<_> = expected_members.iter().copied().collect();
        if actual != expected {
            violations.push(format!(
                "venom-scanner `{feature}` raw feature closure must be exactly {expected:?}, found {actual:?}"
            ));
        }
    }

    violations.extend(compatibility_alias_violations(features));

    let plugins = raw_feature_closure(features, "plugins");
    if plugins.contains("lua") || plugins.contains("dep:mlua") {
        violations.push("venom-scanner `plugins` must not enable `lua` or `dep:mlua`".to_owned());
    }
    if raw_feature_closure(features, "lua").contains("plugins") {
        violations.push("venom-scanner `lua` must not enable `plugins`".to_owned());
    }

    violations
}

fn compatibility_alias_violations(features: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut violations = Vec::new();
    for (alias, expected_members) in [
        ("minimal", DEFAULT_SCANNER_FEATURES),
        ("full", FULL_AGGREGATE_FEATURES),
        ("enterprise", ENTERPRISE_AGGREGATE_FEATURES),
        ("research", &["full"][..]),
    ] {
        let actual: BTreeSet<_> = features
            .get(alias)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<_> = expected_members.iter().copied().collect();
        if actual != expected {
            violations.push(format!(
                "venom-scanner compatibility alias `{alias}` members must be exactly {expected:?}, found {actual:?}"
            ));
        }
    }

    for (alias, target) in [("minimal", "scanning"), ("research", "full")] {
        let mut alias_closure = raw_feature_closure(features, alias);
        alias_closure.remove(alias);
        let target_closure = raw_feature_closure(features, target);
        if alias_closure != target_closure {
            violations.push(format!(
                "venom-scanner compatibility alias `{alias}` must have the same raw feature closure as `{target}`"
            ));
        }
    }
    violations
}

fn exact_raw_feature_closures() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        (
            "default",
            &[
                "default",
                "core",
                "scanning",
                "dep:async-trait",
                "dep:html5ever",
                "dep:markup5ever_rcdom",
                "dep:reqwest",
                "dep:tokio",
                "dep:tokio-util",
            ],
        ),
        ("core", &["core"]),
        (
            "scanning",
            &[
                "scanning",
                "core",
                "dep:async-trait",
                "dep:html5ever",
                "dep:markup5ever_rcdom",
                "dep:reqwest",
                "dep:tokio",
                "dep:tokio-util",
            ],
        ),
        (
            "legacy-scanner",
            &[
                "legacy-scanner",
                "scanning",
                "core",
                "venom-core/legacy-contracts",
                "dep:async-trait",
                "dep:html5ever",
                "dep:markup5ever_rcdom",
                "dep:reqwest",
                "dep:tokio",
                "dep:tokio-util",
                "dep:chrono",
                "dep:dashmap",
                "dep:futures",
                "dep:uuid",
            ],
        ),
        (
            "platform-models",
            &[
                "platform-models",
                "core",
                "venom-core/legacy-contracts",
                "dep:dashmap",
                "dep:uuid",
            ],
        ),
        ("reporting", &["reporting", "core"]),
        ("detection", &["detection", "dep:regex"]),
        ("ml", &["ml"]),
        ("distributed", &["distributed"]),
        ("monitoring", &["monitoring"]),
        ("compliance", &["compliance"]),
        ("threat-intel", &["threat-intel"]),
        (
            "plugins",
            &[
                "plugins",
                "core",
                "dep:async-trait",
                "dep:dashmap",
                "dep:futures",
                "dep:regex",
                "dep:tokio",
                "dep:tokio-util",
            ],
        ),
        ("lua", &["lua", "core", "dep:mlua", "dep:tokio"]),
    ]
}

fn scanner_dependency_violations(
    dependencies: &BTreeMap<String, DependencyContract>,
) -> Vec<String> {
    FEATURE_OWNED_DEPENDENCIES
        .iter()
        .filter(|dependency| {
            dependencies
                .get(**dependency)
                .is_none_or(|contract| !contract.optional)
        })
        .map(|dependency| {
            format!(
                "venom-scanner feature-owned dependency `{dependency}` must remain present and optional"
            )
        })
        .collect()
}

fn raw_feature_closure<'a>(
    features: &'a BTreeMap<String, Vec<String>>,
    root: &'a str,
) -> BTreeSet<&'a str> {
    let mut closure = BTreeSet::new();
    let mut expanded = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(feature) = pending.pop() {
        closure.insert(feature);
        if !expanded.insert(feature) {
            continue;
        }
        if let Some(members) = features.get(feature) {
            for member in members {
                closure.insert(member);
                if features.contains_key(member) {
                    pending.push(member);
                }
            }
        }
    }
    closure
}

fn module_gate_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    for module_name in FORBIDDEN_SCANNER_MODULES {
        if syntax
            .items
            .iter()
            .any(|item| matches!(item, Item::Mod(module) if module.ident == *module_name))
        {
            violations.push(format!(
                "retired venom-scanner module `{module_name}` must not be declared"
            ));
        }
    }
    for (module_name, expected) in EXACT_MODULE_GATES {
        let matches: Vec<_> = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(module) if module.ident == *module_name => Some(module),
                _ => None,
            })
            .collect();
        match matches.as_slice() {
            [] => violations.push(format!(
                "venom-scanner module `{module_name}` is missing from lib.rs"
            )),
            [module] => {
                let actual = cfg_predicates(module);
                if actual != [(*expected).to_owned()] {
                    violations.push(format!(
                        "venom-scanner module `{module_name}` must use exact cfg({expected}), found {actual:?}"
                    ));
                }
                if *module_name == "reporting" {
                    let non_doc_attributes: Vec<_> = module
                        .attrs
                        .iter()
                        .filter(|attribute| !attribute.path().is_ident("doc"))
                        .collect();
                    if !is_public(&module.vis)
                        || module.content.is_some()
                        || non_doc_attributes.len() != 1
                        || !non_doc_attributes[0].path().is_ident("cfg")
                    {
                        violations.push(
                            "venom-scanner `reporting` must remain one public out-of-line module with only its exact cfg and optional docs"
                                .to_owned(),
                        );
                    }
                }
                if PRIVATE_FACADE_SURFACES.contains(module_name) {
                    let non_doc_attributes: Vec<_> = module
                        .attrs
                        .iter()
                        .filter(|attribute| !attribute.path().is_ident("doc"))
                        .collect();
                    if !matches!(module.vis, Visibility::Inherited)
                        || module.content.is_some()
                        || non_doc_attributes.len() != 1
                        || !non_doc_attributes[0].path().is_ident("cfg")
                    {
                        violations.push(format!(
                            "venom-scanner `{module_name}` must remain one private out-of-line module behind exact root re-exports"
                        ));
                    }
                }
            },
            _ => violations.push(format!(
                "venom-scanner module `{module_name}` must be declared exactly once"
            )),
        }
    }
    Ok(violations)
}

fn core_surface_violations(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let core_source = workspace_root.join("crates/venom-core/src");
    let lib_source = fs::read_to_string(core_source.join("lib.rs"))?;
    let mut violations = core_library_gate_violations(&lib_source)?;

    let models_source = fs::read_to_string(core_source.join("models.rs"))?;
    let model_shape = public_api_shape(&models_source)?;
    for symbol in LEGACY_CORE_MODEL_SYMBOLS {
        if !model_shape.symbols.contains(*symbol) {
            violations.push(format!(
                "venom-core legacy models must retain opt-in `{symbol}` for the pinned compatibility baseline"
            ));
        }
    }
    Ok(violations)
}

fn core_library_gate_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    for (module_name, expected) in EXACT_CORE_MODULE_GATES {
        let matches: Vec<_> = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(module) if module.ident == *module_name => Some(module),
                _ => None,
            })
            .collect();
        match matches.as_slice() {
            [] => violations.push(format!(
                "venom-core module `{module_name}` is missing from lib.rs"
            )),
            [module] => {
                let actual = cfg_predicates(module);
                if actual != [(*expected).to_owned()] {
                    violations.push(format!(
                        "venom-core module `{module_name}` must use exact cfg({expected}), found {actual:?}"
                    ));
                }
            },
            _ => violations.push(format!(
                "venom-core module `{module_name}` must be declared exactly once"
            )),
        }
    }

    let expected_reexports: BTreeSet<_> = [
        "Config",
        "ConfigBuilder",
        "ConfigError",
        "Event",
        "EventBuilder",
        "EventSeverity",
        "EventType",
        "Error",
        "HttpRequest",
        "HttpResponse",
        "Result",
        "ScanFinding",
        "ScanIntensity",
        "ScanResult",
        "Vulnerability",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut actual_reexports = BTreeMap::<String, usize>::new();
    for item in &syntax.items {
        let Item::Use(item) = item else {
            continue;
        };
        if !is_public(&item.vis) {
            continue;
        }
        let mut names = BTreeSet::new();
        collect_use_names(&item.tree, &mut names);
        let legacy_names: Vec<_> = names.intersection(&expected_reexports).cloned().collect();
        if legacy_names.is_empty() {
            continue;
        }
        let actual_cfg = cfg_predicates_from_attributes(&item.attrs);
        let expected_cfg = "feature=\"legacy-contracts\"".to_owned();
        if actual_cfg != [expected_cfg.clone()] {
            violations.push(format!(
                "venom-core legacy re-exports {legacy_names:?} must use exact cfg({expected_cfg}), found {actual_cfg:?}"
            ));
        }
        for name in legacy_names {
            *actual_reexports.entry(name).or_default() += 1;
        }
    }
    for name in expected_reexports {
        match actual_reexports.get(&name).copied().unwrap_or_default() {
            1 => {},
            count => violations.push(format!(
                "venom-core legacy symbol `{name}` must be re-exported exactly once; found {count}"
            )),
        }
    }
    Ok(violations)
}

fn scanner_legacy_reexport_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let expected = BTreeMap::from([
        ("Event", "feature=\"legacy-scanner\""),
        ("EventBuilder", "feature=\"legacy-scanner\""),
        ("EventSeverity", "feature=\"legacy-scanner\""),
        ("EventType", "feature=\"legacy-scanner\""),
        (
            "ScanFinding",
            "any(feature=\"legacy-scanner\",feature=\"platform-models\")",
        ),
    ]);
    let mut counts = BTreeMap::<String, usize>::new();
    let mut violations = Vec::new();
    for item in &syntax.items {
        let Item::Use(item) = item else {
            continue;
        };
        if !is_public(&item.vis) {
            continue;
        }
        let mut names = BTreeSet::new();
        collect_use_names(&item.tree, &mut names);
        for name in names {
            let Some(expected_cfg) = expected.get(name.as_str()) else {
                continue;
            };
            *counts.entry(name.clone()).or_default() += 1;
            let actual_cfg = cfg_predicates_from_attributes(&item.attrs);
            if actual_cfg != [(*expected_cfg).to_owned()] {
                violations.push(format!(
                    "venom-scanner legacy re-export `{name}` must use exact cfg({expected_cfg}), found {actual_cfg:?}"
                ));
            }
        }
    }
    for name in expected.keys() {
        match counts.get(*name).copied().unwrap_or_default() {
            1 => {},
            count => violations.push(format!(
                "venom-scanner legacy symbol `{name}` must be re-exported exactly once; found {count}"
            )),
        }
    }
    Ok(violations)
}

const EXACT_DISTRIBUTED_REEXPORTS: &[&str] = &[
    "AggregatedResult",
    "CancellationOutcome",
    "CompletionOutcome",
    "CompletionReceipt",
    "DistributedError",
    "DistributedLimits",
    "FailureOutcome",
    "MAX_ACTIVE_TASKS",
    "MAX_AGGREGATE_ITEMS",
    "MAX_HEARTBEAT_TIMEOUT_SECS",
    "MAX_IDENTIFIER_BYTES",
    "MAX_LEASE_TTL_SECS",
    "MAX_RESULTS",
    "MAX_RESULT_BYTES",
    "MAX_RETRIES",
    "MAX_TARGET_REF_BYTES",
    "MAX_TASK_PHASES",
    "MAX_TASK_RECORDS",
    "MAX_TASK_TTL_SECS",
    "MAX_TOTAL_RESULT_BYTES",
    "MAX_WORKERS",
    "MAX_WORKER_CAPACITY",
    "MAX_WORKER_TAGS",
    "QueuedTaskFence",
    "RecoverySummary",
    "ResultAggregator",
    "ResultLimits",
    "ScanTask",
    "StartOutcome",
    "StateSnapshot",
    "StoreResultOutcome",
    "TaskLease",
    "TaskOwnership",
    "TaskPriority",
    "TaskQueue",
    "TaskSpec",
    "TaskStatus",
    "Transition",
    "UTILIZATION_BASIS_POINTS",
    "WorkerNode",
    "WorkerObservation",
    "WorkerPool",
    "WorkerSpec",
    "WorkerStatus",
    "WorkerTag",
];

const EXACT_LUA_REEXPORTS: &[&str] = &[
    "LuaCancellationToken",
    "LuaContext",
    "LuaExecutionError",
    "LuaExecutionReceipt",
    "LuaExecutionResult",
    "LuaExecutionStatus",
    "LuaRegistrationError",
    "LuaRegistryError",
    "LuaReturnValue",
    "LuaScript",
    "LuaScriptManifest",
    "LuaScriptRegistry",
    "ScriptCategory",
];

const EXACT_LUA_CONFIG_REEXPORTS: &[&str] =
    &["LuaConfigError", "LuaConfigViolation", "LuaEngineConfig"];

const EXACT_SCAN_PROFILE_REEXPORTS: &[&str] = &[
    "BASELINE_SCAN_PROFILE_ID",
    "BASELINE_SCAN_PROFILE_MAX_TOTAL_REQUESTS",
    "BASELINE_SCAN_PROFILE_MAX_TOTAL_RESPONSE_BYTES",
    "BASELINE_SCAN_PROFILE_MAX_WALL_TIME_MS",
    "BuiltInScanProfile",
    "BuiltInScanProfileParseError",
    "SCAN_PROFILE_V1_SCHEMA",
    "ScanProfileCapabilitiesV1",
    "ScanProfileLimitsV1",
    "ScanProfileScope",
    "ScanProfileSelectionError",
    "ScanProfileV1",
    "ScanProfileV1Error",
    "WEB_REVIEW_SCAN_PROFILE_ID",
];

fn private_facade_reexport_violations(
    source: &str,
    module: &str,
    expected_cfg: &str,
    expected_symbols: &[&str],
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut all_uses = Vec::new();
    collect_recursive_item_uses(&syntax.items, 0, &mut all_uses);
    let mut all_type_aliases = Vec::new();
    collect_recursive_type_aliases(&syntax.items, 0, &mut all_type_aliases);
    let mut aliases: BTreeSet<String> = expected_symbols
        .iter()
        .map(|name| (*name).to_owned())
        .chain([module.to_owned()])
        .collect();
    let bindings: Vec<_> = all_uses
        .iter()
        .map(|record| {
            let mut bindings = Vec::new();
            collect_use_bindings(&record.item.tree, &mut Vec::new(), &mut bindings);
            bindings
        })
        .collect();
    let type_alias_paths: Vec<_> = all_type_aliases
        .iter()
        .map(|record| collect_type_paths(&record.item.ty))
        .collect();
    let mut related = vec![false; all_uses.len()];
    let mut related_type_aliases = vec![false; all_type_aliases.len()];
    loop {
        let mut changed = false;
        for (index, use_bindings) in bindings.iter().enumerate() {
            if related[index]
                || !use_bindings
                    .iter()
                    .any(|(path, _)| path.iter().any(|segment| aliases.contains(segment)))
            {
                continue;
            }
            related[index] = true;
            changed = true;
            for (_, exposed) in use_bindings {
                aliases.insert(exposed.clone());
            }
        }
        for (index, paths) in type_alias_paths.iter().enumerate() {
            if related_type_aliases[index]
                || !paths
                    .iter()
                    .any(|path| path.iter().any(|segment| aliases.contains(segment)))
            {
                continue;
            }
            related_type_aliases[index] = true;
            changed = true;
            aliases.insert(semantic_ident_name(&all_type_aliases[index].item.ident));
        }
        if !changed {
            break;
        }
    }

    let expected: BTreeSet<_> = expected_symbols
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut violations = Vec::new();
    for (record, is_related) in all_type_aliases.iter().zip(related_type_aliases) {
        if is_related {
            violations.push(format!(
                "venom-scanner `{module}` facade cannot pass through type alias `{}` at inline-module depth {}",
                record.item.ident, record.depth
            ));
        }
    }
    let related_uses: Vec<_> = all_uses
        .iter()
        .zip(related)
        .filter_map(|(record, is_related)| is_related.then_some(record))
        .collect();
    match related_uses.as_slice() {
        [record] => {
            let item = record.item;
            if record.depth != 0 || !is_public(&item.vis) {
                violations.push(format!(
                    "venom-scanner `{module}` facade must be one public root re-export"
                ));
            }
            if item.leading_colon.is_some()
                || use_tree_root_ident(&item.tree).as_deref() != Some(module)
            {
                violations.push(format!(
                    "venom-scanner `{module}` re-exports must use the exact direct `{module}::{{...}}` path"
                ));
            }
            let actual_cfg = cfg_predicates_from_attributes(&item.attrs);
            if actual_cfg != [expected_cfg.to_owned()] {
                violations.push(format!(
                    "venom-scanner `{module}` re-exports must use exact cfg({expected_cfg}), found {actual_cfg:?}"
                ));
            }
            let mut actual = BTreeSet::new();
            collect_use_names(&item.tree, &mut actual);
            let mut exact_paths = Vec::new();
            let direct_names_only =
                collect_reporting_import_paths(&item.tree, &mut Vec::new(), &mut exact_paths);
            if actual != expected || !direct_names_only {
                violations.push(format!(
                    "venom-scanner `{module}` re-exports must be exactly {expected:?} without aliases or globs, found {actual:?}"
                ));
            }
        },
        _ => violations.push(format!(
            "venom-scanner must declare exactly one public `{module}` re-export with symbols {expected:?}; found {}",
            related_uses.len()
        )),
    }
    Ok(violations)
}

fn private_natural_child_module_violations(
    source: &str,
    module: &str,
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(item) if item.ident == module => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() == 1
        && matches!(modules[0].vis, Visibility::Inherited)
        && modules[0].content.is_none()
        && modules[0].attrs.is_empty()
    {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "venom-scanner `{module}` implementation must remain one private natural external child with no attributes or path redirection"
    )])
}

fn host_surface_cfg_facade_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    for item in &syntax.items {
        let attrs = reporting_item_attributes(item);
        let predicates = cfg_predicates_from_attributes(attrs);
        let mentions_distributed = predicates
            .iter()
            .any(|predicate| predicate.contains("feature=\"distributed\""));
        let mentions_lua = predicates
            .iter()
            .any(|predicate| predicate.contains("feature=\"lua\""));
        if !mentions_distributed && !mentions_lua {
            continue;
        }
        let allowed = match item {
            Item::Mod(module) => {
                matches!(
                    module.ident.to_string().as_str(),
                    "distributed" | "lua_engine" | "lua_config"
                )
            },
            Item::Use(item) => matches!(
                use_tree_root_ident(&item.tree).as_deref(),
                Some("distributed" | "lua_engine" | "lua_config")
            ),
            _ => false,
        };
        if !allowed {
            violations.push(format!(
                "venom-scanner cfg-gated host facade item `{}` is forbidden; only the exact private modules and root re-exports are allowed",
                reporting_item_label(item)
            ));
        }
    }
    Ok(violations)
}

const EXACT_REPORTING_REEXPORTS: &[&str] = &[
    "MAX_RENDERED_REPORT_BYTES",
    "REPORT_DOCUMENT_SCHEMA",
    "ReportError",
    "ReportFormat",
    "ReportGenerator",
];

fn reporting_reexport_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    collect_reporting_cfg_item_violations(&syntax.items, 0, false, &mut violations);
    let mut all_uses = Vec::new();
    collect_recursive_item_uses(&syntax.items, 0, &mut all_uses);
    let mut all_type_aliases = Vec::new();
    collect_recursive_type_aliases(&syntax.items, 0, &mut all_type_aliases);
    let mut aliases: BTreeSet<String> = EXACT_REPORTING_REEXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .chain([
            "ASSESSMENT_REPORT_DOCUMENT_SCHEMA".to_owned(),
            "reporting".to_owned(),
        ])
        .collect();
    let bindings: Vec<_> = all_uses
        .iter()
        .map(|record| {
            let mut bindings = Vec::new();
            collect_use_bindings(&record.item.tree, &mut Vec::new(), &mut bindings);
            bindings
        })
        .collect();
    let type_alias_paths: Vec<_> = all_type_aliases
        .iter()
        .map(|record| collect_type_paths(&record.item.ty))
        .collect();
    let mut related = vec![false; all_uses.len()];
    let mut related_type_aliases = vec![false; all_type_aliases.len()];
    loop {
        let mut changed = false;
        for (index, use_bindings) in bindings.iter().enumerate() {
            if related[index]
                || !use_bindings
                    .iter()
                    .any(|(source, _)| source.iter().any(|segment| aliases.contains(segment)))
            {
                continue;
            }
            related[index] = true;
            changed = true;
            for (_, exposed) in use_bindings {
                aliases.insert(exposed.clone());
            }
        }
        for (index, paths) in type_alias_paths.iter().enumerate() {
            if related_type_aliases[index]
                || !paths
                    .iter()
                    .any(|path| path.iter().any(|segment| aliases.contains(segment)))
            {
                continue;
            }
            related_type_aliases[index] = true;
            changed = true;
            aliases.insert(semantic_ident_name(&all_type_aliases[index].item.ident));
        }
        if !changed {
            break;
        }
    }
    let reporting_uses: Vec<_> = all_uses
        .iter()
        .zip(related)
        .filter_map(|(record, related)| related.then_some(record))
        .collect();
    let expected: BTreeSet<_> = EXACT_REPORTING_REEXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    for (record, related) in all_type_aliases.iter().zip(related_type_aliases) {
        if related {
            violations.push(format!(
                "venom-scanner reporting facade cannot pass through type alias `{}` at inline-module depth {}",
                record.item.ident, record.depth
            ));
        }
    }
    let mut base_count = 0_usize;
    for record in &reporting_uses {
        let item = record.item;
        if record.depth != 0 || !is_public(&item.vis) {
            violations.push(
                "venom-scanner reporting facade cannot pass through private aliases or inline modules"
                    .to_owned(),
            );
        }
        if item.leading_colon.is_some()
            || use_tree_root_ident(&item.tree).as_deref() != Some("reporting")
        {
            violations.push(
                "venom-scanner reporting re-exports must use the exact direct `reporting::{...}` path"
                    .to_owned(),
            );
        }
        let mut actual = BTreeSet::new();
        collect_use_names(&item.tree, &mut actual);
        let actual_cfg = cfg_predicates_from_attributes(&item.attrs);
        if actual == expected {
            base_count += 1;
            let expected_cfg = ["feature=\"reporting\"".to_owned()];
            if actual_cfg != expected_cfg {
                violations.push(format!(
                    "venom-scanner base reporting re-exports must use exact cfg(feature=\"reporting\"), found {actual_cfg:?}"
                ));
            }
        } else {
            violations.push(format!(
                "venom-scanner reporting re-exports must be exactly {expected:?}; assessment-only symbols remain available through the public reporting module, found {actual:?}"
            ));
        }
    }
    if base_count != 1 || reporting_uses.len() != 1 {
        violations.push(format!(
            "venom-scanner must declare exactly one public base reporting re-export; found base={base_count}, total={}",
            reporting_uses.len()
        ));
    }
    Ok(violations)
}

fn collect_reporting_cfg_item_violations(
    items: &[Item],
    depth: usize,
    inherited_reporting_cfg: bool,
    violations: &mut Vec<String>,
) {
    for item in items {
        let reporting_cfg = inherited_reporting_cfg
            || attributes_mention_reporting_cfg(reporting_item_attributes(item));
        if reporting_cfg {
            let exact_root_item = depth == 0
                && match item {
                    Item::Mod(module) => is_exact_reporting_module(module),
                    Item::Use(item) => is_exact_reporting_reexport(item),
                    _ => false,
                };
            if !exact_root_item {
                violations.push(format!(
                    "venom-scanner cfg(reporting) facade item `{}` at inline-module depth {depth} is forbidden; only the exact root module and five-symbol base re-export are allowed",
                    reporting_item_label(item)
                ));
            }
        }
        if let Item::Mod(module) = item {
            if let Some((_, nested)) = &module.content {
                collect_reporting_cfg_item_violations(nested, depth + 1, reporting_cfg, violations);
            }
        }
    }
}

fn attributes_mention_reporting_cfg(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let path = reporting_syn_path_key(attribute.path());
        if path != "cfg" && path != "cfg_attr" {
            return false;
        }
        match &attribute.meta {
            Meta::List(list) => token_stream_mentions_reporting(&list.tokens),
            _ => false,
        }
    })
}

fn token_stream_mentions_reporting(tokens: &TokenStream) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        TokenTree::Group(group) => token_stream_mentions_reporting(&group.stream()),
        TokenTree::Ident(identifier) => semantic_ident_name(&identifier) == "reporting",
        TokenTree::Literal(literal) => syn::parse_str::<syn::LitStr>(&literal.to_string())
            .is_ok_and(|literal| literal.value() == "reporting"),
        TokenTree::Punct(_) => false,
    })
}

fn reporting_item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn reporting_item_label(item: &Item) -> String {
    match item {
        Item::Const(item) => format!("const {}", item.ident),
        Item::Enum(item) => format!("enum {}", item.ident),
        Item::ExternCrate(item) => format!("extern crate {}", item.ident),
        Item::Fn(item) => format!("fn {}", item.sig.ident),
        Item::ForeignMod(_) => "foreign module".to_owned(),
        Item::Impl(_) => "impl".to_owned(),
        Item::Macro(item) => item.ident.as_ref().map_or_else(
            || "macro invocation".to_owned(),
            |ident| format!("macro {ident}"),
        ),
        Item::Mod(item) => format!("mod {}", item.ident),
        Item::Static(item) => format!("static {}", item.ident),
        Item::Struct(item) => format!("struct {}", item.ident),
        Item::Trait(item) => format!("trait {}", item.ident),
        Item::TraitAlias(item) => format!("trait alias {}", item.ident),
        Item::Type(item) => format!("type {}", item.ident),
        Item::Union(item) => format!("union {}", item.ident),
        Item::Use(_) => "use".to_owned(),
        _ => "unknown item".to_owned(),
    }
}

fn is_exact_reporting_module(module: &ItemMod) -> bool {
    let non_doc_attributes: Vec<_> = module
        .attrs
        .iter()
        .filter(|attribute| !attribute.path().is_ident("doc"))
        .collect();
    module.ident == "reporting"
        && is_public(&module.vis)
        && module.content.is_none()
        && non_doc_attributes.len() == 1
        && non_doc_attributes[0].path().is_ident("cfg")
        && cfg_predicate(non_doc_attributes[0]).as_deref() == Some("feature=\"reporting\"")
}

fn is_exact_reporting_reexport(item: &syn::ItemUse) -> bool {
    let non_doc_attributes: Vec<_> = item
        .attrs
        .iter()
        .filter(|attribute| !attribute.path().is_ident("doc"))
        .collect();
    let mut names = BTreeSet::new();
    collect_use_names(&item.tree, &mut names);
    let expected: BTreeSet<_> = EXACT_REPORTING_REEXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let cfg = cfg_predicates_from_attributes(&item.attrs);
    let contract_is_exact = names == expected && cfg == ["feature=\"reporting\"".to_owned()];
    is_public(&item.vis)
        && item.leading_colon.is_none()
        && use_tree_root_ident(&item.tree).as_deref() == Some("reporting")
        && contract_is_exact
        && non_doc_attributes.len() == 1
        && non_doc_attributes[0].path().is_ident("cfg")
}

const WHOLE_CRATE_REPORTING_IDENTIFIERS: &[&str] = &[
    "ASSESSMENT_REPORT_DOCUMENT_SCHEMA",
    "MAX_RENDERED_REPORT_BYTES",
    "REPORT_DOCUMENT_SCHEMA",
    "ReportError",
    "ReportFormat",
    "ReportGenerator",
    "reporting",
];

const ALLOWED_QUALIFIED_SCANNER_MACROS: &[&str] = &[
    "serde_json::json",
    "tokio::join",
    "tokio::pin",
    "tokio::select",
    "tokio::try_join",
];

const ALLOWED_IMPORTED_SCANNER_MACROS: &[(&str, &str)] =
    &[("html5ever::ns", "ns"), ("serde_json::json", "json")];

fn reporting_whole_crate_closure_violations(
    scanner_source: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut files = Vec::new();
    collect_scanner_rust_sources(scanner_source, &mut files)?;
    files.sort();
    let mut sources = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(scanner_source)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "reporting.rs" {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        sources.push((relative, source));
    }
    Ok(reporting_cross_source_set_violations_with_inventory(
        &sources, true,
    )?)
}

fn collect_scanner_rust_sources(
    directory: &Path,
    files: &mut Vec<std::path::PathBuf>,
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_scanner_rust_sources(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
fn reporting_cross_file_source_violations(
    relative_path: &str,
    source: &str,
) -> Result<Vec<String>, syn::Error> {
    reporting_cross_source_set_violations(&[(relative_path.to_owned(), source.to_owned())])
}

#[cfg(test)]
fn reporting_cross_source_set_violations(
    sources: &[(String, String)],
) -> Result<Vec<String>, syn::Error> {
    reporting_cross_source_set_violations_with_inventory(sources, false)
}

fn reporting_cross_source_set_violations_with_inventory(
    sources: &[(String, String)],
    enforce_internal_reporting_cfg_inventory: bool,
) -> Result<Vec<String>, syn::Error> {
    let parsed: Vec<_> = sources
        .iter()
        .map(|(path, source)| syn::parse_file(source).map(|syntax| (path, syntax)))
        .collect::<Result<_, _>>()?;
    let run_report_aliases = collect_run_report_aliases(&parsed);
    let mut violations = Vec::new();
    for (relative_path, syntax) in parsed {
        if relative_path == "web_runtime/web_assessment_tests.rs" {
            continue;
        }
        let imported_macro_bindings = collect_production_use_bindings(&syntax);
        let mut visitor = ReportingCrossFileVisitor {
            relative_path,
            run_report_aliases: &run_report_aliases,
            imported_macro_bindings: &imported_macro_bindings,
            public_trait_depth: 0,
            internal_reporting_cfg_count: 0,
            violations: BTreeSet::new(),
        };
        if relative_path == "lib.rs" {
            for item in &syntax.items {
                let exact_reporting_item = match item {
                    Item::Mod(module) => is_exact_reporting_module(module),
                    Item::Use(item) => is_exact_reporting_reexport(item),
                    _ => false,
                };
                if !exact_reporting_item {
                    visitor.visit_item(item);
                }
            }
        } else {
            visitor.visit_file(&syntax);
        }
        if enforce_internal_reporting_cfg_inventory {
            let expected = match relative_path.as_str() {
                "web_runtime.rs" => Some(2),
                "web_runtime/assessment_item.rs" => Some(7),
                "web_runtime/web_assessment.rs" => Some(7),
                _ => None,
            };
            if let Some(expected) = expected {
                if visitor.internal_reporting_cfg_count != expected {
                    visitor.violations.insert(format!(
                        "venom-scanner reporting authority must remain in reporting.rs and the exact lib.rs facade; {relative_path} must retain its exact report-only cfg inventory of {expected} sites, found {}",
                        visitor.internal_reporting_cfg_count,
                    ));
                }
            }
        }
        violations.extend(visitor.violations);
    }
    Ok(violations)
}

#[derive(Default)]
struct ProductionUseBindingCollector {
    bindings: BTreeMap<String, BTreeSet<String>>,
}

impl<'ast> Visit<'ast> for ProductionUseBindingCollector {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut bindings = Vec::new();
        collect_use_bindings(&item.tree, &mut Vec::new(), &mut bindings);
        for (source, exposed) in bindings {
            if matches!(exposed.as_str(), "*" | "self") {
                continue;
            }
            self.bindings
                .entry(exposed)
                .or_default()
                .insert(source.join("::"));
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if is_exact_test_module(item) {
            return;
        }
        syn::visit::visit_item_mod(self, item);
    }
}

fn collect_production_use_bindings(syntax: &syn::File) -> BTreeMap<String, BTreeSet<String>> {
    let mut collector = ProductionUseBindingCollector::default();
    collector.visit_file(syntax);
    collector.bindings
}

fn is_exact_test_module(item: &syn::ItemMod) -> bool {
    let cfg_attributes: Vec<_> = item
        .attrs
        .iter()
        .filter(|attribute| {
            matches!(
                reporting_syn_path_key(attribute.path()).as_str(),
                "cfg" | "cfg_attr"
            )
        })
        .collect();
    cfg_attributes.len() == 1
        && reporting_syn_path_key(cfg_attributes[0].path()) == "cfg"
        && cfg_predicate(cfg_attributes[0]).as_deref() == Some("test")
}

fn collect_run_report_aliases(parsed: &[(&String, syn::File)]) -> BTreeSet<String> {
    let mut aliases = BTreeSet::from(["RunReport".to_owned()]);
    let mut use_bindings = Vec::new();
    let mut type_aliases = Vec::new();
    for (_, syntax) in parsed {
        let mut uses = Vec::new();
        collect_recursive_item_uses(&syntax.items, 0, &mut uses);
        use_bindings.extend(uses.into_iter().map(|record| {
            let mut bindings = Vec::new();
            collect_use_bindings(&record.item.tree, &mut Vec::new(), &mut bindings);
            bindings
        }));
        let mut types = Vec::new();
        collect_recursive_type_aliases(&syntax.items, 0, &mut types);
        type_aliases.extend(types.into_iter().map(|record| {
            (
                semantic_ident_name(&record.item.ident),
                collect_type_paths(&record.item.ty),
            )
        }));
    }
    loop {
        let mut changed = false;
        for bindings in &use_bindings {
            for (source, exposed) in bindings {
                if source.iter().any(|segment| aliases.contains(segment)) {
                    changed |= aliases.insert(exposed.clone());
                }
            }
        }
        for (exposed, paths) in &type_aliases {
            if paths
                .iter()
                .any(|path| path.iter().any(|segment| aliases.contains(segment)))
            {
                changed |= aliases.insert(exposed.clone());
            }
        }
        if !changed {
            break;
        }
    }
    aliases
}

fn type_contains_run_report(ty: &syn::Type, aliases: &BTreeSet<String>) -> bool {
    let mut visitor = RunReportPathVisitor {
        aliases,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

fn generics_contain_run_report(generics: &syn::Generics, aliases: &BTreeSet<String>) -> bool {
    let mut visitor = RunReportPathVisitor {
        aliases,
        found: false,
    };
    visitor.visit_generics(generics);
    visitor.found
}

struct RunReportPathVisitor<'a> {
    aliases: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for RunReportPathVisitor<'_> {
    fn visit_path(&mut self, path: &'ast SynPath) {
        if path
            .segments
            .iter()
            .any(|segment| self.aliases.contains(&semantic_ident_name(&segment.ident)))
        {
            self.found = true;
        }
        syn::visit::visit_path(self, path);
    }
}

fn type_exposes_run_report_callable(ty: &syn::Type, aliases: &BTreeSet<String>) -> bool {
    let mut visitor = RunReportCallableVisitor {
        aliases,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

struct RunReportCallableVisitor<'a> {
    aliases: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for RunReportCallableVisitor<'_> {
    fn visit_type_bare_fn(&mut self, function: &'ast syn::TypeBareFn) {
        if function
            .inputs
            .iter()
            .any(|input| type_contains_run_report(&input.ty, self.aliases))
        {
            self.found = true;
        }
        syn::visit::visit_type_bare_fn(self, function);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        for segment in &path.segments {
            if !matches!(
                semantic_ident_name(&segment.ident).as_str(),
                "Fn" | "FnMut" | "FnOnce"
            ) {
                continue;
            }
            match &segment.arguments {
                syn::PathArguments::Parenthesized(arguments)
                    if arguments
                        .inputs
                        .iter()
                        .any(|input| type_contains_run_report(input, self.aliases)) =>
                {
                    self.found = true;
                },
                syn::PathArguments::AngleBracketed(arguments)
                    if arguments.args.iter().any(|argument| {
                        matches!(
                            argument,
                            syn::GenericArgument::Type(ty)
                                if type_contains_run_report(ty, self.aliases)
                        )
                    }) =>
                {
                    self.found = true;
                },
                _ => {},
            }
        }
        syn::visit::visit_path(self, path);
    }
}

fn signature_exposes_run_report_consumer(
    signature: &syn::Signature,
    aliases: &BTreeSet<String>,
) -> bool {
    signature.inputs.iter().any(|input| match input {
        syn::FnArg::Receiver(receiver) => {
            receiver.colon_token.is_some() && type_contains_run_report(&receiver.ty, aliases)
        },
        syn::FnArg::Typed(input) => type_contains_run_report(&input.ty, aliases),
    }) || generics_contain_run_report(&signature.generics, aliases)
        || match &signature.output {
            syn::ReturnType::Default => false,
            syn::ReturnType::Type(_, ty) => type_exposes_run_report_callable(ty, aliases),
        }
}

fn fields_expose_run_report_callable(
    fields: &Fields,
    aliases: &BTreeSet<String>,
    enum_fields_are_public: bool,
) -> bool {
    fields.iter().any(|field| {
        (enum_fields_are_public || is_public(&field.vis))
            && type_exposes_run_report_callable(&field.ty, aliases)
    })
}

fn bounds_expose_run_report_callable(
    bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::token::Plus>,
    aliases: &BTreeSet<String>,
) -> bool {
    let mut visitor = RunReportCallableVisitor {
        aliases,
        found: false,
    };
    for bound in bounds {
        visitor.visit_type_param_bound(bound);
    }
    visitor.found
}

struct ReportingCrossFileVisitor<'a> {
    relative_path: &'a str,
    run_report_aliases: &'a BTreeSet<String>,
    imported_macro_bindings: &'a BTreeMap<String, BTreeSet<String>>,
    public_trait_depth: usize,
    internal_reporting_cfg_count: usize,
    violations: BTreeSet<String>,
}

impl ReportingCrossFileVisitor<'_> {
    fn insert(&mut self, detail: impl std::fmt::Display) {
        self.violations.insert(format!(
            "venom-scanner reporting authority must remain in reporting.rs and the exact lib.rs facade; {} contains {detail}",
            self.relative_path
        ));
    }
}

impl<'ast> Visit<'ast> for ReportingCrossFileVisitor<'_> {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let externally_callable = is_public(&item.vis) || is_pub_crate(&item.vis);
        let test_only = cfg_predicates_from_attributes(&item.attrs)
            .iter()
            .any(|predicate| predicate == "test");
        if externally_callable
            && !test_only
            && signature_exposes_run_report_consumer(&item.sig, self.run_report_aliases)
        {
            let authority = if is_public(&item.vis) {
                "public function"
            } else {
                "crate-callable function"
            };
            self.insert(format_args!(
                "{authority} `{}` that consumes or exports a callable over RunReport",
                item.sig.ident
            ));
        }
        if is_public(&item.vis) && signature_mentions_type(&item.sig, "AssessmentRunReport") {
            self.insert(format_args!(
                "public function `{}` that exposes AssessmentRunReport outside reporting.rs",
                item.sig.ident
            ));
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        for member in &item.items {
            let ImplItem::Fn(method) = member else {
                continue;
            };
            if is_assessment_run_report_bridge_candidate(item, method)
                && !is_exact_assessment_run_report_bridge(self.relative_path, item, method)
            {
                self.insert(
                    "WebAssessmentRunReport::into_assessment_report must remain the exact crate-private consuming truth bridge",
                );
            }
            let externally_callable =
                item.trait_.is_some() || is_public(&method.vis) || is_pub_crate(&method.vis);
            let test_only = cfg_predicates_from_attributes(&method.attrs)
                .iter()
                .any(|predicate| predicate == "test");
            if externally_callable
                && !test_only
                && signature_exposes_run_report_consumer(&method.sig, self.run_report_aliases)
            {
                let authority = if item.trait_.is_some() || is_public(&method.vis) {
                    "publicly callable method"
                } else {
                    "crate-callable method"
                };
                self.insert(format_args!(
                    "{authority} `{}` that consumes or exports a callable over RunReport",
                    method.sig.ident
                ));
            }
            if (item.trait_.is_some() || is_public(&method.vis))
                && signature_mentions_type(&method.sig, "AssessmentRunReport")
            {
                self.insert(format_args!(
                    "publicly callable method `{}` that exposes AssessmentRunReport outside reporting.rs",
                    method.sig.ident
                ));
            }
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if is_public(&item.vis) {
            if bounds_expose_run_report_callable(&item.supertraits, self.run_report_aliases) {
                self.insert(format_args!(
                    "public trait `{}` with a callable RunReport input",
                    item.ident
                ));
            }
            self.public_trait_depth += 1;
            syn::visit::visit_item_trait(self, item);
            self.public_trait_depth -= 1;
            return;
        }
        syn::visit::visit_item_trait(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if self.public_trait_depth != 0
            && signature_exposes_run_report_consumer(&item.sig, self.run_report_aliases)
        {
            self.insert(format_args!(
                "public trait method `{}` that consumes or exports a callable over RunReport",
                item.sig.ident
            ));
        }
        syn::visit::visit_trait_item_fn(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if is_public(&item.vis)
            && (type_exposes_run_report_callable(&item.ty, self.run_report_aliases)
                || generics_contain_run_report(&item.generics, self.run_report_aliases))
        {
            self.insert(format_args!(
                "public callable type alias `{}` over RunReport",
                item.ident
            ));
        }
        syn::visit::visit_item_type(self, item);
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if is_public(&item.vis)
            && type_exposes_run_report_callable(&item.ty, self.run_report_aliases)
        {
            self.insert(format_args!(
                "public callable const `{}` over RunReport",
                item.ident
            ));
        }
        syn::visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if is_public(&item.vis)
            && type_exposes_run_report_callable(&item.ty, self.run_report_aliases)
        {
            self.insert(format_args!(
                "public callable static `{}` over RunReport",
                item.ident
            ));
        }
        syn::visit::visit_item_static(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if is_public(&item.vis)
            && (fields_expose_run_report_callable(&item.fields, self.run_report_aliases, false)
                || generics_contain_run_report(&item.generics, self.run_report_aliases))
        {
            self.insert(format_args!(
                "public struct `{}` with a callable RunReport input",
                item.ident
            ));
        }
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if is_public(&item.vis)
            && (item.variants.iter().any(|variant| {
                fields_expose_run_report_callable(&variant.fields, self.run_report_aliases, true)
            }) || generics_contain_run_report(&item.generics, self.run_report_aliases))
        {
            self.insert(format_args!(
                "public enum `{}` with a callable RunReport input",
                item.ident
            ));
        }
        syn::visit::visit_item_enum(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        if is_public(&item.vis)
            && (item.fields.named.iter().any(|field| {
                is_public(&field.vis)
                    && type_exposes_run_report_callable(&field.ty, self.run_report_aliases)
            }) || generics_contain_run_report(&item.generics, self.run_report_aliases))
        {
            self.insert(format_args!(
                "public union `{}` with a callable RunReport input",
                item.ident
            ));
        }
        syn::visit::visit_item_union(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if is_exact_test_module(item) {
            return;
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        let predicate = cfg_predicate(attribute);
        let internal_predicate = predicate.as_deref() == Some("feature=\"reporting\"")
            || (self.relative_path == "web_runtime/assessment_item.rs"
                && predicate.as_deref() == Some("any(feature=\"reporting\",test)"));
        let internal_report_cfg = matches!(
            self.relative_path,
            "web_runtime.rs" | "web_runtime/assessment_item.rs" | "web_runtime/web_assessment.rs"
        ) && attribute.path().is_ident("cfg")
            && internal_predicate;
        if internal_report_cfg {
            self.internal_reporting_cfg_count += 1;
            return;
        }
        if attributes_mention_reporting_cfg(std::slice::from_ref(attribute)) {
            self.insert("a cfg/cfg_attr predicate that enables `reporting`");
        }
        let path = reporting_syn_path_key(attribute.path());
        if path == "macro_use" {
            self.insert("a production `#[macro_use]` macro import");
        }
        if path == "path" {
            self.insert("a production `#[path]` source indirection");
        }
        if path != "doc" {
            if let Meta::List(list) = &attribute.meta {
                for identifier in reporting_macro_token_identifiers(&list.tokens) {
                    self.insert(format_args!(
                        "reporting identifier `{identifier}` inside attribute tokens"
                    ));
                }
            }
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_ident(&mut self, identifier: &'ast syn::Ident) {
        let name = semantic_ident_name(identifier);
        if WHOLE_CRATE_REPORTING_IDENTIFIERS.contains(&name.as_str()) {
            self.insert(format_args!("reporting identifier `{name}`"));
        }
        syn::visit::visit_ident(self, identifier);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        let path = reporting_syn_path_key(&item.path);
        if !path.contains("::") {
            if let Some(sources) = self.imported_macro_bindings.get(&path) {
                let trusted = sources.len() == 1
                    && sources.iter().all(|source| {
                        ALLOWED_IMPORTED_SCANNER_MACROS.contains(&(source.as_str(), path.as_str()))
                    });
                if !trusted {
                    self.insert(format_args!(
                        "unclassified imported macro invocation `{path}!` from {}",
                        sources.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }
        if path.contains("::") && !ALLOWED_QUALIFIED_SCANNER_MACROS.contains(&path.as_str()) {
            self.insert(format_args!(
                "unclassified qualified macro invocation `{path}!`"
            ));
        }
        if path == "include" {
            self.insert("a production `include!` source indirection");
        }
        for identifier in reporting_macro_token_identifiers(&item.tokens) {
            self.insert(format_args!(
                "reporting identifier `{identifier}` inside `{path}!` tokens"
            ));
        }
        syn::visit::visit_macro(self, item);
    }
}

fn signature_mentions_type(signature: &syn::Signature, expected: &str) -> bool {
    struct NamedTypeVisitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for NamedTypeVisitor<'_> {
        fn visit_path(&mut self, path: &'ast SynPath) {
            self.found |= path
                .segments
                .iter()
                .any(|segment| semantic_ident_name(&segment.ident) == self.expected);
            if !self.found {
                syn::visit::visit_path(self, path);
            }
        }
    }
    let mut visitor = NamedTypeVisitor {
        expected,
        found: false,
    };
    visitor.visit_signature(signature);
    visitor.found
}

fn has_exact_reporting_cfg(attributes: &[Attribute]) -> bool {
    attributes.iter().all(|attribute| {
        attribute.path().is_ident("doc")
            || (attribute.path().is_ident("cfg")
                && cfg_predicate(attribute).as_deref() == Some("feature=\"reporting\""))
    }) && attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .count()
        == 1
}

fn is_exact_assessment_run_report_bridge(
    relative_path: &str,
    item_impl: &syn::ItemImpl,
    method: &syn::ImplItemFn,
) -> bool {
    if relative_path != "web_runtime/web_assessment.rs"
        || !is_assessment_run_report_bridge_candidate(item_impl, method)
    {
        return false;
    }
    is_exact_assessment_run_report_bridge_method(relative_path, method)
}

fn is_exact_assessment_run_report_bridge_method(
    relative_path: &str,
    method: &syn::ImplItemFn,
) -> bool {
    if relative_path != "web_runtime/web_assessment.rs"
        || method.sig.ident != "into_assessment_report"
        || !is_pub_crate(&method.vis)
        || !has_exact_reporting_cfg(&method.attrs)
        || method.sig.inputs.len() != 2
    {
        return false;
    }
    let mut inputs = method.sig.inputs.iter();
    let receiver_is_consuming = matches!(inputs.next(), Some(syn::FnArg::Receiver(receiver))
        if receiver.reference.is_none()
            && receiver.mutability.is_none()
            && receiver.colon_token.is_none());
    let profile_is_exact = matches!(inputs.next(), Some(syn::FnArg::Typed(argument))
        if simple_type_path(&argument.ty, "ScanProfileV1").is_some());
    receiver_is_consuming
        && profile_is_exact
        && assessment_bridge_return_is_exact(&method.sig.output)
        && assessment_bridge_body_is_exact(&method.block)
}

fn is_web_assessment_run_report_impl(item_impl: &syn::ItemImpl) -> bool {
    item_impl.trait_.is_none()
        && matches!(item_impl.self_ty.as_ref(), syn::Type::Path(path)
            if path.qself.is_none()
                && path.path.segments.last().is_some_and(|segment|
                    semantic_ident_name(&segment.ident) == "WebAssessmentRunReport"))
}

fn is_assessment_run_report_bridge_candidate(
    item_impl: &syn::ItemImpl,
    method: &syn::ImplItemFn,
) -> bool {
    is_web_assessment_run_report_impl(item_impl) && method.sig.ident == "into_assessment_report"
}

fn is_pub_crate(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Restricted(restricted)
        if restricted.in_token.is_none() && restricted.path.is_ident("crate"))
}

fn assessment_bridge_return_is_exact(output: &syn::ReturnType) -> bool {
    let syn::ReturnType::Type(_, item_type) = output else {
        return false;
    };
    let syn::Type::Path(path) = item_type.as_ref() else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let types = arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(item_type) => Some(item_type),
            _ => None,
        })
        .collect::<Vec<_>>();
    segment.ident == "Result"
        && arguments.args.len() == 2
        && types.len() == 2
        && simple_type_path(types[0], "AssessmentRunReport").is_some()
        && simple_type_path(types[1], "AssessmentRunReportError").is_some()
}

fn assessment_bridge_body_is_exact(block: &syn::Block) -> bool {
    if block.stmts.len() != 2 {
        return false;
    }

    let syn::Stmt::Local(truth_local) = &block.stmts[0] else {
        return false;
    };
    if !matches!(&truth_local.pat, syn::Pat::Ident(pattern)
        if pattern.ident == "truth"
            && pattern.by_ref.is_none()
            && pattern.mutability.is_none()
            && pattern.subpat.is_none())
        || truth_local
            .init
            .as_ref()
            .is_none_or(|init| init.diverge.is_some())
    {
        return false;
    }
    let Some(truth_init) = truth_local.init.as_ref() else {
        return false;
    };
    let syn::Expr::Try(tried) = truth_init.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Call(truth_call) = tried.expr.as_ref() else {
        return false;
    };
    if reporting_expression_path_key(truth_call.func.as_ref()).as_deref()
        != Some("CompletedWebAssessmentTruth::new")
        || truth_call.args.len() != 7
    {
        return false;
    }
    let mut truth_arguments = truth_call.args.iter();
    let truth_is_exact = truth_arguments
        .next()
        .is_some_and(|argument| assessment_bridge_self_field(argument, "run_started_at"))
        && truth_arguments.next().is_some_and(|argument| {
            assessment_bridge_borrowed_self_field(argument, "authorized_root")
        })
        && truth_arguments
            .next()
            .is_some_and(|argument| assessment_bridge_self_field(argument, "limits"))
        && truth_arguments
            .next()
            .is_some_and(|argument| assessment_bridge_self_field(argument, "usage"))
        && truth_arguments
            .next()
            .is_some_and(|argument| assessment_bridge_borrowed_self_field(argument, "completion"))
        && truth_arguments
            .next()
            .is_some_and(assessment_bridge_exact_defense_mode)
        && truth_arguments.next().is_some_and(|argument| {
            reporting_expression_path_key(argument).as_deref() == Some("profile")
        });
    if !truth_is_exact {
        return false;
    }

    let syn::Stmt::Expr(syn::Expr::Call(report_call), None) = &block.stmts[1] else {
        return false;
    };
    if reporting_expression_path_key(report_call.func.as_ref()).as_deref()
        != Some("AssessmentRunReport::from_completed_truth")
        || report_call.args.len() != 2
    {
        return false;
    }
    let mut arguments = report_call.args.iter();
    arguments
        .next()
        .is_some_and(|argument| assessment_bridge_self_field(argument, "assessment_items"))
        && reporting_expression_path_key(arguments.next().expect("checked length")).as_deref()
            == Some("truth")
}

fn assessment_bridge_self_field(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Field(field)
        if reporting_expression_path_key(field.base.as_ref()).as_deref() == Some("self")
            && matches!(&field.member, syn::Member::Named(member)
                if semantic_ident_name(member) == expected))
}

fn assessment_bridge_borrowed_self_field(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Reference(reference)
        if reference.mutability.is_none()
            && assessment_bridge_self_field(reference.expr.as_ref(), expected))
}

fn assessment_bridge_exact_defense_mode(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::MethodCall(call)
        if call.method == "mode"
            && call.args.is_empty()
            && assessment_bridge_self_field(call.receiver.as_ref(), "defense"))
}

fn reporting_macro_token_identifiers(tokens: &TokenStream) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::new();
    for token in tokens.clone() {
        match token {
            TokenTree::Group(group) => {
                identifiers.extend(reporting_macro_token_identifiers(&group.stream()));
            },
            TokenTree::Ident(identifier) => {
                let identifier = semantic_ident_name(&identifier);
                if WHOLE_CRATE_REPORTING_IDENTIFIERS.contains(&identifier.as_str()) {
                    identifiers.insert(identifier);
                }
            },
            TokenTree::Literal(literal) => {
                if let Ok(literal) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    let value = literal.value();
                    for identifier in WHOLE_CRATE_REPORTING_IDENTIFIERS {
                        if value.contains(identifier) {
                            identifiers.insert((*identifier).to_owned());
                        }
                    }
                }
            },
            TokenTree::Punct(_) => {},
        }
    }
    identifiers
}

fn semantic_ident_name(identifier: &syn::Ident) -> String {
    let name = identifier.to_string();
    name.strip_prefix("r#").unwrap_or(&name).to_owned()
}

struct RecursiveUseRecord<'a> {
    item: &'a syn::ItemUse,
    depth: usize,
}

struct RecursiveTypeAliasRecord<'a> {
    item: &'a syn::ItemType,
    depth: usize,
}

fn collect_recursive_item_uses<'a>(
    items: &'a [Item],
    depth: usize,
    uses: &mut Vec<RecursiveUseRecord<'a>>,
) {
    for item in items {
        match item {
            Item::Use(item) => uses.push(RecursiveUseRecord { item, depth }),
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_recursive_item_uses(items, depth + 1, uses);
                }
            },
            _ => {},
        }
    }
}

fn collect_recursive_type_aliases<'a>(
    items: &'a [Item],
    depth: usize,
    aliases: &mut Vec<RecursiveTypeAliasRecord<'a>>,
) {
    for item in items {
        match item {
            Item::Type(item) => aliases.push(RecursiveTypeAliasRecord { item, depth }),
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_recursive_type_aliases(items, depth + 1, aliases);
                }
            },
            _ => {},
        }
    }
}

#[derive(Default)]
struct TypePathCollector {
    paths: Vec<Vec<String>>,
}

impl<'ast> Visit<'ast> for TypePathCollector {
    fn visit_path(&mut self, path: &'ast SynPath) {
        self.paths.push(
            path.segments
                .iter()
                .map(|segment| semantic_ident_name(&segment.ident))
                .collect(),
        );
        syn::visit::visit_path(self, path);
    }
}

fn collect_type_paths(ty: &syn::Type) -> Vec<Vec<String>> {
    let mut collector = TypePathCollector::default();
    collector.visit_type(ty);
    collector.paths
}

fn collect_use_bindings(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    bindings: &mut Vec<(Vec<String>, String)>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(semantic_ident_name(&path.ident));
            collect_use_bindings(&path.tree, prefix, bindings);
            prefix.pop();
        },
        UseTree::Name(name) => {
            let exposed = semantic_ident_name(&name.ident);
            if exposed != "self" {
                prefix.push(exposed.clone());
            }
            bindings.push((prefix.clone(), exposed));
            if semantic_ident_name(&name.ident) != "self" {
                prefix.pop();
            }
        },
        UseTree::Rename(rename) => {
            prefix.push(semantic_ident_name(&rename.ident));
            bindings.push((prefix.clone(), semantic_ident_name(&rename.rename)));
            prefix.pop();
        },
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_bindings(item, prefix, bindings);
            }
        },
        UseTree::Glob(_) => bindings.push((prefix.clone(), "*".to_owned())),
    }
}

fn use_tree_root_ident(tree: &UseTree) -> Option<String> {
    match tree {
        UseTree::Name(name) => Some(semantic_ident_name(&name.ident)),
        UseTree::Path(path) => Some(semantic_ident_name(&path.ident)),
        UseTree::Rename(rename) => Some(semantic_ident_name(&rename.ident)),
        UseTree::Glob(_) | UseTree::Group(_) => None,
    }
}

const EXACT_REPORTING_PUBLIC_ITEMS: &[(&str, &str)] = &[
    ("ASSESSMENT_REPORT_DOCUMENT_SCHEMA", "const"),
    ("MAX_RENDERED_REPORT_BYTES", "const"),
    ("REPORT_DOCUMENT_SCHEMA", "const"),
    ("ReportError", "enum"),
    ("ReportFormat", "enum"),
    ("ReportGenerator", "struct"),
];

const EXACT_REPORTING_INHERENT_METHODS: &[(&str, &[&str])] = &[
    ("ReportFormat", &["as_str", "extension", "media_type"]),
    (
        "ReportGenerator",
        &[
            "available_formats",
            "compose_assessment",
            "generate",
            "generate_assessment",
        ],
    ),
];

const EXACT_REPORTING_PUBLIC_TRAIT_IMPLS: &[(&str, &str)] =
    &[("ReportError", "fmt::Display"), ("ReportError", "Error")];

type ReportingDocumentField = (&'static str, &'static str);
type ReportingDocumentShape = (
    &'static str,
    &'static [&'static str],
    &'static [ReportingDocumentField],
);

const EXACT_REPORTING_DOCUMENT_STRUCTS: &[ReportingDocumentShape] = &[
    (
        "AssessmentDocument",
        &["a"],
        &[
            ("schema", "&'static str"),
            ("source_schema", "&'a str"),
            ("run_schema", "&'a str"),
            ("profile_schema", "&'a str"),
            ("profile", "&'a str"),
            ("status", "&'static str"),
            ("subject_count", "u64"),
            ("item_count", "u64"),
            ("items", "Vec<AssessmentItemDocument<'a>>"),
        ],
    ),
    (
        "AssessmentItemDocument",
        &["a"],
        &[
            ("schema", "&'a str"),
            ("capability_id", "&'a str"),
            ("subject_reference", "String"),
            ("title", "&'a str"),
            ("disposition", "&'static str"),
            ("claim_basis", "&'static str"),
            ("severity", "Option<&'static str>"),
            ("confidence_ppm", "u32"),
            ("fingerprint", "&'a str"),
            ("evidence_count", "u64"),
            ("redacted_summary", "&'a str"),
            ("category", "&'a str"),
            ("cwe", "Option<&'a str>"),
            ("remediation", "AssessmentRemediationDocument<'a>"),
            ("evidence_references", "Vec<String>"),
            ("control_evidence_references", "Vec<String>"),
            ("candidate_evidence_references", "Vec<String>"),
            ("case_reference", "Option<String>"),
            ("outcome_reference", "Option<String>"),
            ("verification_stage", "Option<&'static str>"),
        ],
    ),
    (
        "AssessmentBasisLinkageDocument",
        &[],
        &[
            ("evidence_references", "Vec<String>"),
            ("control_evidence_references", "Vec<String>"),
            ("candidate_evidence_references", "Vec<String>"),
            ("case_reference", "Option<String>"),
            ("outcome_reference", "Option<String>"),
            ("verification_stage", "Option<&'static str>"),
        ],
    ),
    (
        "AssessmentRemediationDocument",
        &["a"],
        &[("id", "&'a str"), ("summary", "&'a str")],
    ),
    (
        "ReportDocument",
        &["a"],
        &[
            ("schema", "&'static str"),
            ("source_schema", "&'a str"),
            ("status", "&'static str"),
            ("stop_code", "&'static str"),
            ("target", "&'a str"),
            ("authorized_origin", "&'a str"),
            ("started_at", "String"),
            ("completed_at", "String"),
            ("accounting", "AccountingDocument"),
            ("steps", "Vec<StepDocument<'a>>"),
            ("outcomes", "Vec<OutcomeDocument<'a>>"),
        ],
    ),
    (
        "AccountingDocument",
        &[],
        &[
            ("requests", "AccountingDimension"),
            ("response_body_bytes", "AccountingDimension"),
            ("request_body_bytes", "AccountingDimension"),
            ("wall_time_ms", "AccountingDimension"),
        ],
    ),
    (
        "AccountingDimension",
        &[],
        &[
            ("mode", "&'static str"),
            ("limit", "Option<String>"),
            ("consumed", "Option<String>"),
            ("remaining", "Option<String>"),
        ],
    ),
    (
        "StepDocument",
        &["a"],
        &[
            ("ordinal", "u32"),
            ("action_id", "&'a str"),
            ("status", "&'static str"),
            ("duration_ms", "String"),
        ],
    ),
    (
        "OutcomeDocument",
        &["a"],
        &[
            ("kind", "&'static str"),
            ("action_id", "&'a str"),
            ("severity", "&'static str"),
            ("disposition", "&'static str"),
            ("confidence_ppm", "u32"),
            ("evidence_count", "u64"),
            ("redacted_summary", "&'a str"),
        ],
    ),
];

fn reporting_document_contract_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let expected: BTreeMap<_, _> = EXACT_REPORTING_DOCUMENT_STRUCTS
        .iter()
        .map(|(name, lifetimes, fields)| (*name, (*lifetimes, *fields)))
        .collect();
    let mut counts = BTreeMap::<String, usize>::new();
    let mut violations = Vec::new();

    for item in &syntax.items {
        let Item::Struct(item) = item else {
            continue;
        };
        let name = item.ident.to_string();
        let Some((expected_lifetimes, expected_fields)) = expected.get(name.as_str()) else {
            continue;
        };
        *counts.entry(name.clone()).or_default() += 1;
        let assessment_document = matches!(
            name.as_str(),
            "AssessmentDocument"
                | "AssessmentItemDocument"
                | "AssessmentBasisLinkageDocument"
                | "AssessmentRemediationDocument"
        );
        let expected_derives: &[&str] = if name == "AssessmentBasisLinkageDocument" {
            &[]
        } else {
            &["Serialize"]
        };
        let non_cfg_attributes: Vec<_> = item
            .attrs
            .iter()
            .filter(|attribute| {
                !matches!(
                    reporting_syn_path_key(attribute.path()).as_str(),
                    "cfg" | "cfg_attr"
                )
            })
            .cloned()
            .collect();
        if assessment_document {
            let cfg_attributes: Vec<_> = item
                .attrs
                .iter()
                .filter(|attribute| {
                    matches!(
                        reporting_syn_path_key(attribute.path()).as_str(),
                        "cfg" | "cfg_attr"
                    )
                })
                .collect();
            if cfg_attributes.len() != 1
                || !cfg_attributes[0].path().is_ident("cfg")
                || cfg_predicate(cfg_attributes[0]).as_deref() != Some("feature=\"scanning\"")
            {
                violations.push(format!(
                    "reporting private assessment document type `{name}` must have exactly cfg(feature = \"scanning\")"
                ));
            }
        }
        validate_reporting_attributes(
            if assessment_document {
                &non_cfg_attributes
            } else {
                &item.attrs
            },
            expected_derives,
            false,
            &format!("private document type `{name}`"),
            &mut violations,
        );
        let expected_lifetimes: Vec<_> = expected_lifetimes
            .iter()
            .map(|lifetime| (*lifetime).to_owned())
            .collect();
        if !matches!(item.vis, Visibility::Inherited)
            || reporting_lifetime_parameters(&item.generics) != Some(expected_lifetimes)
        {
            violations.push(format!(
                "reporting private document type `{name}` must retain its exact visibility and lifetime parameters"
            ));
        }
        let actual_fields: Option<Vec<_>> = match &item.fields {
            Fields::Named(fields) => fields
                .named
                .iter()
                .map(|field| {
                    if !field.attrs.is_empty() || !matches!(field.vis, Visibility::Inherited) {
                        return None;
                    }
                    Some((
                        field.ident.as_ref()?.to_string(),
                        reporting_type_key(&field.ty)?,
                    ))
                })
                .collect(),
            Fields::Unnamed(_) | Fields::Unit => None,
        };
        let expected_fields: Vec<_> = expected_fields
            .iter()
            .map(|(field, ty)| ((*field).to_owned(), (*ty).to_owned()))
            .collect();
        if actual_fields.as_ref() != Some(&expected_fields) {
            violations.push(format!(
                "reporting private document type `{name}` fields must remain exactly {expected_fields:?}, found {actual_fields:?}"
            ));
        }
    }

    for name in expected.keys() {
        if counts.get(*name).copied().unwrap_or_default() != 1 {
            violations.push(format!(
                "reporting private document type `{name}` must appear exactly once"
            ));
        }
    }
    Ok(violations)
}

fn reporting_lifetime_parameters(generics: &syn::Generics) -> Option<Vec<String>> {
    if generics.where_clause.is_some() {
        return None;
    }
    generics
        .params
        .iter()
        .map(|parameter| match parameter {
            syn::GenericParam::Lifetime(lifetime)
                if lifetime.attrs.is_empty()
                    && lifetime.colon_token.is_none()
                    && lifetime.bounds.is_empty() =>
            {
                Some(lifetime.lifetime.ident.to_string())
            },
            syn::GenericParam::Const(_)
            | syn::GenericParam::Lifetime(_)
            | syn::GenericParam::Type(_) => None,
        })
        .collect()
}

fn reporting_type_key(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(reference) if reference.mutability.is_none() => {
            let lifetime = reference
                .lifetime
                .as_ref()
                .map_or_else(String::new, |lifetime| format!("{lifetime} "));
            Some(format!(
                "&{lifetime}{}",
                reporting_type_key(&reference.elem)?
            ))
        },
        syn::Type::Path(path) if path.qself.is_none() && path.path.leading_colon.is_none() => {
            let mut segments = Vec::new();
            for segment in &path.path.segments {
                let arguments = match &segment.arguments {
                    syn::PathArguments::None => String::new(),
                    syn::PathArguments::AngleBracketed(arguments) => {
                        if arguments.colon2_token.is_some() {
                            return None;
                        }
                        let arguments = arguments
                            .args
                            .iter()
                            .map(|argument| match argument {
                                syn::GenericArgument::Lifetime(lifetime) => {
                                    Some(lifetime.to_string())
                                },
                                syn::GenericArgument::Type(ty) => reporting_type_key(ty),
                                _ => None,
                            })
                            .collect::<Option<Vec<_>>>()?;
                        format!("<{}>", arguments.join(","))
                    },
                    syn::PathArguments::Parenthesized(_) => return None,
                };
                segments.push(format!("{}{arguments}", segment.ident));
            }
            Some(segments.join("::"))
        },
        _ => None,
    }
}

fn reporting_public_api_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let expected_items: BTreeMap<_, _> = EXACT_REPORTING_PUBLIC_ITEMS.iter().copied().collect();
    let expected_methods: BTreeMap<_, BTreeSet<_>> = EXACT_REPORTING_INHERENT_METHODS
        .iter()
        .map(|(owner, methods)| (*owner, methods.iter().copied().collect()))
        .collect();
    let expected_trait_impls: BTreeMap<_, BTreeSet<_>> =
        EXACT_REPORTING_PUBLIC_TRAIT_IMPLS.iter().fold(
            BTreeMap::new(),
            |mut implementations, (owner, trait_name)| {
                implementations
                    .entry(*owner)
                    .or_default()
                    .insert(*trait_name);
                implementations
            },
        );
    let mut actual_items = BTreeMap::<String, Vec<&'static str>>::new();
    let mut actual_methods = BTreeMap::<String, BTreeMap<String, Vec<&syn::Signature>>>::new();
    let mut actual_trait_impls = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut violations = Vec::new();

    for item in &syntax.items {
        match item {
            Item::Const(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "const");
                if item.ident == "ASSESSMENT_REPORT_DOCUMENT_SCHEMA" {
                    if !reporting_scanning_cfg_is_exact(&item.attrs) {
                        violations.push(
                            "reporting public constant `ASSESSMENT_REPORT_DOCUMENT_SCHEMA` must have exactly cfg(feature = \"scanning\") plus documentation"
                                .to_owned(),
                        );
                    }
                } else {
                    validate_reporting_attributes(
                        &item.attrs,
                        &[],
                        false,
                        &format!("public constant `{}`", item.ident),
                        &mut violations,
                    );
                }
                validate_reporting_public_constant(item, &mut violations);
            },
            Item::Enum(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "enum");
                validate_reporting_public_enum(item, &mut violations);
            },
            Item::Struct(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "struct");
                if item.ident == "ReportGenerator" {
                    validate_reporting_attributes(
                        &item.attrs,
                        &["Clone", "Copy", "Debug", "Default"],
                        false,
                        "public type `ReportGenerator`",
                        &mut violations,
                    );
                    if !matches!(item.fields, Fields::Unit) {
                        violations.push(
                            "reporting public `ReportGenerator` must remain a stateless unit struct"
                                .to_owned(),
                        );
                    }
                }
            },
            Item::Fn(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.sig.ident.to_string(), "fn")
            },
            Item::Mod(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "mod")
            },
            Item::Static(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "static")
            },
            Item::Trait(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "trait")
            },
            Item::Type(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "type")
            },
            Item::Union(item) if is_public(&item.vis) => {
                record_reporting_public_item(&mut actual_items, item.ident.to_string(), "union")
            },
            Item::Use(item) if is_public(&item.vis) => {
                let mut names = BTreeSet::new();
                collect_use_names(&item.tree, &mut names);
                for name in names {
                    record_reporting_public_item(&mut actual_items, name, "use");
                }
            },
            Item::ExternCrate(item) if is_public(&item.vis) => record_reporting_public_item(
                &mut actual_items,
                item.rename
                    .as_ref()
                    .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string()),
                "extern crate",
            ),
            Item::Macro(item)
                if item
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("macro_export")) =>
            {
                violations.push(
                    "reporting must not export macros outside its exact public API".to_owned(),
                );
            },
            Item::Impl(item) if item.trait_.is_none() => {
                let owner = reporting_impl_owner(item)
                    .unwrap_or_else(|| "<unrecognized inherent impl>".to_owned());
                if expected_items.contains_key(owner.as_str()) {
                    reject_reporting_cfg_attributes(
                        &item.attrs,
                        &format!("inherent impl for `{owner}`"),
                        &mut violations,
                    );
                }
                for implementation_item in &item.items {
                    match implementation_item {
                        ImplItem::Fn(method) if is_public(&method.vis) => {
                            if owner == "ReportGenerator"
                                && matches!(
                                    method.sig.ident.to_string().as_str(),
                                    "compose_assessment" | "generate_assessment"
                                )
                            {
                                if !reporting_scanning_cfg_is_exact(&method.attrs) {
                                    violations.push(format!(
                                        "reporting public method `ReportGenerator::{}` must have exactly cfg(feature = \"scanning\") plus documentation",
                                        method.sig.ident
                                    ));
                                }
                            } else {
                                reject_reporting_cfg_attributes(
                                    &method.attrs,
                                    &format!("public method `{owner}::{}`", method.sig.ident),
                                    &mut violations,
                                );
                            }
                            validate_reporting_public_method_body(
                                &owner,
                                &method.sig.ident.to_string(),
                                &method.block,
                                &mut violations,
                            );
                            actual_methods
                                .entry(owner.clone())
                                .or_default()
                                .entry(method.sig.ident.to_string())
                                .or_default()
                                .push(&method.sig);
                        },
                        ImplItem::Const(item) if is_public(&item.vis) => violations.push(format!(
                            "reporting must not add public inherent associated const `{}::{}`",
                            owner, item.ident
                        )),
                        ImplItem::Type(item) if is_public(&item.vis) => violations.push(format!(
                            "reporting must not add public inherent associated type `{}::{}`",
                            owner, item.ident
                        )),
                        _ => {},
                    }
                }
            },
            Item::Impl(item) => {
                let Some(owner) = reporting_impl_owner(item) else {
                    continue;
                };
                if !expected_items.contains_key(owner.as_str()) {
                    continue;
                }
                reject_reporting_cfg_attributes(
                    &item.attrs,
                    &format!("trait impl for public type `{owner}`"),
                    &mut violations,
                );
                let trait_name = item
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| reporting_source_path(path))
                    .unwrap_or_else(|| "<unrecognized trait>".to_owned());
                *actual_trait_impls
                    .entry(owner)
                    .or_default()
                    .entry(trait_name)
                    .or_default() += 1;
                if item.unsafety.is_some()
                    || item.defaultness.is_some()
                    || !item.generics.params.is_empty()
                    || item.generics.where_clause.is_some()
                {
                    violations.push(
                        "reporting public-type trait impls must remain plain, safe, and non-generic"
                            .to_owned(),
                    );
                }
            },
            _ => {},
        }
    }

    for (name, kinds) in &actual_items {
        match (expected_items.get(name.as_str()), kinds.as_slice()) {
            (Some(expected_kind), [actual_kind]) if expected_kind == actual_kind => {},
            (Some(expected_kind), _) => violations.push(format!(
                "reporting public item `{name}` must appear exactly once as {expected_kind}, found {kinds:?}"
            )),
            (None, _) => violations.push(format!(
                "reporting public top-level item `{name}` is outside the exact API inventory"
            )),
        }
    }
    for (name, kind) in &expected_items {
        if !actual_items.contains_key(*name) {
            violations.push(format!(
                "reporting public {kind} `{name}` is missing from the exact API inventory"
            ));
        }
    }

    for (owner, methods) in &actual_methods {
        let Some(expected) = expected_methods.get(owner.as_str()) else {
            for method in methods.keys() {
                violations.push(format!(
                    "reporting public inherent method `{owner}::{method}` is outside the exact API inventory"
                ));
            }
            continue;
        };
        for (method, signatures) in methods {
            if !expected.contains(method.as_str()) {
                violations.push(format!(
                    "reporting public inherent method `{owner}::{method}` is outside the exact API inventory"
                ));
                continue;
            }
            if signatures.len() != 1 || !reporting_signature_matches(owner, method, signatures[0]) {
                violations.push(format!(
                    "reporting public method `{owner}::{method}` must retain its exact bounded signature"
                ));
            }
        }
    }
    for (owner, expected) in &expected_methods {
        for method in expected {
            if actual_methods
                .get(*owner)
                .and_then(|methods| methods.get(*method))
                .is_none()
            {
                violations.push(format!(
                    "reporting public method `{owner}::{method}` is missing from the exact API inventory"
                ));
            }
        }
    }

    for (owner, implementations) in &actual_trait_impls {
        for (trait_name, count) in implementations {
            let expected = expected_trait_impls
                .get(owner.as_str())
                .is_some_and(|traits| traits.contains(trait_name.as_str()));
            if !expected || *count != 1 {
                violations.push(format!(
                    "reporting explicit trait impl `{trait_name} for {owner}` is outside the exact public-type trait inventory or duplicated"
                ));
            }
        }
    }
    for (owner, expected) in &expected_trait_impls {
        for trait_name in expected {
            if actual_trait_impls
                .get(*owner)
                .and_then(|implementations| implementations.get(*trait_name))
                != Some(&1)
            {
                violations.push(format!(
                    "reporting explicit trait impl `{trait_name} for {owner}` is missing from the exact public-type trait inventory"
                ));
            }
        }
    }

    Ok(violations)
}

fn record_reporting_public_item(
    items: &mut BTreeMap<String, Vec<&'static str>>,
    name: String,
    kind: &'static str,
) {
    items.entry(name).or_default().push(kind);
}

fn reporting_impl_owner(item: &syn::ItemImpl) -> Option<String> {
    let syn::Type::Path(path) = item.self_ty.as_ref() else {
        return None;
    };
    path.qself
        .is_none()
        .then(|| {
            path.path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
        })
        .flatten()
}

fn reporting_source_path(path: &SynPath) -> Option<String> {
    (path.leading_colon.is_none()
        && path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, syn::PathArguments::None)))
    .then(|| {
        path.segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    })
}

fn validate_reporting_attributes(
    attributes: &[Attribute],
    expected_derives: &[&str],
    expect_non_exhaustive: bool,
    context: &str,
    violations: &mut Vec<String>,
) {
    let mut derives = BTreeSet::new();
    let mut derive_entry_count = 0;
    let mut derive_attribute_count = 0;
    let mut non_exhaustive_count = 0;
    for attribute in attributes {
        if attribute.path().is_ident("doc") {
            continue;
        }
        if attribute.path().is_ident("derive") {
            derive_attribute_count += 1;
            let Ok(paths) = attribute.parse_args_with(
                syn::punctuated::Punctuated::<SynPath, syn::Token![,]>::parse_terminated,
            ) else {
                violations.push(format!(
                    "reporting {context} has an unparsable derive inventory"
                ));
                continue;
            };
            for path in paths {
                derive_entry_count += 1;
                let Some(name) = reporting_source_path(&path).filter(|name| !name.contains("::"))
                else {
                    violations.push(format!(
                        "reporting {context} derives must use exact unqualified names"
                    ));
                    continue;
                };
                derives.insert(name);
            }
        } else if attribute.path().is_ident("non_exhaustive") {
            non_exhaustive_count += 1;
        } else {
            let name = reporting_source_path(attribute.path())
                .unwrap_or_else(|| "<unrecognized>".to_owned());
            violations.push(format!(
                "reporting {context} attribute `{name}` is outside the exact attribute inventory"
            ));
        }
    }

    let expected: BTreeSet<_> = expected_derives
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    if derives != expected
        || derive_entry_count != expected.len()
        || derive_attribute_count != usize::from(!expected.is_empty())
    {
        violations.push(format!(
            "reporting {context} derives must be exactly {expected:?}, found {derives:?}"
        ));
    }
    if non_exhaustive_count != usize::from(expect_non_exhaustive) {
        violations.push(format!(
            "reporting {context} non_exhaustive marker must match the exact contract"
        ));
    }
}

fn reject_reporting_cfg_attributes(
    attributes: &[Attribute],
    context: &str,
    violations: &mut Vec<String>,
) {
    if attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
    {
        violations.push(format!(
            "reporting {context} must not be conditionally compiled with cfg/cfg_attr"
        ));
    }
}

fn reporting_scanning_cfg_is_exact(attributes: &[Attribute]) -> bool {
    attributes.iter().all(|attribute| {
        attribute.path().is_ident("doc")
            || (attribute.path().is_ident("cfg")
                && cfg_predicate(attribute).as_deref() == Some("feature=\"scanning\""))
    }) && attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .count()
        == 1
}

fn validate_reporting_public_constant(item: &syn::ItemConst, violations: &mut Vec<String>) {
    match item.ident.to_string().as_str() {
        "ASSESSMENT_REPORT_DOCUMENT_SCHEMA"
            if simple_type_path(&item.ty, "str").is_none()
                && matches!(
                    item.ty.as_ref(),
                    syn::Type::Reference(reference)
                        if reference.mutability.is_none()
                            && reference.lifetime.is_none()
                            && simple_type_path(&reference.elem, "str").is_some()
                )
                && matches!(
                    item.expr.as_ref(),
                    syn::Expr::Lit(expression)
                        if matches!(&expression.lit, syn::Lit::Str(value) if value.value() == "venom-rendered-assessment/v1")
                ) => {},
        "REPORT_DOCUMENT_SCHEMA"
            if simple_type_path(&item.ty, "str").is_none()
                && matches!(
                    item.ty.as_ref(),
                    syn::Type::Reference(reference)
                        if reference.mutability.is_none()
                            && reference.lifetime.is_none()
                            && simple_type_path(&reference.elem, "str").is_some()
                )
                && matches!(
                    item.expr.as_ref(),
                    syn::Expr::Lit(expression)
                        if matches!(&expression.lit, syn::Lit::Str(value) if value.value() == "venom-rendered-run/v1")
                ) => {},
        "MAX_RENDERED_REPORT_BYTES"
            if simple_type_path(&item.ty, "usize").is_some()
                && evaluate_reporting_usize(&item.expr) == Some(16 * 1_024 * 1_024) => {},
        "ASSESSMENT_REPORT_DOCUMENT_SCHEMA" => violations.push(
            "reporting `ASSESSMENT_REPORT_DOCUMENT_SCHEMA` must remain `venom-rendered-assessment/v1` with type `&str`"
                .to_owned(),
        ),
        "REPORT_DOCUMENT_SCHEMA" => violations.push(
            "reporting `REPORT_DOCUMENT_SCHEMA` must remain `venom-rendered-run/v1` with type `&str`"
                .to_owned(),
        ),
        "MAX_RENDERED_REPORT_BYTES" => violations.push(
            "reporting `MAX_RENDERED_REPORT_BYTES` must remain exactly `16 * 1_024 * 1_024` bytes"
                .to_owned(),
        ),
        _ => {},
    }
}

fn evaluate_reporting_usize(expression: &syn::Expr) -> Option<usize> {
    match expression {
        syn::Expr::Lit(expression) => match &expression.lit {
            syn::Lit::Int(value) => value.base10_parse().ok(),
            _ => None,
        },
        syn::Expr::Binary(expression) if matches!(expression.op, syn::BinOp::Mul(_)) => {
            evaluate_reporting_usize(&expression.left)?
                .checked_mul(evaluate_reporting_usize(&expression.right)?)
        },
        syn::Expr::Paren(expression) => evaluate_reporting_usize(&expression.expr),
        _ => None,
    }
}

fn validate_reporting_public_enum(item: &syn::ItemEnum, violations: &mut Vec<String>) {
    if item.ident == "ReportFormat" {
        validate_reporting_attributes(
            &item.attrs,
            &["Clone", "Copy", "Debug", "Eq", "Hash", "PartialEq"],
            true,
            "public type `ReportFormat`",
            violations,
        );
        for variant in &item.variants {
            reject_reporting_cfg_attributes(
                &variant.attrs,
                &format!("variant `ReportFormat::{}`", variant.ident),
                violations,
            );
        }
        let exact = item
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("non_exhaustive"))
            && item.variants.len() == 4
            && item
                .variants
                .iter()
                .zip(["Json", "Csv", "Html", "Markdown"])
                .all(|(variant, expected)| {
                    variant.ident == expected
                        && matches!(variant.fields, Fields::Unit)
                        && variant.discriminant.is_none()
                });
        if !exact {
            violations.push(
                "reporting public `ReportFormat` variants must remain exactly Json, Csv, Html, Markdown and non-exhaustive"
                    .to_owned(),
            );
        }
    } else if item.ident == "ReportError" {
        validate_reporting_attributes(
            &item.attrs,
            &["Clone", "Copy", "Debug", "Eq", "PartialEq"],
            true,
            "public type `ReportError`",
            violations,
        );
        for variant in &item.variants {
            reject_reporting_cfg_attributes(
                &variant.attrs,
                &format!("variant `ReportError::{}`", variant.ident),
                violations,
            );
        }
        let exact = item
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("non_exhaustive"))
            && item.variants.len() == 2
            && item.variants[0].ident == "OutputLimitExceeded"
            && matches!(
                &item.variants[0].fields,
                Fields::Named(fields)
                    if fields.named.len() == 1
                        && fields.named[0].ident.as_ref().is_some_and(|ident| ident == "limit")
                        && simple_type_path(&fields.named[0].ty, "usize").is_some()
            )
            && item.variants[0].discriminant.is_none()
            && item.variants[1].ident == "Serialization"
            && matches!(item.variants[1].fields, Fields::Unit)
            && item.variants[1].discriminant.is_none();
        if !exact {
            violations.push(
                "reporting public `ReportError` variants must remain exactly OutputLimitExceeded { limit: usize } and Serialization and non-exhaustive"
                    .to_owned(),
            );
        }
    }
}

fn reporting_signature_matches(owner: &str, method: &str, signature: &syn::Signature) -> bool {
    let plain = signature.asyncness.is_none()
        && signature.unsafety.is_none()
        && signature.abi.is_none()
        && signature.variadic.is_none()
        && signature.generics.params.is_empty()
        && signature.generics.where_clause.is_none();
    if !plain {
        return false;
    }
    match (owner, method) {
        ("ReportFormat", "as_str" | "extension" | "media_type") => {
            signature.constness.is_some()
                && signature.inputs.len() == 1
                && matches!(
                    signature.inputs.first(),
                    Some(syn::FnArg::Receiver(receiver))
                        if receiver.reference.is_none()
                            && receiver.mutability.is_none()
                            && receiver.colon_token.is_none()
                )
                && return_type_is_static_str(&signature.output)
        },
        ("ReportGenerator", "available_formats") => {
            signature.constness.is_some()
                && signature.inputs.is_empty()
                && return_type_is_static_report_format_slice(&signature.output)
        },
        ("ReportGenerator", "generate") => {
            signature.constness.is_none()
                && signature.inputs.len() == 2
                && matches!(
                    signature.inputs.first(),
                    Some(syn::FnArg::Typed(argument))
                        if immutable_elided_reference_to(&argument.ty, "RunReport")
                )
                && matches!(
                    signature.inputs.iter().nth(1),
                    Some(syn::FnArg::Typed(argument))
                        if simple_type_path(&argument.ty, "ReportFormat").is_some()
                )
                && return_type_is_report_result(&signature.output)
        },
        ("ReportGenerator", "compose_assessment") => {
            signature.constness.is_none()
                && signature.inputs.len() == 2
                && matches!(signature.inputs.first(), Some(syn::FnArg::Typed(argument))
                    if simple_type_path(&argument.ty, "WebAssessmentRunReport").is_some())
                && matches!(signature.inputs.iter().nth(1), Some(syn::FnArg::Typed(argument))
                    if simple_type_path(&argument.ty, "ScanProfileV1").is_some())
                && assessment_bridge_return_is_exact(&signature.output)
        },
        ("ReportGenerator", "generate_assessment") => {
            signature.constness.is_none()
                && signature.inputs.len() == 2
                && matches!(
                    signature.inputs.first(),
                    Some(syn::FnArg::Typed(argument))
                        if immutable_elided_reference_to(&argument.ty, "AssessmentRunReport")
                )
                && matches!(
                    signature.inputs.iter().nth(1),
                    Some(syn::FnArg::Typed(argument))
                        if simple_type_path(&argument.ty, "ReportFormat").is_some()
                )
                && return_type_is_report_result(&signature.output)
        },
        _ => false,
    }
}

fn validate_reporting_public_method_body(
    owner: &str,
    method: &str,
    block: &syn::Block,
    violations: &mut Vec<String>,
) {
    let exact = match (owner, method) {
        ("ReportFormat", "as_str") => reporting_format_mapping_matches(
            block,
            &[
                ("Json", "json"),
                ("Csv", "csv"),
                ("Html", "html"),
                ("Markdown", "markdown"),
            ],
        ),
        ("ReportFormat", "media_type") => reporting_format_mapping_matches(
            block,
            &[
                ("Json", "application/json"),
                ("Csv", "text/csv; charset=utf-8"),
                ("Html", "text/html; charset=utf-8"),
                ("Markdown", "text/markdown; charset=utf-8"),
            ],
        ),
        ("ReportFormat", "extension") => reporting_format_mapping_matches(
            block,
            &[
                ("Json", "json"),
                ("Csv", "csv"),
                ("Html", "html"),
                ("Markdown", "md"),
            ],
        ),
        ("ReportGenerator", "available_formats") => {
            matches!(
                reporting_only_expression(block),
                Some(syn::Expr::Reference(reference))
                    if reference.mutability.is_none()
                        && reporting_expression_path_is(&reference.expr, &["REPORT_FORMATS"])
            )
        },
        ("ReportGenerator", "generate") => reporting_generate_body_matches(block),
        ("ReportGenerator", "compose_assessment") => {
            reporting_compose_assessment_body_matches(block)
        },
        ("ReportGenerator", "generate_assessment") => {
            reporting_generate_assessment_body_matches(block)
        },
        _ => true,
    };
    if !exact {
        violations.push(format!(
            "reporting public method `{owner}::{method}` must retain its exact bounded implementation contract"
        ));
    }
}

fn reporting_compose_assessment_body_matches(block: &syn::Block) -> bool {
    let Some(syn::Expr::MethodCall(call)) = reporting_only_expression(block) else {
        return false;
    };
    call.method == "into_assessment_report"
        && call.turbofish.is_none()
        && reporting_expression_path_key(call.receiver.as_ref()).as_deref() == Some("report")
        && call.args.len() == 1
        && call.args.first().is_some_and(|argument| {
            reporting_expression_path_key(argument).as_deref() == Some("profile")
        })
}

fn reporting_generate_assessment_body_matches(block: &syn::Block) -> bool {
    reporting_projection_generate_body_matches(
        block,
        "AssessmentDocument",
        "render_assessment_with_limit",
    )
}

fn reporting_only_expression(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(expression, None)] => Some(expression),
        _ => None,
    }
}

fn reporting_format_mapping_matches(block: &syn::Block, expected: &[(&str, &str)]) -> bool {
    let Some(syn::Expr::Match(expression)) = reporting_only_expression(block) else {
        return false;
    };
    reporting_expression_path_is(&expression.expr, &["self"])
        && expression.arms.len() == expected.len()
        && expression
            .arms
            .iter()
            .zip(expected)
            .all(|(arm, (variant, value))| {
                arm.attrs.is_empty()
                    && arm.guard.is_none()
                    && matches!(
                        &arm.pat,
                        syn::Pat::Path(path)
                            if path.qself.is_none()
                                && reporting_path_is(&path.path, &["Self", variant])
                    )
                    && matches!(
                        arm.body.as_ref(),
                        syn::Expr::Lit(expression)
                            if matches!(&expression.lit, syn::Lit::Str(literal) if literal.value() == *value)
                    )
            })
}

fn reporting_generate_body_matches(block: &syn::Block) -> bool {
    reporting_projection_generate_body_matches(block, "ReportDocument", "render_with_limit")
}

fn reporting_projection_generate_body_matches(
    block: &syn::Block,
    document_type: &str,
    render_function: &str,
) -> bool {
    let [syn::Stmt::Local(local), syn::Stmt::Expr(render, None)] = block.stmts.as_slice() else {
        return false;
    };
    let local_is_exact = local.attrs.is_empty()
        && matches!(
            &local.pat,
            syn::Pat::Ident(identifier)
                if identifier.ident == "document"
                    && identifier.by_ref.is_none()
                    && identifier.mutability.is_none()
                    && identifier.subpat.is_none()
        )
        && local.init.as_ref().is_some_and(|init| {
            init.diverge.is_none()
                && matches!(
                    init.expr.as_ref(),
                    syn::Expr::Try(expression)
                        if matches!(
                            expression.expr.as_ref(),
                            syn::Expr::Call(call)
                                if reporting_expression_path_is(
                                    &call.func,
                                    &[document_type, "from_report"],
                                ) && call.args.len() == 1
                                    && call.args.first().is_some_and(|argument| {
                                        reporting_expression_path_is(argument, &["report"])
                                    })
                        )
                )
        });
    local_is_exact
        && matches!(
            render,
            syn::Expr::Call(call)
                if reporting_expression_path_is(&call.func, &[render_function])
                    && call.args.len() == 3
                    && matches!(
                        call.args.first(),
                        Some(syn::Expr::Reference(reference))
                            if reference.mutability.is_none()
                                && reporting_expression_path_is(&reference.expr, &["document"])
                    )
                    && call.args.iter().nth(1).is_some_and(|argument| {
                        reporting_expression_path_is(argument, &["format"])
                    })
                    && call.args.iter().nth(2).is_some_and(|argument| {
                        reporting_expression_path_is(argument, &["MAX_RENDERED_REPORT_BYTES"])
                    })
        )
}

fn reporting_expression_path_is(expression: &syn::Expr, expected: &[&str]) -> bool {
    matches!(
        expression,
        syn::Expr::Path(path)
            if path.qself.is_none() && reporting_path_is(&path.path, expected)
    )
}

fn reporting_path_is(path: &SynPath, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path.segments.iter().zip(expected).all(|(segment, name)| {
            semantic_ident_name(&segment.ident) == *name
                && matches!(segment.arguments, syn::PathArguments::None)
        })
}

fn reporting_syn_path_key(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|segment| semantic_ident_name(&segment.ident))
        .collect::<Vec<_>>()
        .join("::")
}

fn reporting_expression_path_key(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    (path.qself.is_none() && path.path.leading_colon.is_none())
        .then(|| reporting_syn_path_key(&path.path))
}

fn simple_type_path<'a>(ty: &'a syn::Type, expected: &str) -> Option<&'a syn::PathSegment> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    (path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == expected
        && matches!(path.path.segments[0].arguments, syn::PathArguments::None))
    .then_some(&path.path.segments[0])
}

fn immutable_elided_reference_to(ty: &syn::Type, expected: &str) -> bool {
    matches!(
        ty,
        syn::Type::Reference(reference)
            if reference.mutability.is_none()
                && reference.lifetime.is_none()
                && simple_type_path(&reference.elem, expected).is_some()
    )
}

fn return_type_is_static_str(output: &syn::ReturnType) -> bool {
    matches!(
        output,
        syn::ReturnType::Type(_, ty)
            if matches!(
                ty.as_ref(),
                syn::Type::Reference(reference)
                    if reference.mutability.is_none()
                        && reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "static")
                        && simple_type_path(&reference.elem, "str").is_some()
            )
    )
}

fn return_type_is_static_report_format_slice(output: &syn::ReturnType) -> bool {
    matches!(
        output,
        syn::ReturnType::Type(_, ty)
            if matches!(
                ty.as_ref(),
                syn::Type::Reference(reference)
                    if reference.mutability.is_none()
                        && reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "static")
                        && matches!(
                            reference.elem.as_ref(),
                            syn::Type::Slice(slice)
                                if simple_type_path(&slice.elem, "ReportFormat").is_some()
                        )
            )
    )
}

fn return_type_is_report_result(output: &syn::ReturnType) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    let syn::Type::Path(path) = ty.as_ref() else {
        return false;
    };
    if path.qself.is_some() || path.path.leading_colon.is_some() || path.path.segments.len() != 1 {
        return false;
    }
    let segment = &path.path.segments[0];
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let types: Vec<_> = arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .collect();
    segment.ident == "Result"
        && arguments.args.len() == 2
        && types.len() == 2
        && simple_type_path(types[0], "String").is_some()
        && simple_type_path(types[1], "ReportError").is_some()
}

fn cfg_predicates(module: &ItemMod) -> Vec<String> {
    cfg_predicates_from_attributes(&module.attrs)
}

fn cfg_predicates_from_attributes(attributes: &[Attribute]) -> Vec<String> {
    attributes.iter().filter_map(cfg_predicate).collect()
}

fn cfg_predicate(attribute: &Attribute) -> Option<String> {
    if reporting_syn_path_key(attribute.path()) != "cfg" {
        return None;
    }
    match &attribute.meta {
        Meta::List(list) => Some(
            list.tokens
                .to_string()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect(),
        ),
        _ => Some("<invalid>".to_owned()),
    }
}

fn surface_contract_violations(
    contracts: &[SurfaceContract],
    lib_source: &str,
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(lib_source)?;
    let modules: BTreeMap<_, _> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) => Some((module.ident.to_string(), module)),
            _ => None,
        })
        .collect();
    let mut violations = Vec::new();
    let mut inventoried = BTreeSet::new();
    for contract in contracts {
        if !inventoried.insert(contract.module) {
            violations.push(format!(
                "quarantined surface `{}` appears more than once in the lifecycle inventory",
                contract.module
            ));
            continue;
        }
        if contract.implementation == ImplementationClaim::Implemented
            && contract.host == HostContract::NoExecution
        {
            violations.push(format!(
                "quarantined surface `{}` cannot be labelled implemented without a repository caller or explicit host contract",
                contract.module
            ));
        }
        if contract.lifecycle == Lifecycle::Preview && contract.host == HostContract::NoExecution {
            violations.push(format!(
                "quarantined surface `{}` has lifecycle {:?} but no explicit host contract",
                contract.module, contract.lifecycle
            ));
        }
        if let HostContract::Library(name) = contract.host {
            if name.trim().is_empty() {
                violations.push(format!(
                    "quarantined surface `{}` has an empty library host contract",
                    contract.module
                ));
            }
        }
        let Some(module) = modules.get(contract.module) else {
            violations.push(format!(
                "inventoried quarantined surface `{}` is missing from venom-scanner lib.rs",
                contract.module
            ));
            continue;
        };
        let expects_private_facade = PRIVATE_FACADE_SURFACES.contains(&contract.module);
        if expects_private_facade && !matches!(module.vis, Visibility::Inherited) {
            violations.push(format!(
                "inventoried quarantined surface `{}` must keep its implementation module private behind exact root re-exports",
                contract.module
            ));
        } else if !expects_private_facade && !matches!(module.vis, Visibility::Public(_)) {
            violations.push(format!(
                "inventoried quarantined surface `{}` must remain an explicit public host boundary or be removed from the inventory",
                contract.module
            ));
        }
        let expected_gate = format!("feature=\"{}\"", contract.feature);
        let actual_gates = cfg_predicates(module);
        if actual_gates != [expected_gate.clone()] {
            violations.push(format!(
                "inventoried quarantined surface `{}` must use exact cfg({expected_gate}), found {actual_gates:?}",
                contract.module
            ));
        }
    }
    let expected: BTreeSet<_> = EXPECTED_QUARANTINED_PUBLIC_MODULES
        .iter()
        .copied()
        .collect();
    for missing in expected.difference(&inventoried) {
        violations.push(format!(
            "quarantined public surface `{missing}` is missing from the exact lifecycle inventory"
        ));
    }
    for unexpected in inventoried.difference(&expected) {
        violations.push(format!(
            "quarantined public surface `{unexpected}` is not classified in the exact lifecycle inventory"
        ));
    }
    let actual_public_surfaces: BTreeSet<_> = modules
        .values()
        .filter(|module| {
            (is_public(&module.vis)
                || PRIVATE_FACADE_SURFACES.contains(&module.ident.to_string().as_str()))
                && cfg_predicates(module).iter().any(|predicate| {
                    QUARANTINED_PUBLIC_FEATURES.iter().any(|feature| {
                        let marker = format!("feature=\"{feature}\"");
                        predicate.contains(marker.as_str())
                    })
                })
        })
        .map(|module| module.ident.to_string())
        .collect();
    let inventoried_owned: BTreeSet<_> = inventoried
        .iter()
        .map(|module| (*module).to_owned())
        .collect();
    for missing in actual_public_surfaces.difference(&inventoried_owned) {
        violations.push(format!(
            "public opt-in scanner module `{missing}` has no lifecycle, implementation, and host classification"
        ));
    }
    for stale in inventoried_owned.difference(&actual_public_surfaces) {
        violations.push(format!(
            "inventoried quarantined surface `{stale}` is not an actual public opt-in scanner module"
        ));
    }
    Ok(violations)
}

type NamedSource<'a> = (&'a str, &'a str);

/// Stable source order follows the facade's private module declarations. Paths
/// are part of the production fingerprint so moving, omitting, or substituting
/// one child cannot preserve the audited inventory accidentally.
const DISTRIBUTED_PRODUCTION_SOURCE_PATHS: &[&str] = &[
    "distributed.rs",
    "distributed/coordinator.rs",
    "distributed/lease.rs",
    "distributed/limits.rs",
    "distributed/model.rs",
    "distributed/queue.rs",
    "distributed/recovery.rs",
    "distributed/results.rs",
    "distributed/worker.rs",
];

const DISTRIBUTED_ROOT_MODULES: &[&str] = &[
    "coordinator",
    "lease",
    "limits",
    "model",
    "queue",
    "recovery",
    "results",
    "worker",
];

const LUA_ENGINE_PRODUCTION_SOURCE_PATHS: &[&str] = &[
    "lua_engine.rs",
    "lua_engine/execution.rs",
    "lua_engine/history.rs",
    "lua_engine/limits.rs",
    "lua_engine/registry.rs",
    "lua_engine/source.rs",
    "lua_engine/vm.rs",
];

const LUA_ENGINE_ROOT_MODULES: &[&str] =
    &["execution", "history", "limits", "registry", "source", "vm"];
const LUA_CONFIG_PRODUCTION_SOURCE_PATHS: &[&str] = &["lua_config.rs"];

fn read_ordered_sources(
    source_root: &Path,
    paths: &'static [&'static str],
) -> io::Result<Vec<(&'static str, String)>> {
    paths
        .iter()
        .map(|path| fs::read_to_string(source_root.join(path)).map(|source| (*path, source)))
        .collect()
}

fn borrowed_sources<'a>(sources: &'a [(&'static str, String)]) -> Vec<NamedSource<'a>> {
    sources
        .iter()
        .map(|(path, source)| (*path, source.as_str()))
        .collect()
}

fn source_path_inventory_violations(
    surface: &str,
    sources: &[NamedSource<'_>],
    expected_paths: &[&str],
) -> Vec<String> {
    let actual_paths: Vec<_> = sources.iter().map(|(path, _)| *path).collect();
    if actual_paths == expected_paths {
        Vec::new()
    } else {
        vec![format!(
            "{surface} production source inventory must remain exactly {expected_paths:?}, found {actual_paths:?}"
        )]
    }
}

fn combined_public_api_shape(sources: &[NamedSource<'_>]) -> Result<PublicApiShape, syn::Error> {
    let mut combined = PublicApiShape::default();
    for (_, source) in sources {
        let shape = public_api_shape(source)?;
        combined.symbols.extend(shape.symbols);
        combined.methods.extend(shape.methods);
        combined.fields.extend(shape.fields);
    }
    Ok(combined)
}

const EXACT_DISTRIBUTED_CONSTANTS: &[(&str, &str, u128)] = &[
    ("MAX_IDENTIFIER_BYTES", "usize", 256),
    ("MAX_TARGET_REF_BYTES", "usize", 1_024),
    ("MAX_TASK_PHASES", "usize", 256),
    ("MAX_WORKER_TAGS", "usize", 5),
    ("UTILIZATION_BASIS_POINTS", "u16", 10_000),
    ("MAX_TASK_RECORDS", "usize", 65_536),
    ("MAX_ACTIVE_TASKS", "usize", 16_384),
    ("MAX_WORKERS", "usize", 4_096),
    ("MAX_RETRIES", "u32", 32),
    ("MAX_WORKER_CAPACITY", "u32", 4_096),
    ("MAX_LEASE_TTL_SECS", "u64", 86_400),
    ("MAX_TASK_TTL_SECS", "u64", 31 * 86_400),
    ("MAX_HEARTBEAT_TIMEOUT_SECS", "u64", 86_400),
    ("MAX_RESULTS", "usize", 65_536),
    ("MAX_RESULT_BYTES", "usize", 16 * 1_024 * 1_024),
    ("MAX_TOTAL_RESULT_BYTES", "usize", 256 * 1_024 * 1_024),
    ("MAX_AGGREGATE_ITEMS", "usize", 65_536),
];

const EXACT_DISTRIBUTED_PRODUCTION_TOKEN_BYTES: usize = 90_986;
const EXACT_DISTRIBUTED_PRODUCTION_FINGERPRINT: u128 = 0xd532_01fe_237b_3a56_832d_5a7e_e74a_e2fe;

fn distributed_public_api_violations(
    sources: &[NamedSource<'_>],
) -> Result<Vec<String>, syn::Error> {
    let syntaxes: Vec<_> = sources
        .iter()
        .map(|(path, source)| syn::parse_file(source).map(|syntax| (*path, syntax)))
        .collect::<Result<_, _>>()?;
    let shape = combined_public_api_shape(sources)?;
    let expected_symbols: BTreeSet<_> = EXACT_DISTRIBUTED_REEXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut violations = source_path_inventory_violations(
        "distributed",
        sources,
        DISTRIBUTED_PRODUCTION_SOURCE_PATHS,
    );
    if shape.symbols != expected_symbols {
        violations.push(format!(
            "distributed public symbols must remain exactly {expected_symbols:?}, found {:?}",
            shape.symbols
        ));
    }

    let expected_constants: BTreeMap<_, _> = EXACT_DISTRIBUTED_CONSTANTS
        .iter()
        .map(|(name, ty, value)| (*name, (*ty, *value)))
        .collect();
    let mut actual_constants = BTreeMap::new();
    for item in syntaxes.iter().flat_map(|(_, syntax)| &syntax.items) {
        let Item::Const(item) = item else {
            continue;
        };
        if is_public(&item.vis) {
            actual_constants.insert(
                item.ident.to_string(),
                (
                    simple_type_name(&item.ty).unwrap_or_else(|| "<complex>".to_owned()),
                    evaluate_integer_expression(&item.expr),
                ),
            );
        }
    }
    for (name, (expected_type, expected_value)) in expected_constants {
        match actual_constants.get(name) {
            Some((actual_type, Some(actual_value)))
                if actual_type == expected_type && *actual_value == expected_value => {},
            actual => violations.push(format!(
                "distributed constant `{name}` must remain `{expected_type}` with value {expected_value}, found {actual:?}"
            )),
        }
    }
    if actual_constants.len() != EXACT_DISTRIBUTED_CONSTANTS.len() {
        violations.push(format!(
            "distributed public constant inventory must contain exactly {} items, found {}",
            EXACT_DISTRIBUTED_CONSTANTS.len(),
            actual_constants.len()
        ));
    }

    let required_private_snapshots = ["AggregatedResult", "ScanTask", "WorkerNode"];
    for name in required_private_snapshots {
        let matching: Vec<_> = syntaxes
            .iter()
            .flat_map(|(_, syntax)| &syntax.items)
            .filter_map(|item| match item {
                Item::Struct(item) if item.ident == name => Some(item),
                _ => None,
            })
            .collect();
        match matching.as_slice() {
            [item]
                if is_public(&item.vis)
                    && item.fields.iter().all(|field| !is_public(&field.vis)) => {},
            _ => violations.push(format!(
                "distributed snapshot `{name}` must exist exactly once with all fields non-public"
            )),
        }
    }
    let worker_pools: Vec<_> = syntaxes
        .iter()
        .flat_map(|(_, syntax)| &syntax.items)
        .filter_map(|item| match item {
            Item::Struct(item) if item.ident == "WorkerPool" => Some(item),
            _ => None,
        })
        .collect();
    let exact_private_task_queue = matches!(worker_pools.as_slice(), [item] if {
        item.fields.iter().any(|field| {
            field.ident.as_ref().is_some_and(|ident| ident == "task_queue")
                && matches!(field.vis, Visibility::Inherited)
        })
    });
    if !exact_private_task_queue {
        violations.push(
            "distributed `WorkerPool::task_queue` field must exist exactly as a private field"
                .to_owned(),
        );
    }

    Ok(violations)
}

fn simple_type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    (path.qself.is_none() && path.path.segments.len() == 1)
        .then(|| semantic_ident_name(&path.path.segments[0].ident))
}

fn evaluate_integer_expression(expression: &syn::Expr) -> Option<u128> {
    match expression {
        syn::Expr::Lit(expression) => match &expression.lit {
            syn::Lit::Int(value) => value.base10_parse().ok(),
            _ => None,
        },
        syn::Expr::Binary(expression) => match expression.op {
            syn::BinOp::Add(_) => evaluate_integer_expression(&expression.left)?
                .checked_add(evaluate_integer_expression(&expression.right)?),
            syn::BinOp::Mul(_) => evaluate_integer_expression(&expression.left)?
                .checked_mul(evaluate_integer_expression(&expression.right)?),
            _ => None,
        },
        syn::Expr::Paren(expression) => evaluate_integer_expression(&expression.expr),
        _ => None,
    }
}

#[derive(Default)]
struct DistributedSourceVisitor {
    violations: BTreeSet<String>,
    inside_test_module: usize,
    allowed_modules: BTreeSet<String>,
}

impl DistributedSourceVisitor {
    fn inspect_identifier(&mut self, identifier: &str) {
        if matches!(
            identifier,
            "DashMap"
                | "Deserialize"
                | "HashMap"
                | "HashSet"
                | "Instant"
                | "OsRng"
                | "RandomState"
                | "Serialize"
                | "SystemTime"
                | "Uuid"
                | "allow"
                | "chrono"
                | "env"
                | "f32"
                | "f64"
                | "fs"
                | "getrandom"
                | "net"
                | "process"
                | "random"
                | "reqwest"
                | "serde"
                | "thread"
                | "thread_rng"
                | "tokio"
        ) {
            self.violations.insert(format!(
                "distributed production source cannot use `{identifier}`"
            ));
        }
    }
}

impl<'ast> Visit<'ast> for DistributedSourceVisitor {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        let exact_tests = item.ident == "tests"
            && item.content.is_some()
            && item.attrs.len() == 1
            && cfg_predicate(&item.attrs[0]).as_deref() == Some("test");
        if self.inside_test_module == 0 && exact_tests {
            self.inside_test_module += 1;
            syn::visit::visit_item_mod(self, item);
            self.inside_test_module -= 1;
            return;
        }
        let module_name = semantic_ident_name(&item.ident);
        let exact_allowed_child = self.inside_test_module == 0
            && item.content.is_none()
            && item.attrs.is_empty()
            && matches!(item.vis, Visibility::Inherited)
            && self.allowed_modules.contains(&module_name);
        if self.inside_test_module == 0 && !exact_allowed_child {
            self.violations.insert(format!(
                "distributed production module `{}` is forbidden",
                item.ident
            ));
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_ident(&mut self, identifier: &'ast syn::Ident) {
        if self.inside_test_module == 0 {
            self.inspect_identifier(&semantic_ident_name(identifier));
        }
        syn::visit::visit_ident(self, identifier);
    }

    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        if self.inside_test_module == 0 {
            let name = reporting_syn_path_key(attribute.path());
            if matches!(name.as_str(), "allow" | "cfg_attr")
                || (name == "cfg" && cfg_predicate(attribute).as_deref() != Some("test"))
            {
                self.violations.insert(format!(
                    "distributed production attribute `{name}` is forbidden"
                ));
            }
            self.inspect_identifier(&name);
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if self.inside_test_module == 0 {
            self.violations.insert(format!(
                "distributed production static `{}` is forbidden",
                item.ident
            ));
        }
        syn::visit::visit_item_static(self, item);
    }

    fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
        if self.inside_test_module == 0 {
            self.violations
                .insert("distributed production unsafe block is forbidden".to_owned());
        }
        syn::visit::visit_expr_unsafe(self, expression);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        if self.inside_test_module == 0 {
            self.violations
                .insert("distributed production FFI is forbidden".to_owned());
        }
        syn::visit::visit_item_foreign_mod(self, item);
    }

    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if self.inside_test_module == 0 && (signature.unsafety.is_some() || signature.abi.is_some())
        {
            self.violations.insert(
                "distributed production functions must remain safe Rust without a foreign ABI"
                    .to_owned(),
            );
        }
        syn::visit::visit_signature(self, signature);
    }

    fn visit_lit_float(&mut self, literal: &'ast syn::LitFloat) {
        if self.inside_test_module == 0 {
            self.violations
                .insert("distributed production float literals are forbidden".to_owned());
        }
        syn::visit::visit_lit_float(self, literal);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if self.inside_test_module == 0 {
            let name = reporting_syn_path_key(&item.path);
            if matches!(
                name.as_str(),
                "env" | "include" | "include_bytes" | "include_str" | "option_env"
            ) {
                self.violations.insert(format!(
                    "distributed production macro `{name}!` is forbidden"
                ));
            }
            inspect_distributed_macro_tokens(item.tokens.clone(), &mut self.violations);
        }
        syn::visit::visit_macro(self, item);
    }
}

fn inspect_distributed_macro_tokens(tokens: TokenStream, violations: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Group(group) => inspect_distributed_macro_tokens(group.stream(), violations),
            TokenTree::Ident(identifier) => {
                let mut visitor = DistributedSourceVisitor::default();
                visitor.inspect_identifier(&semantic_ident_name(&identifier));
                violations.extend(visitor.violations);
            },
            TokenTree::Punct(_) | TokenTree::Literal(_) => {},
        }
    }
}

fn distributed_source_authority_violations(
    sources: &[NamedSource<'_>],
) -> Result<Vec<String>, syn::Error> {
    let mut visitor = DistributedSourceVisitor::default();
    visitor.violations.extend(source_path_inventory_violations(
        "distributed",
        sources,
        DISTRIBUTED_PRODUCTION_SOURCE_PATHS,
    ));
    for (path, source) in sources {
        let syntax = syn::parse_file(source)?;
        visitor.allowed_modules = if *path == "distributed.rs" {
            DISTRIBUTED_ROOT_MODULES
                .iter()
                .map(|module| (*module).to_owned())
                .collect()
        } else {
            BTreeSet::new()
        };
        visitor.visit_file(&syntax);
    }
    Ok(visitor.violations.into_iter().collect())
}

fn exact_inline_tests_production<'a>(
    source_label: &str,
    source: &'a str,
) -> Result<&'a str, Vec<String>> {
    let syntax = syn::parse_file(source)
        .map_err(|_| vec![format!("{source_label} must remain valid Rust source")])?;
    let exact_test_modules = syntax
        .items
        .iter()
        .filter(|item| {
            matches!(
                item,
                Item::Mod(module)
                    if module.ident == "tests"
                        && module.content.is_some()
                        && module.attrs.len() == 1
                        && cfg_predicate(&module.attrs[0]).as_deref() == Some("test")
            )
        })
        .count();
    if exact_test_modules != 1
        || !matches!(
            syntax.items.last(),
            Some(Item::Mod(module))
                if module.ident == "tests"
                    && module.content.is_some()
                    && module.attrs.len() == 1
                    && cfg_predicate(&module.attrs[0]).as_deref() == Some("test")
        )
    {
        return Err(vec![format!(
            "{source_label} must end with exactly one exact cfg(test) inline tests module"
        )]);
    }
    source
        .rsplit_once("#[cfg(test)]")
        .map(|(production, _)| production)
        .ok_or_else(|| {
            vec![format!(
                "{source_label} must end production code with the exact cfg(test) module boundary"
            )]
        })
}

fn normalized_text_fingerprint(normalized: &str) -> (usize, u128) {
    let fingerprint = normalized.bytes().fold(
        0x6c62_272e_07bb_0142_62b8_2175_6295_c58d_u128,
        |fingerprint, byte| {
            (fingerprint ^ u128::from(byte))
                .wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013B_u128)
        },
    );
    (normalized.len(), fingerprint)
}

fn normalized_production_source_set_fingerprint(
    surface: &str,
    sources: &[NamedSource<'_>],
    expected_paths: &[&str],
    inline_test_roots: &[&str],
) -> Result<(usize, u128), Vec<String>> {
    let inventory_violations = source_path_inventory_violations(surface, sources, expected_paths);
    if !inventory_violations.is_empty() {
        return Err(inventory_violations);
    }

    let mut framed = String::new();
    for (path, source) in sources {
        let production = if inline_test_roots.contains(path) {
            exact_inline_tests_production(path, source)?
        } else {
            syn::parse_file(source)
                .map_err(|_| vec![format!("{path} must remain valid Rust source")])?;
            source
        };
        let normalized = production
            .parse::<TokenStream>()
            .map_err(|_| {
                vec![format!(
                    "{path} production source must remain valid Rust tokens"
                )]
            })?
            .to_string();
        framed.push_str(&path.len().to_string());
        framed.push(':');
        framed.push_str(path);
        framed.push(':');
        framed.push_str(&normalized.len().to_string());
        framed.push(':');
        framed.push_str(&normalized);
        framed.push(';');
    }
    Ok(normalized_text_fingerprint(&framed))
}

fn distributed_production_inventory_violations(sources: &[NamedSource<'_>]) -> Vec<String> {
    let (bytes, fingerprint) = match normalized_production_source_set_fingerprint(
        "distributed",
        sources,
        DISTRIBUTED_PRODUCTION_SOURCE_PATHS,
        &["distributed.rs"],
    ) {
        Ok(inventory) => inventory,
        Err(violations) => return violations,
    };
    if bytes == EXACT_DISTRIBUTED_PRODUCTION_TOKEN_BYTES
        && fingerprint == EXACT_DISTRIBUTED_PRODUCTION_FINGERPRINT
    {
        Vec::new()
    } else {
        vec![format!(
            "distributed root+children exact public signatures and production AST/body inventory changed; expected normalized framed bytes/fingerprint {EXACT_DISTRIBUTED_PRODUCTION_TOKEN_BYTES}/{EXACT_DISTRIBUTED_PRODUCTION_FINGERPRINT:032x}, found {bytes}/{fingerprint:032x}"
        )]
    }
}

const EXACT_LUA_CONFIG_CONSTANTS: &[(&str, &str, u128)] = &[
    ("HARD_MAX_HISTORY_ENTRIES", "usize", 1_024),
    ("HARD_MAX_MEMORY_BYTES", "usize", 256 * 1_024 * 1_024),
    ("HARD_MAX_TIMEOUT_MS", "u64", 60_000),
    ("HARD_MAX_SOURCE_BYTES", "usize", 1_024 * 1_024),
    ("HARD_MAX_TOTAL_SOURCE_BYTES", "usize", 64 * 1_024 * 1_024),
    ("HARD_MAX_CONTEXT_BYTES", "usize", 1_024 * 1_024),
    ("HARD_MAX_TARGET_BYTES", "usize", 256 * 1_024),
    ("HARD_MAX_PAYLOAD_BYTES", "usize", 512 * 1_024),
    ("HARD_MAX_PARAMETERS", "usize", 1_024),
    ("HARD_MAX_PARAMETER_KEY_BYTES", "usize", 4 * 1_024),
    ("HARD_MAX_PARAMETER_VALUE_BYTES", "usize", 64 * 1_024),
    ("HARD_MAX_OUTPUT_BYTES", "usize", 1_024 * 1_024),
    ("HARD_MAX_RETURN_BYTES", "usize", 1_024 * 1_024),
    ("HARD_MAX_INSTRUCTIONS", "u64", 100_000_000),
    ("HARD_MAX_HOOK_INTERVAL", "u32", 10_000),
    ("HARD_MAX_SCRIPTS", "usize", 4_096),
    ("HARD_MAX_CONCURRENT_EXECUTIONS", "usize", 64),
    (
        "HARD_MAX_HISTORY_BYTES_PER_SCRIPT",
        "usize",
        8 * 1_024 * 1_024,
    ),
    ("HARD_MAX_HISTORY_BYTES_TOTAL", "usize", 64 * 1_024 * 1_024),
];

const EXACT_LUA_CONFIG_FIELDS: &[&str] = &[
    "default_timeout_ms",
    "history_size",
    "hook_interval",
    "instruction_limit",
    "max_concurrent_executions",
    "max_context_bytes",
    "max_history_bytes_per_script",
    "max_history_bytes_total",
    "max_memory_bytes",
    "max_output_bytes",
    "max_parameter_key_bytes",
    "max_parameter_value_bytes",
    "max_parameters",
    "max_payload_bytes",
    "max_return_bytes",
    "max_scripts",
    "max_source_bytes",
    "max_target_bytes",
    "max_total_source_bytes",
];

const EXACT_LUA_ENGINE_PRODUCTION_TOKEN_BYTES: usize = 58_031;
const EXACT_LUA_ENGINE_PRODUCTION_FINGERPRINT: u128 = 0x2b5a_1daf_b4bd_b033_1348_2ea7_2a48_d917;
const EXACT_LUA_CONFIG_PRODUCTION_TOKEN_BYTES: usize = 14_705;
const EXACT_LUA_CONFIG_PRODUCTION_FINGERPRINT: u128 = 0xfd78_2485_5656_70da_0d9e_2954_d06b_3fcb;

fn lua_public_api_violations(
    engine_sources: &[NamedSource<'_>],
    config_source: &str,
) -> Result<Vec<String>, syn::Error> {
    let engine_syntaxes: Vec<_> = engine_sources
        .iter()
        .map(|(path, source)| syn::parse_file(source).map(|syntax| (*path, syntax)))
        .collect::<Result<_, _>>()?;
    let config_syntax = syn::parse_file(config_source)?;
    let engine_shape = combined_public_api_shape(engine_sources)?;
    let expected_engine: BTreeSet<_> = EXACT_LUA_REEXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut violations = source_path_inventory_violations(
        "Lua engine",
        engine_sources,
        LUA_ENGINE_PRODUCTION_SOURCE_PATHS,
    );
    if engine_shape.symbols != expected_engine {
        violations.push(format!(
            "Lua engine public symbols must remain exactly {expected_engine:?}, found {:?}",
            engine_shape.symbols
        ));
    }

    for name in [
        "LuaCancellationToken",
        "LuaContext",
        "LuaExecutionReceipt",
        "LuaExecutionResult",
        "LuaScript",
        "LuaScriptManifest",
        "LuaScriptRegistry",
    ] {
        let matching: Vec<_> = engine_syntaxes
            .iter()
            .flat_map(|(_, syntax)| &syntax.items)
            .filter_map(|item| match item {
                Item::Struct(item) if item.ident == name => Some(item),
                _ => None,
            })
            .collect();
        match matching.as_slice() {
            [item]
                if is_public(&item.vis)
                    && item.fields.iter().all(|field| !is_public(&field.vis)) => {},
            _ => violations.push(format!(
                "Lua public host type `{name}` must exist exactly once with all fields non-public"
            )),
        }
    }

    let config_shape = public_api_shape(config_source)?;
    let expected_config_symbols: BTreeSet<_> = EXACT_LUA_CONFIG_CONSTANTS
        .iter()
        .map(|(name, _, _)| (*name).to_owned())
        .chain(
            EXACT_LUA_CONFIG_REEXPORTS
                .iter()
                .map(|name| (*name).to_owned()),
        )
        .collect();
    if config_shape.symbols != expected_config_symbols {
        violations.push(format!(
            "Lua config public symbols must remain exactly {expected_config_symbols:?}, found {:?}",
            config_shape.symbols
        ));
    }
    let expected_constants: BTreeMap<_, _> = EXACT_LUA_CONFIG_CONSTANTS
        .iter()
        .map(|(name, ty, value)| (*name, (*ty, *value)))
        .collect();
    let mut actual_constants = BTreeMap::new();
    for item in &config_syntax.items {
        let Item::Const(item) = item else {
            continue;
        };
        if is_public(&item.vis) {
            actual_constants.insert(
                item.ident.to_string(),
                (
                    simple_type_name(&item.ty).unwrap_or_else(|| "<complex>".to_owned()),
                    evaluate_integer_expression(&item.expr),
                ),
            );
        }
    }
    for (name, (expected_type, expected_value)) in expected_constants {
        match actual_constants.get(name) {
            Some((actual_type, Some(actual_value)))
                if actual_type == expected_type && *actual_value == expected_value => {},
            actual => violations.push(format!(
                "Lua config constant `{name}` must remain `{expected_type}` with value {expected_value}, found {actual:?}"
            )),
        }
    }
    if actual_constants.len() != EXACT_LUA_CONFIG_CONSTANTS.len() {
        violations.push(format!(
            "Lua config public constant inventory must contain exactly {} items, found {}",
            EXACT_LUA_CONFIG_CONSTANTS.len(),
            actual_constants.len()
        ));
    }

    let config = config_syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "LuaEngineConfig" => Some(item),
        _ => None,
    });
    let expected_fields: BTreeSet<_> = EXACT_LUA_CONFIG_FIELDS
        .iter()
        .map(|field| (*field).to_owned())
        .collect();
    let actual_fields: BTreeSet<_> = config
        .into_iter()
        .flat_map(|item| item.fields.iter())
        .filter_map(|field| {
            (is_public(&field.vis))
                .then(|| field.ident.as_ref().map(ToString::to_string))
                .flatten()
        })
        .collect();
    if actual_fields != expected_fields {
        violations.push(format!(
            "LuaEngineConfig public fields must remain exactly {expected_fields:?}, found {actual_fields:?}"
        ));
    }
    let private_config_error = config_syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "LuaConfigError" => Some(item),
        _ => None,
    });
    if private_config_error.is_none_or(|item| {
        item.fields
            .iter()
            .any(|field| !matches!(field.vis, Visibility::Inherited))
    }) {
        violations.push(
            "Lua config error `LuaConfigError` must retain private fields and typed accessors"
                .to_owned(),
        );
    }

    Ok(violations)
}

#[derive(Default)]
struct LuaSourceVisitor {
    violations: BTreeSet<String>,
    inside_test_module: usize,
    current_function: Vec<String>,
    allowed_modules: BTreeSet<String>,
    new_with_calls: usize,
    memory_limit_calls: usize,
    hook_calls: usize,
    text_mode_calls: usize,
    environment_calls: usize,
    load_calls: usize,
    multi_value_calls: usize,
    create_function_calls: usize,
    spawn_blocking_calls: usize,
}

impl LuaSourceVisitor {
    fn in_source_loader(&self) -> bool {
        self.current_function.last().is_some_and(|name| {
            matches!(
                name.as_str(),
                "read_registered_source" | "reject_symlink_components" | "same_file_metadata"
            )
        })
    }

    fn inspect_macro_tokens(&mut self, tokens: TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.inspect_macro_tokens(group.stream()),
                TokenTree::Ident(identifier) => {
                    let identifier = semantic_ident_name(&identifier);
                    if matches!(
                        identifier.as_str(),
                        "include"
                            | "include_bytes"
                            | "include_str"
                            | "macro_rules"
                            | "option_env"
                            | "unsafe"
                    ) {
                        self.violations.insert(format!(
                            "Lua production macro tokens cannot contain `{identifier}`"
                        ));
                    }
                },
                TokenTree::Punct(_) | TokenTree::Literal(_) => {},
            }
        }
    }
}

impl<'ast> Visit<'ast> for LuaSourceVisitor {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        let exact_tests = item.ident == "tests"
            && item.content.is_some()
            && item.attrs.len() == 1
            && cfg_predicate(&item.attrs[0]).as_deref() == Some("test");
        if self.inside_test_module == 0 && exact_tests {
            self.inside_test_module += 1;
            syn::visit::visit_item_mod(self, item);
            self.inside_test_module -= 1;
            return;
        }
        let module_name = semantic_ident_name(&item.ident);
        let exact_allowed_child = self.inside_test_module == 0
            && item.content.is_none()
            && item.attrs.is_empty()
            && matches!(item.vis, Visibility::Inherited)
            && self.allowed_modules.contains(&module_name);
        if self.inside_test_module == 0 && !exact_allowed_child {
            self.violations.insert(format!(
                "Lua production module `{}` is forbidden",
                item.ident
            ));
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if self.inside_test_module == 0 {
            self.current_function
                .push(semantic_ident_name(&item.sig.ident));
            syn::visit::visit_item_fn(self, item);
            self.current_function.pop();
        } else {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if self.inside_test_module == 0 {
            let mut bindings = Vec::new();
            collect_use_bindings(&item.tree, &mut Vec::new(), &mut bindings);
            for (path, _) in bindings {
                let key = path.join("::");
                let allowed_loader_file = key == "std::fs::File";
                let filesystem_path = key.starts_with("std::fs")
                    || (key.starts_with("std::os::") && path.iter().any(|segment| segment == "fs"));
                let ambient_path = key.starts_with("std::env")
                    || key.starts_with("std::net")
                    || key.starts_with("std::process")
                    || key.starts_with("std::thread")
                    || key.starts_with("tokio::fs")
                    || key.starts_with("tokio::net")
                    || key.starts_with("tokio::process");
                if ambient_path
                    || (filesystem_path && !allowed_loader_file && !self.in_source_loader())
                {
                    self.violations.insert(format!(
                        "Lua production ambient capability import `{key}` is forbidden"
                    ));
                }
            }
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        if self.inside_test_module == 0 {
            let name = reporting_syn_path_key(attribute.path());
            if matches!(
                name.as_str(),
                "allow" | "cfg_attr" | "macro_export" | "path"
            ) {
                self.violations
                    .insert(format!("Lua production attribute `{name}` is forbidden"));
            }
            if name == "cfg" {
                let predicate = cfg_predicate(attribute).unwrap_or_else(|| "<invalid>".to_owned());
                if !matches!(predicate.as_str(), "unix" | "not(unix)" | "test") {
                    self.violations.insert(format!(
                        "Lua production cfg({predicate}) is outside the exact source-loader portability contract"
                    ));
                }
            }
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if self.inside_test_module == 0 {
            self.violations.insert(format!(
                "Lua production static `{}` is forbidden",
                item.ident
            ));
        }
        syn::visit::visit_item_static(self, item);
    }

    fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
        if self.inside_test_module == 0 {
            self.violations
                .insert("Lua production unsafe block is forbidden".to_owned());
        }
        syn::visit::visit_expr_unsafe(self, expression);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        if self.inside_test_module == 0 {
            self.violations
                .insert("Lua production FFI is forbidden".to_owned());
        }
        syn::visit::visit_item_foreign_mod(self, item);
    }

    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if self.inside_test_module == 0 && (signature.unsafety.is_some() || signature.abi.is_some())
        {
            self.violations.insert(
                "Lua production functions must remain safe Rust without a foreign ABI".to_owned(),
            );
        }
        syn::visit::visit_signature(self, signature);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        if self.inside_test_module == 0 {
            let key = reporting_syn_path_key(path);
            if matches!(
                key.as_str(),
                "Lua::new" | "Lua::unsafe_new" | "Lua::unsafe_new_with"
            ) {
                self.violations
                    .insert(format!("Lua VM constructor `{key}` is forbidden"));
            }
            if key.starts_with("StdLib::") && key != "StdLib::NONE" {
                self.violations.insert(format!(
                    "Lua standard-library selection `{key}` is forbidden"
                ));
            }
            if key.starts_with("ChunkMode::") && key != "ChunkMode::Text" {
                self.violations
                    .insert(format!("Lua chunk mode `{key}` is forbidden"));
            }
            if matches!(
                key.as_str(),
                "std::env"
                    | "std::net"
                    | "std::process"
                    | "std::thread"
                    | "tokio::fs"
                    | "tokio::net"
                    | "tokio::process"
            ) || key.starts_with("std::env::")
                || key.starts_with("std::net::")
                || key.starts_with("std::process::")
                || key.starts_with("std::thread::")
                || key.starts_with("tokio::fs::")
                || key.starts_with("tokio::net::")
                || key.starts_with("tokio::process::")
            {
                self.violations.insert(format!(
                    "Lua production ambient capability path `{key}` is forbidden"
                ));
            }
            if (key.starts_with("File::")
                || key.starts_with("fs::")
                || key.starts_with("std::fs::"))
                && key != "std::fs::File"
                && !self.in_source_loader()
            {
                self.violations.insert(format!(
                    "Lua filesystem operation `{key}` is allowed only in the exact registration-time source loader"
                ));
            }
            if key == "Lua::new_with" {
                self.new_with_calls += 1;
            }
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.inside_test_module == 0 {
            let method = semantic_ident_name(&call.method);
            if matches!(
                method.as_str(),
                "call_async"
                    | "create_async_function"
                    | "create_async_function_mut"
                    | "create_function_mut"
                    | "create_ser_userdata"
                    | "create_thread"
                    | "create_userdata"
                    | "eval"
                    | "eval_async"
                    | "exec"
                    | "globals"
                    | "load_from_function"
                    | "load_from_std_lib"
                    | "set_app_data"
            ) {
                self.violations
                    .insert(format!("Lua production method `{method}` is forbidden"));
            }
            match method.as_str() {
                "set_memory_limit" => self.memory_limit_calls += 1,
                "set_hook" => self.hook_calls += 1,
                "set_mode" => {
                    self.text_mode_calls += usize::from(
                        call.args.len() == 1
                            && reporting_expression_path_is(&call.args[0], &["ChunkMode", "Text"]),
                    );
                },
                "set_environment" => self.environment_calls += 1,
                "load" if reporting_expression_path_is(&call.receiver, &["lua"]) => {
                    self.load_calls += 1;
                },
                "create_function" => self.create_function_calls += 1,
                "spawn_blocking" => self.spawn_blocking_calls += 1,
                "call" => {
                    let has_multi_value = call.turbofish.as_ref().is_some_and(|arguments| {
                        arguments.args.iter().any(|argument| {
                            matches!(
                                argument,
                                syn::GenericArgument::Type(syn::Type::Path(path))
                                    if reporting_syn_path_key(&path.path) == "MultiValue"
                            )
                        })
                    });
                    self.multi_value_calls += usize::from(has_multi_value);
                },
                "canonicalize" | "metadata" | "read_to_end" | "symlink_metadata"
                    if !self.in_source_loader() =>
                {
                    self.violations.insert(format!(
                        "Lua filesystem method `{method}` is allowed only in the exact registration-time source loader"
                    ));
                },
                _ => {},
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if self.inside_test_module == 0 {
            let name = reporting_syn_path_key(&item.path);
            if matches!(
                name.as_str(),
                "env" | "include" | "include_bytes" | "include_str" | "macro_rules" | "option_env"
            ) {
                self.violations
                    .insert(format!("Lua production macro `{name}!` is forbidden"));
            }
            self.inspect_macro_tokens(item.tokens.clone());
        }
        syn::visit::visit_macro(self, item);
    }
}

fn lua_source_authority_violations(sources: &[NamedSource<'_>]) -> Result<Vec<String>, syn::Error> {
    let mut visitor = LuaSourceVisitor::default();
    visitor.violations.extend(source_path_inventory_violations(
        "Lua engine",
        sources,
        LUA_ENGINE_PRODUCTION_SOURCE_PATHS,
    ));
    for (path, source) in sources {
        let syntax = syn::parse_file(source)?;
        visitor.allowed_modules = if *path == "lua_engine.rs" {
            LUA_ENGINE_ROOT_MODULES
                .iter()
                .map(|module| (*module).to_owned())
                .collect()
        } else {
            BTreeSet::new()
        };
        visitor.visit_file(&syntax);
    }
    for (label, actual, expected) in [
        ("Lua::new_with", visitor.new_with_calls, 1),
        ("set_memory_limit", visitor.memory_limit_calls, 1),
        ("set_hook", visitor.hook_calls, 1),
        ("ChunkMode::Text", visitor.text_mode_calls, 1),
        ("set_environment", visitor.environment_calls, 1),
        ("load", visitor.load_calls, 1),
        ("MultiValue call", visitor.multi_value_calls, 1),
        ("create_function", visitor.create_function_calls, 5),
        ("spawn_blocking", visitor.spawn_blocking_calls, 1),
    ] {
        if actual != expected {
            visitor.violations.insert(format!(
                "Lua production `{label}` count must remain exactly {expected}, found {actual}"
            ));
        }
    }
    Ok(visitor.violations.into_iter().collect())
}

fn lua_production_inventory_violations(
    engine_sources: &[NamedSource<'_>],
    config_source: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    let config_sources = [("lua_config.rs", config_source)];
    for (
        surface,
        sources,
        expected_paths,
        inline_test_roots,
        expected_bytes,
        expected_fingerprint,
    ) in [
        (
            "Lua engine",
            engine_sources,
            LUA_ENGINE_PRODUCTION_SOURCE_PATHS,
            &["lua_engine.rs"][..],
            EXACT_LUA_ENGINE_PRODUCTION_TOKEN_BYTES,
            EXACT_LUA_ENGINE_PRODUCTION_FINGERPRINT,
        ),
        (
            "Lua config",
            &config_sources,
            LUA_CONFIG_PRODUCTION_SOURCE_PATHS,
            &["lua_config.rs"][..],
            EXACT_LUA_CONFIG_PRODUCTION_TOKEN_BYTES,
            EXACT_LUA_CONFIG_PRODUCTION_FINGERPRINT,
        ),
    ] {
        let (bytes, fingerprint) = match normalized_production_source_set_fingerprint(
            surface,
            sources,
            expected_paths,
            inline_test_roots,
        ) {
            Ok(inventory) => inventory,
            Err(mut errors) => {
                violations.append(&mut errors);
                continue;
            },
        };
        if bytes != expected_bytes || fingerprint != expected_fingerprint {
            violations.push(format!(
                "{surface} root+children exact public signatures and production AST/body inventory changed; expected normalized framed bytes/fingerprint {expected_bytes}/{expected_fingerprint:032x}, found {bytes}/{fingerprint:032x}"
            ));
        }
    }
    violations
}

#[derive(Debug, Default)]
struct PublicApiShape {
    symbols: BTreeSet<String>,
    methods: BTreeSet<String>,
    fields: BTreeSet<String>,
}

fn forbidden_surface_source_violations(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let scanner_source = workspace_root.join("crates/venom-scanner/src");
    let mut violations = Vec::new();
    for contract in FORBIDDEN_SURFACE_APIS {
        let path = scanner_source.join(format!("{}.rs", contract.module));
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound && contract.module == "waf" => {
                continue;
            },
            Err(error) => return Err(error.into()),
        };
        violations.extend(forbidden_public_api_violations(contract, &source)?);
    }
    let lib_source = fs::read_to_string(scanner_source.join("lib.rs"))?;
    let lib_shape = public_api_shape(&lib_source)?;
    let retired_symbols: BTreeSet<_> = FORBIDDEN_SURFACE_APIS
        .iter()
        .flat_map(|contract| contract.public_symbols.iter().copied())
        .chain(FORBIDDEN_ADAPTIVE_API.public_symbols.iter().copied())
        .chain(FORBIDDEN_ADAPTIVE_API.public_methods.iter().copied())
        .collect();
    for symbol in retired_symbols {
        if lib_shape.symbols.contains(symbol) {
            violations.push(format!(
                "retired public facade `{symbol}` must not be re-exported by venom-scanner"
            ));
        }
    }
    Ok(violations)
}

#[derive(Default)]
struct ReportingSourceVisitor {
    violations: BTreeSet<String>,
    inside_test_module: usize,
}

const EXACT_REPORTING_PRODUCTION_TOKEN_BYTES: usize = 48_537;
const EXACT_REPORTING_PRODUCTION_FINGERPRINT: u128 = 0xa7e8_6395_492c_37d9_ba90_4a62_bc03_d480;

fn reporting_production_body_inventory_violations(source: &str) -> Vec<String> {
    let Ok(syntax) = syn::parse_file(source) else {
        return vec!["reporting.rs must remain valid Rust source".to_owned()];
    };
    let exact_test_modules = syntax
        .items
        .iter()
        .filter(|item| {
            matches!(
                item,
                Item::Mod(module)
                    if module.ident == "tests"
                        && module.content.is_some()
                        && module.attrs.len() == 1
                        && cfg_predicate(&module.attrs[0]).as_deref() == Some("test")
            )
        })
        .count();
    if exact_test_modules != 1
        || !matches!(
            syntax.items.last(),
            Some(Item::Mod(module))
                if module.ident == "tests"
                    && module.content.is_some()
                    && module.attrs.len() == 1
                    && cfg_predicate(&module.attrs[0]).as_deref() == Some("test")
        )
    {
        return vec![
            "reporting.rs must end with exactly one exact cfg(test) inline tests module".to_owned(),
        ];
    }
    let Some((production, _)) = source.split_once("#[cfg(test)]") else {
        return vec![
            "reporting.rs must end production code with the exact cfg(test) module boundary"
                .to_owned(),
        ];
    };
    let Ok(tokens) = production.parse::<TokenStream>() else {
        return vec!["reporting.rs production source must remain valid Rust tokens".to_owned()];
    };
    let normalized = tokens.to_string();
    let fingerprint = normalized.bytes().fold(
        0x6c62_272e_07bb_0142_62b8_2175_6295_c58d_u128,
        |fingerprint, byte| {
            (fingerprint ^ u128::from(byte))
                .wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013B_u128)
        },
    );
    if normalized.len() == EXACT_REPORTING_PRODUCTION_TOKEN_BYTES
        && fingerprint == EXACT_REPORTING_PRODUCTION_FINGERPRINT
    {
        Vec::new()
    } else {
        vec![format!(
            "reporting.rs production AST/body inventory changed; expected normalized bytes/fingerprint {EXACT_REPORTING_PRODUCTION_TOKEN_BYTES}/{EXACT_REPORTING_PRODUCTION_FINGERPRINT:032x}, found {}/{fingerprint:032x}",
            normalized.len()
        )]
    }
}

const EXACT_REPORTING_SOURCE_IMPORTS: &[&str] = &[
    "crate::web_runtime::AssessmentBasis",
    "crate::web_runtime::AssessmentRunReport",
    "crate::web_runtime::AssessmentRunReportError",
    "crate::web_runtime::ScanProfileV1",
    "crate::web_runtime::WebAssessmentRunReport",
    "serde::Serialize",
    "std::error::Error",
    "std::fmt",
    "std::io",
    "venom_core::OutcomeStatus",
    "venom_core::ResourceAccounting",
    "venom_core::ResourceAccountingMode",
    "venom_core::RunOutcomeRecord",
    "venom_core::RunReport",
    "venom_core::RunStatus",
    "venom_core::RunStepStatus",
    "venom_core::RunStopCode",
    "venom_core::SecuritySeverity",
];

const ALLOWED_REPORTING_QUALIFIED_PATHS: &[&str] = &[
    "AssessmentBasis::Differential",
    "AssessmentBasis::Observation",
    "AssessmentBasis::Verifier",
    "AssessmentBasisLinkageDocument::from_basis",
    "AssessmentDocument::from_report",
    "AssessmentItemDocument::from_item",
    "OutcomeDocument::from_outcome",
    "OutcomeStatus::Blocked",
    "OutcomeStatus::ConfirmedNegative",
    "OutcomeStatus::FalsePositive",
    "OutcomeStatus::NeedsReview",
    "OutcomeStatus::Success",
    "OutcomeStatus::Unknown",
    "ReportError::OutputLimitExceeded",
    "ReportError::Serialization",
    "ReportFormat::Csv",
    "ReportFormat::Html",
    "ReportFormat::Json",
    "ReportFormat::Markdown",
    "ResourceAccountingMode::Metered",
    "ResourceAccountingMode::Observed",
    "ResourceAccountingMode::Unmetered",
    "RunStatus::Cancelled",
    "RunStatus::Complete",
    "RunStatus::Failed",
    "RunStatus::Partial",
    "RunStepStatus::BudgetExhausted",
    "RunStepStatus::Cancelled",
    "RunStepStatus::Failed",
    "RunStepStatus::Skipped",
    "RunStepStatus::Succeeded",
    "RunStepStatus::TimedOut",
    "RunStopCode::BudgetExhausted",
    "RunStopCode::Cancelled",
    "RunStopCode::Completed",
    "RunStopCode::NoEligibleAction",
    "RunStopCode::ReportLimitExceeded",
    "RunStopCode::RuntimeFailed",
    "RunStopCode::StepFailed",
    "RunStopCode::StepTimedOut",
    "RunStopCode::TaskJoinFailed",
    "SecuritySeverity::Critical",
    "SecuritySeverity::High",
    "SecuritySeverity::Info",
    "SecuritySeverity::Low",
    "SecuritySeverity::Medium",
    "Self::Csv",
    "Self::Html",
    "Self::Json",
    "Self::Markdown",
    "Self::OutputLimitExceeded",
    "Self::Serialization",
    "StepDocument::from_step",
    "ToString::to_string",
    "char::from",
    "crate::web_runtime::AssessmentBasis",
    "crate::web_runtime::AssessmentItem",
    "crate::web_runtime::AssessmentRunReport",
    "crate::web_runtime::AssessmentRunReportError",
    "crate::web_runtime::ScanProfileV1",
    "crate::web_runtime::WebAssessmentRunReport",
    "fmt::Arguments",
    "fmt::Display",
    "fmt::Error",
    "fmt::Formatter",
    "fmt::Result",
    "fmt::Write",
    "fmt::write",
    "io::Error",
    "io::Error::other",
    "io::Result",
    "io::Write",
    "serde::Serialize",
    "serde_json::to_writer",
    "std::error::Error",
    "std::fmt",
    "std::io",
    "std::str::from_utf8",
    "u16::MAX",
    "u32::from",
    "u64::try_from",
    "venom_core::OutcomeStatus",
    "venom_core::ResourceAccounting",
    "venom_core::ResourceAccountingMode",
    "venom_core::RunOutcomeRecord",
    "venom_core::RunReport",
    "venom_core::RunStatus",
    "venom_core::RunStepReport",
    "venom_core::RunStepStatus",
    "venom_core::RunStopCode",
    "venom_core::SecuritySeverity",
];

const ALLOWED_REPORTING_FUNCTION_CALLS: &[&str] = &[
    "AccountingDimension::from_accounting",
    "AccountingDocument::from_report",
    "AssessmentBasisLinkageDocument::from_basis",
    "AssessmentDocument::from_report",
    "AssessmentItemDocument::from_item",
    "Err",
    "Ok",
    "RawJsonWriter::new",
    "RenderBuffer::new",
    "ReportDocument::from_report",
    "Some",
    "String::from",
    "String::new",
    "String::with_capacity",
    "Vec::new",
    "accounting_mode_token",
    "assessment_basis_token",
    "assessment_reference_list",
    "char::from",
    "disposition_token",
    "fmt::write",
    "io::Error::other",
    "is_bidi_control",
    "longest_backtick_run",
    "push_visible_codepoint",
    "render_csv",
    "render_assessment_csv",
    "render_assessment_html",
    "render_assessment_markdown",
    "render_assessment_with_limit",
    "render_html",
    "render_json",
    "render_markdown",
    "render_serializable_json",
    "render_with_limit",
    "run_status_token",
    "serde_json::to_writer",
    "severity_token",
    "starts_csv_formula_after_whitespace",
    "std::str::from_utf8",
    "step_status_token",
    "stop_code_token",
    "u32::from",
    "u64::try_from",
    "visible_text",
    "valid_opaque_assessment_reference",
    "write_assessment_csv_row",
    "write_csv_cell",
    "write_csv_row",
    "write_html_optional_decimal",
    "write_html_optional_assessment_text",
    "write_html_text",
    "write_json_codepoint",
    "write_markdown_code_span",
    "write_markdown_optional_assessment_text",
    "write_markdown_optional_decimal",
    "write_visible_codepoint",
];

const ALLOWED_REPORTING_METHOD_CALLS: &[&str] = &[
    "accounting",
    "action_id",
    "all",
    "and_then",
    "as_deref",
    "as_str",
    "authorized_origin",
    "basis",
    "bytes",
    "candidate",
    "capability_id",
    "case_reference",
    "category",
    "chain",
    "chars",
    "checked_add",
    "clone",
    "code",
    "collect",
    "completed_at",
    "confidence",
    "contains",
    "consumed",
    "control",
    "cwe",
    "dimensions",
    "disposition",
    "duration_ms",
    "ends_with",
    "enumerate",
    "evidence_ids",
    "evidence",
    "evidence_count",
    "extend_from_slice",
    "find",
    "fingerprint",
    "finish",
    "id",
    "into_iter",
    "into_assessment_report",
    "is_control",
    "is_ascii_digit",
    "is_empty",
    "is_err",
    "is_none",
    "is_some",
    "is_some_and",
    "is_whitespace",
    "iter",
    "item_count",
    "items",
    "join",
    "len",
    "len_utf8",
    "limit",
    "map",
    "map_err",
    "max",
    "metadata",
    "mode",
    "ok_or",
    "ok",
    "ordinal",
    "outcomes",
    "outcome_reference",
    "paired_comparison",
    "parts_per_million",
    "push",
    "push_char",
    "push_fmt",
    "push_str",
    "profile",
    "redacted_summary",
    "remaining",
    "reference_count",
    "remediation",
    "request_body_bytes",
    "requests",
    "required_metadata",
    "response_body_bytes",
    "run_report",
    "schema",
    "severity",
    "started_at",
    "stage",
    "starts_with",
    "status",
    "steps",
    "stop_reason",
    "strip_prefix",
    "subject_count",
    "subject_reference",
    "summary",
    "target",
    "title",
    "to_owned",
    "to_rfc3339",
    "to_string",
    "try_reserve",
    "unwrap_or",
    "unwrap_or_else",
    "validate",
    "verification_outcome",
    "wall_time_ms",
    "write_str",
];

const ALLOWED_REPORTING_MACROS: &[&str] = &["format_args", "matches", "vec"];
const ALLOWED_REPORTING_ATTRIBUTES: &[&str] = &["derive", "doc", "non_exhaustive"];

fn reporting_source_import_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let expected: BTreeSet<_> = EXACT_REPORTING_SOURCE_IMPORTS
        .iter()
        .map(|path| (*path).to_owned())
        .collect();
    let mut actual = BTreeMap::<String, usize>::new();
    let mut violations = Vec::new();
    for item in &syntax.items {
        let Item::Use(item) = item else {
            continue;
        };
        let mut paths = Vec::new();
        if !collect_reporting_import_paths(&item.tree, &mut Vec::new(), &mut paths) {
            violations.push("reporting production imports cannot use aliases or globs".to_owned());
        }
        let assessment_import = !paths.is_empty()
            && paths.iter().all(|path| {
                matches!(
                    path.as_str(),
                    "crate::web_runtime::AssessmentBasis"
                        | "crate::web_runtime::AssessmentRunReport"
                        | "crate::web_runtime::AssessmentRunReportError"
                        | "crate::web_runtime::ScanProfileV1"
                        | "crate::web_runtime::WebAssessmentRunReport"
                )
            });
        let attributes_are_exact = if assessment_import {
            item.attrs.len() == 1
                && item.attrs[0].path().is_ident("cfg")
                && cfg_predicate(&item.attrs[0]).as_deref() == Some("feature=\"scanning\"")
        } else {
            item.attrs.is_empty()
        };
        if !matches!(item.vis, Visibility::Inherited) || !attributes_are_exact {
            violations.push(
                "reporting production imports must remain private; only the exact web-assessment import may use cfg(feature = \"scanning\")"
                    .to_owned(),
            );
        }
        for path in paths {
            *actual.entry(path).or_default() += 1;
        }
    }
    let actual_names: BTreeSet<_> = actual.keys().cloned().collect();
    if actual_names != expected || actual.values().any(|count| *count != 1) {
        violations.push(format!(
            "reporting production imports must be exactly {expected:?}, found {actual:?}"
        ));
    }
    Ok(violations)
}

fn collect_reporting_import_paths(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    paths: &mut Vec<String>,
) -> bool {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            let exact = collect_reporting_import_paths(&path.tree, prefix, paths);
            prefix.pop();
            exact
        },
        UseTree::Name(name) => {
            let name = semantic_ident_name(&name.ident);
            if name != "self" {
                prefix.push(name.clone());
            }
            if prefix.is_empty() {
                return false;
            }
            paths.push(prefix.join("::"));
            if name != "self" {
                prefix.pop();
            }
            true
        },
        UseTree::Group(group) => group
            .items
            .iter()
            .all(|item| collect_reporting_import_paths(item, prefix, paths)),
        UseTree::Glob(_) | UseTree::Rename(_) => false,
    }
}

impl<'ast> Visit<'ast> for ReportingSourceVisitor {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        let attribute_name = reporting_syn_path_key(attribute.path());
        if attribute_name == "macro_export" {
            self.violations
                .insert("reporting must not export macros from any nested source scope".to_owned());
        }
        if self.inside_test_module != 0 {
            syn::visit::visit_attribute(self, attribute);
            return;
        }
        let exact_scanning_gate = attribute_name == "cfg"
            && cfg_predicate(attribute).as_deref() == Some("feature=\"scanning\"");
        if matches!(attribute_name.as_str(), "cfg" | "cfg_attr") && !exact_scanning_gate {
            self.violations.insert(
                "reporting production source may contain only the exact cfg(feature = \"scanning\") assessment-composition gate"
                    .to_owned(),
            );
        }
        if !ALLOWED_REPORTING_ATTRIBUTES.contains(&attribute_name.as_str())
            && !matches!(attribute_name.as_str(), "cfg" | "cfg_attr")
        {
            self.violations.insert(format!(
                "reporting production attribute `{attribute_name}` is outside the exact allowlist"
            ));
        }
        let path: Vec<_> = attribute
            .path()
            .segments
            .iter()
            .map(|segment| semantic_ident_name(&segment.ident))
            .collect();
        inspect_reporting_path(&path, &mut self.violations);
        if let syn::Meta::List(list) = &attribute.meta {
            inspect_reporting_macro_tokens(list.tokens.clone(), &mut self.violations);
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_ident(&mut self, identifier: &'ast syn::Ident) {
        if self.inside_test_module != 0 {
            syn::visit::visit_ident(self, identifier);
            return;
        }
        inspect_reporting_identifier(&semantic_ident_name(identifier), &mut self.violations);
        syn::visit::visit_ident(self, identifier);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if self.inside_test_module != 0 {
            syn::visit::visit_item_use(self, item);
            return;
        }
        inspect_reporting_use_tree(&item.tree, &mut Vec::new(), &mut self.violations);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if self.inside_test_module == 0 {
            self.violations.insert(format!(
                "reporting production source cannot delegate through extern crate `{}`",
                item.ident
            ));
        }
        syn::visit::visit_item_extern_crate(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if self.inside_test_module != 0 {
            syn::visit::visit_item_mod(self, item);
            return;
        }
        let cfg_attributes: Vec<_> = item
            .attrs
            .iter()
            .filter(|attribute| {
                matches!(
                    reporting_syn_path_key(attribute.path()).as_str(),
                    "cfg" | "cfg_attr"
                )
            })
            .collect();
        let exact_inline_tests = item.ident == "tests"
            && item.content.is_some()
            && cfg_attributes.len() == 1
            && reporting_syn_path_key(cfg_attributes[0].path()) == "cfg"
            && cfg_predicate(cfg_attributes[0]).as_deref() == Some("test");
        let exact_test_attributes = item.attrs.iter().all(|attribute| {
            reporting_syn_path_key(attribute.path()) == "doc"
                || (reporting_syn_path_key(attribute.path()) == "cfg"
                    && cfg_predicate(attribute).as_deref() == Some("test"))
        });
        if exact_inline_tests && exact_test_attributes {
            self.inside_test_module += 1;
            syn::visit::visit_item_mod(self, item);
            self.inside_test_module -= 1;
            return;
        }
        self.violations.insert(format!(
            "reporting production module `{}` is forbidden; only the exact inline cfg(test) module is allowed",
            item.ident
        ));
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if self.inside_test_module == 0 {
            self.violations.insert(format!(
                "reporting static `{}` is forbidden; rendering must remain stateless",
                item.ident
            ));
        }
        syn::visit::visit_item_static(self, item);
    }

    fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
        if self.inside_test_module == 0 {
            self.violations.insert(
                "reporting cannot contain unsafe blocks or bypass Rust authority boundaries"
                    .to_owned(),
            );
        }
        syn::visit::visit_expr_unsafe(self, expression);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        if self.inside_test_module == 0 {
            self.violations.insert(
                "reporting cannot declare foreign modules or call through raw FFI".to_owned(),
            );
        }
        syn::visit::visit_item_foreign_mod(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if self.inside_test_module == 0 && item.unsafety.is_some() {
            self.violations
                .insert("reporting cannot contain unsafe impls".to_owned());
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if self.inside_test_module == 0 {
            self.violations.insert(format!(
                "reporting production trait `{}` is forbidden; public trait semantics must come from exact imports",
                item.ident
            ));
        }
        syn::visit::visit_item_trait(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if self.inside_test_module == 0 {
            self.violations.insert(format!(
                "reporting production type alias `{}` is forbidden; public signatures must resolve directly",
                item.ident
            ));
        }
        syn::visit::visit_item_type(self, item);
    }

    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if self.inside_test_module == 0 && (signature.unsafety.is_some() || signature.abi.is_some())
        {
            self.violations.insert(
                "reporting functions must be safe Rust functions without a foreign ABI".to_owned(),
            );
        }
        syn::visit::visit_signature(self, signature);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        if self.inside_test_module != 0 {
            syn::visit::visit_path(self, path);
            return;
        }
        let segments: Vec<_> = path
            .segments
            .iter()
            .map(|segment| semantic_ident_name(&segment.ident))
            .collect();
        inspect_reporting_path(&segments, &mut self.violations);
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.inside_test_module == 0 {
            let function = reporting_expression_path_key(&call.func)
                .unwrap_or_else(|| "<indirect-call>".to_owned());
            if !ALLOWED_REPORTING_FUNCTION_CALLS.contains(&function.as_str()) {
                self.violations.insert(format!(
                    "reporting production function call `{function}` is outside the exact allowlist"
                ));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.inside_test_module == 0 {
            let method = call.method.to_string();
            if !ALLOWED_REPORTING_METHOD_CALLS.contains(&method.as_str()) {
                self.violations.insert(format!(
                    "reporting production method call `{method}` is outside the exact allowlist"
                ));
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if self.inside_test_module != 0 {
            syn::visit::visit_macro(self, item);
            return;
        }
        let path = reporting_syn_path_key(&item.path);
        if !ALLOWED_REPORTING_MACROS.contains(&path.as_str()) {
            self.violations.insert(format!(
                "reporting production macro `{path}!` is outside the exact allowlist"
            ));
        }
        let segments: Vec<_> = item
            .path
            .segments
            .iter()
            .map(|segment| semantic_ident_name(&segment.ident))
            .collect();
        inspect_reporting_path(&segments, &mut self.violations);
        inspect_reporting_macro_tokens(item.tokens.clone(), &mut self.violations);
        syn::visit::visit_macro(self, item);
    }
}

fn reporting_source_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = ReportingSourceVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.violations.into_iter().collect())
}

fn inspect_reporting_use_tree(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    violations: &mut BTreeSet<String>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(semantic_ident_name(&path.ident));
            inspect_reporting_use_tree(&path.tree, prefix, violations);
            prefix.pop();
        },
        UseTree::Name(name) => {
            prefix.push(semantic_ident_name(&name.ident));
            inspect_reporting_path(prefix, violations);
            prefix.pop();
        },
        UseTree::Rename(rename) => {
            if (prefix.is_empty() && rename.ident == "std")
                || (prefix.len() == 1 && prefix[0] == "std" && rename.ident == "self")
            {
                violations.insert(
                    "reporting must not alias `std`; direct module paths keep the I/O policy auditable"
                        .to_owned(),
                );
            }
            prefix.push(semantic_ident_name(&rename.ident));
            inspect_reporting_path(prefix, violations);
            prefix.pop();
        },
        UseTree::Group(group) => {
            for item in &group.items {
                inspect_reporting_use_tree(item, prefix, violations);
            }
        },
        UseTree::Glob(_) => inspect_reporting_path(prefix, violations),
    }
}

fn inspect_reporting_path(segments: &[String], violations: &mut BTreeSet<String>) {
    let Some(root) = segments.first() else {
        return;
    };
    let key = segments.join("::");
    let exact_internal_assessment_path = ALLOWED_REPORTING_QUALIFIED_PATHS.contains(&key.as_str())
        && key.starts_with("crate::web_runtime::");
    if (root == "crate" || root == "super" || (root == "self" && segments.len() > 1))
        && !exact_internal_assessment_path
    {
        violations.insert(format!(
            "reporting production path `{key}` cannot delegate outside the audited source unit"
        ));
        return;
    }
    if segments.len() == 1 {
        return;
    }
    if !ALLOWED_REPORTING_QUALIFIED_PATHS.contains(&key.as_str())
        && !ALLOWED_REPORTING_FUNCTION_CALLS.contains(&key.as_str())
    {
        violations.insert(format!(
            "reporting production path `{key}` is outside the exact authority allowlist"
        ));
    }
}

fn inspect_reporting_identifier(identifier: &str, violations: &mut BTreeSet<String>) {
    match identifier {
        "ScanFinding" => {
            violations.insert(
                "reporting must consume typed `RunReport`, not legacy `ScanFinding`".to_owned(),
            );
        },
        "VulnerabilityReport" | "phase_stats" | "risk_score" | "severity_stats" => {
            violations.insert(format!(
                "retired reporting API `{identifier}` must not return"
            ));
        },
        "File" | "OpenOptions" => {
            violations.insert(format!(
                "reporting must remain a pure renderer and cannot use `{identifier}`"
            ));
        },
        "copy" | "read_to_string" | "stderr" | "stdin" | "stdout" => {
            violations.insert(format!(
                "reporting cannot use concrete standard-I/O operation `{identifier}`"
            ));
        },
        "extern" | "unsafe" => {
            violations.insert(format!(
                "reporting macro tokens cannot generate `{identifier}` authority"
            ));
        },
        "Instant" | "Local" | "OsRng" | "SystemTime" | "Utc" | "Uuid" | "getrandom" | "random"
        | "thread_rng" => {
            violations.insert(format!(
                "reporting cannot use ambient clock, identity, or randomness source `{identifier}`"
            ));
        },
        "HashMap" | "HashSet" | "RandomState" => {
            violations.insert(format!(
                "reporting cannot use randomized-order collection or state `{identifier}`"
            ));
        },
        "LazyLock" | "Mutex" | "OnceLock" | "RwLock" | "lazy_static" | "once_cell"
        | "thread_local" => {
            violations.insert(format!(
                "reporting cannot use mutable or lazy global-state primitive `{identifier}`"
            ));
        },
        _ => {},
    }
}

fn inspect_reporting_macro_tokens(tokens: TokenStream, violations: &mut BTreeSet<String>) {
    let mut path = Vec::<String>::new();
    let mut colon_count = 0_u8;
    let flush_path = |path: &mut Vec<String>, violations: &mut BTreeSet<String>| {
        if !path.is_empty() {
            inspect_reporting_path(path, violations);
            path.clear();
        }
    };
    for token in tokens {
        match token {
            TokenTree::Group(group) => {
                flush_path(&mut path, violations);
                inspect_reporting_macro_tokens(group.stream(), violations);
                colon_count = 0;
            },
            TokenTree::Ident(identifier) => {
                let identifier = semantic_ident_name(&identifier);
                inspect_reporting_identifier(&identifier, violations);
                if identifier == "mod" {
                    violations.insert(
                        "reporting cannot generate a module through macro tokens".to_owned(),
                    );
                }
                if path.is_empty() || colon_count == 2 {
                    path.push(identifier);
                } else {
                    flush_path(&mut path, violations);
                    path.push(identifier);
                }
                colon_count = 0;
            },
            TokenTree::Punct(punctuation) if punctuation.as_char() == ':' && !path.is_empty() => {
                colon_count = colon_count.saturating_add(1);
            },
            TokenTree::Punct(punctuation)
                if punctuation.as_char() == '!'
                    && punctuation.spacing() == proc_macro2::Spacing::Alone =>
            {
                if !path.is_empty() {
                    let nested = path.join("::");
                    violations.insert(format!(
                        "reporting allowlisted macros cannot invoke nested macro `{nested}!`"
                    ));
                }
                flush_path(&mut path, violations);
                colon_count = 0;
            },
            TokenTree::Punct(_) | TokenTree::Literal(_) => {
                flush_path(&mut path, violations);
                colon_count = 0;
            },
        }
    }
    flush_path(&mut path, violations);
}

fn adaptive_surface_violations(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let adaptive_dir = workspace_root.join("crates/venom-scanner/src/adaptive");
    let module_source = fs::read_to_string(adaptive_dir.join("mod.rs"))?;
    let pipeline_source = fs::read_to_string(adaptive_dir.join("pipeline.rs"))?;
    let mut violations = adaptive_module_source_violations(&module_source)?;
    violations.extend(forbidden_public_api_violations(
        &FORBIDDEN_ADAPTIVE_API,
        &pipeline_source,
    )?);

    for entry in fs::read_dir(&adaptive_dir)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        for retired in RETIRED_ADAPTIVE_MODULES {
            let retired_file = file_name
                .strip_suffix(".rs")
                .is_some_and(|stem| stem == *retired);
            if file_name == *retired || retired_file {
                violations.push(format!(
                    "retired adaptive source `{}` must remain absent; only adaptive::pipeline is supported",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
    }
    Ok(violations)
}

fn adaptive_module_source_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = forbidden_public_api_violations(&FORBIDDEN_ADAPTIVE_API, source)?;
    let pipeline_modules: Vec<_> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == "pipeline" => Some(module),
            _ => None,
        })
        .collect();
    match pipeline_modules.as_slice() {
        [module]
            if is_public(&module.vis)
                && module.content.is_none()
                && cfg_predicates(module).is_empty() => {},
        _ => violations.push(
            "adaptive must expose exactly one unconditional out-of-line `pub mod pipeline;`"
                .to_owned(),
        ),
    }
    for retired in RETIRED_ADAPTIVE_MODULES {
        if syntax
            .items
            .iter()
            .any(|item| matches!(item, Item::Mod(module) if module.ident == *retired))
        {
            violations.push(format!(
                "retired adaptive module `{retired}` must not be declared"
            ));
        }
    }
    Ok(violations)
}

fn forbidden_public_api_violations(
    contract: &ForbiddenSurfaceApi,
    source: &str,
) -> Result<Vec<String>, syn::Error> {
    let shape = public_api_shape(source)?;
    let mut violations = Vec::new();
    for symbol in contract.public_symbols {
        if shape.symbols.contains(*symbol) {
            violations.push(format!(
                "retired public facade `{symbol}` must not return in `{}`",
                contract.module
            ));
        }
    }
    for method in contract.public_methods {
        if shape.methods.contains(*method) || shape.symbols.contains(*method) {
            violations.push(format!(
                "retired operational API `{method}` must not return in `{}`",
                contract.module
            ));
        }
    }
    for field in contract.public_fields {
        if shape.fields.contains(*field) {
            violations.push(format!(
                "retired security-claiming field `{field}` must not return in `{}`",
                contract.module
            ));
        }
    }
    Ok(violations)
}

fn public_api_shape(source: &str) -> Result<PublicApiShape, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut shape = PublicApiShape::default();
    for item in &syntax.items {
        match item {
            Item::Const(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
            },
            Item::Enum(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
                for variant in &item.variants {
                    collect_fields(&variant.fields, &mut shape.fields, true);
                }
            },
            Item::Fn(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.sig.ident.to_string());
            },
            Item::Impl(item) => {
                for implementation_item in &item.items {
                    match implementation_item {
                        ImplItem::Fn(method) if is_public(&method.vis) => {
                            shape.methods.insert(method.sig.ident.to_string());
                        },
                        _ => {},
                    }
                }
            },
            Item::Static(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
            },
            Item::Struct(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
                collect_fields(&item.fields, &mut shape.fields, false);
            },
            Item::Trait(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
            },
            Item::Type(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
            },
            Item::Union(item) if is_public(&item.vis) => {
                shape.symbols.insert(item.ident.to_string());
                for field in &item.fields.named {
                    match &field.ident {
                        Some(identifier) if is_public(&field.vis) => {
                            shape.fields.insert(identifier.to_string());
                        },
                        _ => {},
                    }
                }
            },
            Item::Use(item) if is_public(&item.vis) => {
                collect_use_names(&item.tree, &mut shape.symbols);
            },
            _ => {},
        }
    }
    Ok(shape)
}

fn collect_use_names(tree: &UseTree, names: &mut BTreeSet<String>) {
    match tree {
        UseTree::Name(name) => {
            names.insert(name.ident.to_string());
        },
        UseTree::Rename(rename) => {
            names.insert(rename.rename.to_string());
        },
        UseTree::Path(path) => collect_use_names(&path.tree, names),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_names(item, names);
            }
        },
        UseTree::Glob(_) => {},
    }
}

fn collect_fields(fields: &Fields, names: &mut BTreeSet<String>, enum_fields_are_public: bool) {
    for field in fields {
        match &field.ident {
            Some(identifier) if enum_fields_are_public || is_public(&field.vis) => {
                names.insert(identifier.to_string());
            },
            _ => {},
        }
    }
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn distributed_sources() -> Vec<NamedSource<'static>> {
        vec![
            (
                "distributed.rs",
                include_str!("../../../crates/venom-scanner/src/distributed.rs"),
            ),
            (
                "distributed/coordinator.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/coordinator.rs"),
            ),
            (
                "distributed/lease.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/lease.rs"),
            ),
            (
                "distributed/limits.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/limits.rs"),
            ),
            (
                "distributed/model.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/model.rs"),
            ),
            (
                "distributed/queue.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/queue.rs"),
            ),
            (
                "distributed/recovery.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/recovery.rs"),
            ),
            (
                "distributed/results.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/results.rs"),
            ),
            (
                "distributed/worker.rs",
                include_str!("../../../crates/venom-scanner/src/distributed/worker.rs"),
            ),
        ]
    }

    fn lua_engine_sources() -> Vec<NamedSource<'static>> {
        vec![
            (
                "lua_engine.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine.rs"),
            ),
            (
                "lua_engine/execution.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine/execution.rs"),
            ),
            (
                "lua_engine/history.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine/history.rs"),
            ),
            (
                "lua_engine/limits.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine/limits.rs"),
            ),
            (
                "lua_engine/registry.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine/registry.rs"),
            ),
            (
                "lua_engine/source.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine/source.rs"),
            ),
            (
                "lua_engine/vm.rs",
                include_str!("../../../crates/venom-scanner/src/lua_engine/vm.rs"),
            ),
        ]
    }

    fn source<'a>(sources: &[NamedSource<'a>], path: &str) -> &'a str {
        sources
            .iter()
            .find_map(|(candidate, source)| (*candidate == path).then_some(*source))
            .unwrap_or_else(|| panic!("missing test source {path}"))
    }

    fn replacing_source<'a>(
        sources: &[NamedSource<'static>],
        path: &str,
        replacement: &'a str,
    ) -> Vec<NamedSource<'a>> {
        assert!(sources.iter().any(|(candidate, _)| *candidate == path));
        sources
            .iter()
            .map(|(candidate, source)| {
                (
                    *candidate,
                    if *candidate == path {
                        replacement
                    } else {
                        *source
                    },
                )
            })
            .collect()
    }

    fn valid_feature_map() -> BTreeMap<String, Vec<String>> {
        let mut features = BTreeMap::new();
        features.insert(
            "default".to_owned(),
            vec!["core".to_owned(), "scanning".to_owned()],
        );
        features.insert("core".to_owned(), Vec::new());
        features.insert(
            "scanning".to_owned(),
            [
                "core",
                "dep:async-trait",
                "dep:html5ever",
                "dep:markup5ever_rcdom",
                "dep:reqwest",
                "dep:tokio",
                "dep:tokio-util",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
        features.insert(
            "legacy-scanner".to_owned(),
            [
                "scanning",
                "venom-core/legacy-contracts",
                "dep:chrono",
                "dep:dashmap",
                "dep:futures",
                "dep:uuid",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
        features.insert(
            "platform-models".to_owned(),
            [
                "core",
                "venom-core/legacy-contracts",
                "dep:dashmap",
                "dep:uuid",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
        features.insert("reporting".to_owned(), vec!["core".to_owned()]);
        features.insert("detection".to_owned(), vec!["dep:regex".to_owned()]);
        features.insert("ml".to_owned(), Vec::new());
        features.insert("distributed".to_owned(), Vec::new());
        features.insert("monitoring".to_owned(), Vec::new());
        features.insert("compliance".to_owned(), Vec::new());
        features.insert("threat-intel".to_owned(), Vec::new());
        features.insert(
            "plugins".to_owned(),
            [
                "core",
                "dep:async-trait",
                "dep:dashmap",
                "dep:futures",
                "dep:regex",
                "dep:tokio",
                "dep:tokio-util",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
        features.insert(
            "lua".to_owned(),
            ["core", "dep:mlua", "dep:tokio"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        features.insert(
            "full".to_owned(),
            FULL_AGGREGATE_FEATURES
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        );
        features.insert(
            "minimal".to_owned(),
            DEFAULT_SCANNER_FEATURES
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        );
        features.insert(
            "enterprise".to_owned(),
            ENTERPRISE_AGGREGATE_FEATURES
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        );
        features.insert("research".to_owned(), vec!["full".to_owned()]);
        features
    }

    #[test]
    fn host_execution_facades_are_private_direct_and_exact() {
        let source = include_str!("../../../crates/venom-scanner/src/lib.rs");
        for (module, cfg, symbols) in [
            (
                "distributed",
                "feature=\"distributed\"",
                EXACT_DISTRIBUTED_REEXPORTS,
            ),
            ("lua_engine", "feature=\"lua\"", EXACT_LUA_REEXPORTS),
            (
                "lua_config",
                "any(feature=\"platform-models\",feature=\"lua\")",
                EXACT_LUA_CONFIG_REEXPORTS,
            ),
        ] {
            assert!(
                private_facade_reexport_violations(source, module, cfg, symbols)
                    .unwrap()
                    .is_empty(),
                "{module}"
            );
        }
        let web_runtime_source = include_str!("../../../crates/venom-scanner/src/web_runtime.rs");
        assert!(
            private_natural_child_module_violations(web_runtime_source, "scan_profile")
                .unwrap()
                .is_empty()
        );
        assert!(private_facade_reexport_violations(
            web_runtime_source,
            "scan_profile",
            "feature=\"scanning\"",
            EXACT_SCAN_PROFILE_REEXPORTS,
        )
        .unwrap()
        .is_empty());
        let redirected_scan_profile = web_runtime_source.replace(
            "mod scan_profile;",
            "#[path = \"alternate.rs\"] mod scan_profile;",
        );
        assert!(
            private_natural_child_module_violations(&redirected_scan_profile, "scan_profile",)
                .unwrap()
                .join("\n")
                .contains("no attributes or path redirection")
        );
        assert!(host_surface_cfg_facade_violations(source)
            .unwrap()
            .is_empty());

        let public_module = source.replacen("mod distributed;", "pub mod distributed;", 1);
        assert!(module_gate_violations(&public_module)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("private out-of-line module")));

        let qualified =
            source.replacen("pub use distributed::{", "pub use crate::distributed::{", 1);
        assert!(private_facade_reexport_violations(
            &qualified,
            "distributed",
            "feature=\"distributed\"",
            EXACT_DISTRIBUTED_REEXPORTS,
        )
        .unwrap()
        .iter()
        .any(|violation| violation.contains("exact direct")));

        let wrapper = format!("{source}\n#[cfg(feature = \"lua\")] pub fn escaped_lua_host() {{}}");
        assert!(host_surface_cfg_facade_violations(&wrapper)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("escaped_lua_host")));
    }

    #[test]
    fn distributed_feature_is_dependency_free_and_cannot_reenter_product_closures() {
        let mut features = valid_feature_map();
        assert!(feature_violations(&features).is_empty());

        features
            .get_mut("distributed")
            .unwrap()
            .push("dep:dashmap".to_owned());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("`distributed` raw feature closure")
                && violation.contains("dep:dashmap")
        }));

        let mut features = valid_feature_map();
        features
            .get_mut("scanning")
            .unwrap()
            .push("distributed".to_owned());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("`default` raw feature closure") && violation.contains("distributed")
        }));

        let mut features = valid_feature_map();
        features
            .get_mut("reporting")
            .unwrap()
            .push("lua".to_owned());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("`reporting` raw feature closure") && violation.contains("lua")
        }));
    }

    #[test]
    fn distributed_source_is_ordered_integer_only_and_ambient_authority_free() {
        let sources = distributed_sources();
        assert!(distributed_source_authority_violations(&sources)
            .unwrap()
            .is_empty());
        assert!(distributed_public_api_violations(&sources)
            .unwrap()
            .is_empty());

        let root = source(&sources, "distributed.rs");
        for mutation in [
            "use dashmap::DashMap;",
            "use std::collections::HashMap;",
            "use std::collections::HashSet;",
            "use std::fs::File;",
            "use std::process::Command;",
            "use std::thread;",
            "use std::time::Instant;",
            "use std::time::SystemTime;",
            "use uuid::Uuid;",
            "use rand::random;",
            "use serde::Serialize;",
            "use std::net::TcpStream;",
            "static ESCAPED_STATE: usize = 0;",
            "#[allow(dead_code)] fn escaped_allow() {}",
            "fn float_score(value: f64) -> f64 { value }",
            "unsafe fn escaped_unsafe() {}",
            "const ESCAPED_INCLUDE: &str = include_str!(\"escaped\");",
        ] {
            let mutated = root.replacen("#[cfg(test)]", &format!("{mutation}\n#[cfg(test)]"), 1);
            let mutated_sources = replacing_source(&sources, "distributed.rs", &mutated);
            let violations = distributed_source_authority_violations(&mutated_sources).unwrap();
            assert!(
                !violations.is_empty(),
                "distributed authority mutation escaped: {mutation}"
            );
        }

        let coordinator = source(&sources, "distributed/coordinator.rs");
        let escaped_child = format!(
            "{coordinator}\nuse std::process::Command;\nunsafe fn escaped_child_authority() {{}}\n"
        );
        let escaped_child_sources =
            replacing_source(&sources, "distributed/coordinator.rs", &escaped_child);
        let escaped_child_violations =
            distributed_source_authority_violations(&escaped_child_sources).unwrap();
        for marker in ["cannot use `process`", "safe Rust"] {
            assert!(
                escaped_child_violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "distributed child authority marker escaped: {marker}"
            );
        }

        let worker = source(&sources, "distributed/worker.rs");
        let public_snapshot = worker.replacen(
            "pub struct WorkerNode {\n    pub(super) worker_id:",
            "pub struct WorkerNode {\n    pub worker_id:",
            1,
        );
        assert_ne!(public_snapshot, worker);
        let public_snapshot_sources =
            replacing_source(&sources, "distributed/worker.rs", &public_snapshot);
        assert!(distributed_public_api_violations(&public_snapshot_sources)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("all fields non-public")));

        let limits = source(&sources, "distributed/limits.rs");
        let constant_drift = limits.replacen(
            "pub const MAX_RESULTS: usize = 65_536;",
            "pub const MAX_RESULTS: usize = 65_535;",
            1,
        );
        assert_ne!(constant_drift, limits);
        let constant_drift_sources =
            replacing_source(&sources, "distributed/limits.rs", &constant_drift);
        assert!(distributed_public_api_violations(&constant_drift_sources)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("MAX_RESULTS")));
    }

    #[test]
    fn host_surface_production_signatures_and_bodies_are_exact() {
        let distributed = distributed_sources();
        let lua_engine = lua_engine_sources();
        let lua_config = include_str!("../../../crates/venom-scanner/src/lua_config.rs");
        let distributed_violations = distributed_production_inventory_violations(&distributed);
        assert!(
            distributed_violations.is_empty(),
            "{distributed_violations:?}"
        );
        let lua_violations = lua_production_inventory_violations(&lua_engine, lua_config);
        assert!(lua_violations.is_empty(), "{lua_violations:?}");

        let queue = source(&distributed, "distributed/queue.rs");
        let distributed_signature =
            queue.replacen("expected_revision: u64,", "expected_revision: u32,", 1);
        assert_ne!(distributed_signature, queue);
        let distributed_signature_sources =
            replacing_source(&distributed, "distributed/queue.rs", &distributed_signature);
        assert!(
            !distributed_production_inventory_violations(&distributed_signature_sources).is_empty()
        );

        let distributed_root = source(&distributed, "distributed.rs");
        let receipt_variant =
            distributed_root.replacen("MismatchedResultReceipt", "StaleResult", 1);
        assert_ne!(receipt_variant, distributed_root);
        let receipt_variant_sources =
            replacing_source(&distributed, "distributed.rs", &receipt_variant);
        assert!(!distributed_production_inventory_violations(&receipt_variant_sources).is_empty());

        let retry_backpressure = queue.replacen(
            "if state.queue.len() >= state.limits.max_queued_tasks {",
            "if false {",
            1,
        );
        assert_ne!(retry_backpressure, queue);
        let retry_backpressure_sources =
            replacing_source(&distributed, "distributed/queue.rs", &retry_backpressure);
        assert!(
            !distributed_production_inventory_violations(&retry_backpressure_sources).is_empty()
        );

        let execution = source(&lua_engine, "lua_engine/execution.rs");
        let lua_signature =
            execution.replacen("pub async fn execute(", "pub async fn execute_changed(", 1);
        assert_ne!(lua_signature, execution);
        let lua_signature_sources =
            replacing_source(&lua_engine, "lua_engine/execution.rs", &lua_signature);
        assert!(
            !lua_production_inventory_violations(&lua_signature_sources, lua_config).is_empty()
        );

        let config_default = lua_config.replacen(
            "max_concurrent_executions: 4,",
            "max_concurrent_executions: 5,",
            1,
        );
        assert!(!lua_production_inventory_violations(&lua_engine, &config_default).is_empty());
    }

    #[test]
    fn host_surface_child_source_inventory_fails_closed() {
        let mut distributed = distributed_sources();
        distributed.remove(1);
        assert!(distributed_public_api_violations(&distributed)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("production source inventory")));
        assert!(distributed_source_authority_violations(&distributed)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("production source inventory")));
        assert!(distributed_production_inventory_violations(&distributed)
            .iter()
            .any(|violation| violation.contains("production source inventory")));

        let mut lua = lua_engine_sources();
        lua.pop();
        assert!(lua_public_api_violations(
            &lua,
            include_str!("../../../crates/venom-scanner/src/lua_config.rs")
        )
        .unwrap()
        .iter()
        .any(|violation| violation.contains("production source inventory")));
        assert!(lua_source_authority_violations(&lua)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("production source inventory")));
        assert!(lua_production_inventory_violations(
            &lua,
            include_str!("../../../crates/venom-scanner/src/lua_config.rs")
        )
        .iter()
        .any(|violation| violation.contains("production source inventory")));

        let mut reordered = distributed_sources();
        reordered.swap(1, 2);
        assert!(distributed_production_inventory_violations(&reordered)
            .iter()
            .any(|violation| violation.contains("production source inventory")));
    }

    #[test]
    fn lua_vm_construction_and_ambient_authority_are_exact() {
        let sources = lua_engine_sources();
        let config = include_str!("../../../crates/venom-scanner/src/lua_config.rs");
        assert!(lua_source_authority_violations(&sources)
            .unwrap()
            .is_empty());
        assert!(lua_public_api_violations(&sources, config)
            .unwrap()
            .is_empty());

        for (path, before, after) in [
            ("lua_engine/vm.rs", "Lua::new_with(", "Lua::new("),
            ("lua_engine/vm.rs", "StdLib::NONE", "StdLib::ALL"),
            ("lua_engine/vm.rs", "ChunkMode::Text", "ChunkMode::Binary"),
            (
                "lua_engine/vm.rs",
                ".set_environment(environment)",
                ".set_environment(lua.globals())",
            ),
            (
                "lua_engine/execution.rs",
                "runtime.spawn_blocking",
                "runtime.spawn",
            ),
            (
                "lua_engine/vm.rs",
                ".call::<_, MultiValue>(())",
                ".call::<_, Value>(())",
            ),
        ] {
            let original = source(&sources, path);
            let mutation = original.replacen(before, after, 1);
            assert_ne!(mutation, original, "missing Lua mutation target: {before}");
            let mutated_sources = replacing_source(&sources, path, &mutation);
            assert!(
                !lua_source_authority_violations(&mutated_sources)
                    .unwrap()
                    .is_empty(),
                "Lua child authority mutation escaped: {before}"
            );
        }

        let execution = source(&sources, "lua_engine/execution.rs");
        let escaped_child = format!(
            "{execution}\nuse std::process::Command;\nunsafe fn escaped_child_authority() {{}}\n"
        );
        let escaped_child_sources =
            replacing_source(&sources, "lua_engine/execution.rs", &escaped_child);
        let escaped_child_violations =
            lua_source_authority_violations(&escaped_child_sources).unwrap();
        for marker in ["ambient capability import", "safe Rust"] {
            assert!(
                escaped_child_violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "Lua child authority marker escaped: {marker}"
            );
        }

        let root = source(&sources, "lua_engine.rs");
        for mutation in [
            root.replacen(
                "#[cfg(test)]",
                "use std::process::Command;\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "use std::net::TcpStream;\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "fn escaped_alias_fs() { let _ = fs::read(\"escaped\"); }\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "fn escaped_file(path: &Path) { let _ = File::open(path); }\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "static ESCAPED_LUA: usize = 0;\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "fn escaped_thread(lua: &Lua) { let _ = lua.create_thread(()); }\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "fn escaped_eval(lua: &Lua) { let _ = lua.eval::<()>(\"\"); }\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "fn escaped_userdata(lua: &Lua) { let _ = lua.create_userdata(()); }\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "fn escaped_callback(lua: &Lua) { let _ = lua.create_function_mut(|_, _: ()| Ok(())); }\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "unsafe fn escaped_unsafe() {}\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "const ESCAPED_INCLUDE: &[u8] = include_bytes!(\"escaped\");\n#[cfg(test)]",
                1,
            ),
            root.replacen(
                "#[cfg(test)]",
                "macro_rules! escaped_macro { () => {} }\n#[cfg(test)]",
                1,
            ),
        ] {
            let mutated_sources = replacing_source(&sources, "lua_engine.rs", &mutation);
            assert!(
                !lua_source_authority_violations(&mutated_sources)
                    .unwrap()
                    .is_empty(),
                "Lua authority mutation escaped"
            );
        }

        let public_manifest = root.replacen(
            "pub struct LuaScriptManifest {\n    id:",
            "pub struct LuaScriptManifest {\n    pub id:",
            1,
        );
        assert_ne!(public_manifest, root);
        let public_manifest_sources = replacing_source(&sources, "lua_engine.rs", &public_manifest);
        assert!(lua_public_api_violations(&public_manifest_sources, config)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("all fields non-public")));

        let config_drift = config.replacen(
            "pub const HARD_MAX_MEMORY_BYTES: usize = 256 * 1_024 * 1_024;",
            "pub const HARD_MAX_MEMORY_BYTES: usize = 512 * 1_024 * 1_024;",
            1,
        );
        assert!(lua_public_api_violations(&sources, &config_drift)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("HARD_MAX_MEMORY_BYTES")));
    }

    #[test]
    fn mlua_dependency_contract_is_minimal_and_exact() {
        let mut dependencies = BTreeMap::from([(
            "mlua".to_owned(),
            DependencyContract {
                optional: true,
                uses_default_features: false,
                features: BTreeSet::from(["lua54".to_owned(), "vendored".to_owned()]),
            },
        )]);
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &dependencies,
            "mlua",
            true,
            false,
            &["lua54", "vendored"],
        )
        .is_empty());
        assert!(exact_dependency_requirement_violations(
            "venom-scanner",
            "mlua",
            Some("^0.9"),
            "^0.9",
        )
        .is_empty());
        assert!(exact_dependency_requirement_violations(
            "venom-scanner",
            "mlua",
            Some("^0.10"),
            "^0.9",
        )
        .iter()
        .any(|violation| violation.contains("^0.10")));

        dependencies
            .get_mut("mlua")
            .unwrap()
            .features
            .insert("serialize".to_owned());
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &dependencies,
            "mlua",
            true,
            false,
            &["lua54", "vendored"],
        )
        .iter()
        .any(|violation| violation.contains("serialize")));

        let dependency = dependencies.get_mut("mlua").unwrap();
        dependency.features.remove("serialize");
        dependency.uses_default_features = true;
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &dependencies,
            "mlua",
            true,
            false,
            &["lua54", "vendored"],
        )
        .iter()
        .any(|violation| violation.contains("default-features=false")));
    }

    #[test]
    fn core_features_are_exact_and_legacy_contracts_are_nondefault() {
        let mut features = BTreeMap::from([
            ("default".to_owned(), Vec::new()),
            (
                "legacy-contracts".to_owned(),
                vec!["dep:serde_json".to_owned(), "dep:toml".to_owned()],
            ),
        ]);
        assert!(core_feature_violations(&features).is_empty());

        features
            .get_mut("default")
            .unwrap()
            .push("legacy-contracts".to_owned());
        assert!(core_feature_violations(&features)
            .iter()
            .any(|violation| { violation.contains("`default` members must be exactly") }));

        features.get_mut("default").unwrap().clear();
        features.insert("unclassified".to_owned(), Vec::new());
        assert!(core_feature_violations(&features)
            .iter()
            .any(|violation| violation.contains("feature names must be exactly")));
    }

    #[test]
    fn core_legacy_modules_and_reexports_require_the_exact_gate() {
        let source = r#"
            #[cfg(feature = "legacy-contracts")]
            pub mod config;
            #[cfg(feature = "legacy-contracts")]
            pub mod error;
            #[cfg(feature = "legacy-contracts")]
            pub mod events;
            #[cfg(feature = "legacy-contracts")]
            pub mod models;
            #[cfg(feature = "legacy-contracts")]
            pub use config::{Config, ConfigBuilder, ConfigError, ScanIntensity};
            #[cfg(feature = "legacy-contracts")]
            pub use error::{Error, Result};
            #[cfg(feature = "legacy-contracts")]
            pub use events::{Event, EventBuilder, EventSeverity, EventType};
            #[cfg(feature = "legacy-contracts")]
            pub use models::{HttpRequest, HttpResponse, ScanFinding, ScanResult, Vulnerability};
        "#;
        assert!(core_library_gate_violations(source).unwrap().is_empty());

        let broadened = source.replace(
            "#[cfg(feature = \"legacy-contracts\")]\n            pub mod events;",
            "#[cfg(any(feature = \"legacy-contracts\", test))]\n            pub mod events;",
        );
        assert!(core_library_gate_violations(&broadened)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("module `events`")
                && violation.contains("exact cfg")));
    }

    #[test]
    fn core_library_gate_rejects_ungated_compatibility_modules() {
        let source = r#"
            pub mod config;
            #[cfg(feature = "legacy-contracts")]
            pub mod error;
            #[cfg(feature = "legacy-contracts")]
            pub mod events;
            #[cfg(feature = "legacy-contracts")]
            pub mod models;
            #[cfg(feature = "legacy-contracts")]
            pub use config::{Config, ConfigBuilder, ConfigError, ScanIntensity};
            #[cfg(feature = "legacy-contracts")]
            pub use error::{Error, Result};
            #[cfg(feature = "legacy-contracts")]
            pub use events::{Event, EventBuilder, EventSeverity, EventType};
            #[cfg(feature = "legacy-contracts")]
            pub use models::{HttpRequest, HttpResponse, ScanFinding, ScanResult, Vulnerability};
        "#;
        assert!(core_library_gate_violations(source)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("module `config`")
                && violation.contains("exact cfg")));

        let shape = public_api_shape(
            "pub struct HttpRequest; pub struct HttpResponse; pub struct ScanFinding; pub struct ScanResult; pub struct Vulnerability;",
        )
        .unwrap();
        for symbol in LEGACY_CORE_MODEL_SYMBOLS {
            assert!(shape.symbols.contains(*symbol));
        }
    }

    #[test]
    fn scanner_legacy_reexports_follow_their_only_consumers() {
        let source = r#"
            #[cfg(feature = "legacy-scanner")]
            pub use event_bus::{Event, EventBuilder, EventSeverity, EventType};
            #[cfg(any(
                feature = "legacy-scanner",
                feature = "platform-models"
            ))]
            pub use venom_core::ScanFinding;
        "#;
        assert!(scanner_legacy_reexport_violations(source)
            .unwrap()
            .is_empty());

        let widened = source.replace(
            "feature = \"platform-models\"\n            ))]",
            "feature = \"platform-models\",\n                feature = \"reporting\"\n            ))]",
        );
        assert!(scanner_legacy_reexport_violations(&widened)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("`ScanFinding`") && violation.contains("exact cfg")
            ));
    }

    #[test]
    fn reporting_reexports_are_exact_and_feature_gated() {
        let source = r#"
            #[cfg(feature = "reporting")]
            pub use reporting::{
                ReportError, ReportFormat, ReportGenerator, MAX_RENDERED_REPORT_BYTES,
                REPORT_DOCUMENT_SCHEMA,
            };
        "#;
        assert!(reporting_reexport_violations(source).unwrap().is_empty());

        let missing = source.replace("ReportError, ", "");
        assert!(reporting_reexport_violations(&missing)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("must be exactly")
                && violation.contains("ReportError")));

        let widened = source.replace(
            "#[cfg(feature = \"reporting\")]",
            "#[cfg(any(feature = \"reporting\", feature = \"scanning\"))]",
        );
        assert!(reporting_reexport_violations(&widened)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("exact cfg")));

        let assessment_alias = format!(
            "{source}\n#[cfg(all(feature = \"reporting\", feature = \"scanning\"))]\npub use reporting::ASSESSMENT_REPORT_DOCUMENT_SCHEMA;"
        );
        assert!(reporting_reexport_violations(&assessment_alias)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("assessment-only symbols")));

        let legacy = source.replace(
            "ReportError, ReportFormat",
            "ReportError, ReportFormat, VulnerabilityReport",
        );
        assert!(reporting_reexport_violations(&legacy)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("VulnerabilityReport")));

        let qualified_alias = format!(
            "{source}\n#[cfg(feature = \"reporting\")]\npub use crate::reporting::ReportGenerator as RendererAlias;"
        );
        assert!(reporting_reexport_violations(&qualified_alias)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("exactly one public base reporting re-export")));

        let hidden_module_alias = format!(
            r#"{source}
                #[cfg(feature = "reporting")]
                mod hidden {{
                    pub use crate::reporting::ReportGenerator as Renderer;
                }}
                #[cfg(feature = "reporting")]
                pub use hidden::Renderer as RendererAlias;
            "#
        );
        assert!(reporting_reexport_violations(&hidden_module_alias)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("exactly one public base reporting re-export")));

        let hidden_type_alias = format!(
            r#"{source}
                mod hidden {{
                    #[cfg(feature = "reporting")]
                    pub type Renderer = crate::reporting::ReportGenerator;
                    #[cfg(not(feature = "reporting"))]
                    pub struct Renderer;
                }}
                pub use hidden::Renderer;
            "#
        );
        let violations = reporting_reexport_violations(&hidden_type_alias).unwrap();
        for marker in [
            "type alias `Renderer`",
            "exactly one public base reporting re-export",
        ] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "hidden reporting facade marker `{marker}` bypassed: {violations:?}"
            );
        }

        let absolute_reporting = source.replace("pub use reporting::", "pub use ::reporting::");
        assert!(reporting_reexport_violations(&absolute_reporting)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("exact direct `reporting::{...}` path")));

        let unbounded_wrapper = format!(
            r#"{source}
                #[cfg(feature = "reporting")]
                pub fn render_unbounded(report: &RunReport) -> Result<String, serde_json::Error> {{
                    serde_json::to_string(report)
                }}
            "#
        );
        assert!(reporting_reexport_violations(&unbounded_wrapper)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("fn render_unbounded")
                && violation.contains("cfg(reporting) facade item")));

        let escaped_feature_wrapper = format!(
            r#"{source}
                #[cfg(feature = "report\x69ng")]
                pub fn escaped_unbounded(report: &RunReport) -> String {{
                    serde_json::to_string(report).unwrap()
                }}
            "#
        );
        assert!(reporting_reexport_violations(&escaped_feature_wrapper)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("fn escaped_unbounded")
                && violation.contains("cfg(reporting) facade item")));

        for extra in [
            r#"
                #[cfg(feature = "reporting")]
                impl reporting::ReportGenerator {
                    pub fn generate_unbounded(report: &RunReport) -> String {
                        serde_json::to_string(report).unwrap()
                    }
                }
            "#,
            r#"
                #[cfg(feature = "reporting")]
                reporting_extension!();
            "#,
            r#"
                #[cfg(feature = "reporting")]
                mod reporting_extensions;
            "#,
        ] {
            let source = format!("{source}\n{extra}");
            assert!(reporting_reexport_violations(&source)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("cfg(reporting) facade item")));
        }
    }

    #[test]
    fn reporting_whole_crate_closure_rejects_cross_file_extensions() {
        let extension = r#"
            impl crate::reporting::ReportGenerator {
                pub fn generate_unbounded(report: &RunReport) -> String {
                    serde_json::to_string(report).unwrap()
                }
            }
        "#;
        for path in ["reporting_extensions.rs", "api_evidence.rs"] {
            let violations = reporting_cross_file_source_violations(path, extension).unwrap();
            for marker in ["reporting", "ReportGenerator"] {
                assert!(
                    violations
                        .iter()
                        .any(|violation| violation.contains(marker)),
                    "cross-file reporting marker `{marker}` bypassed in {path}: {violations:?}"
                );
            }
        }

        let unbounded_run_export = r#"
            pub fn export(report: &venom_core::RunReport) -> Result<String, serde_json::Error> {
                serde_json::to_string(report)
            }
        "#;
        for path in ["lib.rs", "api_evidence.rs"] {
            assert!(
                reporting_cross_file_source_violations(path, unbounded_run_export)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains("public function `export`")
                        && violation.contains("RunReport"))
            );
        }

        let typed_assessment_bridge = r#"
            impl WebAssessmentRunReport {
                #[cfg(feature = "reporting")]
                pub(crate) fn into_assessment_report(
                    self,
                    profile: ScanProfileV1,
                ) -> Result<AssessmentRunReport, AssessmentRunReportError> {
                    let truth = CompletedWebAssessmentTruth::new(
                        self.run_started_at,
                        &self.authorized_root,
                        self.limits,
                        self.usage,
                        &self.completion,
                        self.defense.mode(),
                        profile,
                    )?;
                    AssessmentRunReport::from_completed_truth(self.assessment_items, truth)
                }
            }
        "#;
        assert!(reporting_cross_file_source_violations(
            "web_runtime/web_assessment.rs",
            typed_assessment_bridge,
        )
        .unwrap()
        .is_empty());
        for mutated in [
            typed_assessment_bridge.replace(
                "pub(crate) fn into_assessment_report",
                "pub fn into_assessment_report",
            ),
            typed_assessment_bridge.replace("#[cfg(feature = \"reporting\")]", ""),
            typed_assessment_bridge.replace(
                "AssessmentRunReport::from_completed_truth(self.assessment_items, truth)",
                "render(self.assessment_items)",
            ),
            typed_assessment_bridge.replace(
                "Result<AssessmentRunReport, AssessmentRunReportError>",
                "Result<String, AssessmentRunReportError>",
            ),
            typed_assessment_bridge.replace("self.run_started_at", "SystemTime::now()"),
            typed_assessment_bridge.replace("&self.authorized_root", "&caller_root"),
            typed_assessment_bridge.replace("self.limits", "WebAssessmentLimits::default()"),
            typed_assessment_bridge.replace("self.usage", "WebAssessmentUsage::default()"),
            typed_assessment_bridge.replace("&self.completion", "&completion"),
            typed_assessment_bridge.replace(
                "self.defense.mode()",
                "WebAssessmentDefenseMode::ObservationOnly",
            ),
            typed_assessment_bridge.replace(
                "AssessmentRunReport::from_completed_truth(self.assessment_items, truth)",
                "AssessmentRunReport::from_completed_truth(forged_items, truth)",
            ),
            typed_assessment_bridge.replace(
                "AssessmentRunReport::from_completed_truth(self.assessment_items, truth)",
                "AssessmentRunReport::from_completed_truth(self.assessment_items, forged_truth)",
            ),
        ] {
            assert!(!reporting_cross_file_source_violations(
                "web_runtime/web_assessment.rs",
                &mutated,
            )
            .unwrap()
            .is_empty());
        }
        assert!(!reporting_cross_file_source_violations(
            "api_evidence.rs",
            typed_assessment_bridge,
        )
        .unwrap()
        .is_empty());

        let broad_public_consumer = r#"
            impl WebAssessmentRunReport {
                pub fn export_generic_run_report(
                    self,
                    run_report: venom_core::RunReport,
                ) -> AssessmentRunReport {
                    forge(run_report)
                }
            }
        "#;
        assert!(!reporting_cross_file_source_violations(
            "web_runtime/web_assessment.rs",
            broad_public_consumer,
        )
        .unwrap()
        .is_empty());

        let crate_generic_consumer = r#"
            pub(crate) fn compose_untrusted(
                run_report: venom_core::RunReport,
            ) -> AssessmentRunReport {
                forge(run_report)
            }
        "#;
        assert!(reporting_cross_file_source_violations(
            "web_runtime/api_visibility.rs",
            crate_generic_consumer,
        )
        .unwrap()
        .iter()
        .any(|violation| violation.contains("crate-callable function")
            && violation.contains("RunReport")));

        let public_typed_bridge = r#"
            pub fn compose_elsewhere(
                report: WebAssessmentRunReport,
            ) -> Result<AssessmentRunReport, AssessmentRunReportError> {
                forge(report)
            }
        "#;
        assert!(reporting_cross_file_source_violations(
            "web_runtime/api_visibility.rs",
            public_typed_bridge,
        )
        .unwrap()
        .iter()
        .any(|violation| violation.contains("AssessmentRunReport outside reporting.rs")));

        let aliased_sources = vec![
            (
                "aliases.rs".to_owned(),
                "pub type RenderInput = venom_core::r#RunReport;".to_owned(),
            ),
            (
                "api_evidence.rs".to_owned(),
                r#"
                    pub fn export(report: &crate::RenderInput) -> String {
                        serde_json::to_string(report).unwrap()
                    }
                "#
                .to_owned(),
            ),
        ];
        assert!(reporting_cross_source_set_violations(&aliased_sources)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("public function `export`")
                && violation.contains("RunReport")));

        for callable in [
            "pub type Exporter = fn(&venom_core::RunReport) -> String;",
            "pub trait Export { fn render(&self, report: &venom_core::RunReport) -> String; }",
            "pub fn exporter() -> impl Fn(&venom_core::RunReport) -> String { todo!() }",
        ] {
            assert!(
                !reporting_cross_file_source_violations("api_evidence.rs", callable)
                    .unwrap()
                    .is_empty()
            );
        }

        for external_macro in ["venom_core::x!();", "r#venom_core::r#x!();"] {
            assert!(
                reporting_cross_file_source_violations("lib.rs", external_macro)
                    .unwrap()
                    .iter()
                    .any(|violation| violation
                        .contains("unclassified qualified macro invocation `venom_core::x!`"))
            );
        }

        for imported_macro in [
            "use venom_core::x; x!();",
            "use venom_core::x as format; format!();",
        ] {
            assert!(
                reporting_cross_file_source_violations("lib.rs", imported_macro)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains("unclassified imported macro invocation")),
                "imported external macro bypassed whole-crate closure: {imported_macro}"
            );
        }

        for macro_use in [
            "#[macro_use] extern crate venom_core; x!();",
            "#[macro_use] mod imported_macros {}",
        ] {
            assert!(
                reporting_cross_file_source_violations("lib.rs", macro_use)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains("production `#[macro_use]` macro import")),
                "macro_use import bypassed whole-crate closure: {macro_use}"
            );
        }

        assert!(reporting_cross_file_source_violations(
            "api_evidence.rs",
            "pub fn completed_run() -> venom_core::RunReport { todo!() }"
        )
        .unwrap()
        .is_empty());

        let raw_identifier_extension = r#"
            impl crate::r#reporting::r#ReportGenerator {}
        "#;
        assert!(reporting_cross_file_source_violations(
            "api_evidence.rs",
            raw_identifier_extension
        )
        .unwrap()
        .iter()
        .any(|violation| violation.contains("ReportGenerator")));

        let cfg_extension = r#"
            #[cfg(feature = "reporting")]
            mod extension { pub fn render_unbounded() {} }
        "#;
        assert!(
            reporting_cross_file_source_violations("api_evidence.rs", cfg_extension)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("cfg/cfg_attr predicate"))
        );

        for included_extension in [
            r#"include!(concat!(env!("OUT_DIR"), "/report_extension.rs"));"#,
            r#"r#include!("outside.inc");"#,
        ] {
            assert!(
                reporting_cross_file_source_violations("api_evidence.rs", included_extension)
                    .unwrap()
                    .iter()
                    .any(|violation| violation
                        .contains("production `include!` source indirection"))
            );
        }
        assert!(reporting_cross_file_source_violations(
            "bridge_tests.rs",
            "include!(\"outside.inc\");"
        )
        .unwrap()
        .iter()
        .any(|violation| violation.contains("production `include!` source indirection")));

        for path_extension in [
            r#"#[path = "../outside.rs"] mod extension;"#,
            r#"#[r#path = "outside.inc"] mod extension;"#,
        ] {
            assert!(
                reporting_cross_file_source_violations("api_evidence.rs", path_extension)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains("production `#[path]` source indirection"))
            );
        }

        assert!(reporting_cross_file_source_violations(
            "api_evidence.rs",
            "pub fn unrelated_api_surface() {}"
        )
        .unwrap()
        .is_empty());
    }

    fn valid_reporting_public_api_fixture() -> &'static str {
        r#"
            pub const REPORT_DOCUMENT_SCHEMA: &str = "venom-rendered-run/v1";
            #[cfg(feature = "scanning")]
            pub const ASSESSMENT_REPORT_DOCUMENT_SCHEMA: &str =
                "venom-rendered-assessment/v1";
            pub const MAX_RENDERED_REPORT_BYTES: usize = 16 * 1_024 * 1_024;

            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            #[non_exhaustive]
            pub enum ReportFormat { Json, Csv, Html, Markdown }
            impl ReportFormat {
                pub const fn as_str(self) -> &'static str {
                    match self {
                        Self::Json => "json",
                        Self::Csv => "csv",
                        Self::Html => "html",
                        Self::Markdown => "markdown",
                    }
                }
                pub const fn media_type(self) -> &'static str {
                    match self {
                        Self::Json => "application/json",
                        Self::Csv => "text/csv; charset=utf-8",
                        Self::Html => "text/html; charset=utf-8",
                        Self::Markdown => "text/markdown; charset=utf-8",
                    }
                }
                pub const fn extension(self) -> &'static str {
                    match self {
                        Self::Json => "json",
                        Self::Csv => "csv",
                        Self::Html => "html",
                        Self::Markdown => "md",
                    }
                }
            }

            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            #[non_exhaustive]
            pub enum ReportError {
                OutputLimitExceeded { limit: usize },
                Serialization,
            }
            impl fmt::Display for ReportError {}
            impl Error for ReportError {}

            #[derive(Debug, Default, Clone, Copy)]
            pub struct ReportGenerator;
            impl ReportGenerator {
                pub fn generate(
                    report: &RunReport,
                    format: ReportFormat,
                ) -> Result<String, ReportError> {
                    let document = ReportDocument::from_report(report)?;
                    render_with_limit(&document, format, MAX_RENDERED_REPORT_BYTES)
                }
                #[cfg(feature = "scanning")]
                pub fn compose_assessment(
                    report: WebAssessmentRunReport,
                    profile: ScanProfileV1,
                ) -> Result<AssessmentRunReport, AssessmentRunReportError> {
                    report.into_assessment_report(profile)
                }
                #[cfg(feature = "scanning")]
                pub fn generate_assessment(
                    report: &AssessmentRunReport,
                    format: ReportFormat,
                ) -> Result<String, ReportError> {
                    let document = AssessmentDocument::from_report(report)?;
                    render_assessment_with_limit(
                        &document,
                        format,
                        MAX_RENDERED_REPORT_BYTES,
                    )
                }
                pub const fn available_formats() -> &'static [ReportFormat] { &REPORT_FORMATS }
            }
        "#
    }

    #[test]
    fn reporting_public_items_signatures_and_constants_are_exact() {
        let source = valid_reporting_public_api_fixture();
        assert!(reporting_public_api_violations(source).unwrap().is_empty());

        let extra_method =
            format!("{source}\nimpl ReportGenerator {{ pub fn write_to_disk() {{}} }}");
        assert!(reporting_public_api_violations(&extra_method)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("ReportGenerator::write_to_disk")
                    && violation.contains("outside the exact API")
            ));

        let widened_signature = source.replace("format: ReportFormat,", "format: &ReportFormat,");
        assert!(reporting_public_api_violations(&widened_signature)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("ReportGenerator::generate")
                && violation.contains("exact bounded signature")));

        let unbounded_body = source.replace(
            "let document = ReportDocument::from_report(report)?;\n                    render_with_limit(&document, format, MAX_RENDERED_REPORT_BYTES)",
            "serde_json::to_string(report).map_err(|_| ReportError::Serialization)",
        );
        assert!(reporting_public_api_violations(&unbounded_body)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("ReportGenerator::generate")
                && violation.contains("exact bounded implementation")));

        let schema_drift = source.replace("venom-rendered-run/v1", "venom-rendered-run/v2");
        assert!(reporting_public_api_violations(&schema_drift)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("REPORT_DOCUMENT_SCHEMA")));

        let assessment_schema_drift = source.replace(
            "venom-rendered-assessment/v1",
            "venom-rendered-assessment/v2",
        );
        assert!(reporting_public_api_violations(&assessment_schema_drift)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("ASSESSMENT_REPORT_DOCUMENT_SCHEMA")));

        let limit_drift = source.replace("16 * 1_024 * 1_024", "32 * 1_024 * 1_024");
        assert!(reporting_public_api_violations(&limit_drift)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("MAX_RENDERED_REPORT_BYTES")));

        let extra_item = format!("{source}\npub fn unbounded_render() {{}}");
        assert!(reporting_public_api_violations(&extra_item)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("unbounded_render")
                && violation.contains("outside the exact API")));

        let extra_trait = format!(
            "{source}\ntrait UnboundedWriter {{}} impl UnboundedWriter for ReportGenerator {{}}"
        );
        assert!(reporting_public_api_violations(&extra_trait)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("UnboundedWriter for ReportGenerator")
                    && violation.contains("exact public-type trait inventory")
            ));

        let conditional_method = source.replace(
            "pub fn generate(",
            "#[cfg(any())]\n                pub fn generate(",
        );
        assert!(reporting_public_api_violations(&conditional_method)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("ReportGenerator::generate")
                && violation.contains("conditionally compiled")));

        let externally_supplied_run =
            source.replace("report: WebAssessmentRunReport,", "report: RunReport,");
        assert!(reporting_public_api_violations(&externally_supplied_run)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("ReportGenerator::compose_assessment")
                    && violation.contains("exact bounded signature")
            ));

        let ungated_compose = source.replace(
            "#[cfg(feature = \"scanning\")]\n                pub fn compose_assessment",
            "pub fn compose_assessment",
        );
        assert!(reporting_public_api_violations(&ungated_compose)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("compose_assessment")
                && violation.contains("exactly cfg")));

        let forged_compose = source.replace(
            "report.into_assessment_report(profile)",
            "AssessmentRunReport::from_untrusted(report, profile)",
        );
        assert!(reporting_public_api_violations(&forged_compose)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("compose_assessment")
                && violation.contains("exact bounded implementation")));

        let externally_supplied_assessment_run =
            source.replace("report: &AssessmentRunReport,", "report: &RunReport,");
        assert!(
            reporting_public_api_violations(&externally_supplied_assessment_run)
                .unwrap()
                .iter()
                .any(
                    |violation| violation.contains("ReportGenerator::generate_assessment")
                        && violation.contains("exact bounded signature")
                )
        );

        let ungated_generate_assessment = source.replace(
            "#[cfg(feature = \"scanning\")]\n                pub fn generate_assessment",
            "pub fn generate_assessment",
        );
        assert!(
            reporting_public_api_violations(&ungated_generate_assessment)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("generate_assessment")
                    && violation.contains("exactly cfg"))
        );

        let bypassed_assessment_projection = source.replace(
            "let document = AssessmentDocument::from_report(report)?;\n                    render_assessment_with_limit(\n                        &document,\n                        format,\n                        MAX_RENDERED_REPORT_BYTES,\n                    )",
            "serde_json::to_string(report).map_err(|_| ReportError::Serialization)",
        );
        assert!(
            reporting_public_api_violations(&bypassed_assessment_projection)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("generate_assessment")
                    && violation.contains("exact bounded implementation"))
        );

        let derive_drift = source.replace(
            "Debug, Default, Clone, Copy",
            "Debug, Default, Clone, Copy, serde::Serialize",
        );
        assert!(reporting_public_api_violations(&derive_drift)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("ReportGenerator") && violation.contains("derives")
            ));
    }

    #[test]
    fn reporting_feature_closure_cannot_regain_legacy_contracts() {
        let mut features = valid_feature_map();
        assert!(feature_violations(&features).is_empty());

        features
            .get_mut("reporting")
            .unwrap()
            .push("venom-core/legacy-contracts".to_owned());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("`reporting` raw feature closure")
                && violation.contains("venom-core/legacy-contracts")
        }));
    }

    fn valid_reporting_import_fixture() -> &'static str {
        r#"
            use serde::Serialize;
            use std::{error::Error, fmt, io};
            use venom_core::{
                OutcomeStatus, ResourceAccounting, ResourceAccountingMode, RunOutcomeRecord,
                RunReport, RunStatus, RunStepStatus, RunStopCode, SecuritySeverity,
            };
            #[cfg(feature = "scanning")]
            use crate::web_runtime::{
                AssessmentBasis, AssessmentRunReport, AssessmentRunReportError, ScanProfileV1,
                WebAssessmentRunReport,
            };
        "#
    }

    #[test]
    fn reporting_imports_pin_error_and_signature_type_semantics() {
        let imports = valid_reporting_import_fixture();
        assert!(reporting_source_import_violations(imports)
            .unwrap()
            .is_empty());

        let imported_error =
            format!("{imports}\nstruct ReportError;\nimpl Error for ReportError {{}}");
        assert!(reporting_source_import_violations(&imported_error)
            .unwrap()
            .is_empty());
        assert!(reporting_source_violations(&imported_error)
            .unwrap()
            .is_empty());

        let spoofed_error = imported_error.replace(
            "use std::{error::Error, fmt, io};",
            "use std::{fmt, io};\ntrait Error {}",
        );
        assert!(reporting_source_import_violations(&spoofed_error)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("std::error::Error")));
        assert!(reporting_source_violations(&spoofed_error)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("production trait `Error`")));

        let spoofed_result = format!("{imports}\ntype Result<T, E> = std::result::Result<T, E>;");
        assert!(reporting_source_violations(&spoofed_result)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("production type alias `Result`")));
    }

    #[test]
    fn reporting_source_stays_run_report_only_and_ambient_authority_free() {
        let valid = r#"
            use std::fmt;
            pub struct ReportGenerator;
            impl fmt::Display for ReportGenerator {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("RunReport renderer")
                }
            }
        "#;
        assert!(reporting_source_violations(valid).unwrap().is_empty());

        let legacy_and_io = r#"
            use crate::ScanFinding;
            use std as standard;
            use std::{fs, path::Path};
            use std::fs::{File, OpenOptions};
            pub struct VulnerabilityReport;
            pub fn risk_score() {}
        "#;
        let violations = reporting_source_violations(legacy_and_io).unwrap();
        for marker in [
            "ScanFinding",
            "alias `std`",
            "std::fs",
            "File",
            "OpenOptions",
            "VulnerabilityReport",
            "risk_score",
        ] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "missing `{marker}` in {violations:?}"
            );
        }

        let concrete_io = r#"
            use std::io::{self, Write};
            fn leak(document: &[u8]) {
                io::stdout().write_all(document).unwrap();
                println!("leaked");
            }
        "#;
        let violations = reporting_source_violations(concrete_io).unwrap();
        for marker in ["stdout", "println"] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "standard-I/O marker `{marker}` bypassed policy: {violations:?}"
            );
        }

        let comments = r#"
            //! Historical ScanFinding, std::fs, File, and OpenOptions names are prose only.
            pub struct ReportGenerator;
        "#;
        assert!(reporting_source_violations(comments).unwrap().is_empty());

        let macro_tokens = r#"
            fixture!(std::path::Path, ScanFinding, severity_stats, OpenOptions);
        "#;
        let violations = reporting_source_violations(macro_tokens).unwrap();
        for marker in [
            "std::path::Path",
            "ScanFinding",
            "severity_stats",
            "OpenOptions",
        ] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "macro token `{marker}` bypassed policy: {violations:?}"
            );
        }
    }

    #[test]
    fn reporting_rejects_out_of_line_modules_aliases_and_combined_feature_authority() {
        assert!(reporting_source_violations("#[cfg(test)] mod tests {}")
            .unwrap()
            .is_empty());

        let submodule = "#[cfg(any())] mod hidden_transport;";
        assert!(reporting_source_violations(submodule)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("production module `hidden_transport`")));

        let delegated_helper = r#"
            fn leak(report: &RunReport) {
                crate::api_evidence::exfiltrate(report);
            }
        "#;
        assert!(reporting_source_violations(delegated_helper)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("crate::api_evidence::exfiltrate")
                    && violation.contains("cannot delegate")
            ));

        let external_macro = "crate::external_renderer!(report);";
        let violations = reporting_source_violations(external_macro).unwrap();
        for marker in ["crate::external_renderer", "outside the exact allowlist"] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "external macro marker `{marker}` bypassed policy: {violations:?}"
            );
        }

        let unix_socket = r#"
            fn connect() {
                std::os::unix::net::UnixStream::connect("/tmp/venom.sock");
            }
        "#;
        assert!(reporting_source_violations(unix_socket)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("std::os::unix::net::UnixStream::connect")
                    && violation.contains("authority allowlist")
            ));

        let panic_hook = r#"
            fn mutate_hook() {
                std::panic::set_hook(Box::new(|_| {}));
            }
        "#;
        assert!(reporting_source_violations(panic_hook)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("std::panic::set_hook")
                && violation.contains("authority allowlist")));

        let cfg_path = "#[cfg(tokio::fs)] fn disabled_authority() {}";
        let violations = reporting_source_violations(cfg_path).unwrap();
        for marker in ["exact cfg(feature", "tokio"] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "conditional authority marker `{marker}` bypassed policy: {violations:?}"
            );
        }

        let foreign = r#"
            unsafe extern "C" { fn system(command: *const core::ffi::c_char) -> i32; }
            unsafe fn raw_helper() {}
            fn invoke(command: *const core::ffi::c_char) { unsafe { system(command); } }
        "#;
        let violations = reporting_source_violations(foreign).unwrap();
        for marker in ["foreign modules", "unsafe blocks", "safe Rust functions"] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "unsafe/FFI marker `{marker}` bypassed policy: {violations:?}"
            );
        }

        let macro_paths = r#"
            fixture!(
                std::net::TcpStream,
                hyper::Client,
                chrono::Utc,
                rand::random,
                getrandom::fill,
                include_str!("ambient.txt"),
                env!("AMBIENT")
            );
        "#;
        let violations = reporting_source_violations(macro_paths).unwrap();
        for marker in [
            "std::net::TcpStream",
            "hyper",
            "chrono",
            "rand",
            "getrandom",
            "include_str",
            "env",
        ] {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(marker)),
                "macro/alias marker `{marker}` bypassed policy: {violations:?}"
            );
        }

        let generated_module = "fixture!(mod hidden;);";
        assert!(reporting_source_violations(generated_module)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("generate a module through macro tokens")));

        let nested_export = r#"
            mod private {
                #[macro_export]
                macro_rules! escaped_public_api { () => {} }
            }
        "#;
        assert!(reporting_source_violations(nested_export)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("export macros from any nested source scope")));
    }

    #[test]
    fn reporting_rejects_static_and_lazy_global_state() {
        let statics = r#"
            static PRIVATE_CACHE: usize = 0;
            pub static mut PUBLIC_CACHE: usize = 0;
        "#;
        let violations = reporting_source_violations(statics).unwrap();
        for name in ["PRIVATE_CACHE", "PUBLIC_CACHE"] {
            assert!(violations.iter().any(|violation| violation.contains(name)));
        }

        for primitive in [
            "OnceLock",
            "LazyLock",
            "Mutex",
            "RwLock",
            "lazy_static",
            "once_cell",
            "thread_local",
        ] {
            let source = format!("fn hidden_state() {{ fixture!({primitive}); }}");
            assert!(
                reporting_source_violations(&source)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains(primitive)),
                "global state primitive `{primitive}` bypassed policy"
            );
        }

        for nondeterministic in ["HashMap", "HashSet", "RandomState"] {
            let source = format!("fn randomized_order() {{ fixture!({nondeterministic}); }}");
            assert!(
                reporting_source_violations(&source)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains(nondeterministic)),
                "randomized-order primitive `{nondeterministic}` bypassed policy"
            );
        }

        for ambient_macro in [
            "cfg",
            "dbg",
            "eprint",
            "eprintln",
            "env",
            "include",
            "include_bytes",
            "include_str",
            "option_env",
            "print",
            "println",
        ] {
            let source = format!("{ambient_macro}!(\"ambient\");");
            assert!(
                reporting_source_violations(&source)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains(ambient_macro)),
                "compile-time macro `{ambient_macro}!` bypassed policy"
            );
        }
    }

    fn valid_reporting_document_contract_fixture() -> &'static str {
        r#"
            #[cfg(feature = "scanning")]
            #[derive(Serialize)]
            struct AssessmentDocument<'a> {
                schema: &'static str,
                source_schema: &'a str,
                run_schema: &'a str,
                profile_schema: &'a str,
                profile: &'a str,
                status: &'static str,
                subject_count: u64,
                item_count: u64,
                items: Vec<AssessmentItemDocument<'a>>,
            }
            #[cfg(feature = "scanning")]
            #[derive(Serialize)]
            struct AssessmentItemDocument<'a> {
                schema: &'a str,
                capability_id: &'a str,
                subject_reference: String,
                title: &'a str,
                disposition: &'static str,
                claim_basis: &'static str,
                severity: Option<&'static str>,
                confidence_ppm: u32,
                fingerprint: &'a str,
                evidence_count: u64,
                redacted_summary: &'a str,
                category: &'a str,
                cwe: Option<&'a str>,
                remediation: AssessmentRemediationDocument<'a>,
                evidence_references: Vec<String>,
                control_evidence_references: Vec<String>,
                candidate_evidence_references: Vec<String>,
                case_reference: Option<String>,
                outcome_reference: Option<String>,
                verification_stage: Option<&'static str>,
            }
            #[cfg(feature = "scanning")]
            struct AssessmentBasisLinkageDocument {
                evidence_references: Vec<String>,
                control_evidence_references: Vec<String>,
                candidate_evidence_references: Vec<String>,
                case_reference: Option<String>,
                outcome_reference: Option<String>,
                verification_stage: Option<&'static str>,
            }
            #[cfg(feature = "scanning")]
            #[derive(Serialize)]
            struct AssessmentRemediationDocument<'a> {
                id: &'a str,
                summary: &'a str,
            }
            #[derive(Serialize)]
            struct ReportDocument<'a> {
                schema: &'static str,
                source_schema: &'a str,
                status: &'static str,
                stop_code: &'static str,
                target: &'a str,
                authorized_origin: &'a str,
                started_at: String,
                completed_at: String,
                accounting: AccountingDocument,
                steps: Vec<StepDocument<'a>>,
                outcomes: Vec<OutcomeDocument<'a>>,
            }
            #[derive(Serialize)]
            struct AccountingDocument {
                requests: AccountingDimension,
                response_body_bytes: AccountingDimension,
                request_body_bytes: AccountingDimension,
                wall_time_ms: AccountingDimension,
            }
            #[derive(Serialize)]
            struct AccountingDimension {
                mode: &'static str,
                limit: Option<String>,
                consumed: Option<String>,
                remaining: Option<String>,
            }
            #[derive(Serialize)]
            struct StepDocument<'a> {
                ordinal: u32,
                action_id: &'a str,
                status: &'static str,
                duration_ms: String,
            }
            #[derive(Serialize)]
            struct OutcomeDocument<'a> {
                kind: &'static str,
                action_id: &'a str,
                severity: &'static str,
                disposition: &'static str,
                confidence_ppm: u32,
                evidence_count: u64,
                redacted_summary: &'a str,
            }
        "#
    }

    #[test]
    fn reporting_private_document_shapes_are_exact() {
        let source = valid_reporting_document_contract_fixture();
        assert!(reporting_document_contract_violations(source)
            .unwrap()
            .is_empty());

        let private_fingerprint = source.replace(
            "redacted_summary: &'a str,",
            "redacted_summary: &'a str,\n                fingerprint: &'a str,",
        );
        assert!(reporting_document_contract_violations(&private_fingerprint)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("OutcomeDocument")
                && violation.contains("fields must remain exactly")));

        let numeric_drift = source.replace("duration_ms: String,", "duration_ms: u64,");
        assert!(reporting_document_contract_violations(&numeric_drift)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("StepDocument")
                && violation.contains("fields must remain exactly")));

        let missing_opaque_outcome = source.replace(
            "                outcome_reference: Option<String>,\n                verification_stage: Option<&'static str>,\n            }\n            #[cfg(feature = \"scanning\")]\n            #[derive(Serialize)]\n            struct AssessmentRemediationDocument",
            "                verification_stage: Option<&'static str>,\n            }\n            #[cfg(feature = \"scanning\")]\n            #[derive(Serialize)]\n            struct AssessmentRemediationDocument",
        );
        assert!(
            reporting_document_contract_violations(&missing_opaque_outcome)
                .unwrap()
                .iter()
                .any(
                    |violation| violation.contains("AssessmentBasisLinkageDocument")
                        && violation.contains("fields must remain exactly")
                )
        );

        let ungated_item_projection = source.replace(
            "#[cfg(feature = \"scanning\")]\n            #[derive(Serialize)]\n            struct AssessmentItemDocument",
            "#[derive(Serialize)]\n            struct AssessmentItemDocument",
        );
        assert!(
            reporting_document_contract_violations(&ungated_item_projection)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("AssessmentItemDocument")
                    && violation.contains("exactly cfg"))
        );
    }

    #[test]
    fn reporting_production_semantics_and_cap_accounting_are_fingerprinted() {
        let source = include_str!("../../../crates/venom-scanner/src/reporting.rs");
        assert!(reporting_production_body_inventory_violations(source).is_empty());

        let private_detail = source.replace(
            "started_at: report.started_at().to_rfc3339(),",
            r#"started_at: format_args!("{}", report.stop_reason().detail()).to_string(),"#,
        );
        let forged_macro_status = source.replace(
            "status: run_status_token(report.status()),",
            r#"status: if matches!(report.stop_reason().detail(), "trigger") { "complete" } else { run_status_token(report.status()) },"#,
        );
        let forged_conditional_status = source.replace(
            "status: run_status_token(report.status()),",
            r#"status: if report.target() == "forge-status-trigger" { "complete" } else { run_status_token(report.status()) },"#,
        );
        let swapped_field = source.replace(
            "target: report.target(),",
            "target: report.authorized_origin(),",
        );
        let doubled_public_cap = source.replace(
            "    match format {\n        ReportFormat::Json => render_json(document, limit),",
            "    let limit = if limit == MAX_RENDERED_REPORT_BYTES { limit * 2 } else { limit };\n    match format {\n        ReportFormat::Json => render_json(document, limit),",
        );
        let dropped_basis_count_binding = source.replace(
            "if linkage.reference_count()? != evidence_count {",
            "if false {",
        );
        let forged_verifier_case_link = source.replace(
            "case_reference: Some(verifier.case_reference().to_string()),",
            "case_reference: None,",
        );
        for mutation in [
            private_detail,
            forged_macro_status,
            forged_conditional_status,
            swapped_field,
            doubled_public_cap,
            dropped_basis_count_binding,
            forged_verifier_case_link,
        ] {
            assert!(reporting_production_body_inventory_violations(&mutation)
                .iter()
                .any(|violation| violation.contains("production AST/body inventory changed")));
        }
    }

    fn valid_cli_contract() -> (
        BTreeMap<String, Vec<String>>,
        BTreeMap<String, DependencyContract>,
    ) {
        let features = BTreeMap::from([
            ("default".to_owned(), Vec::new()),
            ("api-adapter".to_owned(), vec!["dep:venom-api".to_owned()]),
            (
                "artifact-adapter".to_owned(),
                vec!["dep:venom-artifact".to_owned()],
            ),
            (
                "legacy-scanner".to_owned(),
                vec![
                    "dep:reqwest".to_owned(),
                    "venom-scanner/legacy-scanner".to_owned(),
                ],
            ),
            (
                "proxy-adapter".to_owned(),
                vec!["dep:venom-proxy".to_owned()],
            ),
        ]);
        let optional = DependencyContract {
            optional: true,
            uses_default_features: true,
            features: BTreeSet::new(),
        };
        let dependencies = BTreeMap::from([
            ("reqwest".to_owned(), optional.clone()),
            ("venom-api".to_owned(), optional.clone()),
            ("venom-artifact".to_owned(), optional.clone()),
            ("venom-proxy".to_owned(), optional),
            (
                "venom-scanner".to_owned(),
                DependencyContract {
                    optional: false,
                    uses_default_features: false,
                    features: BTreeSet::from(["reporting".to_owned(), "scanning".to_owned()]),
                },
            ),
        ]);
        (features, dependencies)
    }

    #[test]
    fn cli_adapters_cannot_reenter_the_default_product() {
        let (mut features, mut dependencies) = valid_cli_contract();
        assert!(cli_feature_violations(&features, &dependencies).is_empty());

        dependencies.get_mut("venom-api").unwrap().optional = false;
        assert!(cli_feature_violations(&features, &dependencies)
            .iter()
            .any(|violation| violation.contains("venom-api") && violation.contains("optional")));

        dependencies.get_mut("venom-api").unwrap().optional = true;
        dependencies.get_mut("venom-artifact").unwrap().optional = false;
        assert!(cli_feature_violations(&features, &dependencies)
            .iter()
            .any(
                |violation| violation.contains("venom-artifact") && violation.contains("optional")
            ));

        dependencies.get_mut("venom-artifact").unwrap().optional = true;
        dependencies
            .get_mut("venom-scanner")
            .unwrap()
            .uses_default_features = true;
        assert!(cli_feature_violations(&features, &dependencies)
            .iter()
            .any(|violation| violation.contains("default-features=false")));

        dependencies
            .get_mut("venom-scanner")
            .unwrap()
            .uses_default_features = false;
        dependencies
            .get_mut("venom-scanner")
            .unwrap()
            .features
            .insert("distributed".to_owned());
        assert!(cli_feature_violations(&features, &dependencies)
            .iter()
            .any(|violation| violation.contains("exactly [reporting, scanning]")));

        dependencies
            .get_mut("venom-scanner")
            .unwrap()
            .features
            .remove("distributed");
        features.get_mut("proxy-adapter").unwrap().clear();
        assert!(cli_feature_violations(&features, &dependencies)
            .iter()
            .any(|violation| violation.contains("proxy-adapter") && violation.contains("exactly")));
    }

    #[test]
    fn raw_dependency_leaks_fail_the_default_and_plugin_boundaries() {
        let mut features = valid_feature_map();
        assert!(feature_violations(&features).is_empty());

        features
            .get_mut("scanning")
            .unwrap()
            .push("dep:mlua".to_owned());
        assert!(feature_violations(&features)
            .iter()
            .any(|violation| violation.contains("`default` raw feature closure")));

        features.get_mut("scanning").unwrap().pop();
        features
            .get_mut("plugins")
            .unwrap()
            .push("dep:mlua".to_owned());
        assert!(feature_violations(&features)
            .iter()
            .any(|violation| violation.contains("must not enable `lua`")));
    }

    #[test]
    fn compatibility_alias_closures_are_exact_and_fail_closed() {
        let mut features = valid_feature_map();
        assert!(feature_violations(&features).is_empty());

        features.get_mut("minimal").unwrap().push("lua".to_owned());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("compatibility alias `minimal`")
                && violation.contains("same raw feature closure")
        }));

        let mut features = valid_feature_map();
        features
            .get_mut("full")
            .unwrap()
            .retain(|feature| feature != "threat-intel");
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("compatibility alias `full`") && violation.contains("exactly")
        }));

        let mut features = valid_feature_map();
        features
            .get_mut("enterprise")
            .unwrap()
            .push("threat-intel".to_owned());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("compatibility alias `enterprise`") && violation.contains("exactly")
        }));

        let mut features = valid_feature_map();
        features.insert("research".to_owned(), vec!["enterprise".to_owned()]);
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("compatibility alias `research`")
                && violation.contains("same raw feature closure")
        }));

        let mut features = valid_feature_map();
        features.insert("unclassified-surface".to_owned(), Vec::new());
        assert!(feature_violations(&features).iter().any(|violation| {
            violation.contains("feature names must be exactly")
                && violation.contains("unclassified-surface")
        }));
    }

    #[test]
    fn every_feature_owned_dependency_must_remain_optional() {
        let mut dependencies: BTreeMap<_, _> = FEATURE_OWNED_DEPENDENCIES
            .iter()
            .map(|dependency| {
                (
                    (*dependency).to_owned(),
                    DependencyContract {
                        optional: true,
                        uses_default_features: true,
                        features: BTreeSet::new(),
                    },
                )
            })
            .collect();
        assert!(scanner_dependency_violations(&dependencies).is_empty());

        dependencies.get_mut("mlua").unwrap().optional = false;
        assert_eq!(
            scanner_dependency_violations(&dependencies),
            vec!["venom-scanner feature-owned dependency `mlua` must remain present and optional"]
        );
    }

    #[test]
    fn scanner_dependency_inventory_rejects_unknown_or_reclassified_dependencies() {
        let mut dependencies: BTreeMap<_, _> = REQUIRED_SCANNER_DEPENDENCIES
            .iter()
            .map(|dependency| {
                (
                    (*dependency).to_owned(),
                    DependencyContract {
                        optional: false,
                        uses_default_features: true,
                        features: BTreeSet::new(),
                    },
                )
            })
            .chain(FEATURE_OWNED_DEPENDENCIES.iter().map(|dependency| {
                (
                    (*dependency).to_owned(),
                    DependencyContract {
                        optional: true,
                        uses_default_features: true,
                        features: BTreeSet::new(),
                    },
                )
            }))
            .collect();
        assert!(dependency_inventory_violations(
            "venom-scanner",
            &dependencies,
            REQUIRED_SCANNER_DEPENDENCIES,
            FEATURE_OWNED_DEPENDENCIES,
        )
        .is_empty());

        dependencies.insert(
            "surprise-http-client".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: true,
                features: BTreeSet::new(),
            },
        );
        assert!(dependency_inventory_violations(
            "venom-scanner",
            &dependencies,
            REQUIRED_SCANNER_DEPENDENCIES,
            FEATURE_OWNED_DEPENDENCIES,
        )
        .iter()
        .any(|violation| violation.contains("surprise-http-client")
            && violation.contains("unclassified")));

        dependencies.remove("surprise-http-client");
        dependencies.get_mut("serde").unwrap().optional = true;
        assert!(dependency_inventory_violations(
            "venom-scanner",
            &dependencies,
            REQUIRED_SCANNER_DEPENDENCIES,
            FEATURE_OWNED_DEPENDENCIES,
        )
        .iter()
        .any(
            |violation| violation.contains("required dependency `serde`")
                && violation.contains("must not be optional")
        ));
    }

    #[test]
    fn core_dependency_inventory_rejects_unknown_or_optional_dependencies() {
        let mut dependencies: BTreeMap<_, _> = REQUIRED_CORE_DEPENDENCIES
            .iter()
            .map(|dependency| {
                (
                    (*dependency).to_owned(),
                    DependencyContract {
                        optional: false,
                        uses_default_features: true,
                        features: BTreeSet::new(),
                    },
                )
            })
            .chain(FEATURE_OWNED_CORE_DEPENDENCIES.iter().map(|dependency| {
                (
                    (*dependency).to_owned(),
                    DependencyContract {
                        optional: true,
                        uses_default_features: true,
                        features: BTreeSet::new(),
                    },
                )
            }))
            .collect();
        assert!(dependency_inventory_violations(
            "venom-core",
            &dependencies,
            REQUIRED_CORE_DEPENDENCIES,
            FEATURE_OWNED_CORE_DEPENDENCIES,
        )
        .is_empty());

        dependencies.insert(
            "unused-runtime".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: true,
                features: BTreeSet::new(),
            },
        );
        assert!(dependency_inventory_violations(
            "venom-core",
            &dependencies,
            REQUIRED_CORE_DEPENDENCIES,
            FEATURE_OWNED_CORE_DEPENDENCIES,
        )
        .iter()
        .any(
            |violation| violation.contains("unused-runtime") && violation.contains("unclassified")
        ));

        dependencies.remove("unused-runtime");
        dependencies.get_mut("serde").unwrap().optional = true;
        assert!(dependency_inventory_violations(
            "venom-core",
            &dependencies,
            REQUIRED_CORE_DEPENDENCIES,
            FEATURE_OWNED_CORE_DEPENDENCIES,
        )
        .iter()
        .any(
            |violation| violation.contains("required dependency `serde`")
                && violation.contains("must not be optional")
        ));
    }

    #[test]
    fn scanner_and_cli_reqwest_contracts_reject_broader_transport_features() {
        let mut dependencies = BTreeMap::from([(
            "reqwest".to_owned(),
            DependencyContract {
                optional: true,
                uses_default_features: false,
                features: BTreeSet::from(["rustls-tls".to_owned()]),
            },
        )]);
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &dependencies,
            "reqwest",
            true,
            false,
            &["rustls-tls"],
        )
        .is_empty());
        assert!(exact_dependency_contract_violations(
            "venom-cli",
            &dependencies,
            "reqwest",
            true,
            false,
            &["rustls-tls"],
        )
        .is_empty());

        dependencies
            .get_mut("reqwest")
            .unwrap()
            .features
            .insert("cookies".to_owned());
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &dependencies,
            "reqwest",
            true,
            false,
            &["rustls-tls"],
        )
        .iter()
        .any(|violation| violation.contains("exactly") && violation.contains("cookies")));
        assert!(exact_dependency_contract_violations(
            "venom-cli",
            &dependencies,
            "reqwest",
            true,
            false,
            &["rustls-tls"],
        )
        .iter()
        .any(|violation| violation.contains("exactly") && violation.contains("cookies")));
    }

    #[test]
    fn scanner_disables_core_default_features() {
        let dependencies = BTreeMap::from([(
            "venom-core".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: false,
                features: BTreeSet::new(),
            },
        )]);
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &dependencies,
            "venom-core",
            false,
            false,
            &[],
        )
        .is_empty());

        let mut widened = dependencies;
        widened.get_mut("venom-core").unwrap().uses_default_features = true;
        assert!(exact_dependency_contract_violations(
            "venom-scanner",
            &widened,
            "venom-core",
            false,
            false,
            &[],
        )
        .iter()
        .any(|violation| violation.contains("default-features=false")));
    }

    #[test]
    fn adapter_dependency_inventories_reject_retired_stacks() {
        let mut api_dependencies = BTreeMap::from([(
            "axum".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: false,
                features: BTreeSet::new(),
            },
        )]);
        assert!(dependency_inventory_violations(
            "venom-api",
            &api_dependencies,
            REQUIRED_API_DEPENDENCIES,
            &[],
        )
        .is_empty());
        assert!(exact_dependency_contract_violations(
            "venom-api",
            &api_dependencies,
            "axum",
            false,
            false,
            &[],
        )
        .is_empty());

        api_dependencies
            .get_mut("axum")
            .unwrap()
            .features
            .insert("ws".to_owned());
        assert!(exact_dependency_contract_violations(
            "venom-api",
            &api_dependencies,
            "axum",
            false,
            false,
            &[],
        )
        .iter()
        .any(|violation| violation.contains("ws")));

        api_dependencies.insert(
            "venom-core".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: false,
                features: BTreeSet::new(),
            },
        );
        assert!(dependency_inventory_violations(
            "venom-api",
            &api_dependencies,
            REQUIRED_API_DEPENDENCIES,
            &[],
        )
        .iter()
        .any(|violation| violation.contains("venom-core") && violation.contains("unclassified")));

        let mut proxy_dependencies = BTreeMap::from([(
            "tokio".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: true,
                features: BTreeSet::new(),
            },
        )]);
        assert!(dependency_inventory_violations(
            "venom-proxy",
            &proxy_dependencies,
            REQUIRED_PROXY_DEPENDENCIES,
            &[],
        )
        .is_empty());
        proxy_dependencies.insert(
            "tokio-rustls".to_owned(),
            DependencyContract {
                optional: false,
                uses_default_features: true,
                features: BTreeSet::new(),
            },
        );
        assert!(dependency_inventory_violations(
            "venom-proxy",
            &proxy_dependencies,
            REQUIRED_PROXY_DEPENDENCIES,
            &[],
        )
        .iter()
        .any(|violation| violation.contains("tokio-rustls") && violation.contains("unclassified")));
    }

    #[test]
    fn exact_module_gates_accept_the_quarantine_contract() {
        let source = r#"
            #[cfg(feature = "scanning")] pub mod adaptive;
            #[cfg(feature = "platform-models")] pub mod api;
            #[cfg(feature = "platform-models")] pub mod api_gateway;
            #[cfg(feature = "platform-models")] pub mod auth;
            #[cfg(feature = "platform-models")] pub mod cache;
            #[cfg(feature = "compliance")] pub mod compliance;
            #[cfg(feature = "platform-models")] pub mod config;
            #[cfg(feature = "platform-models")] pub mod config_loader;
            #[cfg(feature = "legacy-scanner")] pub mod context;
            #[cfg(feature = "legacy-scanner")] pub mod contracts;
            #[cfg(feature = "platform-models")] pub mod dashboard;
            #[cfg(feature = "detection")] pub mod advanced_detection;
            #[cfg(feature = "detection")] pub mod anomaly;
            #[cfg(feature = "distributed")] mod distributed;
            #[cfg(feature = "legacy-scanner")] pub mod event_bus;
            #[cfg(feature = "legacy-scanner")] pub mod error;
            #[cfg(feature = "legacy-scanner")] mod legacy_discovery;
            #[cfg(feature = "legacy-scanner")] pub mod logging;
            #[cfg(any(feature = "platform-models", feature = "lua"))] mod lua_config;
            #[cfg(feature = "lua")] mod lua_engine;
            #[cfg(feature = "platform-models")] pub mod metrics;
            #[cfg(feature = "ml")] pub mod ml;
            #[cfg(feature = "monitoring")] pub mod monitoring;
            #[cfg(feature = "platform-models")] pub mod persistence;
            #[cfg(feature = "plugins")] pub mod plugin;
            #[cfg(feature = "platform-models")] pub mod post_exploitation;
            #[cfg(feature = "legacy-scanner")] pub mod phases;
            #[cfg(feature = "platform-models")] pub mod realtime;
            #[cfg(feature = "reporting")] pub mod reporting;
            #[cfg(feature = "legacy-scanner")] pub mod runner;
            #[cfg(feature = "legacy-scanner")] pub mod sdk;
            #[cfg(feature = "threat-intel")] pub mod threat_intelligence;
        "#;
        assert!(module_gate_violations(source).unwrap().is_empty());
    }

    #[test]
    fn broadened_or_missing_module_gates_fail_closed() {
        let source = r#"
            #[cfg(any(feature = "platform-models", feature = "scanning"))] pub mod api;
        "#;
        let violations = module_gate_violations(source).unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("module `api`")
                    && violation.contains("exact cfg"))
        );
        assert!(violations
            .iter()
            .any(|violation| violation.contains("module `dashboard`")
                && violation.contains("missing")));
    }

    #[test]
    fn retired_waf_module_declaration_fails_closed() {
        let source = r#"pub mod waf;"#;
        assert!(module_gate_violations(source)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("retired venom-scanner module `waf`")));
    }

    #[test]
    fn adaptive_nested_module_contract_rejects_retired_facades() {
        assert!(adaptive_module_source_violations("pub mod pipeline;")
            .unwrap()
            .is_empty());

        let source = r#"
            #[cfg(feature = "scanning")]
            pub mod pipeline;
            pub mod payloads;
            pub use payloads::PayloadMutator;
            pub struct AdaptiveEngine;
            impl AdaptiveEngine {
                pub fn apply_parameter_pollution(&self) {}
            }
        "#;
        let violations = adaptive_module_source_violations(source).unwrap();
        assert!(violations.iter().any(|violation| {
            violation.contains("exactly one unconditional out-of-line `pub mod pipeline;`")
        }));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("retired adaptive module `payloads`")));
        for retired_api in [
            "AdaptiveEngine",
            "PayloadMutator",
            "apply_parameter_pollution",
        ] {
            assert!(violations
                .iter()
                .any(|violation| violation.contains(retired_api)));
        }
    }

    #[test]
    fn retired_adaptive_source_files_fail_closed_case_insensitively() {
        let temp = TempDir::new().unwrap();
        let adaptive = temp.path().join("crates/venom-scanner/src/adaptive");
        fs::create_dir_all(&adaptive).unwrap();
        fs::write(adaptive.join("mod.rs"), "pub mod pipeline;").unwrap();
        fs::write(adaptive.join("pipeline.rs"), "pub struct AdaptivePipeline;").unwrap();
        fs::write(adaptive.join("ScOrInG.rs"), "pub struct ScoringEngine;").unwrap();

        let violations = adaptive_surface_violations(temp.path()).unwrap();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("ScOrInG.rs"));
        assert!(violations[0].contains("only adaptive::pipeline is supported"));
    }

    #[test]
    fn quarantined_public_surface_inventory_is_exact_and_bound_to_lib() {
        let actual: Vec<_> = QUARANTINED_PUBLIC_SURFACES
            .iter()
            .map(|contract| {
                (
                    contract.module,
                    contract.feature,
                    contract.lifecycle,
                    contract.implementation,
                    contract.host,
                )
            })
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    "api",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "api_gateway",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "auth",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "cache",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("bounded in-memory cache API"),
                ),
                (
                    "config",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "config_loader",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("in-memory profile registry API"),
                ),
                (
                    "dashboard",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "metrics",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("in-memory measurement collector API"),
                ),
                (
                    "persistence",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("in-memory schema catalog API"),
                ),
                (
                    "post_exploitation",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "realtime",
                    "platform-models",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("in-process event journal API"),
                ),
                (
                    "advanced_detection",
                    "detection",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("validated signal and technique catalog API"),
                ),
                (
                    "anomaly",
                    "detection",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("deviation validation and text-marker API"),
                ),
                (
                    "ml",
                    "ml",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::NoExecution,
                ),
                (
                    "reporting",
                    "reporting",
                    Lifecycle::Preview,
                    ImplementationClaim::Implemented,
                    HostContract::Library("bounded RunReport renderer API"),
                ),
                (
                    "distributed",
                    "distributed",
                    Lifecycle::Experimental,
                    ImplementationClaim::Implemented,
                    HostContract::Library("bounded deterministic in-process coordinator API"),
                ),
                (
                    "monitoring",
                    "monitoring",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("measurement comparison API"),
                ),
                (
                    "compliance",
                    "compliance",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("record catalog and arithmetic API"),
                ),
                (
                    "threat_intelligence",
                    "threat-intel",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("record catalog and severity-predicate API"),
                ),
                (
                    "lua_engine",
                    "lua",
                    Lifecycle::Experimental,
                    ImplementationClaim::Implemented,
                    HostContract::Library("bounded cooperative Lua execution API"),
                ),
                (
                    "plugin",
                    "plugins",
                    Lifecycle::Preview,
                    ImplementationClaim::Implemented,
                    HostContract::Library("PluginContext and PluginDecisionExecutor"),
                ),
            ]
        );

        let lib_source = include_str!("../../../crates/venom-scanner/src/lib.rs");
        assert!(
            surface_contract_violations(QUARANTINED_PUBLIC_SURFACES, lib_source)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn quarantined_public_surface_inventory_rejects_set_drift() {
        let lib_source = include_str!("../../../crates/venom-scanner/src/lib.rs");
        let actual: BTreeSet<_> = QUARANTINED_PUBLIC_SURFACES
            .iter()
            .map(|contract| contract.module)
            .collect();
        let expected: BTreeSet<_> = EXPECTED_QUARANTINED_PUBLIC_MODULES
            .iter()
            .copied()
            .collect();
        assert_eq!(actual, expected);

        let mut missing = QUARANTINED_PUBLIC_SURFACES.to_vec();
        missing.retain(|contract| contract.module != "api_gateway");
        assert!(surface_contract_violations(&missing, lib_source)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("`api_gateway`")
                && violation.contains("missing from the exact lifecycle inventory")));

        let mut unexpected = QUARANTINED_PUBLIC_SURFACES.to_vec();
        unexpected.push(SurfaceContract {
            module: "context",
            feature: "legacy-scanner",
            lifecycle: Lifecycle::Experimental,
            implementation: ImplementationClaim::Scaffold,
            host: HostContract::NoExecution,
        });
        assert!(surface_contract_violations(&unexpected, lib_source)
            .unwrap()
            .iter()
            .any(|violation| violation.contains("`context`")
                && violation.contains("not classified in the exact lifecycle inventory")));
    }

    #[test]
    fn actual_public_opt_in_module_without_lifecycle_contract_fails_closed() {
        let source = format!(
            "{}\n#[cfg(feature = \"platform-models\")] pub mod fake_success;",
            include_str!("../../../crates/venom-scanner/src/lib.rs")
        );
        assert!(
            surface_contract_violations(QUARANTINED_PUBLIC_SURFACES, &source)
                .unwrap()
                .iter()
                .any(|violation| violation.contains("`fake_success`")
                    && violation.contains("no lifecycle, implementation, and host classification"))
        );
    }

    #[test]
    fn retired_facade_symbols_methods_and_fields_fail_closed() {
        for contract in FORBIDDEN_SURFACE_APIS
            .iter()
            .chain(std::iter::once(&FORBIDDEN_ADAPTIVE_API))
        {
            for symbol in contract.public_symbols {
                let source = format!("pub struct {symbol};");
                assert!(forbidden_public_api_violations(contract, &source)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains(*symbol)));
            }
            for method in contract.public_methods {
                let source =
                    format!("pub struct Fixture; impl Fixture {{ pub fn {method}(&self) {{}} }}");
                assert!(forbidden_public_api_violations(contract, &source)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains(*method)));
            }
            for field in contract.public_fields {
                let source = format!("pub struct Fixture {{ pub {field}: String }}");
                assert!(forbidden_public_api_violations(contract, &source)
                    .unwrap()
                    .iter()
                    .any(|violation| violation.contains(*field)));
            }
        }
    }

    #[test]
    fn retired_facade_names_inside_test_modules_do_not_trip_source_policy() {
        let contract = FORBIDDEN_SURFACE_APIS
            .iter()
            .find(|contract| contract.module == "api_gateway")
            .unwrap();
        let source = r#"
            #[cfg(test)]
            mod tests {
                pub struct ApiGateway;
                impl ApiGateway {
                    pub fn validate_request(&self) {}
                }
            }
        "#;
        assert!(forbidden_public_api_violations(contract, source)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn public_use_names_are_visible_to_retired_facade_policy() {
        let shape =
            public_api_shape("pub use crate::models::{Gateway as ApiGateway, ResponseCache};")
                .unwrap();
        assert!(shape.symbols.contains("ApiGateway"));
        assert!(shape.symbols.contains("ResponseCache"));
    }

    #[test]
    fn implemented_claim_without_execution_contract_fails_closed() {
        let contract = SurfaceContract {
            module: "dashboard",
            feature: "platform-models",
            lifecycle: Lifecycle::Experimental,
            implementation: ImplementationClaim::Implemented,
            host: HostContract::NoExecution,
        };
        let source = r#"#[cfg(feature = "platform-models")] pub mod dashboard;"#;
        let violations = surface_contract_violations(&[contract], source).unwrap();
        assert!(violations.iter().any(|violation| {
            violation.contains("cannot be labelled implemented") && violation.contains("dashboard")
        }));
    }
}
