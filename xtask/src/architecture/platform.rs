//! Scanner feature and platform-surface quarantine policy.
//!
//! The default scanner is the deterministic reasoning/runtime product. Unwired
//! platform models, historical reporting, Lua, distributed scaffolds, and the
//! historical ordered scanner must remain explicit opt-ins. This check binds the
//! Cargo feature graph to the corresponding `lib.rs` module gates so a manifest
//! edit cannot silently pull an unsupported surface back into default builds.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs, io,
    path::Path,
};

use cargo_metadata::{DependencyKind, MetadataCommand};
use syn::{Attribute, Fields, ImplItem, Item, ItemMod, Meta, UseTree, Visibility};

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

const OPTIONAL_CLI_DEPENDENCIES: &[&str] = &["reqwest", "venom-api", "venom-proxy"];
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
    Legacy,
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
        lifecycle: Lifecycle::Legacy,
        implementation: ImplementationClaim::Implemented,
        host: HostContract::Library("finding-to-report renderer API"),
    },
    SurfaceContract {
        module: "distributed",
        feature: "distributed",
        lifecycle: Lifecycle::Experimental,
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("in-process coordinator API"),
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
        implementation: ImplementationClaim::Scaffold,
        host: HostContract::Library("fail-closed registry API"),
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
    violations.extend(surface_contract_violations(
        QUARANTINED_PUBLIC_SURFACES,
        &source,
    )?);
    violations.extend(forbidden_surface_source_violations(workspace_root)?);
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

    for dependency in ["reqwest", "venom-api", "venom-proxy"] {
        if dependencies
            .get(dependency)
            .is_none_or(|contract| !contract.optional)
        {
            violations.push(format!(
                "venom-cli dependency `{dependency}` must remain optional"
            ));
        }
    }
    let expected_scanner_features = BTreeSet::from(["scanning".to_owned()]);
    match dependencies.get("venom-scanner") {
        Some(contract)
            if !contract.optional
                && !contract.uses_default_features
                && contract.features == expected_scanner_features => {},
        Some(contract) => violations.push(format!(
            "venom-cli must use non-optional venom-scanner with default-features=false and exactly [scanning], found {contract:?}"
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
        (
            "reporting",
            &["reporting", "core", "venom-core/legacy-contracts"],
        ),
        ("detection", &["detection", "dep:regex"]),
        ("ml", &["ml"]),
        ("distributed", &["distributed", "dep:dashmap"]),
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
        (
            "lua",
            &[
                "lua",
                "core",
                "dep:dashmap",
                "dep:mlua",
                "dep:tokio",
                "dep:uuid",
            ],
        ),
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
            "any(feature=\"legacy-scanner\",feature=\"platform-models\",feature=\"reporting\")",
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

fn cfg_predicates(module: &ItemMod) -> Vec<String> {
    cfg_predicates_from_attributes(&module.attrs)
}

fn cfg_predicates_from_attributes(attributes: &[Attribute]) -> Vec<String> {
    attributes.iter().filter_map(cfg_predicate).collect()
}

fn cfg_predicate(attribute: &Attribute) -> Option<String> {
    if !attribute.path().is_ident("cfg") {
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
        if matches!(contract.lifecycle, Lifecycle::Legacy | Lifecycle::Preview)
            && contract.host == HostContract::NoExecution
        {
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
        if !matches!(module.vis, Visibility::Public(_)) {
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
            is_public(&module.vis)
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
        features.insert(
            "reporting".to_owned(),
            vec!["core".to_owned(), "venom-core/legacy-contracts".to_owned()],
        );
        features.insert("detection".to_owned(), vec!["dep:regex".to_owned()]);
        features.insert("ml".to_owned(), Vec::new());
        features.insert("distributed".to_owned(), vec!["dep:dashmap".to_owned()]);
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
            ["core", "dep:dashmap", "dep:mlua", "dep:tokio", "dep:uuid"]
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
                feature = "platform-models",
                feature = "reporting"
            ))]
            pub use venom_core::ScanFinding;
        "#;
        assert!(scanner_legacy_reexport_violations(source)
            .unwrap()
            .is_empty());

        let widened = source.replace(
            "feature = \"reporting\"\n            ))]",
            "feature = \"reporting\",\n                feature = \"scanning\"\n            ))]",
        );
        assert!(scanner_legacy_reexport_violations(&widened)
            .unwrap()
            .iter()
            .any(
                |violation| violation.contains("`ScanFinding`") && violation.contains("exact cfg")
            ));
    }

    fn valid_cli_contract() -> (
        BTreeMap<String, Vec<String>>,
        BTreeMap<String, DependencyContract>,
    ) {
        let features = BTreeMap::from([
            ("default".to_owned(), Vec::new()),
            ("api-adapter".to_owned(), vec!["dep:venom-api".to_owned()]),
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
            ("venom-proxy".to_owned(), optional),
            (
                "venom-scanner".to_owned(),
                DependencyContract {
                    optional: false,
                    uses_default_features: false,
                    features: BTreeSet::from(["scanning".to_owned()]),
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
            #[cfg(feature = "distributed")] pub mod distributed;
            #[cfg(feature = "legacy-scanner")] pub mod event_bus;
            #[cfg(feature = "legacy-scanner")] pub mod error;
            #[cfg(feature = "legacy-scanner")] mod legacy_discovery;
            #[cfg(feature = "legacy-scanner")] pub mod logging;
            #[cfg(any(feature = "platform-models", feature = "lua"))] mod lua_config;
            #[cfg(feature = "lua")] pub mod lua_engine;
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
                    Lifecycle::Legacy,
                    ImplementationClaim::Implemented,
                    HostContract::Library("finding-to-report renderer API"),
                ),
                (
                    "distributed",
                    "distributed",
                    Lifecycle::Experimental,
                    ImplementationClaim::Scaffold,
                    HostContract::Library("in-process coordinator API"),
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
                    ImplementationClaim::Scaffold,
                    HostContract::Library("fail-closed registry API"),
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
