//! Stable responsibility ownership for scanner facades split into child modules.
//!
//! These checks deliberately key off domain symbols, not line counts. A facade
//! may grow when its public contract grows, but the implementation domains below
//! cannot silently collapse back into the root file or migrate between siblings.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
};

use syn::{visit::Visit, Item, Type, Visibility};

use super::collect_use_paths;

#[derive(Clone, Copy)]
struct MethodOwner {
    receiver: &'static str,
    method: &'static str,
}

#[derive(Clone, Copy)]
struct ChildDomain {
    module: &'static str,
    symbols: &'static [&'static str],
    methods: &'static [MethodOwner],
}

#[derive(Clone, Copy)]
struct FacadeDomain {
    source: &'static str,
    children: &'static [ChildDomain],
    resident_symbols: &'static [&'static str],
    resident_methods: &'static [MethodOwner],
}

const NO_METHODS: &[MethodOwner] = &[];
const NO_SYMBOLS: &[&str] = &[];

const PLUGIN_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "limits",
        symbols: &["PluginBudget", "PluginConfig"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "transport",
        symbols: &[
            "PluginHttpMethod",
            "PluginHttpRequest",
            "PluginHttpResponse",
            "PluginRequestBroker",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "recorder",
        symbols: &[
            "PluginRedactionPolicy",
            "SecretRedactionPolicy",
            "PluginObservation",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "context",
        symbols: &[
            "PluginExecutionRequest",
            "PluginUsage",
            "PluginExecutionResult",
            "PluginContext",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "metadata",
        symbols: &["PluginMetadata"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "registry",
        symbols: &["PluginRegistry"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "execution",
        symbols: &[],
        methods: &[MethodOwner {
            receiver: "PluginRegistry",
            method: "execute",
        }],
    },
];

const DECISION_LOOP_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "command",
        symbols: &[
            "command_requiring_host_policy_context",
            "execution_command_action_id",
            "DecisionActionOrigin",
            "DecisionStopReason",
            "DecisionLoopCommand",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "state",
        symbols: &[
            "DecisionLoopState",
            "DecisionSession",
            "DecisionSessionSummary",
            "DecisionSessionTransition",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "receipts",
        symbols: &[
            "DecisionReasoningCommitReceipt",
            "DecisionPlanningReport",
            "DecisionOutcomeReport",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "policy",
        symbols: &["DecisionLoop"],
        methods: NO_METHODS,
    },
];

const DECISION_RUNNER_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "execution",
        symbols: &[
            "DecisionExecutionStage",
            "DecisionExecutionLimits",
            "DecisionExecutionRequest",
            "DecisionExecutionClass",
            "DecisionActionExecutor",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "failures",
        symbols: &[
            "DecisionExecutorError",
            "DecisionExecutionFailureKind",
            "DecisionRunnerError",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "receipts",
        symbols: &[
            "DecisionExecutionFailureReceipt",
            "DecisionEvidenceReceipt",
            "DecisionRunnerTurn",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "registry",
        symbols: &["DecisionExecutorRegistry"],
        methods: NO_METHODS,
    },
];

const HTTP_EVIDENCE_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "probe",
        symbols: &[
            "HttpProbeMethod",
            "HttpProbe",
            "HttpProbeProvider",
            "SubjectHttpProbeProvider",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "policy",
        symbols: &["HttpBodyCapture", "HttpEvidencePolicy"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "response",
        symbols: &["CollectedHttpResponse"],
        methods: NO_METHODS,
    },
];

const KNOWLEDGE_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "index",
        symbols: &["collect_indexed", "index"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "relations",
        symbols: &[
            "MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES",
            "MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS",
            "MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES",
            "MAX_KNOWLEDGE_RELATION_ID_BYTES",
            "MAX_KNOWLEDGE_RELATION_KIND_BYTES",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "snapshot",
        symbols: &["KnowledgeSnapshot"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "store",
        symbols: &["KnowledgeBase"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "writes",
        symbols: &[
            "HypothesisStateTransition",
            "KnowledgeWrite",
            "KnowledgeRecordKind",
            "KnowledgeBaseError",
            "KnowledgeBaseStats",
        ],
        methods: NO_METHODS,
    },
];

const RULES_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "expression",
        symbols: &[
            "KnowledgeLayer",
            "Expression",
            "ExpressionEvaluation",
            "ExpressionTrace",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "registry",
        symbols: &[
            "EvidenceSelector",
            "EvidenceAggregation",
            "EvidenceCalibration",
            "HypothesisConclusion",
            "ReasoningRule",
            "RuleWrite",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "evaluation",
        symbols: &["RuleEvaluation", "RuleApplication"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "engine",
        symbols: &["RuleEngine"],
        methods: NO_METHODS,
    },
];

const PLANNER_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "model",
        symbols: &[
            "RequiredStrength",
            "HypothesisSelector",
            "VerificationTarget",
            "ResolvedVerificationTarget",
            "AttackAction",
            "PlanningContext",
            "ExclusionReason",
            "ExcludedAction",
            "PlanStep",
            "AttackPlan",
            "PlannerWrite",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "policy",
        symbols: &[
            "ActionSuppressionContext",
            "ScheduledActionAuthorizationError",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "scoring",
        symbols: &[
            "BenefitScore",
            "RiskScore",
            "ActionCost",
            "UtilityScore",
            "UtilityBreakdown",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "selection",
        symbols: &["AttackPlanner"],
        methods: NO_METHODS,
    },
];

const API_OBSERVATION_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "cursor",
        symbols: &["ApiVisibilityReviewCursor"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "ingest",
        symbols: &["ingest_api_visibility_observation"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "model",
        symbols: &[
            "ApiObservationCommitReceipt",
            "ApiObservationError",
            "ApiObservationReceipt",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "query",
        symbols: &[
            "api_visibility_reviews_for_resource",
            "api_visibility_reviews_for_resource_v2",
            "ApiVisibilityReviewPage",
            "ApiVisibilityReviewQuery",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "review",
        symbols: &[
            "api_visibility_review_for_commit",
            "ApiVisibilityReview",
            "ApiVisibilityReviewDisposition",
        ],
        methods: NO_METHODS,
    },
];

const LUA_ENGINE_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "source",
        symbols: &["read_registered_source", "stable_script_id"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "registry",
        symbols: &[],
        methods: &[MethodOwner {
            receiver: "LuaScriptRegistry",
            method: "register",
        }],
    },
    ChildDomain {
        module: "execution",
        symbols: &[],
        methods: &[MethodOwner {
            receiver: "LuaScriptRegistry",
            method: "execute",
        }],
    },
    ChildDomain {
        module: "vm",
        symbols: &["execute_snapshot"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "limits",
        symbols: &["enforce_hook_controls"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "history",
        symbols: &["ExecutionProvenance", "elapsed_ms"],
        methods: NO_METHODS,
    },
];

const DISTRIBUTED_CHILDREN: &[ChildDomain] = &[
    ChildDomain {
        module: "model",
        symbols: &[
            "StateSnapshot",
            "TaskPriority",
            "TaskSpec",
            "TaskStatus",
            "Transition",
        ],
        methods: &[MethodOwner {
            receiver: "TaskStatus",
            method: "as_str",
        }],
    },
    ChildDomain {
        module: "limits",
        symbols: &[
            "DistributedLimits",
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
            "UTILIZATION_BASIS_POINTS",
        ],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "coordinator",
        symbols: &["WorkerPool"],
        methods: &[MethodOwner {
            receiver: "WorkerPool",
            method: "recover_expired_leases",
        }],
    },
    ChildDomain {
        module: "queue",
        symbols: &["TaskQueue"],
        methods: &[MethodOwner {
            receiver: "TaskQueue",
            method: "enqueue",
        }],
    },
    ChildDomain {
        module: "lease",
        symbols: &[
            "CancellationOutcome",
            "CompletionOutcome",
            "CompletionReceipt",
            "FailureOutcome",
            "QueuedTaskFence",
            "ScanTask",
            "StartOutcome",
            "TaskLease",
            "TaskOwnership",
        ],
        methods: &[MethodOwner {
            receiver: "ScanTask",
            method: "ownership",
        }],
    },
    ChildDomain {
        module: "worker",
        symbols: &[
            "WorkerNode",
            "WorkerObservation",
            "WorkerSpec",
            "WorkerStatus",
            "WorkerTag",
        ],
        methods: &[MethodOwner {
            receiver: "WorkerNode",
            method: "effective_capacity",
        }],
    },
    ChildDomain {
        module: "recovery",
        symbols: &["RecoverySummary"],
        methods: NO_METHODS,
    },
    ChildDomain {
        module: "results",
        symbols: &[
            "AggregatedResult",
            "ResultAggregator",
            "ResultLimits",
            "StoreResultOutcome",
        ],
        methods: &[MethodOwner {
            receiver: "ResultAggregator",
            method: "store_result",
        }],
    },
];

const FACADES: &[FacadeDomain] = &[
    FacadeDomain {
        source: "plugin.rs",
        children: PLUGIN_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "decision_loop.rs",
        children: DECISION_LOOP_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "decision_runner.rs",
        children: DECISION_RUNNER_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "http_evidence.rs",
        children: HTTP_EVIDENCE_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "knowledge.rs",
        children: KNOWLEDGE_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "rules.rs",
        children: RULES_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "planner.rs",
        children: PLANNER_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: &[MethodOwner {
            receiver: "PlannerError",
            method: "from",
        }],
    },
    FacadeDomain {
        source: "api_observation.rs",
        children: API_OBSERVATION_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: &[
            MethodOwner {
                receiver: "ApiObservationError",
                method: "committed_observation",
            },
            MethodOwner {
                receiver: "ApiObservationError",
                method: "into_committed_observation",
            },
            MethodOwner {
                receiver: "ApiObservationError",
                method: "reasoning_source",
            },
        ],
    },
    FacadeDomain {
        source: "lua_engine.rs",
        children: LUA_ENGINE_CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    },
    FacadeDomain {
        source: "distributed.rs",
        children: DISTRIBUTED_CHILDREN,
        resident_symbols: &["DistributedError", "lock_state"],
        resident_methods: NO_METHODS,
    },
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let source_root = workspace_root.join("crates/termivar-scanner/src");
    let mut violations = Vec::new();
    for facade in FACADES {
        violations.extend(inspect_facade(&source_root, facade)?);
    }
    Ok(violations)
}

fn inspect_facade(
    source_root: &Path,
    facade: &FacadeDomain,
) -> Result<Vec<String>, Box<dyn Error>> {
    let facade_path = source_root.join(facade.source);
    let facade_source = fs::read_to_string(&facade_path)?;
    let facade_syntax = syn::parse_file(&facade_source)?;
    let facade_symbols = top_level_symbols(&facade_syntax.items);
    let facade_methods = top_level_methods(&facade_syntax.items);
    let facade_bindings = facade_child_bindings(&facade_syntax.items);
    let mut child_symbols = BTreeMap::new();
    let mut child_methods = BTreeMap::new();
    let mut violations = Vec::new();

    for child in facade.children {
        let declarations = facade_syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(item) if item.ident == child.module => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !matches!(declarations.as_slice(), [item]
            if item.content.is_none()
                && item.attrs.is_empty()
                && matches!(&item.vis, Visibility::Inherited))
        {
            violations.push(format!(
                "{} must declare exactly one private external `mod {};` responsibility boundary",
                facade.source, child.module
            ));
        }

        let child_path = facade_path
            .with_extension("")
            .join(format!("{}.rs", child.module));
        if !child_path.is_file() {
            violations.push(format!(
                "{} responsibility module {} is missing",
                facade.source,
                child_path.display()
            ));
            continue;
        }
        let child_source = fs::read_to_string(child_path)?;
        let child_syntax = syn::parse_file(&child_source)?;
        if contains_parent_glob_import(&child_syntax) {
            violations.push(format!(
                "{}/{}.rs must not import its parent facade with `use super::*`",
                facade_path.with_extension("").display(),
                child.module
            ));
        }
        child_symbols.insert(child.module, top_level_symbols(&child_syntax.items));
        child_methods.insert(child.module, top_level_methods(&child_syntax.items));
    }

    for symbol in facade.resident_symbols {
        if !facade_symbols.contains(*symbol) {
            violations.push(format!(
                "{} authority `{symbol}` must remain defined in the facade",
                facade.source
            ));
        }
        for (child, symbols) in &child_symbols {
            if symbols.contains(*symbol) {
                violations.push(format!(
                    "{} authority `{symbol}` must not move into child module {child}",
                    facade.source
                ));
            }
        }
    }

    for method in facade.resident_methods {
        let ownership = (method.receiver.to_owned(), method.method.to_owned());
        if !facade_methods.contains(&ownership) {
            violations.push(format!(
                "{} authority {}::{} must remain implemented in the facade",
                facade.source, method.receiver, method.method
            ));
        }
        for (child, methods) in &child_methods {
            if methods.contains(&ownership) {
                violations.push(format!(
                    "{} authority {}::{} must not move into child module {child}",
                    facade.source, method.receiver, method.method
                ));
            }
        }
    }

    for child in facade.children {
        let owned_symbols = child_symbols.get(child.module).cloned().unwrap_or_default();
        let owned_methods = child_methods.get(child.module).cloned().unwrap_or_default();
        let bindings = facade_bindings
            .get(child.module)
            .cloned()
            .unwrap_or_default();
        for symbol in child.symbols {
            if !owned_symbols.contains(*symbol) {
                violations.push(format!(
                    "{} responsibility `{symbol}` must remain defined in {}/{}.rs",
                    facade.source,
                    facade_path.with_extension("").display(),
                    child.module
                ));
            }
            if facade_symbols.contains(*symbol) {
                violations.push(format!(
                    "{} responsibility `{symbol}` collapsed back into the facade",
                    facade.source
                ));
            }
            for (sibling, symbols) in &child_symbols {
                if sibling != &child.module && symbols.contains(*symbol) {
                    violations.push(format!(
                        "{} responsibility `{symbol}` moved into sibling module {sibling}",
                        facade.source
                    ));
                }
            }
            if !bindings.contains(*symbol) {
                violations.push(format!(
                    "{} must re-export `{symbol}` from its owning `{}` module",
                    facade.source, child.module
                ));
            }
        }
        for method in child.methods {
            let ownership = (method.receiver.to_owned(), method.method.to_owned());
            if !owned_methods.contains(&ownership) {
                violations.push(format!(
                    "{} method {}::{} must remain implemented in {}/{}.rs",
                    facade.source,
                    method.receiver,
                    method.method,
                    facade_path.with_extension("").display(),
                    child.module
                ));
            }
            if facade_methods.contains(&ownership) {
                violations.push(format!(
                    "{} method {}::{} collapsed back into the facade",
                    facade.source, method.receiver, method.method
                ));
            }
            for (sibling, methods) in &child_methods {
                if sibling != &child.module && methods.contains(&ownership) {
                    violations.push(format!(
                        "{} method {}::{} moved into sibling module {sibling}",
                        facade.source, method.receiver, method.method
                    ));
                }
            }
        }
    }

    Ok(violations)
}

#[derive(Default)]
struct ParentGlobImportVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for ParentGlobImportVisitor {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        if paths
            .iter()
            .any(|(segments, _, glob)| *glob && segments.as_slice() == ["super"])
        {
            self.found = true;
        }
        syn::visit::visit_item_use(self, item);
    }
}

fn contains_parent_glob_import(source: &syn::File) -> bool {
    let mut visitor = ParentGlobImportVisitor::default();
    visitor.visit_file(source);
    visitor.found
}

fn top_level_symbols(items: &[Item]) -> BTreeSet<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item) => Some(item.ident.to_string()),
            Item::Enum(item) => Some(item.ident.to_string()),
            Item::Fn(item) => Some(item.sig.ident.to_string()),
            Item::Static(item) => Some(item.ident.to_string()),
            Item::Struct(item) => Some(item.ident.to_string()),
            Item::Trait(item) => Some(item.ident.to_string()),
            Item::TraitAlias(item) => Some(item.ident.to_string()),
            Item::Type(item) => Some(item.ident.to_string()),
            Item::Union(item) => Some(item.ident.to_string()),
            _ => None,
        })
        .collect()
}

fn top_level_methods(items: &[Item]) -> BTreeSet<(String, String)> {
    let mut methods = BTreeSet::new();
    for item in items {
        let Item::Impl(item) = item else {
            continue;
        };
        let Some(receiver) = simple_type_name(&item.self_ty) else {
            continue;
        };
        for implementation in &item.items {
            if let syn::ImplItem::Fn(method) = implementation {
                methods.insert((receiver.clone(), method.sig.ident.to_string()));
            }
        }
    }
    methods
}

fn simple_type_name(item: &Type) -> Option<String> {
    let Type::Path(path) = item else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn facade_child_bindings(items: &[Item]) -> BTreeMap<String, BTreeSet<String>> {
    let mut bindings = BTreeMap::<String, BTreeSet<String>>::new();
    for item in items {
        let Item::Use(item) = item else {
            continue;
        };
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, binding, glob) in paths {
            if glob || segments.len() < 2 {
                continue;
            }
            let Some(module) = segments.first() else {
                continue;
            };
            let Some(binding) = binding.or_else(|| segments.last().cloned()) else {
                continue;
            };
            bindings.entry(module.clone()).or_default().insert(binding);
        }
    }
    bindings
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHILDREN: &[ChildDomain] = &[ChildDomain {
        module: "model",
        symbols: &["OwnedModel"],
        methods: &[MethodOwner {
            receiver: "OwnedModel",
            method: "run",
        }],
    }];
    const DOMAIN: FacadeDomain = FacadeDomain {
        source: "facade.rs",
        children: CHILDREN,
        resident_symbols: NO_SYMBOLS,
        resident_methods: NO_METHODS,
    };

    fn fixture(facade: &str, child: &str) -> Vec<String> {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("facade")).unwrap();
        fs::write(directory.path().join("facade.rs"), facade).unwrap();
        fs::write(directory.path().join("facade/model.rs"), child).unwrap();
        inspect_facade(directory.path(), &DOMAIN).unwrap()
    }

    #[test]
    fn accepts_private_external_domain_with_owned_symbol_and_method() {
        assert!(fixture(
            "mod model; pub use model::OwnedModel;",
            "pub struct OwnedModel; impl OwnedModel { pub fn run(&self) {} }",
        )
        .is_empty());
    }

    #[test]
    fn rejects_inline_redirected_or_collapsed_domains() {
        for facade in [
            "mod model { pub struct OwnedModel; } pub use model::OwnedModel;",
            "#[path = \"elsewhere.rs\"] mod model; pub use model::OwnedModel;",
            "mod model; pub use model::OwnedModel; pub struct OwnedModel;",
        ] {
            let violations = fixture(
                facade,
                "pub struct OwnedModel; impl OwnedModel { pub fn run(&self) {} }",
            );
            assert!(
                !violations.is_empty(),
                "facade unexpectedly passed: {facade}"
            );
        }
    }

    #[test]
    fn rejects_missing_owner_symbol_method_or_reexport() {
        let violations = fixture("mod model;", "pub struct DifferentModel;");
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must remain defined")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must remain implemented")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must re-export")));
    }

    #[test]
    fn rejects_parent_facade_glob_but_accepts_specific_super_imports() {
        let violations = fixture(
            "mod model; pub use model::OwnedModel;",
            "use super::*; pub struct OwnedModel; impl OwnedModel { pub fn run(&self) {} }",
        );
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must not import its parent facade")));

        assert!(fixture(
            "struct ParentAuthority; mod model; pub use model::OwnedModel;",
            "use super::ParentAuthority; pub struct OwnedModel; impl OwnedModel { pub fn run(&self) { let _ = core::mem::size_of::<ParentAuthority>(); } }",
        )
        .is_empty());
    }

    #[test]
    fn locks_facade_resident_authority_out_of_children() {
        const AUTHORITY_DOMAIN: FacadeDomain = FacadeDomain {
            source: "facade.rs",
            children: CHILDREN,
            resident_symbols: &["FacadeError"],
            resident_methods: &[MethodOwner {
                receiver: "FacadeError",
                method: "classify",
            }],
        };

        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("facade")).unwrap();
        fs::write(
            directory.path().join("facade.rs"),
            "pub enum FacadeError {} impl FacadeError { pub fn classify(&self) {} } mod model; pub use model::OwnedModel;",
        )
        .unwrap();
        fs::write(
            directory.path().join("facade/model.rs"),
            "pub struct OwnedModel; impl OwnedModel { pub fn run(&self) {} }",
        )
        .unwrap();
        assert!(inspect_facade(directory.path(), &AUTHORITY_DOMAIN)
            .unwrap()
            .is_empty());

        fs::write(
            directory.path().join("facade.rs"),
            "mod model; pub use model::{FacadeError, OwnedModel};",
        )
        .unwrap();
        fs::write(
            directory.path().join("facade/model.rs"),
            "pub enum FacadeError {} impl FacadeError { pub fn classify(&self) {} } pub struct OwnedModel; impl OwnedModel { pub fn run(&self) {} }",
        )
        .unwrap();
        let violations = inspect_facade(directory.path(), &AUTHORITY_DOMAIN).unwrap();
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must remain defined in the facade")));
        assert!(violations.iter().any(|violation| violation
            .contains("authority FacadeError::classify must remain implemented in the facade")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("must not move into child module")));
    }
}
