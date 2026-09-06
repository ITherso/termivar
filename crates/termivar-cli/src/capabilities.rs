//! Offline, build-accurate inventory of CLI surfaces compiled into this binary.
//!
//! The inventory is fixed product metadata plus compile-time package feature
//! state. It never inspects the host, reads configuration, or initializes the
//! scanner runtime.

use std::{
    fmt,
    io::{self, Write},
    process::ExitCode,
};

use clap::{Args, ValueEnum};
use serde::Serialize;

const CAPABILITIES_SCHEMA: &str = "termivar-cli-capabilities/v1";
const MAX_CAPABILITIES_OUTPUT_BYTES: usize = 64 * 1024;
const INVENTORY_NOTICE: &str = "Build inventory only. No assessment was started or evaluated.";
const BUILD_ORIGIN_LIMITATION: &str = "Self-reported package version and compile features do not establish source authenticity, an official release origin, or runtime readiness.";

#[derive(Args)]
pub(crate) struct CapabilitiesArgs {
    /// Render the compiled CLI inventory as human-readable text or JSON.
    #[arg(long, value_enum, default_value_t = CapabilitiesFormat::Text)]
    format: CapabilitiesFormat,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum CapabilitiesFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BuildState {
    Compiled,
    NotCompiled,
}

impl BuildState {
    const fn from_compiled(compiled: bool) -> Self {
        if compiled {
            Self::Compiled
        } else {
            Self::NotCompiled
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Compiled => "compiled",
            Self::NotCompiled => "not_compiled",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SurfaceGroup {
    Everyday,
    Optional,
}

impl SurfaceGroup {
    const fn heading(self) -> &'static str {
        match self {
            Self::Everyday => "Everyday CLI surfaces",
            Self::Optional => "Optional CLI surfaces",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SurfaceKind {
    Command,
    Profile,
    ReportOutput,
    ScanOption,
}

impl SurfaceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Profile => "profile",
            Self::ReportOutput => "report_output",
            Self::ScanOption => "scan_option",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Maturity {
    Preview,
    Deprecated,
    Experimental,
    Legacy,
    Unsupported,
}

impl Maturity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Deprecated => "deprecated",
            Self::Experimental => "experimental",
            Self::Legacy => "legacy",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImplementationStatus {
    Implemented,
    ExperimentalLimited,
    LegacyUnmetered,
    UnsupportedStub,
}

impl ImplementationStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::ExperimentalLimited => "experimental_limited",
            Self::LegacyUnmetered => "legacy_unmetered",
            Self::UnsupportedStub => "unsupported_stub",
        }
    }
}

#[derive(Serialize)]
struct BuildFeatureDescriptor {
    name: &'static str,
    build_state: BuildState,
}

#[derive(Serialize)]
struct AliasDescriptor {
    name: &'static str,
    command: &'static str,
    maturity: Maturity,
    relation: &'static str,
}

#[derive(Serialize)]
struct SurfaceDescriptor {
    key: &'static str,
    label: &'static str,
    group: SurfaceGroup,
    kind: SurfaceKind,
    compile_feature: Option<&'static str>,
    build_state: BuildState,
    maturity: Maturity,
    implementation_status: ImplementationStatus,
    alias: Option<AliasDescriptor>,
    prerequisites: &'static [&'static str],
    limitation: &'static str,
    documentation: &'static str,
}

#[derive(Serialize)]
struct CapabilitiesDocument {
    schema: &'static str,
    product: &'static str,
    package_version: &'static str,
    inventory_scope: &'static str,
    runtime_execution: &'static str,
    cli_package_features: Vec<BuildFeatureDescriptor>,
    surfaces: Vec<SurfaceDescriptor>,
    notice: &'static str,
    build_origin_authenticity: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilitiesError {
    RenderFailed,
    OutputTooLarge,
    OutputFailed,
}

impl fmt::Display for CapabilitiesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RenderFailed => "capabilities inventory could not be rendered",
            Self::OutputTooLarge => "capabilities inventory exceeded its 64 KiB output limit",
            Self::OutputFailed => "capabilities inventory could not be written",
        })
    }
}

impl fmt::Debug for CapabilitiesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for CapabilitiesError {}

pub(crate) fn run(args: CapabilitiesArgs) -> Result<ExitCode, CapabilitiesError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    run_with_writer(args, &mut output)
}

fn run_with_writer(
    args: CapabilitiesArgs,
    output: &mut impl Write,
) -> Result<ExitCode, CapabilitiesError> {
    let document = build_document();
    let rendered = render(&document, args.format)?;
    output
        .write_all(&rendered)
        .map_err(|_| CapabilitiesError::OutputFailed)?;
    output
        .flush()
        .map_err(|_| CapabilitiesError::OutputFailed)?;
    Ok(ExitCode::SUCCESS)
}

fn build_document() -> CapabilitiesDocument {
    CapabilitiesDocument {
        schema: CAPABILITIES_SCHEMA,
        product: "Termivar",
        package_version: env!("CARGO_PKG_VERSION"),
        inventory_scope: "cli_surfaces",
        runtime_execution: "not_performed",
        cli_package_features: build_features(),
        surfaces: surfaces(),
        notice: INVENTORY_NOTICE,
        build_origin_authenticity: BUILD_ORIGIN_LIMITATION,
    }
}

fn build_features() -> Vec<BuildFeatureDescriptor> {
    [
        ("api-adapter", cfg!(feature = "api-adapter")),
        ("artifact-adapter", cfg!(feature = "artifact-adapter")),
        (
            "authorization-review",
            cfg!(feature = "authorization-review"),
        ),
        ("graphql-review", cfg!(feature = "graphql-review")),
        ("legacy-scanner", cfg!(feature = "legacy-scanner")),
        (
            "normalization-resilience",
            cfg!(feature = "normalization-resilience"),
        ),
        ("openapi-review", cfg!(feature = "openapi-review")),
        ("proxy-adapter", cfg!(feature = "proxy-adapter")),
        ("release-bundle", cfg!(feature = "release-bundle")),
        ("rest-review", cfg!(feature = "rest-review")),
        ("ssrf-oast-review", cfg!(feature = "ssrf-oast-review")),
    ]
    .into_iter()
    .map(|(name, compiled)| BuildFeatureDescriptor {
        name,
        build_state: BuildState::from_compiled(compiled),
    })
    .collect()
}

fn surfaces() -> Vec<SurfaceDescriptor> {
    vec![
        surface(
            "command.capabilities",
            "Compiled CLI capabilities",
            SurfaceGroup::Everyday,
            SurfaceKind::Command,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar capabilities [--format text|json]"],
            "Describes this binary only; it does not activate or test another surface.",
            "docs/GETTING_STARTED.md#inspect-compiled-cli-capabilities",
        ),
        surface(
            "command.scan",
            "Bounded deterministic scan",
            SurfaceGroup::Everyday,
            SurfaceKind::Command,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar scan TARGET"],
            "Requires an exact origin the operator owns or is authorized to assess.",
            "docs/internals/runtime-map.md",
        )
        .with_alias(AliasDescriptor {
            name: "decision-scan",
            command: "termivar decision-scan TARGET",
            maturity: Maturity::Deprecated,
            relation: "compatibility_alias_same_engine",
        }),
        surface(
            "profile.baseline",
            "Baseline scan profile",
            SurfaceGroup::Everyday,
            SurfaceKind::Profile,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar scan TARGET --profile baseline"],
            "Selects the baseline profile without creating a second scanner.",
            "docs/internals/runtime-map.md",
        ),
        surface(
            "profile.web-review",
            "Web-review scan profile",
            SurfaceGroup::Everyday,
            SurfaceKind::Profile,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar scan TARGET --profile web-review"],
            "Runs the bounded passive, semantic, defense-observation, and native CORS, redirect, reflection, SQL, SSTI, and XSS review catalog; optional review flags remain separately compiled and selected.",
            "docs/internals/runtime-map.md",
        ),
        surface(
            "output.assessment-reports",
            "Assessment report formats",
            SurfaceGroup::Everyday,
            SurfaceKind::ReportOutput,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &[
                "a completed --profile web-review assessment",
                "optional --report-format <json|csv|html|markdown> overrides the default Markdown/JSON mapping",
                "--report-output FILE requires --report-format",
            ],
            "Central rendering requires a completed assessment; incomplete runs retain diagnostics.",
            "docs/reporting.md",
        ),
        surface(
            "output.report-bundle",
            "Single-run report bundle",
            SurfaceGroup::Everyday,
            SurfaceKind::ReportOutput,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["--profile web-review", "--report-dir DIRECTORY"],
            "Publishes HTML, JSON, and a manifest only after one completed assessment.",
            "docs/reporting.md#single-run-report-bundles",
        ),
        surface(
            "command.report-compare",
            "Offline report comparison",
            SurfaceGroup::Everyday,
            SurfaceKind::Command,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar report compare --before FILE --after FILE --same-scope"],
            "The same-scope assertion is operator-declared; disappearance is not verified remediation.",
            "docs/reporting.md#offline-assessment-report-comparison",
        ),
        surface(
            "command.report-verify",
            "Offline report-bundle verification",
            SurfaceGroup::Everyday,
            SurfaceKind::Command,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar report verify --dir DIRECTORY [--format text|json]"],
            "Checks supported structure and bytes, not authenticity, scope, remediation, or HTML safety.",
            "docs/reporting.md#offline-report-bundle-verification",
        ),
        surface(
            "option.root-authorization-context",
            "Root authorization-context input",
            SurfaceGroup::Everyday,
            SurfaceKind::ScanOption,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &[
                "--profile web-review",
                "one of --auth-env, --auth-file, or --auth-stdin",
                "exact origin-root target",
                "HTTPS, except numeric-loopback HTTP fixtures",
            ],
            "Credential values stay outside argv; hosts remain responsible for authorization and context meaning.",
            "docs/internals/credential-input.md",
        ),
        surface(
            "option.defense-enforcement",
            "Defense enforcement",
            SurfaceGroup::Everyday,
            SurfaceKind::ScanOption,
            None,
            true,
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["--profile web-review", "--enforce-defense"],
            "May suppress or narrow work; it cannot add actions, intensity, scope, or budget.",
            "docs/internals/defense-observation.md",
        ),
        surface(
            "command.artifact",
            "Bounded local artifact scan",
            SurfaceGroup::Optional,
            SurfaceKind::Command,
            Some("artifact-adapter"),
            cfg!(feature = "artifact-adapter"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["termivar artifact scan-file --signatures FILE --input FILE"],
            "Scans one explicit local file; it does not recurse, execute content, or issue a malware verdict.",
            "docs/artifact-signatures.md",
        ),
        surface(
            "option.normalization-resilience",
            "Normalization-resilience review",
            SurfaceGroup::Optional,
            SurfaceKind::ScanOption,
            Some("normalization-resilience"),
            cfg!(feature = "normalization-resilience"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["--profile web-review", "--normalization-resilience"],
            "Uses bounded committed evidence and remains KnowledgeOnly; compilation does not enable it.",
            "docs/internals/normalization-resilience.md",
        ),
        surface(
            "option.graphql-review",
            "GraphQL surface review",
            SurfaceGroup::Optional,
            SurfaceKind::ScanOption,
            Some("graphql-review"),
            cfg!(feature = "graphql-review"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["--profile web-review", "--graphql-review"],
            "Anonymous bounded structure review only; no mutation, authorization, or availability claim.",
            "docs/internals/graphql-review.md",
        ),
        surface(
            "option.openapi-review",
            "OpenAPI surface review",
            SurfaceGroup::Optional,
            SurfaceKind::ScanOption,
            Some("openapi-review"),
            cfg!(feature = "openapi-review"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &["--profile web-review", "--openapi-review"],
            "A discovered document is typed knowledge, not authority to execute described operations.",
            "docs/internals/openapi-surface-review.md",
        ),
        surface(
            "option.rest-review",
            "REST read-only review",
            SurfaceGroup::Optional,
            SurfaceKind::ScanOption,
            Some("rest-review"),
            cfg!(feature = "rest-review"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &[
                "--profile web-review",
                "--openapi-review",
                "--rest-review",
            ],
            "Uses one eligible anonymous read-only operation; it does not establish a vulnerability.",
            "docs/internals/rest-readonly-review.md",
        ),
        surface(
            "option.resource-authorization-review",
            "Resource authorization review",
            SurfaceGroup::Optional,
            SurfaceKind::ScanOption,
            Some("authorization-review"),
            cfg!(feature = "authorization-review"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &[
                "--profile web-review",
                "--authorization-review-policy FILE",
                "one primary source: --authz-primary-env, --authz-primary-file, or --authz-primary-stdin",
                "one peer source: --authz-peer-env, --authz-peer-file, or --authz-peer-stdin",
                "HTTPS, except numeric-loopback HTTP fixtures",
            ],
            "Distinct principals are operator-provided; no identifier mutation or confirmed authorization claim.",
            "docs/internals/authorization-differential-review.md",
        ),
        surface(
            "option.ssrf-oast-review",
            "SSRF OAST query review",
            SurfaceGroup::Optional,
            SurfaceKind::ScanOption,
            Some("ssrf-oast-review"),
            cfg!(feature = "ssrf-oast-review"),
            Maturity::Preview,
            ImplementationStatus::Implemented,
            &[
                "--profile web-review",
                "--ssrf-oast-review",
                "--ssrf-oast-policy FILE",
                "one of --oast-admin-token-env, --oast-admin-token-file, or --oast-admin-token-stdin",
            ],
            "KnowledgeOnly maximum; corrective-maintenance F3 remains deferred, out of scope, and unresolved.",
            "docs/audits/native-oast-corrective-maintenance.md",
        ),
        surface(
            "command.legacy-scan",
            "Legacy scanner",
            SurfaceGroup::Optional,
            SurfaceKind::Command,
            Some("legacy-scanner"),
            cfg!(feature = "legacy-scanner"),
            Maturity::Legacy,
            ImplementationStatus::LegacyUnmetered,
            &[
                "termivar legacy-scan TARGET",
                "--acknowledge-legacy-heuristics",
            ],
            "The complete mixed-authority run remains Unmetered and is not the target scanner architecture.",
            "docs/internals/runtime-map.md#historical-mixed-authority-runner-surface-a",
        ),
        surface(
            "command.api",
            "HTTP API adapter",
            SurfaceGroup::Optional,
            SurfaceKind::Command,
            Some("api-adapter"),
            cfg!(feature = "api-adapter"),
            Maturity::Unsupported,
            ImplementationStatus::UnsupportedStub,
            &["termivar api [--addr SOCKET]"],
            "The command reports a typed nonzero unsupported error; no listener is implemented.",
            "docs/internals/runtime-map.md#optional-adapters-and-platform-shell-surface-c",
        ),
        surface(
            "command.proxy",
            "Fixed-upstream proxy adapter",
            SurfaceGroup::Optional,
            SurfaceKind::Command,
            Some("proxy-adapter"),
            cfg!(feature = "proxy-adapter"),
            Maturity::Experimental,
            ImplementationStatus::ExperimentalLimited,
            &["termivar proxy --upstream SOCKET [--addr SOCKET]"],
            "Fixed-upstream TCP relay only; no CONNECT, TLS termination, certificates, or HTTP inspection.",
            "docs/internals/runtime-map.md#optional-adapters-and-platform-shell-surface-c",
        ),
    ]
}

const fn surface(
    key: &'static str,
    label: &'static str,
    group: SurfaceGroup,
    kind: SurfaceKind,
    compile_feature: Option<&'static str>,
    compiled: bool,
    maturity: Maturity,
    implementation_status: ImplementationStatus,
    prerequisites: &'static [&'static str],
    limitation: &'static str,
    documentation: &'static str,
) -> SurfaceDescriptor {
    SurfaceDescriptor {
        key,
        label,
        group,
        kind,
        compile_feature,
        build_state: BuildState::from_compiled(compiled),
        maturity,
        implementation_status,
        alias: None,
        prerequisites,
        limitation,
        documentation,
    }
}

impl SurfaceDescriptor {
    const fn with_alias(mut self, alias: AliasDescriptor) -> Self {
        self.alias = Some(alias);
        self
    }
}

fn render(
    document: &CapabilitiesDocument,
    format: CapabilitiesFormat,
) -> Result<Vec<u8>, CapabilitiesError> {
    let bytes = match format {
        CapabilitiesFormat::Text => render_text(document)?.into_bytes(),
        CapabilitiesFormat::Json => {
            let mut bytes =
                serde_json::to_vec_pretty(document).map_err(|_| CapabilitiesError::RenderFailed)?;
            bytes.push(b'\n');
            bytes
        },
    };
    enforce_output_limit(bytes)
}

fn enforce_output_limit(bytes: Vec<u8>) -> Result<Vec<u8>, CapabilitiesError> {
    if bytes.len() > MAX_CAPABILITIES_OUTPUT_BYTES {
        return Err(CapabilitiesError::OutputTooLarge);
    }
    Ok(bytes)
}

fn render_text(document: &CapabilitiesDocument) -> Result<String, CapabilitiesError> {
    use fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "Termivar CLI capabilities").map_err(|_| CapabilitiesError::RenderFailed)?;
    writeln!(output, "version: {}", document.package_version)
        .map_err(|_| CapabilitiesError::RenderFailed)?;
    writeln!(output, "inventory_scope: {}", document.inventory_scope)
        .map_err(|_| CapabilitiesError::RenderFailed)?;
    writeln!(output, "runtime_execution: {}", document.runtime_execution)
        .map_err(|_| CapabilitiesError::RenderFailed)?;

    for group in [SurfaceGroup::Everyday, SurfaceGroup::Optional] {
        writeln!(output, "\n{}", group.heading()).map_err(|_| CapabilitiesError::RenderFailed)?;
        for surface in document
            .surfaces
            .iter()
            .filter(|surface| surface.group == group)
        {
            writeln!(
                output,
                "  [{}] {} ({}, {}; {})",
                surface.build_state.as_str(),
                surface.label,
                surface.kind.as_str(),
                surface.maturity.as_str(),
                surface.implementation_status.as_str(),
            )
            .map_err(|_| CapabilitiesError::RenderFailed)?;
            writeln!(output, "    key: {}", surface.key)
                .map_err(|_| CapabilitiesError::RenderFailed)?;
            if let Some(alias) = &surface.alias {
                writeln!(
                    output,
                    "    alias: {} ({}, {})",
                    alias.command,
                    alias.maturity.as_str(),
                    alias.relation,
                )
                .map_err(|_| CapabilitiesError::RenderFailed)?;
            }
            if let Some(feature) = surface.compile_feature {
                writeln!(output, "    compile_feature: {feature}")
                    .map_err(|_| CapabilitiesError::RenderFailed)?;
            }
            for prerequisite in surface.prerequisites {
                writeln!(output, "    requires: {prerequisite}")
                    .map_err(|_| CapabilitiesError::RenderFailed)?;
            }
            writeln!(output, "    limit: {}", surface.limitation)
                .map_err(|_| CapabilitiesError::RenderFailed)?;
            writeln!(output, "    docs: {}", surface.documentation)
                .map_err(|_| CapabilitiesError::RenderFailed)?;
        }
    }

    writeln!(output, "\nCompile features (termivar-cli package)")
        .map_err(|_| CapabilitiesError::RenderFailed)?;
    for feature in &document.cli_package_features {
        writeln!(
            output,
            "  [{}] {}",
            feature.build_state.as_str(),
            feature.name
        )
        .map_err(|_| CapabilitiesError::RenderFailed)?;
    }
    writeln!(output, "\n{}", document.notice).map_err(|_| CapabilitiesError::RenderFailed)?;
    writeln!(
        output,
        "Build origin/authenticity: {}",
        document.build_origin_authenticity
    )
    .map_err(|_| CapabilitiesError::RenderFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, io};

    use clap::{CommandFactory, Parser};

    use super::*;

    #[test]
    fn document_is_bounded_ordered_and_unique() {
        let document = build_document();
        assert_eq!(document.schema, CAPABILITIES_SCHEMA);
        assert_eq!(document.package_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(document.inventory_scope, "cli_surfaces");
        assert_eq!(document.runtime_execution, "not_performed");
        assert_eq!(document.surfaces.len(), 20);

        let keys = document
            .surfaces
            .iter()
            .map(|surface| surface.key)
            .collect::<Vec<_>>();
        assert_eq!(
            keys.iter().copied().collect::<BTreeSet<_>>().len(),
            keys.len()
        );
        assert_eq!(
            keys,
            [
                "command.capabilities",
                "command.scan",
                "profile.baseline",
                "profile.web-review",
                "output.assessment-reports",
                "output.report-bundle",
                "command.report-compare",
                "command.report-verify",
                "option.root-authorization-context",
                "option.defense-enforcement",
                "command.artifact",
                "option.normalization-resilience",
                "option.graphql-review",
                "option.openapi-review",
                "option.rest-review",
                "option.resource-authorization-review",
                "option.ssrf-oast-review",
                "command.legacy-scan",
                "command.api",
                "command.proxy",
            ]
        );

        let feature_names = document
            .cli_package_features
            .iter()
            .map(|feature| feature.name)
            .collect::<Vec<_>>();
        let mut sorted = feature_names.clone();
        sorted.sort_unstable();
        assert_eq!(feature_names, sorted);
        assert!(!feature_names.contains(&"default"));

        for format in [CapabilitiesFormat::Text, CapabilitiesFormat::Json] {
            let rendered = render(&document, format).unwrap();
            assert!(rendered.len() < MAX_CAPABILITIES_OUTPUT_BYTES);
        }
    }

    #[test]
    fn text_and_json_project_the_same_build_states() {
        let document = build_document();
        let text = String::from_utf8(render(&document, CapabilitiesFormat::Text).unwrap()).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&render(&document, CapabilitiesFormat::Json).unwrap()).unwrap();
        assert_eq!(json["schema"], CAPABILITIES_SCHEMA);
        assert_eq!(
            json["surfaces"].as_array().unwrap().len(),
            document.surfaces.len()
        );
        assert_eq!(
            json["cli_package_features"].as_array().unwrap().len(),
            document.cli_package_features.len()
        );
        for surface in &document.surfaces {
            assert!(text.contains(&format!(
                "[{}] {}",
                surface.build_state.as_str(),
                surface.label
            )));
        }
        for feature in &document.cli_package_features {
            assert!(text.contains(&format!(
                "[{}] {}",
                feature.build_state.as_str(),
                feature.name
            )));
        }
    }

    #[test]
    fn compile_states_match_the_actual_clap_grammar() {
        let document = build_document();
        let command = crate::Cli::command();
        for always in ["capabilities", "scan", "report"] {
            assert!(
                command.find_subcommand(always).is_some(),
                "missing {always}"
            );
        }
        let scan = command.find_subcommand("scan").unwrap();
        for (key, flag) in [
            (
                "option.normalization-resilience",
                "normalization-resilience",
            ),
            ("option.graphql-review", "graphql-review"),
            ("option.openapi-review", "openapi-review"),
            ("option.rest-review", "rest-review"),
            (
                "option.resource-authorization-review",
                "authorization-review-policy",
            ),
            ("option.ssrf-oast-review", "ssrf-oast-review"),
        ] {
            let state = document
                .surfaces
                .iter()
                .find(|surface| surface.key == key)
                .unwrap()
                .build_state;
            let exposed = scan
                .get_arguments()
                .any(|argument| argument.get_long() == Some(flag));
            assert_eq!(state == BuildState::Compiled, exposed, "{key}");
        }
        for (key, subcommand) in [
            ("command.artifact", "artifact"),
            ("command.legacy-scan", "legacy-scan"),
            ("command.api", "api"),
            ("command.proxy", "proxy"),
        ] {
            let state = document
                .surfaces
                .iter()
                .find(|surface| surface.key == key)
                .unwrap()
                .build_state;
            assert_eq!(
                state == BuildState::Compiled,
                command.find_subcommand(subcommand).is_some(),
                "{key}"
            );
        }

        let report = command.find_subcommand("report").unwrap();
        for subcommand in ["compare", "verify"] {
            assert!(report.find_subcommand(subcommand).is_some());
        }
        assert!(
            crate::Cli::try_parse_from(["termivar", "decision-scan", "https://example.test",])
                .is_ok()
        );
    }

    #[test]
    fn descriptor_contracts_pin_lifecycle_implementation_and_activation_truth() {
        let document = build_document();
        let expected = [
            ("command.capabilities", None, "preview", "implemented"),
            ("command.scan", None, "preview", "implemented"),
            ("profile.baseline", None, "preview", "implemented"),
            ("profile.web-review", None, "preview", "implemented"),
            ("output.assessment-reports", None, "preview", "implemented"),
            ("output.report-bundle", None, "preview", "implemented"),
            ("command.report-compare", None, "preview", "implemented"),
            ("command.report-verify", None, "preview", "implemented"),
            (
                "option.root-authorization-context",
                None,
                "preview",
                "implemented",
            ),
            ("option.defense-enforcement", None, "preview", "implemented"),
            (
                "command.artifact",
                Some("artifact-adapter"),
                "preview",
                "implemented",
            ),
            (
                "option.normalization-resilience",
                Some("normalization-resilience"),
                "preview",
                "implemented",
            ),
            (
                "option.graphql-review",
                Some("graphql-review"),
                "preview",
                "implemented",
            ),
            (
                "option.openapi-review",
                Some("openapi-review"),
                "preview",
                "implemented",
            ),
            (
                "option.rest-review",
                Some("rest-review"),
                "preview",
                "implemented",
            ),
            (
                "option.resource-authorization-review",
                Some("authorization-review"),
                "preview",
                "implemented",
            ),
            (
                "option.ssrf-oast-review",
                Some("ssrf-oast-review"),
                "preview",
                "implemented",
            ),
            (
                "command.legacy-scan",
                Some("legacy-scanner"),
                "legacy",
                "legacy_unmetered",
            ),
            (
                "command.api",
                Some("api-adapter"),
                "unsupported",
                "unsupported_stub",
            ),
            (
                "command.proxy",
                Some("proxy-adapter"),
                "experimental",
                "experimental_limited",
            ),
        ];
        assert_eq!(document.surfaces.len(), expected.len());
        for (surface, (key, feature, maturity, implementation)) in
            document.surfaces.iter().zip(expected)
        {
            assert_eq!(surface.key, key);
            assert_eq!(surface.compile_feature, feature);
            assert_eq!(surface.maturity.as_str(), maturity);
            assert_eq!(surface.implementation_status.as_str(), implementation);
        }

        let find = |key| {
            document
                .surfaces
                .iter()
                .find(|surface| surface.key == key)
                .unwrap()
        };
        let scan = find("command.scan");
        let alias = scan.alias.as_ref().unwrap();
        assert_eq!(alias.name, "decision-scan");
        assert_eq!(alias.command, "termivar decision-scan TARGET");
        assert_eq!(alias.maturity.as_str(), "deprecated");
        assert_eq!(alias.relation, "compatibility_alias_same_engine");

        assert_eq!(
            find("output.assessment-reports").prerequisites,
            [
                "a completed --profile web-review assessment",
                "optional --report-format <json|csv|html|markdown> overrides the default Markdown/JSON mapping",
                "--report-output FILE requires --report-format",
            ]
        );
        assert_eq!(
            find("option.rest-review").prerequisites,
            ["--profile web-review", "--openapi-review", "--rest-review"]
        );
        assert_eq!(
            find("option.root-authorization-context").prerequisites,
            [
                "--profile web-review",
                "one of --auth-env, --auth-file, or --auth-stdin",
                "exact origin-root target",
                "HTTPS, except numeric-loopback HTTP fixtures",
            ]
        );
        assert_eq!(
            find("option.resource-authorization-review").prerequisites,
            [
                "--profile web-review",
                "--authorization-review-policy FILE",
                "one primary source: --authz-primary-env, --authz-primary-file, or --authz-primary-stdin",
                "one peer source: --authz-peer-env, --authz-peer-file, or --authz-peer-stdin",
                "HTTPS, except numeric-loopback HTTP fixtures",
            ]
        );
    }

    #[test]
    fn declared_option_relationships_match_the_clap_grammar() {
        assert!(crate::Cli::try_parse_from([
            "termivar",
            "scan",
            "https://example.test",
            "--profile",
            "web-review",
        ])
        .is_ok());
        for invalid in [
            vec![
                "termivar",
                "scan",
                "https://example.test",
                "--report-output",
                "assessment.json",
            ],
            vec![
                "termivar",
                "scan",
                "https://example.test",
                "--profile",
                "web-review",
                "--report-dir",
                "bundle",
                "--report-format",
                "json",
            ],
            vec![
                "termivar",
                "scan",
                "https://example.test",
                "--profile",
                "web-review",
                "--auth-env",
                "PRIMARY",
                "--auth-file",
                "credential.txt",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(invalid).is_err());
        }

        #[cfg(feature = "rest-review")]
        assert!(crate::Cli::try_parse_from([
            "termivar",
            "scan",
            "https://example.test",
            "--profile",
            "web-review",
            "--rest-review",
        ])
        .is_err());

        #[cfg(feature = "authorization-review")]
        assert!(crate::Cli::try_parse_from([
            "termivar",
            "scan",
            "https://example.test",
            "--profile",
            "web-review",
            "--authz-primary-env",
            "PRIMARY",
        ])
        .is_err());
    }

    #[test]
    fn render_contains_no_host_or_runtime_metadata() {
        let json = String::from_utf8(render(&build_document(), CapabilitiesFormat::Json).unwrap())
            .unwrap();
        for forbidden in [
            "CARGO_FEATURE_",
            "target_triple",
            "rustc_version",
            "build_timestamp",
            "source_commit",
            "binary_hash",
            "127.0.0.1",
            "Authorization",
        ] {
            assert!(!json.contains(forbidden), "leaked {forbidden}");
        }
        assert!(json.contains(INVENTORY_NOTICE));
        assert!(json.contains(BUILD_ORIGIN_LIMITATION));
    }

    #[test]
    fn output_failure_is_typed_and_does_not_panic() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let error = run_with_writer(
            CapabilitiesArgs {
                format: CapabilitiesFormat::Json,
            },
            &mut FailingWriter,
        )
        .unwrap_err();
        assert_eq!(error, CapabilitiesError::OutputFailed);
        assert_eq!(
            error.to_string(),
            "capabilities inventory could not be written"
        );
    }

    #[test]
    fn partial_write_and_flush_failures_remain_typed() {
        struct PartialWriter {
            wrote_once: bool,
        }
        impl Write for PartialWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                if self.wrote_once {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "private detail"))
                } else {
                    self.wrote_once = true;
                    Ok(buffer.len().min(7))
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct FlushFailWriter;
        impl Write for FlushFailWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("private detail"))
            }
        }

        for mut writer in [
            Box::new(PartialWriter { wrote_once: false }) as Box<dyn Write>,
            Box::new(FlushFailWriter),
        ] {
            let error = run_with_writer(
                CapabilitiesArgs {
                    format: CapabilitiesFormat::Text,
                },
                &mut writer,
            )
            .unwrap_err();
            assert_eq!(error, CapabilitiesError::OutputFailed);
            assert!(!error.to_string().contains("private detail"));
        }
    }

    #[test]
    fn output_limit_rejects_a_document_above_64_kib() {
        assert_eq!(
            enforce_output_limit(vec![b'x'; MAX_CAPABILITIES_OUTPUT_BYTES + 1]).unwrap_err(),
            CapabilitiesError::OutputTooLarge
        );
        assert_eq!(
            enforce_output_limit(vec![b'x'; MAX_CAPABILITIES_OUTPUT_BYTES])
                .unwrap()
                .len(),
            MAX_CAPABILITIES_OUTPUT_BYTES
        );
    }

    #[test]
    fn unknown_options_and_extra_arguments_are_rejected_by_clap() {
        assert!(crate::Cli::try_parse_from(["termivar", "capabilities", "extra"]).is_err());
        assert!(
            crate::Cli::try_parse_from(["termivar", "capabilities", "--format", "yaml",]).is_err()
        );
        assert!(crate::Cli::try_parse_from(["termivar", "capabilities", "--target", "x"]).is_err());
    }
}
