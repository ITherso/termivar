//! Same-revision consumer of deterministic assessment and typed reporting.

#![forbid(unsafe_code)]

use url::Url;
use termivar_scanner::{
    web_runtime::{
        AssessmentRunReport, ScanProfileV1, WebAssessmentRuntime, WebAssessmentRuntimeError,
    },
    ReportError, ReportFormat, ReportGenerator,
};

/// Builds, but deliberately does not run, a bounded loopback assessment.
///
/// Constructing the runtime checks the profile-to-authority bridge without
/// dispatching any request. A caller must separately invoke `analyze` to do
/// network work; this fixture never does so.
pub fn build_web_review_runtime() -> Result<WebAssessmentRuntime, WebAssessmentRuntimeError> {
    let profile = ScanProfileV1::web_review().expect("the built-in profile is valid");
    let target =
        Url::parse("http://127.0.0.1:9/current-head").expect("the static loopback URL is valid");
    WebAssessmentRuntime::builder(target)
        .limits(profile.web_assessment_limits())
        .enable_low_risk_differential_review()
        .build()
}

/// Compiles the typed assessment renderer boundary without manufacturing a
/// report or bypassing runtime-owned completion truth.
pub fn render_completed_assessment(
    report: &AssessmentRunReport,
    format: ReportFormat,
) -> Result<String, ReportError> {
    ReportGenerator::generate_assessment(report, format)
}

#[cfg(test)]
mod tests {
    use termivar_scanner::web_runtime::SCAN_PROFILE_V1_SCHEMA;

    use super::*;

    #[test]
    fn profile_runtime_and_report_surfaces_compile_without_dispatch() {
        let profile = ScanProfileV1::web_review().unwrap();
        assert_eq!(profile.schema(), SCAN_PROFILE_V1_SCHEMA);
        assert!(profile.capabilities().origin_discovery());
        assert!(profile.capabilities().low_risk_differential_review());
        assert!(!profile.defense_enforcement_enabled());

        let runtime = build_web_review_runtime().unwrap();
        assert!(!runtime.has_started());
        assert_eq!(
            runtime
                .authorized_root()
                .url()
                .origin()
                .ascii_serialization(),
            "http://127.0.0.1:9"
        );

        let formats: Vec<_> = ReportGenerator::available_formats()
            .iter()
            .map(|format| format.as_str())
            .collect();
        assert_eq!(formats, ["json", "csv", "html", "markdown"]);
    }
}
