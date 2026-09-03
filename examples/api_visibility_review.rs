//! Review one authorized, host-paired API visibility observation.
//!
//! This example performs no network I/O. In a real integration, the host must
//! authenticate the producer, authorize both contexts, and establish that they
//! describe the same logical resource before constructing the comparison.

use std::error::Error;

use termivar_scanner::{
    ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityPairKind,
    ApiVisibilityResult, ApiVisibilityReviewQuery, ConfidenceScore, EntityId,
    StandardWebDecisionRuntime,
};
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    let target = Url::parse("https://example.test/api/accounts/42")?;
    let resource = EntityId::new("resource:account-42")?;

    // These are non-secret opaque handles selected by an authorized host. The
    // host has already compared the two response views and classified this
    // single visibility dimension; no raw values enter the runtime facade.
    let comparison = ApiVisibilityComparison::new(
        "comparison:account-42:anonymous-member:fields",
        ApiSurfaceKind::JsonHttp,
        ApiVisibilityPairKind::AuthorizationContext,
        ApiVisibilityResult::Different,
        ApiVisibilityDimension::Fields,
        "context:anonymous",
        "context:member",
        resource.as_str(),
    )?
    .with_observed_at_ms(1_800_000_000_000);
    let observation =
        comparison.to_observation("example.authorized-api-pairer", ConfidenceScore::MAX)?;

    let mut runtime = StandardWebDecisionRuntime::builder(target)
        .enable_api_reasoning()
        .build()?;
    let receipt = runtime.ingest_api_visibility(observation, &resource)?;
    let page = runtime.api_visibility_reviews(&resource, &ApiVisibilityReviewQuery::new(32)?)?;

    println!(
        "committed comparison={} evidence_write={:?} relation_write={:?}",
        receipt.commit().comparison_subject(),
        receipt.commit().evidence_write(),
        receipt.commit().relation_write(),
    );
    for review in page.reviews() {
        println!(
            "review resource={} comparison={} boundaries={}",
            review.resource_scope(),
            review.comparison_subject(),
            review.boundary_hypotheses().len(),
        );
    }

    Ok(())
}
