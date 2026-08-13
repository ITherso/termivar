//! Ordered scan phases for the historical `venom legacy-scan` pipeline.
//!
//! ## Runtime scope
//!
//! - **Build:** non-default `legacy-scanner` feature.
//! - **Execution:** Surface A — the mixed-authority ordered sequence composed
//!   for `venom legacy-scan`. Phases 2–4 use a bounded passive discovery
//!   authority and phases 5–9 use a separate bounded active-verification
//!   authority. Phase 1 and custom extensions may retain direct I/O, so the
//!   complete run remains outside `StandardWebDecisionRuntime` and reports
//!   `Unmetered` accounting.
//! - **Default `venom scan`:** no. Within `legacy-scan`, `DirectoryFuzzer` is
//!   conditional on `--legacy-directory-fuzz`.
//! - **Support:** legacy alpha.
//!
//! See `docs/internals/runtime-map.md`.

pub mod phase1_recon;
pub mod phase2_crawl;
pub mod phase3_fuzzer;
pub mod phase4_param;
pub mod phase5_sqli;
pub mod phase6_xss;
pub mod phase7_ssti;
pub mod phase8_lfi_xxe;
pub mod phase9_ssrf;

pub use phase1_recon::ReconPhase;
pub use phase2_crawl::CrawlPhase;
pub use phase3_fuzzer::DirectoryFuzzer;
pub use phase4_param::ParameterDiscoverer;
pub use phase5_sqli::SqliScanner;
pub use phase6_xss::XssScanner;
pub use phase7_ssti::SstiScanner;
pub use phase8_lfi_xxe::LfiXxeScanner;
pub use phase9_ssrf::SsrfScanner;
