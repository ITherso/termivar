//! Vulnerability Scanner Plugins
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `plugins`.
//! - **Execution:** host/library only (concrete plugins built on the plugin boundary).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Modular plugin implementations for various vulnerability types.

pub mod lfi;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod xss;
pub mod xxe;

pub use lfi::LFIPlugin;
pub use sqli::SQLiPlugin;
pub use ssrf::SSRFPlugin;
pub use ssti::SSTIPlugin;
pub use xss::XSSPlugin;
pub use xxe::XXEPlugin;
