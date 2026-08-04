//! Vulnerability Scanner Plugins
//!
//! Modular plugin implementations for various vulnerability types.
//!
//! # Runtime scope
//!
//! These built-in plugin modules are part of the **platform-shell** boundary in
//! Runtime Consolidation 5.5. They are feature-gated (`plugins`) and are not
//! part of the default `venom scan` runtime path.

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
