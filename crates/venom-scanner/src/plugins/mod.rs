//! Vulnerability Scanner Plugins
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
