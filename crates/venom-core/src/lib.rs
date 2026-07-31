//! Stable inward-facing contracts shared by Venom crates.
//!
//! `venom-core` contains transport-neutral data: configuration, events,
//! findings, errors, and request/response models. Execution behavior belongs
//! in higher-level crates.
//!
//! # Example
//!
//! ```rust
//! use venom_core::{Event, EventType, ScanFinding};
//!
//! let event = Event::builder(EventType::ScanStarted, "authorized scan").build();
//! let finding = ScanFinding {
//!     phase: 1,
//!     module_name: "example".to_string(),
//!     severity: "INFO".to_string(),
//!     description: "Contract example".to_string(),
//!     evidence: "https://example.test".to_string(),
//! };
//!
//! assert_eq!(event.event_type, EventType::ScanStarted);
//! assert_eq!(finding.phase, 1);
//! ```

#![deny(rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod error;
pub mod events;
pub mod models;

pub use config::{Config, ConfigBuilder, ConfigError, ScanIntensity};
pub use error::{Error, Result};
pub use events::{Event, EventBuilder, EventSeverity, EventType};
pub use models::{HttpRequest, HttpResponse, ScanFinding, ScanResult, Vulnerability};
