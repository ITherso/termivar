//! VENOM Core - Shared models, error types, configuration, and utilities
//!
//! Core module providing:
//! - Configuration management with builder pattern and validation
//! - Error types and result handling
//! - Shared models across all crates
//! - Environment variable overrides
//! - TOML/JSON serialization support

pub mod config;
pub mod error;
pub mod events;
pub mod models;

pub use config::{Config, ConfigBuilder, ConfigError, ScanIntensity};
pub use error::{Error, Result};
pub use events::{Event, EventBuilder, EventSeverity, EventType};
pub use models::{HttpRequest, HttpResponse, ScanFinding, ScanResult, Vulnerability};
