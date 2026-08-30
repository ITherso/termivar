//! Structured Logging System for VENOM Scanner
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `legacy-scanner`.
//! - **Execution:** historical scanner runtime support
//!   (`ScanRunner` emits `LogEntry` values).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Provides consistent, contextualized logging across all scanning phases
//! with performance metrics, timing information, and structured output.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Structured log entry with timestamp, level, and context
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Unix timestamp (milliseconds)
    pub timestamp: u64,
    /// Log severity level
    pub level: LogLevel,
    /// Associated phase number (1-10)
    pub phase: Option<u8>,
    /// Log message
    pub message: String,
    /// Optional context (URL, parameter, etc.)
    pub context: Option<String>,
    /// Elapsed time in milliseconds (for performance logs)
    pub duration_ms: Option<u64>,
}

impl LogEntry {
    /// Creates a new log entry
    pub fn new(level: LogLevel, message: String) -> Self {
        Self {
            timestamp: current_timestamp_ms(),
            level,
            phase: None,
            message,
            context: None,
            duration_ms: None,
        }
    }

    /// Adds phase information to log entry
    pub fn with_phase(mut self, phase: u8) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Adds context information to log entry
    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }

    /// Adds performance timing to log entry
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Formats log entry as a string
    pub fn format(&self) -> String {
        let mut output = format!("[{}] [{}]", self.timestamp, self.level);

        if let Some(phase) = self.phase {
            output.push_str(&format!(" [Phase {phase}]"));
        }

        output.push_str(&format!(" {}", self.message));

        if let Some(ctx) = &self.context {
            output.push_str(&format!(" | {ctx}"));
        }

        if let Some(duration) = self.duration_ms {
            output.push_str(&format!(" | {duration}ms"));
        }

        output
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// Logger for structured output
pub struct Logger {
    level: LogLevel,
}

impl Logger {
    /// Creates a new logger with specified minimum level
    pub fn new(level: LogLevel) -> Self {
        Self { level }
    }

    /// Logs a message if level permits
    pub fn log(&self, entry: LogEntry) {
        if entry.level >= self.level {
            println!("{}", entry.format());
        }
    }

    /// Logs debug message
    pub fn debug(&self, message: String) {
        self.log(LogEntry::new(LogLevel::Debug, message));
    }

    /// Logs info message
    pub fn info(&self, message: String) {
        self.log(LogEntry::new(LogLevel::Info, message));
    }

    /// Logs warning message
    pub fn warn(&self, message: String) {
        self.log(LogEntry::new(LogLevel::Warn, message));
    }

    /// Logs error message
    pub fn error(&self, message: String) {
        self.log(LogEntry::new(LogLevel::Error, message));
    }

    /// Logs phase execution with timing
    pub fn phase_start(&self, phase: u8, name: &str) {
        self.log(
            LogEntry::new(LogLevel::Info, format!("Starting Phase {phase}: {name}"))
                .with_phase(phase),
        );
    }

    /// Logs phase completion with timing
    pub fn phase_complete(&self, phase: u8, count: usize, duration_ms: u64) {
        self.log(
            LogEntry::new(
                LogLevel::Info,
                format!("Phase {phase} completed. Found {count} issues."),
            )
            .with_phase(phase)
            .with_duration(duration_ms),
        );
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new(LogLevel::Info)
    }
}

/// Returns current Unix timestamp in milliseconds
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "Test message".to_string());
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "Test message");
        assert!(entry.phase.is_none());
    }

    #[test]
    fn test_log_entry_with_context() {
        let entry = LogEntry::new(LogLevel::Warn, "Warning".to_string())
            .with_context("https://example.com".to_string());
        assert_eq!(entry.context, Some("https://example.com".to_string()));
    }

    #[test]
    fn test_log_entry_with_phase() {
        let entry = LogEntry::new(LogLevel::Debug, "Debug message".to_string()).with_phase(5);
        assert_eq!(entry.phase, Some(5));
    }

    #[test]
    fn test_log_entry_with_duration() {
        let entry = LogEntry::new(LogLevel::Info, "Completed".to_string()).with_duration(1234);
        assert_eq!(entry.duration_ms, Some(1234));
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
    }

    #[test]
    fn test_logger_filtering() {
        let logger = Logger::new(LogLevel::Warn);
        // Should not panic, just not log debug/info
        logger.debug("Debug message".to_string());
        logger.info("Info message".to_string());
        logger.warn("Warning message".to_string());
        logger.phase_start(3, "bounded review");
        logger.phase_complete(3, 2, 17);
    }
}
