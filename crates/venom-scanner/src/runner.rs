//! Scan pipeline orchestration with phase execution and finding aggregation
//!
//! The ScanRunner coordinates sequential execution of all 9 scanning phases,
//! manages error handling, and aggregates findings with timing metrics.

use crate::{context::ScanContext, Event, EventType, LogEntry, LogLevel, ScanFinding, ScanPhase};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Orchestrates multi-phase scanning pipeline
///
/// - Maintains phase registry in execution order
/// - Tracks timing for performance metrics
/// - Aggregates findings from all phases
/// - Handles phase-level errors gracefully
pub struct ScanRunner {
    phases: Vec<Box<dyn ScanPhase>>,
}

impl ScanRunner {
    /// Creates a new empty runner
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    /// Registers a phase for execution
    ///
    /// Automatically maintains phases in order by phase_number()
    pub fn register_phase(&mut self, phase: Box<dyn ScanPhase>) {
        self.phases.push(phase);
        // Sort by phase number to ensure proper execution order
        self.phases.sort_by_key(|p| p.phase_number());
    }

    /// Executes all registered phases sequentially
    ///
    /// # Process
    /// 1. For each phase (in order):
    ///    - Log phase start with structured logging
    ///    - Execute phase with timeout
    ///    - Log completion with timing metrics
    ///    - Aggregate findings
    /// 2. Return combined findings from all phases
    ///
    /// # Error Handling
    /// Phase errors are logged but don't halt pipeline. Returns partial results.
    pub async fn run_pipeline(&self, ctx: ScanContext) -> Vec<ScanFinding> {
        let mut all_findings = Vec::new();
        let ctx_arc = Arc::new(ctx);

        for phase in &self.phases {
            let phase_num = phase.phase_number();
            let phase_name = phase.name();
            let start = Instant::now();

            // Log structured phase start
            let start_entry = LogEntry::new(
                LogLevel::Info,
                format!("Starting Phase {}: {}", phase_num, phase_name),
            )
            .with_phase(phase_num);
            ctx_arc.logger.log(start_entry);
            ctx_arc.log(format!("[*] Phase {}: {}", phase_num, phase_name));

            // Publish PhaseStarted event for real-time dashboard updates
            let start_event =
                Event::builder(EventType::PhaseStarted, format!("Phase {}", phase_num))
                    .data("phase_number", phase_num.to_string())
                    .data("phase_name", phase_name.to_string())
                    .build();
            ctx_arc.event_bus.publish(start_event);

            // Execute phase with timeout + cancellation (CRITICAL: prevent hangs, allow graceful stop)
            let phase_timeout = Duration::from_secs(ctx_arc.phase_timeout_secs);
            let cancel_token = ctx_arc.cancel_token.clone();

            // Check if cancellation requested before starting phase
            if cancel_token.is_cancelled() {
                let elapsed = start.elapsed().as_millis() as u64;
                let cancel_entry = LogEntry::new(
                    LogLevel::Error,
                    format!("Scan cancelled before Phase {} started", phase_num),
                )
                .with_phase(phase_num)
                .with_duration(elapsed);
                ctx_arc.logger.log(cancel_entry);
                ctx_arc.log(format!("[!] Scan cancelled (Phase {} skipped)", phase_num));
                break; // Exit scan loop immediately
            }

            // Execute phase with both timeout and cancellation protection
            let result = tokio::select! {
                _ = cancel_token.cancelled() => {
                    // Cancellation signal received (CTRL+C, Dashboard cancel, cloud kill)
                    Err::<Vec<ScanFinding>, String>("cancelled".to_string())
                }
                result = timeout(phase_timeout, phase.execute(&ctx_arc)) => {
                    match result {
                        Ok(Ok(findings)) => Ok(findings),
                        Ok(Err(e)) => Err(format!("phase error: {}", e)),
                        Err(_) => Err("timeout".to_string()),
                    }
                }
            };

            match result {
                Ok(findings) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let finding_count = findings.len();

                    // Log structured completion
                    let complete_entry = LogEntry::new(
                        LogLevel::Info,
                        format!("Phase {} completed: {} findings", phase_num, finding_count),
                    )
                    .with_phase(phase_num)
                    .with_duration(elapsed);
                    ctx_arc.logger.log(complete_entry);
                    ctx_arc.log(format!(
                        "[+] Phase {} complete: {} findings in {}ms",
                        phase_num, finding_count, elapsed
                    ));

                    // Publish PhaseCompleted event for real-time dashboard updates
                    let complete_event =
                        Event::builder(EventType::PhaseCompleted, format!("Phase {}", phase_num))
                            .data("phase_number", phase_num.to_string())
                            .data("phase_name", phase_name.to_string())
                            .data("finding_count", finding_count.to_string())
                            .data("elapsed_ms", elapsed.to_string())
                            .build();
                    ctx_arc.event_bus.publish(complete_event);

                    all_findings.extend(findings);
                },
                Err(e) if e == "cancelled" => {
                    let elapsed = start.elapsed().as_millis() as u64;

                    // Log cancellation (graceful shutdown)
                    let cancel_entry = LogEntry::new(
                        LogLevel::Error,
                        format!("Phase {} cancelled by user", phase_num),
                    )
                    .with_phase(phase_num)
                    .with_duration(elapsed);
                    ctx_arc.logger.log(cancel_entry);
                    ctx_arc.log(format!("[!] Phase {} cancelled by user", phase_num));

                    // Publish PhaseFailed event for dashboard
                    let cancel_event =
                        Event::builder(EventType::PhaseFailed, format!("Phase {}", phase_num))
                            .data("phase_number", phase_num.to_string())
                            .data("phase_name", phase_name.to_string())
                            .data("reason", "cancelled")
                            .data("elapsed_ms", elapsed.to_string())
                            .build();
                    ctx_arc.event_bus.publish(cancel_event);

                    break; // Exit scan loop, return partial results
                },
                Err(e) if e == "timeout" => {
                    let elapsed = start.elapsed().as_millis() as u64;

                    // Log timeout (CRITICAL: phase exceeded timeout)
                    let timeout_entry = LogEntry::new(
                        LogLevel::Error,
                        format!(
                            "Phase {} timed out after {}s",
                            phase_num, ctx_arc.phase_timeout_secs
                        ),
                    )
                    .with_phase(phase_num)
                    .with_duration(elapsed);
                    ctx_arc.logger.log(timeout_entry);
                    ctx_arc.log(format!(
                        "[-] Phase {} timeout (exceeded {}s limit)",
                        phase_num, ctx_arc.phase_timeout_secs
                    ));

                    // Publish PhaseFailed event for dashboard
                    let timeout_event =
                        Event::builder(EventType::PhaseFailed, format!("Phase {}", phase_num))
                            .data("phase_number", phase_num.to_string())
                            .data("phase_name", phase_name.to_string())
                            .data("reason", "timeout")
                            .data("timeout_secs", ctx_arc.phase_timeout_secs.to_string())
                            .data("elapsed_ms", elapsed.to_string())
                            .build();
                    ctx_arc.event_bus.publish(timeout_event);
                },
                Err(e) => {
                    let elapsed = start.elapsed().as_millis() as u64;

                    // Log error with context
                    let error_entry = LogEntry::new(
                        LogLevel::Error,
                        format!("Phase {} failed: {}", phase_num, e),
                    )
                    .with_phase(phase_num)
                    .with_duration(elapsed);
                    ctx_arc.logger.log(error_entry);
                    ctx_arc.log(format!("[-] Phase {} error: {}", phase_num, e));

                    // Publish PhaseFailed event for dashboard
                    let error_event =
                        Event::builder(EventType::PhaseFailed, format!("Phase {}", phase_num))
                            .data("phase_number", phase_num.to_string())
                            .data("phase_name", phase_name.to_string())
                            .data("reason", "error")
                            .data("error", e.clone())
                            .data("elapsed_ms", elapsed.to_string())
                            .build();
                    ctx_arc.event_bus.publish(error_event);
                },
            }
        }

        all_findings
    }
}

impl Default for ScanRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_creation() {
        let runner = ScanRunner::new();
        assert_eq!(runner.phases.len(), 0);
    }

    #[test]
    fn test_runner_phase_sorting() {
        use crate::phases::{CrawlPhase, ReconPhase, SqliScanner};

        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(SqliScanner));
        runner.register_phase(Box::new(ReconPhase));
        runner.register_phase(Box::new(CrawlPhase));

        assert_eq!(runner.phases[0].phase_number(), 1);
        assert_eq!(runner.phases[1].phase_number(), 2);
        assert_eq!(runner.phases[2].phase_number(), 5);
    }
}
