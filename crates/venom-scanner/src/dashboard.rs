//! Dashboard presentation records.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This module contains caller-supplied presentation records only. It does not
//! collect scan state, retain dashboard history, or run a dashboard service.

use serde::{Deserialize, Serialize};

/// Caller-supplied counts for a scan overview.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardOverview {
    pub total_scans: u64,
    pub active_scans: u64,
    pub completed_scans: u64,
    pub failed_scans: u64,
    pub total_findings: u64,
    pub critical_findings: u64,
    pub high_findings: u64,
    pub average_completed_scan_duration_secs: Option<u64>,
}

impl DashboardOverview {
    /// Returns `completed_scans / total_scans` only for a non-empty,
    /// internally consistent overview.
    ///
    /// `None` means that the denominator is zero, an addition overflowed, or
    /// the active, completed, and failed counts do not account for the stated
    /// total. A returned ratio is therefore always in the inclusive `0..=1`
    /// range.
    pub fn completion_ratio(&self) -> Option<f64> {
        let accounted_scans = self
            .active_scans
            .checked_add(self.completed_scans)?
            .checked_add(self.failed_scans)?;

        if self.total_scans == 0 || accounted_scans != self.total_scans {
            return None;
        }

        Some(self.completed_scans as f64 / self.total_scans as f64)
    }
}

/// Caller-supplied timeline data for a chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: u64,
    pub scans_completed: u64,
    pub findings_discovered: u64,
    pub critical_count: u64,
    pub high_count: u64,
}

/// Caller-supplied severity counts for a chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
}

impl SeverityDistribution {
    /// Returns the total when the supplied counts can be added without
    /// overflowing.
    pub fn checked_total(&self) -> Option<u64> {
        self.critical
            .checked_add(self.high)?
            .checked_add(self.medium)?
            .checked_add(self.low)
    }
}

/// Caller-supplied finding data for presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCard {
    pub finding_id: String,
    pub scan_id: String,
    pub phase: u8,
    pub module: String,
    pub severity: String,
    pub description: String,
    pub discovered_at: u64,
    pub status: FindingStatus,
}

/// Review status supplied for a finding card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    #[serde(rename = "new")]
    New,
    #[serde(rename = "review")]
    Review,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "false_positive")]
    FalsePositive,
    #[serde(rename = "resolved")]
    Resolved,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Review => "review",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::Resolved => "resolved",
        }
    }
}

/// Caller-supplied scan data for presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCard {
    pub scan_id: String,
    pub target: String,
    pub status: String,
    pub findings: u64,
    pub critical: u64,
    pub high: u64,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub duration_secs: Option<u64>,
}

/// Caller-supplied dashboard widget description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub id: String,
    pub title: String,
    pub widget_type: WidgetType,
    pub data: serde_json::Value,
    pub refresh_interval_secs: u32,
}

/// Widget presentation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WidgetType {
    #[serde(rename = "kpi")]
    Kpi,
    #[serde(rename = "chart")]
    Chart,
    #[serde(rename = "timeline")]
    Timeline,
    #[serde(rename = "distribution")]
    Distribution,
    #[serde(rename = "table")]
    Table,
}

impl WidgetType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kpi => "kpi",
            Self::Chart => "chart",
            Self::Timeline => "timeline",
            Self::Distribution => "distribution",
            Self::Table => "table",
        }
    }
}

/// Caller-supplied dashboard presentation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub title: String,
    pub refresh_interval_secs: u32,
    pub widgets: Vec<String>,
    pub theme: String,
    pub timezone: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overview() -> DashboardOverview {
        DashboardOverview {
            total_scans: 10,
            active_scans: 1,
            completed_scans: 8,
            failed_scans: 1,
            total_findings: 50,
            critical_findings: 5,
            high_findings: 15,
            average_completed_scan_duration_secs: Some(300),
        }
    }

    #[test]
    fn completion_ratio_is_bounded_for_consistent_counts() {
        let ratio = overview()
            .completion_ratio()
            .expect("counts are consistent");

        assert_eq!(ratio, 0.8);
        assert!((0.0..=1.0).contains(&ratio));
    }

    #[test]
    fn completion_ratio_rejects_empty_or_inconsistent_counts() {
        let mut supplied = overview();
        supplied.total_scans = 0;
        supplied.active_scans = 0;
        supplied.completed_scans = 0;
        supplied.failed_scans = 0;
        assert_eq!(supplied.completion_ratio(), None);

        supplied.total_scans = 3;
        supplied.completed_scans = 4;
        assert_eq!(supplied.completion_ratio(), None);
    }

    #[test]
    fn completion_ratio_rejects_count_overflow() {
        let supplied = DashboardOverview {
            total_scans: u64::MAX,
            active_scans: u64::MAX,
            completed_scans: 1,
            failed_scans: 0,
            total_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            average_completed_scan_duration_secs: None,
        };

        assert_eq!(supplied.completion_ratio(), None);
    }

    #[test]
    fn severity_total_is_checked() {
        let supplied = SeverityDistribution {
            critical: 10,
            high: 20,
            medium: 30,
            low: 40,
        };
        assert_eq!(supplied.checked_total(), Some(100));

        let overflowing = SeverityDistribution {
            critical: u64::MAX,
            high: 1,
            medium: 0,
            low: 0,
        };
        assert_eq!(overflowing.checked_total(), None);
    }

    #[test]
    fn presentation_enums_have_stable_labels() {
        assert_eq!(FindingStatus::FalsePositive.as_str(), "false_positive");
        assert_eq!(WidgetType::Distribution.as_str(), "distribution");
    }
}
