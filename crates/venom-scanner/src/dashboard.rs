//! Dashboard Service & Visualization Layer
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Backend for web dashboard with real-time scan visualization,
//! findings explorer, and interactive reporting.

use serde::{Deserialize, Serialize};

/// Dashboard data model for scan overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardOverview {
    pub total_scans: u64,
    pub active_scans: u64,
    pub completed_scans: u64,
    pub failed_scans: u64,
    pub total_findings: u64,
    pub critical_findings: u64,
    pub high_findings: u64,
    pub scan_success_rate: f32,
    pub avg_scan_duration_mins: f32,
}

impl DashboardOverview {
    pub fn new() -> Self {
        Self {
            total_scans: 0,
            active_scans: 0,
            completed_scans: 0,
            failed_scans: 0,
            total_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            scan_success_rate: 0.0,
            avg_scan_duration_mins: 0.0,
        }
    }

    pub fn calculate_success_rate(&mut self) {
        if self.total_scans > 0 {
            self.scan_success_rate =
                (self.completed_scans as f32 / self.total_scans as f32) * 100.0;
        }
    }
}

impl Default for DashboardOverview {
    fn default() -> Self {
        Self::new()
    }
}

/// Timeline chart data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: u64,
    pub scans_completed: u64,
    pub findings_discovered: u64,
    pub critical_count: u64,
    pub high_count: u64,
}

/// Severity distribution for charts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
}

impl SeverityDistribution {
    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low
    }

    pub fn percentages(&self) -> SeverityDistribution {
        let total = self.total() as f32;
        if total == 0.0 {
            return SeverityDistribution {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            };
        }

        SeverityDistribution {
            critical: ((self.critical as f32 / total) * 100.0) as u64,
            high: ((self.high as f32 / total) * 100.0) as u64,
            medium: ((self.medium as f32 / total) * 100.0) as u64,
            low: ((self.low as f32 / total) * 100.0) as u64,
        }
    }
}

/// Finding card for findings explorer
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Finding status for tracking
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
    pub fn as_str(&self) -> &str {
        match self {
            FindingStatus::New => "new",
            FindingStatus::Review => "review",
            FindingStatus::Confirmed => "confirmed",
            FindingStatus::FalsePositive => "false_positive",
            FindingStatus::Resolved => "resolved",
        }
    }
}

/// Scan card for scan list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCard {
    pub scan_id: String,
    pub target: String,
    pub status: String,
    pub progress: f32,
    pub findings: u64,
    pub critical: u64,
    pub high: u64,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub duration_secs: Option<u64>,
}

/// Dashboard widget for key metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub id: String,
    pub title: String,
    pub widget_type: WidgetType,
    pub data: serde_json::Value,
    pub refresh_interval_secs: u32,
}

/// Widget types
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
    pub fn as_str(&self) -> &str {
        match self {
            WidgetType::Kpi => "kpi",
            WidgetType::Chart => "chart",
            WidgetType::Timeline => "timeline",
            WidgetType::Distribution => "distribution",
            WidgetType::Table => "table",
        }
    }
}

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub title: String,
    pub refresh_interval_secs: u32,
    pub widgets: Vec<String>,
    pub theme: String,
    pub timezone: String,
}

impl DashboardConfig {
    pub fn default_config() -> Self {
        Self {
            title: "VENOM Security Dashboard".to_string(),
            refresh_interval_secs: 5,
            widgets: vec![
                "overview".to_string(),
                "timeline".to_string(),
                "severity".to_string(),
                "recent_findings".to_string(),
            ],
            theme: "dark".to_string(),
            timezone: "UTC".to_string(),
        }
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Dashboard service
pub struct DashboardService {
    overview: DashboardOverview,
    timeline: Vec<TimelineEntry>,
    severity_dist: SeverityDistribution,
    recent_findings: Vec<FindingCard>,
    active_scans: Vec<ScanCard>,
}

impl DashboardService {
    pub fn new() -> Self {
        Self {
            overview: DashboardOverview::default(),
            timeline: Vec::new(),
            severity_dist: SeverityDistribution {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            },
            recent_findings: Vec::new(),
            active_scans: Vec::new(),
        }
    }

    pub fn update_overview(&mut self, overview: DashboardOverview) {
        self.overview = overview;
        self.overview.calculate_success_rate();
    }

    pub fn add_timeline_entry(&mut self, entry: TimelineEntry) {
        self.timeline.push(entry);
    }

    pub fn update_severity_distribution(&mut self, dist: SeverityDistribution) {
        self.severity_dist = dist;
    }

    pub fn add_finding(&mut self, finding: FindingCard) {
        self.recent_findings.push(finding);
        // Keep only last 100 findings
        if self.recent_findings.len() > 100 {
            self.recent_findings.remove(0);
        }
    }

    pub fn add_active_scan(&mut self, scan: ScanCard) {
        self.active_scans.push(scan);
    }

    pub fn remove_active_scan(&mut self, scan_id: &str) {
        self.active_scans.retain(|s| s.scan_id != scan_id);
    }

    pub fn get_overview(&self) -> DashboardOverview {
        self.overview.clone()
    }

    pub fn get_timeline(&self) -> Vec<TimelineEntry> {
        self.timeline.clone()
    }

    pub fn get_severity_distribution(&self) -> SeverityDistribution {
        self.severity_dist.clone()
    }

    pub fn get_recent_findings(&self, limit: usize) -> Vec<FindingCard> {
        self.recent_findings
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_active_scans(&self) -> Vec<ScanCard> {
        self.active_scans.clone()
    }
}

impl Default for DashboardService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_overview() {
        let overview = DashboardOverview::new();
        assert_eq!(overview.total_scans, 0);
        assert_eq!(overview.scan_success_rate, 0.0);
    }

    #[test]
    fn test_success_rate_calculation() {
        let mut overview = DashboardOverview::new();
        overview.total_scans = 10;
        overview.completed_scans = 8;
        overview.calculate_success_rate();

        assert_eq!(overview.scan_success_rate, 80.0);
    }

    #[test]
    fn test_severity_distribution() {
        let dist = SeverityDistribution {
            critical: 10,
            high: 20,
            medium: 30,
            low: 40,
        };

        assert_eq!(dist.total(), 100);
    }

    #[test]
    fn test_severity_percentages() {
        let dist = SeverityDistribution {
            critical: 25,
            high: 25,
            medium: 25,
            low: 25,
        };

        let percentages = dist.percentages();
        assert_eq!(percentages.critical, 25);
        assert_eq!(percentages.high, 25);
    }

    #[test]
    fn test_finding_status() {
        assert_eq!(FindingStatus::New.as_str(), "new");
        assert_eq!(FindingStatus::Confirmed.as_str(), "confirmed");
    }

    #[test]
    fn test_widget_type() {
        assert_eq!(WidgetType::Kpi.as_str(), "kpi");
        assert_eq!(WidgetType::Chart.as_str(), "chart");
    }

    #[test]
    fn test_dashboard_config() {
        let config = DashboardConfig::default();
        assert_eq!(config.refresh_interval_secs, 5);
        assert_eq!(config.widgets.len(), 4);
    }

    #[test]
    fn test_dashboard_service() {
        let mut service = DashboardService::new();
        let overview = DashboardOverview {
            total_scans: 5,
            active_scans: 1,
            completed_scans: 4,
            failed_scans: 0,
            total_findings: 50,
            critical_findings: 5,
            high_findings: 15,
            scan_success_rate: 80.0,
            avg_scan_duration_mins: 5.0,
        };

        service.update_overview(overview);
        assert_eq!(service.get_overview().total_scans, 5);
    }

    #[test]
    fn test_add_finding() {
        let mut service = DashboardService::new();
        let finding = FindingCard {
            finding_id: "f1".to_string(),
            scan_id: "s1".to_string(),
            phase: 5,
            module: "SQLi".to_string(),
            severity: "CRITICAL".to_string(),
            description: "Test finding".to_string(),
            discovered_at: 1000,
            status: FindingStatus::New,
        };

        service.add_finding(finding);
        assert_eq!(service.get_recent_findings(10).len(), 1);
    }

    #[test]
    fn test_scan_card() {
        let card = ScanCard {
            scan_id: "scan1".to_string(),
            target: "https://example.com".to_string(),
            status: "running".to_string(),
            progress: 50.0,
            findings: 10,
            critical: 2,
            high: 5,
            started_at: 1000,
            completed_at: None,
            duration_secs: None,
        };

        assert_eq!(card.progress, 50.0);
        assert_eq!(card.findings, 10);
    }

    #[test]
    fn test_active_scan_management() {
        let mut service = DashboardService::new();
        let scan = ScanCard {
            scan_id: "scan1".to_string(),
            target: "https://example.com".to_string(),
            status: "running".to_string(),
            progress: 50.0,
            findings: 0,
            critical: 0,
            high: 0,
            started_at: 1000,
            completed_at: None,
            duration_secs: None,
        };

        service.add_active_scan(scan);
        assert_eq!(service.get_active_scans().len(), 1);

        service.remove_active_scan("scan1");
        assert_eq!(service.get_active_scans().len(), 0);
    }
}
