//! Pulse Core Engine
//!
//! Orchestrator + formatters + report builder.

pub mod analysis;
pub mod anomaly;
pub mod format;
pub mod merkle;
pub mod modules;
pub mod output;
pub mod render;
pub mod report;
pub mod sign;
pub mod snapshot;
pub mod timeline;
pub mod trust;
pub mod types;

pub use analysis::{build_analysis, AnalysisReport};
pub use anomaly::{build_baseline, check_anomalies, AnomalyReport, Baseline};
pub use format::{Format, JsonStyle};
pub use modules::attack_surface::AttackSurface;
pub use modules::hardening::HardeningReport;
pub use modules::vulnerabilities::VulnerabilityReport;
pub use output::Target;
pub use report::{build_full_report, FullReport};
pub use snapshot::{diff, DiffReport, Snapshot};
pub use timeline::{build_timeline, TimelineEvent, TimelineReport};
pub use trust::{build_trust_report, Signal, SignalState, TrustReport, TrustSummary};
pub use types::Confidence;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

pub fn banner() -> String {
    format!("pulse {} ({})", VERSION, pulse_platform::arch())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn banner_contains_version() {
        assert!(banner().contains(VERSION));
    }

    #[test]
    fn format_parses_text() {
        assert_eq!(Format::parse("text"), Some(Format::Text));
        assert_eq!(Format::parse("TXT"), Some(Format::Text));
    }

    #[test]
    fn format_parses_json() {
        assert_eq!(Format::parse("json"), Some(Format::Json));
    }

    #[test]
    fn format_parses_markdown() {
        assert_eq!(Format::parse("markdown"), Some(Format::Markdown));
        assert_eq!(Format::parse("md"), Some(Format::Markdown));
    }

    #[test]
    fn format_rejects_unknown() {
        assert_eq!(Format::parse("yaml"), None);
        assert_eq!(Format::parse("xml"), None);
    }
}
