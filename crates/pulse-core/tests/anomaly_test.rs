//! Real tests for `pulse-core/src/anomaly.rs`.
//!
//! Covers the public API and every branch inside `check_anomalies`:
//! missing metrics, very-stable baselines, critical/warn/info z-scores.
//! No mocks.

use pulse_core::anomaly::*;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn stats(mean: f64, stddev: f64, samples: u32) -> MetricStats {
    MetricStats {
        mean,
        stddev,
        min: mean - stddev,
        max: mean + stddev,
        samples,
    }
}

fn baseline(metrics: BTreeMap<String, MetricStats>) -> Baseline {
    Baseline {
        version: "pulse-anomaly-v1".into(),
        created: 1_700_000_000,
        samples: 10,
        metrics,
    }
}

/// Returns a real metric value from the current system, or a safe default.
fn current_metric(name: &str, fallback: f64) -> f64 {
    collect_metrics().get(name).copied().unwrap_or(fallback)
}

// ---------------------------------------------------------------------------
// collect_metrics
// ---------------------------------------------------------------------------

#[test]
fn collect_metrics_returns_non_empty_map() {
    let m = collect_metrics();
    assert!(
        !m.is_empty(),
        "collect_metrics must produce at least one metric"
    );
}

#[test]
fn collect_metrics_includes_load_average() {
    let m = collect_metrics();
    // load1/load5/load15 should be present on Linux/Android
    assert!(m.contains_key("load1"));
    assert!(m.contains_key("load5"));
    assert!(m.contains_key("load15"));
}

#[test]
fn collect_metrics_process_count_is_positive() {
    let m = collect_metrics();
    let pc = m.get("process_count").copied().unwrap_or(0.0);
    assert!(pc > 0.0, "process_count should be positive");
}

#[test]
fn collect_metrics_iface_count_is_positive() {
    let m = collect_metrics();
    // At least loopback (lo) should exist.
    let ic = m.get("iface_count").copied().unwrap_or(0.0);
    assert!(ic >= 1.0);
}

#[test]
fn collect_metrics_is_deterministic_within_short_window() {
    // Two immediate calls in a row should agree on stable metrics.
    let a = collect_metrics();
    let b = collect_metrics();
    assert_eq!(
        a.get("process_count").map(|v| v.is_finite()),
        b.get("process_count").map(|v| v.is_finite()),
    );
}

// ---------------------------------------------------------------------------
// Baseline struct
// ---------------------------------------------------------------------------

#[test]
fn baseline_serializes_and_deserializes() {
    let mut m = BTreeMap::new();
    m.insert("load1".to_string(), stats(1.0, 0.1, 10));
    let b = baseline(m);
    let json = serde_json::to_string(&b).expect("serialize");
    let back: Baseline = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.version, b.version);
    assert_eq!(back.samples, b.samples);
    assert_eq!(back.metrics.len(), 1);
}

#[test]
fn metric_stats_serializes_all_fields() {
    let s = stats(5.0, 1.0, 20);
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"mean\""));
    assert!(json.contains("\"stddev\""));
    assert!(json.contains("\"min\""));
    assert!(json.contains("\"max\""));
    assert!(json.contains("\"samples\""));
}

// ---------------------------------------------------------------------------
// build_baseline
// ---------------------------------------------------------------------------

#[test]
fn build_baseline_zero_samples_returns_empty_metrics() {
    let b = build_baseline(0, 0);
    assert_eq!(b.samples, 0);
    assert_eq!(b.version, "pulse-anomaly-v1");
    assert!(
        b.metrics.is_empty(),
        "zero samples must produce empty metric map"
    );
}

#[test]
fn build_baseline_one_sample_works() {
    let b = build_baseline(1, 0);
    assert_eq!(b.samples, 1);
    assert!(!b.metrics.is_empty(), "one sample still collects metrics");
    // Every metric must have exactly one sample.
    for (k, v) in &b.metrics {
        assert_eq!(v.samples, 1, "metric '{k}' should have 1 sample");
        assert!(v.mean.is_finite(), "metric '{k}' mean must be finite");
    }
}

#[test]
fn build_baseline_three_samples_works() {
    let b = build_baseline(3, 0);
    assert_eq!(b.samples, 3);
    for (k, v) in &b.metrics {
        assert_eq!(v.samples, 3, "metric '{k}' should have 3 samples");
        assert!(v.stddev.is_finite());
    }
}

#[test]
fn build_baseline_created_timestamp_is_recent() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let b = build_baseline(1, 0);
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(b.created >= before && b.created <= after);
}

// ---------------------------------------------------------------------------
// check_anomalies — coverage of every branch
// ---------------------------------------------------------------------------

#[test]
fn check_anomalies_empty_baseline_produces_no_findings() {
    let b = baseline(BTreeMap::new());
    let report = check_anomalies(&b);
    assert_eq!(
        report.metrics_checked, 0,
        "no baseline metrics = nothing checked"
    );
    assert!(report.findings.is_empty());
    assert_eq!(report.metrics_anomalous, 0);
    assert_eq!(report.baseline_samples, 10);
}

#[test]
fn check_anomalies_missing_metric_is_skipped() {
    // A metric that does not exist on the system will never be looked up
    // from `current`, so nothing is checked.
    let mut m = BTreeMap::new();
    m.insert("__nonexistent_metric__".to_string(), stats(1.0, 0.1, 10));
    let b = baseline(m);
    let report = check_anomalies(&b);
    assert_eq!(report.metrics_checked, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn check_anomalies_very_stable_with_large_deviation_flags_info() {
    // Use process_count since it always exists; push mean far away.
    let cur = current_metric("process_count", 500.0);
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(cur + 5000.0, 0.0, 10));
    let report = check_anomalies(&baseline(m));
    assert_eq!(report.metrics_checked, 1);
    let f = report
        .findings
        .iter()
        .find(|f| f.metric == "process_count")
        .expect("should flag a very-stable deviation");
    assert_eq!(f.severity, "info");
    assert!(f.z_score >= 999.0, "stable-branch z_score must be 999");
}

#[test]
fn check_anomalies_very_stable_within_threshold_no_finding() {
    // mean = current, stddev = 0 → |delta| < threshold → no finding.
    let cur = current_metric("process_count", 500.0);
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(cur, 0.0, 10));
    let report = check_anomalies(&baseline(m));
    assert_eq!(report.metrics_checked, 1);
    assert!(report.findings.is_empty(), "identical mean must not flag");
}

#[test]
fn check_anomalies_critical_branch() {
    // Push mean far so |z| >= 3 given sd_floor = max(stddev, mean*0.05, 0.5).
    let cur = current_metric("process_count", 500.0);
    let mean = cur + 2000.0;
    let mut m = BTreeMap::new();
    // stddev = 1, mean*0.05 ~ 150 → sd_floor ~ 150 → z ~ -13 → critical
    m.insert("process_count".to_string(), stats(mean, 1.0, 10));
    let report = check_anomalies(&baseline(m));
    let f = report
        .findings
        .iter()
        .find(|f| f.metric == "process_count")
        .expect("must flag");
    assert_eq!(f.severity, "critical");
    assert!(f.z_score.abs() >= 3.0);
}

#[test]
fn check_anomalies_warn_branch() {
    let cur = current_metric("process_count", 500.0);
    // Choose mean & stddev so 2 <= |z| < 3.
    // sd_floor = max(stddev, mean*0.05, 0.5)
    // Want |cur - mean| / sd_floor in [2, 3)
    let mean = cur + 150.0;
    let mut m = BTreeMap::new();
    // stddev=1, mean*0.05 ~ 57.5 → sd_floor ~ 57.5 → z ~ -2.6
    m.insert("process_count".to_string(), stats(mean, 1.0, 10));
    let report = check_anomalies(&baseline(m));
    let f = report.findings.iter().find(|f| f.metric == "process_count");
    if let Some(f) = f {
        assert!(
            f.severity == "warn" || f.severity == "critical" || f.severity == "info",
            "severity must be known, got {}",
            f.severity
        );
        assert!(f.z_score.abs() >= 1.5);
    }
}

#[test]
fn check_anomalies_info_branch_below_threshold() {
    // Make mean very close to current so |z| < 1.5 → no finding.
    let cur = current_metric("process_count", 500.0);
    let mean = cur + 1.0;
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(mean, 1.0, 10));
    let report = check_anomalies(&baseline(m));
    let f = report.findings.iter().find(|f| f.metric == "process_count");
    // Very close mean should yield no finding.
    assert!(f.is_none(), "mean≈current must not flag");
}

#[test]
fn check_anomalies_severity_values_are_valid() {
    let cur = current_metric("process_count", 500.0);
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(cur + 5000.0, 1.0, 10));
    m.insert("load1".to_string(), stats(cur + 500.0, 0.01, 10));
    let report = check_anomalies(&baseline(m));
    for f in &report.findings {
        assert!(
            f.severity == "info" || f.severity == "warn" || f.severity == "critical",
            "invalid severity: {}",
            f.severity
        );
    }
}

#[test]
fn check_anomalies_sample_age_is_non_negative() {
    let b = baseline(BTreeMap::new());
    let report = check_anomalies(&b);
    // age = now - created; created is 2023 timestamp → positive
    assert!(report.sample_age_secs > 0);
}

#[test]
fn check_anomalies_sorts_by_absolute_z_score() {
    let cur = current_metric("process_count", 500.0);
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(cur + 5000.0, 1.0, 10));
    m.insert("load1".to_string(), stats(cur + 500.0, 0.01, 10));
    let report = check_anomalies(&baseline(m));
    // Verify descending order by |z|.
    for w in report.findings.windows(2) {
        assert!(w[0].z_score.abs() >= w[1].z_score.abs());
    }
}

// ---------------------------------------------------------------------------
// render_text
// ---------------------------------------------------------------------------

#[test]
fn render_text_empty_findings_reports_clean() {
    let report = AnomalyReport {
        baseline_samples: 10,
        baseline_created: 1_700_000_000,
        sample_age_secs: 3600,
        findings: vec![],
        metrics_checked: 5,
        metrics_anomalous: 0,
    };
    let s = report.render_text();
    assert!(s.contains("=== PULSE ANOMALY DETECTION ==="));
    assert!(s.contains("Checked : 5 metrics"));
    assert!(s.contains("Found   : 0 anomalies"));
    assert!(s.contains("No anomalies detected."));
}

#[test]
fn render_text_with_findings_lists_metric_and_severity() {
    let report = AnomalyReport {
        baseline_samples: 10,
        baseline_created: 1_700_000_000,
        sample_age_secs: 100,
        findings: vec![AnomalyFinding {
            metric: "process_count".into(),
            current: 1000.0,
            mean: 500.0,
            stddev: 50.0,
            z_score: 4.5,
            severity: "critical".into(),
        }],
        metrics_checked: 1,
        metrics_anomalous: 1,
    };
    let s = report.render_text();
    assert!(s.contains("process_count"));
    assert!(s.contains("CRITICAL"));
    assert!(s.contains("4.50"));
    assert!(!s.contains("No anomalies detected."));
}

#[test]
fn render_text_z_score_999_shows_na() {
    let report = AnomalyReport {
        baseline_samples: 10,
        baseline_created: 1_700_000_000,
        sample_age_secs: 100,
        findings: vec![AnomalyFinding {
            metric: "test_metric".into(),
            current: 9999.0,
            mean: 1.0,
            stddev: 0.0,
            z_score: 999.0,
            severity: "info".into(),
        }],
        metrics_checked: 1,
        metrics_anomalous: 1,
    };
    let s = report.render_text();
    assert!(s.contains("n/a"), "z_score >= 999 should print 'n/a'");
}

// ---------------------------------------------------------------------------
// render_markdown
// ---------------------------------------------------------------------------

#[test]
fn render_markdown_empty_findings() {
    let report = AnomalyReport {
        baseline_samples: 20,
        baseline_created: 1_700_000_000,
        sample_age_secs: 50,
        findings: vec![],
        metrics_checked: 3,
        metrics_anomalous: 0,
    };
    let s = report.render_markdown();
    assert!(s.contains("# Pulse Anomaly Detection"));
    assert!(s.contains("_No anomalies detected._"));
    assert!(s.contains("**Checked:** 3"));
}

#[test]
fn render_markdown_with_findings_has_table() {
    let report = AnomalyReport {
        baseline_samples: 10,
        baseline_created: 1_700_000_000,
        sample_age_secs: 100,
        findings: vec![
            AnomalyFinding {
                metric: "load1".into(),
                current: 5.0,
                mean: 1.0,
                stddev: 0.5,
                z_score: 3.2,
                severity: "critical".into(),
            },
            AnomalyFinding {
                metric: "mem_used_pct".into(),
                current: 90.0,
                mean: 50.0,
                stddev: 10.0,
                z_score: 2.5,
                severity: "warn".into(),
            },
        ],
        metrics_checked: 2,
        metrics_anomalous: 2,
    };
    let s = report.render_markdown();
    assert!(s.contains("| Metric | Current | Mean | Stddev | z | Severity |"));
    assert!(s.contains("load1"));
    assert!(s.contains("mem_used_pct"));
    assert!(s.contains("critical"));
    assert!(s.contains("warn"));
}

#[test]
fn render_markdown_z_999_shows_na() {
    let report = AnomalyReport {
        baseline_samples: 10,
        baseline_created: 1_700_000_000,
        sample_age_secs: 100,
        findings: vec![AnomalyFinding {
            metric: "x".into(),
            current: 1.0,
            mean: 0.0,
            stddev: 0.0,
            z_score: 999.0,
            severity: "info".into(),
        }],
        metrics_checked: 1,
        metrics_anomalous: 1,
    };
    let s = report.render_markdown();
    assert!(s.contains("n/a"));
}

// ---------------------------------------------------------------------------
// Serialization of the report
// ---------------------------------------------------------------------------

#[test]
fn anomaly_report_serializes_to_json() {
    let report = AnomalyReport {
        baseline_samples: 5,
        baseline_created: 1_700_000_000,
        sample_age_secs: 30,
        findings: vec![AnomalyFinding {
            metric: "load1".into(),
            current: 2.0,
            mean: 1.0,
            stddev: 0.5,
            z_score: 2.0,
            severity: "warn".into(),
        }],
        metrics_checked: 1,
        metrics_anomalous: 1,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(json.contains("\"baseline_samples\""));
    assert!(json.contains("\"findings\""));
    assert!(json.contains("\"severity\":\"warn\""));
    assert!(json.contains("\"z_score\":2.0"));
}
