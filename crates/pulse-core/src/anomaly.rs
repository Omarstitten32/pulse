//! Anomaly detection via statistical baseline.
//! Build a baseline of N samples, then compare current state.

use pulse_platform::{CpuInfo, MemoryInfo, ThermalInfo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;

// ---------------------------------------------------------
// Baseline structure
// ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStats {
    pub mean: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
    pub samples: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub created: u64,
    pub samples: u32,
    pub metrics: BTreeMap<String, MetricStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyFinding {
    pub metric: String,
    pub current: f64,
    pub mean: f64,
    pub stddev: f64,
    pub z_score: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyReport {
    pub baseline_samples: u32,
    pub baseline_created: u64,
    pub sample_age_secs: u64,
    pub findings: Vec<AnomalyFinding>,
    pub metrics_checked: u32,
    pub metrics_anomalous: u32,
}

// ---------------------------------------------------------
// Metrics collection
// ---------------------------------------------------------

pub(crate) fn parse_loadavg(content: &str) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return m;
    }
    if let Ok(v) = parts[0].parse::<f64>() {
        m.insert("load1".into(), v);
    }
    if let Ok(v) = parts[1].parse::<f64>() {
        m.insert("load5".into(), v);
    }
    if let Ok(v) = parts[2].parse::<f64>() {
        m.insert("load15".into(), v);
    }
    m
}

pub(crate) fn metrics_from_memory(mem: &MemoryInfo) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    if mem.total_kb > 0 {
        let used_pct = 100.0 * (1.0 - mem.available_kb as f64 / mem.total_kb as f64);
        m.insert("mem_used_pct".into(), used_pct);
    }
    if mem.swap_total_kb > 0 {
        let swap_pct = 100.0 * (1.0 - mem.swap_free_kb as f64 / mem.swap_total_kb as f64);
        m.insert("swap_used_pct".into(), swap_pct);
    }
    m
}

pub fn collect_metrics() -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();

    if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
        for (k, v) in parse_loadavg(&content) {
            m.insert(k, v);
        }
    }

    if let Ok(mem) = metrics_memory() {
        for (k, v) in metrics_from_memory(&mem) {
            m.insert(k, v);
        }
    }

    // Processes
    if let Ok(pinfo) = pulse_platform::process_info() {
        m.insert("process_count".into(), pinfo.total as f64);
        let rss_mb: f64 = pinfo
            .processes
            .iter()
            .map(|p| p.rss_pages as f64 * 4.0 / 1024.0)
            .sum();
        m.insert("total_rss_mb".into(), rss_mb);
    }

    // CPU frequency
    if let Ok(cpu) = pulse_platform::cpu_info() {
        let freqs: Vec<f64> = cpu
            .per_core
            .iter()
            .filter_map(|c| c.cur_freq_khz.map(|f| f as f64 / 1_000_000.0))
            .collect();
        if !freqs.is_empty() {
            let avg: f64 = freqs.iter().sum::<f64>() / freqs.len() as f64;
            let max = freqs.iter().cloned().fold(0.0f64, f64::max);
            m.insert("cpu_freq_avg_ghz".into(), avg);
            m.insert("cpu_freq_max_ghz".into(), max);
        }
    }

    // Thermal
    if let Ok(thermal) = pulse_platform::thermal_info() {
        if let Some(hottest) = thermal.zones.first() {
            m.insert("hottest_temp_c".into(), hottest.temp_celsius);
        }
    }

    // Network interfaces
    if let Ok(net) = pulse_platform::network_info() {
        m.insert("iface_count".into(), net.interfaces.len() as f64);
    }

    // Kernel modules
    if let Ok(drv) = pulse_platform::drivers_info() {
        m.insert("module_count".into(), drv.total as f64);
    }

    m
}

fn stats_from(values: &[f64]) -> MetricStats {
    let n = values.len() as f64;
    if values.is_empty() {
        return MetricStats {
            mean: 0.0,
            stddev: 0.0,
            min: 0.0,
            max: 0.0,
            samples: 0,
        };
    }
    let mean = values.iter().sum::<f64>() / n;
    let variance = if values.len() > 1 {
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let stddev = variance.sqrt();
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    MetricStats {
        mean,
        stddev,
        min,
        max,
        samples: values.len() as u32,
    }
}

pub fn build_baseline(sample_count: u32, delay_ms: u64) -> Baseline {
    let mut all_metrics: BTreeMap<String, Vec<f64>> = BTreeMap::new();

    for i in 0..sample_count {
        let snapshot = collect_metrics();
        for (k, v) in snapshot {
            all_metrics.entry(k).or_default().push(v);
        }
        if i + 1 < sample_count {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let metrics: BTreeMap<String, MetricStats> = all_metrics
        .into_iter()
        .map(|(k, v)| (k, stats_from(&v)))
        .collect();

    Baseline {
        version: "pulse-anomaly-v1".into(),
        created,
        samples: sample_count,
        metrics,
    }
}

pub fn check_anomalies(baseline: &Baseline) -> AnomalyReport {
    let current = collect_metrics();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut findings = Vec::new();
    let mut checked = 0u32;

    for (key, &cur_val) in &current {
        let Some(stats) = baseline.metrics.get(key) else {
            continue;
        };
        checked += 1;

        if stats.stddev <= 1e-9 {
            // Very stable metric — any deviation > 5% of mean is notable
            let threshold = (stats.mean.abs() * 0.05).max(0.5);
            if (cur_val - stats.mean).abs() > threshold {
                findings.push(AnomalyFinding {
                    metric: key.clone(),
                    current: cur_val,
                    mean: stats.mean,
                    stddev: stats.stddev,
                    z_score: 999.0,
                    severity: "info".into(),
                });
            }
            continue;
        }

        // Prevent false positives from tiny stddev:
        // Use a floor of 5% of |mean| (or 0.5 absolute minimum)
        let sd_floor = stats.stddev.max(stats.mean.abs() * 0.05).max(0.5);
        let z = (cur_val - stats.mean) / sd_floor;
        let az = z.abs();
        if az >= 3.0 {
            findings.push(AnomalyFinding {
                metric: key.clone(),
                current: cur_val,
                mean: stats.mean,
                stddev: stats.stddev,
                z_score: z,
                severity: "critical".into(),
            });
        } else if az >= 2.0 {
            findings.push(AnomalyFinding {
                metric: key.clone(),
                current: cur_val,
                mean: stats.mean,
                stddev: stats.stddev,
                z_score: z,
                severity: "warn".into(),
            });
        } else if az >= 1.5 {
            findings.push(AnomalyFinding {
                metric: key.clone(),
                current: cur_val,
                mean: stats.mean,
                stddev: stats.stddev,
                z_score: z,
                severity: "info".into(),
            });
        }
    }

    findings.sort_by(|a, b| {
        b.z_score
            .abs()
            .partial_cmp(&a.z_score.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let anomalous = findings.len() as u32;

    AnomalyReport {
        baseline_samples: baseline.samples,
        baseline_created: baseline.created,
        sample_age_secs: now.saturating_sub(baseline.created),
        findings,
        metrics_checked: checked,
        metrics_anomalous: anomalous,
    }
}

impl AnomalyReport {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "=== PULSE ANOMALY DETECTION ===");
        s.push('\n');
        let _ = writeln!(
            s,
            "Baseline: {} samples, {}s old",
            self.baseline_samples, self.sample_age_secs
        );
        let _ = writeln!(s, "Checked : {} metrics", self.metrics_checked);
        let _ = writeln!(s, "Found   : {} anomalies", self.metrics_anomalous);
        s.push('\n');

        if self.findings.is_empty() {
            s.push_str("No anomalies detected.\n");
            return s;
        }

        let _ = writeln!(
            s,
            "{:<22} {:>12} {:>12} {:>8}  severity",
            "metric", "current", "baseline", "z-score"
        );
        for f in &self.findings {
            let z_str = if f.z_score >= 999.0 {
                "n/a".to_string()
            } else {
                format!("{:.2}", f.z_score)
            };
            let _ = writeln!(
                s,
                "{:<22} {:>12.2} {:>12.2} {:>8}  {}",
                f.metric,
                f.current,
                f.mean,
                z_str,
                f.severity.to_uppercase()
            );
        }
        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Pulse Anomaly Detection\n\n");
        let _ = writeln!(
            s,
            "- **Baseline:** {} samples, {} seconds old",
            self.baseline_samples, self.sample_age_secs
        );
        let _ = writeln!(s, "- **Checked:** {} metrics", self.metrics_checked);
        let _ = writeln!(s, "- **Anomalies:** {}\n", self.metrics_anomalous);

        if self.findings.is_empty() {
            s.push_str("_No anomalies detected._\n");
            return s;
        }

        s.push_str("| Metric | Current | Mean | Stddev | z | Severity |\n");
        s.push_str("|--------|---------|------|--------|---|----------|\n");
        for f in &self.findings {
            let z_str = if f.z_score >= 999.0 {
                "n/a".to_string()
            } else {
                format!("{:.2}", f.z_score)
            };
            let _ = writeln!(
                s,
                "| `{}` | {:.2} | {:.2} | {:.2} | {} | {} |",
                f.metric, f.current, f.mean, f.stddev, z_str, f.severity
            );
        }
        s
    }
}

// Helper to avoid cyclic import with platform
pub(crate) fn metrics_memory() -> Result<MemoryInfo, pulse_platform::PlatformError> {
    pulse_platform::memory_info()
}
// Silence unused import warnings when features not used
#[allow(dead_code)]
fn _unused(_: &CpuInfo, _: &ThermalInfo) {}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn stats_from_empty_slice() {
        let s = stats_from(&[]);
        assert_eq!(s.samples, 0);
        assert_eq!(s.mean, 0.0);
        assert_eq!(s.stddev, 0.0);
        assert_eq!(s.min, 0.0);
        assert_eq!(s.max, 0.0);
    }

    #[test]
    fn stats_from_single_value() {
        let s = stats_from(&[42.0]);
        assert_eq!(s.samples, 1);
        assert_eq!(s.mean, 42.0);
        assert_eq!(s.stddev, 0.0);
        assert_eq!(s.min, 42.0);
        assert_eq!(s.max, 42.0);
    }

    #[test]
    fn stats_from_two_values() {
        let s = stats_from(&[10.0, 20.0]);
        assert_eq!(s.samples, 2);
        assert!((s.mean - 15.0).abs() < 1e-9);
        // variance = ((10-15)^2 + (20-15)^2) / (2-1) = 50 → stddev = ~7.07
        assert!((s.stddev - (50.0_f64).sqrt()).abs() < 1e-9);
        assert_eq!(s.min, 10.0);
        assert_eq!(s.max, 20.0);
    }

    #[test]
    fn stats_from_three_values() {
        let s = stats_from(&[1.0, 2.0, 3.0]);
        assert_eq!(s.samples, 3);
        assert!((s.mean - 2.0).abs() < 1e-9);
        // variance = (1 + 0 + 1) / 2 = 1 → stddev = 1
        assert!((s.stddev - 1.0).abs() < 1e-9);
    }

    #[test]
    fn stats_from_identical_values_zero_stddev() {
        let s = stats_from(&[5.0, 5.0, 5.0, 5.0]);
        assert_eq!(s.mean, 5.0);
        assert!(s.stddev < 1e-9);
        assert_eq!(s.min, 5.0);
        assert_eq!(s.max, 5.0);
    }

    #[test]
    fn stats_from_negative_values() {
        let s = stats_from(&[-10.0, -20.0, -30.0]);
        assert!((s.mean - (-20.0)).abs() < 1e-9);
        assert_eq!(s.min, -30.0);
        assert_eq!(s.max, -10.0);
    }

    #[test]
    fn stats_from_mixed_sign_values() {
        let s = stats_from(&[-5.0, 0.0, 5.0]);
        assert!((s.mean - 0.0).abs() < 1e-9);
        assert_eq!(s.min, -5.0);
        assert_eq!(s.max, 5.0);
    }

    #[test]
    fn stats_from_large_numbers() {
        let s = stats_from(&[1_000_000.0, 2_000_000.0]);
        assert!((s.mean - 1_500_000.0).abs() < 1e-6);
        assert!(s.stddev > 0.0);
    }
}

#[cfg(test)]
mod refactor_tests {
    use super::*;

    #[test]
    fn parse_loadavg_full_line() {
        let c = "1.25 0.85 0.75 3/500 12345\n";
        let m = parse_loadavg(c);
        assert_eq!(m.get("load1"), Some(&1.25));
        assert_eq!(m.get("load5"), Some(&0.85));
        assert_eq!(m.get("load15"), Some(&0.75));
    }

    #[test]
    fn parse_loadavg_short_line_returns_empty() {
        let m = parse_loadavg("1.25 0.85\n");
        assert!(m.is_empty());
    }

    #[test]
    fn parse_loadavg_empty() {
        assert!(parse_loadavg("").is_empty());
    }

    #[test]
    fn parse_loadavg_ignores_non_numeric() {
        let c = "abc def ghi 1/1 1\n";
        assert!(parse_loadavg(c).is_empty());
    }

    #[test]
    fn parse_loadavg_partial_numeric() {
        let c = "1.5 abc 2.5 1/1 1\n";
        let m = parse_loadavg(c);
        assert_eq!(m.get("load1"), Some(&1.5));
        assert!(!m.contains_key("load5"));
        assert_eq!(m.get("load15"), Some(&2.5));
    }

    #[test]
    fn metrics_from_memory_full() {
        let mem = MemoryInfo {
            total_kb: 1000,
            free_kb: 500,
            available_kb: 400,
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 2000,
            swap_free_kb: 1500,
        };
        let m = metrics_from_memory(&mem);
        assert_eq!(m.get("mem_used_pct"), Some(&60.0));
        assert_eq!(m.get("swap_used_pct"), Some(&25.0));
    }

    #[test]
    fn metrics_from_memory_zero_total_skips_mem_pct() {
        let mem = MemoryInfo {
            total_kb: 0,
            free_kb: 0,
            available_kb: 0,
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 0,
            swap_free_kb: 0,
        };
        let m = metrics_from_memory(&mem);
        assert!(!m.contains_key("mem_used_pct"));
        assert!(!m.contains_key("swap_used_pct"));
    }

    #[test]
    fn metrics_from_memory_zero_swap_skips_swap_pct() {
        let mem = MemoryInfo {
            total_kb: 1000,
            free_kb: 500,
            available_kb: 500,
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 0,
            swap_free_kb: 0,
        };
        let m = metrics_from_memory(&mem);
        assert_eq!(m.get("mem_used_pct"), Some(&50.0));
        assert!(!m.contains_key("swap_used_pct"));
    }
}

#[cfg(test)]
mod io_path_tests {
    use super::*;

    #[test]
    fn collect_metrics_hits_all_sources() {
        let m = collect_metrics();
        // Run repeatedly to maximize chance all Ok branches fire.
        for _ in 0..3 {
            let m2 = collect_metrics();
            assert!(!m2.is_empty());
        }
        assert!(!m.is_empty());
    }

    #[test]
    fn collect_metrics_includes_process_count() {
        let m = collect_metrics();
        assert!(
            m.contains_key("process_count"),
            "process_count must be present"
        );
        assert!(m.get("process_count").copied().unwrap_or(0.0) > 0.0);
    }

    #[test]
    fn collect_metrics_includes_total_rss() {
        let m = collect_metrics();
        assert!(
            m.contains_key("total_rss_mb"),
            "total_rss_mb must be present"
        );
    }

    #[test]
    fn collect_metrics_includes_iface_count() {
        let m = collect_metrics();
        assert!(m.contains_key("iface_count"));
        assert!(m.get("iface_count").copied().unwrap_or(0.0) >= 1.0);
    }

    #[test]
    fn collect_metrics_includes_mem_used_pct() {
        let m = collect_metrics();
        assert!(m.contains_key("mem_used_pct"));
        let v = m.get("mem_used_pct").copied().unwrap();
        assert!((0.0..=100.0).contains(&v));
    }

    #[test]
    fn collect_metrics_includes_load_metrics() {
        let m = collect_metrics();
        assert!(m.contains_key("load1"));
        assert!(m.contains_key("load5"));
        assert!(m.contains_key("load15"));
    }
}
