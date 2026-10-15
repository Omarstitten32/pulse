//! Health analysis + findings engine.

use pulse_platform::{CpuInfo, MemoryInfo, ThermalInfo};
use serde::Serialize;
use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warn,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK  ",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Critical => "CRIT",
        }
    }
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Ok => "[OK]",
            Self::Info => "[i]",
            Self::Warn => "[!]",
            Self::Critical => "[X]",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub evidence: Vec<String>,
}

impl Finding {
    pub fn new(severity: Severity, code: &str, message: impl Into<String>) -> Self {
        Self {
            severity,
            code: code.to_string(),
            message: message.into(),
            evidence: Vec::new(),
        }
    }
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuCluster {
    pub label: String,
    pub cores: Vec<u32>,
    pub max_freq_khz: u64,
    pub min_freq_khz: u64,
}

pub fn detect_cpu_clusters(cpu: &CpuInfo) -> Vec<CpuCluster> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
    for c in &cpu.per_core {
        if let Some(mx) = c.max_freq_khz {
            groups.entry(mx).or_default().push(c.id);
        }
    }
    let mut clusters: Vec<CpuCluster> = groups
        .into_iter()
        .map(|(max_freq, cores)| {
            let min_freq = cpu
                .per_core
                .iter()
                .filter(|c| cores.contains(&c.id))
                .filter_map(|c| c.min_freq_khz)
                .min()
                .unwrap_or(0);
            CpuCluster {
                label: String::new(),
                cores,
                max_freq_khz: max_freq,
                min_freq_khz: min_freq,
            }
        })
        .collect();

    clusters.sort_by_key(|c| c.max_freq_khz);
    let n = clusters.len();
    for (i, c) in clusters.iter_mut().enumerate() {
        c.label = if n == 1 {
            "all".to_string()
        } else if i == 0 {
            "little".to_string()
        } else if i == n - 1 && n >= 3 {
            "prime".to_string()
        } else {
            "big".to_string()
        };
    }
    clusters
}

pub fn analyze_thermal(thermal: &ThermalInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    if thermal.zones.is_empty() {
        out.push(Finding::new(
            Severity::Info,
            "thermal_no_zones",
            "No readable thermal zones",
        ));
        return out;
    }
    let hottest = &thermal.zones[0];
    let temp = hottest.temp_celsius;
    let (sev, msg) = if temp >= 85.0 {
        (
            Severity::Critical,
            format!("Thermal critical: {} at {:.1}C", hottest.name, temp),
        )
    } else if temp >= 75.0 {
        (
            Severity::Warn,
            format!("Thermal high: {} at {:.1}C", hottest.name, temp),
        )
    } else if temp >= 65.0 {
        (
            Severity::Info,
            format!("Thermal warm: {} at {:.1}C", hottest.name, temp),
        )
    } else {
        (
            Severity::Ok,
            format!("Thermal nominal: hottest {} at {:.1}C", hottest.name, temp),
        )
    };
    out.push(
        Finding::new(sev, "thermal_hottest", msg)
            .with_evidence(format!("zone={}", hottest.name))
            .with_evidence(format!("temp_c={:.1}", temp))
            .with_evidence(format!("total_zones={}", thermal.zones.len())),
    );
    out
}

pub fn analyze_memory(mem: &MemoryInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    if mem.total_kb == 0 {
        out.push(Finding::new(
            Severity::Info,
            "mem_unreadable",
            "MemTotal unreadable",
        ));
        return out;
    }
    let used_pct = 100.0 * (1.0 - mem.available_kb as f64 / mem.total_kb as f64);
    let swap_used_pct = if mem.swap_total_kb > 0 {
        100.0 * (1.0 - mem.swap_free_kb as f64 / mem.swap_total_kb as f64)
    } else {
        0.0
    };

    let (sev, msg) = if used_pct >= 90.0 {
        (
            Severity::Critical,
            format!("Memory critical: {:.1}% used", used_pct),
        )
    } else if used_pct >= 75.0 {
        (
            Severity::Warn,
            format!("Memory high: {:.1}% used", used_pct),
        )
    } else if used_pct >= 60.0 {
        (
            Severity::Info,
            format!("Memory moderate: {:.1}% used", used_pct),
        )
    } else {
        (
            Severity::Ok,
            format!("Memory normal: {:.1}% used", used_pct),
        )
    };
    out.push(
        Finding::new(sev, "mem_pressure", msg)
            .with_evidence(format!("total_kb={}", mem.total_kb))
            .with_evidence(format!("available_kb={}", mem.available_kb)),
    );

    if mem.swap_total_kb > 0 && swap_used_pct >= 50.0 {
        out.push(Finding::new(
            Severity::Warn,
            "swap_pressure",
            format!("Swap heavily used: {:.1}%", swap_used_pct),
        ));
    } else if mem.swap_total_kb > 0 {
        out.push(Finding::new(
            Severity::Ok,
            "swap_ok",
            format!("Swap usage normal: {:.1}%", swap_used_pct),
        ));
    }
    out
}

pub fn analyze_cpu(cpu: &CpuInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    if cpu.cores == 0 {
        out.push(Finding::new(
            Severity::Info,
            "cpu_no_cores",
            "No CPU cores detected",
        ));
        return out;
    }
    let pinned: Vec<&pulse_platform::CoreInfo> = cpu
        .per_core
        .iter()
        .filter(|c| match (c.cur_freq_khz, c.max_freq_khz) {
            (Some(cur), Some(max)) if max > 0 => cur * 100 >= max * 95,
            _ => false,
        })
        .collect();

    if !pinned.is_empty() {
        let ids: Vec<String> = pinned.iter().map(|c| c.id.to_string()).collect();
        out.push(
            Finding::new(
                Severity::Info,
                "cpu_pinned",
                format!("{} core(s) at ~max frequency", pinned.len()),
            )
            .with_evidence(format!("cores=[{}]", ids.join(","))),
        );
    } else {
        out.push(Finding::new(
            Severity::Ok,
            "cpu_freq_ok",
            "No core pinned at max frequency",
        ));
    }
    out.push(Finding::new(
        Severity::Info,
        "cpu_features",
        format!("{} CPU features detected", cpu.features.len()),
    ));
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub cpu_clusters: Vec<CpuCluster>,
    pub findings: Vec<Finding>,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub ok: u32,
    pub info: u32,
    pub warn: u32,
    pub critical: u32,
}

impl AnalysisSummary {
    fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self {
            ok: 0,
            info: 0,
            warn: 0,
            critical: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Ok => s.ok += 1,
                Severity::Info => s.info += 1,
                Severity::Warn => s.warn += 1,
                Severity::Critical => s.critical += 1,
            }
        }
        s
    }
}

pub fn build_analysis(cpu: &CpuInfo, mem: &MemoryInfo, thermal: &ThermalInfo) -> AnalysisReport {
    let mut findings = Vec::new();
    findings.extend(analyze_cpu(cpu));
    findings.extend(analyze_memory(mem));
    findings.extend(analyze_thermal(thermal));
    let summary = AnalysisSummary::from_findings(&findings);
    AnalysisReport {
        cpu_clusters: detect_cpu_clusters(cpu),
        findings,
        summary,
    }
}

impl AnalysisReport {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        s.push_str("=== PULSE HEALTH ANALYSIS ===\n\n");
        s.push_str("[CPU Clusters]\n");
        for c in &self.cpu_clusters {
            let cores_str = if c.cores.len() == 1 {
                format!("core  {}", c.cores[0])
            } else {
                format!("cores {}-{}", c.cores[0], c.cores[c.cores.len() - 1])
            };
            let _ = writeln!(
                s,
                "  {:<7} {:<12} max {:.2} GHz",
                c.label,
                cores_str,
                c.max_freq_khz as f64 / 1_000_000.0
            );
        }
        s.push('\n');
        s.push_str("[Findings]\n");
        for f in &self.findings {
            let _ = writeln!(
                s,
                "  {} {:<5} : {}",
                f.severity.symbol(),
                f.severity.label(),
                f.message
            );
        }
        s.push('\n');
        let _ = writeln!(
            s,
            "[Summary] ok={} info={} warn={} critical={}",
            self.summary.ok, self.summary.info, self.summary.warn, self.summary.critical
        );
        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Pulse Health Analysis\n\n## CPU Clusters\n\n");
        s.push_str("| Cluster | Cores | Max Freq |\n|---------|-------|----------|\n");
        for c in &self.cpu_clusters {
            let cores_str = if c.cores.len() == 1 {
                format!("{}", c.cores[0])
            } else {
                format!("{}-{}", c.cores[0], c.cores[c.cores.len() - 1])
            };
            let _ = writeln!(
                s,
                "| {} | {} | {:.2} GHz |",
                c.label,
                cores_str,
                c.max_freq_khz as f64 / 1_000_000.0
            );
        }
        s.push_str(
            "\n## Findings\n\n| Severity | Code | Message |\n|----------|------|---------|\n",
        );
        for f in &self.findings {
            let _ = writeln!(
                s,
                "| {} | `{}` | {} |",
                f.severity.label(),
                f.code,
                f.message
            );
        }
        s.push_str("\n## Summary\n\n");
        let _ = writeln!(s, "- **OK:** {}", self.summary.ok);
        let _ = writeln!(s, "- **Info:** {}", self.summary.info);
        let _ = writeln!(s, "- **Warn:** {}", self.summary.warn);
        let _ = writeln!(s, "- **Critical:** {}", self.summary.critical);
        s
    }
}
