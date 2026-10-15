//! Real tests for `pulse-core/src/analysis.rs`.
//!
//! Every public function, every branch, and every severity level is
//! exercised with hand-crafted fixtures.

use pulse_core::analysis::*;
use pulse_platform::{CoreInfo, CpuInfo, MemoryInfo, ThermalInfo, ThermalZone};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn cpu_one_cluster() -> CpuInfo {
    CpuInfo {
        model: "Test CPU".into(),
        architecture: "aarch64".into(),
        cores: 4,
        features: vec!["neon".into(), "sve".into()],
        per_core: (0..4)
            .map(|id| CoreInfo {
                id,
                cur_freq_khz: Some(1_000_000),
                min_freq_khz: Some(400_000),
                max_freq_khz: Some(2_000_000),
                governor: Some("schedutil".into()),
            })
            .collect(),
    }
}

fn cpu_two_clusters() -> CpuInfo {
    let mut per_core = Vec::new();
    for id in 0..4 {
        per_core.push(CoreInfo {
            id,
            cur_freq_khz: Some(800_000),
            min_freq_khz: Some(400_000),
            max_freq_khz: Some(1_800_000), // little cluster
            governor: None,
        });
    }
    for id in 4..8 {
        per_core.push(CoreInfo {
            id,
            cur_freq_khz: Some(2_200_000),
            min_freq_khz: Some(800_000),
            max_freq_khz: Some(3_000_000), // big cluster
            governor: None,
        });
    }
    CpuInfo {
        model: "Test CPU".into(),
        architecture: "aarch64".into(),
        cores: 8,
        features: vec![],
        per_core,
    }
}

fn cpu_three_clusters() -> CpuInfo {
    let mut per_core = Vec::new();
    // Cluster 1: little, max 1.8 GHz, ids 0-3
    for id in 0..4 {
        per_core.push(CoreInfo {
            id,
            cur_freq_khz: Some(600_000),
            min_freq_khz: Some(300_000),
            max_freq_khz: Some(1_800_000),
            governor: None,
        });
    }
    // Cluster 2: big, max 2.4 GHz, ids 4-6
    for id in 4..7 {
        per_core.push(CoreInfo {
            id,
            cur_freq_khz: Some(1_500_000),
            min_freq_khz: Some(400_000),
            max_freq_khz: Some(2_400_000),
            governor: None,
        });
    }
    // Cluster 3: prime, max 3.2 GHz, id 7
    per_core.push(CoreInfo {
        id: 7,
        cur_freq_khz: Some(3_000_000),
        min_freq_khz: Some(500_000),
        max_freq_khz: Some(3_200_000),
        governor: None,
    });
    CpuInfo {
        model: "Test CPU".into(),
        architecture: "aarch64".into(),
        cores: 8,
        features: vec![],
        per_core,
    }
}

fn cpu_no_freqs() -> CpuInfo {
    CpuInfo {
        model: "Test CPU".into(),
        architecture: "aarch64".into(),
        cores: 2,
        features: vec![],
        per_core: vec![
            CoreInfo {
                id: 0,
                cur_freq_khz: None,
                min_freq_khz: None,
                max_freq_khz: None,
                governor: None,
            },
            CoreInfo {
                id: 1,
                cur_freq_khz: None,
                min_freq_khz: None,
                max_freq_khz: None,
                governor: None,
            },
        ],
    }
}

fn cpu_zero_cores() -> CpuInfo {
    CpuInfo {
        model: "None".into(),
        architecture: "aarch64".into(),
        cores: 0,
        features: vec![],
        per_core: vec![],
    }
}

fn cpu_pinned() -> CpuInfo {
    // cur == max → definitely pinned (100% >= 95%)
    CpuInfo {
        model: "Pinned CPU".into(),
        architecture: "aarch64".into(),
        cores: 2,
        features: vec!["sve".into()],
        per_core: vec![
            CoreInfo {
                id: 0,
                cur_freq_khz: Some(2_000_000),
                min_freq_khz: Some(400_000),
                max_freq_khz: Some(2_000_000),
                governor: None,
            },
            CoreInfo {
                id: 1,
                cur_freq_khz: Some(1_000_000),
                min_freq_khz: Some(400_000),
                max_freq_khz: Some(2_000_000),
                governor: None,
            },
        ],
    }
}

fn cpu_at_94_percent() -> CpuInfo {
    // cur = 94% of max → NOT pinned (94 < 95)
    CpuInfo {
        model: "Almost".into(),
        architecture: "aarch64".into(),
        cores: 1,
        features: vec![],
        per_core: vec![CoreInfo {
            id: 0,
            cur_freq_khz: Some(1_880_000),
            min_freq_khz: Some(400_000),
            max_freq_khz: Some(2_000_000),
            governor: None,
        }],
    }
}

fn memory_low() -> MemoryInfo {
    MemoryInfo {
        total_kb: 8_000_000,
        free_kb: 4_000_000,
        available_kb: 6_000_000, // 25% used
        buffers_kb: 100_000,
        cached_kb: 1_000_000,
        swap_total_kb: 4_000_000,
        swap_free_kb: 4_000_000,
    }
}

fn memory_moderate() -> MemoryInfo {
    MemoryInfo {
        total_kb: 8_000_000,
        free_kb: 2_500_000,
        available_kb: 3_000_000, // 62.5% used
        buffers_kb: 100_000,
        cached_kb: 1_000_000,
        swap_total_kb: 0,
        swap_free_kb: 0,
    }
}

fn memory_high() -> MemoryInfo {
    MemoryInfo {
        total_kb: 8_000_000,
        free_kb: 1_500_000,
        available_kb: 1_800_000, // 77.5% used
        buffers_kb: 100_000,
        cached_kb: 1_000_000,
        swap_total_kb: 4_000_000,
        swap_free_kb: 1_000_000, // 75% swap used
    }
}

fn memory_critical() -> MemoryInfo {
    MemoryInfo {
        total_kb: 8_000_000,
        free_kb: 500_000,
        available_kb: 600_000, // 92.5% used
        buffers_kb: 100_000,
        cached_kb: 1_000_000,
        swap_total_kb: 4_000_000,
        swap_free_kb: 500_000, // 87.5% swap used
    }
}

fn memory_unreadable() -> MemoryInfo {
    MemoryInfo {
        total_kb: 0,
        free_kb: 0,
        available_kb: 0,
        buffers_kb: 0,
        cached_kb: 0,
        swap_total_kb: 0,
        swap_free_kb: 0,
    }
}

fn thermal_with(temp: f64) -> ThermalInfo {
    ThermalInfo {
        zones: vec![ThermalZone {
            name: "cpu".into(),
            temp_millicelsius: (temp * 1000.0) as i64,
            temp_celsius: temp,
        }],
    }
}

fn thermal_empty() -> ThermalInfo {
    ThermalInfo { zones: vec![] }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[test]
fn severity_label_all_variants() {
    assert_eq!(Severity::Ok.label(), "OK  ");
    assert_eq!(Severity::Info.label(), "INFO");
    assert_eq!(Severity::Warn.label(), "WARN");
    assert_eq!(Severity::Critical.label(), "CRIT");
}

#[test]
fn severity_symbol_all_variants() {
    assert_eq!(Severity::Ok.symbol(), "[OK]");
    assert_eq!(Severity::Info.symbol(), "[i]");
    assert_eq!(Severity::Warn.symbol(), "[!]");
    assert_eq!(Severity::Critical.symbol(), "[X]");
}

#[test]
fn severity_eq_and_copy() {
    let a = Severity::Warn;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(Severity::Ok, Severity::Critical);
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

#[test]
fn finding_new_has_empty_evidence() {
    let f = Finding::new(Severity::Ok, "code", "msg");
    assert_eq!(f.severity, Severity::Ok);
    assert_eq!(f.code, "code");
    assert_eq!(f.message, "msg");
    assert!(f.evidence.is_empty());
}

#[test]
fn finding_with_evidence_appends() {
    let f = Finding::new(Severity::Info, "c", "m")
        .with_evidence("a")
        .with_evidence("b");
    assert_eq!(f.evidence.len(), 2);
    assert_eq!(f.evidence[0], "a");
    assert_eq!(f.evidence[1], "b");
}

// ---------------------------------------------------------------------------
// detect_cpu_clusters
// ---------------------------------------------------------------------------

#[test]
fn clusters_empty_on_zero_cores() {
    let clusters = detect_cpu_clusters(&cpu_zero_cores());
    assert!(clusters.is_empty());
}

#[test]
fn clusters_one_label_all() {
    let clusters = detect_cpu_clusters(&cpu_one_cluster());
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].label, "all");
    assert_eq!(clusters[0].cores.len(), 4);
    assert_eq!(clusters[0].max_freq_khz, 2_000_000);
    assert_eq!(clusters[0].min_freq_khz, 400_000);
}

#[test]
fn clusters_two_labels_little_big() {
    let clusters = detect_cpu_clusters(&cpu_two_clusters());
    assert_eq!(clusters.len(), 2);
    assert_eq!(clusters[0].label, "little");
    assert_eq!(clusters[0].max_freq_khz, 1_800_000);
    assert_eq!(clusters[1].label, "big");
    assert_eq!(clusters[1].max_freq_khz, 3_000_000);
}

#[test]
fn clusters_three_labels_little_big_prime() {
    let clusters = detect_cpu_clusters(&cpu_three_clusters());
    assert_eq!(clusters.len(), 3);
    assert_eq!(clusters[0].label, "little");
    assert_eq!(clusters[1].label, "big");
    assert_eq!(clusters[2].label, "prime");
    assert_eq!(clusters[2].cores, vec![7]);
}

#[test]
fn clusters_skip_cores_without_max_freq() {
    let clusters = detect_cpu_clusters(&cpu_no_freqs());
    assert!(
        clusters.is_empty(),
        "cores without max_freq must be skipped"
    );
}

#[test]
fn clusters_sorted_by_max_freq_ascending() {
    let clusters = detect_cpu_clusters(&cpu_three_clusters());
    let freqs: Vec<u64> = clusters.iter().map(|c| c.max_freq_khz).collect();
    let mut sorted = freqs.clone();
    sorted.sort();
    assert_eq!(freqs, sorted);
}

// ---------------------------------------------------------------------------
// analyze_thermal
// ---------------------------------------------------------------------------

#[test]
fn thermal_empty_returns_info_finding() {
    let findings = analyze_thermal(&thermal_empty());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert_eq!(findings[0].code, "thermal_no_zones");
}

#[test]
fn thermal_critical_at_85c() {
    let findings = analyze_thermal(&thermal_with(85.0));
    assert_eq!(findings[0].severity, Severity::Critical);
    assert!(findings[0].message.contains("critical"));
    assert_eq!(findings[0].evidence.len(), 3);
}

#[test]
fn thermal_critical_at_90c() {
    let findings = analyze_thermal(&thermal_with(90.0));
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn thermal_warn_at_75c() {
    let findings = analyze_thermal(&thermal_with(75.0));
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(findings[0].message.contains("high"));
}

#[test]
fn thermal_warn_at_80c() {
    let findings = analyze_thermal(&thermal_with(80.0));
    assert_eq!(findings[0].severity, Severity::Warn);
}

#[test]
fn thermal_info_at_65c() {
    let findings = analyze_thermal(&thermal_with(65.0));
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].message.contains("warm"));
}

#[test]
fn thermal_info_at_70c() {
    let findings = analyze_thermal(&thermal_with(70.0));
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn thermal_ok_at_50c() {
    let findings = analyze_thermal(&thermal_with(50.0));
    assert_eq!(findings[0].severity, Severity::Ok);
    assert!(findings[0].message.contains("nominal"));
}

#[test]
fn thermal_ok_at_20c() {
    let findings = analyze_thermal(&thermal_with(20.0));
    assert_eq!(findings[0].severity, Severity::Ok);
}

#[test]
fn thermal_evidence_contains_zone_and_temp() {
    let findings = analyze_thermal(&thermal_with(45.0));
    let joined = findings[0].evidence.join("|");
    assert!(joined.contains("zone=cpu"));
    assert!(joined.contains("temp_c=45"));
    assert!(joined.contains("total_zones=1"));
}

// ---------------------------------------------------------------------------
// analyze_memory
// ---------------------------------------------------------------------------

#[test]
fn memory_unreadable_returns_info() {
    let findings = analyze_memory(&memory_unreadable());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert_eq!(findings[0].code, "mem_unreadable");
}

#[test]
fn memory_low_is_ok_no_swap_finding() {
    let findings = analyze_memory(&memory_low());
    // Memory low → Ok + swap ok (swap_total > 0, swap used = 0)
    assert!(findings
        .iter()
        .any(|f| f.code == "mem_pressure" && f.severity == Severity::Ok));
    assert!(findings.iter().any(|f| f.code == "swap_ok"));
}

#[test]
fn memory_moderate_is_info_no_swap_total() {
    let findings = analyze_memory(&memory_moderate());
    assert!(findings
        .iter()
        .any(|f| f.code == "mem_pressure" && f.severity == Severity::Info));
    // swap_total = 0 → no swap finding
    assert!(!findings.iter().any(|f| f.code.starts_with("swap")));
}

#[test]
fn memory_high_is_warn_with_swap_pressure() {
    let findings = analyze_memory(&memory_high());
    assert!(findings
        .iter()
        .any(|f| f.code == "mem_pressure" && f.severity == Severity::Warn));
    assert!(findings
        .iter()
        .any(|f| f.code == "swap_pressure" && f.severity == Severity::Warn));
}

#[test]
fn memory_critical_at_90_percent() {
    let findings = analyze_memory(&memory_critical());
    assert!(findings
        .iter()
        .any(|f| f.code == "mem_pressure" && f.severity == Severity::Critical));
}

#[test]
fn memory_swap_under_50_is_ok() {
    let mut m = memory_high();
    m.swap_free_kb = 3_000_000; // 25% used
    let findings = analyze_memory(&m);
    assert!(findings.iter().any(|f| f.code == "swap_ok"));
    assert!(!findings.iter().any(|f| f.code == "swap_pressure"));
}

#[test]
fn memory_pressure_has_evidence() {
    let findings = analyze_memory(&memory_low());
    let pressure = findings.iter().find(|f| f.code == "mem_pressure").unwrap();
    let joined = pressure.evidence.join("|");
    assert!(joined.contains("total_kb="));
    assert!(joined.contains("available_kb="));
}

// ---------------------------------------------------------------------------
// analyze_cpu
// ---------------------------------------------------------------------------

#[test]
fn cpu_zero_cores_returns_info() {
    let findings = analyze_cpu(&cpu_zero_cores());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "cpu_no_cores");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn cpu_pinned_detected_at_100_percent() {
    let findings = analyze_cpu(&cpu_pinned());
    assert!(findings.iter().any(|f| f.code == "cpu_pinned"));
    let pinned = findings.iter().find(|f| f.code == "cpu_pinned").unwrap();
    assert!(pinned.message.contains("1 core"));
    assert!(pinned.evidence[0].contains("cores=[0]"));
}

#[test]
fn cpu_not_pinned_at_94_percent() {
    let findings = analyze_cpu(&cpu_at_94_percent());
    assert!(findings.iter().any(|f| f.code == "cpu_freq_ok"));
    assert!(!findings.iter().any(|f| f.code == "cpu_pinned"));
}

#[test]
fn cpu_features_finding_always_present() {
    let findings = analyze_cpu(&cpu_one_cluster());
    assert!(findings.iter().any(|f| f.code == "cpu_features"));
    let ff = findings.iter().find(|f| f.code == "cpu_features").unwrap();
    assert!(ff.message.contains("2 CPU features"));
}

#[test]
fn cpu_no_pinned_with_zero_freqs() {
    let findings = analyze_cpu(&cpu_no_freqs());
    // No cur/max → not pinned, so "cpu_freq_ok"
    assert!(findings.iter().any(|f| f.code == "cpu_freq_ok"));
}

// ---------------------------------------------------------------------------
// build_analysis
// ---------------------------------------------------------------------------

#[test]
fn build_analysis_aggregates_all_sections() {
    let report = build_analysis(&cpu_one_cluster(), &memory_low(), &thermal_with(45.0));
    assert!(!report.findings.is_empty());
    assert_eq!(report.cpu_clusters.len(), 1);
}

#[test]
fn build_analysis_summary_counts() {
    let report = build_analysis(&cpu_one_cluster(), &memory_low(), &thermal_with(45.0));
    let total =
        report.summary.ok + report.summary.info + report.summary.warn + report.summary.critical;
    assert_eq!(total, report.findings.len() as u32);
}

#[test]
fn build_analysis_empty_inputs() {
    let report = build_analysis(&cpu_zero_cores(), &memory_unreadable(), &thermal_empty());
    // cpu: no_cores(Info)
    // mem: unreadable(Info)
    // thermal: no_zones(Info)
    assert_eq!(report.summary.info, 3);
    assert_eq!(report.summary.warn, 0);
    assert_eq!(report.summary.critical, 0);
    assert!(report.cpu_clusters.is_empty());
}

#[test]
fn build_analysis_all_critical() {
    let report = build_analysis(&cpu_one_cluster(), &memory_critical(), &thermal_with(95.0));
    assert!(report.summary.critical >= 2);
}

// ---------------------------------------------------------------------------
// render_text / render_markdown
// ---------------------------------------------------------------------------

#[test]
fn render_text_contains_sections() {
    let report = build_analysis(&cpu_one_cluster(), &memory_low(), &thermal_with(45.0));
    let s = report.render_text();
    assert!(s.contains("=== PULSE HEALTH ANALYSIS ==="));
    assert!(s.contains("[CPU Clusters]"));
    assert!(s.contains("[Findings]"));
    assert!(s.contains("[Summary]"));
}

#[test]
fn render_text_shows_cluster_label_and_ghz() {
    let report = build_analysis(&cpu_one_cluster(), &memory_low(), &thermal_with(45.0));
    let s = report.render_text();
    assert!(s.contains("all"));
    assert!(s.contains("2.00 GHz"));
}

#[test]
fn render_text_cluster_single_core_format() {
    let cpu = CpuInfo {
        model: "x".into(),
        architecture: "aarch64".into(),
        cores: 1,
        features: vec![],
        per_core: vec![CoreInfo {
            id: 0,
            cur_freq_khz: Some(1_000_000),
            min_freq_khz: Some(100_000),
            max_freq_khz: Some(2_000_000),
            governor: None,
        }],
    };
    let report = build_analysis(&cpu, &memory_low(), &thermal_with(45.0));
    let s = report.render_text();
    assert!(s.contains("core  0"));
}

#[test]
fn render_text_cluster_multi_core_format() {
    let report = build_analysis(&cpu_one_cluster(), &memory_low(), &thermal_with(45.0));
    let s = report.render_text();
    assert!(s.contains("cores 0-3"));
}

#[test]
fn render_markdown_has_tables() {
    let report = build_analysis(&cpu_three_clusters(), &memory_high(), &thermal_with(80.0));
    let s = report.render_markdown();
    assert!(s.contains("# Pulse Health Analysis"));
    assert!(s.contains("## CPU Clusters"));
    assert!(s.contains("| Cluster | Cores | Max Freq |"));
    assert!(s.contains("## Findings"));
    assert!(s.contains("| Severity | Code | Message |"));
    assert!(s.contains("## Summary"));
}

#[test]
fn render_markdown_contains_severity_labels() {
    let report = build_analysis(&cpu_one_cluster(), &memory_low(), &thermal_with(45.0));
    let s = report.render_markdown();
    assert!(s.contains("OK") || s.contains("INFO"));
}

#[test]
fn render_markdown_single_core_cluster_format() {
    let cpu = CpuInfo {
        model: "x".into(),
        architecture: "aarch64".into(),
        cores: 1,
        features: vec![],
        per_core: vec![CoreInfo {
            id: 0,
            cur_freq_khz: Some(1_000_000),
            min_freq_khz: Some(100_000),
            max_freq_khz: Some(2_000_000),
            governor: None,
        }],
    };
    let report = build_analysis(&cpu, &memory_low(), &thermal_with(45.0));
    let s = report.render_markdown();
    assert!(s.contains("| all | 0 |"));
}

#[test]
fn render_text_empty_report_does_not_panic() {
    let report = build_analysis(&cpu_zero_cores(), &memory_unreadable(), &thermal_empty());
    let s = report.render_text();
    assert!(s.contains("[Summary]"));
}

#[test]
fn render_markdown_empty_report_does_not_panic() {
    let report = build_analysis(&cpu_zero_cores(), &memory_unreadable(), &thermal_empty());
    let s = report.render_markdown();
    assert!(s.contains("## Summary"));
    assert!(s.contains("**OK:**"));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn analysis_is_deterministic() {
    let cpu = cpu_three_clusters();
    let mem = memory_high();
    let thermal = thermal_with(80.0);

    let r1 = build_analysis(&cpu, &mem, &thermal);
    let r2 = build_analysis(&cpu, &mem, &thermal);

    assert_eq!(r1.render_text(), r2.render_text());
    assert_eq!(r1.render_markdown(), r2.render_markdown());
}
