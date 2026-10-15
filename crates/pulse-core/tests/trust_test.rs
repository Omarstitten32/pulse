//! Real tests for `pulse-core/src/trust.rs`.
//!
//! Two layers:
//! 1. Live tests against the running system (every signal function is called).
//! 2. Synthetic tests with hand-built `TrustReport` to verify rendering paths
//!    that cannot be forced on a healthy production machine.

use pulse_core::build_trust_report;
use pulse_core::trust::{is_loopback_addr, Signal, SignalState, TrustReport, TrustSummary};

// ---------------------------------------------------------------------------
// SignalState
// ---------------------------------------------------------------------------

#[test]
fn signal_state_symbol_all_variants() {
    assert_eq!(SignalState::Good.symbol(), "[+]");
    assert_eq!(SignalState::Warn.symbol(), "[~]");
    assert_eq!(SignalState::Bad.symbol(), "[-]");
    assert_eq!(SignalState::Unknown.symbol(), "[?]");
}

#[test]
fn signal_state_label_all_variants() {
    assert_eq!(SignalState::Good.label(), "PASS");
    assert_eq!(SignalState::Warn.label(), "WARN");
    assert_eq!(SignalState::Bad.label(), "FAIL");
    assert_eq!(SignalState::Unknown.label(), "N/A");
}

#[test]
fn signal_state_is_copy_and_eq() {
    let a = SignalState::Warn;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(SignalState::Good, SignalState::Bad);
}

// ---------------------------------------------------------------------------
// is_loopback_addr (public helper)
// ---------------------------------------------------------------------------

#[test]
fn loopback_ipv4_recognised() {
    assert!(is_loopback_addr("0100007F"));
}

#[test]
fn loopback_ipv6_recognised() {
    assert!(is_loopback_addr("00000000000000000000000001000000"));
}

#[test]
fn any_address_not_loopback() {
    assert!(!is_loopback_addr("00000000"));
}

#[test]
fn ipv4_127_0_0_2_not_loopback() {
    // 127.0.0.2 = 0200007F (little-endian), not the loopback constant
    assert!(!is_loopback_addr("0200007F"));
}

#[test]
fn empty_string_is_not_loopback() {
    assert!(!is_loopback_addr(""));
}

#[test]
fn random_hex_is_not_loopback() {
    assert!(!is_loopback_addr("DEADBEEF"));
}

// ---------------------------------------------------------------------------
// build_trust_report — structural invariants
// ---------------------------------------------------------------------------

#[test]
fn build_report_returns_valid_report() {
    let r = build_trust_report();
    assert!(!r.grade.is_empty());
    assert!(r.score >= 0 && r.score <= 100);
    assert!(matches!(r.grade.as_str(), "A" | "B" | "C" | "D" | "F"));
}

#[test]
fn build_report_has_exactly_18_signals() {
    let r = build_trust_report();
    assert_eq!(r.signals.len(), 18, "18 signals expected");
    assert_eq!(r.summary.total, 18);
}

#[test]
fn build_report_summary_counts_match_signals() {
    let r = build_trust_report();
    let mut good = 0;
    let mut warn = 0;
    let mut bad = 0;
    let mut unknown = 0;
    for s in &r.signals {
        match s.state {
            SignalState::Good => good += 1,
            SignalState::Warn => warn += 1,
            SignalState::Bad => bad += 1,
            SignalState::Unknown => unknown += 1,
        }
    }
    assert_eq!(r.summary.good, good);
    assert_eq!(r.summary.warn, warn);
    assert_eq!(r.summary.bad, bad);
    assert_eq!(r.summary.unknown, unknown);
    assert_eq!(good + warn + bad + unknown, r.summary.total);
}

#[test]
fn build_report_all_signals_have_required_fields() {
    let r = build_trust_report();
    for s in &r.signals {
        assert!(!s.id.is_empty(), "id must not be empty");
        assert!(!s.name.is_empty(), "name must not be empty");
        assert!(!s.category.is_empty(), "category must not be empty");
        assert!(!s.detail.is_empty(), "detail must not be empty");
        assert!(s.points_delta >= 0, "points_delta must be non-negative");
    }
}

#[test]
fn build_report_categories_are_known() {
    let r = build_trust_report();
    let known = ["kernel", "mac", "fs", "config", "network", "posture"];
    for s in &r.signals {
        assert!(
            known.contains(&s.category.as_str()),
            "unknown category: {}",
            s.category
        );
    }
}

#[test]
fn build_report_signal_ids_are_unique() {
    let r = build_trust_report();
    let mut ids: Vec<&str> = r.signals.iter().map(|s| s.id.as_str()).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n, "signal ids must be unique");
}

#[test]
fn build_report_score_plus_penalty_matches_invariant() {
    // score = clamp(100 - penalty, 0, 100)
    let r = build_trust_report();
    if r.summary.penalty < 100 {
        assert_eq!(r.score, 100 - r.summary.penalty);
    } else {
        assert_eq!(r.score, 0);
    }
}

#[test]
fn build_report_grade_matches_score() {
    let r = build_trust_report();
    let expected_grade = match r.score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };
    assert_eq!(r.grade, expected_grade);
}

#[test]
fn build_report_is_deterministic_within_short_window() {
    let a = build_trust_report();
    let b = build_trust_report();
    // Signals may vary slightly (uptime, processes), but structural
    // invariants must hold.
    assert_eq!(a.summary.total, b.summary.total);
    assert_eq!(a.grade, b.grade);
}

// ---------------------------------------------------------------------------
// Individual signal behaviour on the live system
// ---------------------------------------------------------------------------

#[test]
fn signal_aslr_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "aslr").unwrap();
    assert_eq!(s.name, "ASLR");
    assert_eq!(s.category, "kernel");
    assert_eq!(s.points_delta, 10);
}

#[test]
fn signal_kptr_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "kptr_restrict").unwrap();
    assert_eq!(s.category, "kernel");
    assert_eq!(s.points_delta, 8);
}

#[test]
fn signal_dmesg_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "dmesg_restrict").unwrap();
    assert_eq!(s.points_delta, 5);
}

#[test]
fn signal_perf_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "perf_paranoid").unwrap();
    assert_eq!(s.points_delta, 5);
}

#[test]
fn signal_tainted_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "kernel_tainted").unwrap();
    assert_eq!(s.points_delta, 10);
}

#[test]
fn signal_selinux_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "selinux").unwrap();
    assert_eq!(s.category, "mac");
    assert_eq!(s.points_delta, 15, "SELinux is highest weighted signal");
}

#[test]
fn signal_lockdown_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "lockdown").unwrap();
    assert_eq!(s.category, "mac");
    assert_eq!(s.points_delta, 8);
}

#[test]
fn signal_suid_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "suid_bins").unwrap();
    assert_eq!(s.category, "fs");
    assert_eq!(s.points_delta, 5);
}

#[test]
fn signal_etc_ww_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "etc_ww").unwrap();
    assert_eq!(s.points_delta, 8);
}

#[test]
fn signal_tmp_exec_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "tmp_exec").unwrap();
    assert_eq!(s.points_delta, 6);
}

#[test]
fn signal_ssh_root_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "ssh_root").unwrap();
    assert_eq!(s.category, "config");
    assert_eq!(s.points_delta, 10);
}

#[test]
fn signal_public_ports_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "public_ports").unwrap();
    assert_eq!(s.category, "network");
    assert_eq!(s.points_delta, 8);
}

#[test]
fn signal_remote_conns_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "remote_conns").unwrap();
    assert_eq!(s.points_delta, 0, "informational only");
    assert_eq!(s.state, SignalState::Good);
}

#[test]
fn signal_uptime_is_informational() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "uptime").unwrap();
    assert_eq!(s.points_delta, 0);
    assert_eq!(s.state, SignalState::Good);
}

#[test]
fn signal_deleted_bins_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "deleted_bins").unwrap();
    assert_eq!(s.points_delta, 8);
}

#[test]
fn signal_cron_is_informational() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "cron").unwrap();
    assert_eq!(s.points_delta, 0);
    assert_eq!(s.state, SignalState::Good);
}

#[test]
fn signal_uid0_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "uid0").unwrap();
    assert_eq!(s.points_delta, 10);
}

#[test]
fn signal_unlocked_has_correct_metadata() {
    let r = build_trust_report();
    let s = r.signals.iter().find(|s| s.id == "unlocked").unwrap();
    assert_eq!(s.points_delta, 8);
}

// ---------------------------------------------------------------------------
// Penalty logic
// ---------------------------------------------------------------------------

#[test]
fn penalty_non_negative() {
    let r = build_trust_report();
    assert!(r.summary.penalty >= 0);
}

#[test]
fn penalty_minimal_on_perfect_system() {
    // If all signals are Good, penalty must be 0.
    let r = build_trust_report();
    if r.summary.good == r.summary.total {
        assert_eq!(r.summary.penalty, 0);
        assert_eq!(r.score, 100);
        assert_eq!(r.grade, "A");
    }
}

#[test]
fn score_never_below_zero() {
    let r = build_trust_report();
    assert!(r.score >= 0);
}

#[test]
fn score_never_above_100() {
    let r = build_trust_report();
    assert!(r.score <= 100);
}

// ---------------------------------------------------------------------------
// Synthetic report — testing every rendering branch
// ---------------------------------------------------------------------------

fn good_signal(id: &str, cat: &str, points: i32) -> Signal {
    Signal {
        id: id.to_string(),
        name: id.to_string(),
        category: cat.to_string(),
        state: SignalState::Good,
        detail: "ok".to_string(),
        evidence: vec![],
        points_delta: points,
    }
}

fn synthetic_report() -> TrustReport {
    TrustReport {
        score: 85,
        grade: "B".to_string(),
        signals: vec![
            good_signal("aslr", "kernel", 10),
            Signal {
                id: "selinux".to_string(),
                name: "SELinux".to_string(),
                category: "mac".to_string(),
                state: SignalState::Warn,
                detail: "Permissive".to_string(),
                evidence: vec!["evidence1".to_string(), "evidence2".to_string()],
                points_delta: 15,
            },
            Signal {
                id: "etc_ww".to_string(),
                name: "World-writable".to_string(),
                category: "fs".to_string(),
                state: SignalState::Bad,
                detail: "3 files".to_string(),
                evidence: vec![],
                points_delta: 8,
            },
        ],
        summary: TrustSummary {
            total: 3,
            good: 1,
            warn: 1,
            bad: 1,
            unknown: 0,
            penalty: 23,
        },
    }
}

#[test]
fn render_text_contains_header_and_score() {
    let r = synthetic_report();
    let s = r.render_text();
    assert!(s.contains("=== PULSE TRUST SCORE ==="));
    assert!(s.contains("Overall : 85/100"));
    assert!(s.contains("Grade B"));
}

#[test]
fn render_text_lists_all_states() {
    let r = synthetic_report();
    let s = r.render_text();
    assert!(s.contains("1 pass"));
    assert!(s.contains("1 warn"));
    assert!(s.contains("1 fail"));
}

#[test]
fn render_text_shows_category_headers() {
    let r = synthetic_report();
    let s = r.render_text();
    assert!(s.contains("[KERNEL]"));
    assert!(s.contains("[MAC]"));
    assert!(s.contains("[FS]"));
}

#[test]
fn render_text_shows_evidence_indented() {
    let r = synthetic_report();
    let s = r.render_text();
    assert!(s.contains("evidence1"));
    assert!(s.contains("evidence2"));
    assert!(s.contains("└─"));
}

#[test]
fn render_text_has_penalty_breakdown() {
    let r = synthetic_report();
    let s = r.render_text();
    assert!(s.contains("Penalty breakdown:"));
    assert!(s.contains("-15 SELinux"));
    assert!(s.contains("-8 World-writable"));
}

#[test]
fn render_text_low_confidence_warning_when_unknown_high() {
    let mut r = synthetic_report();
    r.summary.unknown = 2;
    r.summary.good = 1;
    r.summary.warn = 0;
    r.summary.bad = 0;
    let s = r.render_text();
    assert!(s.contains("Low confidence"));
}

#[test]
fn render_text_no_warning_when_confidence_high() {
    let r = synthetic_report();
    let s = r.render_text();
    assert!(!s.contains("Low confidence"));
}

#[test]
fn render_markdown_has_header_and_score() {
    let r = synthetic_report();
    let s = r.render_markdown();
    assert!(s.contains("# Pulse Trust Score"));
    assert!(s.contains("**Score:** 85/100"));
    assert!(s.contains("Grade **B**"));
}

#[test]
fn render_markdown_has_signal_table() {
    let r = synthetic_report();
    let s = r.render_markdown();
    assert!(s.contains("## Signals"));
    assert!(s.contains("| State | Name | Detail | Points |"));
}

#[test]
fn render_markdown_escapes_pipes_in_detail() {
    let mut r = synthetic_report();
    r.signals[0].detail = "value|with|pipes".to_string();
    let s = r.render_markdown();
    assert!(s.contains("value\\|with\\|pipes"));
}

// ---------------------------------------------------------------------------
// Fully-empty report
// ---------------------------------------------------------------------------

#[test]
fn empty_report_renders_cleanly() {
    let r = TrustReport {
        score: 100,
        grade: "A".to_string(),
        signals: vec![],
        summary: TrustSummary {
            total: 0,
            good: 0,
            warn: 0,
            bad: 0,
            unknown: 0,
            penalty: 0,
        },
    };
    let _ = r.render_text();
    let _ = r.render_markdown();
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

#[test]
fn trust_report_serializes_to_json() {
    let r = synthetic_report();
    let json = serde_json::to_string(&r).expect("serialize");
    assert!(json.contains("\"score\":85"));
    assert!(json.contains("\"grade\":\"B\""));
    assert!(json.contains("\"good\":1"));
}

#[test]
fn signal_state_serializes_lowercase() {
    let s = good_signal("aslr", "kernel", 10);
    let json = serde_json::to_string(&s).expect("serialize");
    assert!(json.contains("\"state\":\"good\""));
}
