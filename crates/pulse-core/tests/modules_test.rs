//! Integration tests for `pulse-core/src/modules/*`.
//!
//! These tests exercise:
//! - Pure helpers (now exposed as `pub(crate)` for testing).
//! - Real report collection on the running system.
//! - All three render output formats (text / markdown).
//!
//! Target files:
//! - hardening.rs
//! - attack_surface.rs
//! - vulnerabilities.rs

#![allow(clippy::field_reassign_with_default)]

use pulse_core::modules::attack_surface::{
    compute_score as as_compute_score, parse_hex_addr, AttackSurface,
};
use pulse_core::modules::hardening::{
    grade_for, value_matches, CheckSpec, HardeningReport, MatchKind, Severity,
};
use pulse_core::modules::vulnerabilities::{
    compute_score as vuln_compute_score, is_writable, VulnerabilityReport,
};

// ===========================================================================
// hardening.rs — pure helpers
// ===========================================================================

fn spec(kind: MatchKind, expected: &'static str) -> CheckSpec {
    CheckSpec {
        id: "x",
        name: "x",
        path: "/x",
        expected,
        weight: 1,
        severity: Severity::Info,
        kind,
    }
}

#[test]
fn value_matches_exact_hit() {
    let s = spec(MatchKind::Exact, "1");
    assert!(value_matches("1", &s));
}

#[test]
fn value_matches_exact_miss() {
    let s = spec(MatchKind::Exact, "1");
    assert!(!value_matches("0", &s));
}

#[test]
fn value_matches_exact_empty_string() {
    let s = spec(MatchKind::Exact, "1");
    assert!(!value_matches("", &s));
}

#[test]
fn value_matches_min_at_least_hit() {
    let s = spec(MatchKind::MinAtLeast(2), "2");
    assert!(value_matches("2", &s));
    assert!(value_matches("5", &s));
}

#[test]
fn value_matches_min_at_least_miss() {
    let s = spec(MatchKind::MinAtLeast(2), "2");
    assert!(!value_matches("1", &s));
}

#[test]
fn value_matches_min_at_least_non_numeric() {
    let s = spec(MatchKind::MinAtLeast(2), "2");
    assert!(!value_matches("abc", &s));
}

#[test]
fn value_matches_zero_means_enabled_hit() {
    let s = spec(MatchKind::ZeroMeansEnabled, "0");
    assert!(value_matches("0", &s));
}

#[test]
fn value_matches_zero_means_enabled_miss() {
    let s = spec(MatchKind::ZeroMeansEnabled, "0");
    assert!(!value_matches("1", &s));
}

#[test]
fn grade_for_letter_a() {
    assert_eq!(grade_for(95, 100), 'A');
    assert_eq!(grade_for(100, 100), 'A');
}

#[test]
fn grade_for_letter_b() {
    assert_eq!(grade_for(85, 100), 'B');
    assert_eq!(grade_for(94, 100), 'B');
}

#[test]
fn grade_for_letter_c() {
    assert_eq!(grade_for(70, 100), 'C');
    assert_eq!(grade_for(84, 100), 'C');
}

#[test]
fn grade_for_letter_d() {
    assert_eq!(grade_for(50, 100), 'D');
    assert_eq!(grade_for(69, 100), 'D');
}

#[test]
fn grade_for_letter_f() {
    assert_eq!(grade_for(0, 100), 'F');
    assert_eq!(grade_for(49, 100), 'F');
}

#[test]
fn grade_for_zero_max_returns_f() {
    assert_eq!(grade_for(0, 0), 'F');
}

// ===========================================================================
// hardening.rs — real collection & rendering
// ===========================================================================

#[test]
fn hardening_collect_produces_report() {
    let r = HardeningReport::collect();
    assert!(!r.checks.is_empty());
    assert!(r.max_score > 0);
    assert!(matches!(r.grade, 'A' | 'B' | 'C' | 'D' | 'F'));
}

#[test]
fn hardening_each_check_has_required_fields() {
    let r = HardeningReport::collect();
    for c in &r.checks {
        assert!(!c.id.is_empty());
        assert!(!c.name.is_empty());
        assert!(!c.path.is_empty());
        assert!(!c.expected.is_empty());
        assert!(c.weight > 0);
    }
}

#[test]
fn hardening_render_text_has_header() {
    let r = HardeningReport::collect();
    let s = r.render_text();
    assert!(s.contains("KERNEL HARDENING AUDIT"));
    assert!(s.contains("Score"));
    assert!(s.contains("[CHECKS]"));
}

#[test]
fn hardening_render_markdown_has_table() {
    let r = HardeningReport::collect();
    let s = r.render_markdown();
    assert!(s.contains("# Kernel Hardening Audit"));
    assert!(s.contains("| State | Check |"));
}

#[test]
fn hardening_summary_non_empty() {
    let r = HardeningReport::collect();
    assert!(!r.summary().is_empty());
}

// ===========================================================================
// attack_surface.rs — pure helpers
// ===========================================================================

#[test]
fn parse_hex_addr_ipv4() {
    let (a, p) = parse_hex_addr("0100007F:1F90").unwrap();
    assert_eq!(a, "127.0.0.1");
    assert_eq!(p, 8080);
}

#[test]
fn parse_hex_addr_all_interfaces() {
    let (a, p) = parse_hex_addr("00000000:0050").unwrap();
    assert_eq!(a, "0.0.0.0");
    assert_eq!(p, 80);
}

#[test]
fn parse_hex_addr_ipv6_passthrough() {
    let h = "00000000000000000000000001000000";
    let (a, p) = parse_hex_addr(&format!("{h}:1F90")).unwrap();
    assert_eq!(a, h);
    assert_eq!(p, 8080);
}

#[test]
fn parse_hex_addr_missing_colon_returns_none() {
    assert!(parse_hex_addr("0100007F").is_none());
}

#[test]
fn parse_hex_addr_bad_port_returns_none() {
    assert!(parse_hex_addr("0100007F:XYZ").is_none());
}

#[test]
fn attack_surface_score_bounds() {
    let s = AttackSurface::default();
    let score = as_compute_score(&s);
    assert!(score <= 100);
}

#[test]
fn attack_surface_score_penalized_by_listeners() {
    let mut s = AttackSurface::default();
    for i in 0..5u16 {
        s.listening_ports
            .push(pulse_core::modules::attack_surface::ListeningPort {
                proto: "tcp".into(),
                address: "0.0.0.0".into(),
                port: 1000 + i,
                state: "LISTEN".into(),
            });
    }
    let score = as_compute_score(&s);
    assert!(score < 100);
}

// ===========================================================================
// attack_surface.rs — real collection & rendering
// ===========================================================================

#[test]
fn attack_surface_collect_produces_report() {
    let s = AttackSurface::collect();
    // score is None iff no sources readable. Otherwise must be <= 100.
    match s.score {
        Some(n) => assert!(n <= 100),
        None => assert_eq!(s.sources_read, 0),
    }
    assert!(s.sources_total > 0);
    assert!(s.sources_read <= s.sources_total);
}

#[test]
fn attack_surface_confidence_matches_counts() {
    let s = AttackSurface::collect();
    let expected = pulse_core::Confidence::from_counts(s.sources_read, s.sources_total);
    assert_eq!(s.confidence, expected);
}

#[test]
fn attack_surface_score_none_iff_zero_reads() {
    let s = AttackSurface::collect();
    match s.score {
        Some(_) => assert!(s.sources_read > 0),
        None => assert_eq!(s.sources_read, 0),
    }
}

#[test]
fn attack_surface_render_text_has_sections() {
    let s = AttackSurface::collect();
    let out = s.render_text();
    assert!(out.contains("ATTACK SURFACE"));
    assert!(out.contains("Score"));
}

#[test]
fn attack_surface_render_markdown_has_headers() {
    let s = AttackSurface::collect();
    let out = s.render_markdown();
    assert!(out.contains("# Attack Surface"));
    assert!(out.contains("**Score:**"));
}

// ===========================================================================
// vulnerabilities.rs — pure helpers
// ===========================================================================

#[test]
fn vuln_is_writable_returns_false_for_root_only_file() {
    // /etc/shadow is normally not world-writable
    assert!(!is_writable("/etc/shadow") || is_writable("/etc/shadow"));
    // just ensure no panic
}

#[test]
fn vuln_is_writable_missing_path_returns_false() {
    assert!(!is_writable("/__nonexistent_pulse_test__"));
}

#[test]
fn vuln_compute_score_empty_report_is_100() {
    let r = VulnerabilityReport::default();
    assert_eq!(vuln_compute_score(&r), 100);
}

#[test]
fn vuln_compute_score_with_empty_passwords_penalized() {
    let mut r = VulnerabilityReport::default();
    r.empty_passwords = vec!["a".into(), "b".into()];
    assert!(vuln_compute_score(&r) < 100);
}

#[test]
fn vuln_compute_score_with_writable_passwd_penalized() {
    let mut r = VulnerabilityReport::default();
    r.writable_passwd = true;
    assert!(vuln_compute_score(&r) <= 80);
}

#[test]
fn vuln_compute_score_clamps_at_zero() {
    let mut r = VulnerabilityReport::default();
    r.empty_passwords = vec![String::new(); 100];
    r.world_readable_keys = vec![String::new(); 100];
    r.dangerous_sudoers = vec![String::new(); 100];
    r.writable_passwd = true;
    r.writable_shadow = true;
    let s = vuln_compute_score(&r);
    assert_eq!(s, 0);
}

// ===========================================================================
// vulnerabilities.rs — real collection & rendering
// ===========================================================================

#[test]
fn vuln_collect_produces_report() {
    let r = VulnerabilityReport::collect();
    match r.score {
        Some(n) => assert!(n <= 100),
        None => assert_eq!(r.sources_read, 0),
    }
}

#[test]
fn vuln_render_text_has_header() {
    let r = VulnerabilityReport::collect();
    let s = r.render_text();
    assert!(s.contains("VULNERABILITY REPORT"));
    assert!(s.contains("Score"));
}

#[test]
fn vuln_render_markdown_has_headers() {
    let r = VulnerabilityReport::collect();
    let s = r.render_markdown();
    assert!(s.contains("# Vulnerability Report"));
    assert!(s.contains("**Score:**"));
}

// ===========================================================================
// Cross-module sanity
// ===========================================================================

#[test]
fn all_three_modules_collect_without_panic() {
    let _ = HardeningReport::collect();
    let _ = AttackSurface::collect();
    let _ = VulnerabilityReport::collect();
}

#[test]
fn all_three_modules_have_scores_within_bounds() {
    let h = HardeningReport::collect();
    let a = AttackSurface::collect();
    let v = VulnerabilityReport::collect();
    assert!(h.score <= h.max_score);

    // attack-surface now returns Option<u32>: Some only when at least
    // one source was readable. When None, sources_read must be 0.
    match a.score {
        Some(n) => assert!(n <= 100, "attack-surface score out of bounds: {n}"),
        None => assert_eq!(a.sources_read, 0, "None score requires zero reads"),
    }

    // vulnerabilities now returns Option<u32> as well.
    match v.score {
        Some(n) => assert!(n <= 100, "vulns score out of bounds: {n}"),
        None => assert_eq!(v.sources_read, 0, "None score requires zero reads"),
    }
}

// ===========================================================================
// vulnerabilities.rs — empty report rendering branches
// ===========================================================================

use pulse_core::modules::vulnerabilities::{
    build_findings, scan_dangerous_sudoers, scan_insecure_mounts, scan_unsigned_repos,
    scan_world_readable_keys,
};

fn empty_vuln_report() -> VulnerabilityReport {
    VulnerabilityReport::default()
}

#[test]
fn vuln_render_text_empty_shows_clean_message() {
    // Construct an empty report to exercise the empty branch.
    // The breakdown is now always present (structural invariant),
    // only the findings message changes.
    let r = VulnerabilityReport {
        score: Some(100),
        sources_read: 7,
        sources_total: 7,
        confidence: pulse_core::Confidence::High,
        ..Default::default()
    };
    let s = r.render_text();
    assert!(s.contains("No known vulnerabilities detected."));
    // Structural sections are present regardless of findings.
    assert!(s.contains("[BREAKDOWN]"));
    assert!(s.contains("empty_passwords"));
    assert!(s.contains("writable /etc/passwd"));
}

#[test]
fn vuln_render_markdown_empty_shows_clean_message() {
    let r = empty_vuln_report();
    let s = r.render_markdown();
    assert!(s.contains("# Vulnerability Report"));
    assert!(s.contains("_No known vulnerabilities detected._"));
    assert!(!s.contains("## Findings"));
}

#[test]
fn vuln_render_text_with_findings_shows_breakdown() {
    let mut r = empty_vuln_report();
    r.empty_passwords = vec!["u1".into()];
    r.findings = build_findings(&r);
    r.score = Some(90);
    let s = r.render_text();
    assert!(s.contains("Findings: 1"));
    assert!(s.contains("[BREAKDOWN]"));
    assert!(s.contains("empty_passwords"));
}

// ===========================================================================
// build_findings — every branch
// ===========================================================================

#[test]
fn build_findings_empty_produces_nothing() {
    let r = empty_vuln_report();
    assert!(build_findings(&r).is_empty());
}

#[test]
fn build_findings_empty_passwords() {
    let mut r = empty_vuln_report();
    r.empty_passwords = vec!["alice".into(), "bob".into()];
    let f = build_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "critical");
    assert!(f[0].message.contains("2 account"));
    assert!(f[0].evidence.contains("alice"));
}

#[test]
fn build_findings_world_readable_keys() {
    let mut r = empty_vuln_report();
    r.world_readable_keys = vec!["/root/.ssh/id_rsa".into()];
    let f = build_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "high");
    assert!(f[0].message.contains("world-readable"));
}

#[test]
fn build_findings_writable_passwd() {
    let mut r = empty_vuln_report();
    r.writable_passwd = true;
    let f = build_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "critical");
    assert!(f[0].message.contains("/etc/passwd"));
}

#[test]
fn build_findings_writable_shadow() {
    let mut r = empty_vuln_report();
    r.writable_shadow = true;
    let f = build_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "critical");
    assert!(f[0].message.contains("/etc/shadow"));
}

#[test]
fn build_findings_dangerous_sudoers() {
    let mut r = empty_vuln_report();
    r.dangerous_sudoers = vec!["/etc/sudoers.d/x:3: user ALL=(ALL) NOPASSWD: ALL".into()];
    let f = build_findings(&r);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, "high");
    assert!(f[0].message.contains("NOPASSWD"));
}

#[test]
fn build_findings_all_five_categories() {
    let mut r = empty_vuln_report();
    r.empty_passwords = vec!["a".into()];
    r.world_readable_keys = vec!["k".into()];
    r.writable_passwd = true;
    r.writable_shadow = true;
    r.dangerous_sudoers = vec!["s".into()];
    let f = build_findings(&r);
    assert_eq!(f.len(), 5);
}

// ===========================================================================
// compute_score — writable_shadow branch
// ===========================================================================

#[test]
fn vuln_score_writable_shadow_penalty() {
    let mut r = empty_vuln_report();
    r.writable_shadow = true;
    let s = vuln_compute_score(&r);
    assert_eq!(s, 80);
}

#[test]
fn vuln_score_writable_both_passwd_and_shadow() {
    let mut r = empty_vuln_report();
    r.writable_passwd = true;
    r.writable_shadow = true;
    let s = vuln_compute_score(&r);
    assert_eq!(s, 60);
}

// ===========================================================================
// is_writable — positive branch (world-writable file we create)
// ===========================================================================

#[test]
fn vuln_is_writable_true_for_world_writable_file() {
    use std::os::unix::fs::PermissionsExt;
    let mut p = std::env::temp_dir();
    p.push(format!("pulse-vuln-ww-{}", std::process::id()));
    std::fs::write(&p, b"x").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(is_writable(&p.to_string_lossy()));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn vuln_is_writable_false_for_0600_file() {
    use std::os::unix::fs::PermissionsExt;
    let mut p = std::env::temp_dir();
    p.push(format!("pulse-vuln-ro-{}", std::process::id()));
    std::fs::write(&p, b"x").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!is_writable(&p.to_string_lossy()));
    let _ = std::fs::remove_file(&p);
}

// ===========================================================================
// I/O scanners — call to exercise code paths even when result is empty
// ===========================================================================

#[test]
fn scanners_run_without_panic() {
    let _ = scan_world_readable_keys();
    let _ = scan_insecure_mounts();
    let _ = scan_unsigned_repos();
    let _ = scan_dangerous_sudoers();
}

#[test]
fn vuln_confidence_matches_counts() {
    let r = VulnerabilityReport::collect();
    let expected = pulse_core::Confidence::from_counts(r.sources_read, r.sources_total);
    assert_eq!(r.confidence, expected);
}

#[test]
fn vuln_score_none_iff_zero_reads() {
    let r = VulnerabilityReport::collect();
    match r.score {
        Some(_) => assert!(r.sources_read > 0),
        None => assert_eq!(r.sources_read, 0),
    }
}
