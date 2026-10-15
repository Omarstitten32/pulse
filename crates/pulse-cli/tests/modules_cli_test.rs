//! Integration tests for the new module CLI commands:
//! `hardening`, `attack-surface`, `vulns`.

use std::process::Command;

fn pulse() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pulse"))
}

fn run(args: &[&str]) -> std::process::Output {
    pulse().args(args).output().expect("spawn pulse")
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

// ===========================================================================
// pulse hardening
// ===========================================================================

#[test]
fn hardening_text_runs() {
    let out = run(&["hardening"]);
    assert!(out.status.success(), "hardening failed");
    let s = stdout(&out);
    assert!(s.contains("KERNEL HARDENING AUDIT"));
    assert!(s.contains("Score"));
    assert!(s.contains("Checks"));
    assert!(s.contains("[CHECKS]"));
}

#[test]
fn hardening_json_is_valid() {
    let out = run(&["--json", "hardening"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert!(v.get("score").is_some());
    assert!(v.get("max_score").is_some());
    assert!(v.get("grade").is_some());
    assert!(v.get("checks").is_some());
    assert!(v.get("findings").is_some());
}

#[test]
fn hardening_markdown_has_table() {
    let out = run(&["--format=markdown", "hardening"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("# Kernel Hardening Audit"));
    assert!(s.contains("| State | Check |"));
}

#[test]
fn hardening_json_checks_array_non_empty() {
    let out = run(&["--json", "hardening"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let checks = v
        .get("checks")
        .and_then(|x| x.as_array())
        .expect("checks array");
    assert!(!checks.is_empty());
    // Each check has required fields
    for c in checks {
        assert!(c.get("id").is_some());
        assert!(c.get("name").is_some());
        assert!(c.get("enabled").is_some());
    }
}

// ===========================================================================
// pulse attack-surface
// ===========================================================================

#[test]
fn attack_surface_text_runs() {
    let out = run(&["attack-surface"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("ATTACK SURFACE"));
    assert!(s.contains("LISTENING PORTS") || s.contains("SUID"));
}

#[test]
fn attack_surface_alias_attack_runs() {
    let out = run(&["attack"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("ATTACK SURFACE"));
}

#[test]
fn attack_surface_json_is_valid() {
    let out = run(&["--json", "attack-surface"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert!(v.get("score").is_some());
    assert!(v.get("listening_ports").is_some());
    assert!(v.get("suid_binaries").is_some());
    assert!(v.get("docker_socket").is_some());
}

#[test]
fn attack_surface_markdown_has_table() {
    let out = run(&["--format=markdown", "attack-surface"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("# Attack Surface"));
    assert!(s.contains("| Proto | Address |"));
}

// ===========================================================================
// pulse vulns
// ===========================================================================

#[test]
fn vulns_text_runs() {
    let out = run(&["vulns"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("VULNERABILITY REPORT"));
    assert!(s.contains("Score"));
    assert!(s.contains("BREAKDOWN") || s.contains("Findings"));
}

#[test]
fn vulns_alias_vulnerabilities_runs() {
    let out = run(&["vulnerabilities"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("VULNERABILITY REPORT"));
}

#[test]
fn vulns_json_is_valid() {
    let out = run(&["--json", "vulns"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert!(v.get("score").is_some());
    assert!(v.get("findings").is_some());
    assert!(v.get("empty_passwords").is_some());
    assert!(v.get("writable_passwd").is_some());
}

#[test]
fn vulns_markdown_has_sections() {
    let out = run(&["--format=markdown", "vulns"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("# Vulnerability Report"));
    assert!(s.contains("## Breakdown"));
}

// ===========================================================================
// Cross-module: hardening vs trust vs vulns all produce scores
// ===========================================================================

#[test]
fn all_three_modules_produce_scores_in_json() {
    for cmd in &["hardening", "attack-surface", "vulns"] {
        let out = run(&["--json", cmd]);
        assert!(out.status.success(), "{cmd} failed");
        let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        let score = v.get("score").and_then(|x| x.as_u64());
        assert!(score.is_some(), "{cmd} must produce a score");
    }
}

#[test]
fn modules_reject_unknown_format() {
    for cmd in &["hardening", "attack-surface", "vulns"] {
        let out = run(&["--format=yaml", cmd]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{cmd} must reject --format=yaml"
        );
    }
}

#[test]
fn modules_write_to_file_all_formats() {
    let mut dir = std::env::temp_dir();
    dir.push(format!("pulse-mod-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    for cmd in &["hardening", "attack-surface", "vulns"] {
        for fmt in &["text", "json", "markdown"] {
            let path = dir.join(format!("{cmd}-{fmt}.out"));
            let out = run(&[
                &format!("--format={fmt}"),
                cmd,
                &format!("--output={}", path.display()),
            ]);
            assert!(out.status.success(), "{cmd} --format={fmt} --output failed");
            let data = std::fs::read_to_string(&path).unwrap();
            assert!(!data.trim().is_empty(), "{cmd} {fmt} produced empty file");
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
