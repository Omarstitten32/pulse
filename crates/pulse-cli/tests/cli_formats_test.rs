//! Format-coverage tests for the CLI.
//!
//! Every command is exercised in **all three formats** (text, json, markdown).
//! This closes the `Format::Markdown` arms in every `generate_*` function.
//! It also covers `sign`/`verify` in JSON, `anomaly learn/check`,
//! `diff` edge cases, and `parse_duration` variants.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn pulse() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pulse"))
}

fn run(args: &[&str]) -> std::process::Output {
    pulse().args(args).output().expect("failed to spawn pulse")
}

fn run_home(args: &[&str], home: &std::path::Path) -> std::process::Output {
    pulse()
        .args(args)
        .env("HOME", home)
        .output()
        .expect("failed to spawn pulse")
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pulse_{name}_{}", std::process::id()));
    p
}

fn cleanup(p: &PathBuf) {
    let _ = fs::remove_file(p);
    let _ = fs::remove_file(format!("{}.sig", p.display()));
}

// All commands that have a `generate_*` function with a 3-arm format match.
const DATA_COMMANDS: &[&str] = &[
    "system",
    "cpu",
    "memory",
    "disk",
    "network",
    "process",
    "thermal",
    "gpu",
    "analyze",
    "mem-detail",
    "memdetail",
    "load",
    "vmstat",
    "cputimes",
    "users",
    "packages",
    "services",
    "filesystem",
    "fs",
    "env",
    "usb",
    "pci",
    "battery",
    "sensors",
    "drivers",
    "containers",
    "vm",
    "browsers",
    "crypto",
    "cron",
    "hwid",
    "trust",
    "snapshot",
    "all",
    "timeline",
];

// ---------------------------------------------------------------------------
// 1. Every command × every format must run without panic.
// ---------------------------------------------------------------------------

#[test]
fn every_command_in_text_format() {
    for cmd in DATA_COMMANDS {
        let out = run(&["--format=text", cmd]);
        assert_ne!(
            out.status.code(),
            Some(101),
            "`{cmd}` panicked in text mode"
        );
    }
}

#[test]
fn every_command_in_json_format() {
    for cmd in DATA_COMMANDS {
        let out = run(&["--format=json", cmd]);
        assert_ne!(
            out.status.code(),
            Some(101),
            "`{cmd}` panicked in json mode"
        );
        if out.status.success() {
            let s = stdout(&out);
            if !s.trim().is_empty() {
                let _ = serde_json::from_str::<serde_json::Value>(&s)
                    .unwrap_or_else(|e| panic!("`{cmd}` produced invalid JSON: {e}"));
            }
        }
    }
}

#[test]
fn every_command_in_markdown_format() {
    for cmd in DATA_COMMANDS {
        let out = run(&["--format=markdown", cmd]);
        assert_ne!(
            out.status.code(),
            Some(101),
            "`{cmd}` panicked in markdown mode"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Markdown output actually contains markdown markers.
// ---------------------------------------------------------------------------

#[test]
fn markdown_output_has_markdown_syntax() {
    // These commands produce structured reports with predictable markers.
    for cmd in &[
        "system", "cpu", "memory", "disk", "network", "process", "thermal", "users", "usb", "pci",
        "sensors", "drivers",
    ] {
        let out = run(&["--format=markdown", cmd]);
        if !out.status.success() {
            continue;
        }
        let s = stdout(&out);
        if s.trim().is_empty() {
            continue;
        }
        // Markdown renderers emit tables or headers.
        assert!(
            s.contains('|') || s.contains('#') || s.contains("**"),
            "`{cmd}` markdown output lacks markdown syntax:\n{s}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Text output is not empty for structured data commands.
// ---------------------------------------------------------------------------

#[test]
fn text_output_is_non_empty_for_data_commands() {
    for cmd in &["system", "cpu", "memory", "platform", "network", "process"] {
        let out = run(&[cmd]);
        if !out.status.success() {
            continue;
        }
        let s = stdout(&out);
        assert!(
            !s.trim().is_empty(),
            "`{cmd}` text output must not be empty"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Sign / Verify in JSON format (covers `Format::Json` arms).
// ---------------------------------------------------------------------------

#[test]
fn sign_in_json_format_returns_valid_envelope() {
    let p = tmp("sign_json");
    cleanup(&p);
    fs::write(&p, b"payload").unwrap();

    let out = run(&["--format=json", "sign", &p.display().to_string()]);
    assert!(out.status.success(), "sign json failed: {}", stderr(&out));
    let s = stdout(&out);
    let v: serde_json::Value = serde_json::from_str(&s).expect("sign json must be valid JSON");
    assert_eq!(v.get("version").and_then(|x| x.as_u64()), Some(1));
    assert_eq!(v.get("algorithm").and_then(|x| x.as_str()), Some("ed25519"));
    assert!(v.get("sha256").is_some());
    assert!(v.get("public_key").is_some());
    assert!(v.get("signature").is_some());
    cleanup(&p);
}

#[test]
fn verify_valid_in_json_format() {
    let p = tmp("verify_ok_json");
    cleanup(&p);
    fs::write(&p, b"payload").unwrap();
    let _ = run(&["sign", &p.display().to_string()]);

    let out = run(&["--format=json", "verify", &p.display().to_string()]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("verify json");
    assert_eq!(v.get("valid").and_then(|x| x.as_bool()), Some(true));
    cleanup(&p);
}

#[test]
fn verify_invalid_after_tamper_in_json_format() {
    let p = tmp("verify_tamper_json");
    cleanup(&p);
    fs::write(&p, b"original").unwrap();
    let _ = run(&["sign", &p.display().to_string()]);
    fs::write(&p, b"tampered").unwrap();

    let out = run(&["--format=json", "verify", &p.display().to_string()]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("verify json");
    assert_eq!(v.get("valid").and_then(|x| x.as_bool()), Some(false));
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("file modified since signing")
    );
    cleanup(&p);
}

#[test]
fn verify_pubkey_mismatch_in_json_format() {
    let p = tmp("verify_mismatch_json");
    cleanup(&p);
    fs::write(&p, b"payload").unwrap();
    let _ = run(&["sign", &p.display().to_string()]);

    let wrong = "0".repeat(64);
    let out = run(&[
        "--format=json",
        "verify",
        &p.display().to_string(),
        &format!("--pubkey={wrong}"),
    ]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("verify json");
    assert_eq!(v.get("valid").and_then(|x| x.as_bool()), Some(false));
    assert_eq!(
        v.get("reason").and_then(|x| x.as_str()),
        Some("pubkey mismatch")
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// 5. Sign with text format (covers text arm) — sanity of "signed:" prefix.
// ---------------------------------------------------------------------------

#[test]
fn sign_in_text_format_prints_signed_marker() {
    let p = tmp("sign_text");
    cleanup(&p);
    fs::write(&p, b"payload").unwrap();

    let out = run(&["--format=text", "sign", &p.display().to_string()]);
    assert!(out.status.success());
    assert!(stdout(&out).starts_with("signed:"));
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// 6. Anomaly learn / check (covers anomaly arms in main.rs).
// ---------------------------------------------------------------------------

fn isolated_home(name: &str) -> PathBuf {
    let mut h = std::env::temp_dir();
    h.push(format!("pulse_{name}_home_{}", std::process::id()));
    let _ = fs::remove_dir_all(&h);
    fs::create_dir_all(&h).expect("create isolated HOME");
    h
}

#[test]
fn anomaly_learn_creates_baseline() {
    let home = isolated_home("anomaly_learn");

    let out = run_home(&["anomaly", "learn"], &home);
    assert!(
        out.status.success(),
        "anomaly learn failed: {}",
        stderr(&out)
    );

    let baseline = home.join(".config/pulse/baseline.json");
    assert!(
        baseline.exists(),
        "baseline.json not created at {}",
        baseline.display()
    );
    let data = fs::read_to_string(&baseline).unwrap();
    let v: serde_json::Value = serde_json::from_str(&data).expect("baseline must be valid JSON");
    assert!(v.get("version").is_some());
    assert!(v.get("samples").is_some());
    assert!(v.get("metrics").is_some());

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn anomaly_check_succeeds_after_learn() {
    let home = isolated_home("anomaly_check_ok");

    let _ = run_home(&["anomaly", "learn"], &home);
    let out = run_home(&["anomaly", "check"], &home);

    assert!(
        out.status.success(),
        "anomaly check failed: {}",
        stderr(&out)
    );
    assert!(!stdout(&out).trim().is_empty());

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn anomaly_check_in_json_format() {
    let home = isolated_home("anomaly_check_json");

    let _ = run_home(&["anomaly", "learn"], &home);
    let out = run_home(&["--format=json", "anomaly", "check"], &home);

    if out.status.success() {
        let s = stdout(&out);
        if !s.trim().is_empty() {
            let _ = serde_json::from_str::<serde_json::Value>(&s).expect("anomaly check json");
        }
    }

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn anomaly_check_in_markdown_format() {
    let home = isolated_home("anomaly_check_md");

    let _ = run_home(&["anomaly", "learn"], &home);
    let out = run_home(&["--format=markdown", "anomaly", "check"], &home);

    assert_ne!(out.status.code(), Some(101));

    let _ = fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// 7. Diff with real files, all formats.
// ---------------------------------------------------------------------------

#[test]
fn diff_requires_two_files_returns_error() {
    let out = run(&["diff"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("usage"));
}

#[test]
fn diff_with_one_file_returns_error() {
    let out = run(&["diff", "/tmp/only-one.json"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn diff_nonexistent_files_returns_error() {
    let out = run(&["diff", "/__none_a__.json", "/__none_b__.json"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn diff_invalid_json_returns_error() {
    let a = tmp("diff_bad_a.json");
    let b = tmp("diff_bad_b.json");
    fs::write(&a, b"not json").unwrap();
    fs::write(&b, b"also not json").unwrap();

    let out = run(&["diff", &a.display().to_string(), &b.display().to_string()]);
    assert_eq!(out.status.code(), Some(1));

    let _ = fs::remove_file(&a);
    let _ = fs::remove_file(&b);
}

#[test]
fn diff_two_real_snapshots_all_formats() {
    let a = tmp("diff_ok_a.json");
    let b = tmp("diff_ok_b.json");
    let _ = fs::remove_file(&a);
    let _ = fs::remove_file(&b);

    let _ = run(&["snapshot", &format!("--output={}", a.display())]);
    std::thread::sleep(std::time::Duration::from_millis(150));
    let _ = run(&["snapshot", &format!("--output={}", b.display())]);

    if !a.exists() || !b.exists() {
        return; // snapshot unavailable; nothing to test
    }

    for fmt in &["text", "json", "markdown"] {
        let out = run(&[
            &format!("--format={fmt}"),
            "diff",
            &a.display().to_string(),
            &b.display().to_string(),
        ]);
        assert!(
            out.status.success(),
            "diff --format={fmt} failed: {}",
            stderr(&out)
        );
    }

    // JSON must be parseable
    let out = run(&[
        "--format=json",
        "diff",
        &a.display().to_string(),
        &b.display().to_string(),
    ]);
    let _ =
        serde_json::from_str::<serde_json::Value>(&stdout(&out)).expect("diff json must be valid");

    let _ = fs::remove_file(&a);
    let _ = fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// 8. Timeline parse_duration — all suffixes.
// ---------------------------------------------------------------------------

#[test]
fn timeline_since_all_suffixes_do_not_panic() {
    for arg in &[
        "--since=30s",
        "--since=2m",
        "--since=1h",
        "--since=1d",
        "--since=120",
        "--since=abc",
        "--since=",
    ] {
        let out = run(&["timeline", arg]);
        assert_ne!(out.status.code(), Some(101), "timeline {arg} panicked");
    }
}

#[test]
fn timeline_since_suffixes_do_not_trigger_parse_error() {
    for arg in &[
        "--since=30s",
        "--since=2m",
        "--since=1h",
        "--since=1d",
        "--since=120",
    ] {
        let out = run(&["timeline", arg]);
        assert_ne!(
            out.status.code(),
            Some(2),
            "timeline {arg} rejected by parser"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. Timeline source filter — all formats.
// ---------------------------------------------------------------------------

#[test]
fn timeline_source_filter_all_formats() {
    for fmt in &["text", "json", "markdown"] {
        let out = run(&[&format!("--format={fmt}"), "timeline", "--source=kernel"]);
        assert_ne!(out.status.code(), Some(101));
    }
}

// ---------------------------------------------------------------------------
// 10. Snapshot output — output to file, all formats.
// ---------------------------------------------------------------------------

#[test]
fn snapshot_to_file_all_formats() {
    for fmt in &["text", "json", "markdown"] {
        let path = tmp(&format!("snap_{fmt}.txt"));
        let _ = fs::remove_file(&path);

        let out = run(&[
            &format!("--format={fmt}"),
            "snapshot",
            &format!("--output={}", path.display()),
        ]);
        if out.status.success() && path.exists() {
            let data = fs::read_to_string(&path).unwrap();
            assert!(
                !data.trim().is_empty(),
                "snapshot --format={fmt} produced empty file"
            );
        }

        let _ = fs::remove_file(&path);
    }
}
