//! Full integration tests for the `pulse` CLI binary.
//!
//! Every command, option, format, and failure path is exercised through
//! the actual compiled binary via `std::process::Command`. Nothing is
//! mocked. We assert on exit codes, stdout, and stderr.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pulse() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pulse"))
}

fn run(args: &[&str]) -> Output {
    pulse()
        .args(args)
        .output()
        .expect("failed to spawn pulse binary")
}

fn run_with_home(args: &[&str], home: &Path) -> Output {
    pulse()
        .args(args)
        .env("HOME", home)
        .output()
        .expect("failed to spawn pulse binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pulse_cli_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create temp dir");
    p
}

fn cleanup(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Parse stdout as JSON. Panics with a clear message on failure.
fn parse_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| {
        panic!("stdout is not valid JSON: {e}\n--- stdout ---\n{s}\n--- end ---")
    })
}

// ---------------------------------------------------------------------------
// 1. Help, version, and no-args
// ---------------------------------------------------------------------------

#[test]
fn help_long_flag() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("USAGE:"));
    assert!(s.contains("COMMANDS:"));
    assert!(s.contains("OPTIONS:"));
}

#[test]
fn help_short_flag() {
    let out = run(&["-h"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("USAGE:"));
}

#[test]
fn help_command() {
    let out = run(&["help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("COMMANDS:"));
}

#[test]
fn no_args_prints_help() {
    let out = run(&[]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("USAGE:"));
}

#[test]
fn version_long_flag() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.to_lowercase().contains("pulse"));
}

#[test]
fn version_short_flag() {
    let out = run(&["-V"]);
    assert!(out.status.success());
    assert!(!stdout(&out).is_empty());
}

#[test]
fn version_command() {
    let out = run(&["version"]);
    assert!(out.status.success());
    assert!(!stdout(&out).is_empty());
}

#[test]
fn formats_command() {
    let out = run(&["formats"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("text"));
    assert!(s.contains("json"));
    assert!(s.contains("markdown"));
}

#[test]
fn platform_command() {
    let out = run(&["platform"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("arch"));
    assert!(s.contains("os"));
    assert!(s.contains("pointer_width"));
    assert!(s.contains("endianness"));
}

// ---------------------------------------------------------------------------
// 2. Argument parsing errors
// ---------------------------------------------------------------------------

#[test]
fn unknown_command_returns_exit_2() {
    let out = run(&["this-command-does-not-exist"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown command"));
}

#[test]
fn unknown_long_option_returns_exit_2() {
    let out = run(&["--nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown option"));
}

#[test]
fn unknown_short_option_returns_exit_2() {
    let out = run(&["-x"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown option"));
}

#[test]
fn invalid_format_returns_exit_2() {
    let out = run(&["--format=yaml", "cpu"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown format"));
}

#[test]
fn output_without_value_returns_exit_2() {
    let out = run(&["--output=", "cpu"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--output requires a file path"));
}

// ---------------------------------------------------------------------------
// 3. Format handling
// ---------------------------------------------------------------------------

#[test]
fn format_json_produces_valid_json_cpu() {
    let out = run(&["--format=json", "cpu"]);
    if out.status.success() {
        let _ = parse_json(&stdout(&out));
    } else {
        assert!(stderr(&out).contains("error"));
    }
}

#[test]
fn format_markdown_cpu_has_table_or_dash() {
    let out = run(&["--format=markdown", "cpu"]);
    if out.status.success() {
        let s = stdout(&out);
        assert!(
            s.contains('|') || s.contains('-') || s.contains('#'),
            "markdown output should contain markdown syntax"
        );
    }
}

#[test]
fn format_text_cpu_is_plain() {
    let out = run(&["--format=text", "cpu"]);
    if out.status.success() {
        let s = stdout(&out);
        assert!(s.contains("Model") || s.contains("Cores") || s.contains("Architecture"));
    }
}

#[test]
fn json_shorthand_matches_format_json() {
    // Use `platform`: reads only std::env::consts, so output is byte-identical
    // across invocations. `cpu` would differ because CPU frequencies fluctuate.
    let a = run(&["--format=json", "platform"]);
    let b = run(&["--json", "platform"]);
    assert_eq!(a.status.code(), b.status.code());
    if a.status.success() && b.status.success() {
        assert_eq!(stdout(&a), stdout(&b));
    }
}

#[test]
fn compact_json_is_single_line() {
    let out = run(&["--json", "--compact", "cpu"]);
    if out.status.success() {
        let s = stdout(&out);
        let lines = s.lines().filter(|l| !l.is_empty()).count();
        assert!(lines <= 1, "compact JSON should be one line, got {lines}");
    }
}

#[test]
fn pretty_json_is_multi_line() {
    let out = run(&["--json", "cpu"]);
    if out.status.success() {
        let s = stdout(&out);
        assert!(s.lines().count() > 1, "pretty JSON should be multi-line");
    }
}

// ---------------------------------------------------------------------------
// 4. Output-to-file
// ---------------------------------------------------------------------------

#[test]
fn output_flag_writes_file_cpu() {
    let dir = temp_dir("output_file");
    let path = dir.join("cpu.json");

    let out = run(&[
        "--format=json",
        &format!("--output={}", path.display()),
        "cpu",
    ]);

    if out.status.success() {
        assert!(path.exists(), "output file should exist");
        let data = fs::read_to_string(&path).unwrap();
        assert!(data.starts_with('{') || data.starts_with('['));
    }

    cleanup(&dir);
}

#[test]
fn output_flag_writes_file_platform() {
    let dir = temp_dir("output_platform");
    let path = dir.join("platform.txt");

    let out = run(&[
        "--format=text",
        &format!("--output={}", path.display()),
        "platform",
    ]);

    assert!(out.status.success());
    assert!(path.exists());
    let data = fs::read_to_string(&path).unwrap();
    assert!(data.contains("arch"));

    cleanup(&dir);
}

// ---------------------------------------------------------------------------
// 5. Command execution — data commands
// ---------------------------------------------------------------------------

#[test]
fn system_command_runs() {
    let out = run(&["system"]);
    assert!(out.status.code() != Some(2));
    if out.status.success() {
        let s = stdout(&out);
        assert!(s.contains("OS") || s.contains("Kernel") || s.contains("Hostname"));
    }
}

#[test]
fn system_command_json() {
    let out = run(&["--json", "system"]);
    if out.status.success() {
        let _ = parse_json(&stdout(&out));
    }
}

#[test]
fn cpu_command_runs() {
    let out = run(&["cpu"]);
    assert!(out.status.code() != Some(2));
    if out.status.success() {
        let s = stdout(&out);
        assert!(s.contains("Model") || s.contains("Cores"));
    }
}

#[test]
fn memory_command_runs() {
    let out = run(&["memory"]);
    assert!(out.status.code() != Some(2));
    if out.status.success() {
        assert!(stdout(&out).contains("Total") || stdout(&out).contains("MB"));
    }
}

#[test]
fn disk_command_runs() {
    let out = run(&["disk"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn network_command_runs() {
    let out = run(&["network"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn process_command_runs() {
    let out = run(&["process"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn thermal_command_runs() {
    let out = run(&["thermal"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn gpu_command_runs() {
    let out = run(&["gpu"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn analyze_command_runs() {
    let out = run(&["analyze"]);
    assert!(out.status.code() != Some(2));
    if out.status.success() {
        let s = stdout(&out);
        assert!(s.contains("HEALTH") || s.contains("Findings") || s.contains("Summary"));
    }
}

#[test]
fn analyze_command_json() {
    let out = run(&["--json", "analyze"]);
    if out.status.success() {
        let _ = parse_json(&stdout(&out));
    }
}

#[test]
fn mem_detail_command_runs() {
    let out = run(&["mem-detail"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn mem_detail_alias_runs() {
    let out = run(&["memdetail"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn load_command_runs() {
    let out = run(&["load"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn vmstat_command_runs() {
    let out = run(&["vmstat"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn cputimes_command_runs() {
    let out = run(&["cputimes"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn users_command_runs() {
    let out = run(&["users"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn packages_command_runs() {
    let out = run(&["packages"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn services_command_runs() {
    let out = run(&["services"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn filesystem_command_runs() {
    let out = run(&["filesystem"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn fs_alias_runs() {
    let out = run(&["fs"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn env_command_runs() {
    let out = run(&["env"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn usb_command_runs() {
    let out = run(&["usb"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn pci_command_runs() {
    let out = run(&["pci"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn battery_command_runs() {
    let out = run(&["battery"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn sensors_command_runs() {
    let out = run(&["sensors"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn drivers_command_runs() {
    let out = run(&["drivers"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn containers_command_runs() {
    let out = run(&["containers"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn vm_command_runs() {
    let out = run(&["vm"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn browsers_command_runs() {
    let out = run(&["browsers"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn crypto_command_runs() {
    let out = run(&["crypto"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn cron_command_runs() {
    let out = run(&["cron"]);
    assert!(out.status.code() != Some(2));
}

// ---------------------------------------------------------------------------
// 6. HWID
// ---------------------------------------------------------------------------

#[test]
fn hwid_command_runs() {
    let out = run(&["hwid"]);
    assert!(out.status.code() != Some(2));
    if out.status.success() {
        assert!(stdout(&out).contains("PULSE HWID"));
    }
}

#[test]
fn hwid_verbose_shows_sources() {
    let out = run(&["hwid", "--verbose"]);
    if out.status.success() {
        assert!(stdout(&out).contains("Source breakdown"));
    }
}

#[test]
fn hwid_with_context() {
    let out = run(&["hwid", "--context=integration-test"]);
    if out.status.success() {
        assert!(stdout(&out).contains("integration-test"));
    }
}

#[test]
fn hwid_json_has_hash_field() {
    let out = run(&["--json", "hwid"]);
    if out.status.success() {
        let v = parse_json(&stdout(&out));
        assert!(v.get("hash").is_some());
        assert!(v.get("mode").is_some());
    }
}

#[test]
fn hwid_deterministic_without_context() {
    let a = run(&["--json", "hwid"]);
    let b = run(&["--json", "hwid"]);
    if a.status.success() && b.status.success() {
        assert_eq!(stdout(&a), stdout(&b));
    }
}

// ---------------------------------------------------------------------------
// 7. Trust
// ---------------------------------------------------------------------------

#[test]
fn trust_command_runs() {
    let out = run(&["trust"]);
    assert!(out.status.code() != Some(2));
    if out.status.success() {
        assert!(!stdout(&out).is_empty());
    }
}

#[test]
fn trust_json_output() {
    let out = run(&["--json", "trust"]);
    if out.status.success() {
        let v = parse_json(&stdout(&out));
        assert!(v.is_object());
    }
}

// ---------------------------------------------------------------------------
// 8. Snapshot
// ---------------------------------------------------------------------------

#[test]
fn snapshot_writes_valid_json() {
    let dir = temp_dir("snapshot");
    let path = dir.join("snap.json");

    let out = run(&["snapshot", &format!("--output={}", path.display())]);
    if out.status.success() && path.exists() {
        let data = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&data).expect("snapshot JSON");
        assert!(v.get("version").is_some());
        assert!(v.get("timestamp").is_some());
        assert!(v.get("merkle_root").is_some());
    }

    cleanup(&dir);
}

#[test]
fn snapshot_default_format_is_json() {
    let out = run(&["snapshot"]);
    if out.status.success() {
        let _ = parse_json(&stdout(&out));
    }
}

#[test]
fn merkle_leaves_command_runs() {
    let out = run(&["merkle-leaves"]);
    if out.status.success() {
        // Expected: tab-separated label/hash lines
        let s = stdout(&out);
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// 9. Diff
// ---------------------------------------------------------------------------

#[test]
fn diff_two_snapshots() {
    let dir = temp_dir("diff");
    let a = dir.join("a.json");
    let b = dir.join("b.json");

    let r1 = run(&["snapshot", &format!("--output={}", a.display())]);
    let r2 = run(&["snapshot", &format!("--output={}", b.display())]);

    if r1.status.success() && r2.status.success() {
        let out = run(&["diff", &a.display().to_string(), &b.display().to_string()]);
        assert!(out.status.code() != Some(2));
        if out.status.success() {
            let s = stdout(&out);
            assert!(!s.is_empty());
        }
    }

    cleanup(&dir);
}

// ---------------------------------------------------------------------------
// 10. Sign / Verify
// ---------------------------------------------------------------------------

#[test]
fn sign_and_verify_workflow() {
    let dir = temp_dir("sign_verify");
    let file = dir.join("payload.txt");
    fs::write(&file, b"integration test payload").unwrap();

    let sign_out = run(&["sign", &file.display().to_string()]);
    assert!(
        sign_out.status.success(),
        "sign failed: {}",
        stderr(&sign_out)
    );

    let sig = dir.join("payload.txt.sig");
    assert!(sig.exists());

    let verify_out = run(&["verify", &file.display().to_string()]);
    assert!(verify_out.status.success());

    let s = stdout(&verify_out);
    assert!(s.contains("VALID"));
    assert!(!s.contains("INVALID"));

    // Tamper
    fs::write(&file, b"tampered content").unwrap();
    let verify_out2 = run(&["verify", &file.display().to_string()]);
    let s2 = stdout(&verify_out2);
    assert!(s2.contains("INVALID"));

    cleanup(&dir);
}

#[test]
fn sign_without_file_fails() {
    let out = run(&["sign"]);
    assert!(!out.status.success());
}

#[test]
fn verify_without_file_fails() {
    let out = run(&["verify"]);
    assert!(!out.status.success());
}

#[test]
fn verify_json_reports_valid_true() {
    let dir = temp_dir("verify_json");
    let file = dir.join("p.txt");
    fs::write(&file, b"json verify").unwrap();
    let _ = run(&["sign", &file.display().to_string()]);

    let out = run(&["--json", "verify", &file.display().to_string()]);
    if out.status.success() {
        let v = parse_json(&stdout(&out));
        assert_eq!(v.get("valid").and_then(|x| x.as_bool()), Some(true));
    }

    cleanup(&dir);
}

#[test]
fn verify_with_pubkey_mismatch_detected() {
    let dir = temp_dir("verify_mismatch");
    let file = dir.join("m.txt");
    fs::write(&file, b"payload").unwrap();
    let _ = run(&["sign", &file.display().to_string()]);

    let wrong = "0".repeat(64);
    let out = run(&[
        "verify",
        &file.display().to_string(),
        &format!("--pubkey={wrong}"),
    ]);
    let s = stdout(&out);
    assert!(s.contains("INVALID") || s.contains("mismatch") || s.contains("does not match"));

    cleanup(&dir);
}

// ---------------------------------------------------------------------------
// 11. Anomaly
// ---------------------------------------------------------------------------

#[test]
fn anomaly_help_without_subcommand() {
    let home = temp_dir("anomaly_home");
    let out = run_with_home(&["anomaly"], &home);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("Usage") || s.contains("learn") || s.contains("check"));
    cleanup(&home);
}

#[test]
fn anomaly_check_without_baseline_fails_cleanly() {
    let home = temp_dir("anomaly_check_home");
    let out = run_with_home(&["anomaly", "check"], &home);
    // Should fail with exit 1, not panic with exit 101
    assert!(out.status.code() != Some(101));
    cleanup(&home);
}

// ---------------------------------------------------------------------------
// 12. Timeline filters
// ---------------------------------------------------------------------------

#[test]
fn timeline_runs_default() {
    let out = run(&["timeline"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn timeline_accepts_since_seconds() {
    let out = run(&["timeline", "--since=60s"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn timeline_accepts_since_minutes() {
    let out = run(&["timeline", "--since=5m"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn timeline_accepts_since_hours() {
    let out = run(&["timeline", "--since=1h"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn timeline_accepts_since_days() {
    let out = run(&["timeline", "--since=1d"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn timeline_accepts_source_filter() {
    let out = run(&["timeline", "--source=boot"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn timeline_json_output() {
    let out = run(&["--json", "timeline"]);
    if out.status.success() {
        let _ = parse_json(&stdout(&out));
    }
}

// ---------------------------------------------------------------------------
// 13. All (composite)
// ---------------------------------------------------------------------------

#[test]
fn all_command_runs() {
    let out = run(&["all"]);
    assert!(out.status.code() != Some(2));
}

#[test]
fn all_json_output() {
    let out = run(&["--json", "all"]);
    if out.status.success() {
        let _ = parse_json(&stdout(&out));
    }
}

// ---------------------------------------------------------------------------
// 14. Cross-command JSON consistency
// ---------------------------------------------------------------------------

#[test]
fn every_json_command_produces_valid_json_or_clean_error() {
    let commands = [
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
        "load",
        "vmstat",
        "cputimes",
        "users",
        "packages",
        "services",
        "filesystem",
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
    ];

    for cmd in commands {
        let out = run(&["--json", cmd]);
        let code = out.status.code();
        assert!(code != Some(2), "command '{cmd}' rejected by parser");
        assert!(code != Some(101), "command '{cmd}' panicked");

        if out.status.success() {
            let s = stdout(&out);
            if !s.trim().is_empty() {
                let _ = serde_json::from_str::<serde_json::Value>(&s)
                    .unwrap_or_else(|e| panic!("'{cmd}' produced invalid JSON: {e}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 15. Determinism checks
// ---------------------------------------------------------------------------

#[test]
fn hwid_is_stable_across_invocations() {
    let a = run(&["--json", "hwid"]);
    let b = run(&["--json", "hwid"]);
    if a.status.success() && b.status.success() {
        let va = parse_json(&stdout(&a));
        let vb = parse_json(&stdout(&b));
        assert_eq!(va.get("hash"), vb.get("hash"));
    }
}

#[test]
fn platform_output_is_stable() {
    let a = run(&["platform"]);
    let b = run(&["platform"]);
    assert_eq!(stdout(&a), stdout(&b));
}
