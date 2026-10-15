//! Batch 1 — targeted tests for uncovered lines in pulse-core.
//!
//! Each test names the exact file:line it closes. No filler tests.

use pulse_core::render::disk_text;
use pulse_core::sign::{SigningKey, VerifyingKey};
use pulse_core::snapshot::{Change, DiffReport, DiffSummary};
use pulse_platform::{DiskInfo, MountInfo};

// ===========================================================================
// render.rs:193 — `human_bytes` i==0 branch (b < 1024)
// ===========================================================================
//
// `human_bytes` is private. `disk_text` calls it on `mount.total_bytes`.
// Passing a value < 1024 makes the loop skip and return "<N> B".
#[test]
fn disk_text_human_bytes_small_uses_bytes_unit() {
    let info = DiskInfo {
        mounts: vec![MountInfo {
            device: "/dev/zero".into(),
            mount_point: "/small".into(),
            fs_type: "tmpfs".into(),
            options: "rw".into(),
            total_bytes: Some(500), // < 1024 → hits the i==0 branch
            used_bytes: Some(200),
            available_bytes: Some(300),
            use_percent: Some(40.0),
        }],
    };
    let out = disk_text(&info);
    assert!(
        out.contains("500 B"),
        "small bytes must render as 'N B': {out}"
    );
    assert!(out.contains("200 B"));
    assert!(out.contains("300 B"));
}

#[test]
fn disk_text_human_bytes_zero() {
    let info = DiskInfo {
        mounts: vec![MountInfo {
            device: "/dev/zero".into(),
            mount_point: "/zero".into(),
            fs_type: "tmpfs".into(),
            options: "rw".into(),
            total_bytes: Some(0),
            used_bytes: Some(0),
            available_bytes: Some(0),
            use_percent: Some(0.0),
        }],
    };
    let out = disk_text(&info);
    assert!(out.contains("0 B"));
}

#[test]
fn disk_text_human_bytes_exactly_1023() {
    // 1023 < 1024 → must stay in "B"
    let info = DiskInfo {
        mounts: vec![MountInfo {
            device: "/dev/x".into(),
            mount_point: "/x".into(),
            fs_type: "ext4".into(),
            options: "rw".into(),
            total_bytes: Some(1023),
            used_bytes: None,
            available_bytes: None,
            use_percent: None,
        }],
    };
    let out = disk_text(&info);
    assert!(out.contains("1023 B"), "1023 must stay in B: {out}");
}

#[test]
fn disk_text_human_bytes_exactly_1024() {
    // 1024 >= 1024 → must convert to "1.0 KB"
    let info = DiskInfo {
        mounts: vec![MountInfo {
            device: "/dev/x".into(),
            mount_point: "/x".into(),
            fs_type: "ext4".into(),
            options: "rw".into(),
            total_bytes: Some(1024),
            used_bytes: None,
            available_bytes: None,
            use_percent: None,
        }],
    };
    let out = disk_text(&info);
    assert!(out.contains("1.0 KB"), "1024 must render as 1.0 KB: {out}");
}

// ===========================================================================
// snapshot.rs:337 — `_ => "?"` in `render_text` for unknown change kind
// ===========================================================================
//
// `diff()` never produces a kind other than added/removed/changed.
// We construct a `DiffReport` manually to reach the wildcard arm.
#[test]
fn diff_render_text_unknown_kind_uses_question_mark() {
    let report = DiffReport {
        from_timestamp: 1_700_000_000,
        to_timestamp: 1_700_000_001,
        elapsed_secs: 1,
        from_hostname: "a".into(),
        to_hostname: "b".into(),
        changes: vec![Change {
            category: "process".into(),
            kind: "unknown-kind".into(), // ← hits the `_ => "?"` arm
            item: "pid=1 init".into(),
            detail: None,
        }],
        summary: DiffSummary {
            processes_added: 0,
            processes_removed: 0,
            users_added: 0,
            users_removed: 0,
            modules_added: 0,
            modules_removed: 0,
            ifaces_added: 0,
            ifaces_removed: 0,
            env_added: 0,
            env_removed: 0,
            env_changed: 0,
            total_changes: 1,
        },
    };

    let out = report.render_text();
    assert!(out.contains("?"), "unknown kind must render '?': {out}");
    assert!(out.contains("pid=1 init"));
}

#[test]
fn diff_render_text_unknown_kind_with_detail() {
    let report = DiffReport {
        from_timestamp: 1,
        to_timestamp: 2,
        elapsed_secs: 1,
        from_hostname: "a".into(),
        to_hostname: "b".into(),
        changes: vec![Change {
            category: "env".into(),
            kind: "surprise".into(),
            item: "PATH".into(),
            detail: Some("old=/bin new=/usr/bin".into()),
        }],
        summary: DiffSummary {
            processes_added: 0,
            processes_removed: 0,
            users_added: 0,
            users_removed: 0,
            modules_added: 0,
            modules_removed: 0,
            ifaces_added: 0,
            ifaces_removed: 0,
            env_added: 0,
            env_removed: 0,
            env_changed: 0,
            total_changes: 1,
        },
    };
    let out = report.render_text();
    assert!(out.contains("?"), "unknown kind must show '?': {out}");
    assert!(out.contains("old=/bin new=/usr/bin"));
}

// ===========================================================================
// sign.rs:43 — SigningKey::from_hwid with wrong-length hex
// ===========================================================================
#[test]
fn signing_key_from_hwid_too_short_returns_invalid_hwid() {
    // 30 bytes = 60 hex chars; valid hex but wrong length
    let short = "a".repeat(60);
    assert!(SigningKey::from_hwid(&short).is_err());
}

#[test]
fn signing_key_from_hwid_too_long_returns_invalid_hwid() {
    let long = "a".repeat(68); // 34 bytes
    assert!(SigningKey::from_hwid(&long).is_err());
}

#[test]
fn signing_key_from_hwid_non_hex_returns_err() {
    // 64 chars but contains 'z' → hex decode fails at line 121 (odd check) or later
    let bad = "z".repeat(64);
    assert!(SigningKey::from_hwid(&bad).is_err());
}

#[test]
fn signing_key_from_hwid_empty_returns_err() {
    assert!(SigningKey::from_hwid("").is_err());
}

#[test]
fn signing_key_from_hwid_valid_returns_key() {
    let valid = "0123456789abcdef".repeat(4); // 64 hex chars = 32 bytes
    let key = SigningKey::from_hwid(&valid).expect("valid hwid");
    let _ = key.verifying_key();
}

// ===========================================================================
// sign.rs:66 — VerifyingKey::from_hex wrong length
// ===========================================================================
#[test]
fn verifying_key_from_hex_short_returns_invalid_length() {
    let short = "ab".repeat(15); // 30 bytes
    assert!(VerifyingKey::from_hex(&short).is_err());
}

#[test]
fn verifying_key_from_hex_long_returns_invalid_length() {
    let long = "ab".repeat(40); // 40 bytes
    assert!(VerifyingKey::from_hex(&long).is_err());
}

#[test]
fn verifying_key_from_hex_valid() {
    let valid = "ab".repeat(32); // 64 chars = 32 bytes
                                 // Note: not every 32-byte sequence is a valid Ed25519 point, but the
                                 // dalek library accepts any 32 bytes for decompression until use.
    let _ = VerifyingKey::from_hex(&valid);
}

// ===========================================================================
// sign.rs:121 — decode_hex odd-length input
// ===========================================================================
#[test]
fn signing_key_from_hwid_odd_length_hex_returns_err() {
    // Odd-length hex triggers the `if s.len() % 2 != 0` guard at line 121.
    let odd = "a".repeat(63);
    assert!(SigningKey::from_hwid(&odd).is_err());
}

#[test]
fn verifying_key_from_hex_odd_length_returns_err() {
    let odd = "a".repeat(63);
    assert!(VerifyingKey::from_hex(&odd).is_err());
}

// ===========================================================================
// merkle.rs:98-100, 107 — is_empty / len / proof out-of-bounds
// ===========================================================================
// These are covered indirectly via the public API of Snapshot::merkle_leaves
// through the MerkleTree type. We use the public MerkleTree directly.
use pulse_core::merkle::MerkleTree;

#[test]
fn merkle_tree_empty_is_empty_true() {
    // merkle.rs:98-100 — `is_empty()` and `len()` methods
    let t = MerkleTree::from_hashes(vec![]);
    assert!(t.is_empty(), "empty tree must report is_empty()");
    assert_eq!(t.len(), 0);
}

#[test]
fn merkle_tree_single_leaf_len_one() {
    let t = MerkleTree::from_hashes(vec![[0u8; 32]]);
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
}

#[test]
fn merkle_tree_multiple_leaves_len_matches() {
    let t = MerkleTree::from_hashes(vec![[0u8; 32]; 7]);
    assert_eq!(t.len(), 7);
}

#[test]
fn merkle_tree_proof_out_of_bounds_returns_none() {
    // merkle.rs:107 — `if index >= self.original_len { return None; }`
    let t = MerkleTree::from_hashes(vec![[0u8; 32], [1u8; 32]]);
    assert!(t.proof(2).is_none(), "index 2 == len → must be None");
    assert!(t.proof(100).is_none());
    assert!(t.proof(usize::MAX).is_none());
}

#[test]
fn merkle_tree_proof_in_bounds_returns_some() {
    let t = MerkleTree::from_hashes(vec![[0u8; 32], [1u8; 32]]);
    assert!(t.proof(0).is_some());
    assert!(t.proof(1).is_some());
}

// ===========================================================================
// anomaly.rs:247-254 — info severity branch (1.5 <= |z| < 2.0)
// ===========================================================================
//
// We inject a synthetic baseline that places current `process_count` at
// exactly z ≈ -1.7. The `info` branch fires; the `warn` and `critical`
// branches do not.
use pulse_core::anomaly::*;
use std::collections::BTreeMap;

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

#[test]
fn check_anomalies_info_branch_fires_at_1_7_sigma() {
    // Get current process_count from live system.
    let cur = collect_metrics()
        .get("process_count")
        .copied()
        .unwrap_or(500.0);

    // Choose mean so that |cur - mean| / sd_floor = 1.7
    // sd_floor = max(stddev, |mean|*0.05, 0.5)
    // With stddev = 100 and |mean| large enough, sd_floor = 100.
    let stddev = 100.0;
    let delta = 1.7 * stddev; // 170
    let mean = cur + delta;

    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(mean, stddev, 10));

    let report = check_anomalies(&baseline(m));
    let f = report
        .findings
        .iter()
        .find(|f| f.metric == "process_count")
        .expect("info branch must fire");

    assert_eq!(f.severity, "info", "|z|=1.7 must be classified as info");
    assert!(f.z_score.abs() >= 1.5 && f.z_score.abs() < 2.0);
}

#[test]
fn check_anomalies_warn_branch_fires_at_2_5_sigma() {
    let cur = collect_metrics()
        .get("process_count")
        .copied()
        .unwrap_or(500.0);
    let stddev = 100.0;
    let delta = 2.5 * stddev;
    let mean = cur + delta;
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(mean, stddev, 10));

    let report = check_anomalies(&baseline(m));
    let f = report
        .findings
        .iter()
        .find(|f| f.metric == "process_count")
        .expect("warn branch must fire");
    assert_eq!(f.severity, "warn");
}

#[test]
fn check_anomalies_critical_branch_fires_at_3_5_sigma() {
    let cur = collect_metrics()
        .get("process_count")
        .copied()
        .unwrap_or(500.0);
    let stddev = 100.0;
    let delta = 3.5 * stddev;
    let mean = cur + delta;
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(mean, stddev, 10));

    let report = check_anomalies(&baseline(m));
    let f = report
        .findings
        .iter()
        .find(|f| f.metric == "process_count")
        .expect("critical branch must fire");
    assert_eq!(f.severity, "critical");
}

#[test]
fn check_anomalies_no_branch_fires_at_0_5_sigma() {
    let cur = collect_metrics()
        .get("process_count")
        .copied()
        .unwrap_or(500.0);
    let stddev = 100.0;
    let delta = 0.5 * stddev;
    let mean = cur + delta;
    let mut m = BTreeMap::new();
    m.insert("process_count".to_string(), stats(mean, stddev, 10));

    let report = check_anomalies(&baseline(m));
    let f = report.findings.iter().find(|f| f.metric == "process_count");
    assert!(f.is_none(), "|z|=0.5 must not flag");
}
