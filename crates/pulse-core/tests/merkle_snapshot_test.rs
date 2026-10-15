//! Snapshot merkle_root tests.
//!
//! Uses a real captured snapshot as a fixture. The fixture is stored
//! in `tests/fixtures/snapshot.json` and represents one concrete
//! system state at capture time.

use pulse_core::Snapshot;
use std::path::Path;

fn load_fixture() -> Snapshot {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/snapshot.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse fixture: {}", e))
}

#[test]
fn fixture_loads_successfully() {
    let s = load_fixture();
    assert!(!s.hostname.is_empty(), "fixture has hostname");
    assert!(!s.version.is_empty(), "fixture has version");
}

#[test]
fn computed_root_is_64_hex_chars() {
    let s = load_fixture();
    let h = s.merkle_root_hex();
    assert_eq!(h.len(), 64, "expected 64 hex chars, got {}", h.len());
    assert!(
        h.chars().all(|c| c.is_ascii_hexdigit()),
        "non-hex chars in {}",
        h
    );
}

#[test]
fn computed_root_is_deterministic() {
    let s = load_fixture();
    assert_eq!(s.merkle_root_hex(), s.merkle_root_hex());
}

#[test]
fn leaves_are_not_empty() {
    let s = load_fixture();
    // At minimum: 1 system + 1 cron + N users + N procs + N mods + N nets
    let leaves = s.merkle_leaves();
    assert!(
        leaves.len() >= 3,
        "expected at least 3 leaves, got {}",
        leaves.len()
    );
}

#[test]
fn changing_a_process_does_not_change_root() {
    // Processes are deliberately excluded from the merkle root.
    // See the doc comment on `merkle_leaves` for the rationale.
    let s1 = load_fixture();
    let mut s2 = s1.clone();
    if let Some(first) = s2.processes.first().cloned() {
        let mut modified = first;
        modified.pid = 9_999_999;
        s2.processes.push(modified);
        assert_eq!(
            s1.merkle_root_hex(),
            s2.merkle_root_hex(),
            "processes are excluded; adding one must not change the root"
        );
    }
}

#[test]
fn changing_a_user_changes_root() {
    let s1 = load_fixture();
    let mut s2 = s1.clone();
    if let Some(first) = s2.users.users.first().cloned() {
        let mut modified = first;
        modified.shell = "/bin/false".into();
        s2.users.users.push(modified);
        assert_ne!(
            s1.merkle_root_hex(),
            s2.merkle_root_hex(),
            "adding a user must change the root"
        );
    }
}

#[test]
fn changing_a_module_changes_root() {
    let s1 = load_fixture();
    let mut s2 = s1.clone();
    if let Some(first) = s2.modules.first().cloned() {
        let mut modified = first;
        modified.refs = modified.refs.wrapping_add(1);
        s2.modules.push(modified);
        assert_ne!(
            s1.merkle_root_hex(),
            s2.merkle_root_hex(),
            "adding a module must change the root"
        );
    }
}

#[test]
fn reordered_users_produce_same_root() {
    let s1 = load_fixture();
    let mut s2 = s1.clone();
    s2.users.users.reverse();
    assert_eq!(
        s1.merkle_root_hex(),
        s2.merkle_root_hex(),
        "reordering users must not change the root"
    );
}
