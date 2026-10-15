//! Real tests for `pulse-core/src/snapshot.rs`.
//!
//! Exercises render_summary, diff (all 5 categories), both renderers,
//! and the Merkle root computation. No mocks.

use pulse_core::snapshot::*;
use pulse_platform::{
    CoreInfo, CpuInfo, CronInfo, DriverModule, EnvEntry, EnvInfo, MemoryInfo, NetInterface,
    NetworkInfo, ProcessEntry, SystemInfo, UserEntry, UsersInfo,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn sys(hostname: &str, kernel: &str) -> SystemInfo {
    SystemInfo {
        os_name: "Linux".into(),
        os_version: "1.0".into(),
        kernel_version: kernel.into(),
        hostname: hostname.into(),
        uptime_seconds: 3600,
        boot_time_unix: 1_700_000_000,
        architecture: "aarch64".into(),
        pointer_width: 64,
        endianness: "little".into(),
    }
}

fn cpu() -> CpuInfo {
    CpuInfo {
        model: "Test".into(),
        architecture: "aarch64".into(),
        cores: 1,
        features: vec![],
        per_core: vec![CoreInfo {
            id: 0,
            cur_freq_khz: Some(1_000_000),
            min_freq_khz: Some(100_000),
            max_freq_khz: Some(2_000_000),
            governor: Some("schedutil".into()),
        }],
    }
}

fn mem() -> MemoryInfo {
    MemoryInfo {
        total_kb: 8_000_000,
        free_kb: 4_000_000,
        available_kb: 6_000_000,
        buffers_kb: 100_000,
        cached_kb: 1_000_000,
        swap_total_kb: 0,
        swap_free_kb: 0,
    }
}

fn users(names: &[(&str, u32)]) -> UsersInfo {
    UsersInfo {
        users: names
            .iter()
            .map(|(n, uid)| UserEntry {
                name: (*n).into(),
                uid: *uid,
                gid: *uid,
                gecos: String::new(),
                home: format!("/home/{n}"),
                shell: "/bin/bash".into(),
            })
            .collect(),
        groups: vec![],
    }
}

fn proc(pid: u32, name: &str) -> ProcessEntry {
    ProcessEntry {
        pid,
        ppid: 1,
        name: name.into(),
        state: "S".into(),
        threads: 1,
        rss_pages: 100,
    }
}

fn module(name: &str, size: u64, deps: &[&str]) -> DriverModule {
    DriverModule {
        name: name.into(),
        size,
        refs: 0,
        deps: deps.iter().map(|s| (*s).to_string()).collect(),
        state: "Live".into(),
    }
}

fn net(name: &str, mac: Option<&str>, kind: Option<&str>) -> NetworkInfo {
    NetworkInfo {
        interfaces: vec![NetInterface {
            name: name.into(),
            mac: mac.map(String::from),
            state: None,
            mtu: None,
            kind: kind.map(String::from),
        }],
    }
}

fn net_multi(items: &[(&str, Option<&str>, Option<&str>)]) -> NetworkInfo {
    NetworkInfo {
        interfaces: items
            .iter()
            .map(|(n, m, k)| NetInterface {
                name: (*n).into(),
                mac: m.map(String::from),
                state: None,
                mtu: None,
                kind: k.map(String::from),
            })
            .collect(),
    }
}

fn cron_empty() -> CronInfo {
    CronInfo {
        has_etc_crontab: false,
        system_files: vec![],
        system_dirs: vec![],
        user_crontabs: vec![],
    }
}

fn env(entries: &[(&str, &str)]) -> EnvInfo {
    EnvInfo {
        total: entries.len() as u32,
        entries: entries
            .iter()
            .map(|(k, v)| EnvEntry {
                key: (*k).into(),
                value: (*v).into(),
            })
            .collect(),
    }
}

fn base_snapshot() -> Snapshot {
    Snapshot {
        version: "1.9.0".into(),
        timestamp: 1_700_000_000,
        hostname: "host-a".into(),
        system: sys("host-a", "6.1.138"),
        cpu: cpu(),
        memory: mem(),
        users: users(&[("root", 0)]),
        processes: vec![proc(1, "init")],
        modules: vec![module("mod1", 1000, &[])],
        network: net("eth0", Some("aa:bb:cc:dd:ee:ff"), Some("ethernet")),
        cron: cron_empty(),
        env: env(&[("PATH", "/usr/bin")]),
        merkle_root: String::new(),
    }
}

fn empty_snapshot() -> Snapshot {
    Snapshot {
        version: "1.9.0".into(),
        timestamp: 1_700_000_000,
        hostname: "empty".into(),
        system: sys("empty", "6.1.0"),
        cpu: cpu(),
        memory: mem(),
        users: UsersInfo {
            users: vec![],
            groups: vec![],
        },
        processes: vec![],
        modules: vec![],
        network: NetworkInfo { interfaces: vec![] },
        cron: cron_empty(),
        env: EnvInfo {
            total: 0,
            entries: vec![],
        },
        merkle_root: String::new(),
    }
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_includes_all_counts() {
    let s = base_snapshot();
    let out = s.render_summary();
    assert!(out.contains("Snapshot captured at unix 1700000000"));
    assert!(out.contains("version      : 1.9.0"));
    assert!(out.contains("hostname     : host-a"));
    assert!(out.contains("users        : 1"));
    assert!(out.contains("processes    : 1"));
    assert!(out.contains("modules      : 1"));
    assert!(out.contains("interfaces   : 1"));
    assert!(out.contains("env vars     : 1"));
}

#[test]
fn render_summary_empty_snapshot_zero_counts() {
    let s = empty_snapshot();
    let out = s.render_summary();
    assert!(out.contains("users        : 0"));
    assert!(out.contains("processes    : 0"));
    assert!(out.contains("modules      : 0"));
    assert!(out.contains("interfaces   : 0"));
    assert!(out.contains("env vars     : 0"));
}

// ---------------------------------------------------------------------------
// diff — processes
// ---------------------------------------------------------------------------

#[test]
fn diff_process_added() {
    let mut a = base_snapshot();
    a.processes = vec![proc(1, "init")];
    let mut b = base_snapshot();
    b.processes = vec![proc(1, "init"), proc(2, "kthreadd")];

    let r = diff(&a, &b);
    assert_eq!(r.summary.processes_added, 1);
    assert_eq!(r.summary.processes_removed, 0);
    assert!(r
        .changes
        .iter()
        .any(|c| c.category == "process" && c.kind == "added"));
}

#[test]
fn diff_process_removed() {
    let mut a = base_snapshot();
    a.processes = vec![proc(1, "init"), proc(2, "gone")];
    let mut b = base_snapshot();
    b.processes = vec![proc(1, "init")];

    let r = diff(&a, &b);
    assert_eq!(r.summary.processes_added, 0);
    assert_eq!(r.summary.processes_removed, 1);
    assert!(r
        .changes
        .iter()
        .any(|c| c.category == "process" && c.kind == "removed"));
}

#[test]
fn diff_process_no_change() {
    let a = base_snapshot();
    let b = base_snapshot();
    let r = diff(&a, &b);
    assert_eq!(r.summary.processes_added, 0);
    assert_eq!(r.summary.processes_removed, 0);
}

#[test]
fn diff_process_added_capped_at_20() {
    let mut a = base_snapshot();
    a.processes = vec![];
    let mut b = base_snapshot();
    b.processes = (1..=30).map(|i| proc(i, "p")).collect();

    let r = diff(&a, &b);
    assert_eq!(r.summary.processes_added, 30, "counter is total");
    let added_changes: Vec<_> = r
        .changes
        .iter()
        .filter(|c| c.category == "process" && c.kind == "added")
        .collect();
    assert_eq!(added_changes.len(), 20, "changes list capped at 20");
}

// ---------------------------------------------------------------------------
// diff — users
// ---------------------------------------------------------------------------

#[test]
fn diff_user_added() {
    let mut a = base_snapshot();
    a.users = users(&[("root", 0)]);
    let mut b = base_snapshot();
    b.users = users(&[("root", 0), ("omar", 1000)]);

    let r = diff(&a, &b);
    assert_eq!(r.summary.users_added, 1);
    assert!(r
        .changes
        .iter()
        .any(|c| c.category == "user" && c.kind == "added"));
}

#[test]
fn diff_user_removed() {
    let mut a = base_snapshot();
    a.users = users(&[("root", 0), ("old", 5000)]);
    let mut b = base_snapshot();
    b.users = users(&[("root", 0)]);

    let r = diff(&a, &b);
    assert_eq!(r.summary.users_removed, 1);
}

// ---------------------------------------------------------------------------
// diff — modules
// ---------------------------------------------------------------------------

#[test]
fn diff_module_added() {
    let mut a = base_snapshot();
    a.modules = vec![];
    let mut b = base_snapshot();
    b.modules = vec![module("newmod", 500, &[])];

    let r = diff(&a, &b);
    assert_eq!(r.summary.modules_added, 1);
    assert!(r
        .changes
        .iter()
        .any(|c| c.category == "module" && c.kind == "added"));
}

#[test]
fn diff_module_removed() {
    let mut a = base_snapshot();
    a.modules = vec![module("oldmod", 500, &[]), module("keep", 100, &[])];
    let mut b = base_snapshot();
    b.modules = vec![module("keep", 100, &[])];

    let r = diff(&a, &b);
    assert_eq!(r.summary.modules_removed, 1);
}

// ---------------------------------------------------------------------------
// diff — network
// ---------------------------------------------------------------------------

#[test]
fn diff_iface_added() {
    let mut a = base_snapshot();
    a.network = net("eth0", None, None);
    let mut b = base_snapshot();
    b.network = net_multi(&[
        ("eth0", None, None),
        ("wlan0", Some("11:22:33:44:55:66"), Some("wifi")),
    ]);

    let r = diff(&a, &b);
    assert_eq!(r.summary.ifaces_added, 1);
}

#[test]
fn diff_iface_removed() {
    let mut a = base_snapshot();
    a.network = net_multi(&[("eth0", None, None), ("eth1", None, None)]);
    let mut b = base_snapshot();
    b.network = net("eth0", None, None);

    let r = diff(&a, &b);
    assert_eq!(r.summary.ifaces_removed, 1);
}

// ---------------------------------------------------------------------------
// diff — env
// ---------------------------------------------------------------------------

#[test]
fn diff_env_added() {
    let mut a = base_snapshot();
    a.env = env(&[("PATH", "/bin")]);
    let mut b = base_snapshot();
    b.env = env(&[("PATH", "/bin"), ("HOME", "/root")]);

    let r = diff(&a, &b);
    assert_eq!(r.summary.env_added, 1);
    assert_eq!(r.summary.env_changed, 0);
    assert_eq!(r.summary.env_removed, 0);
}

#[test]
fn diff_env_removed() {
    let mut a = base_snapshot();
    a.env = env(&[("PATH", "/bin"), ("OLD", "x")]);
    let mut b = base_snapshot();
    b.env = env(&[("PATH", "/bin")]);

    let r = diff(&a, &b);
    assert_eq!(r.summary.env_removed, 1);
}

#[test]
fn diff_env_changed() {
    let mut a = base_snapshot();
    a.env = env(&[("PATH", "/bin")]);
    let mut b = base_snapshot();
    b.env = env(&[("PATH", "/usr/bin")]);

    let r = diff(&a, &b);
    assert_eq!(r.summary.env_changed, 1);
    assert_eq!(r.summary.env_added, 0);
    assert_eq!(r.summary.env_removed, 0);
    let ch = r
        .changes
        .iter()
        .find(|c| c.category == "env" && c.kind == "changed")
        .unwrap();
    assert!(ch.detail.as_ref().unwrap().contains("old=/bin"));
    assert!(ch.detail.as_ref().unwrap().contains("new=/usr/bin"));
}

// ---------------------------------------------------------------------------
// diff — metadata
// ---------------------------------------------------------------------------

#[test]
fn diff_metadata_from_to_hostnames() {
    let mut a = base_snapshot();
    a.hostname = "host-a".into();
    a.timestamp = 1000;
    let mut b = base_snapshot();
    b.hostname = "host-b".into();
    b.timestamp = 1500;

    let r = diff(&a, &b);
    assert_eq!(r.from_hostname, "host-a");
    assert_eq!(r.to_hostname, "host-b");
    assert_eq!(r.from_timestamp, 1000);
    assert_eq!(r.to_timestamp, 1500);
    assert_eq!(r.elapsed_secs, 500);
}

#[test]
fn diff_elapsed_secs_saturates_on_negative() {
    let mut a = base_snapshot();
    a.timestamp = 2000;
    let mut b = base_snapshot();
    b.timestamp = 1000;

    let r = diff(&a, &b);
    assert_eq!(r.elapsed_secs, 0, "saturating_sub must yield 0");
}

#[test]
fn diff_total_changes_matches_summary() {
    let mut a = base_snapshot();
    a.processes = vec![proc(1, "init")];
    a.env = env(&[("PATH", "/bin")]);
    let mut b = base_snapshot();
    b.processes = vec![proc(1, "init"), proc(2, "new")];
    b.env = env(&[("PATH", "/usr/bin"), ("HOME", "/root")]);

    let r = diff(&a, &b);
    let sum = r.summary.processes_added
        + r.summary.processes_removed
        + r.summary.users_added
        + r.summary.users_removed
        + r.summary.modules_added
        + r.summary.modules_removed
        + r.summary.ifaces_added
        + r.summary.ifaces_removed
        + r.summary.env_added
        + r.summary.env_removed
        + r.summary.env_changed;
    assert_eq!(r.summary.total_changes, sum);
}

// ---------------------------------------------------------------------------
// DiffReport render_text
// ---------------------------------------------------------------------------

#[test]
fn render_text_empty_diff_reports_no_changes() {
    let a = base_snapshot();
    let b = base_snapshot();
    let r = diff(&a, &b);
    let s = r.render_text();
    assert!(s.contains("=== PULSE DIFF ==="));
    assert!(s.contains("No changes detected."));
}

#[test]
fn render_text_with_changes_has_sections() {
    let mut a = base_snapshot();
    a.processes = vec![];
    a.env = env(&[("PATH", "/bin")]);
    let mut b = base_snapshot();
    b.processes = vec![proc(99, "newproc")];
    b.env = env(&[("PATH", "/usr/bin"), ("HOME", "/root")]);

    let r = diff(&a, &b);
    let s = r.render_text();
    assert!(s.contains("[PROCESS]"));
    assert!(s.contains("[ENV]"));
    assert!(s.contains("[SUMMARY]"));
    assert!(s.contains("+"));
    assert!(s.contains("~"), "changed marker must be present");
}

#[test]
fn render_text_empty_diff_omits_summary_section() {
    // When there are no changes, render_text returns early and
    // does NOT print the [SUMMARY] section.
    let a = base_snapshot();
    let b = base_snapshot();
    let r = diff(&a, &b);
    let s = r.render_text();
    assert!(s.contains("No changes detected."));
    assert!(
        !s.contains("[SUMMARY]"),
        "summary must be omitted on empty diff"
    );
}

#[test]
fn render_text_with_changes_includes_summary() {
    let mut a = base_snapshot();
    a.processes = vec![];
    let mut b = base_snapshot();
    b.processes = vec![proc(99, "p")];
    let r = diff(&a, &b);
    let s = r.render_text();
    assert!(s.contains("[SUMMARY]"));
    assert!(s.contains("processes : +1 -0"));
}

// ---------------------------------------------------------------------------
// DiffReport render_markdown
// ---------------------------------------------------------------------------

#[test]
fn render_markdown_empty_diff() {
    let a = base_snapshot();
    let b = base_snapshot();
    let r = diff(&a, &b);
    let s = r.render_markdown();
    assert!(s.contains("# Pulse Diff"));
    assert!(s.contains("_No changes detected._"));
}

#[test]
fn render_markdown_with_changes_has_tables() {
    let mut a = base_snapshot();
    a.processes = vec![];
    let mut b = base_snapshot();
    b.processes = vec![proc(99, "p")];

    let r = diff(&a, &b);
    let s = r.render_markdown();
    assert!(s.contains("## Changes"));
    assert!(s.contains("| Category | Kind | Item | Detail |"));
    assert!(s.contains("## Summary"));
    assert!(s.contains("| Processes |"));
    assert!(s.contains("| Users |"));
    assert!(s.contains("| Modules |"));
    assert!(s.contains("| Network |"));
    assert!(s.contains("| Env |"));
}

// ---------------------------------------------------------------------------
// Merkle — determinism
// ---------------------------------------------------------------------------

#[test]
fn merkle_leaves_non_empty_for_base_snapshot() {
    let s = base_snapshot();
    assert!(!s.merkle_leaves().is_empty());
    assert!(!s.merkle_leaves_labeled().is_empty());
}

#[test]
fn merkle_root_hex_is_64_chars() {
    let s = base_snapshot();
    let h = s.merkle_root_hex();
    assert_eq!(h.len(), 64, "hex length must be 64");
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn merkle_root_is_deterministic() {
    let s = base_snapshot();
    assert_eq!(s.merkle_root_hex(), s.merkle_root_hex());
}

#[test]
fn merkle_root_changes_when_hostname_changes() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.system.hostname = "different-host".into();
    assert_ne!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_changes_when_user_changes() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.users = users(&[("root", 0), ("newuser", 1000)]);
    assert_ne!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_changes_when_module_changes() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.modules.push(module("extra", 999, &[]));
    assert_ne!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_changes_when_network_mac_changes() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.network = net("eth0", Some("11:11:11:11:11:11"), Some("ethernet"));
    assert_ne!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_changes_when_cron_changes() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.cron.has_etc_crontab = true;
    b.cron.system_files.push("/etc/cron.d/x".into());
    assert_ne!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_process_changes() {
    // Process list is explicitly excluded.
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.processes = vec![proc(1, "init"), proc(42, "new"), proc(99, "extra")];
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_env_changes() {
    // Env is excluded.
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.env = env(&[("NEW", "x")]);
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_cpu_freq() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.cpu.per_core[0].cur_freq_khz = Some(9_999_999);
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_memory_change() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.memory.free_kb = 999;
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_timestamp() {
    let a = base_snapshot();
    let mut b = base_snapshot();
    b.timestamp = 9_999_999_999;
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_user_order() {
    // Users must be sorted internally → reordering yields same root.
    let mut a = base_snapshot();
    a.users = users(&[("root", 0), ("omar", 1000), ("guest", 5000)]);
    let mut b = base_snapshot();
    b.users = users(&[("guest", 5000), ("omar", 1000), ("root", 0)]);
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_root_is_insensitive_to_module_deps_order() {
    let mut a = base_snapshot();
    a.modules = vec![module("m", 100, &["a", "b", "c"])];
    let mut b = base_snapshot();
    b.modules = vec![module("m", 100, &["c", "b", "a"])];
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}

#[test]
fn merkle_leaves_count_matches_expected() {
    // 1 (sys) + 1 (root user) + 1 (module) + 1 (net) + 1 (cron) = 5
    let s = base_snapshot();
    assert_eq!(s.merkle_leaves().len(), 5);
}

#[test]
fn merkle_leaves_labeled_has_expected_labels() {
    let s = base_snapshot();
    let labels: Vec<String> = s
        .merkle_leaves_labeled()
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert!(labels.iter().any(|l| l.starts_with("sys:")));
    assert!(labels.iter().any(|l| l.starts_with("user:")));
    assert!(labels.iter().any(|l| l.starts_with("mod:")));
    assert!(labels.iter().any(|l| l.starts_with("net:")));
    assert!(labels.iter().any(|l| l == "cron"));
}

#[test]
fn merkle_leaves_labeled_hashes_match_merkle_leaves() {
    let s = base_snapshot();
    let plain = s.merkle_leaves();
    let labeled = s.merkle_leaves_labeled();
    assert_eq!(plain.len(), labeled.len());
    for (i, (_, h)) in labeled.iter().enumerate() {
        assert_eq!(*h, plain[i], "leaf {i} mismatch");
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

#[test]
fn snapshot_serializes_and_deserializes() {
    let s = base_snapshot();
    let json = serde_json::to_string(&s).expect("serialize");
    let back: Snapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.hostname, s.hostname);
    assert_eq!(back.version, s.version);
    assert_eq!(back.processes.len(), s.processes.len());
}

#[test]
fn snapshot_deserializes_without_merkle_root_field() {
    // merkle_root has #[serde(default)] — old snapshots must still load.
    let mut s = base_snapshot();
    s.merkle_root = String::new();
    let mut v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("merkle_root");
    let back: Snapshot = serde_json::from_value(v).expect("must deserialize without merkle_root");
    assert_eq!(back.merkle_root, "");
}

#[test]
fn diff_report_serializes_to_json() {
    let a = base_snapshot();
    let b = base_snapshot();
    let r = diff(&a, &b);
    let json = serde_json::to_string(&r).expect("serialize");
    assert!(json.contains("\"from_timestamp\""));
    assert!(json.contains("\"summary\""));
    assert!(json.contains("\"changes\""));
}
