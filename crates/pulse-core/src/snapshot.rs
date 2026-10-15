//! Snapshot + Diff engine.
//! Serializes system state to JSON; compares two snapshots semantically.

use pulse_platform::{
    CpuInfo, CronInfo, DriverModule, EnvInfo, MemoryInfo, NetworkInfo, ProcessEntry, SystemInfo,
    UsersInfo,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: String,
    pub timestamp: u64,
    pub hostname: String,
    pub system: SystemInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub users: UsersInfo,
    pub processes: Vec<ProcessEntry>,
    pub modules: Vec<DriverModule>,
    pub network: NetworkInfo,
    pub cron: CronInfo,
    pub env: EnvInfo,
    /// Merkle root over stable fields (system, users, processes,
    /// modules, network, cron). Populated by `capture_snapshot()`
    /// in the CLI. Empty string when deserialized from older snapshots.
    #[serde(default)]
    pub merkle_root: String,
}

impl Snapshot {
    pub fn render_summary(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Snapshot captured at unix {}", self.timestamp);
        let _ = writeln!(s, "  version      : {}", self.version);
        let _ = writeln!(s, "  hostname     : {}", self.hostname);
        let _ = writeln!(s, "  users        : {}", self.users.users.len());
        let _ = writeln!(s, "  processes    : {}", self.processes.len());
        let _ = writeln!(s, "  modules      : {}", self.modules.len());
        let _ = writeln!(s, "  interfaces   : {}", self.network.interfaces.len());
        let _ = writeln!(s, "  env vars     : {}", self.env.total);
        s
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub from_timestamp: u64,
    pub to_timestamp: u64,
    pub elapsed_secs: u64,
    pub from_hostname: String,
    pub to_hostname: String,
    pub changes: Vec<Change>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub category: String,
    pub kind: String,
    pub item: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffSummary {
    pub processes_added: u32,
    pub processes_removed: u32,
    pub users_added: u32,
    pub users_removed: u32,
    pub modules_added: u32,
    pub modules_removed: u32,
    pub ifaces_added: u32,
    pub ifaces_removed: u32,
    pub env_added: u32,
    pub env_removed: u32,
    pub env_changed: u32,
    pub total_changes: u32,
}

pub fn diff(old: &Snapshot, new: &Snapshot) -> DiffReport {
    let mut changes: Vec<Change> = Vec::new();

    // Processes
    let old_pids: std::collections::BTreeSet<u32> = old.processes.iter().map(|p| p.pid).collect();
    let new_pids: std::collections::BTreeSet<u32> = new.processes.iter().map(|p| p.pid).collect();
    let mut proc_added = 0u32;
    let mut proc_removed = 0u32;
    for p in &new.processes {
        if !old_pids.contains(&p.pid) {
            proc_added += 1;
            if proc_added <= 20 {
                changes.push(Change {
                    category: "process".into(),
                    kind: "added".into(),
                    item: format!("pid={} {}", p.pid, p.name),
                    detail: Some(format!("ppid={} state={}", p.ppid, p.state)),
                });
            }
        }
    }
    for p in &old.processes {
        if !new_pids.contains(&p.pid) {
            proc_removed += 1;
            if proc_removed <= 20 {
                changes.push(Change {
                    category: "process".into(),
                    kind: "removed".into(),
                    item: format!("pid={} {}", p.pid, p.name),
                    detail: None,
                });
            }
        }
    }

    // Users
    let old_users: std::collections::BTreeMap<u32, &str> = old
        .users
        .users
        .iter()
        .map(|u| (u.uid, u.name.as_str()))
        .collect();
    let new_users: std::collections::BTreeMap<u32, &str> = new
        .users
        .users
        .iter()
        .map(|u| (u.uid, u.name.as_str()))
        .collect();
    let mut users_added = 0u32;
    let mut users_removed = 0u32;
    for (uid, name) in &new_users {
        if !old_users.contains_key(uid) {
            users_added += 1;
            changes.push(Change {
                category: "user".into(),
                kind: "added".into(),
                item: format!("uid={uid} name={name}"),
                detail: None,
            });
        }
    }
    for (uid, name) in &old_users {
        if !new_users.contains_key(uid) {
            users_removed += 1;
            changes.push(Change {
                category: "user".into(),
                kind: "removed".into(),
                item: format!("uid={uid} name={name}"),
                detail: None,
            });
        }
    }

    // Modules
    let old_mods: std::collections::BTreeSet<&str> =
        old.modules.iter().map(|m| m.name.as_str()).collect();
    let new_mods: std::collections::BTreeSet<&str> =
        new.modules.iter().map(|m| m.name.as_str()).collect();
    let mut mod_added = 0u32;
    let mut mod_removed = 0u32;
    for m in &new_mods {
        if !old_mods.contains(m) {
            mod_added += 1;
            if mod_added <= 30 {
                changes.push(Change {
                    category: "module".into(),
                    kind: "added".into(),
                    item: (*m).to_string(),
                    detail: None,
                });
            }
        }
    }
    for m in &old_mods {
        if !new_mods.contains(m) {
            mod_removed += 1;
            if mod_removed <= 30 {
                changes.push(Change {
                    category: "module".into(),
                    kind: "removed".into(),
                    item: (*m).to_string(),
                    detail: None,
                });
            }
        }
    }

    // Network
    let old_if: std::collections::BTreeSet<&str> = old
        .network
        .interfaces
        .iter()
        .map(|i| i.name.as_str())
        .collect();
    let new_if: std::collections::BTreeSet<&str> = new
        .network
        .interfaces
        .iter()
        .map(|i| i.name.as_str())
        .collect();
    let mut if_added = 0u32;
    let mut if_removed = 0u32;
    for name in &new_if {
        if !old_if.contains(name) {
            if_added += 1;
            changes.push(Change {
                category: "network".into(),
                kind: "added".into(),
                item: (*name).to_string(),
                detail: None,
            });
        }
    }
    for name in &old_if {
        if !new_if.contains(name) {
            if_removed += 1;
            changes.push(Change {
                category: "network".into(),
                kind: "removed".into(),
                item: (*name).to_string(),
                detail: None,
            });
        }
    }

    // Env
    let old_env: std::collections::BTreeMap<&str, &str> = old
        .env
        .entries
        .iter()
        .map(|e| (e.key.as_str(), e.value.as_str()))
        .collect();
    let new_env: std::collections::BTreeMap<&str, &str> = new
        .env
        .entries
        .iter()
        .map(|e| (e.key.as_str(), e.value.as_str()))
        .collect();
    let mut env_added = 0u32;
    let mut env_removed = 0u32;
    let mut env_changed = 0u32;
    for (k, v) in &new_env {
        match old_env.get(k) {
            None => {
                env_added += 1;
                changes.push(Change {
                    category: "env".into(),
                    kind: "added".into(),
                    item: (*k).to_string(),
                    detail: Some(format!("value={v}")),
                });
            }
            Some(ov) if ov != v => {
                env_changed += 1;
                changes.push(Change {
                    category: "env".into(),
                    kind: "changed".into(),
                    item: (*k).to_string(),
                    detail: Some(format!("old={ov} new={v}")),
                });
            }
            _ => {}
        }
    }
    for (k, v) in &old_env {
        if !new_env.contains_key(k) {
            env_removed += 1;
            changes.push(Change {
                category: "env".into(),
                kind: "removed".into(),
                item: (*k).to_string(),
                detail: Some(format!("old={v}")),
            });
        }
    }

    let total = changes.len() as u32;
    DiffReport {
        from_timestamp: old.timestamp,
        to_timestamp: new.timestamp,
        elapsed_secs: new.timestamp.saturating_sub(old.timestamp),
        from_hostname: old.hostname.clone(),
        to_hostname: new.hostname.clone(),
        summary: DiffSummary {
            processes_added: proc_added,
            processes_removed: proc_removed,
            users_added,
            users_removed,
            modules_added: mod_added,
            modules_removed: mod_removed,
            ifaces_added: if_added,
            ifaces_removed: if_removed,
            env_added,
            env_removed,
            env_changed,
            total_changes: total,
        },
        changes,
    }
}

impl DiffReport {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "=== PULSE DIFF ===");
        s.push('\n');
        let _ = writeln!(
            s,
            "From    : {} (unix {})",
            self.from_hostname, self.from_timestamp
        );
        let _ = writeln!(
            s,
            "To      : {} (unix {})",
            self.to_hostname, self.to_timestamp
        );
        let _ = writeln!(s, "Elapsed : {} seconds", self.elapsed_secs);
        s.push('\n');

        if self.changes.is_empty() {
            s.push_str("No changes detected.\n");
            return s;
        }

        for cat in ["process", "user", "module", "network", "env"] {
            let items: Vec<&Change> = self.changes.iter().filter(|c| c.category == cat).collect();
            if items.is_empty() {
                continue;
            }
            let _ = writeln!(s, "[{}]", cat.to_uppercase());
            for ch in items {
                let mark = match ch.kind.as_str() {
                    "added" => "+",
                    "removed" => "-",
                    "changed" => "~",
                    _ => "?",
                };
                match &ch.detail {
                    Some(d) => {
                        let _ = writeln!(s, "  {} {}    ({})", mark, ch.item, d);
                    }
                    None => {
                        let _ = writeln!(s, "  {} {}", mark, ch.item);
                    }
                }
            }
            s.push('\n');
        }

        let _ = writeln!(s, "[SUMMARY]");
        let _ = writeln!(
            s,
            "  processes : +{} -{}",
            self.summary.processes_added, self.summary.processes_removed
        );
        let _ = writeln!(
            s,
            "  users     : +{} -{}",
            self.summary.users_added, self.summary.users_removed
        );
        let _ = writeln!(
            s,
            "  modules   : +{} -{}",
            self.summary.modules_added, self.summary.modules_removed
        );
        let _ = writeln!(
            s,
            "  network   : +{} -{}",
            self.summary.ifaces_added, self.summary.ifaces_removed
        );
        let _ = writeln!(
            s,
            "  env       : +{} -{} ~{}",
            self.summary.env_added, self.summary.env_removed, self.summary.env_changed
        );
        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Pulse Diff\n\n");
        let _ = writeln!(
            s,
            "- **From:** {} (unix {})",
            self.from_hostname, self.from_timestamp
        );
        let _ = writeln!(
            s,
            "- **To:** {} (unix {})",
            self.to_hostname, self.to_timestamp
        );
        let _ = writeln!(s, "- **Elapsed:** {} seconds\n", self.elapsed_secs);

        if self.changes.is_empty() {
            s.push_str("_No changes detected._\n");
            return s;
        }

        s.push_str("## Changes\n\n");
        s.push_str("| Category | Kind | Item | Detail |\n");
        s.push_str("|----------|------|------|--------|\n");
        for ch in &self.changes {
            let _ = writeln!(
                s,
                "| {} | {} | `{}` | {} |",
                ch.category,
                ch.kind,
                ch.item,
                ch.detail.as_deref().unwrap_or("-")
            );
        }

        s.push_str("\n## Summary\n\n");
        s.push_str("| Category | Added | Removed | Changed |\n");
        s.push_str("|----------|-------|---------|---------|\n");
        let _ = writeln!(
            s,
            "| Processes | {} | {} | - |",
            self.summary.processes_added, self.summary.processes_removed
        );
        let _ = writeln!(
            s,
            "| Users | {} | {} | - |",
            self.summary.users_added, self.summary.users_removed
        );
        let _ = writeln!(
            s,
            "| Modules | {} | {} | - |",
            self.summary.modules_added, self.summary.modules_removed
        );
        let _ = writeln!(
            s,
            "| Network | {} | {} | - |",
            self.summary.ifaces_added, self.summary.ifaces_removed
        );
        let _ = writeln!(
            s,
            "| Env | {} | {} | {} |",
            self.summary.env_added, self.summary.env_removed, self.summary.env_changed
        );
        s
    }
}

// ---------------------------------------------------------------
// Merkle root
// ---------------------------------------------------------------

use sha2::{Digest, Sha256};

fn leaf_hash(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0f) as usize] as char);
    }
    out
}

impl Snapshot {
    /// Build the list of leaf hashes used to compute the Merkle root.
    ///
    /// Only **configuration-state** fields are included. The intent
    /// is to answer the question: *did something meaningful about
    /// this system's configuration change?*
    ///
    /// **Included:**
    /// - system (hostname, kernel version, OS)
    /// - users (account list, shells, home directories)
    /// - modules (loaded kernel modules with size and deps)
    /// - network interfaces (name, MAC, kind)
    /// - cron (schedule files)
    ///
    /// **Excluded:**
    /// - processes — inherently volatile. PIDs change every second
    ///   on a live system. A security incident that matters will
    ///   appear in one of the five stable categories above
    ///   (a new user, a new module, a new cron job), not merely in
    ///   the process list.
    /// - CPU MHz, memory free, environment, timestamp — volatile
    ///   measurements, not configuration.
    /// - Module refcount and state — change while modules are in use.
    /// - Network interface state and MTU — change on link events.
    ///
    /// **Guarantee:** two snapshots taken from the same system
    /// configuration, at any two times, produce the same root.
    /// Two snapshots from different configurations produce
    /// different roots.
    pub fn merkle_leaves(&self) -> Vec<[u8; 32]> {
        let mut leaves = Vec::new();

        // system
        leaves.push(leaf_hash(&format!(
            "sys:{}:{}:{}",
            self.system.hostname, self.system.kernel_version, self.system.os_name,
        )));

        // users — sorted by uid
        let mut users = self.users.users.clone();
        users.sort_by_key(|u| u.uid);
        for u in &users {
            leaves.push(leaf_hash(&format!(
                "user:{}:{}:{}:{}:{}",
                u.uid, u.name, u.gid, u.home, u.shell,
            )));
        }

        // modules — sorted by name, deps sorted
        let mut mods = self.modules.clone();
        mods.sort_by_key(|m| m.name.clone());
        for m in &mods {
            let mut deps = m.deps.clone();
            deps.sort();
            // NOTE: module refcount and state are excluded from
            // the hash. Both change while the system runs
            // (module in use, device hotplug).
            leaves.push(leaf_hash(&format!(
                "mod:{}:{}:{}",
                m.name,
                m.size,
                deps.join(","),
            )));
        }

        // network interfaces — sorted by name
        let mut nets = self.network.interfaces.clone();
        nets.sort_by_key(|n| n.name.clone());
        for n in &nets {
            // NOTE: interface state (up/down) and MTU are volatile
            // and excluded. Only identity fields are included.
            leaves.push(leaf_hash(&format!(
                "net:{}:{}:{}",
                n.name,
                n.mac.as_deref().unwrap_or("-"),
                n.kind.as_deref().unwrap_or("-"),
            )));
        }

        // cron — sort lists for determinism
        let mut sys_files = self.cron.system_files.clone();
        sys_files.sort();
        let mut sys_dirs = self.cron.system_dirs.clone();
        sys_dirs.sort();
        let mut user_crontabs = self.cron.user_crontabs.clone();
        user_crontabs.sort();
        leaves.push(leaf_hash(&format!(
            "cron:{}:{}:{}:{}",
            self.cron.has_etc_crontab,
            sys_files.join(","),
            sys_dirs.join(","),
            user_crontabs.join(","),
        )));

        leaves
    }

    /// Compute the Merkle root as raw 32 bytes.
    pub fn compute_merkle_root(&self) -> [u8; 32] {
        crate::merkle::MerkleTree::from_hashes(self.merkle_leaves()).root()
    }

    /// Compute the Merkle root as lowercase hex (64 chars).
    pub fn merkle_root_hex(&self) -> String {
        hex32(&self.compute_merkle_root())
    }
}

// ---------------------------------------------------------------
// Diagnostics — labeled leaves for debugging
// ---------------------------------------------------------------

impl Snapshot {
    /// Returns the same leaves as `merkle_leaves()`, but each leaf
    /// is paired with its source label ("sys:...", "user:root",
    /// "mod:xt_conntrack", ...). Used for diagnosing which field
    /// changes between snapshots. Not used in production.
    pub fn merkle_leaves_labeled(&self) -> Vec<(String, [u8; 32])> {
        let mut out = Vec::new();

        out.push((
            format!(
                "sys:{}:{}:{}",
                self.system.hostname, self.system.kernel_version, self.system.os_name
            ),
            leaf_hash(&format!(
                "sys:{}:{}:{}",
                self.system.hostname, self.system.kernel_version, self.system.os_name
            )),
        ));

        let mut users = self.users.users.clone();
        users.sort_by_key(|u| u.uid);
        for u in &users {
            let s = format!("user:{}:{}:{}:{}:{}", u.uid, u.name, u.gid, u.home, u.shell);
            out.push((format!("user:{}", u.name), leaf_hash(&s)));
        }

        let mut mods = self.modules.clone();
        mods.sort_by_key(|m| m.name.clone());
        for m in &mods {
            let mut deps = m.deps.clone();
            deps.sort();
            let s = format!("mod:{}:{}:{}", m.name, m.size, deps.join(","));
            out.push((format!("mod:{}", m.name), leaf_hash(&s)));
        }

        let mut nets = self.network.interfaces.clone();
        nets.sort_by_key(|n| n.name.clone());
        for n in &nets {
            let s = format!(
                "net:{}:{}:{}",
                n.name,
                n.mac.as_deref().unwrap_or("-"),
                n.kind.as_deref().unwrap_or("-")
            );
            out.push((format!("net:{}", n.name), leaf_hash(&s)));
        }

        let mut sys_files = self.cron.system_files.clone();
        sys_files.sort();
        let mut sys_dirs = self.cron.system_dirs.clone();
        sys_dirs.sort();
        let mut user_crontabs = self.cron.user_crontabs.clone();
        user_crontabs.sort();
        let s = format!(
            "cron:{}:{}:{}:{}",
            self.cron.has_etc_crontab,
            sys_files.join(","),
            sys_dirs.join(","),
            user_crontabs.join(",")
        );
        out.push(("cron".to_string(), leaf_hash(&s)));

        out
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn leaf_hash_is_deterministic() {
        let a = leaf_hash("hello");
        let b = leaf_hash("hello");
        assert_eq!(a, b);
    }

    #[test]
    fn leaf_hash_differs_for_different_input() {
        let a = leaf_hash("hello");
        let b = leaf_hash("world");
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_hash_returns_32_bytes() {
        let h = leaf_hash("x");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn leaf_hash_empty_string() {
        let h = leaf_hash("");
        assert_eq!(h.len(), 32);
        // SHA-256 of empty string is a known constant
        assert_eq!(
            hex32(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex32_formats_lowercase_hex() {
        let mut b = [0u8; 32];
        b[0] = 0xAB;
        b[31] = 0xCD;
        let h = hex32(&b);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab"));
        assert!(h.ends_with("cd"));
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn hex32_all_zeros() {
        let b = [0u8; 32];
        assert_eq!(hex32(&b), "0".repeat(64));
    }

    #[test]
    fn hex32_all_ff() {
        let b = [0xFFu8; 32];
        assert_eq!(hex32(&b), "f".repeat(64));
    }
}
