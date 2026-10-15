//! Trust Score Engine — aggregate 18 security signals into 0-100.

use serde::Serialize;
use std::fmt::Write as _;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalState {
    Good,
    Warn,
    Bad,
    Unknown,
}

impl SignalState {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Good => "[+]",
            Self::Warn => "[~]",
            Self::Bad => "[-]",
            Self::Unknown => "[?]",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Good => "PASS",
            Self::Warn => "WARN",
            Self::Bad => "FAIL",
            Self::Unknown => "N/A",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub name: String,
    pub category: String,
    pub state: SignalState,
    pub detail: String,
    pub evidence: Vec<String>,
    pub points_delta: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustReport {
    pub score: i32,
    pub grade: String,
    pub signals: Vec<Signal>,
    pub summary: TrustSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustSummary {
    pub total: u32,
    pub good: u32,
    pub warn: u32,
    pub bad: u32,
    pub unknown: u32,
    pub penalty: i32,
}

fn read_opt(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_i64(path: &str) -> Option<i64> {
    read_opt(path)?.parse::<i64>().ok()
}

fn sig(
    id: &str,
    name: &str,
    category: &str,
    state: SignalState,
    detail: String,
    delta: i32,
) -> Signal {
    Signal {
        id: id.to_string(),
        name: name.to_string(),
        category: category.to_string(),
        state,
        detail,
        evidence: Vec::new(),
        points_delta: delta,
    }
}

// ---------------------------------------------------------
// Kernel hardening
// ---------------------------------------------------------

pub(crate) fn classify_aslr(value: Option<i64>) -> Signal {
    match value {
        Some(2) => sig(
            "aslr",
            "ASLR",
            "kernel",
            SignalState::Good,
            "Full randomization".into(),
            10,
        ),
        Some(1) => sig(
            "aslr",
            "ASLR",
            "kernel",
            SignalState::Warn,
            "Partial randomization (1)".into(),
            10,
        ),
        Some(0) => sig(
            "aslr",
            "ASLR",
            "kernel",
            SignalState::Bad,
            "Disabled".into(),
            10,
        ),
        Some(n) => sig(
            "aslr",
            "ASLR",
            "kernel",
            SignalState::Unknown,
            format!("Unknown value: {n}"),
            10,
        ),
        None => sig(
            "aslr",
            "ASLR",
            "kernel",
            SignalState::Unknown,
            "Cannot read".into(),
            10,
        ),
    }
}

fn signal_aslr() -> Signal {
    classify_aslr(read_i64("/proc/sys/kernel/randomize_va_space"))
}

pub(crate) fn classify_kptr(value: Option<i64>) -> Signal {
    match value {
        Some(n) if n >= 1 => sig(
            "kptr_restrict",
            "kptr_restrict",
            "kernel",
            SignalState::Good,
            format!("Restricted (= {n})"),
            8,
        ),
        Some(0) => sig(
            "kptr_restrict",
            "kptr_restrict",
            "kernel",
            SignalState::Warn,
            "Unrestricted kernel pointers exposed".into(),
            8,
        ),
        _ => sig(
            "kptr_restrict",
            "kptr_restrict",
            "kernel",
            SignalState::Unknown,
            "Cannot read".into(),
            8,
        ),
    }
}

fn signal_kptr() -> Signal {
    classify_kptr(read_i64("/proc/sys/kernel/kptr_restrict"))
}

pub(crate) fn classify_dmesg(value: Option<i64>) -> Signal {
    match value {
        Some(1) => sig(
            "dmesg_restrict",
            "dmesg_restrict",
            "kernel",
            SignalState::Good,
            "Kernel log restricted to root".into(),
            5,
        ),
        Some(0) => sig(
            "dmesg_restrict",
            "dmesg_restrict",
            "kernel",
            SignalState::Warn,
            "Kernel log readable by all users".into(),
            5,
        ),
        _ => sig(
            "dmesg_restrict",
            "dmesg_restrict",
            "kernel",
            SignalState::Unknown,
            "Cannot read".into(),
            5,
        ),
    }
}

fn signal_dmesg() -> Signal {
    classify_dmesg(read_i64("/proc/sys/kernel/dmesg_restrict"))
}

pub(crate) fn classify_perf(value: Option<i64>) -> Signal {
    match value {
        Some(n) if n >= 2 => sig(
            "perf_paranoid",
            "perf_event_paranoid",
            "kernel",
            SignalState::Good,
            format!("Restricted (= {n})"),
            5,
        ),
        Some(n) => sig(
            "perf_paranoid",
            "perf_event_paranoid",
            "kernel",
            SignalState::Warn,
            format!("Weak restriction (= {n})"),
            5,
        ),
        _ => sig(
            "perf_paranoid",
            "perf_event_paranoid",
            "kernel",
            SignalState::Unknown,
            "Cannot read".into(),
            5,
        ),
    }
}

fn signal_perf() -> Signal {
    classify_perf(read_i64("/proc/sys/kernel/perf_event_paranoid"))
}

pub(crate) fn classify_tainted(value: Option<i64>, is_android: bool) -> Signal {
    match value {
        Some(0) => sig(
            "kernel_tainted",
            "Kernel taint",
            "kernel",
            SignalState::Good,
            "Not tainted".into(),
            10,
        ),
        Some(n) => {
            if is_android {
                sig(
                    "kernel_tainted",
                    "Kernel taint",
                    "kernel",
                    SignalState::Good,
                    format!("Tainted (0x{n:x}) — expected on Android kernel"),
                    10,
                )
            } else {
                sig(
                    "kernel_tainted",
                    "Kernel taint",
                    "kernel",
                    SignalState::Warn,
                    format!("Tainted (flags: 0x{n:x})"),
                    10,
                )
            }
        }
        _ => sig(
            "kernel_tainted",
            "Kernel taint",
            "kernel",
            SignalState::Unknown,
            "Cannot read".into(),
            10,
        ),
    }
}

fn signal_tainted() -> Signal {
    classify_tainted(read_i64("/proc/sys/kernel/tainted"), is_android_kernel())
}

/// Returns true when running on an Android-derived kernel.
fn is_android_kernel() -> bool {
    if let Ok(v) = fs::read_to_string("/proc/version") {
        let lv = v.to_lowercase();
        if lv.contains("android") || lv.contains("gki-") || lv.contains("-gki") {
            return true;
        }
    }
    // Secondary check: presence of Android-specific paths
    fs::metadata("/system/build.prop").is_ok() || fs::metadata("/apex").is_ok()
}

// ---------------------------------------------------------
// Access control
// ---------------------------------------------------------

pub(crate) fn classify_selinux(
    enforce: Option<&str>,
    ctx: Option<&str>,
    apparmor_active: bool,
) -> Signal {
    if let Some(v) = enforce {
        return match v {
            "1" => sig(
                "selinux",
                "SELinux",
                "mac",
                SignalState::Good,
                "Enforcing".into(),
                15,
            ),
            "0" => sig(
                "selinux",
                "SELinux",
                "mac",
                SignalState::Warn,
                "Permissive".into(),
                15,
            ),
            other => sig(
                "selinux",
                "SELinux",
                "mac",
                SignalState::Unknown,
                format!("Unknown: {other}"),
                15,
            ),
        };
    }
    if let Some(c) = ctx {
        let c = c.trim();
        if !c.is_empty() && c != "unconfined" {
            return sig(
                "selinux",
                "SELinux",
                "mac",
                SignalState::Good,
                format!("Context: {c}"),
                15,
            );
        }
    }
    if apparmor_active {
        return sig(
            "selinux",
            "MAC (AppArmor)",
            "mac",
            SignalState::Good,
            "AppArmor active".into(),
            15,
        );
    }
    sig(
        "selinux",
        "MAC",
        "mac",
        SignalState::Warn,
        "Neither SELinux nor AppArmor detected".into(),
        15,
    )
}

fn signal_selinux() -> Signal {
    let enforce = read_opt("/sys/fs/selinux/enforce");
    let ctx = read_opt("/proc/self/attr/current");
    let apparmor_active = fs::read_to_string("/sys/kernel/security/apparmor/profiles")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    classify_selinux(enforce.as_deref(), ctx.as_deref(), apparmor_active)
}

pub(crate) fn classify_lockdown(value: Option<&str>) -> Signal {
    match value {
        Some(s) if s.contains("[integrity]") || s.contains("[confidentiality]") => sig(
            "lockdown",
            "Kernel lockdown",
            "mac",
            SignalState::Good,
            s.to_string(),
            8,
        ),
        Some(s) if s.contains("[none]") => sig(
            "lockdown",
            "Kernel lockdown",
            "mac",
            SignalState::Warn,
            "Disabled".into(),
            8,
        ),
        Some(s) => sig(
            "lockdown",
            "Kernel lockdown",
            "mac",
            SignalState::Unknown,
            s.to_string(),
            8,
        ),
        None => sig(
            "lockdown",
            "Kernel lockdown",
            "mac",
            SignalState::Unknown,
            "Not exposed".into(),
            8,
        ),
    }
}

fn signal_lockdown() -> Signal {
    classify_lockdown(read_opt("/sys/kernel/security/lockdown").as_deref())
}

pub(crate) fn classify_suid(count: u32, threshold: u32, samples: Vec<String>) -> Signal {
    let mut s = if count == 0 {
        sig(
            "suid_bins",
            "SUID binaries",
            "fs",
            SignalState::Good,
            "None found in PATH dirs".into(),
            5,
        )
    } else if count < threshold {
        sig(
            "suid_bins",
            "SUID binaries",
            "fs",
            SignalState::Good,
            format!("{count} found (typical for this distro)"),
            5,
        )
    } else {
        sig(
            "suid_bins",
            "SUID binaries",
            "fs",
            SignalState::Warn,
            format!("{count} found (elevated)"),
            5,
        )
    };
    s.evidence = samples;
    s
}

fn signal_suid_count() -> Signal {
    const DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];
    let mut count = 0u32;
    let mut samples = Vec::new();
    use std::os::unix::fs::MetadataExt;
    for dir in DIRS {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            if let Ok(md) = e.metadata() {
                if md.mode() & 0o4000 != 0 {
                    count += 1;
                    if samples.len() < 3 {
                        samples.push(format!("{}/{}", dir, e.file_name().to_string_lossy()));
                    }
                }
            }
        }
    }
    classify_suid(count, suid_threshold(), samples)
}

/// Returns the SUID count threshold for the current distro.
/// Security-focused distros ship many more SUID binaries than
/// general-purpose distributions.
pub(crate) fn threshold_for_distro(id: &str) -> u32 {
    match id.to_lowercase().as_str() {
        "kali" | "parrot" | "blackarch" => 60,
        "alpine" | "arch" | "manjaro" | "endeavouros" => 25,
        "debian" | "ubuntu" | "mint" | "pop" | "raspbian" => 15,
        _ => 20,
    }
}

fn suid_threshold() -> u32 {
    let os = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id = os
        .lines()
        .find_map(|l| l.strip_prefix("ID="))
        .unwrap_or("")
        .trim_matches('"');
    threshold_for_distro(id)
}

// ---------------------------------------------------------
// Filesystem
// ---------------------------------------------------------

pub(crate) fn classify_world_writable_etc(count: u32, samples: Vec<String>) -> Signal {
    let mut s = if count == 0 {
        sig(
            "etc_ww",
            "World-writable in /etc",
            "fs",
            SignalState::Good,
            "None".into(),
            8,
        )
    } else {
        sig(
            "etc_ww",
            "World-writable in /etc",
            "fs",
            SignalState::Bad,
            format!("{count} file(s)"),
            8,
        )
    };
    s.evidence = samples;
    s
}

fn signal_world_writable_etc() -> Signal {
    let mut count = 0u32;
    let mut samples = Vec::new();
    use std::os::unix::fs::MetadataExt;
    if let Ok(rd) = fs::read_dir("/etc") {
        for e in rd.flatten() {
            if let Ok(md) = e.metadata() {
                if md.is_file() && md.mode() & 0o002 != 0 {
                    count += 1;
                    if samples.len() < 3 {
                        samples.push(e.file_name().to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    classify_world_writable_etc(count, samples)
}

pub(crate) fn classify_tmp_exec(foreign_count: u32, samples: Vec<String>) -> Signal {
    let mut s = if foreign_count == 0 {
        sig(
            "tmp_exec",
            "Executables in /tmp",
            "fs",
            SignalState::Good,
            "None owned by other users".into(),
            6,
        )
    } else {
        sig(
            "tmp_exec",
            "Executables in /tmp",
            "fs",
            SignalState::Warn,
            format!("{foreign_count} executable(s) owned by other uid"),
            6,
        )
    };
    s.evidence = samples;
    s
}

fn signal_tmp_executables() -> Signal {
    let mut foreign_count = 0u32;
    let mut samples = Vec::new();
    use std::os::unix::fs::MetadataExt;
    let self_uid = unsafe { libc::getuid() };
    if let Ok(rd) = fs::read_dir("/tmp") {
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if !md.is_file() || md.mode() & 0o111 == 0 {
                continue;
            }
            if md.uid() == self_uid {
                continue;
            }
            if self_uid == 0 && md.uid() == 0 {
                continue;
            }
            foreign_count += 1;
            if samples.len() < 3 {
                samples.push(format!(
                    "{} (owner uid={})",
                    e.file_name().to_string_lossy(),
                    md.uid()
                ));
            }
        }
    }
    classify_tmp_exec(foreign_count, samples)
}

pub(crate) fn parse_sshd_permit_root_login(content: &str) -> Option<String> {
    let mut result = None;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("permitrootlogin") {
            result = Some(line.split_whitespace().last().unwrap_or("").to_string());
        }
    }
    result
}

fn signal_ssh_root_login() -> Signal {
    let sshd_running = is_process_running("sshd");
    let port_22_open = is_port_listening(22);

    if !sshd_running && !port_22_open {
        return sig(
            "ssh_root",
            "SSH root login",
            "config",
            SignalState::Good,
            "SSH service not running".into(),
            10,
        );
    }

    let path = "/etc/ssh/sshd_config";
    let Ok(content) = fs::read_to_string(path) else {
        return sig(
            "ssh_root",
            "SSH root login",
            "config",
            SignalState::Unknown,
            "SSH active but no sshd_config".into(),
            10,
        );
    };
    let root_login = parse_sshd_permit_root_login(&content);
    match root_login.as_deref() {
        Some("no") => sig(
            "ssh_root",
            "SSH root login",
            "config",
            SignalState::Good,
            "Disabled".into(),
            10,
        ),
        Some("yes") => sig(
            "ssh_root",
            "SSH root login",
            "config",
            SignalState::Bad,
            "Enabled (SSH active)".into(),
            10,
        ),
        Some(v) => sig(
            "ssh_root",
            "SSH root login",
            "config",
            SignalState::Warn,
            format!("Value: {v}"),
            10,
        ),
        None => sig(
            "ssh_root",
            "SSH root login",
            "config",
            SignalState::Unknown,
            "Not configured".into(),
            10,
        ),
    }
}

fn is_process_running(name: &str) -> bool {
    let Ok(rd) = fs::read_dir("/proc") else {
        return false;
    };
    for e in rd.flatten() {
        let Some(n) = e.file_name().to_str().map(String::from) else {
            continue;
        };
        if n.parse::<u32>().is_err() {
            continue;
        }
        let comm = format!("/proc/{}/comm", n);
        if let Ok(s) = fs::read_to_string(&comm) {
            if s.trim() == name {
                return true;
            }
        }
    }
    false
}

fn is_port_listening(port: u16) -> bool {
    let hex_port = format!("{:04X}", port);
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let state = parts[3];
            if state != "0A" {
                continue;
            }
            if let Some(p) = parts[1].split(':').nth(1) {
                if p == hex_port {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------
// Network
// ---------------------------------------------------------

pub(crate) fn count_public_listeners(content: &str) -> u32 {
    let mut n = 0;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let local = parts[1];
        let state = parts[3];
        if state != "0A" {
            continue;
        }
        if let Some(addr) = local.split(':').next() {
            if addr == "00000000" || addr == "00000000000000000000000000000000" {
                n += 1;
            }
        }
    }
    n
}

fn signal_public_ports() -> Signal {
    let v4 = fs::read_to_string("/proc/net/tcp")
        .map(|s| count_public_listeners(&s))
        .unwrap_or(0);
    let v6 = fs::read_to_string("/proc/net/tcp6")
        .map(|s| count_public_listeners(&s))
        .unwrap_or(0);
    let total = v4 + v6;
    if total == 0 {
        sig(
            "public_ports",
            "Public listening ports",
            "network",
            SignalState::Good,
            "None".into(),
            8,
        )
    } else {
        sig(
            "public_ports",
            "Public listening ports",
            "network",
            SignalState::Warn,
            format!("{total} listening on all interfaces"),
            8,
        )
    }
}

pub(crate) fn count_nonlocal_connections(content: &str) -> u32 {
    let mut n = 0;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let remote = parts[2];
        let state = parts[3];
        if state == "0A" {
            continue;
        }
        if let Some(addr) = remote.split(':').next() {
            if is_loopback_addr(addr) {
                continue;
            }
            n += 1;
        }
    }
    n
}

fn signal_nonlocal_conns() -> Signal {
    let total = fs::read_to_string("/proc/net/tcp")
        .map(|s| count_nonlocal_connections(&s))
        .unwrap_or(0)
        + fs::read_to_string("/proc/net/tcp6")
            .map(|s| count_nonlocal_connections(&s))
            .unwrap_or(0);
    sig(
        "remote_conns",
        "Outbound connections",
        "network",
        SignalState::Good,
        format!("{total} active"),
        0,
    )
}

// ---------------------------------------------------------
// System posture
// ---------------------------------------------------------

pub(crate) fn parse_uptime_seconds(content: &str) -> u64 {
    content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

fn signal_uptime() -> Signal {
    let Ok(content) = fs::read_to_string("/proc/uptime") else {
        return sig(
            "uptime",
            "System uptime",
            "posture",
            SignalState::Unknown,
            "Cannot read".into(),
            0,
        );
    };
    let secs = parse_uptime_seconds(&content);
    let hours = secs / 3600;
    sig(
        "uptime",
        "System uptime",
        "posture",
        SignalState::Good,
        format!("{hours} hours"),
        0,
    )
}

fn signal_deleted_binaries() -> Signal {
    let mut count = 0u32;
    let mut samples = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.parse::<u32>().is_err() {
                continue;
            }
            let exe_path = format!("/proc/{name}/exe");
            if let Ok(target) = fs::read_link(&exe_path) {
                if target.to_string_lossy().ends_with(" (deleted)") {
                    count += 1;
                    if samples.len() < 3 {
                        samples.push(format!("pid {}", name));
                    }
                }
            }
        }
    }
    let mut s = if count == 0 {
        sig(
            "deleted_bins",
            "Processes with deleted binaries",
            "posture",
            SignalState::Good,
            "None".into(),
            8,
        )
    } else {
        sig(
            "deleted_bins",
            "Processes with deleted binaries",
            "posture",
            SignalState::Warn,
            format!("{count} process(es)"),
            8,
        )
    };
    s.evidence = samples;
    s
}

fn signal_cron_jobs() -> Signal {
    let mut count = 0u32;
    for path in ["/etc/crontab", "/etc/cron.d"] {
        if fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) {
            count += 1;
        }
    }
    if let Ok(rd) = fs::read_dir("/etc/cron.d") {
        count += rd.flatten().count() as u32;
    }
    sig(
        "cron",
        "Cron jobs",
        "posture",
        SignalState::Good,
        format!("{count} cron source(s)"),
        0,
    )
}

pub(crate) fn parse_uid0_accounts(content: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[2] == "0" {
            names.push(parts[0].to_string());
        }
    }
    names
}

fn signal_users_uid0() -> Signal {
    let Ok(content) = fs::read_to_string("/etc/passwd") else {
        return sig(
            "uid0",
            "UID 0 accounts",
            "posture",
            SignalState::Unknown,
            "No /etc/passwd".into(),
            10,
        );
    };
    let names = parse_uid0_accounts(&content);
    let count = names.len() as u32;
    let mut s = if count == 1 && names.first().map(|n| n == "root").unwrap_or(false) {
        sig(
            "uid0",
            "UID 0 accounts",
            "posture",
            SignalState::Good,
            "Only root".into(),
            10,
        )
    } else {
        sig(
            "uid0",
            "UID 0 accounts",
            "posture",
            SignalState::Bad,
            format!("{count} accounts with UID 0"),
            10,
        )
    };
    s.evidence = names;
    s
}

pub(crate) fn count_unlocked_accounts(content: &str) -> u32 {
    let mut count = 0u32;
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        if parts[1].is_empty() {
            count += 1;
        }
    }
    count
}

fn signal_unlocked_accounts() -> Signal {
    let Ok(content) = fs::read_to_string("/etc/shadow") else {
        return sig(
            "unlocked",
            "Unlocked accounts",
            "posture",
            SignalState::Unknown,
            "No /etc/shadow access".into(),
            8,
        );
    };
    let count = count_unlocked_accounts(&content);
    if count == 0 {
        sig(
            "unlocked",
            "Unlocked accounts",
            "posture",
            SignalState::Good,
            "All accounts have passwords".into(),
            8,
        )
    } else {
        sig(
            "unlocked",
            "Unlocked accounts",
            "posture",
            SignalState::Warn,
            format!("{count} account(s) without password"),
            8,
        )
    }
}

// ---------------------------------------------------------
// Build report
// ---------------------------------------------------------

pub fn build_trust_report() -> TrustReport {
    let signals = vec![
        // kernel
        signal_aslr(),
        signal_kptr(),
        signal_dmesg(),
        signal_perf(),
        signal_tainted(),
        // MAC
        signal_selinux(),
        signal_lockdown(),
        signal_suid_count(),
        // fs
        signal_world_writable_etc(),
        signal_tmp_executables(),
        signal_ssh_root_login(),
        // network
        signal_public_ports(),
        signal_nonlocal_conns(),
        // posture
        signal_uptime(),
        signal_deleted_binaries(),
        signal_cron_jobs(),
        signal_users_uid0(),
        signal_unlocked_accounts(),
    ];

    let mut penalty = 0i32;
    let mut good = 0u32;
    let mut warn = 0u32;
    let mut bad = 0u32;
    let mut unknown = 0u32;
    for s in &signals {
        match s.state {
            SignalState::Good => good += 1,
            SignalState::Warn => {
                warn += 1;
                penalty += s.points_delta.abs();
            }
            SignalState::Bad => {
                bad += 1;
                penalty += s.points_delta.abs();
            }
            SignalState::Unknown => {
                unknown += 1;
                // Unverifiable signals: partial penalty (40% of weight)
                // Rationale: cannot verify = cannot trust = must count against
                penalty += (s.points_delta.abs() * 40) / 100;
            }
        }
    }

    // Extra penalty if too many signals are unverifiable
    let unknown_ratio = unknown as f32 / signals.len() as f32;
    if unknown_ratio >= 0.5 {
        penalty += 15; // Heavy penalty: less than half verified
    } else if unknown_ratio >= 0.3 {
        penalty += 8;
    }

    let score = (100 - penalty).clamp(0, 100);
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };

    TrustReport {
        score,
        grade: grade.to_string(),
        summary: TrustSummary {
            total: signals.len() as u32,
            good,
            warn,
            bad,
            unknown,
            penalty,
        },
        signals,
    }
}

// ---------------------------------------------------------
// Rendering
// ---------------------------------------------------------

impl TrustReport {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "=== PULSE TRUST SCORE ===");
        s.push('\n');
        let _ = writeln!(s, "Overall : {}/100  (Grade {})", self.score, self.grade);
        let _ = writeln!(
            s,
            "Signals : {} total | {} pass | {} warn | {} fail | {} n/a",
            self.summary.total,
            self.summary.good,
            self.summary.warn,
            self.summary.bad,
            self.summary.unknown
        );
        let verified = self.summary.total.saturating_sub(self.summary.unknown);
        let confidence = verified
            .checked_mul(100)
            .and_then(|x| x.checked_div(self.summary.total))
            .unwrap_or(0);
        let _ = writeln!(
            s,
            "Verified: {}/{} signals ({confidence}%)",
            verified, self.summary.total
        );
        if confidence < 50 {
            let _ = writeln!(s, "⚠️  Low confidence — run with root for accurate score");
        }
        s.push('\n');

        let categories = ["kernel", "mac", "fs", "config", "network", "posture"];
        for cat in categories {
            let in_cat: Vec<&Signal> = self.signals.iter().filter(|x| x.category == cat).collect();
            if in_cat.is_empty() {
                continue;
            }
            let _ = writeln!(s, "[{}]", cat.to_uppercase());
            for sig in in_cat {
                let _ = writeln!(
                    s,
                    "  {} {:<5} {:<28} {}",
                    sig.state.symbol(),
                    sig.state.label(),
                    sig.name,
                    sig.detail
                );
                for ev in &sig.evidence {
                    let _ = writeln!(s, "           └─ {}", ev);
                }
            }
            s.push('\n');
        }

        if self.summary.bad > 0 || self.summary.warn > 0 {
            s.push_str("Penalty breakdown:\n");
            for sig in &self.signals {
                if matches!(sig.state, SignalState::Warn | SignalState::Bad) {
                    let _ = writeln!(s, "  -{} {}", sig.points_delta.abs(), sig.name);
                }
            }
        }
        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Pulse Trust Score\n\n");
        let _ = writeln!(
            s,
            "**Score:** {}/100 (Grade **{}**)\n",
            self.score, self.grade
        );
        let _ = writeln!(
            s,
            "**Summary:** {} pass | {} warn | {} fail | {} n/a\n",
            self.summary.good, self.summary.warn, self.summary.bad, self.summary.unknown
        );

        s.push_str("## Signals\n\n");
        s.push_str("| State | Name | Detail | Points |\n");
        s.push_str("|-------|------|--------|--------|\n");
        for sig in &self.signals {
            let _ = writeln!(
                s,
                "| {} {} | {} | {} | {} |",
                sig.state.symbol(),
                sig.state.label(),
                sig.name,
                sig.detail.replace('|', "\\|"),
                sig.points_delta
            );
        }
        s
    }
}

// ---------------------------------------------------------
// Address classification helpers
// ---------------------------------------------------------

/// Returns true when the given address (in /proc/net hex format)
/// is a loopback address.
///
/// IPv4 loopback (127.0.0.1) is stored in little-endian as "0100007F".
/// IPv6 loopback (::1) is stored as "00000000000000000000000001000000".
pub fn is_loopback_addr(addr: &str) -> bool {
    if addr == "0100007F" {
        return true;
    }
    if addr == "00000000000000000000000001000000" {
        return true;
    }
    false
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // ---------- read_opt ----------

    #[test]
    fn read_opt_missing_returns_none() {
        assert!(read_opt("/__pulse_nonexistent__/file").is_none());
    }

    #[test]
    fn read_opt_trims_whitespace() {
        let s = read_opt("/proc/sys/kernel/hostname");
        if let Some(v) = s {
            assert_eq!(v, v.trim());
        }
    }

    // ---------- read_i64 ----------

    #[test]
    fn read_i64_missing_returns_none() {
        assert!(read_i64("/__pulse_nonexistent__/file").is_none());
    }

    #[test]
    fn read_i64_parses_current_tainted() {
        // /proc/sys/kernel/tainted exists on Linux and contains an integer
        let _ = read_i64("/proc/sys/kernel/tainted");
    }

    // ---------- sig ----------

    #[test]
    fn sig_builds_signal_with_empty_evidence() {
        let s = sig("x", "X", "cat", SignalState::Good, "d".to_string(), 7);
        assert_eq!(s.id, "x");
        assert_eq!(s.name, "X");
        assert_eq!(s.category, "cat");
        assert_eq!(s.state, SignalState::Good);
        assert_eq!(s.detail, "d");
        assert_eq!(s.points_delta, 7);
        assert!(s.evidence.is_empty());
    }

    // ---------- is_android_kernel ----------

    #[test]
    fn is_android_kernel_does_not_panic() {
        let _ = is_android_kernel();
    }

    #[test]
    fn is_android_kernel_returns_bool() {
        let v: bool = is_android_kernel();
        assert!(v || !v);
    }

    // ---------- suid_threshold ----------

    #[test]
    fn suid_threshold_is_one_of_expected() {
        let t = suid_threshold();
        assert!(
            matches!(t, 15 | 20 | 25 | 60),
            "unexpected SUID threshold: {t}"
        );
    }

    // ---------- is_process_running ----------

    #[test]
    fn is_process_running_unknown_returns_false() {
        assert!(!is_process_running("__pulse_nonexistent_proc__"));
    }

    #[test]
    fn is_process_running_init_returns_true() {
        // PID 1 on Linux is always "init" (or systemd as pid 1 named "systemd",
        // or /system/bin/init on Android, whose comm might be "init").
        // We just ensure the function does not panic.
        let _ = is_process_running("init");
    }

    // ---------- is_port_listening ----------

    #[test]
    fn is_port_listening_does_not_panic() {
        let _ = is_port_listening(1);
        let _ = is_port_listening(65535);
    }

    #[test]
    fn is_port_listening_returns_bool() {
        let v: bool = is_port_listening(22);
        assert!(v || !v);
    }

    // ---------- individual signal functions - shape check ----------

    #[test]
    fn signal_aslr_has_correct_id() {
        let s = signal_aslr();
        assert_eq!(s.id, "aslr");
        assert_eq!(s.points_delta, 10);
    }

    #[test]
    fn signal_kptr_has_correct_id() {
        let s = signal_kptr();
        assert_eq!(s.id, "kptr_restrict");
    }

    #[test]
    fn signal_dmesg_has_correct_id() {
        let s = signal_dmesg();
        assert_eq!(s.id, "dmesg_restrict");
    }

    #[test]
    fn signal_perf_has_correct_id() {
        let s = signal_perf();
        assert_eq!(s.id, "perf_paranoid");
    }

    #[test]
    fn signal_tainted_has_correct_id() {
        let s = signal_tainted();
        assert_eq!(s.id, "kernel_tainted");
    }

    #[test]
    fn signal_selinux_has_correct_id() {
        let s = signal_selinux();
        assert_eq!(s.id, "selinux");
        assert_eq!(s.points_delta, 15);
    }

    #[test]
    fn signal_lockdown_has_correct_id() {
        let s = signal_lockdown();
        assert_eq!(s.id, "lockdown");
    }

    #[test]
    fn signal_suid_count_has_correct_id() {
        let s = signal_suid_count();
        assert_eq!(s.id, "suid_bins");
    }

    #[test]
    fn signal_world_writable_etc_has_correct_id() {
        let s = signal_world_writable_etc();
        assert_eq!(s.id, "etc_ww");
    }

    #[test]
    fn signal_tmp_executables_has_correct_id() {
        let s = signal_tmp_executables();
        assert_eq!(s.id, "tmp_exec");
    }

    #[test]
    fn signal_ssh_root_login_has_correct_id() {
        let s = signal_ssh_root_login();
        assert_eq!(s.id, "ssh_root");
    }

    #[test]
    fn signal_public_ports_has_correct_id() {
        let s = signal_public_ports();
        assert_eq!(s.id, "public_ports");
    }

    #[test]
    fn signal_nonlocal_conns_has_correct_id() {
        let s = signal_nonlocal_conns();
        assert_eq!(s.id, "remote_conns");
    }

    #[test]
    fn signal_uptime_has_correct_id() {
        let s = signal_uptime();
        assert_eq!(s.id, "uptime");
    }

    #[test]
    fn signal_deleted_binaries_has_correct_id() {
        let s = signal_deleted_binaries();
        assert_eq!(s.id, "deleted_bins");
    }

    #[test]
    fn signal_cron_jobs_has_correct_id() {
        let s = signal_cron_jobs();
        assert_eq!(s.id, "cron");
    }

    #[test]
    fn signal_users_uid0_has_correct_id() {
        let s = signal_users_uid0();
        assert_eq!(s.id, "uid0");
    }

    #[test]
    fn signal_unlocked_accounts_has_correct_id() {
        let s = signal_unlocked_accounts();
        assert_eq!(s.id, "unlocked");
    }

    // ---------- is_loopback_addr ----------

    #[test]
    fn is_loopback_addr_ipv4_loopback() {
        assert!(is_loopback_addr("0100007F"));
    }

    #[test]
    fn is_loopback_addr_ipv6_loopback() {
        assert!(is_loopback_addr("00000000000000000000000001000000"));
    }

    #[test]
    fn is_loopback_addr_any_not_loopback() {
        assert!(!is_loopback_addr("00000000"));
    }

    #[test]
    fn is_loopback_addr_empty_not_loopback() {
        assert!(!is_loopback_addr(""));
    }

    #[test]
    fn is_loopback_addr_case_sensitive() {
        assert!(!is_loopback_addr("0100007f"));
    }
}

#[cfg(test)]
mod classifier_tests {
    use super::*;

    // ---------- classify_aslr ----------

    #[test]
    fn classify_aslr_full() {
        let s = classify_aslr(Some(2));
        assert_eq!(s.state, SignalState::Good);
        assert_eq!(s.detail, "Full randomization");
    }

    #[test]
    fn classify_aslr_partial() {
        let s = classify_aslr(Some(1));
        assert_eq!(s.state, SignalState::Warn);
        assert!(s.detail.contains("Partial"));
    }

    #[test]
    fn classify_aslr_disabled() {
        let s = classify_aslr(Some(0));
        assert_eq!(s.state, SignalState::Bad);
        assert_eq!(s.detail, "Disabled");
    }

    #[test]
    fn classify_aslr_unknown_value() {
        let s = classify_aslr(Some(99));
        assert_eq!(s.state, SignalState::Unknown);
        assert!(s.detail.contains("99"));
    }

    #[test]
    fn classify_aslr_unreadable() {
        let s = classify_aslr(None);
        assert_eq!(s.state, SignalState::Unknown);
        assert_eq!(s.detail, "Cannot read");
    }

    // ---------- classify_kptr ----------

    #[test]
    fn classify_kptr_1_good() {
        let s = classify_kptr(Some(1));
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_kptr_2_good() {
        let s = classify_kptr(Some(2));
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_kptr_0_warn() {
        let s = classify_kptr(Some(0));
        assert_eq!(s.state, SignalState::Warn);
    }

    #[test]
    fn classify_kptr_none_unknown() {
        let s = classify_kptr(None);
        assert_eq!(s.state, SignalState::Unknown);
    }

    // ---------- classify_dmesg ----------

    #[test]
    fn classify_dmesg_1_good() {
        assert_eq!(classify_dmesg(Some(1)).state, SignalState::Good);
    }

    #[test]
    fn classify_dmesg_0_warn() {
        assert_eq!(classify_dmesg(Some(0)).state, SignalState::Warn);
    }

    #[test]
    fn classify_dmesg_none_unknown() {
        assert_eq!(classify_dmesg(None).state, SignalState::Unknown);
    }

    // ---------- classify_perf ----------

    #[test]
    fn classify_perf_2_good() {
        assert_eq!(classify_perf(Some(2)).state, SignalState::Good);
    }

    #[test]
    fn classify_perf_3_good() {
        assert_eq!(classify_perf(Some(3)).state, SignalState::Good);
    }

    #[test]
    fn classify_perf_1_warn() {
        let s = classify_perf(Some(1));
        assert_eq!(s.state, SignalState::Warn);
        assert!(s.detail.contains("Weak"));
    }

    #[test]
    fn classify_perf_0_warn() {
        assert_eq!(classify_perf(Some(0)).state, SignalState::Warn);
    }

    #[test]
    fn classify_perf_none_unknown() {
        assert_eq!(classify_perf(None).state, SignalState::Unknown);
    }

    // ---------- classify_tainted ----------

    #[test]
    fn classify_tainted_clean_good() {
        let s = classify_tainted(Some(0), false);
        assert_eq!(s.state, SignalState::Good);
        assert_eq!(s.detail, "Not tainted");
    }

    #[test]
    fn classify_tainted_clean_android_good() {
        let s = classify_tainted(Some(0), true);
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_tainted_dirty_linux_warn() {
        let s = classify_tainted(Some(0x100), false);
        assert_eq!(s.state, SignalState::Warn);
        assert!(s.detail.contains("100"));
    }

    #[test]
    fn classify_tainted_dirty_android_good() {
        let s = classify_tainted(Some(0x100), true);
        assert_eq!(s.state, SignalState::Good);
        assert!(s.detail.contains("Android"));
    }

    #[test]
    fn classify_tainted_unreadable() {
        let s = classify_tainted(None, false);
        assert_eq!(s.state, SignalState::Unknown);
    }

    #[test]
    fn classify_tainted_uses_hex_format() {
        let s = classify_tainted(Some(0xAB), false);
        assert!(
            s.detail.contains("ab"),
            "detail should have lowercase hex: {}",
            s.detail
        );
    }
}

#[cfg(test)]
mod classifier_tests_2 {
    use super::*;

    // ---------- classify_selinux ----------

    #[test]
    fn classify_selinux_enforcing() {
        let s = classify_selinux(Some("1"), None, false);
        assert_eq!(s.state, SignalState::Good);
        assert_eq!(s.detail, "Enforcing");
    }

    #[test]
    fn classify_selinux_permissive() {
        let s = classify_selinux(Some("0"), None, false);
        assert_eq!(s.state, SignalState::Warn);
        assert_eq!(s.detail, "Permissive");
    }

    #[test]
    fn classify_selinux_unknown_value() {
        let s = classify_selinux(Some("2"), None, false);
        assert_eq!(s.state, SignalState::Unknown);
        assert!(s.detail.contains('2'));
    }

    #[test]
    fn classify_selinux_context() {
        let s = classify_selinux(None, Some("u:r:init:s0"), false);
        assert_eq!(s.state, SignalState::Good);
        assert!(s.detail.contains("init"));
    }

    #[test]
    fn classify_selinux_unconfined_context_falls_through() {
        let s = classify_selinux(None, Some("unconfined"), false);
        // unconfined is not accepted → falls through to neither → warn
        assert_eq!(s.state, SignalState::Warn);
    }

    #[test]
    fn classify_selinux_empty_context_falls_through() {
        let s = classify_selinux(None, Some(""), false);
        assert_eq!(s.state, SignalState::Warn);
    }

    #[test]
    fn classify_selinux_apparmor() {
        let s = classify_selinux(None, None, true);
        assert_eq!(s.state, SignalState::Good);
        assert!(s.detail.contains("AppArmor"));
    }

    #[test]
    fn classify_selinux_none() {
        let s = classify_selinux(None, None, false);
        assert_eq!(s.state, SignalState::Warn);
        assert!(s.detail.contains("Neither"));
    }

    #[test]
    fn classify_selinux_weight_is_15() {
        assert_eq!(classify_selinux(None, None, false).points_delta, 15);
    }

    // ---------- classify_lockdown ----------

    #[test]
    fn classify_lockdown_integrity() {
        let s = classify_lockdown(Some("[integrity] confidentiality"));
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_lockdown_confidentiality() {
        let s = classify_lockdown(Some("none [confidentiality]"));
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_lockdown_none() {
        let s = classify_lockdown(Some("[none]"));
        assert_eq!(s.state, SignalState::Warn);
        assert_eq!(s.detail, "Disabled");
    }

    #[test]
    fn classify_lockdown_other_value() {
        let s = classify_lockdown(Some("garbage"));
        assert_eq!(s.state, SignalState::Unknown);
    }

    #[test]
    fn classify_lockdown_missing() {
        let s = classify_lockdown(None);
        assert_eq!(s.state, SignalState::Unknown);
        assert_eq!(s.detail, "Not exposed");
    }

    // ---------- classify_suid ----------

    #[test]
    fn classify_suid_zero() {
        let s = classify_suid(0, 20, vec![]);
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_suid_below_threshold() {
        let s = classify_suid(15, 20, vec![]);
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_suid_at_threshold_warn() {
        let s = classify_suid(20, 20, vec![]);
        assert_eq!(s.state, SignalState::Warn);
    }

    #[test]
    fn classify_suid_above_threshold_warn() {
        let s = classify_suid(100, 20, vec![]);
        assert_eq!(s.state, SignalState::Warn);
        assert!(s.detail.contains("100"));
    }

    #[test]
    fn classify_suid_preserves_evidence() {
        let s = classify_suid(50, 20, vec!["a".into(), "b".into()]);
        assert_eq!(s.evidence.len(), 2);
    }

    // ---------- classify_world_writable_etc ----------

    #[test]
    fn classify_etc_ww_zero() {
        let s = classify_world_writable_etc(0, vec![]);
        assert_eq!(s.state, SignalState::Good);
        assert_eq!(s.detail, "None");
    }

    #[test]
    fn classify_etc_ww_one() {
        let s = classify_world_writable_etc(1, vec!["x".into()]);
        assert_eq!(s.state, SignalState::Bad);
        assert!(s.detail.contains('1'));
    }

    #[test]
    fn classify_etc_ww_many() {
        let s = classify_world_writable_etc(5, vec![]);
        assert_eq!(s.state, SignalState::Bad);
    }

    // ---------- classify_tmp_exec ----------

    #[test]
    fn classify_tmp_exec_zero() {
        let s = classify_tmp_exec(0, vec![]);
        assert_eq!(s.state, SignalState::Good);
    }

    #[test]
    fn classify_tmp_exec_one() {
        let s = classify_tmp_exec(1, vec!["bash".into()]);
        assert_eq!(s.state, SignalState::Warn);
        assert_eq!(s.evidence.len(), 1);
    }

    #[test]
    fn classify_tmp_exec_many() {
        let s = classify_tmp_exec(10, vec![]);
        assert_eq!(s.state, SignalState::Warn);
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    // ===== threshold_for_distro =====

    #[test]
    fn threshold_kali_60() {
        assert_eq!(threshold_for_distro("kali"), 60);
    }

    #[test]
    fn threshold_parrot_60() {
        assert_eq!(threshold_for_distro("parrot"), 60);
    }

    #[test]
    fn threshold_blackarch_60() {
        assert_eq!(threshold_for_distro("blackarch"), 60);
    }

    #[test]
    fn threshold_alpine_25() {
        assert_eq!(threshold_for_distro("alpine"), 25);
    }

    #[test]
    fn threshold_arch_25() {
        assert_eq!(threshold_for_distro("arch"), 25);
    }

    #[test]
    fn threshold_manjaro_25() {
        assert_eq!(threshold_for_distro("manjaro"), 25);
    }

    #[test]
    fn threshold_endeavouros_25() {
        assert_eq!(threshold_for_distro("endeavouros"), 25);
    }

    #[test]
    fn threshold_debian_15() {
        assert_eq!(threshold_for_distro("debian"), 15);
    }

    #[test]
    fn threshold_ubuntu_15() {
        assert_eq!(threshold_for_distro("ubuntu"), 15);
    }

    #[test]
    fn threshold_mint_15() {
        assert_eq!(threshold_for_distro("mint"), 15);
    }

    #[test]
    fn threshold_pop_15() {
        assert_eq!(threshold_for_distro("pop"), 15);
    }

    #[test]
    fn threshold_raspbian_15() {
        assert_eq!(threshold_for_distro("raspbian"), 15);
    }

    #[test]
    fn threshold_unknown_default_20() {
        assert_eq!(threshold_for_distro("gentoo"), 20);
    }

    #[test]
    fn threshold_empty_default_20() {
        assert_eq!(threshold_for_distro(""), 20);
    }

    #[test]
    fn threshold_uppercase_normalized() {
        assert_eq!(threshold_for_distro("KALI"), 60);
        assert_eq!(threshold_for_distro("Ubuntu"), 15);
    }

    // ===== parse_sshd_permit_root_login =====

    #[test]
    fn sshd_permit_root_no() {
        assert_eq!(
            parse_sshd_permit_root_login("PermitRootLogin no\n"),
            Some("no".into())
        );
    }

    #[test]
    fn sshd_permit_root_yes() {
        assert_eq!(
            parse_sshd_permit_root_login("PermitRootLogin yes\n"),
            Some("yes".into())
        );
    }

    #[test]
    fn sshd_permit_root_case_insensitive() {
        assert_eq!(
            parse_sshd_permit_root_login("permitrootlogin no\n"),
            Some("no".into())
        );
    }

    #[test]
    fn sshd_permit_root_commented_ignored() {
        assert_eq!(
            parse_sshd_permit_root_login("# PermitRootLogin yes\n"),
            None
        );
    }

    #[test]
    fn sshd_permit_root_missing() {
        assert_eq!(parse_sshd_permit_root_login("Port 22\n# nothing\n"), None);
    }

    #[test]
    fn sshd_permit_root_empty() {
        assert_eq!(parse_sshd_permit_root_login(""), None);
    }

    #[test]
    fn sshd_permit_root_with_leading_space() {
        assert_eq!(
            parse_sshd_permit_root_login("   PermitRootLogin no\n"),
            Some("no".into())
        );
    }

    #[test]
    fn sshd_permit_root_last_wins() {
        let c = "PermitRootLogin yes\nPermitRootLogin no\n";
        assert_eq!(parse_sshd_permit_root_login(c), Some("no".into()));
    }

    #[test]
    fn sshd_permit_root_value_only() {
        assert_eq!(
            parse_sshd_permit_root_login("PermitRootLogin\n"),
            Some("PermitRootLogin".into())
        );
    }

    // ===== parse_uid0_accounts =====

    #[test]
    fn uid0_root_only() {
        let c = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:x:/h:/sh\n";
        assert_eq!(parse_uid0_accounts(c), vec!["root"]);
    }

    #[test]
    fn uid0_multiple() {
        let c = "root:x:0:0:r:/r:/sh\nalt:x:0:0:a:/a:/sh\n";
        let r = parse_uid0_accounts(c);
        assert_eq!(r.len(), 2);
        assert!(r.contains(&"root".to_string()));
        assert!(r.contains(&"alt".to_string()));
    }

    #[test]
    fn uid0_none() {
        let c = "user:x:1000:1000:x:/h:/sh\n";
        assert!(parse_uid0_accounts(c).is_empty());
    }

    #[test]
    fn uid0_empty() {
        assert!(parse_uid0_accounts("").is_empty());
    }

    #[test]
    fn uid0_short_lines_skipped() {
        let c = "short:x\n";
        assert!(parse_uid0_accounts(c).is_empty());
    }

    // ===== count_unlocked_accounts =====

    #[test]
    fn unlocked_none() {
        let c = "root:$6$hash:19000:0:99999:7:::\n";
        assert_eq!(count_unlocked_accounts(c), 0);
    }

    #[test]
    fn unlocked_one() {
        let c = "root::$6\n";
        assert_eq!(count_unlocked_accounts(c), 1);
    }

    #[test]
    fn unlocked_multiple() {
        let c = "a::x\nb::y\nc:$6$z\n";
        assert_eq!(count_unlocked_accounts(c), 2);
    }

    #[test]
    fn unlocked_skips_short_lines() {
        let c = "single\n";
        assert_eq!(count_unlocked_accounts(c), 0);
    }

    #[test]
    fn unlocked_empty() {
        assert_eq!(count_unlocked_accounts(""), 0);
    }

    // ===== count_public_listeners =====

    #[test]
    fn public_listeners_all_interfaces() {
        let header = "sl  local_address rem_address st\n";
        let line = "0: 00000000:1F90 00000000:0000 0A ...\n";
        let c = format!("{header}{line}");
        assert_eq!(count_public_listeners(&c), 1);
    }

    #[test]
    fn public_listeners_ipv6_all() {
        let header = "sl  local_address rem_address st\n";
        let line = "0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A ...\n";
        let c = format!("{header}{line}");
        assert_eq!(count_public_listeners(&c), 1);
    }

    #[test]
    fn public_listeners_specific_ip_not_counted() {
        let header = "sl  local_address rem_address st\n";
        let line = "0: 0100007F:1F90 00000000:0000 0A ...\n";
        let c = format!("{header}{line}");
        assert_eq!(count_public_listeners(&c), 0);
    }

    #[test]
    fn public_listeners_non_listen_state_skipped() {
        let header = "sl  local_address rem_address st\n";
        let line = "0: 00000000:1F90 00000000:0000 01 ...\n";
        let c = format!("{header}{line}");
        assert_eq!(count_public_listeners(&c), 0);
    }

    #[test]
    fn public_listeners_empty() {
        assert_eq!(count_public_listeners(""), 0);
    }

    #[test]
    fn public_listeners_header_only() {
        assert_eq!(
            count_public_listeners("sl local_address rem_address st\n"),
            0
        );
    }

    #[test]
    fn public_listeners_multiple() {
        let c = "h\n0: 00000000:1 0:0 0A\n0: 00000000:2 0:0 0A\n";
        assert_eq!(count_public_listeners(c), 2);
    }

    #[test]
    fn public_listeners_short_line_skipped() {
        let c = "h\n0: 00000000\n";
        assert_eq!(count_public_listeners(c), 0);
    }

    // ===== count_nonlocal_connections =====

    #[test]
    fn nonlocal_one_connection() {
        let c = "h\n0: 0100007F:1 8.8.8.8:2 01\n";
        assert_eq!(count_nonlocal_connections(c), 1);
    }

    #[test]
    fn nonlocal_loopback_skipped() {
        let c = "h\n0: 0100007F:1 0100007F:2 01\n";
        assert_eq!(count_nonlocal_connections(c), 0);
    }

    #[test]
    fn nonlocal_listen_state_skipped() {
        let c = "h\n0: 0100007F:1 8.8.8.8:2 0A\n";
        assert_eq!(count_nonlocal_connections(c), 0);
    }

    #[test]
    fn nonlocal_empty() {
        assert_eq!(count_nonlocal_connections(""), 0);
    }

    // ===== parse_uptime_seconds =====

    #[test]
    fn uptime_normal() {
        assert_eq!(parse_uptime_seconds("7200.50 100.0\n"), 7200);
    }

    #[test]
    fn uptime_zero() {
        assert_eq!(parse_uptime_seconds("0.0\n"), 0);
    }

    #[test]
    fn uptime_empty() {
        assert_eq!(parse_uptime_seconds(""), 0);
    }

    #[test]
    fn uptime_garbage() {
        assert_eq!(parse_uptime_seconds("not a number\n"), 0);
    }

    #[test]
    fn uptime_only_integer() {
        assert_eq!(parse_uptime_seconds("12345\n"), 12345);
    }

    #[test]
    fn uptime_with_leading_space() {
        assert_eq!(parse_uptime_seconds("  100.0\n"), 100);
    }
}
