//! Attack-surface enumeration.
//!
//! Collects open ports, setuid binaries, file capabilities,
//! world-writable directories, cron entries, SSH keys.

#[cfg(not(unix))]
use crate::platform_shim::PermissionsExt;
use crate::types::Confidence;
use serde::Serialize;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct AttackSurface {
    pub listening_ports: Vec<ListeningPort>,
    pub suid_binaries: Vec<String>,
    pub sgid_binaries: Vec<String>,
    pub file_capabilities: Vec<FileCap>,
    pub world_writable_etc: Vec<String>,
    pub user_crontabs: Vec<String>,
    pub system_crontabs: Vec<String>,
    pub ssh_authorized: Vec<String>,
    pub ssh_private_keys: Vec<String>,
    pub docker_socket: bool,
    pub exposed_secrets: Vec<String>,
    /// 0-100 attack-surface score. `None` when no sources were readable.
    pub score: Option<u32>,
    /// Number of scanner sources that successfully read their input.
    pub sources_read: u32,
    /// Total scanner sources considered.
    pub sources_total: u32,
    /// Confidence level derived from `sources_read / sources_total`.
    pub confidence: Confidence,
}

#[derive(Debug, Serialize)]
pub struct ListeningPort {
    pub proto: String,
    pub address: String,
    pub port: u16,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct FileCap {
    pub path: String,
    pub caps: String,
}

impl AttackSurface {
    pub fn collect() -> Self {
        let mut s = Self {
            listening_ports: scan_listening_ports(),
            suid_binaries: scan_suid(),
            sgid_binaries: scan_sgid(),
            file_capabilities: scan_file_caps(),
            world_writable_etc: scan_world_writable("/etc"),
            user_crontabs: scan_user_crontabs(),
            system_crontabs: scan_system_crontabs(),
            ssh_authorized: scan_ssh_authorized(),
            ssh_private_keys: scan_ssh_private(),
            docker_socket: Path::new("/var/run/docker.sock").exists()
                || Path::new("/run/docker.sock").exists(),
            exposed_secrets: scan_secrets("/etc"),
            ..Default::default()
        };

        let (read, total) = assess_readability();
        s.sources_read = read;
        s.sources_total = total;
        s.confidence = Confidence::from_counts(read, total);

        // Only assign a score if at least one source was readable.
        // Otherwise the score would be a meaningless "100/100".
        s.score = if read == 0 {
            None
        } else {
            Some(compute_score(&s))
        };

        s
    }
}

impl AttackSurface {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        s.push_str("=== ATTACK SURFACE ===\n\n");
        match self.score {
            Some(n) => s.push_str(&format!(
                "Score: {}/100  (Confidence: {} — {}/{} sources)\n\n",
                n,
                self.confidence.label(),
                self.sources_read,
                self.sources_total
            )),
            None => s.push_str(&format!(
                "Score: N/A  (Confidence: None — {}/{} sources readable)\n\
                 Run with elevated privileges for a full scan.\n\n",
                self.sources_read, self.sources_total
            )),
        }

        s.push_str(&format!(
            "[LISTENING PORTS] ({})\n",
            self.listening_ports.len()
        ));
        for p in &self.listening_ports {
            s.push_str(&format!(
                "  {} {}:{} {}\n",
                p.proto, p.address, p.port, p.state
            ));
        }

        s.push_str(&format!(
            "\n[SUID BINARIES] ({})\n",
            self.suid_binaries.len()
        ));
        for b in &self.suid_binaries {
            s.push_str(&format!("  {}\n", b));
        }

        s.push_str(&format!(
            "\n[SGID BINARIES] ({})\n",
            self.sgid_binaries.len()
        ));
        for b in &self.sgid_binaries {
            s.push_str(&format!("  {}\n", b));
        }

        s.push_str(&format!(
            "\n[FILE CAPABILITIES] ({})\n",
            self.file_capabilities.len()
        ));
        for c in &self.file_capabilities {
            s.push_str(&format!("  {} {}\n", c.path, c.caps));
        }

        s.push_str(&format!(
            "\n[WORLD-WRITABLE /etc] ({})\n",
            self.world_writable_etc.len()
        ));
        for f in &self.world_writable_etc {
            s.push_str(&format!("  {}\n", f));
        }

        s.push_str(&format!(
            "\n[SSH AUTHORIZED] ({})\n",
            self.ssh_authorized.len()
        ));
        for f in &self.ssh_authorized {
            s.push_str(&format!("  {}\n", f));
        }

        s.push_str(&format!(
            "\n[SSH PRIVATE KEYS] ({})\n",
            self.ssh_private_keys.len()
        ));
        for f in &self.ssh_private_keys {
            s.push_str(&format!("  {}\n", f));
        }

        s.push_str(&format!("\n[DOCKER SOCKET] {}\n", self.docker_socket));
        s.push_str(&format!(
            "[EXPOSED SECRETS] ({})\n",
            self.exposed_secrets.len()
        ));
        for f in &self.exposed_secrets {
            s.push_str(&format!("  {}\n", f));
        }
        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Attack Surface\n\n");
        match self.score {
            Some(n) => s.push_str(&format!(
                "**Score:** {}/100  ·  **Confidence:** {} ({}/{})\n\n",
                n,
                self.confidence.label(),
                self.sources_read,
                self.sources_total
            )),
            None => s.push_str(&format!(
                "**Score:** N/A  ·  **Confidence:** None ({}/{})\n\n                 > Run with elevated privileges for a full scan.\n\n",
                self.sources_read, self.sources_total
            )),
        }

        s.push_str(&format!(
            "## Listening Ports ({})\n\n",
            self.listening_ports.len()
        ));
        s.push_str("| Proto | Address | Port | State |\n|-------|---------|------|-------|\n");
        for p in &self.listening_ports {
            s.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                p.proto, p.address, p.port, p.state
            ));
        }

        s.push_str(&format!(
            "\n## SUID Binaries ({})\n\n",
            self.suid_binaries.len()
        ));
        for b in &self.suid_binaries {
            s.push_str(&format!("- `{}`\n", b));
        }

        s.push_str(&format!(
            "\n## SGID Binaries ({})\n\n",
            self.sgid_binaries.len()
        ));
        for b in &self.sgid_binaries {
            s.push_str(&format!("- `{}`\n", b));
        }

        s.push_str(&format!(
            "\n## File Capabilities ({})\n\n",
            self.file_capabilities.len()
        ));
        s.push_str("| Path | Caps |\n|------|------|\n");
        for c in &self.file_capabilities {
            s.push_str(&format!("| `{}` | {} |\n", c.path, c.caps));
        }
        s
    }
}

fn scan_listening_ports() -> Vec<ListeningPort> {
    let mut out = Vec::new();
    let tables = [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ];
    for (path, proto) in tables {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            let state = f[3];
            let is_tcp = proto.starts_with("tcp");
            if is_tcp && state != "0A" {
                continue;
            }
            let Some((addr, port)) = parse_hex_addr(f[1]) else {
                continue;
            };
            out.push(ListeningPort {
                proto: proto.into(),
                address: addr,
                port,
                state: if is_tcp {
                    "LISTEN".into()
                } else {
                    "OPEN".into()
                },
            });
        }
    }
    out.sort_by_key(|p| p.port);
    out.dedup_by_key(|p| (p.port, p.proto.clone()));
    out
}

pub fn parse_hex_addr(s: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if addr_hex.len() == 8 {
        let mut bytes = [0u8; 4];
        for i in 0..4 {
            bytes[i] = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        bytes.reverse();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        addr_hex.to_string()
    };
    Some((addr, port))
}

fn walk_dir<F: FnMut(&Path)>(dir: &str, cb: &mut F, depth: u32) {
    if depth > 6 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(md) = e.metadata() else { continue };
        if md.is_file() {
            cb(&p);
        } else if md.is_dir() {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == "proc" || name == "sys" || name == "dev" || name == "run" {
                continue;
            }
            walk_dir(&p.to_string_lossy(), cb, depth + 1);
        }
    }
}

fn scan_suid() -> Vec<String> {
    let mut out = Vec::new();
    for base in [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/lib",
        "/usr/libexec",
    ] {
        walk_dir(
            base,
            &mut |p| {
                if let Ok(md) = fs::metadata(p) {
                    if md.permissions().mode() & 0o4000 != 0 {
                        out.push(p.to_string_lossy().into_owned());
                    }
                }
            },
            0,
        );
    }
    out.sort();
    out.dedup();
    out
}

fn scan_sgid() -> Vec<String> {
    let mut out = Vec::new();
    for base in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"] {
        walk_dir(
            base,
            &mut |p| {
                if let Ok(md) = fs::metadata(p) {
                    if md.permissions().mode() & 0o2000 != 0 {
                        out.push(p.to_string_lossy().into_owned());
                    }
                }
            },
            0,
        );
    }
    out.sort();
    out.dedup();
    out
}

fn scan_file_caps() -> Vec<FileCap> {
    // Scanning `/` recursively is extremely slow (60-90s on modern systems
    // with large filesystems). We limit the scan to directories that
    // actually ship binaries with capabilities.
    const DIRS: &[&str] = &[
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];

    let mut out = Vec::new();
    for dir in DIRS {
        let Ok(result) = std::process::Command::new("getcap")
            .args(["-r", dir])
            .output()
        else {
            continue;
        };
        for line in String::from_utf8_lossy(&result.stdout).lines() {
            if let Some((p, c)) = line.split_once(' ') {
                out.push(FileCap {
                    path: p.into(),
                    caps: c.into(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

fn scan_world_writable(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    walk_dir(
        dir,
        &mut |p| {
            if let Ok(md) = fs::metadata(p) {
                if md.permissions().mode() & 0o002 != 0 {
                    out.push(p.to_string_lossy().into_owned());
                }
            }
        },
        0,
    );
    out.sort();
    out
}

fn scan_user_crontabs() -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    out.push(e.path().to_string_lossy().into_owned());
                }
            }
        }
    }
    out
}

fn scan_system_crontabs() -> Vec<String> {
    let mut out = Vec::new();
    for dir in [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                out.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    if Path::new("/etc/crontab").exists() {
        out.push("/etc/crontab".into());
    }
    out.sort();
    out
}

fn scan_ssh_authorized() -> Vec<String> {
    let mut out = Vec::new();
    for home in homes() {
        let p = format!("{home}/.ssh/authorized_keys");
        if Path::new(&p).exists() {
            out.push(p);
        }
    }
    out
}

fn scan_ssh_private() -> Vec<String> {
    let mut out = Vec::new();
    for home in homes() {
        let dir = format!("{home}/.ssh");
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if (n.starts_with("id_") && !n.ends_with(".pub")) || n == "identity" {
                out.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    out
}

fn scan_secrets(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    let names = [
        "shadow",
        "gshadow",
        "sudoers",
        "passwd-",
        "shadow-",
        "master.passwd",
    ];
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if names.iter().any(|x| n.contains(x)) {
                out.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    out
}

pub fn homes() -> Vec<String> {
    let mut out = vec!["/root".to_string()];
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && parts[5].starts_with("/home") {
                out.push(parts[5].to_string());
            }
        }
    }
    out
}

/// Probe the same paths that the scanners read from, and count how
/// many scanner sources are actually readable in this environment.
///
/// Returns `(read, total)`. `total` is the number of scanners (10).
///
/// A source counts as readable if its primary input can be opened or
/// listed. This is deliberately conservative: we do not attempt to
/// parse anything here, only to answer the question "would the
/// scanner have produced real data?"
fn assess_readability() -> (u32, u32) {
    let home = std::env::var("HOME").unwrap_or_default();
    let home_readable = !home.is_empty() && fs::read_dir(&home).is_ok();

    let path_dirs = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];
    let path_readable = path_dirs.iter().any(|p| fs::read_dir(p).is_ok());

    let proc_net_readable = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ]
    .iter()
    .any(|p| fs::File::open(p).is_ok());

    let etc_readable = fs::read_dir("/etc").is_ok();

    let user_cron_readable = ["/var/spool/cron/crontabs", "/var/spool/cron"]
        .iter()
        .any(|p| fs::read_dir(p).is_ok());

    let system_cron_readable =
        fs::File::open("/etc/crontab").is_ok() || fs::read_dir("/etc/cron.d").is_ok();

    // Scanners and their input sources:
    //   1. listening_ports  <- /proc/net/*
    //   2. suid             <- PATH dirs
    //   3. sgid             <- PATH dirs
    //   4. file_capabilities<- PATH dirs
    //   5. world_writable   <- /etc
    //   6. user_crontabs    <- /var/spool/cron*
    //   7. system_crontabs  <- /etc/crontab, /etc/cron.d
    //   8. ssh_authorized   <- $HOME
    //   9. ssh_private      <- $HOME
    //  10. exposed_secrets  <- /etc
    let checks: [bool; 10] = [
        proc_net_readable,
        path_readable,
        path_readable,
        path_readable,
        etc_readable,
        user_cron_readable,
        system_cron_readable,
        home_readable,
        home_readable,
        etc_readable,
    ];

    let read = checks.iter().filter(|&&b| b).count() as u32;
    (read, checks.len() as u32)
}

pub fn compute_score(s: &AttackSurface) -> u32 {
    let mut penalty: u32 = 0;
    penalty = penalty.saturating_add((s.listening_ports.len() as u32).min(20).saturating_mul(2));
    penalty = penalty.saturating_add((s.suid_binaries.len() as u32).min(20));
    penalty = penalty.saturating_add((s.sgid_binaries.len() as u32).min(10));
    penalty = penalty.saturating_add(
        (s.world_writable_etc.len() as u32)
            .min(20)
            .saturating_mul(2),
    );
    penalty = penalty.saturating_add((s.ssh_private_keys.len() as u32).min(10).saturating_mul(3));
    if s.docker_socket {
        penalty = penalty.saturating_add(10);
    }
    100u32.saturating_sub(penalty)
}
