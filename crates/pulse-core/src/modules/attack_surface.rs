//! Attack-surface enumeration.
//!
//! Collects open ports, setuid binaries, file capabilities,
//! world-writable directories, cron entries, SSH keys.

use serde::Serialize;
use std::fs;
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
    pub score: u32,
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
        let mut s = Self::default();
        s.listening_ports = scan_listening_ports();
        s.suid_binaries = scan_suid();
        s.sgid_binaries = scan_sgid();
        s.file_capabilities = scan_file_caps();
        s.world_writable_etc = scan_world_writable("/etc");
        s.user_crontabs = scan_user_crontabs();
        s.system_crontabs = scan_system_crontabs();
        s.ssh_authorized = scan_ssh_authorized();
        s.ssh_private_keys = scan_ssh_private();
        s.docker_socket =
            Path::new("/var/run/docker.sock").exists() || Path::new("/run/docker.sock").exists();
        s.exposed_secrets = scan_secrets("/etc");
        s.score = compute_score(&s);
        s
    }
}

impl AttackSurface {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        s.push_str("=== ATTACK SURFACE ===\n\n");
        s.push_str(&format!("Score: {}/100\n\n", self.score));

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
        s.push_str(&format!("**Score:** {}/100\n\n", self.score));

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
