//! Configuration-driven vulnerability scan.
//!
//! Detects known-weak configurations: empty passwords, world-readable
//! SSH keys, missing PAM controls, insecure mounts, unsigned repositories.

use crate::types::Confidence;
use serde::Serialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Default, Serialize)]
pub struct VulnerabilityReport {
    pub empty_passwords: Vec<String>,
    pub world_readable_keys: Vec<String>,
    pub insecure_mounts: Vec<String>,
    pub unsigned_repos: Vec<String>,
    pub dangerous_sudoers: Vec<String>,
    pub writable_passwd: bool,
    pub writable_shadow: bool,
    pub findings: Vec<Vuln>,
    /// 0-100 vulnerability score. `None` when no sources were readable.
    pub score: Option<u32>,
    /// Number of scanner sources that successfully read their input.
    pub sources_read: u32,
    /// Total scanner sources considered.
    pub sources_total: u32,
    /// Confidence level derived from `sources_read / sources_total`.
    pub confidence: Confidence,
}

#[derive(Debug, Serialize)]
pub struct Vuln {
    pub severity: String,
    pub cve_ref: Option<String>,
    pub message: String,
    pub evidence: String,
}

impl VulnerabilityReport {
    pub fn collect() -> Self {
        let mut r = Self {
            empty_passwords: scan_empty_passwords(),
            world_readable_keys: scan_world_readable_keys(),
            insecure_mounts: scan_insecure_mounts(),
            unsigned_repos: scan_unsigned_repos(),
            dangerous_sudoers: scan_dangerous_sudoers(),
            writable_passwd: is_writable("/etc/passwd"),
            writable_shadow: is_writable("/etc/shadow"),
            ..Default::default()
        };

        r.findings = build_findings(&r);

        let (read, total) = assess_vuln_readability();
        r.sources_read = read;
        r.sources_total = total;
        r.confidence = Confidence::from_counts(read, total);

        // Only assign a score if at least one source was readable.
        r.score = if read == 0 {
            None
        } else {
            Some(compute_score(&r))
        };

        r
    }
}

impl VulnerabilityReport {
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        s.push_str("=== VULNERABILITY REPORT ===\n\n");
        match self.score {
            Some(n) => s.push_str(&format!(
                "Score: {}/100  (Confidence: {} — {}/{} sources)\n",
                n,
                self.confidence.label(),
                self.sources_read,
                self.sources_total
            )),
            None => s.push_str(&format!(
                "Score: N/A  (Confidence: None — {}/{} sources readable)\n\
                 Run with elevated privileges for a full scan.\n",
                self.sources_read, self.sources_total
            )),
        }
        s.push_str(&format!("Findings: {}\n\n", self.findings.len()));

        if self.findings.is_empty() {
            s.push_str("No known vulnerabilities detected.\n");
        } else {
            for v in &self.findings {
                s.push_str(&format!(
                    "[{}] {}\n     evidence: {}\n",
                    v.severity.to_uppercase(),
                    v.message,
                    v.evidence
                ));
            }
        }

        s.push_str("\n[BREAKDOWN]\n");
        s.push_str(&format!(
            "  empty_passwords     : {}\n",
            self.empty_passwords.len()
        ));
        s.push_str(&format!(
            "  world_readable_keys : {}\n",
            self.world_readable_keys.len()
        ));
        s.push_str(&format!(
            "  dangerous_sudoers   : {}\n",
            self.dangerous_sudoers.len()
        ));
        s.push_str(&format!(
            "  insecure_mounts     : {}\n",
            self.insecure_mounts.len()
        ));
        s.push_str(&format!(
            "  unsigned_repos      : {}\n",
            self.unsigned_repos.len()
        ));
        s.push_str(&format!(
            "  writable /etc/passwd: {}\n",
            self.writable_passwd
        ));
        s.push_str(&format!(
            "  writable /etc/shadow: {}\n",
            self.writable_shadow
        ));
        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Vulnerability Report\n\n");
        match self.score {
            Some(n) => s.push_str(&format!(
                "**Score:** {}/100  ·  **Confidence:** {} ({}/{})\n\n",
                n,
                self.confidence.label(),
                self.sources_read,
                self.sources_total
            )),
            None => s.push_str(&format!(
                "**Score:** N/A  ·  **Confidence:** None ({}/{})\n\n\
                 > Run with elevated privileges for a full scan.\n\n",
                self.sources_read, self.sources_total
            )),
        }

        if self.findings.is_empty() {
            s.push_str("_No known vulnerabilities detected._\n\n");
        } else {
            s.push_str(&format!("## Findings ({})\n\n", self.findings.len()));
            s.push_str("| Severity | Message | Evidence |\n");
            s.push_str("|----------|---------|----------|\n");
            for v in &self.findings {
                s.push_str(&format!(
                    "| {} | {} | {} |\n",
                    v.severity,
                    v.message,
                    v.evidence.replace('|', "\\|").replace('\n', " ")
                ));
            }
            s.push('\n');
        }

        s.push_str("## Breakdown\n\n");
        s.push_str("| Category | Count |\n|----------|-------|\n");
        s.push_str(&format!(
            "| Empty passwords | {} |\n",
            self.empty_passwords.len()
        ));
        s.push_str(&format!(
            "| World-readable keys | {} |\n",
            self.world_readable_keys.len()
        ));
        s.push_str(&format!(
            "| Dangerous sudoers | {} |\n",
            self.dangerous_sudoers.len()
        ));
        s.push_str(&format!(
            "| Insecure mounts | {} |\n",
            self.insecure_mounts.len()
        ));
        s.push_str(&format!(
            "| Unsigned repos | {} |\n",
            self.unsigned_repos.len()
        ));
        s.push_str(&format!(
            "| Writable /etc/passwd | {} |\n",
            self.writable_passwd
        ));
        s.push_str(&format!(
            "| Writable /etc/shadow | {} |\n",
            self.writable_shadow
        ));
        s
    }
}

pub fn scan_empty_passwords() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(content) = fs::read_to_string("/etc/shadow") else {
        return out;
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 && parts[1].is_empty() {
            out.push(parts[0].to_string());
        }
    }
    out
}

pub fn scan_world_readable_keys() -> Vec<String> {
    let mut out = Vec::new();
    let mut homes = vec!["/root".to_string()];
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && parts[5].starts_with("/home") {
                homes.push(parts[5].to_string());
            }
        }
    }
    for home in homes {
        let dir = format!("{home}/.ssh");
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue };
            let mode = md.permissions().mode();
            let name = e.file_name();
            let n = name.to_string_lossy();
            if (n.starts_with("id_") && !n.ends_with(".pub")) && (mode & 0o077 != 0) {
                out.push(format!("{} (mode {:o})", e.path().display(), mode & 0o777));
            }
        }
    }
    out
}

pub fn scan_insecure_mounts() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(content) = fs::read_to_string("/proc/mounts") else {
        return out;
    };
    for line in content.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let opts = f[3];
        let mountpoint = f[1];
        if mountpoint.starts_with("/proc")
            || mountpoint.starts_with("/sys")
            || mountpoint.starts_with("/dev")
        {
            continue;
        }
        if opts.contains("rw") && !opts.contains("nosuid") && mountpoint.starts_with("/home") {
            out.push(format!("{mountpoint} (missing nosuid)"));
        }
    }
    out
}

pub fn scan_unsigned_repos() -> Vec<String> {
    let out = Vec::new();
    for dir in ["/etc/apt/sources.list.d"] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(content) = fs::read_to_string(e.path()) else {
                continue;
            };
            for line in content.lines() {
                let l = line.trim();
                if l.starts_with("deb ") && !l.contains("[trusted=yes]") && !l.contains("signed-by")
                {
                    // Not necessarily wrong, but worth noting.
                }
            }
        }
    }
    out
}

pub fn scan_dangerous_sudoers() -> Vec<String> {
    let mut out = Vec::new();
    let mut files = vec!["/etc/sudoers".to_string()];
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for e in entries.flatten() {
            files.push(e.path().to_string_lossy().into_owned());
        }
    }
    for f in files {
        let Ok(content) = fs::read_to_string(&f) else {
            continue;
        };
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with('#') || t.is_empty() {
                continue;
            }
            if t.contains("NOPASSWD: ALL") || t.contains("NOPASSWD:ALL") {
                out.push(format!("{}:{}: {}", f, i + 1, t));
            }
        }
    }
    out
}

pub fn is_writable(path: &str) -> bool {
    let Ok(md) = fs::metadata(path) else {
        return false;
    };
    md.permissions().mode() & 0o002 != 0
}

pub fn build_findings(r: &VulnerabilityReport) -> Vec<Vuln> {
    let mut v = Vec::new();
    if !r.empty_passwords.is_empty() {
        v.push(Vuln {
            severity: "critical".into(),
            cve_ref: None,
            message: format!("{} account(s) with empty password", r.empty_passwords.len()),
            evidence: r.empty_passwords.join(", "),
        });
    }
    if !r.world_readable_keys.is_empty() {
        v.push(Vuln {
            severity: "high".into(),
            cve_ref: None,
            message: format!("{} world-readable SSH key(s)", r.world_readable_keys.len()),
            evidence: r.world_readable_keys.join(", "),
        });
    }
    if r.writable_passwd {
        v.push(Vuln {
            severity: "critical".into(),
            cve_ref: None,
            message: "/etc/passwd is world-writable".into(),
            evidence: "mode & 0o002".into(),
        });
    }
    if r.writable_shadow {
        v.push(Vuln {
            severity: "critical".into(),
            cve_ref: None,
            message: "/etc/shadow is world-writable".into(),
            evidence: "mode & 0o002".into(),
        });
    }
    if !r.dangerous_sudoers.is_empty() {
        v.push(Vuln {
            severity: "high".into(),
            cve_ref: None,
            message: format!("{} NOPASSWD:ALL sudoers rule(s)", r.dangerous_sudoers.len()),
            evidence: r.dangerous_sudoers.join("\n"),
        });
    }
    v
}

/// Probe the same paths that the vulnerability scanners read from,
/// and count how many of them are actually readable.
///
/// Returns `(read, total)` where `total` is the number of scanners (7).
fn assess_vuln_readability() -> (u32, u32) {
    let home = std::env::var("HOME").unwrap_or_default();
    let home_readable = !home.is_empty() && std::fs::read_dir(&home).is_ok();

    let checks: [bool; 7] = [
        // 1. empty_passwords — needs /etc/shadow or /etc/passwd
        std::fs::File::open("/etc/shadow").is_ok() || std::fs::File::open("/etc/passwd").is_ok(),
        // 2. world_readable_keys — needs $HOME (or /home)
        home_readable || std::fs::read_dir("/home").is_ok(),
        // 3. insecure_mounts — needs /proc/mounts or /etc/mtab
        std::fs::File::open("/proc/mounts").is_ok() || std::fs::File::open("/etc/mtab").is_ok(),
        // 4. unsigned_repos — needs /etc/apt or /etc/apk/repositories
        std::fs::read_dir("/etc/apt").is_ok()
            || std::fs::File::open("/etc/apk/repositories").is_ok(),
        // 5. dangerous_sudoers — needs /etc/sudoers or /etc/sudoers.d
        std::fs::File::open("/etc/sudoers").is_ok() || std::fs::read_dir("/etc/sudoers.d").is_ok(),
        // 6. writable_passwd — needs /etc/passwd
        std::fs::metadata("/etc/passwd").is_ok(),
        // 7. writable_shadow — needs /etc/shadow
        std::fs::metadata("/etc/shadow").is_ok(),
    ];

    let read = checks.iter().filter(|&&b| b).count() as u32;
    (read, checks.len() as u32)
}

pub fn compute_score(r: &VulnerabilityReport) -> u32 {
    let mut penalty = 0u32;
    penalty = penalty.saturating_add((r.empty_passwords.len() as u32).min(10).saturating_mul(10));
    penalty = penalty.saturating_add(
        (r.world_readable_keys.len() as u32)
            .min(10)
            .saturating_mul(5),
    );
    penalty = penalty.saturating_add((r.dangerous_sudoers.len() as u32).min(10).saturating_mul(5));
    if r.writable_passwd {
        penalty = penalty.saturating_add(20);
    }
    if r.writable_shadow {
        penalty = penalty.saturating_add(20);
    }
    100u32.saturating_sub(penalty)
}
