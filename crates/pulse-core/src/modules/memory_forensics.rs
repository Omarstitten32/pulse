//! Fileless malware detection via /proc/`[pid]`/maps and /proc/`[pid]`/exe.
//!
//! Detects processes running without a file on disk (`memfd_create`),
//! whose executable has been deleted, or whose mappings contain
//! writable+executable pages (RWX — the primary shellcode indicator).
//!
//! Pure read of /proc. No ptrace, no kernel module, no root required.
//!
//! ## Whitelist
//!
//! JIT runtimes (Android ART, V8, Firefox Spidermonkey) legitimately
//! allocate RWX pages and memfd regions. Without a whitelist, every
//! Java/JavaScript process would appear suspicious. The built-in
//! whitelist covers the well-known system and runtime processes; any
//! other process is reported as actionable. Use `--verbose` to see
//! the whitelisted findings too.

use crate::types::Confidence;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessFinding {
    pub pid: u32,
    pub name: String,
    pub rwx_pages: usize,
    pub memfd: bool,
    pub deleted_exe: bool,
    pub threat_score: u8,
    pub whitelisted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryForensicReport {
    pub scanned: usize,
    pub unreadable: usize,
    pub findings: Vec<FilelessFinding>,
    pub whitelisted: usize,
    pub actionable: usize,
    pub total_rwx_pages: usize,
    pub total_memfd: usize,
    pub total_deleted_exe: usize,
    pub score: Option<u32>,
    pub sources_read: u32,
    pub sources_total: u32,
    pub confidence: Confidence,
}

impl Default for MemoryForensicReport {
    fn default() -> Self {
        Self {
            scanned: 0,
            unreadable: 0,
            findings: Vec::new(),
            whitelisted: 0,
            actionable: 0,
            total_rwx_pages: 0,
            total_memfd: 0,
            total_deleted_exe: 0,
            score: None,
            sources_read: 0,
            sources_total: 2,
            confidence: Confidence::None,
        }
    }
}

/// Return true if `name` matches a known-safe system or runtime process.
///
/// Matching is case-insensitive substring for long patterns, and
/// prefix-only for short patterns (to avoid matching "success" for
/// "cess", for example). This is heuristic, not absolute; malware
/// can masquerade as any of these names. Use `--verbose` to disable.
pub fn is_whitelisted(name: &str) -> bool {
    let n = name.to_lowercase();

    const CONTAINS: &[&str] = &[
        // Android system
        "zygote",
        "system_server",
        "surfaceflinger",
        "android.hardware",
        "android.system",
        "audioserver",
        "cameraserver",
        "mediaserver",
        "webview_zygote",
        "com.android",
        "com.google",
        "com.miui",
        "com.xiaomi",
        "com.termux",
        // Desktop JIT runtimes
        "chrome",
        "chromium",
        "firefox",
        "electron",
        "webview",
        "blastbuffer",
        "minikin",
        "hwui",
        "skia",
        // Build tools that legitimately JIT
        "rustc",
        "cargo",
    ];

    if CONTAINS.iter().any(|p| n.contains(p)) {
        return true;
    }

    // Prefix-only patterns (Linux truncates comm to 15 chars)
    n.starts_with("cess") // Xiaomi cessService (truncated)
        || n.starts_with("android.")
        || n.starts_with("hal.")
}

/// Parse the content of `/proc/`[pid]`/maps`.
///
/// Returns `(rwx_page_count, has_memfd)`.
pub fn parse_maps(content: &str) -> (usize, bool) {
    let mut rwx = 0usize;
    let mut memfd = false;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let _addr = parts.next();
        if let Some(perms) = parts.next() {
            if perms.starts_with("rwx") {
                rwx += 1;
            }
        }
        if line.contains("/memfd:") {
            memfd = true;
        }
    }
    (rwx, memfd)
}

/// Compute a 0-100 threat score from the three indicators.
pub fn compute_threat(rwx_pages: usize, memfd: bool, deleted_exe: bool) -> u8 {
    let mut score: u8 = 0;
    if rwx_pages > 0 {
        score = score.saturating_add(50);
    }
    if memfd {
        score = score.saturating_add(40);
    }
    if deleted_exe {
        score = score.saturating_add(30);
    }
    score.min(100)
}

impl MemoryForensicReport {
    pub fn collect() -> Self {
        let mut report = Self::default();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return report,
        };

        let mut readable_maps: u32 = 0;
        let mut readable_exe: u32 = 0;

        for entry in proc_dir.flatten() {
            let pid_str = match entry.file_name().to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            report.scanned += 1;

            let maps_path = format!("/proc/{}/maps", pid);
            let (rwx, memfd, maps_ok) = match fs::read_to_string(&maps_path) {
                Ok(content) => {
                    readable_maps += 1;
                    let (r, m) = parse_maps(&content);
                    (r, m, true)
                }
                Err(_) => (0usize, false, false),
            };

            let exe_path = format!("/proc/{}/exe", pid);
            let (deleted, exe_ok) = match fs::read_link(&exe_path) {
                Ok(target) => {
                    readable_exe += 1;
                    (target.to_string_lossy().contains("(deleted)"), true)
                }
                Err(_) => (false, false),
            };

            if !maps_ok && !exe_ok {
                report.unreadable += 1;
                continue;
            }

            if rwx > 0 || memfd || deleted {
                let name = fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| format!("pid:{}", pid));

                let threat = compute_threat(rwx, memfd, deleted);
                let wl = is_whitelisted(&name);

                report.total_rwx_pages += rwx;
                if memfd {
                    report.total_memfd += 1;
                }
                if deleted {
                    report.total_deleted_exe += 1;
                }
                if wl {
                    report.whitelisted += 1;
                } else {
                    report.actionable += 1;
                }

                report.findings.push(FilelessFinding {
                    pid,
                    name,
                    rwx_pages: rwx,
                    memfd,
                    deleted_exe: deleted,
                    threat_score: threat,
                    whitelisted: wl,
                });
            }
        }

        report
            .findings
            .sort_by_key(|a| std::cmp::Reverse(a.threat_score));

        let read = ((readable_maps > 0) as u32) + ((readable_exe > 0) as u32);
        report.sources_read = read;
        report.confidence = Confidence::from_counts(read, 2);

        // Score reflects actionable findings only. Whitelisted entries
        // (known-safe JIT runtimes) do not penalize the host.
        let actionable_high = report
            .findings
            .iter()
            .filter(|f| !f.whitelisted && f.threat_score >= 50)
            .count() as u32;

        report.score = if read == 0 {
            None
        } else {
            Some(100u32.saturating_sub(actionable_high.min(10) * 10))
        };

        report
    }

    fn render_header(&self, s: &mut String, markdown: bool) {
        if markdown {
            s.push_str("# Memory Forensic Scan\n\n");
            match self.score {
                Some(n) => s.push_str(&format!(
                    "**Score:** {}/100  ·  **Confidence:** {} ({}/{})\n\n",
                    n,
                    self.confidence.label(),
                    self.sources_read,
                    self.sources_total
                )),
                None => s.push_str(&format!(
                    "**Score:** N/A  ·  **Confidence:** None ({}/{})\n\n",
                    self.sources_read, self.sources_total
                )),
            }
        } else {
            s.push_str("=== MEMORY FORENSIC SCAN ===\n\n");
            match self.score {
                Some(n) => s.push_str(&format!(
                    "Score : {}/100  (Confidence: {} — {}/{} sources)\n",
                    n,
                    self.confidence.label(),
                    self.sources_read,
                    self.sources_total
                )),
                None => s.push_str(&format!(
                    "Score : N/A  (Confidence: None — {}/{} sources)\n",
                    self.sources_read, self.sources_total
                )),
            }
        }
    }

    fn render_summary(&self, s: &mut String, markdown: bool) {
        if markdown {
            s.push_str("## Summary\n\n");
            s.push_str(&format!("- Processes scanned: **{}**\n", self.scanned));
            s.push_str(&format!("- Unreadable: {}\n", self.unreadable));
            s.push_str(&format!(
                "- Suspicious total: **{}**\n",
                self.findings.len()
            ));
            s.push_str(&format!(
                "  - Whitelisted (system/JIT): {}\n",
                self.whitelisted
            ));
            s.push_str(&format!("  - **Actionable: {}**\n", self.actionable));
            s.push_str(&format!("- RWX pages total: {}\n", self.total_rwx_pages));
            s.push_str(&format!("- memfd executions: {}\n", self.total_memfd));
            s.push_str(&format!("- Deleted exes: {}\n\n", self.total_deleted_exe));
        } else {
            s.push_str(&format!("Processes scanned : {}\n", self.scanned));
            s.push_str(&format!("Unreadable        : {}\n", self.unreadable));
            s.push_str(&format!("Suspicious total  : {}\n", self.findings.len()));
            s.push_str(&format!(
                "  ├─ Whitelisted  : {} (system/JIT runtimes)\n",
                self.whitelisted
            ));
            s.push_str(&format!("  └─ Actionable   : {}\n", self.actionable));
            s.push_str(&format!("RWX pages total   : {}\n", self.total_rwx_pages));
            s.push_str(&format!("memfd executions  : {}\n", self.total_memfd));
            s.push_str(&format!(
                "Deleted exes      : {}\n\n",
                self.total_deleted_exe
            ));
        }
    }

    fn render_finding_text(&self, s: &mut String, f: &FilelessFinding) {
        let sev = if f.threat_score >= 80 {
            "CRITICAL"
        } else if f.threat_score >= 50 {
            "HIGH"
        } else {
            "MEDIUM"
        };
        let tag = if f.whitelisted { " [whitelisted]" } else { "" };
        s.push_str(&format!(
            "[{}] pid={} name={} threat={}{}\n",
            sev, f.pid, f.name, f.threat_score, tag
        ));
        if f.rwx_pages > 0 {
            s.push_str(&format!("  - {} RWX page(s)\n", f.rwx_pages));
        }
        if f.memfd {
            s.push_str("  - memfd execution (fileless)\n");
        }
        if f.deleted_exe {
            s.push_str("  - deleted executable\n");
        }
    }

    pub fn render_text(&self) -> String {
        self.render_text_with(false)
    }

    pub fn render_text_with(&self, show_all: bool) -> String {
        let mut s = String::new();
        self.render_header(&mut s, false);
        self.render_summary(&mut s, false);

        let display: Vec<&FilelessFinding> = self
            .findings
            .iter()
            .filter(|f| show_all || !f.whitelisted)
            .collect();

        if display.is_empty() {
            if self.whitelisted > 0 && !show_all {
                s.push_str(&format!(
                    "No actionable findings ({} whitelisted — use --verbose to see).\n",
                    self.whitelisted
                ));
            } else {
                s.push_str("No fileless indicators detected.\n");
            }
            return s;
        }

        for f in display {
            self.render_finding_text(&mut s, f);
        }
        s
    }

    pub fn render_markdown(&self) -> String {
        self.render_markdown_with(false)
    }

    pub fn render_markdown_with(&self, show_all: bool) -> String {
        let mut s = String::new();
        self.render_header(&mut s, true);
        self.render_summary(&mut s, true);

        let display: Vec<&FilelessFinding> = self
            .findings
            .iter()
            .filter(|f| show_all || !f.whitelisted)
            .collect();

        if display.is_empty() {
            if self.whitelisted > 0 && !show_all {
                s.push_str(&format!(
                    "_No actionable findings ({} whitelisted)._ Use `--verbose` to include them.\n",
                    self.whitelisted
                ));
            } else {
                s.push_str("_No fileless indicators detected._\n");
            }
            return s;
        }

        s.push_str("## Findings\n\n");
        s.push_str("| Severity | PID | Name | Threat | RWX | memfd | deleted | WL |\n");
        s.push_str("|----------|-----|------|--------|-----|-------|---------|----|\n");
        for f in display {
            let sev = if f.threat_score >= 80 {
                "CRITICAL"
            } else if f.threat_score >= 50 {
                "HIGH"
            } else {
                "MEDIUM"
            };
            s.push_str(&format!(
                "| {} | {} | `{}` | {} | {} | {} | {} | {} |\n",
                sev,
                f.pid,
                f.name,
                f.threat_score,
                f.rwx_pages,
                f.memfd,
                f.deleted_exe,
                if f.whitelisted { "Y" } else { "" }
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_report_is_empty() {
        let r = MemoryForensicReport::default();
        assert_eq!(r.scanned, 0);
        assert!(r.findings.is_empty());
        assert_eq!(r.whitelisted, 0);
        assert_eq!(r.actionable, 0);
        assert_eq!(r.score, None);
    }

    #[test]
    fn parse_maps_rwx_detected() {
        let content = "7f0000000000-7f0000001000 rwxp 00000000 00:00 0\n";
        let (rwx, memfd) = parse_maps(content);
        assert_eq!(rwx, 1);
        assert!(!memfd);
    }

    #[test]
    fn parse_maps_memfd_detected() {
        let content = "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 /memfd:foo (deleted)\n";
        let (rwx, memfd) = parse_maps(content);
        assert_eq!(rwx, 0);
        assert!(memfd);
    }

    #[test]
    fn parse_maps_empty() {
        let (rwx, memfd) = parse_maps("");
        assert_eq!(rwx, 0);
        assert!(!memfd);
    }

    #[test]
    fn compute_threat_clean() {
        assert_eq!(compute_threat(0, false, false), 0);
    }

    #[test]
    fn compute_threat_all_three() {
        assert_eq!(compute_threat(3, true, true), 100);
    }

    #[test]
    fn compute_threat_clamps() {
        for rwx in [0usize, 1, 5, 100] {
            for memfd in [false, true] {
                for deleted in [false, true] {
                    assert!(compute_threat(rwx, memfd, deleted) <= 100);
                }
            }
        }
    }

    // ─── whitelist tests ───

    #[test]
    fn wl_zygote() {
        assert!(is_whitelisted("zygote"));
        assert!(is_whitelisted("zygote64"));
    }

    #[test]
    fn wl_android_system() {
        assert!(is_whitelisted("system_server"));
        assert!(is_whitelisted("surfaceflinger"));
        assert!(is_whitelisted("android.hardware.camera"));
        assert!(is_whitelisted("android.system.netd"));
    }

    #[test]
    fn wl_com_android() {
        assert!(is_whitelisted("com.android.systemui"));
        assert!(is_whitelisted("com.google.android.gms"));
        assert!(is_whitelisted("com.miui.home"));
        assert!(is_whitelisted("com.termux"));
    }

    #[test]
    fn wl_jit_runtimes() {
        assert!(is_whitelisted("chrome"));
        assert!(is_whitelisted("firefox"));
        assert!(is_whitelisted("electron"));
        assert!(is_whitelisted("rustc"));
    }

    #[test]
    fn wl_cess_prefix() {
        assert!(is_whitelisted("cessService0:13"));
        assert!(is_whitelisted("cessService0:14"));
    }

    #[test]
    fn wl_case_insensitive() {
        assert!(is_whitelisted("ZYGOTE64"));
        assert!(is_whitelisted("System_Server"));
        assert!(is_whitelisted("CessService"));
    }

    #[test]
    fn wl_unknown_is_actionable() {
        assert!(!is_whitelisted("malware"));
        assert!(!is_whitelisted("nc"));
        assert!(!is_whitelisted("bash"));
        assert!(!is_whitelisted("python3"));
        assert!(!is_whitelisted("node"));
    }

    #[test]
    fn wl_does_not_match_substring_false_positive() {
        // "process" contains "cess" but shouldn't be whitelisted
        assert!(!is_whitelisted("process"));
        assert!(!is_whitelisted("success"));
        // "partial" contains "art" but "art" isn't in whitelist anyway
        assert!(!is_whitelisted("partial"));
    }

    // ─── report-level tests ───

    #[test]
    fn collect_does_not_panic() {
        let r = MemoryForensicReport::collect();
        assert!(r.scanned > 0);
        assert!(r.sources_read <= r.sources_total);
        assert_eq!(r.whitelisted + r.actionable, r.findings.len());
    }

    #[test]
    fn collect_score_none_iff_no_reads() {
        let r = MemoryForensicReport::collect();
        match r.score {
            Some(_) => assert!(r.sources_read > 0),
            None => assert_eq!(r.sources_read, 0),
        }
    }

    #[test]
    fn collect_confidence_matches_counts() {
        let r = MemoryForensicReport::collect();
        let expected = Confidence::from_counts(r.sources_read, r.sources_total);
        assert_eq!(r.confidence, expected);
    }

    #[test]
    fn render_text_has_header() {
        let r = MemoryForensicReport::collect();
        let s = r.render_text();
        assert!(s.contains("MEMORY FORENSIC SCAN"));
        assert!(s.contains("Processes scanned"));
        assert!(s.contains("Whitelisted"));
        assert!(s.contains("Actionable"));
    }

    #[test]
    fn render_markdown_has_headers() {
        let r = MemoryForensicReport::collect();
        let s = r.render_markdown();
        assert!(s.contains("# Memory Forensic Scan"));
        assert!(s.contains("## Summary"));
    }

    #[test]
    fn render_default_hides_whitelisted() {
        let r = MemoryForensicReport::collect();
        if r.whitelisted > 0 && r.actionable == 0 {
            let s = r.render_text();
            assert!(s.contains("whitelisted") || s.contains("No actionable"));
        }
    }

    #[test]
    fn render_verbose_shows_all() {
        let r = MemoryForensicReport::collect();
        if r.whitelisted > 0 {
            let s = r.render_text_with(true);
            assert!(s.contains("[whitelisted]"));
        }
    }
}
