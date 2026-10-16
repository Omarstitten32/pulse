//! Kernel hardening analysis.
//!
//! Reads kernel tunables from `/proc/sys/` and `/sys/kernel/`,
//! computes a weighted score, and produces actionable findings.

use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct HardeningReport {
    pub checks: Vec<Check>,
    pub score: u32,
    pub max_score: u32,
    pub grade: char,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub name: String,
    pub path: String,
    pub value: String,
    pub expected: String,
    /// Tri-state result: Ok / Fail / Unreadable.
    pub state: CheckState,
    /// Kept for backward compatibility: true iff state == Ok.
    pub enabled: bool,
    /// true iff the underlying tunable could be read.
    pub readable: bool,
    pub weight: u32,
    pub critical: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub check_id: String,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Result of evaluating a single hardening check.
///
/// Distinguishes "the kernel says this is insecure" (Fail) from
/// "we could not read the tunable" (Unreadable). Only Ok contributes
/// to the score; Fail and Unreadable both leave the score unfulfilled,
/// but only Fail is treated as an actual security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CheckState {
    Ok,
    Fail,
    Unreadable,
}

impl CheckState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Fail => "FAIL",
            Self::Unreadable => "UNREADABLE",
        }
    }

    pub fn mark(self) -> &'static str {
        match self {
            Self::Ok => "[+]",
            Self::Fail => "[-]",
            Self::Unreadable => "[?]",
        }
    }
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl HardeningReport {
    pub fn collect() -> Self {
        let mut checks = Vec::new();
        let mut findings = Vec::new();
        let mut score = 0u32;
        let mut max_score = 0u32;

        for spec in CHECKS {
            let value_opt: Option<String> = read_trim(spec.path);

            let (state, value) = match value_opt {
                Some(v) => {
                    let enabled = value_matches(&v, spec);
                    let state = if enabled {
                        CheckState::Ok
                    } else {
                        CheckState::Fail
                    };
                    (state, v)
                }
                None => (CheckState::Unreadable, String::new()),
            };

            max_score += spec.weight;

            match state {
                CheckState::Ok => {
                    score += spec.weight;
                }
                CheckState::Fail => {
                    findings.push(Finding {
                        severity: spec.severity,
                        check_id: spec.id.into(),
                        message: format!("{} is not set to a secure value", spec.name),
                        evidence: format!("{} = {}", spec.path, value),
                    });
                }
                CheckState::Unreadable => {
                    // Not a security finding. Recorded separately so users
                    // know the score is based on partial data.
                }
            }

            checks.push(Check {
                id: spec.id.into(),
                name: spec.name.into(),
                path: spec.path.into(),
                value,
                expected: spec.expected.into(),
                state,
                enabled: matches!(state, CheckState::Ok),
                readable: !matches!(state, CheckState::Unreadable),
                weight: spec.weight,
                critical: spec.severity as u8 == Severity::Critical as u8,
            });
        }

        let grade = grade_for(score, max_score);
        Self {
            checks,
            score,
            max_score,
            grade,
            findings,
        }
    }

    pub fn render_text(&self) -> String {
        let mut s = String::new();
        s.push_str("=== KERNEL HARDENING AUDIT ===\n\n");
        s.push_str(&format!(
            "Score : {}/{}  (Grade {})\n",
            self.score, self.max_score, self.grade
        ));
        s.push_str(&format!("Checks: {}\n", self.checks.len()));
        s.push_str(&format!(
            "Readable: {}/{} ({} unreadable)\n",
            self.readable_count(),
            self.checks.len(),
            self.unreadable_count()
        ));
        s.push_str(&format!("Issues: {}\n\n", self.findings.len()));

        s.push_str("[CHECKS]\n");
        for c in &self.checks {
            s.push_str(&format!(
                "  {} {:<28} {:<10} expected={} actual={}\n",
                c.state.mark(),
                c.name,
                c.state.label(),
                c.expected,
                if c.readable {
                    c.value.as_str()
                } else {
                    "<unreadable>"
                }
            ));
        }

        if !self.findings.is_empty() {
            s.push_str("\n[FINDINGS]\n");
            for f in &self.findings {
                s.push_str(&format!(
                    "  [{}] {} — {}\n     {}\n",
                    f.severity.as_str().to_uppercase(),
                    f.check_id,
                    f.message,
                    f.evidence
                ));
            }
        }

        s
    }

    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# Kernel Hardening Audit\n\n");
        s.push_str(&format!(
            "**Score:** {}/{} (Grade **{}**)\n\n",
            self.score, self.max_score, self.grade
        ));
        s.push_str("## Checks\n\n");
        s.push_str("| State | Check | Expected | Actual | Weight |\n");
        s.push_str("|-------|-------|----------|--------|--------|\n");
        for c in &self.checks {
            s.push_str(&format!(
                "| {} | `{}` | {} | {} | {} |\n",
                c.state.label(),
                c.name,
                c.expected,
                if c.readable {
                    c.value.as_str()
                } else {
                    "<unreadable>"
                },
                c.weight
            ));
        }

        if !self.findings.is_empty() {
            s.push_str("\n## Findings\n\n");
            s.push_str("| Severity | Check | Message |\n");
            s.push_str("|----------|-------|---------|\n");
            for f in &self.findings {
                s.push_str(&format!(
                    "| {} | `{}` | {} |\n",
                    f.severity.as_str(),
                    f.check_id,
                    f.message
                ));
            }
        }
        s
    }

    /// Number of checks whose tunable could be read (Ok or Fail).
    pub fn readable_count(&self) -> usize {
        self.checks.iter().filter(|c| c.readable).count()
    }

    /// Number of checks that were unreadable (permission denied, missing).
    pub fn unreadable_count(&self) -> usize {
        self.checks.iter().filter(|c| !c.readable).count()
    }

    pub fn summary(&self) -> String {
        format!(
            "Hardening score: {}/{} (grade {}) — {} findings ({} readable, {} unreadable)",
            self.score,
            self.max_score,
            self.grade,
            self.findings.len(),
            self.readable_count(),
            self.unreadable_count()
        )
    }
}

pub struct CheckSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub path: &'static str,
    pub expected: &'static str,
    pub weight: u32,
    pub severity: Severity,
    pub kind: MatchKind,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum MatchKind {
    Exact,
    MinAtLeast(u64),
    ZeroMeansEnabled,
}

pub fn value_matches(value: &str, spec: &CheckSpec) -> bool {
    match spec.kind {
        MatchKind::Exact => value == spec.expected,
        MatchKind::MinAtLeast(min) => value.parse::<u64>().map(|v| v >= min).unwrap_or(false),
        MatchKind::ZeroMeansEnabled => value == "0",
    }
}

pub fn read_trim(path: &str) -> Option<String> {
    if !Path::new(path).exists() {
        return None;
    }
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn grade_for(score: u32, max: u32) -> char {
    if max == 0 {
        return 'F';
    }
    let pct = score * 100 / max;
    match pct {
        95..=100 => 'A',
        85..=94 => 'B',
        70..=84 => 'C',
        50..=69 => 'D',
        _ => 'F',
    }
}

static CHECKS: &[CheckSpec] = &[
    CheckSpec {
        id: "kaslr",
        name: "Kernel ASLR",
        path: "/proc/sys/kernel/randomize_va_space",
        expected: "2",
        weight: 10,
        severity: Severity::Critical,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "dmesg_restrict",
        name: "dmesg restricted to root",
        path: "/proc/sys/kernel/dmesg_restrict",
        expected: "1",
        weight: 6,
        severity: Severity::High,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "kptr_restrict",
        name: "Kernel pointers hidden",
        path: "/proc/sys/kernel/kptr_restrict",
        expected: "2",
        weight: 8,
        severity: Severity::High,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "perf_paranoid",
        name: "perf_event_paranoid",
        path: "/proc/sys/kernel/perf_event_paranoid",
        expected: "3",
        weight: 8,
        severity: Severity::High,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "unprivileged_bpf",
        name: "Unprivileged BPF disabled",
        path: "/proc/sys/kernel/unprivileged_bpf_disabled",
        expected: "1",
        weight: 10,
        severity: Severity::Critical,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "unprivileged_userns",
        name: "Unprivileged user namespaces disabled",
        path: "/proc/sys/kernel/unprivileged_userns_clone",
        expected: "0",
        weight: 8,
        severity: Severity::High,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "yama_ptrace",
        name: "YAMA ptrace scope",
        path: "/proc/sys/kernel/yama/ptrace_scope",
        expected: "1",
        weight: 6,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "kexec_load_disabled",
        name: "kexec disabled",
        path: "/proc/sys/kernel/kexec_load_disabled",
        expected: "1",
        weight: 5,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "panic_on_oops",
        name: "Panic on oops",
        path: "/proc/sys/kernel/panic_on_oops",
        expected: "1",
        weight: 3,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "modules_disabled",
        name: "Kernel module loading disabled",
        path: "/proc/sys/kernel/modules_disabled",
        expected: "1",
        weight: 5,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "suid_dumpable",
        name: "SUID core dumps disabled",
        path: "/proc/sys/fs/suid_dumpable",
        expected: "0",
        weight: 6,
        severity: Severity::High,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "protected_symlinks",
        name: "Protected symlinks",
        path: "/proc/sys/fs/protected_symlinks",
        expected: "1",
        weight: 4,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "protected_hardlinks",
        name: "Protected hardlinks",
        path: "/proc/sys/fs/protected_hardlinks",
        expected: "1",
        weight: 4,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "protected_fifos",
        name: "Protected FIFOs",
        path: "/proc/sys/fs/protected_fifos",
        expected: "2",
        weight: 3,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "protected_regular",
        name: "Protected regular files",
        path: "/proc/sys/fs/protected_regular",
        expected: "2",
        weight: 3,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "ip_forward",
        name: "IP forwarding disabled",
        path: "/proc/sys/net/ipv4/ip_forward",
        expected: "0",
        weight: 4,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "icmp_echo_ignore_broadcasts",
        name: "Ignore ICMP broadcasts",
        path: "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
        expected: "1",
        weight: 3,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "tcp_syncookies",
        name: "TCP SYN cookies",
        path: "/proc/sys/net/ipv4/tcp_syncookies",
        expected: "1",
        weight: 4,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "rp_filter",
        name: "Reverse path filtering",
        path: "/proc/sys/net/ipv4/conf/all/rp_filter",
        expected: "1",
        weight: 4,
        severity: Severity::Medium,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "accept_redirects",
        name: "Reject ICMP redirects",
        path: "/proc/sys/net/ipv4/conf/all/accept_redirects",
        expected: "0",
        weight: 3,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "accept_source_route",
        name: "Reject source-routed packets",
        path: "/proc/sys/net/ipv4/conf/all/accept_source_route",
        expected: "0",
        weight: 3,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
    CheckSpec {
        id: "log_martians",
        name: "Log martian packets",
        path: "/proc/sys/net/ipv4/conf/all/log_martians",
        expected: "1",
        weight: 2,
        severity: Severity::Low,
        kind: MatchKind::Exact,
    },
];
