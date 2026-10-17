//! Pulse Security Console — interactive TUI dashboard with command palette.
//!
//! Modes: Dashboard (default) and Output (command result overlay).
//! Keys:
//!   1-8   run a command (trust, hardening, vulns, attack, platform, system, hwid, all)
//!   r     refresh all panels
//!   q/Esc quit (Dashboard) or return (Output)
//!   Up/Down, j/k  scroll output

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame, Terminal,
};

const HISTORY_LEN: usize = 40;
const TICK_MS: u64 = 1000;
const MAX_SCROLL: u16 = 10_000;

const C_BG: Color = Color::Rgb(12, 12, 16);
const C_CYAN: Color = Color::Rgb(0, 220, 220);
const C_CYAN_DIM: Color = Color::Rgb(0, 120, 120);
const C_MAG: Color = Color::Rgb(220, 60, 200);
const C_YEL: Color = Color::Rgb(230, 200, 40);
const C_GRN: Color = Color::Rgb(60, 220, 120);
const C_RED: Color = Color::Rgb(230, 70, 70);
const C_GRAY: Color = Color::Rgb(120, 120, 120);
const C_DIM: Color = Color::Rgb(70, 70, 80);
const C_WHITE: Color = Color::Rgb(230, 230, 230);

// ═══════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════

enum Mode {
    Dashboard,
    Output {
        title: String,
        body: String,
        scroll: u16,
    },
}

struct DashboardState {
    // header
    os_name: String,
    arch: String,
    uptime_secs: u64,
    clock: String,
    load1: f64,
    load5: f64,
    load15: f64,
    proc_count: usize,

    // security
    trust_score: i32,
    trust_grade: String,
    trust_good: u32,
    trust_warn: u32,
    trust_bad: u32,
    trust_unknown: u32,
    trust_total: u32,

    hardening_score: u32,
    hardening_max: u32,
    hardening_grade: String,
    hardening_readable: usize,
    hardening_total: usize,

    vulns_score: Option<u32>,
    vulns_conf: String,

    attack_score: Option<u32>,
    attack_conf: String,

    // resources
    cpu_cores: u32,
    cpu_avg_mhz: u64,
    cpu_history: VecDeque<u64>,
    per_core: Vec<u64>,

    mem_total_mb: u64,
    mem_used_mb: u64,
    mem_pct: f64,

    disk_total_gb: u64,
    disk_used_gb: u64,
    disk_pct: f64,

    net_ifaces: usize,

    // events
    events: Vec<(String, String, String, String)>,

    // ui
    mode: Mode,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            os_name: String::new(),
            arch: String::new(),
            uptime_secs: 0,
            clock: String::new(),
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
            proc_count: 0,
            trust_score: 0,
            trust_grade: String::new(),
            trust_good: 0,
            trust_warn: 0,
            trust_bad: 0,
            trust_unknown: 0,
            trust_total: 0,
            hardening_score: 0,
            hardening_max: 0,
            hardening_grade: String::new(),
            hardening_readable: 0,
            hardening_total: 0,
            vulns_score: None,
            vulns_conf: String::new(),
            attack_score: None,
            attack_conf: String::new(),
            cpu_cores: 0,
            cpu_avg_mhz: 0,
            cpu_history: VecDeque::with_capacity(HISTORY_LEN),
            per_core: Vec::new(),
            mem_total_mb: 0,
            mem_used_mb: 0,
            mem_pct: 0.0,
            disk_total_gb: 0,
            disk_used_gb: 0,
            disk_pct: 0.0,
            net_ifaces: 0,
            events: Vec::new(),
            mode: Mode::Dashboard,
        }
    }
}

impl DashboardState {
    fn full_refresh(&mut self) {
        // header
        self.os_name = match pulse_platform::os() {
            "android" => "Android".to_string(),
            "linux" => "Linux".to_string(),
            other => other.to_string(),
        };
        self.arch = pulse_platform::arch().to_string();
        self.update_clock();

        // security
        let t = pulse_core::build_trust_report();
        self.trust_score = t.score;
        self.trust_grade = t.grade.clone();
        self.trust_good = t.summary.good;
        self.trust_warn = t.summary.warn;
        self.trust_bad = t.summary.bad;
        self.trust_unknown = t.summary.unknown;
        self.trust_total = t.summary.total;

        let h = pulse_core::HardeningReport::collect();
        self.hardening_score = h.score;
        self.hardening_max = h.max_score;
        self.hardening_grade = h.grade.to_string();
        self.hardening_readable = h.readable_count();
        self.hardening_total = h.checks.len();

        let v = pulse_core::VulnerabilityReport::collect();
        self.vulns_score = v.score;
        self.vulns_conf = v.confidence.label().to_string();

        let a = pulse_core::AttackSurface::collect();
        self.attack_score = a.score;
        self.attack_conf = a.confidence.label().to_string();

        // resources
        self.refresh_live();
        self.refresh_disk();

        // events
        let timeline = pulse_core::build_timeline(None, None);
        self.events.clear();
        for e in timeline.events.iter().rev().take(8) {
            let rel = fmt_relative(e.timestamp, timeline.boot_time);
            self.events
                .push((rel, e.source.clone(), e.kind.clone(), e.subject.clone()));
        }
    }

    /// Cheap refresh: only things that change every second.
    fn refresh_live(&mut self) {
        self.update_clock();

        if let Ok(cpu) = pulse_platform::cpu_info() {
            self.cpu_cores = cpu.cores;
            self.per_core = cpu
                .per_core
                .iter()
                .filter_map(|c| c.cur_freq_khz)
                .map(|k| k / 1000)
                .collect();
            let freqs: Vec<u64> = cpu.per_core.iter().filter_map(|c| c.cur_freq_khz).collect();
            let avg = if freqs.is_empty() {
                0
            } else {
                freqs.iter().sum::<u64>() / (freqs.len() as u64) / 1000
            };
            self.cpu_avg_mhz = avg;
            self.cpu_history.push_back(avg);
            while self.cpu_history.len() > HISTORY_LEN {
                self.cpu_history.pop_front();
            }
        }

        if let Ok(mem) = pulse_platform::memory_info() {
            self.mem_total_mb = mem.total_kb / 1024;
            let used_kb = mem.total_kb.saturating_sub(mem.available_kb);
            self.mem_used_mb = used_kb / 1024;
            if mem.total_kb > 0 {
                self.mem_pct = (used_kb as f64 / mem.total_kb as f64) * 100.0;
            }
        }

        if let Ok(sys) = pulse_platform::system_info() {
            self.uptime_secs = sys.uptime_seconds;
        }

        if let Ok(la) = pulse_platform::load_avg() {
            self.load1 = la.load1;
            self.load5 = la.load5;
            self.load15 = la.load15;
        }

        if let Ok(p) = pulse_platform::process_info() {
            self.proc_count = p.processes.len();
        }

        if let Ok(n) = pulse_platform::network_info() {
            self.net_ifaces = n.interfaces.len();
        }
    }

    fn refresh_disk(&mut self) {
        if let Ok(disk) = pulse_platform::disk_info() {
            let mut best_total = 0u64;
            let mut best_used = 0u64;
            for m in &disk.mounts {
                if let Some(total) = m.total_bytes {
                    if total > best_total && m.used_bytes.is_some() {
                        best_total = total;
                        best_used = m.used_bytes.unwrap_or(0);
                    }
                }
            }
            self.disk_total_gb = best_total / (1024 * 1024 * 1024);
            self.disk_used_gb = best_used / (1024 * 1024 * 1024);
            if best_total > 0 {
                self.disk_pct = (best_used as f64 / best_total as f64) * 100.0;
            }
        }
    }

    fn update_clock(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let secs_today = now % 86400;
        let h = secs_today / 3600;
        let m = (secs_today % 3600) / 60;
        let s = secs_today % 60;
        self.clock = format!("{:02}:{:02}:{:02}", h, m, s);
    }
}

fn fmt_relative(ts: u64, boot: u64) -> String {
    if ts < boot {
        return "boot".to_string();
    }
    let d = ts - boot;
    let h = d / 3600;
    let m = (d % 3600) / 60;
    let s = d % 60;
    format!("+{:02}:{:02}:{:02}", h, m, s)
}

fn fmt_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{}d {}h {}m", d, h, m)
    } else if h > 0 {
        format!("{}h {}m", h, m)
    } else {
        format!("{}m", m)
    }
}

// ═══════════════════════════════════════════════════════════
// TERMINAL LIFECYCLE
// ═══════════════════════════════════════════════════════════

pub fn run() -> Result<(), String> {
    enable_raw_mode().map_err(|e| format!("raw: {e}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| format!("alt: {e}"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| format!("term: {e}"))?;

    let mut state = DashboardState::default();
    state.full_refresh();

    let res = run_loop(&mut terminal, &mut state);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    res
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    state: &mut DashboardState,
) -> Result<(), String> {
    loop {
        terminal
            .draw(|f| draw(f, state))
            .map_err(|e| format!("draw: {e}"))?;

        let timeout = Duration::from_millis(TICK_MS);
        if event::poll(timeout).map_err(|e| format!("poll: {e}"))? {
            if let Event::Key(key) = event::read().map_err(|e| format!("read: {e}"))? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match &state.mode {
                    Mode::Dashboard => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('r') => state.full_refresh(),
                        KeyCode::Char('1') => run_cmd(state, "trust", "Trust", || {
                            let s = pulse_core::build_trust_report().render_text();
                            Some(s)
                        }),
                        KeyCode::Char('2') => run_cmd(state, "hardening", "Hardening", || {
                            Some(pulse_core::HardeningReport::collect().render_text())
                        }),
                        KeyCode::Char('3') => run_cmd(state, "vulns", "Vulnerabilities", || {
                            Some(pulse_core::VulnerabilityReport::collect().render_text())
                        }),
                        KeyCode::Char('4') => {
                            run_cmd(state, "attack-surface", "Attack Surface", || {
                                Some(pulse_core::AttackSurface::collect().render_text())
                            })
                        }
                        KeyCode::Char('5') => run_cmd(state, "platform", "Platform", || {
                            pulse_platform::platform_info().ok().map(|p| {
                                format!("arch       : {}\nos         : {}\nfamily     : {}\npointer    : {}\nendianness : {}",
                                    p.arch, p.os, p.family, p.pointer_width, p.endianness)
                            })
                        }),
                        KeyCode::Char('6') => run_cmd(state, "system", "System", || {
                            pulse_platform::system_info().ok().map(|s| {
                                format!("OS         : {}\nVersion    : {}\nKernel     : {}\nHostname   : {}\nUptime     : {} s\nArch       : {}",
                                    s.os_name, s.os_version, s.kernel_version, s.hostname,
                                    s.uptime_seconds, s.architecture)
                            })
                        }),
                        KeyCode::Char('7') => run_cmd(state, "hwid", "HWID", || {
                            pulse_platform::hwid_info(None).ok().map(|h| {
                                format!("HWID     : {}\nMode     : {:?}\nActive   : {}\nTotal    : {}\nConfidence: {:.2}",
                                    h.hash, h.mode, h.active_count, h.total_count, h.confidence)
                            })
                        }),
                        KeyCode::Char('8') => run_cmd(state, "all", "Full Report", || {
                            let t = pulse_core::build_full_report().ok()?;
                            Some(t.render_text())
                        }),
                        _ => {}
                    },
                    Mode::Output { .. } => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => state.mode = Mode::Dashboard,
                        KeyCode::Up | KeyCode::Char('k') => {
                            if let Mode::Output { scroll, .. } = &mut state.mode {
                                *scroll = scroll.saturating_sub(1);
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if let Mode::Output { scroll, .. } = &mut state.mode {
                                *scroll = scroll.saturating_add(1).min(MAX_SCROLL);
                            }
                        }
                        KeyCode::PageUp => {
                            if let Mode::Output { scroll, .. } = &mut state.mode {
                                *scroll = scroll.saturating_sub(10);
                            }
                        }
                        KeyCode::PageDown => {
                            if let Mode::Output { scroll, .. } = &mut state.mode {
                                *scroll = scroll.saturating_add(10).min(MAX_SCROLL);
                            }
                        }
                        _ => {}
                    },
                }
            }
        } else {
            state.refresh_live();
        }
    }
}

fn run_cmd<F>(state: &mut DashboardState, _cmd: &str, title: &str, f: F)
where
    F: FnOnce() -> Option<String>,
{
    let body = match f() {
        Some(b) => b,
        None => format!("(no output — {} returned an error)", title),
    };
    state.mode = Mode::Output {
        title: title.to_string(),
        body,
        scroll: 0,
    };
}

// ═══════════════════════════════════════════════════════════
// DRAW
// ═══════════════════════════════════════════════════════════

fn draw(f: &mut Frame, state: &DashboardState) {
    // Fill background
    let bg = Block::default().style(Style::default().bg(C_BG));
    f.render_widget(bg, f.area());

    match &state.mode {
        Mode::Dashboard => draw_dashboard(f, state),
        Mode::Output {
            title,
            body,
            scroll,
        } => {
            draw_dashboard(f, state);
            draw_output_overlay(f, title, body, *scroll);
        }
    }
}

fn draw_dashboard(f: &mut Frame, state: &DashboardState) {
    let size = f.area();

    // Overall layout: header / main / footer
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(12),   // main
            Constraint::Length(3), // action bar
        ])
        .split(size);

    draw_header(f, outer[0], state);

    // Main: left column (posture) | right column (pulse + feed)
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(outer[1]);

    // Left: posture (top) + engines (bottom)
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(8)])
        .split(main[0]);

    draw_posture(f, left[0], state);
    draw_engines(f, left[1], state);

    // Right: resources (top) + feed (bottom)
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(5)])
        .split(main[1]);

    draw_resources(f, right[0], state);
    draw_feed(f, right[1], state);

    draw_action_bar(f, outer[2]);
}

fn block(title: &str, color: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Line::from(Span::styled(
            format!(" {} ", title),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )))
}

fn draw_header(f: &mut Frame, area: Rect, state: &DashboardState) {
    let line1 = Line::from(vec![
        Span::styled(
            " ◆ ",
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "PULSE",
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" CONSOLE ", Style::default().fg(C_CYAN_DIM)),
        Span::styled(
            "◆",
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "   ● ",
            Style::default().fg(C_GRN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "ONLINE",
            Style::default().fg(C_GRN).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ·  ", Style::default().fg(C_DIM)),
        Span::styled(&state.os_name, Style::default().fg(C_CYAN)),
        Span::styled("  ·  ", Style::default().fg(C_DIM)),
        Span::styled(&state.arch, Style::default().fg(C_CYAN)),
        Span::styled("  ·  up ", Style::default().fg(C_DIM)),
        Span::styled(fmt_uptime(state.uptime_secs), Style::default().fg(C_WHITE)),
    ]);
    let line2 = Line::from(vec![
        Span::raw("   "),
        Span::styled(
            &state.clock,
            Style::default().fg(C_YEL).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   load ", Style::default().fg(C_DIM)),
        Span::styled(format!("{:.2}", state.load1), Style::default().fg(C_WHITE)),
        Span::styled(" ", Style::default().fg(C_DIM)),
        Span::styled(format!("{:.2}", state.load5), Style::default().fg(C_GRAY)),
        Span::styled(" ", Style::default().fg(C_DIM)),
        Span::styled(format!("{:.2}", state.load15), Style::default().fg(C_GRAY)),
        Span::styled("   procs ", Style::default().fg(C_DIM)),
        Span::styled(state.proc_count.to_string(), Style::default().fg(C_WHITE)),
        Span::styled("   ifaces ", Style::default().fg(C_DIM)),
        Span::styled(state.net_ifaces.to_string(), Style::default().fg(C_WHITE)),
    ]);

    let p = Paragraph::new(vec![line1, line2]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_CYAN)),
    );
    f.render_widget(p, area);
}

fn draw_posture(f: &mut Frame, area: Rect, state: &DashboardState) {
    let grade_color = grade_col(&state.trust_grade);

    let lines = vec![
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "TRUST",
                Style::default().fg(C_GRAY).add_modifier(Modifier::BOLD),
            ),
            Span::raw("        "),
            Span::styled(
                format!("{:>3}", state.trust_score),
                Style::default()
                    .fg(grade_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("/100", Style::default().fg(C_DIM)),
            Span::raw("  "),
            Span::styled(
                format!("Grade {}", state.trust_grade),
                Style::default()
                    .fg(grade_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("             ", Style::default()),
            Span::styled(
                bar(state.trust_score.max(0) as f64, 20),
                Style::default().fg(grade_color),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("Signals  ", Style::default().fg(C_DIM)),
            Span::styled(state.trust_total.to_string(), Style::default().fg(C_WHITE)),
            Span::raw("   "),
            Span::styled("● ", Style::default().fg(C_GRN)),
            Span::styled(state.trust_good.to_string(), Style::default().fg(C_GRN)),
            Span::raw("  "),
            Span::styled("● ", Style::default().fg(C_YEL)),
            Span::styled(state.trust_warn.to_string(), Style::default().fg(C_YEL)),
            Span::raw("  "),
            Span::styled("● ", Style::default().fg(C_RED)),
            Span::styled(state.trust_bad.to_string(), Style::default().fg(C_RED)),
            Span::raw("  "),
            Span::styled("○ ", Style::default().fg(C_DIM)),
            Span::styled(state.trust_unknown.to_string(), Style::default().fg(C_DIM)),
        ]),
    ];

    let p = Paragraph::new(lines).block(block("POSTURE", grade_color));
    f.render_widget(p, area);
}

fn draw_engines(f: &mut Frame, area: Rect, state: &DashboardState) {
    let h = &state.hardening_grade;
    let h_color = grade_col(h);

    let hard_pct = if state.hardening_max == 0 {
        0.0
    } else {
        state.hardening_score as f64 * 100.0 / state.hardening_max as f64
    };
    let hard_line = Line::from(vec![
        Span::raw("  "),
        Span::styled("HARDEN ", Style::default().fg(C_GRAY)),
        Span::styled(
            format!("{:>3}/{:<3}", state.hardening_score, state.hardening_max),
            Style::default().fg(C_WHITE),
        ),
        Span::raw(" "),
        Span::styled(bar(hard_pct, 12), Style::default().fg(h_color)),
        Span::raw("  "),
        Span::styled(
            h.to_string(),
            Style::default().fg(h_color).add_modifier(Modifier::BOLD),
        ),
    ]);

    let vs = state.vulns_score.unwrap_or(0);
    let v_color = score_col(vs);
    let vuln_line = Line::from(vec![
        Span::raw("  "),
        Span::styled("VULNS  ", Style::default().fg(C_GRAY)),
        Span::styled(format!("{:>3}/100", vs), Style::default().fg(C_WHITE)),
        Span::raw(" "),
        Span::styled(bar(vs as f64, 12), Style::default().fg(v_color)),
        Span::raw("  "),
        Span::styled(&state.vulns_conf, Style::default().fg(C_DIM)),
    ]);

    let as_ = state.attack_score.unwrap_or(0);
    let a_color = score_col(as_);
    let attack_line = Line::from(vec![
        Span::raw("  "),
        Span::styled("ATTACK ", Style::default().fg(C_GRAY)),
        Span::styled(format!("{:>3}/100", as_), Style::default().fg(C_WHITE)),
        Span::raw(" "),
        Span::styled(bar(as_ as f64, 12), Style::default().fg(a_color)),
        Span::raw("  "),
        Span::styled(&state.attack_conf, Style::default().fg(C_DIM)),
    ]);

    let p = Paragraph::new(vec![hard_line, vuln_line, attack_line]).block(block("ENGINES", C_GRAY));
    f.render_widget(p, area);
}

fn draw_resources(f: &mut Frame, area: Rect, state: &DashboardState) {
    let spark = sparkline(&state.cpu_history, 34);

    // per-core mini bars
    let mut per_core_spans = vec![Span::raw("  ")];
    let max_freq = state.per_core.iter().max().copied().unwrap_or(1).max(1);
    for (i, &f) in state.per_core.iter().enumerate() {
        let pct = f as f64 / max_freq as f64;
        let color = if pct > 0.8 {
            C_RED
        } else if pct > 0.5 {
            C_YEL
        } else {
            C_GRN
        };
        per_core_spans.push(Span::styled(format!("{}", i), Style::default().fg(C_DIM)));
        per_core_spans.push(Span::raw(" "));
        per_core_spans.push(Span::styled(heat(pct), Style::default().fg(color)));
        per_core_spans.push(Span::raw(" "));
    }

    let lines = vec![
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "CPU ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(spark, Style::default().fg(C_CYAN)),
            Span::raw("  "),
            Span::styled(
                format!("{}c {}MHz", state.cpu_cores, state.cpu_avg_mhz),
                Style::default().fg(C_DIM),
            ),
        ]),
        Line::from(per_core_spans),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "MEM ",
                Style::default().fg(C_MAG).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                bar(state.mem_pct, 20),
                Style::default().fg(pct_col(state.mem_pct)),
            ),
            Span::raw("  "),
            Span::styled(
                format!(
                    "{:.1}%  {}M/{}M",
                    state.mem_pct, state.mem_used_mb, state.mem_total_mb
                ),
                Style::default().fg(C_WHITE),
            ),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "DSK ",
                Style::default().fg(C_YEL).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                bar(state.disk_pct, 20),
                Style::default().fg(pct_col(state.disk_pct)),
            ),
            Span::raw("  "),
            Span::styled(
                format!(
                    "{:.1}%  {}G/{}G",
                    state.disk_pct, state.disk_used_gb, state.disk_total_gb
                ),
                Style::default().fg(C_WHITE),
            ),
        ]),
    ];

    let p = Paragraph::new(lines).block(block("RESOURCES", C_CYAN));
    f.render_widget(p, area);
}

fn draw_feed(f: &mut Frame, area: Rect, state: &DashboardState) {
    let mut lines = vec![];
    for (rel, src, kind, subj) in state.events.iter().take(6) {
        let subject = if subj.len() > 32 { &subj[..32] } else { subj };
        let (kcolor, ktext) = event_color(kind);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(rel.clone(), Style::default().fg(C_DIM)),
            Span::raw("  "),
            Span::styled(format!("{:8}", src), Style::default().fg(C_CYAN)),
            Span::raw("  "),
            Span::styled(format!("{:6}", ktext), Style::default().fg(kcolor)),
            Span::raw("  "),
            Span::styled(subject.to_string(), Style::default().fg(C_WHITE)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no events)",
            Style::default().fg(C_DIM),
        )));
    }

    let p = Paragraph::new(lines).block(block("LIVE FEED", C_MAG));
    f.render_widget(p, area);
}

fn draw_action_bar(f: &mut Frame, area: Rect) {
    let keys = [
        ("1", "trust"),
        ("2", "hard"),
        ("3", "vulns"),
        ("4", "attack"),
        ("5", "plat"),
        ("6", "sys"),
        ("7", "hwid"),
        ("8", "all"),
    ];
    let mut spans = vec![Span::raw(" ")];
    for (k, label) in keys.iter() {
        spans.push(Span::styled(
            format!("[{}]", k),
            Style::default().fg(C_YEL).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {}  ", label),
            Style::default().fg(C_WHITE),
        ));
    }
    spans.push(Span::styled(
        "[r]",
        Style::default().fg(C_YEL).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(" refresh  ", Style::default().fg(C_WHITE)));
    spans.push(Span::styled(
        "[q]",
        Style::default().fg(C_YEL).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(" quit", Style::default().fg(C_WHITE)));

    let p = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_DIM)),
    );
    f.render_widget(p, area);
}

fn draw_output_overlay(f: &mut Frame, title: &str, body: &str, scroll: u16) {
    let area = centered_rect(85, 80, f.area());

    // Clear background first
    f.render_widget(Clear, area);

    let inner_h = area.height.saturating_sub(2).max(1) as usize;
    let total_lines = body.lines().count().max(1);

    // Page counting must use the same divisor as scrolling.
    let page = (scroll as usize / inner_h) + 1;
    let total_pages = total_lines.div_ceil(inner_h).max(1);

    let title_span = format!(
        " {} · page {}/{} · lines {} ",
        title,
        page.min(total_pages),
        total_pages,
        total_lines
    );
    let blk = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_CYAN))
        .title(Line::from(Span::styled(
            title_span,
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        )));

    let p = Paragraph::new(body.to_string())
        .block(blk)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    f.render_widget(p, area);

    // Hint at bottom
    let hint = Line::from(vec![
        Span::styled(" [↑↓/jk] scroll  ", Style::default().fg(C_WHITE)),
        Span::styled("[PgUp/PgDn] page  ", Style::default().fg(C_WHITE)),
        Span::styled(
            "[q/Esc]",
            Style::default().fg(C_YEL).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" back", Style::default().fg(C_WHITE)),
    ]);
    let hint_area = Rect {
        x: area.x + 1,
        y: area.y + area.height - 2,
        width: area.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(Paragraph::new(hint), hint_area);
}

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vert[1]);
    horiz[1]
}

// ═══════════════════════════════════════════════════════════
// COLOR / FORMATTING HELPERS
// ═══════════════════════════════════════════════════════════

fn grade_col(g: &str) -> Color {
    match g.chars().next() {
        Some('A') => C_GRN,
        Some('B') => Color::Rgb(160, 220, 60),
        Some('C') => C_YEL,
        Some('D') => Color::Rgb(230, 140, 40),
        _ => C_RED,
    }
}

fn score_col(s: u32) -> Color {
    if s >= 80 {
        C_GRN
    } else if s >= 50 {
        C_YEL
    } else {
        C_RED
    }
}

fn pct_col(p: f64) -> Color {
    if p < 60.0 {
        C_GRN
    } else if p < 85.0 {
        C_YEL
    } else {
        C_RED
    }
}

fn event_color(kind: &str) -> (Color, &'static str) {
    match kind {
        "boot" => (C_YEL, "boot"),
        "start" => (C_GRN, "start"),
        "stop" => (C_RED, "stop"),
        "load" => (C_CYAN, "load"),
        _ => (C_GRAY, "event"),
    }
}

fn bar(pct: f64, width: usize) -> String {
    let pct = pct.clamp(0.0, 100.0);
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

fn heat(pct: f64) -> &'static str {
    if pct >= 0.85 {
        "█"
    } else if pct >= 0.6 {
        "▇"
    } else if pct >= 0.4 {
        "▅"
    } else if pct >= 0.2 {
        "▃"
    } else {
        "▁"
    }
}

fn sparkline(data: &VecDeque<u64>, width: usize) -> String {
    if data.is_empty() {
        return " ".repeat(width);
    }
    const BLOCKS: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    let max = data.iter().max().copied().unwrap_or(1).max(1);
    let min = data.iter().min().copied().unwrap_or(0);
    let range = (max - min).max(1) as f64;
    let mut out = String::new();
    for v in data.iter().take(width) {
        let norm = ((*v as f64 - min as f64) / range * 7.0).round() as usize;
        out.push_str(BLOCKS[norm.min(7)]);
    }
    out
}
