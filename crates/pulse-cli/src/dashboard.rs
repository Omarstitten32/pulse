//! Interactive dashboard for Pulse (Phase 1 — static view).
//!
//! Renders a 2x2 panel grid: Trust / Hardening / CPU / Memory.
//!
//! Keys: `q` or `Esc` quit, `r` refresh.

use std::io;

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
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};

#[derive(Default)]
struct DashboardState {
    trust_score: i32,
    trust_grade: String,
    trust_good: u32,
    trust_warn: u32,
    trust_bad: u32,
    trust_total: u32,

    hardening_score: u32,
    hardening_max: u32,
    hardening_grade: String,
    hardening_readable: usize,
    hardening_total: usize,

    cpu_arch: String,
    cpu_cores: u32,
    cpu_avg_mhz: u64,

    mem_total_mb: u64,
    mem_used_mb: u64,
    mem_pct: f64,
}

impl DashboardState {
    fn refresh() -> Self {
        let mut s = DashboardState::default();

        // Trust
        let t = pulse_core::build_trust_report();
        s.trust_score = t.score;
        s.trust_grade = t.grade.clone();
        s.trust_good = t.summary.good;
        s.trust_warn = t.summary.warn;
        s.trust_bad = t.summary.bad;
        s.trust_total = t.summary.total;

        // Hardening
        let h = pulse_core::HardeningReport::collect();
        s.hardening_score = h.score;
        s.hardening_max = h.max_score;
        s.hardening_grade = h.grade.to_string();
        s.hardening_readable = h.readable_count();
        s.hardening_total = h.checks.len();

        // CPU
        if let Ok(cpu) = pulse_platform::cpu_info() {
            s.cpu_arch = cpu.architecture.clone();
            s.cpu_cores = cpu.cores;
            let freqs: Vec<u64> = cpu.per_core.iter().filter_map(|c| c.cur_freq_khz).collect();
            if !freqs.is_empty() {
                let sum: u64 = freqs.iter().sum();
                s.cpu_avg_mhz = sum / (freqs.len() as u64) / 1000;
            }
        }

        // Memory
        if let Ok(mem) = pulse_platform::memory_info() {
            s.mem_total_mb = mem.total_kb / 1024;
            s.mem_used_mb = (mem.total_kb - mem.available_kb) / 1024;
            if mem.total_kb > 0 {
                s.mem_pct =
                    ((mem.total_kb - mem.available_kb) as f64 / mem.total_kb as f64) * 100.0;
            }
        }

        s
    }
}

/// Entry point for `pulse dashboard`.
pub fn run() -> Result<(), String> {
    enable_raw_mode().map_err(|e| format!("raw mode: {e}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| format!("alt screen: {e}"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| format!("terminal: {e}"))?;

    let mut state = DashboardState::refresh();
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

        if let Event::Key(key) = event::read().map_err(|e| format!("event: {e}"))? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('r') => *state = DashboardState::refresh(),
                _ => {}
            }
        }
    }
}

fn draw(f: &mut Frame, state: &DashboardState) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(size);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " PULSE ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            "Deep system introspection",
            Style::default().fg(Color::White),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);

    let bot = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    draw_trust(f, top[0], state);
    draw_hardening(f, top[1], state);
    draw_cpu(f, bot[0], state);
    draw_memory(f, bot[1], state);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" [q]", Style::default().fg(Color::Yellow)),
        Span::raw("uit  "),
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::raw("efresh"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, chunks[2]);
}

fn draw_trust(f: &mut Frame, area: Rect, state: &DashboardState) {
    let color = grade_color(&state.trust_grade);
    let bar = score_bar(state.trust_score.max(0) as u32, 100, 20);

    let text = vec![
        Line::from(vec![
            Span::styled("Score : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}/100", state.trust_score),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("(Grade {})", state.trust_grade),
                Style::default().fg(color),
            ),
        ]),
        Line::from(bar),
        Line::from(""),
        Line::from(vec![
            Span::styled("Signals : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", state.trust_total),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("\u{25cf}", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled(
                format!("{}", state.trust_good),
                Style::default().fg(Color::Green),
            ),
            Span::raw("   "),
            Span::styled("\u{25cf}", Style::default().fg(Color::Yellow)),
            Span::raw(" "),
            Span::styled(
                format!("{}", state.trust_warn),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("   "),
            Span::styled("\u{25cf}", Style::default().fg(Color::Red)),
            Span::raw(" "),
            Span::styled(
                format!("{}", state.trust_bad),
                Style::default().fg(Color::Red),
            ),
        ]),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .title(" TRUST ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(color)),
    );
    f.render_widget(p, area);
}

fn draw_hardening(f: &mut Frame, area: Rect, state: &DashboardState) {
    let color = grade_color(&state.hardening_grade);
    let bar = score_bar(state.hardening_score, state.hardening_max, 20);

    let text = vec![
        Line::from(vec![
            Span::styled("Score : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}/{}", state.hardening_score, state.hardening_max),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("(Grade {})", state.hardening_grade),
                Style::default().fg(color),
            ),
        ]),
        Line::from(bar),
        Line::from(""),
        Line::from(vec![
            Span::styled("Readable : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}/{}", state.hardening_readable, state.hardening_total),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .title(" HARDENING ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(color)),
    );
    f.render_widget(p, area);
}

fn draw_cpu(f: &mut Frame, area: Rect, state: &DashboardState) {
    let text = vec![
        Line::from(vec![
            Span::styled("Arch    : ", Style::default().fg(Color::Gray)),
            Span::styled(&state.cpu_arch, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Cores   : ", Style::default().fg(Color::Gray)),
            Span::styled(
                state.cpu_cores.to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Avg MHz : ", Style::default().fg(Color::Gray)),
            Span::styled(
                state.cpu_avg_mhz.to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .title(" CPU ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(p, area);
}

fn draw_memory(f: &mut Frame, area: Rect, state: &DashboardState) {
    let bar = pct_bar(state.mem_pct, 20);
    let text = vec![
        Line::from(vec![
            Span::styled("Total   : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} MiB", state.mem_total_mb),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Used    : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} MiB", state.mem_used_mb),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(bar),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .title(" MEMORY ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    f.render_widget(p, area);
}

fn grade_color(g: &str) -> Color {
    match g.chars().next() {
        Some('A') => Color::Green,
        Some('B') => Color::LightGreen,
        Some('C') => Color::Yellow,
        Some('D') => Color::LightYellow,
        _ => Color::Red,
    }
}

fn score_bar(score: u32, max: u32, width: usize) -> Line<'static> {
    if max == 0 {
        return Line::from(format!("[{}]", " ".repeat(width)));
    }
    let filled = ((score as f64 / max as f64) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    let color = if score * 100 >= max * 70 {
        Color::Green
    } else if score * 100 >= max * 40 {
        Color::Yellow
    } else {
        Color::Red
    };
    Line::from(vec![
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled("█".repeat(filled), Style::default().fg(color)),
        Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
    ])
}

fn pct_bar(pct: f64, width: usize) -> Line<'static> {
    let pct = pct.clamp(0.0, 100.0);
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    let color = if pct < 60.0 {
        Color::Green
    } else if pct < 85.0 {
        Color::Yellow
    } else {
        Color::Red
    };
    Line::from(vec![
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled("█".repeat(filled), Style::default().fg(color)),
        Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("  {:.1}%", pct)),
    ])
}
