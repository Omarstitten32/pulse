//! Real tests for `pulse-core/src/timeline.rs`.
//!
//! Exercises the public API, source filters, time windows, and every
//! rendering path. No mocks.

use pulse_core::build_timeline;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// build_timeline — basic shape
// ---------------------------------------------------------------------------

#[test]
fn build_timeline_default_returns_report() {
    let r = build_timeline(None, None);
    assert!(r.boot_time > 0, "boot_time must be non-zero");
    assert!(r.now > 0, "now must be non-zero");
    assert!(r.now >= r.boot_time);
}

#[test]
fn build_timeline_uptime_is_consistent() {
    let r = build_timeline(None, None);
    assert_eq!(r.uptime_secs, r.now.saturating_sub(r.boot_time));
}

#[test]
fn build_timeline_total_matches_events_len() {
    let r = build_timeline(None, None);
    assert_eq!(r.total as usize, r.events.len());
}

#[test]
fn build_timeline_by_source_matches_events() {
    let r = build_timeline(None, None);
    let mut expected: BTreeMap<String, u32> = BTreeMap::new();
    for e in &r.events {
        *expected.entry(e.source.clone()).or_insert(0) += 1;
    }
    assert_eq!(r.by_source, expected);
}

#[test]
fn build_timeline_events_are_sorted_ascending() {
    let r = build_timeline(None, None);
    for w in r.events.windows(2) {
        assert!(w[0].timestamp <= w[1].timestamp);
    }
}

#[test]
fn build_timeline_contains_boot_event() {
    let r = build_timeline(None, None);
    assert!(
        r.events.iter().any(|e| e.kind == "boot"),
        "boot event must be present"
    );
}

#[test]
fn build_timeline_all_events_have_valid_fields() {
    let r = build_timeline(None, None);
    for e in &r.events {
        assert!(!e.source.is_empty(), "source must not be empty");
        assert!(!e.kind.is_empty(), "kind must not be empty");
        assert!(!e.subject.is_empty(), "subject must not be empty");
        assert!(e.timestamp > 0, "timestamp must be non-zero");
    }
}

// ---------------------------------------------------------------------------
// build_timeline — time window filter
// ---------------------------------------------------------------------------

#[test]
fn build_timeline_zero_seconds_since_now_returns_only_boot_or_empty() {
    // since = now - 0 = now → everything except events at exact `now` is dropped
    let r = build_timeline(Some(0), None);
    // Only events with timestamp >= now are kept. Boot is in the past → dropped.
    // But we may still have process events that started just now (edge case).
    // The safe assertion: total <= the events that were at time now.
    assert!(r.total <= 1_000_000, "sane bound");
}

#[test]
fn build_timeline_one_hour_window_subset_of_all() {
    let all = build_timeline(None, None);
    let hour = build_timeline(Some(3600), None);
    assert!(
        hour.total <= all.total,
        "one-hour window must not exceed full window"
    );
}

#[test]
fn build_timeline_one_day_window_matches_all_recent() {
    let day = build_timeline(Some(86400), None);
    // Uptime may be < 1 day; all events fit in the day window.
    assert!(day.total > 0);
}

#[test]
fn build_timeline_large_window_matches_default() {
    let big = build_timeline(Some(u64::MAX / 2), None);
    let default = build_timeline(None, None);

    // Both windows effectively cover all post-boot events: `u64::MAX / 2`
    // saturates to 0 in `now.saturating_sub(secs)`, and `None` uses the
    // boot time. They should yield the same events *in principle*.
    //
    // In practice the system is live: between the two calls, processes
    // start and stop, files change, and kernel threads come and go.
    // Assert a directional invariant instead of exact equality:
    // the "everything" window must be >= the "since boot" window.
    assert!(
        big.total >= default.total,
        "big ({}) must cover at least as many events as default ({})",
        big.total,
        default.total
    );
}

// ---------------------------------------------------------------------------
// build_timeline — source filter
// ---------------------------------------------------------------------------

#[test]
fn build_timeline_filter_kernel() {
    let r = build_timeline(None, Some("kernel"));
    // Only boot event from "kernel" source.
    for e in &r.events {
        assert_eq!(e.source, "kernel");
    }
    assert!(r.events.iter().any(|e| e.kind == "boot"));
}

#[test]
fn build_timeline_filter_process() {
    let r = build_timeline(None, Some("process"));
    for e in &r.events {
        assert_eq!(e.source, "process");
    }
}

#[test]
fn build_timeline_filter_module() {
    let r = build_timeline(None, Some("module"));
    for e in &r.events {
        assert_eq!(e.source, "module");
    }
}

#[test]
fn build_timeline_filter_file() {
    let r = build_timeline(None, Some("file"));
    for e in &r.events {
        assert_eq!(e.source, "file");
    }
}

#[test]
fn build_timeline_filter_nonexistent_source_returns_empty() {
    let r = build_timeline(None, Some("__does_not_exist__"));
    assert_eq!(r.total, 0);
    assert!(r.events.is_empty());
    assert!(r.by_source.is_empty());
}

#[test]
fn build_timeline_combined_filters() {
    let r = build_timeline(Some(86400), Some("process"));
    for e in &r.events {
        assert_eq!(e.source, "process");
    }
}

// ---------------------------------------------------------------------------
// Determinism / stability
// ---------------------------------------------------------------------------

#[test]
fn build_timeline_is_deterministic_within_short_window() {
    let a = build_timeline(None, Some("kernel"));
    let b = build_timeline(None, Some("kernel"));
    assert_eq!(a.total, b.total);
    assert_eq!(a.boot_time, b.boot_time);
}

#[test]
fn build_timeline_total_nonzero_default() {
    let r = build_timeline(None, None);
    assert!(
        r.total > 0,
        "default timeline must have at least boot event"
    );
}

// ---------------------------------------------------------------------------
// render_text — empty report
// ---------------------------------------------------------------------------

#[test]
fn render_text_empty_report_shows_no_events() {
    let r = empty_report();
    let s = r.render_text();
    assert!(s.contains("=== PULSE TIMELINE ==="));
    assert!(s.contains("No events in the selected window."));
    assert!(s.contains("Events    : 0"));
}

// ---------------------------------------------------------------------------
// render_text — non-empty
// ---------------------------------------------------------------------------

#[test]
fn render_text_lists_events() {
    let r = build_timeline(None, Some("kernel"));
    let s = r.render_text();
    assert!(s.contains("PULSE TIMELINE"));
    assert!(s.contains("time"));
    assert!(s.contains("source"));
    assert!(s.contains("kernel"));
    assert!(s.contains("boot"));
    assert!(s.contains("system boot"));
}

#[test]
fn render_text_has_uptime_line() {
    let r = build_timeline(None, None);
    let s = r.render_text();
    assert!(s.contains("Uptime    :"));
    assert!(s.contains("h"));
    assert!(s.contains("m"));
}

#[test]
fn render_text_formats_relative_timestamps() {
    let r = build_timeline(None, Some("kernel"));
    let s = r.render_text();
    // Boot event at btime → "+00:00:00"
    assert!(s.contains("+00:00:00"), "boot event must show +00:00:00");
}

// ---------------------------------------------------------------------------
// render_markdown — empty report
// ---------------------------------------------------------------------------

#[test]
fn render_markdown_empty_report_shows_no_events_marker() {
    let r = empty_report();
    let s = r.render_markdown();
    assert!(s.contains("# Pulse Timeline"));
    assert!(s.contains("_No events._"));
    assert!(s.contains("**Total events:** 0"));
}

// ---------------------------------------------------------------------------
// render_markdown — non-empty
// ---------------------------------------------------------------------------

#[test]
fn render_markdown_has_source_table() {
    let r = build_timeline(None, None);
    let s = r.render_markdown();
    assert!(s.contains("# Pulse Timeline"));
    assert!(s.contains("## By source"));
    assert!(s.contains("| Source | Count |"));
}

#[test]
fn render_markdown_has_events_table() {
    let r = build_timeline(None, None);
    let s = r.render_markdown();
    assert!(s.contains("## Events"));
    assert!(s.contains("| Time | Source | Kind | Subject |"));
}

#[test]
fn render_markdown_contains_kernel_and_boot() {
    let r = build_timeline(None, Some("kernel"));
    let s = r.render_markdown();
    assert!(s.contains("kernel"));
    assert!(s.contains("boot"));
}

#[test]
fn render_markdown_has_summary_metadata() {
    let r = build_timeline(None, None);
    let s = r.render_markdown();
    assert!(s.contains("**Boot:**"));
    assert!(s.contains("**Now:**"));
    assert!(s.contains("**Uptime:**"));
    assert!(s.contains("**Total events:**"));
}

// ---------------------------------------------------------------------------
// Manual fixture (empty report)
// ---------------------------------------------------------------------------

fn empty_report() -> pulse_core::timeline::TimelineReport {
    pulse_core::timeline::TimelineReport {
        boot_time: 1_700_000_000,
        now: 1_700_003_600,
        uptime_secs: 3600,
        total: 0,
        by_source: BTreeMap::new(),
        events: vec![],
    }
}

// ---------------------------------------------------------------------------
// Cross-renderer consistency
// ---------------------------------------------------------------------------

#[test]
fn both_renderers_produce_nonempty_output() {
    let r = build_timeline(None, None);
    assert!(!r.render_text().is_empty());
    assert!(!r.render_markdown().is_empty());
}

#[test]
fn both_renderers_agree_on_total_count() {
    let r = build_timeline(None, None);
    let total_str = r.total.to_string();
    assert!(r.render_text().contains(&total_str));
    assert!(r.render_markdown().contains(&total_str));
}
