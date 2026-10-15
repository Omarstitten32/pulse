//! Tests for `pulse-core::format` and `pulse-core::output`.

use pulse_core::format::{Format, JsonStyle};
use pulse_core::output::Target;
use std::fs;
use std::path::PathBuf;

// ===========================================================================
// Format::parse
// ===========================================================================

#[test]
fn format_parse_text_lowercase() {
    assert_eq!(Format::parse("text"), Some(Format::Text));
}

#[test]
fn format_parse_txt_alias() {
    assert_eq!(Format::parse("txt"), Some(Format::Text));
}

#[test]
fn format_parse_json() {
    assert_eq!(Format::parse("json"), Some(Format::Json));
}

#[test]
fn format_parse_md_alias() {
    assert_eq!(Format::parse("md"), Some(Format::Markdown));
}

#[test]
fn format_parse_markdown_full() {
    assert_eq!(Format::parse("markdown"), Some(Format::Markdown));
}

#[test]
fn format_parse_uppercase() {
    assert_eq!(Format::parse("TEXT"), Some(Format::Text));
    assert_eq!(Format::parse("JSON"), Some(Format::Json));
    assert_eq!(Format::parse("MARKDOWN"), Some(Format::Markdown));
}

#[test]
fn format_parse_mixed_case() {
    assert_eq!(Format::parse("JsOn"), Some(Format::Json));
    assert_eq!(Format::parse("MarkDown"), Some(Format::Markdown));
}

#[test]
fn format_parse_empty_string_returns_none() {
    assert_eq!(Format::parse(""), None);
}

#[test]
fn format_parse_unknown_returns_none() {
    assert_eq!(Format::parse("yaml"), None);
    assert_eq!(Format::parse("xml"), None);
    assert_eq!(Format::parse("txt2"), None);
}

// ===========================================================================
// Format::name
// ===========================================================================

#[test]
fn format_name_all_variants() {
    assert_eq!(Format::Text.name(), "text");
    assert_eq!(Format::Json.name(), "json");
    assert_eq!(Format::Markdown.name(), "markdown");
}

// ===========================================================================
// Format Display
// ===========================================================================

#[test]
fn format_display_matches_name() {
    assert_eq!(format!("{}", Format::Text), "text");
    assert_eq!(format!("{}", Format::Json), "json");
    assert_eq!(format!("{}", Format::Markdown), "markdown");
}

// ===========================================================================
// Format derives
// ===========================================================================

#[test]
fn format_is_copy_and_eq() {
    let a = Format::Json;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(Format::Text, Format::Json);
}

#[test]
fn format_debug() {
    assert_eq!(format!("{:?}", Format::Text), "Text");
    assert_eq!(format!("{:?}", Format::Json), "Json");
    assert_eq!(format!("{:?}", Format::Markdown), "Markdown");
}

// ===========================================================================
// JsonStyle
// ===========================================================================

#[test]
fn json_style_copy_and_eq() {
    let a = JsonStyle::Compact;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(JsonStyle::Pretty, JsonStyle::Compact);
}

#[test]
fn json_style_debug() {
    assert_eq!(format!("{:?}", JsonStyle::Pretty), "Pretty");
    assert_eq!(format!("{:?}", JsonStyle::Compact), "Compact");
}

// ===========================================================================
// Target::from_path / path / is_file
// ===========================================================================

fn temp_file(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pulse_target_{tag}_{}.txt", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

#[test]
fn target_from_path_returns_file_variant() {
    let t = Target::from_path("/tmp/x");
    assert!(t.is_file());
    assert_eq!(t.path(), Some(std::path::Path::new("/tmp/x")));
}

#[test]
fn target_stdout_is_not_file() {
    let t = Target::Stdout;
    assert!(!t.is_file());
    assert!(t.path().is_none());
}

#[test]
fn target_from_path_accepts_string() {
    let s = String::from("/tmp/string-path");
    let t = Target::from_path(s);
    assert!(t.is_file());
}

#[test]
fn target_from_path_accepts_str() {
    let t = Target::from_path("/tmp/str-path");
    assert!(t.is_file());
}

// ===========================================================================
// Target::write — stdout
// ===========================================================================

#[test]
fn target_stdout_write_succeeds() {
    let t = Target::Stdout;
    t.write("hello").expect("stdout write must succeed");
}

#[test]
fn target_stdout_write_with_trailing_newline() {
    let t = Target::Stdout;
    t.write("hello\n").expect("stdout write must succeed");
}

// ===========================================================================
// Target::write — file
// ===========================================================================

#[test]
fn target_file_write_appends_newline_when_missing() {
    let p = temp_file("nl");
    let t = Target::File(p.clone());

    t.write("content").expect("file write");
    let data = fs::read_to_string(&p).unwrap();
    assert_eq!(data, "content\n");

    let _ = fs::remove_file(&p);
}

#[test]
fn target_file_write_keeps_existing_trailing_newline() {
    let p = temp_file("nl_keep");
    let t = Target::File(p.clone());

    t.write("content\n").expect("file write");
    let data = fs::read_to_string(&p).unwrap();
    assert_eq!(data, "content\n");

    let _ = fs::remove_file(&p);
}

#[test]
fn target_file_write_overwrites_previous_content() {
    let p = temp_file("overwrite");
    let t = Target::File(p.clone());

    t.write("first").expect("first write");
    t.write("second").expect("second write");
    let data = fs::read_to_string(&p).unwrap();
    assert_eq!(data, "second\n");

    let _ = fs::remove_file(&p);
}

#[test]
fn target_file_write_empty_content_gets_newline() {
    let p = temp_file("empty");
    let t = Target::File(p.clone());

    t.write("").expect("empty write");
    let data = fs::read_to_string(&p).unwrap();
    assert_eq!(data, "\n");

    let _ = fs::remove_file(&p);
}

#[test]
fn target_file_write_multiline_content() {
    let p = temp_file("multi");
    let t = Target::File(p.clone());

    t.write("line1\nline2\nline3").expect("multiline write");
    let data = fs::read_to_string(&p).unwrap();
    assert_eq!(data, "line1\nline2\nline3\n");

    let _ = fs::remove_file(&p);
}

#[test]
fn target_file_write_invalid_path_returns_err() {
    let t = Target::File(PathBuf::from("/__pulse_nonexistent__/file.txt"));
    let r = t.write("x");
    assert!(r.is_err());
}

// ===========================================================================
// Target derives
// ===========================================================================

#[test]
fn target_debug_shows_variant() {
    assert!(format!("{:?}", Target::Stdout).contains("Stdout"));
    assert!(format!("{:?}", Target::File(PathBuf::from("/x"))).contains("File"));
}

#[test]
fn target_clone_is_independent() {
    let p = temp_file("clone");
    let t1 = Target::File(p.clone());
    let t2 = t1.clone();

    t1.write("A").expect("write t1");
    t2.write("B").expect("write t2");

    let data = fs::read_to_string(&p).unwrap();
    assert_eq!(data, "B\n");

    let _ = fs::remove_file(&p);
}
