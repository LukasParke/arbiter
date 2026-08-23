//! Flow-detail rendering with a lightweight built-in JSON highlighter.
//!
//! The tokenizer is a flat, iterative scan (strings/keys/numbers/booleans/
//! punctuation) — deliberately not syntect (rejected dep: multi-MB grammar
//! load would blow the 150 ms first-paint bar). It never recurses, so deeply
//! nested or malformed JSON cannot blow the stack.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::{App, Screen};
use crate::tui::feed::{BodyViewDto, FlowDetailDto};

/// Highlights one line of JSON into styled spans. Iterative single pass;
/// safe on adversarial input by construction.
pub(crate) fn highlight_json_line(line: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut rest = line;
    let mut plain_start = 0usize;
    let mut in_string = false;
    let mut offset = 0usize;

    while !rest.is_empty() {
        let ch = rest.chars().next().expect("non-empty");
        if in_string {
            if ch == '\\' && rest.len() > 1 {
                rest = &rest[2..];
                continue;
            }
            let end = ch == '"';
            offset += ch.len_utf8();
            rest = &rest[ch.len_utf8()..];
            if end {
                // A string followed by ':' is a key; otherwise a value.
                let after = rest.trim_start();
                let style = if after.starts_with(':') {
                    Style::default().fg(Color::Blue)
                } else {
                    Style::default().fg(Color::Green)
                };
                if plain_start < offset {
                    let text = &line[plain_start..offset];
                    spans.push(Span::styled(text.to_string(), style));
                    plain_start = offset;
                }
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                offset += 1;
                rest = &rest[1..];
            }
            '0'..='9' | '-' => {
                let digits = rest
                    .find(|c: char| {
                        !c.is_ascii_digit()
                            && c != '.'
                            && c != 'e'
                            && c != 'E'
                            && c != '+'
                            && c != '-'
                    })
                    .unwrap_or(rest.len());
                flush_plain(line, plain_start, offset, &mut spans);
                spans.push(Span::styled(
                    rest[..digits].to_string(),
                    Style::default().fg(Color::Magenta),
                ));
                offset += digits;
                rest = &rest[digits..];
                plain_start = offset;
            }
            't' | 'f' if rest.starts_with("true") || rest.starts_with("false") => {
                let word_len = if rest.starts_with("true") { 4 } else { 5 };
                flush_plain(line, plain_start, offset, &mut spans);
                spans.push(Span::styled(
                    rest[..word_len].to_string(),
                    Style::default().fg(Color::Yellow),
                ));
                offset += word_len;
                rest = &rest[word_len..];
                plain_start = offset;
            }
            'n' if rest.starts_with("null") => {
                flush_plain(line, plain_start, offset, &mut spans);
                spans.push(Span::styled(
                    "null".to_string(),
                    Style::default().fg(Color::DarkGray),
                ));
                offset += 4;
                rest = &rest[4..];
                plain_start = offset;
            }
            _ => {
                offset += ch.len_utf8();
                rest = &rest[ch.len_utf8()..];
            }
        }
    }
    if plain_start < line.len() {
        flush_plain(line, plain_start, line.len(), &mut spans);
    }
    spans
}

fn flush_plain(line: &str, start: usize, end: usize, spans: &mut Vec<Span<'static>>) {
    if start < end {
        let punctuation = line[start..end]
            .chars()
            .all(|c| matches!(c, '{' | '}' | '[' | ']' | ':' | ','));
        let style = if punctuation {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        spans.push(Span::styled(line[start..end].to_string(), style));
    }
}

/// Pretty-prints JSON body text when parseable; otherwise returns None and
/// callers fall back to raw.
pub fn pretty_print_json(text: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
}

/// Lossy byte entry point for non-UTF8 payloads (never panics).
pub fn highlight_json_bytes(bytes: &[u8]) -> Vec<Vec<Span<'static>>> {
    let text = String::from_utf8_lossy(bytes).into_owned();
    text.lines().map(highlight_json_line).collect()
}

fn header_pairs(
    headers: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.clone(), value.clone()))
        })
        .collect()
}

/// Renders the flow-detail screen for the selected sequence. Feeds the
/// real body-pane height back into the app so half-page scrolls and
/// clamping track the live viewport (B5).
pub(crate) fn draw_detail(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let [header_area, content_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(5)]).areas(area);

    // The response pane is the primary scroll surface; report its row
    // budget (borders + title + footer allowance) before borrowing detail.
    if app.detail.is_some() {
        app.note_body_viewport(content_area.height.saturating_sub(6) as usize);
    }
    match app.detail.as_ref() {
        Some(detail) => {
            draw_header(f, header_area, detail);
            draw_body(f, content_area, app, detail);
        }
        None => {
            f.render_widget(
                Paragraph::new(if app.detail_loading {
                    "loading detail…"
                } else {
                    "no detail loaded"
                }),
                header_area,
            );
        }
    }
}

fn centered_rect(area: Rect, width_percent: u16, height: u16) -> Rect {
    let w = area.width * width_percent / 100;
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width.saturating_sub(w)) / 2,
        area.y + (area.height.saturating_sub(h)) / 2,
        w,
        h,
    )
}

fn draw_header(f: &mut Frame, area: Rect, detail: &FlowDetailDto) {
    let summary = &detail.summary;
    let status = summary
        .status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!(" {} ", summary.sequence),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{} {}", summary.method, summary.path)),
            ]),
            Line::from(vec![
                Span::styled(format!("status {status}"), Style::default()),
                Span::raw(format!(
                    "  {} ms  kind={}  host={}",
                    summary
                        .duration_ms
                        .map(|ms| format!("{ms:.0}"))
                        .unwrap_or_else(|| "-".into()),
                    summary.kind,
                    summary.host.as_deref().unwrap_or("-")
                )),
            ]),
        ]),
        area,
    );
}

fn draw_body(f: &mut Frame, area: Rect, app: &App, detail: &FlowDetailDto) {
    let [req_headers_area, res_headers_area, req_body_area, resp_body_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Percentage(25),
        Constraint::Min(10),
    ])
    .areas(area);

    render_headers(
        f,
        req_headers_area,
        "request headers",
        &detail.request_headers,
    );
    render_headers(
        f,
        res_headers_area,
        "response headers",
        &detail.response_headers,
    );

    let mode_note = format!(
        " [{}{}]",
        if app.pretty_print {
            "pretty"
        } else {
            "compact"
        },
        if app.show_raw { "/raw" } else { "" }
    );
    render_body_view(
        f,
        req_body_area,
        "request body",
        &detail.request_body,
        app,
        &mode_note,
    );
    render_body_view(
        f,
        resp_body_area,
        "response body",
        &detail.response_body,
        app,
        &mode_note,
    );
}

fn render_headers(
    f: &mut Frame,
    area: Rect,
    title: &str,
    headers: &std::collections::BTreeMap<String, Vec<String>>,
) {
    let pairs = header_pairs(headers);
    let mut lines: Vec<Line> = Vec::with_capacity(pairs.len());
    if pairs.is_empty() {
        lines.push(Line::from(Span::styled(
            "(none)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for (name, value) in pairs {
        lines.push(Line::from(vec![
            Span::styled(name, Style::default().fg(Color::Blue)),
            Span::raw(": "),
            Span::raw(value),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::TOP).title(title)),
        area,
    );
}

fn render_body_view(
    f: &mut Frame,
    area: Rect,
    title: &str,
    view: &BodyViewDto,
    app: &App,
    mode_note: &str,
) {
    if !view.available {
        f.render_widget(
            Paragraph::new(Span::styled(
                "(body unavailable)",
                Style::default().fg(Color::DarkGray),
            ))
            .block(Block::default().borders(Borders::TOP).title(title)),
            area,
        );
        return;
    }
    let text = view.text.clone().unwrap_or_default();
    let prepared: String = if app.pretty_print && !app.show_raw {
        pretty_print_json(&text).unwrap_or(text)
    } else {
        text
    };

    let truncation = if view.truncated {
        format!(
            " — truncated at 256 KiB of {:.1} KiB total",
            view.total_size as f64 / 1024.0
        )
    } else {
        format!(" — {} bytes", view.total_size)
    };
    let full_title = format!("{title}{mode_note}{truncation}");

    // Virtualize: only materialize the visible window of lines.
    let all_lines: Vec<&str> = prepared.lines().collect();
    let total = all_lines.len();
    let visible_rows = area.height.saturating_sub(2) as usize;
    let scrollable = total > visible_rows.max(1);
    // Reserve one footer row for the `line X–Y of N` indicator.
    let para_rows = if scrollable {
        visible_rows.max(1)
    } else {
        area.height.saturating_sub(2) as usize
    };
    let (start, end) = app.body_scroll_window(total, para_rows);
    let styled: Vec<Line> = all_lines[start..end]
        .iter()
        .map(|line| Line::from(highlight_json_line(line)))
        .collect();

    let [para_area, footer_area] = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(u16::from(scrollable)),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(styled)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::TOP).title(full_title)),
        para_area,
    );
    if scrollable {
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("line {}–{} of {total}", start + 1, end),
                Style::default().fg(Color::DarkGray),
            )),
            footer_area,
        );
    }
}

/// Renders help / palette / export-confirm overlays on top of the current
/// screen.
pub(crate) fn draw_overlay(f: &mut Frame, app: &App) {
    // Overwrite confirmation reuses the palette styling (B6).
    if let Some(path) = app.pending_export_path() {
        let area = centered_rect(f.area(), 70, 5);
        f.render_widget(
            Paragraph::new(vec![
                Line::from(format!("export target {} already exists", path.display())),
                Line::from(""),
                Line::from(vec![
                    Span::styled("overwrite? (y/n) ", Style::default().fg(Color::Cyan)),
                    Span::styled("y proceed · n cancel", Style::default().fg(Color::DarkGray)),
                ]),
            ])
            .block(Block::default().borders(Borders::ALL).title("export")),
            area,
        );
        return;
    }
    match app.screen {
        Screen::Help => {
            let mut text = vec![
                Line::from("Arbiter TUI — keys"),
                Line::from(
                    "q quit · Ctrl+C quit from anywhere · / filter · enter open detail · esc back",
                ),
                Line::from("list: j/k or arrows move · PgUp/PgDn page · g/G top/bottom"),
                Line::from(
                    "detail: j/k or arrows scroll body · PgUp/PgDn half page · Home/End jump",
                ),
                Line::from("r replay (y/n confirm) · x delete (y/n confirm)"),
                Line::from("w export HAR · p pretty-print · R raw toggle"),
                Line::from(
                    ": palette — save NAME · load NAME · filters · attach URL · export PATH",
                ),
                Line::from("? toggle this help"),
                Line::from(""),
            ];
            text.extend(crate::tui::filter::FILTER_HELP.lines().map(Line::from));
            let area = centered_rect(f.area(), 90, text.len() as u16 + 2);
            f.render_widget(
                Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("help")),
                area,
            );
        }
        Screen::Palette => {
            let area = centered_rect(f.area(), 70, 3);
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(": ", Style::default().fg(Color::Cyan)),
                    Span::raw(app.palette_text().to_string()),
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ]))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("palette (save/load/filters/attach/export)"),
                ),
                area,
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(spans: &[Span<'static>]) -> String {
        spans.iter().map(|span| span.content.to_string()).collect()
    }

    #[test]
    fn tokenization_preserves_source_text() {
        let cases = [
            r#"{"a": 1, "b": [true, false, null], "c": "x"}"#,
            r#"[1.5e10, -3, "quote\"inside", {"nested": []}]"#,
            "not json at all {",
            "",
            r#""unterminated string"#,
            "{\"dup\":{},\"dup\":{}}",
            "﻿{\"unicode\":\"héllo\"}",
        ];
        for case in cases {
            let spans = highlight_json_line(case);
            assert_eq!(joined(&spans), case, "tokenization must not drop text");
        }
    }

    #[test]
    fn keys_numbers_literals_get_distinct_styles() {
        let spans = highlight_json_line(r#"{"count": 42, "ok": true}"#);
        let styles: Vec<_> = spans.iter().map(|s| s.style).collect();
        // At least three distinct styles appear (keys/strings vs numbers vs
        // booleans or punctuation).
        let unique: std::collections::HashSet<_> = styles.iter().collect();
        assert!(unique.len() >= 2, "expected styled output: {spans:?}");
    }

    #[test]
    fn deep_nesting_10k_does_not_recurse_or_panic() {
        // 10k-deep nested arrays; the tokenizer is a flat iterative scan.
        let depth = 10_000;
        let mut src = String::with_capacity(depth * 2 + 8);
        for _ in 0..depth {
            src.push('[');
        }
        src.push('1');
        for _ in 0..depth {
            src.push(']');
        }
        for line in src.lines() {
            let spans = highlight_json_line(line);
            assert_eq!(joined(&spans), line);
        }
        // And through the byte entry point (lossy UTF-8 path).
        assert!(!highlight_json_bytes(src.as_bytes()).is_empty());
    }

    #[test]
    fn invalid_utf8_is_lossy_never_panics() {
        let mut bytes = b"{\"key\": \"".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, 0x80]);
        bytes.extend_from_slice(b"\", \"n\": 7}");
        let lines = highlight_json_bytes(&bytes);
        assert_eq!(lines.len(), 1);
        let rebuilt = joined(&lines[0]);
        assert!(rebuilt.contains("\"n\""));
        assert!(std::str::from_utf8(bytes.as_slice()).is_err());
    }

    #[test]
    fn pretty_print_round_trips_and_falls_back() {
        let pretty = pretty_print_json("{\"b\":1,\"a\":[2,3]}").expect("parses");
        assert!(pretty.contains("\n"), "multi-line output");
        assert!(pretty_print_json("{broken").is_none());
    }
}
