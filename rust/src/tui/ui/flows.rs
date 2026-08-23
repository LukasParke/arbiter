//! Virtualized flow-list rendering: table, filter bar, status bar.
//!
//! Only the visible window of rows is materialized per frame; the ring may
//! hold up to 100k summaries but draw cost stays O(viewport).

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::App;
use crate::tui::feed::FlowSummaryDto;

pub(crate) const COLUMNS: &[&str] = &[
    "seq", "time", "method", "status", "path", "ms", "provider", "model", "tokens",
];

fn status_style(status: Option<u16>) -> Style {
    match status {
        Some(s) if (200..300).contains(&s) => Style::default().fg(Color::Green),
        Some(s) if (300..400).contains(&s) => Style::default().fg(Color::Cyan),
        Some(s) if (400..500).contains(&s) => Style::default().fg(Color::Yellow),
        Some(s) if s >= 500 => Style::default().fg(Color::Red),
        Some(_) => Style::default(),
        None => Style::default().fg(Color::DarkGray),
    }
}

fn truncate_cell(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn time_column(started_at: &str) -> &str {
    // ISO-8601; show HH:MM:SS.mmm for scannable rows.
    started_at.get(11..23).unwrap_or(started_at)
}

fn tokens_cell(summary: &FlowSummaryDto) -> String {
    summary
        .llm
        .as_ref()
        .map(|llm| {
            format!(
                "{}/{}",
                llm.input_tokens
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into()),
                llm.output_tokens
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into())
            )
        })
        .unwrap_or_default()
}

/// Renders the full flow-list screen (endpoint strip + disconnect banner +
/// table + filter bar + status bar).
pub(crate) fn draw_flows(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let error_lines = usize::from(app.compiled.error().is_some());
    let editing = usize::from(app.filter_editing);
    let bar_height = (1 + editing + error_lines) as u16;
    // T4: full-width red banner while the attached instance is unreachable.
    let banner_height = u16::from(app.disconnected_since.is_some());
    // T3: one-line endpoint strip always visible in embedded mode.
    let strip_height = u16::from(app.embedded.is_some());
    let [banner_area, strip_area, main_area] = ratatui::layout::Layout::vertical([
        Constraint::Length(banner_height),
        Constraint::Length(strip_height),
        Constraint::Min(3),
    ])
    .areas(area);

    if let Some(since) = app.disconnected_since.as_deref() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" ATTACHED INSTANCE UNREACHABLE — data stale since {since} "),
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ))),
            banner_area,
        );
    }
    // Clone the label up front: `app` is borrowed mutably by the table
    // draw below.
    let endpoint_label = app.embedded.as_ref().map(endpoint_line);
    if let Some(label) = &endpoint_label {
        // First paint (no flows yet): a large centered call to action.
        if app.flows.is_empty() && !app.filter_editing {
            let [_, center, _] = ratatui::layout::Layout::vertical([
                Constraint::Percentage(40),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .areas(main_area);
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    label,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))),
                center,
            );
        }
        // Persistent one-line header strip.
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {label} "),
                Style::default().fg(Color::Black).bg(Color::Cyan),
            ))),
            strip_area,
        );
    }

    let [table_area, bar_area, status_area] = ratatui::layout::Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(bar_height),
        Constraint::Length(1),
    ])
    .areas(main_area);

    draw_table(f, table_area, app);
    draw_filter_bar(f, bar_area, app);
    draw_status_bar(f, status_area, app);
}

/// `proxy listening → send traffic to <url>  (target <target>)`.
fn endpoint_line(endpoint: &crate::tui::app::EmbeddedEndpoint) -> String {
    format!(
        "proxy listening → send traffic to {}  (target {})",
        endpoint.listen_url, endpoint.target
    )
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(COLUMNS.iter().map(|name| {
        Cell::from(*name).style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
    }));

    // Virtualized window: rows available under the header + borders.
    let viewport_rows = area.height.saturating_sub(3) as usize;
    app.ensure_visible(viewport_rows.max(1));
    let start = app.list_offset;
    let end = (start + viewport_rows.max(1)).min(app.view.len());

    let rows = app.view[start..end].iter().map(|seq| {
        let summary = app.summary_for(*seq).expect("view seq resolves into ring");
        let selected = Some(*seq) == app.current_seq();
        let base = if selected {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        let status_cell = Cell::from(
            summary
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
        )
        .style(if selected {
            base
        } else {
            status_style(summary.status)
        });
        let llm = summary.llm.as_ref();
        Row::new(vec![
            Cell::from(summary.sequence.to_string()),
            Cell::from(time_column(&summary.started_at)),
            Cell::from(truncate_cell(&summary.method, 7)),
            status_cell,
            Cell::from(truncate_cell(&summary.path, 64)),
            Cell::from(
                summary
                    .duration_ms
                    .map(|ms| format!("{ms:.0}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(truncate_cell(
                llm.map(|l| l.provider.as_str()).unwrap_or(""),
                12,
            )),
            Cell::from(truncate_cell(
                llm.and_then(|l| l.model.as_deref()).unwrap_or(""),
                20,
            )),
            Cell::from(tokens_cell(summary)),
        ])
        .style(base)
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(13),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(20),
            Constraint::Length(11),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(format!(
        " flows {}–{} of {} ",
        start + 1,
        end,
        app.view.len()
    )));
    f.render_widget(table, area);
}

fn draw_filter_bar(f: &mut Frame, area: Rect, app: &App) {
    let prompt = if app.filter_editing {
        "filter> "
    } else {
        "filter  "
    };
    let cursor = if app.filter_editing { "_" } else { "" };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(prompt, Style::default().fg(Color::Cyan)),
            Span::raw(app.filter_input.clone()),
            Span::styled(cursor, Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])),
        Rect::new(area.x, area.y, area.width, 1),
    );
    if let Some(error) = app.compiled.error() {
        f.render_widget(
            Paragraph::new(Span::styled(
                error.render(),
                Style::default().fg(Color::Red),
            )),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
    }
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::styled(
        format!(" {} ", app.view.len()),
        Style::default().fg(Color::Black).bg(Color::Blue),
    )];
    if app.dropped > 0 {
        spans.push(Span::styled(
            format!(" dropped {} ", app.dropped),
            Style::default().fg(Color::Black).bg(Color::Yellow),
        ));
    }
    if let Some(message) = app.status.as_deref() {
        spans.push(Span::styled(
            format!(" {message} "),
            Style::default().fg(Color::Magenta),
        ));
    }
    spans.push(Span::styled(
        format!(" {}", App::status_bar_help()),
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use crate::tui::filter::{InMemorySavedFilterStore, SavedFilterStore};
    use std::sync::{Arc, Mutex as StdMutex};

    fn app() -> App {
        let store: Arc<StdMutex<dyn SavedFilterStore>> =
            Arc::new(StdMutex::new(InMemorySavedFilterStore::new()));
        App::new(None, store)
    }
    /// Renders the flow-list screen into an offscreen buffer and returns
    /// the flattened cell text.
    fn rendered(app: &mut App) -> String {
        let backend = ratatui::backend::TestBackend::new(110, 24);
        let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
        terminal.draw(|f| draw_flows(f, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect()
    }

    #[test]
    fn embedded_header_strip_and_skeleton_advertise_endpoint() {
        let mut app = app();
        app.set_embedded("http://127.0.0.1:9090", "http://api.test:8080");
        // First paint with no flows: the skeleton call to action.
        let skeleton = rendered(&mut app);
        assert!(skeleton.contains("proxy listening"), "{skeleton}");
        assert!(skeleton.contains("http://127.0.0.1:9090"));
        assert!(skeleton.contains("(target http://api.test:8080)"));

        // With traffic present the strip persists at the top.
        app.on_batch(vec![crate::tui::feed::FlowSummaryDto {
            sequence: 1,
            started_at: "2026-08-22T00:00:00.000Z".to_string(),
            method: "GET".to_string(),
            path: "/x".to_string(),
            host: None,
            status: Some(200),
            duration_ms: Some(1.0),
            kind: "http".to_string(),
            llm: None,
        }]);
        let frame = rendered(&mut app);
        assert!(frame.contains("send traffic to http://127.0.0.1:9090"));
    }

    #[test]
    fn attach_mode_shows_no_endpoint_strip() {
        let mut app = app();
        let frame = rendered(&mut app);
        assert!(!frame.contains("proxy listening"));
    }

    #[test]
    fn disconnect_banner_renders_full_width_with_stale_stamp() {
        let mut app = app();
        app.set_disconnected_since(Some("12:34:56".to_string()));
        let frame = rendered(&mut app);
        assert!(frame.contains("ATTACHED INSTANCE UNREACHABLE"));
        assert!(frame.contains("data stale since 12:34:56"));
    }

    #[test]
    fn connected_feed_renders_no_banner() {
        let mut app = app();
        let frame = rendered(&mut app);
        assert!(!frame.contains("UNREACHABLE"));
    }
}
