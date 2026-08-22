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

/// Renders the full flow-list screen (table + filter bar + status bar).
pub(crate) fn draw_flows(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let error_lines = usize::from(app.compiled.error().is_some());
    let editing = usize::from(app.filter_editing);
    let bar_height = (1 + editing + error_lines) as u16;
    let [table_area, bar_area, status_area] = ratatui::layout::Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(bar_height),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_table(f, table_area, app);
    draw_filter_bar(f, bar_area, app);
    draw_status_bar(f, status_area, app);
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
