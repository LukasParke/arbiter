//! TUI application state machine (W5).
//!
//! Owns the flow ring buffer, filtered view, screens, and key semantics.
//! Key handling is expressed as [`Action`]s returning [`Effect`]s so every
//! transition is unit-testable without a terminal; the event loop in
//! `cli/tui.rs` maps crossterm keys to actions and executes effects against
//! the live feed.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::tui::feed::{FlowDetailDto, FlowSummaryDto};
use crate::tui::filter::{Filter, FilterError, SavedFilter, SavedFilterStore};
use url::Url;

/// Ring capacity: bounded memory with an explicit drop-oldest counter shown
/// in the status bar (perf bar: never unbounded).
pub const RING_CAPACITY: usize = 100_000;

/// Fallback detail-body viewport rows before the renderer reports the real
/// pane height.
const DEFAULT_BODY_VIEWPORT_ROWS: usize = 20;

const STATUS_BAR_HELP: &str =
    "q quit · / filter · enter detail · r replay · x delete · w export HAR · : palette · ? help";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    FlowList,
    FlowDetail,
    Help,
    Palette,
}

/// Semantic input, independent of crossterm so transitions are testable.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Quit,
    OpenFilter,
    FilterInput(char),
    FilterBackspace,
    FilterCommit,
    FilterCancel,
    MoveDown,
    MoveUp,
    PageDown,
    PageUp,
    Top,
    Bottom,
    OpenDetail,
    CloseOverlay,
    Replay,
    Delete,
    ConfirmYes,
    ConfirmNo,
    ExportHar(PathBuf),
    TogglePretty,
    ToggleRaw,
    /// Scroll the detail body down by `n` lines.
    BodyScrollDown(usize),
    /// Scroll the detail body up by `n` lines.
    BodyScrollUp(usize),
    /// Scroll the detail body by half a viewport.
    BodyPageDown,
    /// Scroll the detail body back by half a viewport.
    BodyPageUp,
    /// Jump to the top of the detail body.
    BodyTop,
    /// Jump to the bottom of the detail body.
    BodyBottom,
    OpenHelp,
    OpenPalette,
    PaletteInput(char),
    PaletteBackspace,
    PaletteCommit,
}

/// Commands the event loop must execute against the live feed/store.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Lazily resolve detail for the sequence.
    FetchDetail(u64),
    Delete(u64),
    Replay(u64),
    ExportHar {
        path: PathBuf,
    },
    /// Re-attach the feed over HTTP at this base URL.
    AttachHttp(Url),
}

#[derive(Debug, Clone, PartialEq)]
enum Pending {
    Replay(u64),
    Delete(u64),
    /// HAR export awaiting an overwrite confirmation.
    Export(PathBuf),
}

/// Embedded-mode endpoint info for the listening banner (T3).
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddedEndpoint {
    /// Base URL where proxy traffic should be sent, e.g.
    /// `http://127.0.0.1:8080`.
    pub listen_url: String,
    /// Human-readable upstream target the capture proxies to.
    pub target: String,
}

/// Compiled filter state.
#[derive(Debug, Clone)]
pub enum CompiledFilter {
    None,
    Ok(Filter),
    Err(FilterError),
}

impl CompiledFilter {
    /// True when the expression parses but matches nothing.
    pub fn error(&self) -> Option<&FilterError> {
        match self {
            CompiledFilter::Err(e) => Some(e),
            _ => None,
        }
    }
}

pub struct App {
    /// Ring of summaries, ascending by sequence, capped at
    /// [`RING_CAPACITY`].
    pub flows: VecDeque<FlowSummaryDto>,
    /// Sequences passing the active filter (ascending).
    pub view: Vec<u64>,
    /// Flows evicted drop-oldest once the ring capped.
    pub dropped: u64,
    pub screen: Screen,
    pub selected: usize,
    /// Index of the first visible row (virtualized window start).
    pub list_offset: usize,
    pub filter_editing: bool,
    pub filter_input: String,
    pub compiled: CompiledFilter,
    pub detail: Option<FlowDetailDto>,
    pub detail_loading: bool,
    pub pretty_print: bool,
    pub show_raw: bool,
    pub body_scroll: usize,
    /// Rows visible in the detail-body pane (hint fed back by the renderer;
    /// drives half-page scrolls and clamping).
    body_viewport: usize,
    /// Embedded-mode endpoint info; `None` in attach mode.
    pub embedded: Option<EmbeddedEndpoint>,
    /// Attached instance unreachable since this `HH:MM:SS` stamp.
    pub disconnected_since: Option<String>,
    pending: Option<Pending>,
    palette_input: String,
    pub status: Option<String>,
    pub quit: bool,
    saved_filters: Arc<Mutex<dyn SavedFilterStore>>,
}

impl App {
    pub fn new(
        initial_filter: Option<&str>,
        saved_filters: Arc<Mutex<dyn SavedFilterStore>>,
    ) -> Self {
        let mut app = Self {
            flows: VecDeque::new(),
            view: Vec::new(),
            dropped: 0,
            screen: Screen::FlowList,
            selected: 0,
            list_offset: 0,
            filter_editing: false,
            filter_input: initial_filter.unwrap_or_default().to_string(),
            compiled: CompiledFilter::None,
            detail: None,
            detail_loading: false,
            pretty_print: true,
            show_raw: false,
            body_scroll: 0,
            body_viewport: DEFAULT_BODY_VIEWPORT_ROWS,
            embedded: None,
            disconnected_since: None,
            pending: None,
            palette_input: String::new(),
            status: None,
            quit: false,
            saved_filters,
        };
        if let Some(expr) = initial_filter.filter(|e| !e.trim().is_empty()) {
            app.apply_filter(expr);
        }
        app
    }

    // -- data ingestion ----------------------------------------------------

    /// Ingests one feed batch: ring insert with drop-oldest eviction and an
    /// incremental filter pass over just the new rows. Sequences already in
    /// the ring are skipped, so a reconnect's full refetch (cursor reset to
    /// 0) never duplicates rows.
    pub fn on_batch(&mut self, batch: Vec<FlowSummaryDto>) {
        let mut newly_matched: Vec<u64> = Vec::with_capacity(batch.len());
        for summary in batch {
            let seq = summary.sequence;
            if self.summary_for(seq).is_some() {
                continue;
            }
            let passes = match &self.compiled {
                CompiledFilter::Ok(filter) => filter.matches_summary(&summary),
                _ => true,
            };
            self.push_ring(summary);
            if passes {
                newly_matched.push(seq);
            }
        }
        if !newly_matched.is_empty() {
            // Merge ascending (batch arrives ascending), dropping rows the
            // ring already evicted drop-oldest during this batch.
            let min_kept = self.flows.front().map(|summary| summary.sequence);
            let merged: Vec<u64> = std::mem::take(&mut self.view)
                .into_iter()
                .chain(newly_matched)
                .filter(|seq| min_kept.is_none_or(|min| *seq >= min))
                .collect();
            self.view = merged;
            self.view.dedup();
        }
    }

    fn push_ring(&mut self, summary: FlowSummaryDto) {
        self.flows.push_back(summary);
        while self.flows.len() > RING_CAPACITY {
            let evicted = self.flows.pop_front().expect("ring non-empty").sequence;
            self.dropped += 1;
            if let Ok(pos) = self.view.binary_search(&evicted) {
                self.view.remove(pos);
                // Keep the selection anchored to the same logical row.
                if pos < self.selected {
                    self.selected = self.selected.saturating_sub(1);
                }
            }
        }
        self.selected = self.selected.min(self.view.len().saturating_sub(1));
        if self.view.is_empty() {
            self.selected = 0;
        }
    }

    /// Replaces the applied filter and recomputes the whole view.
    pub fn apply_filter(&mut self, expression: &str) {
        self.filter_input = expression.to_string();
        if expression.trim().is_empty() {
            self.compiled = CompiledFilter::None;
        } else {
            self.compiled = match Filter::parse(expression) {
                Ok(filter) => CompiledFilter::Ok(filter),
                Err(e) => CompiledFilter::Err(e),
            };
        }
        self.refilter_all();
    }

    fn refilter_all(&mut self) {
        self.view = self
            .flows
            .iter()
            .filter(|summary| match &self.compiled {
                CompiledFilter::Ok(filter) => filter.matches_summary(summary),
                _ => true,
            })
            .map(|summary| summary.sequence)
            .collect();
        self.selected = self.selected.min(self.view.len().saturating_sub(1));
        self.list_offset = 0;
        if self.view.is_empty() {
            self.selected = 0;
        }
    }

    // -- lookups -----------------------------------------------------------
    pub fn current_seq(&self) -> Option<u64> {
        self.view.get(self.selected).copied()
    }

    /// Resolves a view sequence to its ring summary.
    pub(crate) fn summary_for(&self, seq: u64) -> Option<&FlowSummaryDto> {
        let index = self.seq_index(seq);
        self.flows
            .get(index)
            .filter(|summary| summary.sequence == seq)
    }

    /// Binary search for a sequence's deque position (ascending order).
    fn seq_index(&self, seq: u64) -> usize {
        let mut low = 0usize;
        let mut high = self.flows.len();
        while low < high {
            let mid = (low + high) / 2;
            if self.flows[mid].sequence < seq {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low.min(self.flows.len().saturating_sub(1))
    }

    /// Adjusts the virtualized window so the selection stays visible within
    /// `viewport_rows` (rows available under the table header).
    pub fn ensure_visible(&mut self, viewport_rows: usize) {
        if viewport_rows == 0 || self.view.is_empty() {
            return;
        }
        self.selected = self.selected.min(self.view.len() - 1);
        if self.selected < self.list_offset {
            self.list_offset = self.selected;
        } else if self.selected >= self.list_offset + viewport_rows {
            self.list_offset = self.selected + 1 - viewport_rows;
        }
        self.list_offset = self.list_offset.min(self.view.len().saturating_sub(1));
    }

    // -- actions -----------------------------------------------------------

    /// Applies one semantic action; returns effects the event loop must run.
    pub fn handle_action(&mut self, action: Action) -> Vec<Effect> {
        match action {
            Action::Quit => {
                self.quit = true;
                Vec::new()
            }
            Action::OpenFilter => {
                self.screen = Screen::FlowList;
                self.filter_editing = true;
                Vec::new()
            }
            Action::FilterInput(ch) => {
                self.filter_editing = true;
                self.filter_input.push(ch);
                Vec::new()
            }
            Action::FilterBackspace => {
                self.filter_input.pop();
                Vec::new()
            }
            Action::FilterCancel => {
                self.filter_editing = false;
                Vec::new()
            }
            Action::FilterCommit => {
                self.filter_editing = false;
                let expression = self.filter_input.clone();
                self.apply_filter(&expression);
                self.status = self.compiled.error().map(|e| e.render());
                Vec::new()
            }
            Action::MoveDown => {
                self.move_selection(1);
                Vec::new()
            }
            Action::MoveUp => {
                self.move_selection(-1);
                Vec::new()
            }
            Action::PageDown => {
                self.move_selection(20);
                Vec::new()
            }
            Action::PageUp => {
                self.move_selection(-20);
                Vec::new()
            }
            Action::Top => {
                self.selected = 0;
                Vec::new()
            }
            Action::Bottom => {
                self.selected = self.view.len().saturating_sub(1);
                Vec::new()
            }
            Action::OpenDetail => {
                if let Some(seq) = self.current_seq() {
                    self.screen = Screen::FlowDetail;
                    self.detail_loading = true;
                    self.detail = None;
                    self.body_scroll = 0;
                    return vec![Effect::FetchDetail(seq)];
                }
                Vec::new()
            }
            Action::CloseOverlay => {
                self.pending = None;
                match self.screen {
                    Screen::FlowDetail => {
                        self.screen = Screen::FlowList;
                        self.detail = None;
                    }
                    Screen::Help | Screen::Palette => self.screen = Screen::FlowList,
                    Screen::FlowList => self.filter_editing = false,
                }
                Vec::new()
            }
            Action::Replay => match self.current_seq() {
                Some(seq) => {
                    self.pending = Some(Pending::Replay(seq));
                    self.status = Some(format!("replay flow {seq}? y/n"));
                    Vec::new()
                }
                None => Vec::new(),
            },
            Action::Delete => match self.current_seq() {
                Some(seq) => {
                    self.pending = Some(Pending::Delete(seq));
                    self.status = Some(format!("delete flow {seq}? y/n"));
                    Vec::new()
                }
                None => Vec::new(),
            },
            Action::ConfirmYes => {
                let confirmed = self.pending.take();
                match confirmed {
                    Some(Pending::Delete(seq)) => {
                        self.remove_locally(seq);
                        vec![Effect::Delete(seq)]
                    }
                    Some(Pending::Replay(seq)) => vec![Effect::Replay(seq)],
                    Some(Pending::Export(path)) => {
                        self.status = None;
                        vec![Effect::ExportHar { path }]
                    }
                    None => Vec::new(),
                }
            }
            Action::ConfirmNo => {
                if matches!(self.pending, Some(Pending::Export(_))) {
                    self.status = Some("export cancelled".into());
                } else {
                    self.status = None;
                }
                self.pending = None;
                Vec::new()
            }
            Action::ExportHar(path) => {
                // Never silently clobber an existing file: ask first (B6).
                if path.exists() {
                    self.pending = Some(Pending::Export(path.clone()));
                    self.status = Some(format!("overwrite {}? (y/n)", path.display()));
                    Vec::new()
                } else {
                    vec![Effect::ExportHar { path }]
                }
            }
            Action::TogglePretty => {
                self.pretty_print = !self.pretty_print;
                Vec::new()
            }
            Action::ToggleRaw => {
                self.show_raw = !self.show_raw;
                Vec::new()
            }
            Action::BodyScrollDown(lines) => {
                self.body_scroll = self.body_scroll.saturating_add(lines.max(1));
                self.clamp_body_scroll();
                Vec::new()
            }
            Action::BodyScrollUp(lines) => {
                self.body_scroll = self.body_scroll.saturating_sub(lines.max(1));
                Vec::new()
            }
            Action::BodyPageDown => {
                let half = (self.body_viewport / 2).max(1);
                self.body_scroll = self.body_scroll.saturating_add(half);
                self.clamp_body_scroll();
                Vec::new()
            }
            Action::BodyPageUp => {
                let half = (self.body_viewport / 2).max(1);
                self.body_scroll = self.body_scroll.saturating_sub(half);
                Vec::new()
            }
            Action::BodyTop => {
                self.body_scroll = 0;
                Vec::new()
            }
            Action::BodyBottom => {
                self.body_scroll = usize::MAX;
                self.clamp_body_scroll();
                Vec::new()
            }
            Action::OpenHelp => {
                self.screen = Screen::Help;
                Vec::new()
            }
            Action::OpenPalette => {
                self.screen = Screen::Palette;
                self.palette_input.clear();
                Vec::new()
            }
            Action::PaletteInput(ch) => {
                self.palette_input.push(ch);
                Vec::new()
            }
            Action::PaletteBackspace => {
                self.palette_input.pop();
                Vec::new()
            }
            Action::PaletteCommit => self.run_palette_command(),
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.view.is_empty() {
            return;
        }
        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, self.view.len() as isize - 1) as usize;
    }

    fn remove_locally(&mut self, seq: u64) {
        if let Ok(pos) = self.view.binary_search(&seq) {
            self.view.remove(pos);
            if pos < self.selected {
                self.selected = self.selected.saturating_sub(1);
            }
        }
        self.selected = self.selected.min(self.view.len().saturating_sub(1));
    }

    /// `:` palette commands: `save NAME`, `load NAME`, `attach URL`,
    /// `export PATH`.
    fn run_palette_command(&mut self) -> Vec<Effect> {
        self.screen = Screen::FlowList;
        let command = self.palette_input.trim().to_string();
        self.palette_input.clear();
        let mut parts = command.splitn(2, ' ');
        let verb = parts.next().unwrap_or_default();
        let rest = parts.next().unwrap_or_default().trim().to_string();
        match (verb, rest.is_empty()) {
            ("save", false) => {
                let query = self.filter_input.clone();
                if query.trim().is_empty() {
                    self.status =
                        Some("error: nothing to save\n  help: set a filter with / first".into());
                } else {
                    self.saved_filters
                        .lock()
                        .expect("saved filters lock")
                        .save(SavedFilter { name: rest, query });
                    self.status = Some("saved".into());
                }
                Vec::new()
            }
            ("load", false) => {
                let found = self
                    .saved_filters
                    .lock()
                    .expect("saved filters lock")
                    .list()
                    .into_iter()
                    .find(|f| f.name == rest);
                match found {
                    Some(saved) => {
                        self.apply_filter(&saved.query);
                        Vec::new()
                    }
                    None => {
                        self.status = Some(format!(
                            "error: no saved filter `{rest}`\n  help: create one with `:save {rest}`"
                        ));
                        Vec::new()
                    }
                }
            }
            ("attach", false) => match Url::parse(&rest) {
                Ok(url) => vec![Effect::AttachHttp(url)],
                Err(e) => {
                    self.status = Some(format!("error: invalid attach URL\n  help: {e}"));
                    Vec::new()
                }
            },
            ("export", false) => vec![Effect::ExportHar {
                path: PathBuf::from(rest),
            }],
            ("filters", _) => {
                let names: Vec<String> = self
                    .saved_filters
                    .lock()
                    .expect("saved filters lock")
                    .list()
                    .into_iter()
                    .map(|f| f.name)
                    .collect();
                self.status = Some(if names.is_empty() {
                    "no saved filters".into()
                } else {
                    names.join(", ")
                });
                Vec::new()
            }
            _ => {
                self.status = Some(
                    "error: unknown command\n  help: save NAME · load NAME · filters · attach URL · export PATH"
                        .into(),
                );
                Vec::new()
            }
        }
    }

    // -- results fed back by the event loop ---------------------------------

    pub fn set_detail(&mut self, detail: FlowDetailDto) {
        self.detail = Some(detail);
        self.detail_loading = false;
        self.body_scroll = 0;
    }

    /// Renderer feedback: rows visible in the detail-body pane.
    pub fn note_body_viewport(&mut self, rows: usize) {
        if rows > 0 {
            self.body_viewport = rows;
            self.clamp_body_scroll();
        }
    }

    /// Total rendered lines of the detail body (pretty/compact/raw aware),
    /// matching the renderer's preparation exactly.
    pub fn body_total_lines(&self) -> usize {
        let Some(detail) = &self.detail else {
            return 0;
        };
        let count = |view: &crate::tui::feed::BodyViewDto| -> usize {
            let text = view.text.clone().unwrap_or_default();
            let prepared = if self.pretty_print && !self.show_raw {
                crate::tui::ui::detail::pretty_print_json(&text).unwrap_or(text)
            } else {
                text
            };
            prepared.lines().count()
        };
        count(&detail.request_body).max(count(&detail.response_body))
    }

    /// Clamps `body_scroll` so the window `[offset, offset + viewport)` can
    /// still show the last line of the content (B5).
    pub fn clamp_body_scroll(&mut self) {
        let total = self.body_total_lines();
        if total == 0 || total <= self.body_viewport {
            self.body_scroll = 0;
            return;
        }
        self.body_scroll = self.body_scroll.min(total - self.body_viewport);
    }

    /// Visible scroll window as `(start, end)` line indices for content of
    /// `total_lines` rows in a viewport `rows` tall.
    pub fn body_scroll_window(&self, total_lines: usize, rows: usize) -> (usize, usize) {
        let rows = rows.max(1);
        let start = if total_lines <= rows {
            0
        } else {
            self.body_scroll.min(total_lines - rows)
        };
        (start, (start + rows).min(total_lines))
    }

    /// True when the detail body overflows its viewport (drives the
    /// `line X–Y of N` footer indicator).
    pub fn body_scrollable(&self) -> bool {
        self.body_total_lines() > self.body_viewport
    }

    /// Registers embedded-mode endpoint info for the listening banner (T3).
    pub fn set_embedded(&mut self, listen_url: impl Into<String>, target: impl Into<String>) {
        self.embedded = Some(EmbeddedEndpoint {
            listen_url: listen_url.into(),
            target: target.into(),
        });
    }

    /// Event-loop feedback each poll tick: attached-instance health (T4).
    pub fn set_disconnected_since(&mut self, since: Option<String>) {
        self.disconnected_since = since;
    }

    /// The export path awaiting an overwrite confirmation, if any (B6).
    pub fn pending_export_path(&self) -> Option<&std::path::Path> {
        match &self.pending {
            Some(Pending::Export(path)) => Some(path.as_path()),
            _ => None,
        }
    }

    pub fn detail_fetch_missing(&mut self) {
        self.detail_loading = false;
        self.status = Some("flow detail unavailable (deleted?)".into());
    }

    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status = Some(message.into());
    }

    pub fn palette_text(&self) -> &str {
        &self.palette_input
    }

    pub fn pending_confirmation(&self) -> bool {
        self.pending.is_some()
    }

    pub fn status_bar_help() -> &'static str {
        STATUS_BAR_HELP
    }
}

// ---------------------------------------------------------------------------
// Key mapping (crossterm -> semantic actions)
// ---------------------------------------------------------------------------

/// Maps a crossterm key event to semantic actions for the current screen.
pub fn map_key(code: crossterm::event::KeyCode, screen: Screen, editing: bool) -> Vec<Action> {
    map_key_event(code, crossterm::event::KeyModifiers::NONE, screen, editing)
}

/// Modifier-aware mapping. `Ctrl+C` quits from ANY state — every screen,
/// overlay, editor, or confirmation (T1) — while plain keys keep the
/// per-screen semantics below.
pub fn map_key_event(
    code: crossterm::event::KeyCode,
    modifiers: crossterm::event::KeyModifiers,
    screen: Screen,
    editing: bool,
) -> Vec<Action> {
    use crossterm::event::{KeyCode as K, KeyModifiers as M};
    if modifiers.contains(M::CONTROL) {
        return match code {
            K::Char('c') => vec![Action::Quit],
            _ => Vec::new(),
        };
    }
    if editing {
        return match code {
            K::Enter => vec![if screen == Screen::Palette {
                Action::PaletteCommit
            } else {
                Action::FilterCommit
            }],
            K::Esc => vec![Action::FilterCancel],
            K::Backspace => vec![if screen == Screen::Palette {
                Action::PaletteBackspace
            } else {
                Action::FilterBackspace
            }],
            K::Char(ch) => vec![if screen == Screen::Palette {
                Action::PaletteInput(ch)
            } else {
                Action::FilterInput(ch)
            }],
            _ => Vec::new(),
        };
    }
    if screen == Screen::FlowDetail {
        // Detail view: arrows/j/k scroll one body line, PgUp/PgDn half a
        // page, Home/End jump (B5). Everything else stays global.
        return match code {
            K::Down | K::Char('j') => vec![Action::BodyScrollDown(1)],
            K::Up | K::Char('k') => vec![Action::BodyScrollUp(1)],
            K::PageDown | K::Char('J') => vec![Action::BodyPageDown],
            K::PageUp | K::Char('K') => vec![Action::BodyPageUp],
            K::Home | K::Char('g') => vec![Action::BodyTop],
            K::End | K::Char('G') => vec![Action::BodyBottom],
            K::Char('q') => vec![Action::Quit],
            K::Esc | K::Char('c') => vec![Action::CloseOverlay],
            K::Char('r') => vec![Action::Replay],
            K::Char('x') => vec![Action::Delete],
            K::Char('y') => vec![Action::ConfirmYes],
            K::Char('n') => vec![Action::ConfirmNo],
            K::Char('p') => vec![Action::TogglePretty],
            K::Char('R') => vec![Action::ToggleRaw],
            K::Char('w') => vec![Action::ExportHar(default_har_path())],
            K::Char('?') => vec![Action::OpenHelp],
            K::Char(':') => vec![Action::OpenPalette],
            K::Char('/') => vec![Action::OpenFilter],
            _ => Vec::new(),
        };
    }
    match code {
        K::Char('q') => vec![Action::Quit],
        K::Char('c') => vec![Action::CloseOverlay],
        K::Char('/') => vec![Action::OpenFilter],
        K::Enter => vec![Action::OpenDetail],
        K::Esc => vec![Action::CloseOverlay],
        K::Down | K::Char('j') => vec![Action::MoveDown],
        K::Up | K::Char('k') => vec![Action::MoveUp],
        K::PageDown | K::Char('J') => vec![Action::PageDown],
        K::PageUp | K::Char('K') => vec![Action::PageUp],
        K::Home | K::Char('g') => vec![Action::Top],
        K::End | K::Char('G') => vec![Action::Bottom],
        K::Char('r') => vec![Action::Replay],
        K::Char('x') => vec![Action::Delete],
        K::Char('y') => vec![Action::ConfirmYes],
        K::Char('n') => vec![Action::ConfirmNo],
        K::Char('p') => vec![Action::TogglePretty],
        K::Char('R') => vec![Action::ToggleRaw],
        K::Char('w') => vec![Action::ExportHar(default_har_path())],
        K::Char('?') => vec![Action::OpenHelp],
        K::Char(':') => vec![Action::OpenPalette],
        _ => Vec::new(),
    }
}

fn default_har_path() -> PathBuf {
    PathBuf::from("arbiter-flows.har")
}

// ---------------------------------------------------------------------------
// Tests: state transitions without a terminal
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::filter::{InMemorySavedFilterStore, SavedFilterStore};

    fn summary(seq: u64, method: &str, path: &str, status: u16) -> FlowSummaryDto {
        FlowSummaryDto {
            sequence: seq,
            started_at: "2026-08-22T00:00:00.000Z".to_string(),
            method: method.to_string(),
            path: path.to_string(),
            host: Some("api.example.com".to_string()),
            status: Some(status),
            duration_ms: Some(3.0),
            kind: "http".to_string(),
            llm: None,
        }
    }

    fn store() -> Arc<Mutex<dyn SavedFilterStore>> {
        Arc::new(Mutex::new(InMemorySavedFilterStore::new()))
    }

    #[test]
    fn batches_fill_ring_and_refilter_incrementally() {
        let mut app = App::new(None, store());
        app.on_batch(vec![
            summary(1, "GET", "/a", 200),
            summary(2, "POST", "/b", 500),
        ]);
        app.on_batch(vec![summary(3, "GET", "/c", 404)]);
        assert_eq!(app.flows.len(), 3);
        assert_eq!(app.view.len(), 3);

        app.apply_filter("status>=400");
        assert_eq!(app.view, vec![2, 3]);

        // New arrivals matching the filter join the view immediately.
        app.on_batch(vec![summary(4, "GET", "/d", 503)]);
        assert_eq!(app.view, vec![2, 3, 4]);
        // Non-matching arrivals do not.
        app.on_batch(vec![summary(5, "GET", "/e", 200)]);
        assert_eq!(app.view, vec![2, 3, 4]);
    }

    #[test]
    fn ring_eviction_drops_oldest_and_counts() {
        let mut app = App::new(None, store());
        app.on_batch(
            (0..(RING_CAPACITY as u64 + 25))
                .map(|seq| summary(seq, "GET", "/x", 200))
                .collect(),
        );
        assert_eq!(app.flows.len(), RING_CAPACITY);
        assert_eq!(app.flows.front().expect("front").sequence, 25);
        assert_eq!(app.view.first().copied(), Some(25));
    }

    #[test]
    fn filter_errors_surface_with_position_and_help() {
        let mut app = App::new(Some("status>=xx host=("), store());
        app.handle_action(Action::FilterCommit);
        match &app.compiled {
            CompiledFilter::Err(e) => {
                let rendered = e.render();
                assert!(rendered.starts_with("error: "), "{rendered}");
                assert!(rendered.contains("\n  help: "), "{rendered}");
            }
            other => panic!("expected parse error, got {other:?}"),
        }

        app.apply_filter("");
        assert!(matches!(app.compiled, CompiledFilter::None));
    }

    #[test]
    fn or_and_parens_grouping_in_view() {
        let mut app = App::new(Some("(method=POST OR status=2xx) path~/v1/**"), store());
        app.on_batch(vec![
            summary(1, "POST", "/v1/messages", 500),
            summary(2, "GET", "/v1/models", 200),
            summary(3, "POST", "/other", 200),
            summary(4, "GET", "/outside", 200),
        ]);
        assert_eq!(app.view, vec![1, 2]);
    }

    #[test]
    fn navigation_and_virtualization_window() {
        let mut app = App::new(None, store());
        app.on_batch((0..100).map(|seq| summary(seq, "GET", "/x", 200)).collect());
        app.handle_action(Action::Bottom);
        assert_eq!(app.selected, 99);
        app.ensure_visible(30);
        assert!(app.selected < app.list_offset + 30);
        app.handle_action(Action::Top);
        assert_eq!(app.selected, 0);
        app.ensure_visible(30);
        assert_eq!(app.list_offset, 0);
    }

    #[test]
    fn detail_replay_delete_flows_produce_effects() {
        let mut app = App::new(None, store());
        app.on_batch(vec![summary(7, "GET", "/x", 200)]);

        let effects = app.handle_action(Action::OpenDetail);
        assert_eq!(effects, vec![Effect::FetchDetail(7)]);
        assert_eq!(app.screen, Screen::FlowDetail);
        assert!(app.detail_loading);

        app.handle_action(Action::CloseOverlay);
        assert_eq!(app.screen, Screen::FlowList);

        assert!(app.handle_action(Action::Replay).is_empty());
        assert!(app.pending_confirmation());
        assert_eq!(
            app.handle_action(Action::ConfirmYes),
            vec![Effect::Replay(7)]
        );

        assert!(app.handle_action(Action::Delete).is_empty());
        assert_eq!(
            app.handle_action(Action::ConfirmYes),
            vec![Effect::Delete(7)]
        );
        // Row leaves the local view immediately.
        assert!(app.view.is_empty());

        // Confirm-no clears without effects.
        app.on_batch(vec![summary(8, "GET", "/y", 200)]);
        app.handle_action(Action::Replay);
        assert!(app.handle_action(Action::ConfirmNo).is_empty());
        assert!(!app.pending_confirmation());
    }

    #[test]
    fn palette_save_load_and_attach() {
        let shared: Arc<Mutex<dyn SavedFilterStore>> =
            Arc::new(Mutex::new(InMemorySavedFilterStore::new()));
        let mut app = App::new(None, shared.clone());
        app.apply_filter("provider=anthropic");

        for ch in "save llm-errors".chars() {
            app.handle_action(Action::PaletteInput(ch));
        }
        app.handle_action(Action::OpenPalette); // re-open resets input
        for ch in ":save llm-errors".trim_start_matches(':').chars() {
            app.handle_action(Action::PaletteInput(ch));
        }
        let effects = app.handle_action(Action::PaletteCommit);
        assert!(effects.is_empty());
        assert_eq!(shared.lock().expect("lock").list().len(), 1);

        app.apply_filter("");
        for ch in "load llm-errors".chars() {
            app.handle_action(Action::PaletteInput(ch));
        }
        app.handle_action(Action::PaletteCommit);
        assert_eq!(app.filter_input, "provider=anthropic");

        for ch in "attach http://127.0.0.1:9000".chars() {
            app.handle_action(Action::PaletteInput(ch));
        }
        let effects = app.handle_action(Action::PaletteCommit);
        assert_eq!(
            effects,
            vec![Effect::AttachHttp(
                Url::parse("http://127.0.0.1:9000").expect("url")
            )]
        );
    }

    #[test]
    fn detail_toggles_and_body_scroll_clamp_at_zero() {
        let mut app = App::new(None, store());
        app.handle_action(Action::TogglePretty);
        assert!(!app.pretty_print);
        app.handle_action(Action::BodyScrollUp(1));
        assert_eq!(app.body_scroll, 0);
        // Without a loaded detail there is nothing to scroll.
        app.handle_action(Action::BodyScrollDown(10));
        assert_eq!(app.body_scroll, 0);
        app.handle_action(Action::ToggleRaw);
        assert!(app.show_raw);
    }

    #[test]
    fn body_scroll_clamps_to_content_minus_viewport() {
        let mut app = App::new(None, store());
        // 30-line JSON body; viewport of 10 rows.
        let text = (0..30)
            .map(|i| format!("\"k{i}\": {i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let detail_json = format!("{{{text}}}");
        app.set_detail(detail_fixture(1, &detail_json));

        // Pretty-printing expands the compact JSON to 32 rendered lines.
        assert_eq!(app.body_total_lines(), 32);
        app.note_body_viewport(10);
        assert!(app.body_scrollable());

        // Overscroll clamps so the last line stays reachable.
        for _ in 0..10 {
            app.handle_action(Action::BodyPageDown);
        }
        assert_eq!(app.body_scroll, 22, "clamped to content - viewport");
        app.handle_action(Action::BodyTop);
        assert_eq!(app.body_scroll, 0);
        app.handle_action(Action::BodyPageDown);
        assert_eq!(app.body_scroll, 5, "half the 10-row viewport");

        // Window arithmetic.
        assert_eq!(app.body_scroll_window(32, 10), (5, 15));
        app.handle_action(Action::BodyBottom);
        assert_eq!(app.body_scroll, 22);
        assert_eq!(app.body_scroll_window(32, 10), (22, 32));
        assert_eq!(app.body_scroll_window(3, 10), (0, 3), "short content");
        // Switching flows resets the offset.
        app.set_detail(detail_fixture(2, "{\"a\":1}"));
        assert_eq!(app.body_scroll, 0);
    }

    /// Builds a detail DTO whose response body is `text` (request empty).
    fn detail_fixture(seq: u64, text: &str) -> FlowDetailDto {
        let mut detail =
            FlowDetailDto::from_exchange(&exchange_for(seq), None, Some(text.as_bytes()));
        detail.request_body = crate::tui::feed::BodyViewDto::from_bytes(b"", None);
        detail
    }

    fn exchange_for(seq: u64) -> crate::types::CapturedExchange {
        crate::types::CapturedExchange {
            schema_version: crate::types::EXCHANGE_SCHEMA_VERSION,
            sequence: seq,
            started_at: "2026-08-22T00:00:00.000Z".to_string(),
            duration_ms: 1.0,
            request: crate::types::CapturedRequest {
                method: "GET".into(),
                path: "/x".into(),
                http_version: "1.1".into(),
                headers: crate::types::CapturedHeaders {
                    values: Default::default(),
                    redacted: Vec::new(),
                },
                body: crate::types::CapturedBody {
                    sha256: format!("{seq}-req"),
                    size: 0,
                    media_type: None,
                    content_encoding: None,
                    storage: crate::types::BodyStorage::InlineBase64 {
                        value: String::new(),
                    },
                },
            },
            response: crate::types::CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers: crate::types::CapturedHeaders {
                    values: Default::default(),
                    redacted: Vec::new(),
                },
                body: crate::types::CapturedBody {
                    sha256: format!("{seq}-res"),
                    size: 0,
                    media_type: Some("application/json".into()),
                    content_encoding: None,
                    storage: crate::types::BodyStorage::InlineBase64 {
                        value: String::new(),
                    },
                },
                stream: crate::types::StreamState {
                    kind: "buffered".into(),
                    completed: true,
                    client_aborted: false,
                    upstream_aborted: false,
                    terminal_marker: None,
                    error: None,
                },
            },
            failure: None,
            validation: None,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        }
    }

    #[test]
    fn ctrl_c_quits_from_any_state() {
        use crossterm::event::{KeyCode as K, KeyModifiers as M};
        let ctrl_c = |screen, editing| map_key_event(K::Char('c'), M::CONTROL, screen, editing);
        for (screen, editing) in [
            (Screen::FlowList, false),
            (Screen::FlowList, true),
            (Screen::FlowDetail, false),
            (Screen::Help, false),
            (Screen::Palette, true),
            (Screen::Palette, false),
        ] {
            assert_eq!(
                ctrl_c(screen, editing),
                vec![Action::Quit],
                "Ctrl+C must quit from {screen:?} (editing={editing})"
            );
        }
        // Plain `c` keeps its overlay-close meaning on the list.
        assert_eq!(
            map_key_event(K::Char('c'), M::NONE, Screen::FlowList, false),
            vec![Action::CloseOverlay]
        );
        let mut app = App::new(None, store());
        app.handle_action(Action::Quit);
        assert!(app.quit);
    }

    #[test]
    fn export_existing_file_requires_confirmation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("flows.har");
        std::fs::write(&path, b"old").expect("seed existing file");
        let mut app = App::new(None, store());

        // Existing target: modal state, no effect yet.
        let effects = app.handle_action(Action::ExportHar(path.clone()));
        assert!(effects.is_empty());
        assert_eq!(app.pending_export_path(), Some(path.as_path()));
        let status = app.status.clone().expect("status");
        assert!(status.contains("overwrite"), "{status}");

        // `n` cancels with a status message and clears the pending export.
        assert!(app.handle_action(Action::ConfirmNo).is_empty());
        assert!(app.pending_export_path().is_none());
        assert_eq!(app.status.as_deref(), Some("export cancelled"));

        // Re-request; `y` proceeds with the export effect.
        assert!(app
            .handle_action(Action::ExportHar(path.clone()))
            .is_empty());
        assert_eq!(
            app.handle_action(Action::ConfirmYes),
            vec![Effect::ExportHar { path: path.clone() }]
        );

        // Fresh targets export immediately without a prompt.
        let fresh = dir.path().join("fresh.har");
        assert_eq!(
            app.handle_action(Action::ExportHar(fresh.clone())),
            vec![Effect::ExportHar { path: fresh }]
        );
    }

    #[test]
    fn reconnect_refetch_dedupes_by_sequence() {
        let mut app = App::new(None, store());
        app.on_batch(vec![
            summary(1, "GET", "/a", 200),
            summary(2, "GET", "/b", 200),
        ]);
        // A post-reconnect refetch replays old rows alongside new ones.
        app.on_batch(vec![
            summary(1, "GET", "/a", 200),
            summary(2, "GET", "/b", 200),
            summary(3, "GET", "/c", 200),
        ]);
        assert_eq!(app.flows.len(), 3, "no duplicate ring entries");
        assert_eq!(app.view, vec![1, 2, 3]);
    }

    #[allow(dead_code)] // key-mapping table drift guard
    fn quit_sets_flag_via_mapped_key() {
        let mut app = App::new(None, store());
        let actions = map_key(
            crossterm::event::KeyCode::Char('q'),
            Screen::FlowList,
            false,
        );
        for action in actions {
            app.handle_action(action);
        }
        assert!(app.quit);
    }
}
