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
    BodyScrollDown,
    BodyScrollUp,
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
    /// incremental filter pass over just the new rows.
    pub fn on_batch(&mut self, batch: Vec<FlowSummaryDto>) {
        let mut newly_matched: Vec<u64> = Vec::with_capacity(batch.len());
        for summary in batch {
            let seq = summary.sequence;
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
                    None => Vec::new(),
                }
            }
            Action::ConfirmNo => {
                self.pending = None;
                self.status = None;
                Vec::new()
            }
            Action::ExportHar(path) => vec![Effect::ExportHar { path }],
            Action::TogglePretty => {
                self.pretty_print = !self.pretty_print;
                Vec::new()
            }
            Action::ToggleRaw => {
                self.show_raw = !self.show_raw;
                Vec::new()
            }
            Action::BodyScrollDown => {
                self.body_scroll = self.body_scroll.saturating_add(10);
                Vec::new()
            }
            Action::BodyScrollUp => {
                self.body_scroll = self.body_scroll.saturating_sub(10);
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
    use crossterm::event::KeyCode as K;
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
        app.handle_action(Action::BodyScrollUp);
        assert_eq!(app.body_scroll, 0);
        app.handle_action(Action::BodyScrollDown);
        assert_eq!(app.body_scroll, 10);
        app.handle_action(Action::ToggleRaw);
        assert!(app.show_raw);
    }

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
