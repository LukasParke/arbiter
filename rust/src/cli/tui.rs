//! `arbiter tui` — attach to a running arbiter instance or spawn an embedded
//! capture session, then drive the ratatui flow explorer.
//!
//! Attach mode polls the running instance's flows API (see
//! `server::flows_api`); embedded mode owns a real capture session and
//! subscribes its watch channel. The terminal is restored on every exit
//! path, including panics.

use std::io::{self, Stdout};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use crossterm::event::{Event as CtEvent, KeyEvent, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use url::Url;

use crate::capture::session::{start_capture_session, CaptureSessionOptions};
use crate::error::Result;
use crate::tui::app::{App, Effect, Screen};
use crate::tui::feed::{EmbeddedFlowFeed, FlowFeed, FlowFeedExt, HttpFlowFeed};
use crate::tui::filter::SavedFilterStore;
use crate::types::CaptureMode;

const DEFAULT_TARGET: &str = "http://127.0.0.1:8080";

/// `arbiter tui [--attach URL] | [--target URL --port N --exact]`
#[derive(Debug, Parser)]
pub struct TuiCommand {
    /// Attach to an already-running arbiter instance at this base URL,
    /// e.g. `arbiter tui --attach http://127.0.0.1:9000`.
    #[arg(long, value_name = "URL")]
    pub attach: Option<Url>,

    /// Upstream target for a new embedded capture session,
    /// e.g. `--target https://api.anthropic.com`. Defaults to
    /// `http://127.0.0.1:8080` when omitted.
    #[arg(long, value_name = "URL")]
    pub target: Option<Url>,

    /// Listen port for the embedded capture session; 0 (default) picks an
    /// ephemeral port.
    #[arg(short = 'p', long, default_value_t = 0, value_name = "N")]
    pub port: u16,

    /// Run the embedded capture in exact mode (fail-closed capture).
    #[arg(long)]
    pub exact: bool,

    /// Initial filter expression applied at startup,
    /// e.g. `--filter 'provider=anthropic status>=400'`.
    #[arg(short = 'f', long)]
    pub filter: Option<String>,
}

/// Runs the command (blocking; creates the tokio runtime like other CLI
/// commands). Returns the process exit code.
pub fn run(args: &TuiCommand) -> i32 {
    let runtime = tokio::runtime::Runtime::new().expect("start tokio runtime");
    match runtime.block_on(run_async(args)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("  help: check --attach/--target values; see `arbiter tui --help`");
            1
        }
    }
}

async fn run_async(args: &TuiCommand) -> Result<()> {
    let saved_filters: Arc<Mutex<dyn SavedFilterStore>> =
        Arc::new(Mutex::new(crate::tui::filter::FileSavedFilterStore::new(
            crate::tui::filter::FileSavedFilterStore::default_path(),
        )));
    let mut app = App::new(args.filter.as_deref(), saved_filters);

    let mut embedded_listen_url: Option<String> = None;
    let feed = if let Some(base) = args.attach.clone() {
        probe_attach(&base).await?;
        FlowFeed::Http(HttpFlowFeed::new(base))
    } else {
        let target = args
            .target
            .clone()
            .unwrap_or_else(|| Url::parse(DEFAULT_TARGET).expect("static default target"));
        let options = CaptureSessionOptions {
            target: target.clone(),
            listen_port: args.port,
            mode: if args.exact {
                CaptureMode::Exact
            } else {
                CaptureMode::Observe
            },
            ..CaptureSessionOptions::default()
        };
        let session = start_capture_session(options).await?;
        embedded_listen_url = Some(session.url().to_string());
        let tick = session.subscribe_flows();
        // Replays go against the configured target, not the listen address.
        FlowFeed::Embedded(EmbeddedFlowFeed::new(Arc::new(session), target, tick))
    };

    // T3: advertise where to send traffic from first paint onward.
    if let crate::tui::feed::FlowFeed::Embedded(_) = &feed {
        if let Some(url) = embedded_listen_url.as_ref() {
            app.set_embedded(
                url.clone(),
                args.target.as_ref().map(Url::to_string).unwrap_or_default(),
            );
        }
    }

    run_app(app, feed).await
}

async fn probe_attach(base: &Url) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| crate::error::Error::other(format!("http client: {e}")))?;
    let url = base
        .join("/__flows?limit=1")
        .map_err(|e| crate::error::Error::other(format!("invalid attach URL: {e}")))?;
    let response = client.get(url).send().await.map_err(|e| {
        crate::error::Error::other(format!("no arbiter instance reachable at {base} ({e})"))
    })?;
    if !response.status().is_success() {
        return Err(crate::error::Error::other(format!(
            "{base} answered HTTP {} — is that an arbiter docs port?",
            response.status().as_u16()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Terminal lifecycle
// ---------------------------------------------------------------------------

/// Restores the terminal on drop (normal exit, error unwind, or panic).
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        crossterm::execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        Ok(Self {
            terminal: Terminal::new(backend)?,
        })
    }

    fn draw(&mut self, app: &mut App) -> io::Result<()> {
        self.terminal.draw(|f| {
            match app.screen {
                Screen::FlowDetail => crate::tui::ui::detail::draw_detail(f, app),
                _ => crate::tui::ui::flows::draw_flows(f, app),
            }
            crate::tui::ui::detail::draw_overlay(f, app);
        })?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.terminal.clear();
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

const RENDER_TICK: Duration = Duration::from_millis(100);

async fn run_app(mut app: App, mut feed: FlowFeed) -> Result<()> {
    // Key events come from a dedicated blocking thread so the async loop
    // never blocks on crossterm's poll (perf bar).
    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || loop {
        match crossterm::event::poll(RENDER_TICK) {
            Ok(true) => match crossterm::event::read() {
                Ok(CtEvent::Key(
                    event @ KeyEvent {
                        kind: KeyEventKind::Press | KeyEventKind::Repeat,
                        ..
                    },
                )) => {
                    if key_tx.send(event).is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            },
            Ok(false) => {}
            Err(_) => return,
        }
    });

    let mut guard = TerminalGuard::new().map_err(|e| crate::error::Error::Io {
        context: "enter TUI mode".to_string(),
        source: e,
    })?;

    let mut feed_tick = tokio::time::interval(feed.poll_interval());
    feed_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skeleton first paint before any fetch (<150 ms bar).
    draw_frame(&mut guard, &mut app)?;

    loop {
        tokio::select! {
            maybe_event = key_rx.recv() => {
                let Some(event) = maybe_event else { break };
                let editing = matches!(app.screen, Screen::Palette) || app.filter_editing;
                for action in crate::tui::app::map_key_event(event.code, event.modifiers, app.screen, editing) {
                    for effect in app.handle_action(action) {
                        execute_effect(&mut app, &feed, effect).await;
                    }
                }
            }
            _ = feed_tick.tick() => {
                // T4: surface attached-instance reachability.
                app.set_disconnected_since(feed.disconnected_since());
                if !app.filter_editing && app.screen != Screen::Palette {
                    let batch = feed.next_batch().await;
                    if !batch.is_empty() {
                        app.on_batch(batch);
                    }
                    if let Some(status) = feed.status_line() {
                        app.set_status(status);
                    }
                }
            }
        }
        draw_frame(&mut guard, &mut app)?;
        if app.quit {
            break;
        }
    }
    Ok(())
}

fn draw_frame(guard: &mut TerminalGuard, app: &mut App) -> Result<()> {
    guard.draw(app).map_err(|e| crate::error::Error::Io {
        context: "render TUI frame".to_string(),
        source: e,
    })
}

async fn execute_effect(app: &mut App, feed: &FlowFeed, effect: Effect) {
    match effect {
        Effect::FetchDetail(seq) => match feed.flow_detail(seq).await {
            Some(detail) => app.set_detail(detail),
            None => app.detail_fetch_missing(),
        },
        Effect::Delete(seq) => {
            feed.delete(seq).await;
            if let Some(status) = feed.status_line() {
                app.set_status(status);
            }
        }
        Effect::Replay(seq) => {
            feed.replay(seq).await;
            if let Some(status) = feed.status_line() {
                app.set_status(status);
            }
        }
        Effect::ExportHar { path } => match feed.export_har(&path).await {
            Ok(count) => app.set_status(format!("exported {count} flows to {}", path.display())),
            Err(e) => app.set_status(format!("error: HAR export failed\n  help: {e}")),
        },
        // Runtime re-attachment is applied by restarting `arbiter tui`; the
        // palette surfaces it as guidance instead of tearing down mid-run.
        Effect::AttachHttp(url) => {
            app.set_status(format!("attach requested: restart with --attach {url}"))
        }
    }
}
