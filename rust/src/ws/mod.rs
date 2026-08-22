//! WebSocket upgrade detection and the bidirectional capture pump (W2).
//!
//! The pump is a strictly transparent relay: every frame observed on one leg
//! is recorded into a [`types::WsStream`] and forwarded UNMODIFIED to the
//! other leg. Capture observes; it never rewrites.
//!
//! Framing uses `tokio-tungstenite` over the already-upgraded IO in both
//! roles (`Role::Server` toward the client, `Role::Client` toward the
//! upstream), because both legs have completed their HTTP/1.1 handshake
//! before the pump starts. Known library trade-off (flagged to Main):
//! tungstenite automatically answers Ping frames on each leg with its own
//! Pong, so a client ping can be answered twice (once locally, once via the
//! relayed upstream pong). Observed frames are still relayed 1:1 and
//! recorded exactly once.
//!
//! Protocol violations (reserved opcodes, invalid UTF-8, oversized frames)
//! fail the leg: tungstenite cannot skip a desynced frame safely, so the
//! error is recorded on the [`WsPumpResult`] and the connection is torn
//! down. Capture limits (`max_messages`, `max_message_bytes`) are enforced
//! by the frame codec itself, which keeps memory bounded for hostile peers.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine;
use futures::sink::SinkExt;
use futures::stream::{SplitSink, SplitStream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::WebSocketStream;

use crate::types::{WsDirection, WsMessage, WsOpcode, WsStream};

/// Per-message capture ceiling; mirrors the body sink inline ceiling. Frames
/// larger than this fail the leg (the codec cannot resynchronize past them).
pub const DEFAULT_WS_MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// Recording bound per stream: past this many messages capture records an
/// error and stops recording while the relay keeps running.
pub const MAX_WS_MESSAGES_PER_STREAM: u64 = 100_000;

const MAX_CLOSE_REASON_BYTES: usize = 123;

/// True iff the request carries a well-formed RFC 6455 HTTP/1.1 websocket
/// upgrade: `Connection` contains the token `upgrade`, `Upgrade` is
/// `websocket`, a non-empty `Sec-WebSocket-Key` is present, and
/// `Sec-WebSocket-Version` is 13.
pub fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    let header_tokens = |name: http::HeaderName| -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(|token| token.trim().to_ascii_lowercase())
            .collect()
    };
    if !header_tokens(http::header::CONNECTION)
        .iter()
        .any(|token| token == "upgrade")
    {
        return false;
    }
    if !header_tokens(http::header::UPGRADE)
        .iter()
        .any(|token| token == "websocket")
    {
        return false;
    }
    let key_ok = headers
        .get(http::header::SEC_WEBSOCKET_KEY)
        .map(|key| !key.is_empty())
        .unwrap_or(false);
    if !key_ok {
        return false;
    }
    headers
        .get(http::header::SEC_WEBSOCKET_VERSION)
        .map(|version| version.to_str().unwrap_or("").trim() == "13")
        .unwrap_or(false)
}

/// Derive the `Sec-WebSocket-Accept` value for a client's
/// `Sec-WebSocket-Key` (RFC 6455 §4.2.2). Used when answering an upgrade
/// locally after the upstream handshake was forwarded verbatim.
pub fn derive_accept_key(request_key: &str) -> String {
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(request_key.as_bytes())
}

/// Limits carried alongside one captured websocket session.
#[derive(Debug, Clone)]
pub struct WsCaptureMeta {
    /// Negotiated subprotocol mirrored from the upstream 101 response.
    pub protocol: Option<String>,
    pub max_messages: u64,
    pub max_message_bytes: usize,
}

impl Default for WsCaptureMeta {
    fn default() -> Self {
        Self {
            protocol: None,
            max_messages: MAX_WS_MESSAGES_PER_STREAM,
            max_message_bytes: DEFAULT_WS_MAX_MESSAGE_BYTES,
        }
    }
}

/// Outcome of one pumped websocket session.
#[derive(Debug, Clone)]
pub struct WsPumpResult {
    pub stream: WsStream,
    /// The client leg ended without a close handshake.
    pub client_aborted: bool,
    /// The upstream leg ended without a close handshake.
    pub upstream_aborted: bool,
    /// Protocol/limit failure description; never contains payload bytes.
    pub error: Option<String>,
}

/// Convert the upgraded IO of both legs into WebSocket streams (server role
/// toward the client, client role toward the upstream) and run the pump to
/// completion.
pub async fn pump_ws<ClientIo, UpstreamIo>(
    client_io: ClientIo,
    upstream_io: UpstreamIo,
    meta: WsCaptureMeta,
) -> WsPumpResult
where
    ClientIo: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    UpstreamIo: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = WebSocketConfig {
        max_message_size: Some(meta.max_message_bytes),
        ..WebSocketConfig::default()
    };
    let client = WebSocketStream::from_raw_socket(client_io, Role::Server, Some(config)).await;
    let upstream = WebSocketStream::from_raw_socket(upstream_io, Role::Client, Some(config)).await;
    pump_ws_streams(client, upstream, meta).await
}

/// Pump over an already-negotiated stream pair (e.g. produced by
/// `from_raw_socket` or a full tungstenite handshake).
pub async fn pump_ws_streams<ClientIo, UpstreamIo>(
    client: WebSocketStream<ClientIo>,
    upstream: WebSocketStream<UpstreamIo>,
    meta: WsCaptureMeta,
) -> WsPumpResult
where
    ClientIo: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    UpstreamIo: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // offset_ms is anchored here: both legs are established, i.e. the 101
    // handshake has completed on both sides.
    let recorder = Arc::new(Mutex::new(Recorder::new(meta)));
    let (client_sink, client_stream) = client.split();
    let (upstream_sink, upstream_stream) = upstream.split();

    let client_leg = tokio::spawn(relay_leg(
        client_stream,
        upstream_sink,
        WsDirection::ClientToServer,
        recorder.clone(),
    ));
    let upstream_leg = tokio::spawn(relay_leg(
        upstream_stream,
        client_sink,
        WsDirection::ServerToClient,
        recorder.clone(),
    ));
    let _ = tokio::join!(client_leg, upstream_leg);

    let result = recorder.lock().expect("ws recorder lock").finish();
    result
}

/// One direction of the pump: observe frames from `source`, record them,
/// forward verbatim into `destination`. Ends when the source ends; a clean
/// Close frame stops the loop right after being forwarded.
async fn relay_leg<SourceIo, DestinationIo>(
    mut source: SplitStream<WebSocketStream<SourceIo>>,
    mut destination: SplitSink<WebSocketStream<DestinationIo>, Message>,
    direction: WsDirection,
    recorder: Arc<Mutex<Recorder>>,
) where
    SourceIo: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    DestinationIo: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(item) = source.next().await {
        let message = match item {
            Ok(message) => message,
            Err(err) => {
                recorder
                    .lock()
                    .expect("ws recorder lock")
                    .read_failed(direction, &err);
                return;
            }
        };
        let is_close = matches!(message, Message::Close(_));
        recorder
            .lock()
            .expect("ws recorder lock")
            .record(direction, &message);
        if destination.send(message).await.is_err() {
            // The peer is gone; only interesting before any close handshake.
            recorder
                .lock()
                .expect("ws recorder lock")
                .peer_gone(direction);
            return;
        }
        if is_close {
            return;
        }
    }
}

struct Recorder {
    meta: WsCaptureMeta,
    started: Instant,
    messages: Vec<WsMessage>,
    close_code: Option<u16>,
    close_reason: Option<String>,
    completed: bool,
    error: Option<String>,
    client_aborted: bool,
    upstream_aborted: bool,
}

impl Recorder {
    fn new(meta: WsCaptureMeta) -> Self {
        Self {
            meta,
            started: Instant::now(),
            messages: Vec::new(),
            close_code: None,
            close_reason: None,
            completed: false,
            error: None,
            client_aborted: false,
            upstream_aborted: false,
        }
    }

    fn record(&mut self, direction: WsDirection, message: &Message) {
        if self.messages.len() as u64 >= self.meta.max_messages {
            self.set_error_once(format!(
                "websocket stream exceeded {} messages; capture stopped, relay continued",
                self.meta.max_messages
            ));
            return;
        }
        match convert_message(direction, self.started.elapsed(), message) {
            Ok(message) => self.messages.push(message),
            Err(problem) => self.set_error_once(problem),
        }
        if let Message::Close(frame) = message {
            // First close frame wins; the reply from the other side does not
            // overwrite it.
            if self.close_code.is_none() {
                if let Some(frame) = frame {
                    self.close_code = Some(u16::from(frame.code));
                    self.close_reason = Some(truncate_utf8(
                        frame.reason.as_bytes(),
                        MAX_CLOSE_REASON_BYTES,
                    ));
                }
            }
            self.completed = true;
        }
    }

    fn read_failed(&mut self, direction: WsDirection, err: &WsError) {
        match direction {
            WsDirection::ClientToServer => self.client_aborted = true,
            WsDirection::ServerToClient => self.upstream_aborted = true,
        }
        if !self.completed {
            self.set_error_once(format!("websocket leg failed: {err}"));
        }
    }

    fn peer_gone(&mut self, direction: WsDirection) {
        match direction {
            // Forwarding toward the upstream failing means the client's peer
            // vanished; forwarding toward the client failing means the client
            // hung up.
            WsDirection::ClientToServer => self.upstream_aborted = true,
            WsDirection::ServerToClient => self.client_aborted = true,
        }
        if !self.completed {
            self.set_error_once("websocket peer closed mid-stream".to_string());
        }
    }

    fn set_error_once(&mut self, problem: String) {
        if self.error.is_none() {
            self.error = Some(problem);
        }
    }

    fn finish(&self) -> WsPumpResult {
        WsPumpResult {
            stream: WsStream {
                protocol: self.meta.protocol.clone(),
                messages: self.messages.clone(),
                completed: self.completed,
                close_code: self.close_code,
                close_reason: self.close_reason.clone(),
            },
            client_aborted: self.client_aborted,
            upstream_aborted: self.upstream_aborted,
            error: self.error.clone(),
        }
    }
}

fn truncate_utf8(bytes: &[u8], max_bytes: usize) -> String {
    if bytes.len() <= max_bytes {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut end = max_bytes;
    while end > 0 && std::str::from_utf8(&bytes[..end]).is_err() {
        end -= 1;
    }
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn convert_message(
    direction: WsDirection,
    elapsed: std::time::Duration,
    message: &Message,
) -> std::result::Result<WsMessage, String> {
    let offset_ms = elapsed.as_secs_f64() * 1000.0;
    let build =
        |opcode: WsOpcode, text: Option<String>, data: Option<Vec<u8>>, size: u64| WsMessage {
            direction,
            opcode,
            text,
            data_base64: data.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
            size,
            offset_ms,
        };
    Ok(match message {
        Message::Text(text) => build(
            WsOpcode::Text,
            Some(text.as_str().to_string()),
            None,
            text.len() as u64,
        ),
        Message::Binary(data) => build(
            WsOpcode::Binary,
            None,
            Some(data.clone()),
            data.len() as u64,
        ),
        Message::Ping(payload) => build(
            WsOpcode::Ping,
            None,
            Some(payload.clone()),
            payload.len() as u64,
        ),
        Message::Pong(payload) => build(
            WsOpcode::Pong,
            None,
            Some(payload.clone()),
            payload.len() as u64,
        ),
        Message::Close(frame) => {
            let reason = frame
                .as_ref()
                .map(|frame| frame.reason.to_string())
                .unwrap_or_default();
            build(
                WsOpcode::Close,
                (!reason.is_empty()).then_some(reason.clone()),
                None,
                (2 + reason.len()) as u64,
            )
        }
        Message::Frame(_) => {
            return Err("reserved websocket opcode observed; connection torn down".to_string())
        }
    })
}
