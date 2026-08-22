//! Incremental SSE analysis over a *copy* of the response stream. The stream
//! delivered to the client is never rewritten; this only observes event
//! boundaries to find protocol-aware terminal markers.

#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Terminal markers recognized across provider streaming protocols.
pub fn terminal_marker_for(event: &SseEvent) -> Option<String> {
    // OpenAI Chat Completions: `data: [DONE]`
    if event.data.trim() == "[DONE]" {
        return Some("[DONE]".to_string());
    }
    let name = event.event.as_deref()?;
    // Anthropic Messages: `event: message_stop`; error event terminates too.
    if name == "message_stop" || name == "error" {
        return Some(name.to_string());
    }
    // OpenAI Responses API: `event: response.completed` / `response.failed` /
    // `response.incomplete`
    if matches!(
        name,
        "response.completed" | "response.failed" | "response.incomplete"
    ) {
        return Some(name.to_string());
    }
    None
}

/// Incremental SSE parser. Feed raw bytes; complete events are surfaced as
/// they are terminated by a blank line. Handles `\n`, `\r\n`, and `\r`
/// separators and multi-line data fields per the SSE spec.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: String,
    events: Vec<SseEvent>,
    terminal: Option<String>,
    decoder: Utf8StreamDecoder,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Streaming UTF-8 decode: a multi-byte sequence split across chunks
    /// must not decode to U+FFFD halves. Invalid bytes become U+FFFD (the
    /// TS TextDecoder default).
    pub fn feed(&mut self, chunk: &[u8]) {
        let decoded = self.decoder.feed(chunk);
        self.buffer.push_str(&decoded);
        self.drain(false);
    }

    /// Flush any pending partial decode and emit the trailing block, if any.
    pub fn end(&mut self) {
        let tail = self.decoder.finish();
        self.buffer.push_str(&tail);
        self.drain(true);
    }

    pub fn parsed_events(&self) -> &[SseEvent] {
        &self.events
    }

    pub fn terminal_marker(&self) -> Option<&str> {
        self.terminal.as_deref()
    }

    fn drain(&mut self, flush: bool) {
        // A CRLF pair split across chunks must not be treated as a bare CR
        // separator: when not flushing, hold back a trailing CR until the
        // next chunk reveals whether an LF follows.
        let mut working = std::mem::take(&mut self.buffer);
        let mut held_cr = String::new();
        if !flush && working.ends_with('\r') {
            working.pop();
            held_cr.push('\r');
        }
        // Normalize separators for boundary detection only (analysis copy).
        let normalized = working.replace("\r\n", "\n").replace('\r', "\n");
        let parts: Vec<&str> = normalized.split("\n\n").collect();
        let complete: Vec<&str> = if flush {
            parts.clone()
        } else {
            parts[..parts.len() - 1].to_vec()
        };
        self.buffer = if flush {
            String::new()
        } else {
            format!("{}{}", parts.last().copied().unwrap_or(""), held_cr)
        };
        for block in complete {
            if block.trim().is_empty() {
                continue;
            }
            if let Some(event) = parse_event_block(block) {
                if let Some(marker) = terminal_marker_for(&event) {
                    if self.terminal.is_none() {
                        self.terminal = Some(marker);
                    }
                }
                self.events.push(event);
            }
        }
    }
}

/// Incremental UTF-8 decoder: buffers incomplete trailing sequences across
/// `feed` calls and flushes them as replacement characters on `end`.
#[derive(Default, Debug)]
pub struct Utf8StreamDecoder {
    pending: Vec<u8>,
}

impl Utf8StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) -> String {
        let mut bytes = std::mem::take(&mut self.pending);
        bytes.extend_from_slice(chunk);
        let mut out = String::new();
        let mut consumed = 0;
        while consumed < bytes.len() {
            match std::str::from_utf8(&bytes[consumed..]) {
                Ok(text) => {
                    out.push_str(text);
                    consumed = bytes.len();
                    break;
                }
                Err(e) => {
                    let valid_up_to = e.valid_up_to();
                    if valid_up_to > 0 {
                        out.push_str(&String::from_utf8_lossy(
                            &bytes[consumed..consumed + valid_up_to],
                        ));
                    }
                    consumed += valid_up_to;
                    match e.error_len() {
                        // Incomplete sequence at end: buffer and wait.
                        None => break,
                        // Genuinely invalid byte: replacement char, skip one.
                        Some(bad) => {
                            out.push('\u{FFFD}');
                            consumed += bad;
                        }
                    }
                }
            }
        }
        self.pending = bytes[consumed..].to_vec();
        out
    }

    pub fn finish(&mut self) -> String {
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            String::new()
        } else {
            // Incomplete trailing sequence: replacement character.
            "\u{FFFD}".to_string()
        }
    }
}

fn parse_event_block(block: &str) -> Option<SseEvent> {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<String> = vec![];
    let mut saw_field = false;
    for line in block.split('\n') {
        if let Some(stripped) = line.strip_prefix(':') {
            let _ = stripped;
            continue; // comment
        }
        let (field, value) = match line.find(':') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line, ""),
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => {
                event_name = Some(value.to_string());
                saw_field = true;
            }
            "data" => {
                data_lines.push(value.to_string());
                saw_field = true;
            }
            "id" | "retry" => {
                saw_field = true;
            }
            _ => {}
        }
    }
    if !saw_field {
        return None;
    }
    Some(SseEvent {
        event: event_name,
        data: data_lines.join("\n"),
    })
}

/// Parse a complete SSE body into events (used by replay comparison).
pub fn parse_sse_body(body: &[u8]) -> Vec<SseEvent> {
    let mut decoder = Utf8StreamDecoder::new();
    let text = decoder.feed(body) + &decoder.finish();
    let mut parser = SseParser::new();
    parser.buffer = text;
    parser.end();
    parser.parsed_events().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_events_and_multiline_data() {
        let events = parse_sse_body(
            b"event: message_start\ndata: {\"a\":1}\n\ndata: line1\ndata: line2\n\n",
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("message_start"));
        assert_eq!(events[0].data, "{\"a\":1}");
        assert_eq!(events[1].event, None);
        assert_eq!(events[1].data, "line1\nline2");
    }

    #[test]
    fn handles_crlf_and_bare_cr() {
        let events = parse_sse_body(b"data: a\r\n\r\ndata: b\r\r");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "a");
        assert_eq!(events[1].data, "b");
    }

    #[test]
    fn comments_and_unknown_fields_ignored() {
        let events = parse_sse_body(b": keepalive\nid: 7\nretry: 100\n\n: ping\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, None);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn terminal_markers() {
        let done = parse_sse_body(b"data: [DONE]\n\n");
        let mut parser = SseParser::new();
        parser.feed(b"data: [DONE]\n\n");
        parser.end();
        assert_eq!(parser.terminal_marker(), Some("[DONE]"));
        assert_eq!(done.len(), 1);

        let mut p2 = SseParser::new();
        p2.feed(b"event: message_stop\ndata: {}\n\n");
        p2.end();
        assert_eq!(p2.terminal_marker(), Some("message_stop"));

        let mut p3 = SseParser::new();
        p3.feed(b"event: response.completed\ndata: {}\n\n");
        p3.end();
        assert_eq!(p3.terminal_marker(), Some("response.completed"));

        let mut p4 = SseParser::new();
        p4.feed(b"event: content_block_delta\ndata: {}\n\n");
        p4.end();
        assert_eq!(p4.terminal_marker(), None);
    }

    #[test]
    fn terminal_marker_only_first_wins() {
        let mut p = SseParser::new();
        p.feed(b"event: error\ndata: x\n\nevent: message_stop\ndata: y\n\n");
        p.end();
        assert_eq!(p.terminal_marker(), Some("error"));
        assert_eq!(p.parsed_events().len(), 2);
    }

    #[test]
    fn utf8_split_across_chunks_not_replaced() {
        let mut p = SseParser::new();
        let full = "data: héllo\n\n".as_bytes();
        let (a, b) = full.split_at(9); // split inside the é sequence
        p.feed(a);
        p.feed(b);
        p.end();
        assert_eq!(p.parsed_events()[0].data, "héllo");
    }

    #[test]
    fn crlf_split_across_chunks() {
        let mut p = SseParser::new();
        p.feed(b"data: a\r");
        p.feed(b"\n\r\n");
        p.end();
        assert_eq!(p.parsed_events().len(), 1);
        assert_eq!(p.parsed_events()[0].data, "a");
    }

    #[test]
    fn trailing_partial_block_flushed_on_end() {
        let mut p = SseParser::new();
        p.feed(b"data: final");
        p.end();
        assert_eq!(p.parsed_events().len(), 1);
        assert_eq!(p.parsed_events()[0].data, "final");
    }
}
