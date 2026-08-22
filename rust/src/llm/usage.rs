//! Usage-token and stop-reason extraction per provider dialect (W4).
//!
//! Non-streaming JSON bodies map provider fields directly; streaming bodies
//! are parsed with [`crate::sse::parse_sse_body`] (or line-split NDJSON for
//! Ollama) and folded with a **last non-zero value wins** rule so cumulative
//! or trailing usage chunks converge on the final totals. Usage is never
//! synthesized: if the wire never carried token counts, extraction yields
//! `None`.

use serde_json::Value;

use crate::llm::provider::Provider;
use crate::sse::{parse_sse_body, SseEvent};
use serde::{Deserialize, Serialize};

/// Token counts extracted from one exchange's response half.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

/// Usage plus terminal stop reason extracted from one response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extracted {
    pub usage: Option<Usage>,
    pub stop_reason: Option<String>,
}

/// Entry point: dispatch on media type, with content sniffing fallbacks.
/// Handles JSON (`application/json`), SSE (`text/event-stream`), and Ollama
/// NDJSON (`application/x-ndjson` / `application/xl-ndjson`).
pub fn extract(provider: Provider, media_type: Option<&str>, bytes: &[u8]) -> Extracted {
    let mime = media_type.unwrap_or("").to_ascii_lowercase();
    if mime.contains("event-stream") {
        return extract_from_sse(provider, bytes);
    }
    if mime.contains("ndjson") {
        return extract_from_ndjson(provider, bytes);
    }
    // Content sniffing for missing/lying media types.
    let trimmed = trim_leading_ws(bytes);
    if trimmed.starts_with(b"data:") || trimmed.starts_with(b"event:") {
        return extract_from_sse(provider, bytes);
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(_) if mime.contains("jsonl") => {
            // JSONL-typed bodies fold line-wise even when single-line.
            extract_from_ndjson(provider, bytes)
        }
        Ok(value) => from_json(provider, &value),
        Err(_) => {
            // Try NDJSON (multiple JSON objects, newline separated) before
            // giving up.
            if bytes.iter().filter(|b| **b == b'\n').count() > 0
                && bytes
                    .split(|b| *b == b'\n')
                    .filter(|l| !l.iter().all(|b| b.is_ascii_whitespace()))
                    .all(|line| serde_json::from_slice::<Value>(line).is_ok())
            {
                extract_from_ndjson(provider, bytes)
            } else {
                Extracted::default()
            }
        }
    }
}

fn trim_leading_ws(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Non-streaming JSON extraction.
pub fn from_json(provider: Provider, value: &Value) -> Extracted {
    let mut out = Extracted::default();
    match provider {
        Provider::Anthropic => {
            if let Some(usage) = value.get("usage") {
                let prompt = u_field(usage, "input_tokens");
                let completion = u_field(usage, "output_tokens");
                out.usage = Some(complete_total(Usage {
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    total_tokens: u_field(usage, "total_tokens"),
                }));
            }
            out.stop_reason = s_field(value, "stop_reason");
        }
        Provider::Google => {
            if let Some(meta) = value.get("usageMetadata") {
                out.usage = Some(Usage {
                    prompt_tokens: u_field(meta, "promptTokenCount"),
                    completion_tokens: u_field(meta, "candidatesTokenCount"),
                    total_tokens: u_field(meta, "totalTokenCount"),
                });
            }
            out.stop_reason = value
                .get("candidates")
                .and_then(|c| c.get(0))
                .and_then(|c| s_field(c, "finishReason"));
        }
        Provider::Ollama => {
            let prompt = u_field(value, "prompt_eval_count");
            let completion = u_field(value, "eval_count");
            out.usage = Some(complete_total(Usage {
                prompt_tokens: prompt,
                completion_tokens: completion,
                total_tokens: None,
            }));
            out.stop_reason = s_field(value, "done_reason");
        }
        // OpenAI family: openai, xai, mistral, openrouter, azure-openai.
        _ => {
            if let Some(usage) = value.get("usage") {
                out.usage = Some(Usage {
                    prompt_tokens: u_field(usage, "prompt_tokens"),
                    completion_tokens: u_field(usage, "completion_tokens"),
                    total_tokens: u_field(usage, "total_tokens"),
                });
            }
            out.stop_reason = value
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| s_field(c, "finish_reason"));
        }
    }
    out.normalize()
}

/// Streaming SSE extraction over ordered events.
pub fn extract_from_sse(provider: Provider, body: &[u8]) -> Extracted {
    extract_from_events(provider, &parse_sse_body(body))
}

/// Streaming extraction over pre-parsed events (unit-test friendly).
pub fn extract_from_events(provider: Provider, events: &[SseEvent]) -> Extracted {
    let mut out = Extracted::default();
    for event in events {
        if event.data.trim() == "[DONE]" {
            continue;
        }
        let Ok(data) = serde_json::from_str::<Value>(&event.data) else {
            continue;
        };
        fold_event(provider, &data, &mut out);
    }
    out.normalize()
}

/// Ollama-style NDJSON streaming: each line is a full JSON status object.
pub fn extract_from_ndjson(provider: Provider, body: &[u8]) -> Extracted {
    let mut out = Extracted::default();
    for line in body.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let Ok(data) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        fold_event(provider, &data, &mut out);
    }
    out.normalize()
}

/// Fold one streaming chunk into the accumulator (last non-zero wins).
fn fold_event(provider: Provider, data: &Value, out: &mut Extracted) {
    match provider {
        Provider::Anthropic => {
            // message_start: {"message":{"usage":{"input_tokens":N}}}
            if let Some(input) = data
                .get("message")
                .and_then(|m| m.get("usage"))
                .and_then(|u| u_field(u, "input_tokens"))
            {
                out.usage.get_or_insert_with(Usage::default).prompt_tokens = Some(input);
            }
            // message_delta: {"usage":{"output_tokens":N},"delta":{"stop_reason":...}}
            if let Some(usage) = data.get("usage") {
                let usage_slot = out.usage.get_or_insert_with(Usage::default);
                if nz(u_field(usage, "output_tokens")) {
                    usage_slot.completion_tokens = u_field(usage, "output_tokens");
                }
                if nz(u_field(usage, "input_tokens")) {
                    usage_slot.prompt_tokens = u_field(usage, "input_tokens");
                }
            }
            if let Some(reason) = data
                .get("delta")
                .and_then(|d| s_field(d, "stop_reason"))
                .or_else(|| s_field(data, "stop_reason"))
            {
                out.stop_reason = Some(reason);
            }
        }
        Provider::Google => {
            if let Some(meta) = data.get("usageMetadata") {
                let slot = out.usage.get_or_insert_with(Usage::default);
                if nz(u_field(meta, "promptTokenCount")) {
                    slot.prompt_tokens = u_field(meta, "promptTokenCount");
                }
                if nz(u_field(meta, "candidatesTokenCount")) {
                    slot.completion_tokens = u_field(meta, "candidatesTokenCount");
                }
                if nz(u_field(meta, "totalTokenCount")) {
                    slot.total_tokens = u_field(meta, "totalTokenCount");
                }
            }
            if let Some(reason) = data
                .get("candidates")
                .and_then(|c| c.get(0))
                .and_then(|c| s_field(c, "finishReason"))
            {
                out.stop_reason = Some(reason);
            }
        }
        Provider::Ollama => {
            let slot = out.usage.get_or_insert_with(Usage::default);
            if nz(u_field(data, "prompt_eval_count")) {
                slot.prompt_tokens = u_field(data, "prompt_eval_count");
            }
            if nz(u_field(data, "eval_count")) {
                slot.completion_tokens = u_field(data, "eval_count");
            }
            if let Some(reason) = s_field(data, "done_reason") {
                out.stop_reason = Some(reason);
            }
        }
        // OpenAI family: usage rides the final chunk only when the client
        // sent stream_options.include_usage; finish_reason rides every chunk.
        _ => {
            if let Some(usage) = data.get("usage") {
                let slot = out.usage.get_or_insert_with(Usage::default);
                if nz(u_field(usage, "prompt_tokens")) {
                    slot.prompt_tokens = u_field(usage, "prompt_tokens");
                }
                if nz(u_field(usage, "completion_tokens")) {
                    slot.completion_tokens = u_field(usage, "completion_tokens");
                }
                if nz(u_field(usage, "total_tokens")) {
                    slot.total_tokens = u_field(usage, "total_tokens");
                }
            }
            if let Some(reason) = data
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| s_field(c, "finish_reason"))
            {
                out.stop_reason = Some(reason);
            }
        }
    }
}

impl Extracted {
    /// Drop empty accumulators and derive totals where the dialect reports
    /// none (anthropic/ollama report both sides but no total).
    fn normalize(mut self) -> Self {
        if let Some(usage) = &mut self.usage {
            if *usage == Usage::default() {
                self.usage = None;
            }
        }
        self
    }
}

/// Fill `total_tokens` from prompt+completion when both sides are known and
/// no explicit total was reported.
fn complete_total(mut usage: Usage) -> Usage {
    if usage.total_tokens.is_none() {
        if let (Some(p), Some(c)) = (usage.prompt_tokens, usage.completion_tokens) {
            usage.total_tokens = Some(p + c);
        }
    }
    usage
}

fn nz(v: Option<u64>) -> bool {
    matches!(v, Some(n) if n > 0)
}

fn u_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn s_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sse(transcript: &str) -> Vec<SseEvent> {
        parse_sse_body(transcript.as_bytes())
    }

    const ANTHROPIC_JSON: &str = r#"{
        "id": "msg_01", "type": "response",
        "role": "assistant", "model": "claude-sonnet-4",
        "content": [{"type": "text", "text": "Hello!"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 24, "output_tokens": 101,
                  "cache_read_input_tokens": 3}
    }"#;

    const OPENAI_JSON: &str = r#"{
        "id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
    }"#;

    const GOOGLE_JSON: &str = r#"{
        "candidates": [{"content": {"parts": [{"text": "Hola"}], "role": "model"},
                        "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 4,
                          "totalTokenCount": 13},
        "modelVersion": "gemini-1.5-flash"
    }"#;

    const OLLAMA_JSON: &str = r#"{
        "model": "llama3", "created_at": "2026-08-21T00:00:00Z",
        "message": {"role": "assistant", "content": "hey"},
        "done": true, "done_reason": "stop",
        "prompt_eval_count": 18, "eval_count": 7
    }"#;

    const ANTHROPIC_SSE: &str = concat!(
        "event: message_start\n",
        r#"data: {"type":"message_start","message":{"model":"claude-sonnet-4","usage":{"input_tokens":24,"output_tokens":1}}}"#,
        "\n\n",
        "event: content_block_delta\n",
        r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}"#,
        "\n\n",
        "event: message_delta\n",
        r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":101}}"#,
        "\n\n",
        "event: message_stop\n",
        r#"data: {"type":"message_stop"}"#,
        "\n\n"
    );

    const OPENAI_SSE_WITH_USAGE: &str = concat!(
        r#"data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#,
        "\n\n",
        "data: [DONE]\n\n"
    );

    const OPENAI_SSE_NO_USAGE: &str = concat!(
        r#"data: {"id":"c2","choices":[{"index":0,"delta":{"content":"Hey"},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"c2","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}"#,
        "\n\n",
        "data: [DONE]\n\n"
    );

    const GOOGLE_SSE: &str = concat!(
        r#"data: {"candidates":[{"content":{"parts":[{"text":"Hel"}]}}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2,"totalTokenCount":11}}"#,
        "\n\n",
        r#"data: {"candidates":[{"content":{"parts":[{"text":"lo"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":4,"totalTokenCount":13}}"#,
        "\n\n"
    );

    const OLLAMA_NDJSON: &str = concat!(
        r#"{"model":"llama3","message":{"role":"assistant","content":"he"},"done":false}"#,
        "\n",
        r#"{"model":"llama3","message":{"role":"assistant","content":"y"},"done":true,"done_reason":"stop","prompt_eval_count":18,"eval_count":7}"#,
        "\n"
    );

    #[test]
    fn anthropic_json_usage_and_stop_reason() {
        let v: Value = serde_json::from_str(ANTHROPIC_JSON).unwrap();
        let ex = from_json(Provider::Anthropic, &v);
        assert_eq!(ex.stop_reason.as_deref(), Some("end_turn"));
        let usage = ex.usage.unwrap();
        assert_eq!(usage.prompt_tokens, Some(24));
        assert_eq!(usage.completion_tokens, Some(101));
        assert_eq!(usage.total_tokens, Some(125)); // derived sum
    }

    #[test]
    fn openai_json_usage_and_finish_reason() {
        let v: Value = serde_json::from_str(OPENAI_JSON).unwrap();
        let ex = from_json(Provider::OpenAi, &v);
        let usage = ex.usage.unwrap();
        assert_eq!(
            (
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens
            ),
            (Some(12), Some(5), Some(17))
        );
        assert_eq!(ex.stop_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn google_json_usage_metadata_and_finish_reason() {
        let v: Value = serde_json::from_str(GOOGLE_JSON).unwrap();
        let ex = from_json(Provider::Google, &v);
        let usage = ex.usage.unwrap();
        assert_eq!(
            (
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens
            ),
            (Some(9), Some(4), Some(13))
        );
        assert_eq!(ex.stop_reason.as_deref(), Some("STOP"));
    }

    #[test]
    fn ollama_json_eval_counts_and_done_reason() {
        let v: Value = serde_json::from_str(OLLAMA_JSON).unwrap();
        let ex = from_json(Provider::Ollama, &v);
        let usage = ex.usage.unwrap();
        assert_eq!(
            (
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens
            ),
            (Some(18), Some(7), Some(25))
        );
        assert_eq!(ex.stop_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn anthropic_sse_folds_message_start_and_message_delta() {
        let ex = extract_from_events(Provider::Anthropic, &sse(ANTHROPIC_SSE));
        let usage = ex.usage.expect("usage folded");
        assert_eq!(usage.prompt_tokens, Some(24));
        assert_eq!(usage.completion_tokens, Some(101));
        assert_eq!(usage.total_tokens, None); // never synthesized on streams
        assert_eq!(ex.stop_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn openai_sse_with_include_usage_chunk_folds_final_totals() {
        let ex = extract_from_events(Provider::OpenAi, &sse(OPENAI_SSE_WITH_USAGE));
        let usage = ex.usage.unwrap();
        assert_eq!(
            (
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens
            ),
            (Some(12), Some(5), Some(17))
        );
        assert_eq!(ex.stop_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn openai_sse_without_usage_chunk_yields_none_but_keeps_stop_reason() {
        let ex = extract_from_events(Provider::OpenAi, &sse(OPENAI_SSE_NO_USAGE));
        assert!(ex.usage.is_none());
        assert_eq!(ex.stop_reason.as_deref(), Some("length"));
    }

    #[test]
    fn google_sse_last_non_zero_metadata_wins() {
        let ex = extract_from_events(Provider::Google, &sse(GOOGLE_SSE));
        let usage = ex.usage.unwrap();
        assert_eq!(
            (
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens
            ),
            (Some(9), Some(4), Some(13))
        );
        assert_eq!(ex.stop_reason.as_deref(), Some("STOP"));
    }

    #[test]
    fn ollama_ndjson_stream_folds_done_frame() {
        let ex = extract_from_ndjson(Provider::Ollama, OLLAMA_NDJSON.as_bytes());
        let usage = ex.usage.unwrap();
        assert_eq!(
            (usage.prompt_tokens, usage.completion_tokens),
            (Some(18), Some(7))
        );
        assert_eq!(ex.stop_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn extract_dispatches_on_media_type_and_sniffs_content() {
        let ex = extract(
            Provider::OpenAi,
            Some("text/event-stream"),
            OPENAI_SSE_WITH_USAGE.as_bytes(),
        );
        assert!(ex.usage.is_some());
        // Missing media type: SSE sniffed from leading `data:`.
        let sniffed = extract(Provider::OpenAi, None, OPENAI_SSE_WITH_USAGE.as_bytes());
        assert_eq!(sniffed, ex);
        // Plain JSON via application/json.
        let json_ex = extract(
            Provider::OpenAi,
            Some("application/json"),
            OPENAI_JSON.as_bytes(),
        );
        assert_eq!(json_ex.usage.unwrap().total_tokens, Some(17));
    }

    #[test]
    fn garbage_response_never_panics_and_yields_default() {
        let ex = extract(
            Provider::Anthropic,
            Some("text/plain"),
            b"\xff\xfe not json \x00",
        );
        assert_eq!(ex, Extracted::default());
        let truncated = extract(
            Provider::OpenAi,
            Some("text/event-stream"),
            b"data: {oops\n\n",
        );
        assert_eq!(truncated, Extracted::default());
    }
}
