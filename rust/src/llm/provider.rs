//! Ordered provider-detection rules table (W4).
//!
//! Precedence is table order — most-specific signal first, generic
//! OpenAI-shape last:
//!
//! 1. **bedrock** — `x-amz-target` header, or `/model/{id}/invoke|/converse`
//!    path shape.
//! 2. **google** — `:generateContent`/`:generateMessage`/`countTokens` path
//!    verbs under `/models/`, or the `x-goog-api-key` header.
//! 3. **azure-openai** — host ending `.openai.azure.com`, or an `api-key`
//!    header paired with an Azure/OpenAI-style path.
//! 4. **anthropic** — `/v1/messages` or `/v1/complete` path plus an
//!    `X-API-KEY` or `anthropic-version` header.
//! 5. **xai** — host on `x.ai`, or OpenAI path with a `grok*` body model.
//! 6. **mistral** — OpenAI-completions path with a Bearer token whose request
//!    model is prefixed `mistral`/`magistral`, or host `api.mistral.ai`.
//! 7. **ollama** — native `/api/chat`, `/api/generate`, `/api/embeddings`
//!    paths.
//! 8. **openrouter** — host `openrouter.ai`, or Bearer token prefixed
//!    `sk-or-`.
//! 9. **openai** — generic `/v1/chat/completions`, `/v1/completions`,
//!    `/v1/responses`, `/v1/embeddings` paths with a Bearer token.
//!
//! First match wins; no match yields [`Provider::Unknown`] (never an error).

use serde_json::Value;

use crate::types::HeaderMapValues;

/// Detected LLM provider ids. Serialized kebab-case where multi-word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Google,
    Xai,
    Mistral,
    Ollama,
    OpenRouter,
    AzureOpenAi,
    Bedrock,
    Unknown,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAi => "openai",
            Provider::Google => "google",
            Provider::Xai => "xai",
            Provider::Mistral => "mistral",
            Provider::Ollama => "ollama",
            Provider::OpenRouter => "openrouter",
            Provider::AzureOpenAi => "azure-openai",
            Provider::Bedrock => "bedrock",
            Provider::Unknown => "unknown",
        }
    }
}

/// One detection outcome: the provider plus a human-readable reason naming
/// the winning rule and signals ("path + X-API-KEY header").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub provider: Provider,
    /// Confidence reason: which rule matched and on which signals.
    pub reason: String,
}

impl Detection {
    fn new(provider: Provider, reason: impl Into<String>) -> Self {
        Detection {
            provider,
            reason: reason.into(),
        }
    }
}

/// Everything detection needs from one captured exchange's request half.
pub struct RequestContext<'a> {
    /// Request path including query string (e.g. `/v1/messages`).
    pub path: &'a str,
    /// Host authority without port, when known (`host`/`:authority` header).
    pub host: Option<&'a str>,
    /// Lowercased-name request headers.
    pub headers: &'a HeaderMapValues,
    /// Names of headers whose values were redacted before persistence.
    /// Credential-bearing names (X-API-KEY, authorization, ...) survive as
    /// evidence here even though their values are gone, so provider
    /// detection works on captured traffic.
    pub redacted_header_names: &'a [String],
    /// Parsed request JSON body, when the body was JSON.
    pub body: Option<&'a Value>,
}

impl<'a> RequestContext<'a> {
    /// True when the header is present in `headers` OR listed among the
    /// redacted names (value-stripped evidence).
    pub fn has_header(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.headers.keys().any(|k| k.eq_ignore_ascii_case(&lower))
            || self
                .redacted_header_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&lower))
    }
}

/// Ordered rule table entry point. Pure; never panics on external input.
pub struct ProviderDetector;

impl ProviderDetector {
    pub fn detect(ctx: &RequestContext<'_>) -> Detection {
        let bare_path = bare_path(ctx.path);
        let auth = authorization(ctx.headers);
        let bearer = bearer_token(auth);

        // 1. bedrock — sigv4 shapes.
        if header(ctx.headers, "x-amz-target").is_some() {
            return Detection::new(Provider::Bedrock, "x-amz-target header");
        }
        if bedrock_model_invoke_path(bare_path) {
            return Detection::new(
                Provider::Bedrock,
                "path /model/{id}/invoke or /model/{id}/converse",
            );
        }

        // 2. google — generativelanguage path verbs / api key header.
        if google_path_verb(bare_path) {
            return Detection::new(
                Provider::Google,
                "path /models/{model}:generateContent|generateMessage|countTokens",
            );
        }
        if header(ctx.headers, "x-goog-api-key").is_some() {
            return Detection::new(Provider::Google, "x-goog-api-key header");
        }

        // 3. azure-openai — deployment host or api-key header.
        if let Some(host) = ctx.host {
            if host.to_ascii_lowercase().ends_with(".openai.azure.com") {
                return Detection::new(
                    Provider::AzureOpenAi,
                    format!("host {host} (*.openai.azure.com)"),
                );
            }
        }
        if (header(ctx.headers, "api-key").is_some() || ctx.has_header("api-key"))
            && (bare_path.starts_with("/openai/") || openai_path(bare_path))
        {
            return Detection::new(Provider::AzureOpenAi, "api-key header + openai-style path");
        }

        // 4. anthropic — messages path plus anthropic auth markers.
        if matches!(
            bare_path,
            "/v1/messages" | "/v1/complete" | "/v1/messages/count_tokens"
        ) && (ctx.has_header("x-api-key") || ctx.has_header("anthropic-version"))
        {
            return Detection::new(
                Provider::Anthropic,
                "path /v1/messages|/v1/complete + X-API-KEY or anthropic-version header",
            );
        }

        // 5. xai — x.ai host, else grok model in an OpenAI-shaped body.
        if let Some(host) = ctx.host {
            let host = host.to_ascii_lowercase();
            if host == "x.ai" || host == "api.x.ai" || host.ends_with(".x.ai") {
                return Detection::new(Provider::Xai, format!("host {host}"));
            }
        }
        if openai_path(bare_path) && body_model_is_grok(ctx.body) {
            return Detection::new(Provider::Xai, "grok* model field in openai-shaped body");
        }

        // 6. mistral — model prefix over bearer-authed completions.
        if openai_path(bare_path)
            && bearer.is_some()
            && body_model_prefixed(ctx.body, &["mistral", "magistral"])
        {
            return Detection::new(
                Provider::Mistral,
                "mistral*/magistral* model field + bearer auth on completions path",
            );
        }
        if ctx.host.map(|h| h.to_ascii_lowercase()) == Some("api.mistral.ai".into()) {
            return Detection::new(Provider::Mistral, "host api.mistral.ai");
        }

        // 7. ollama — native API paths.
        if matches!(bare_path, "/api/chat" | "/api/generate" | "/api/embeddings") {
            return Detection::new(
                Provider::Ollama,
                "path /api/chat|/api/generate|/api/embeddings",
            );
        }

        // 8. openrouter — host or sk-or- bearer prefix.
        if let Some(host) = ctx.host {
            let host = host.to_ascii_lowercase();
            if host == "openrouter.ai" || host.ends_with(".openrouter.ai") {
                return Detection::new(Provider::OpenRouter, format!("host {host}"));
            }
        }
        if let Some(token) = bearer {
            if token.starts_with("sk-or-") {
                return Detection::new(Provider::OpenRouter, "authorization bearer sk-or-*");
            }
        }

        // 9. generic openai — completions/responses/embeddings + bearer.
        if openai_path(bare_path) && bearer.is_some() {
            return Detection::new(
                Provider::OpenAi,
                "path /v1/chat/completions|/v1/completions|/v1/responses|/v1/embeddings + bearer",
            );
        }

        Detection::new(Provider::Unknown, "no rule matched")
    }
}

/// Path with any query string removed.
fn bare_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// Case-insensitive first header value lookup (header names are stored
/// lowercased, but be defensive).
fn header<'a>(headers: &'a HeaderMapValues, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(|s| s.as_str())
}

fn authorization(headers: &HeaderMapValues) -> Option<&str> {
    header(headers, "authorization")
}

fn bearer_token(auth: Option<&str>) -> Option<&str> {
    auth.and_then(|v| {
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))
    })
}

/// Generic OpenAI-family endpoint paths.
fn openai_path(bare: &str) -> bool {
    matches!(
        bare,
        "/v1/chat/completions"
            | "/v1/completions"
            | "/v1/responses"
            | "/v1/embeddings"
            | "/v1/models"
    )
}

/// Bedrock model invocation paths: `/model/{id}/invoke[/with-response-stream]`
/// and `/model/{id}/converse[-stream]`.
fn bedrock_model_invoke_path(bare: &str) -> bool {
    let mut segments = bare.trim_matches('/').split('/');
    if segments.next() != Some("model") {
        return false;
    }
    match segments.next() {
        Some(_) => matches!(
            segments.next(),
            Some("invoke")
                | Some("invoke-with-response-stream")
                | Some("converse")
                | Some("converse-stream")
        ),
        None => false,
    }
}

/// Google generativelanguage verb embedded in the model segment
/// (`.../models/{model}:generateContent` etc.).
fn google_path_verb(bare: &str) -> bool {
    bare.split('/')
        .filter_map(|segment| segment.split_once(':'))
        .any(|(prefix, verb)| {
            !prefix.is_empty()
                && matches!(
                    verb,
                    "generateContent"
                        | "streamGenerateContent"
                        | "generateMessage"
                        | "countTokens"
                        | "embedContent"
                )
        })
}

/// The string value of the top-level `model` request field, when present.
fn body_model(body: Option<&Value>) -> Option<&str> {
    body?.get("model")?.as_str()
}

fn body_model_is_grok(body: Option<&Value>) -> bool {
    body_model(body)
        .map(|m| m.starts_with("grok"))
        .unwrap_or(false)
}

fn body_model_prefixed(body: Option<&Value>, prefixes: &[&str]) -> bool {
    body_model(body)
        .map(|m| prefixes.iter().any(|p| m.starts_with(p)))
        .unwrap_or(false)
}

/// Extract the model identifier for a detected provider.
///
/// - google: path-embedded (`/models/{model}:{verb}`).
/// - azure-openai: `/deployments/{name}/...` deployment segment, falling back
///   to the body `model` field.
/// - bedrock: percent-decoded `/model/{id}/...` segment.
/// - every body-dialect provider: the top-level `model` field.
pub fn detect_model(provider: Provider, path: &str, body: Option<&Value>) -> Option<String> {
    let bare = bare_path(path);
    let decoded = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8()
            .map(|d| d.into_owned())
            .unwrap_or_else(|_| s.to_string())
    };
    match provider {
        Provider::Google => {
            let marker = "/models/";
            let start = bare.find(marker)? + marker.len();
            let rest = &bare[start..];
            let name = rest.split(['/', ':']).next()?;
            (!name.is_empty()).then(|| decoded(name))
        }
        Provider::AzureOpenAi => {
            if let Some(rest) = bare.split("/deployments/").nth(1) {
                let name = rest.split('/').next()?;
                if !name.is_empty() {
                    return Some(decoded(name));
                }
            }
            body_model(body).map(decoded)
        }
        Provider::Bedrock => {
            let mut segments = bare.trim_matches('/').split('/');
            if segments.next() != Some("model") {
                return body_model(body).map(decoded);
            }
            segments.next().filter(|s| !s.is_empty()).map(decoded)
        }
        Provider::Anthropic
        | Provider::OpenAi
        | Provider::Xai
        | Provider::Mistral
        | Provider::Ollama
        | Provider::OpenRouter
        | Provider::Unknown => body_model(body).map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMapValues {
        pairs.iter().fold(BTreeMap::new(), |mut map, (k, v)| {
            map.entry(k.to_string())
                .or_insert_with(Vec::new)
                .push(v.to_string());
            map
        })
    }

    fn detect(
        path: &str,
        host: Option<&str>,
        hs: HeaderMapValues,
        body: Option<Value>,
    ) -> Detection {
        ProviderDetector::detect(&RequestContext {
            path,
            host,
            headers: &hs,
            redacted_header_names: &[],
            body: body.as_ref(),
        })
    }

    #[test]
    fn anthropic_messages_with_api_key() {
        let d = detect(
            "/v1/messages",
            Some("api.anthropic.com"),
            headers(&[
                ("X-API-KEY", "sk-ant-01"),
                ("anthropic-version", "2023-06-01"),
            ]),
            Some(json!({"model": "claude-sonnet-4", "max_tokens": 1024, "messages": []})),
        );
        assert_eq!(d.provider, Provider::Anthropic);
        assert!(d.reason.contains("X-API-KEY"));
    }

    #[test]
    fn anthropic_without_version_header_still_matches_on_x_api_key() {
        let d = detect(
            "/v1/messages",
            None,
            headers(&[("X-API-KEY", "sk-ant-01")]),
            Some(json!({"model": "claude"})),
        );
        assert_eq!(d.provider, Provider::Anthropic);
    }

    #[test]
    fn openai_chat_completions_bearer_sk() {
        let d = detect(
            "/v1/chat/completions",
            Some("api.openai.com"),
            headers(&[("authorization", "Bearer sk-proj-abc")]),
            Some(json!({"model": "gpt-4o", "messages": []})),
        );
        assert_eq!(d.provider, Provider::OpenAi);
        assert_eq!(
            detect_model(
                Provider::OpenAi,
                "/v1/chat/completions",
                Some(&json!({"model": "gpt-4o-mini"}))
            )
            .as_deref(),
            Some("gpt-4o-mini")
        );
    }

    #[test]
    fn openai_responses_endpoint_detected() {
        let d = detect(
            "/v1/responses",
            None,
            headers(&[("authorization", "Bearer sk-x")]),
            Some(json!({"model": "gpt-5"})),
        );
        assert_eq!(d.provider, Provider::OpenAi);
    }

    #[test]
    fn azure_via_host_and_via_api_key_header() {
        let d = detect(
            "/openai/deployments/gpt4o/chat/completions?api-version=2024-02-01",
            Some("res.openai.azure.com"),
            headers(&[("api-key", "azkey")]),
            None,
        );
        assert_eq!(d.provider, Provider::AzureOpenAi);
        let d2 = detect(
            "/v1/chat/completions",
            None,
            headers(&[("api-key", "azkey")]),
            Some(json!({"model": "gpt-4o"})),
        );
        assert_eq!(d2.provider, Provider::AzureOpenAi);
        assert_eq!(
            detect_model(
                Provider::AzureOpenAi,
                "/openai/deployments/gpt-4o-deploy/chat/completions",
                None
            )
            .as_deref(),
            Some("gpt-4o-deploy")
        );
    }

    #[test]
    fn google_generate_content_and_path_model() {
        let d = detect(
            "/v1beta/models/gemini-1.5-pro:generateContent?key=k"
                .to_string()
                .as_str(),
            Some("generativelanguage.googleapis.com"),
            headers(&[("x-goog-api-key", "gkey")]),
            Some(json!({"contents": []})),
        );
        assert_eq!(d.provider, Provider::Google);
        assert_eq!(
            detect_model(
                Provider::Google,
                "/v1beta/models/gemini-1.5-flash:generateContent",
                None
            )
            .as_deref(),
            Some("gemini-1.5-flash")
        );
    }

    #[test]
    fn xai_host_wins_and_body_fallback_works() {
        let d = detect(
            "/v1/chat/completions",
            Some("api.x.ai"),
            headers(&[("authorization", "Bearer xai-1")]),
            Some(json!({"model": "grok-3"})),
        );
        assert_eq!(d.provider, Provider::Xai);
        let fallback = detect(
            "/v1/chat/completions",
            None,
            headers(&[("authorization", "Bearer whatever")]),
            Some(json!({"model": "grok-beta"})),
        );
        assert_eq!(fallback.provider, Provider::Xai);
    }

    #[test]
    fn mistral_model_prefix_beats_generic_openai() {
        let d = detect(
            "/v1/chat/completions",
            None,
            headers(&[("authorization", "Bearer mstk")]),
            Some(json!({"model": "mistral-large-latest"})),
        );
        assert_eq!(d.provider, Provider::Mistral);
        let magistral = detect(
            "/v1/chat/completions",
            None,
            headers(&[("authorization", "Bearer t")]),
            Some(json!({"model": "magistral-medium"})),
        );
        assert_eq!(magistral.provider, Provider::Mistral);
    }

    #[test]
    fn ollama_native_paths_match_without_auth() {
        for path in ["/api/chat", "/api/generate"] {
            let d = detect(
                path,
                Some("localhost:11434"),
                headers(&[]),
                Some(json!({"model": "llama3"})),
            );
            assert_eq!(d.provider, Provider::Ollama, "{path}");
        }
        assert_eq!(
            detect_model(
                Provider::Ollama,
                "/api/chat",
                Some(&json!({"model": "llama3"}))
            )
            .as_deref(),
            Some("llama3")
        );
    }

    #[test]
    fn openrouter_via_sk_or_bearer_without_host() {
        let d = detect(
            "/v1/chat/completions",
            None,
            headers(&[("authorization", "Bearer sk-or-v1-abc")]),
            Some(json!({"model": "anthropic/claude-3.5-sonnet"})),
        );
        assert_eq!(d.provider, Provider::OpenRouter);
    }

    #[test]
    fn bedrock_invoke_path_and_amz_target() {
        let d = detect(
            "/model/anthropic.claude-3-5-sonnet/invoke",
            Some("bedrock-runtime.us-east-1.amazonaws.com"),
            headers(&[("authorization", "AWS4-HMAC-SHA256 ...")]),
            None,
        );
        assert_eq!(d.provider, Provider::Bedrock);
        assert_eq!(
            detect_model(
                Provider::Bedrock,
                "/model/anthropic.claude-3-5-sonnet/invoke",
                None
            )
            .as_deref(),
            Some("anthropic.claude-3-5-sonnet")
        );
        let converse = detect(
            "/model/us.amazon.nova-pro-v1:0/converse",
            None,
            headers(&[("x-amz-target", "AmazonBedrockRuntime.Converse")]),
            None,
        );
        assert_eq!(converse.provider, Provider::Bedrock);
    }

    #[test]
    fn precedence_specific_hosts_over_generic_openai() {
        // OpenRouter host serving an OpenAI-shaped path must classify as
        // openrouter, not openai.
        let d = detect(
            "/api/v1/chat/completions",
            Some("openrouter.ai"),
            headers(&[("authorization", "Bearer sk-or-v1-z")]),
            Some(json!({"model": "openai/gpt-4o"})),
        );
        assert_eq!(d.provider, Provider::OpenRouter);
    }

    #[test]
    fn non_llm_traffic_is_unknown() {
        let d = detect("/users/42?page=2", Some("example.com"), headers(&[]), None);
        assert_eq!(d.provider, Provider::Unknown);
        let s3 = detect("/", Some("s3.amazonaws.com"), headers(&[]), None);
        assert_ne!(s3.provider, Provider::Bedrock);
    }
}
