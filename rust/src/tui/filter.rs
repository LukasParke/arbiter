//! Flow filter grammar: parser, predicate tree, evaluator, saved filters.
//!
//! Grammar (implicit AND, `OR` keyword, parentheses):
//!
//! ```text
//! expr    := and_expr (OR and_expr)*
//! and_expr:= primary+
//! primary := '(' expr ')' | term
//! term    := key op value | free-text
//! key     := method | status | host | path | provider | model | body
//! op      := '=' | '!=' | '~' | '>=' | '<=' | '>' | '<'
//! value   := '"' ... '"' | run of non-space/non-paren characters
//! ```
//!
//! Semantics: `status` accepts `2xx` classes, exact codes, and numeric
//! ordering (`status>=500`); `path~` compiles the shared segment-scoped glob
//! (`mock::matcher::GlobPattern`, AMEND-1); `provider`/`model` match the LLM
//! metadata block (flows without one never match those keys); `body~`
//! matches resolved detail body text; free text is a case-insensitive
//! substring across method, path, and host.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::mock::matcher::{compile_glob, GlobPattern};
use crate::tui::feed::{FlowDetailDto, FlowSummaryDto};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Filter parse failure with byte position and an actionable hint. Rendered
/// as `error: <this>` plus a `  help: <help>` line per the DX bar.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid filter at byte {position}: {message}")]
pub struct FilterError {
    /// Byte offset into the original expression.
    pub position: usize,
    pub message: String,
    pub help: String,
}

impl FilterError {
    fn new(position: usize, message: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            position,
            message: message.into(),
            help: help.into(),
        }
    }

    /// Full two-line user-facing rendering (cause + hint).
    pub fn render(&self) -> String {
        format!("error: {self}\n  help: {}", self.help)
    }
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Method,
    Status,
    Host,
    Path,
    Provider,
    Model,
    Body,
}

impl Key {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "method" => Key::Method,
            "status" => Key::Status,
            "host" => Key::Host,
            "path" => Key::Path,
            "provider" => Key::Provider,
            "model" => Key::Model,
            "body" => Key::Body,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Key::Method => "method",
            Key::Status => "status",
            Key::Host => "host",
            Key::Path => "path",
            Key::Provider => "provider",
            Key::Model => "model",
            Key::Body => "body",
        }
    }

    pub const ALL: &'static [&'static str] = &[
        "method", "status", "host", "path", "provider", "model", "body",
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Substr,
    Ge,
    Gt,
    Le,
    Lt,
}

impl Op {
    fn from_text(text: &str) -> Option<Self> {
        Some(match text {
            "=" | "==" => Op::Eq,
            "!=" => Op::Ne,
            "~" => Op::Substr,
            ">=" => Op::Ge,
            ">" => Op::Gt,
            "<=" => Op::Le,
            "<" => Op::Lt,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Substr => "~",
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::Le => "<=",
            Op::Lt => "<",
        }
    }
}

/// Pre-resolved comparison operand, compiled once at parse time.
#[derive(Debug, Clone)]
pub enum Operand {
    Text(String),
    /// Compiled segment-scoped glob (`*` in segment, `**` across).
    Glob(GlobPattern),
    /// Exact status code.
    Code(u16),
    /// `2xx`-style status class lower bound.
    Class(u16),
}

#[derive(Debug, Clone)]
pub enum Pred {
    /// Bareword: case-insensitive substring across method/path/host.
    Free(String),
    Field {
        key: Key,
        op: Op,
        value: Operand,
    },
    All(Vec<Pred>),
    Any(Vec<Pred>),
}

/// Compiled filter predicate tree. Parse once, evaluate many.
#[derive(Debug, Clone)]
pub struct Filter(pub Pred);

/// Evaluation context: the list-row summary plus, optionally, the resolved
/// detail that `body` predicates need.
pub struct FilterInput<'a> {
    pub summary: &'a FlowSummaryDto,
    pub detail: Option<&'a FlowDetailDto>,
}

impl<'a> FilterInput<'a> {
    pub fn summary(summary: &'a FlowSummaryDto) -> Self {
        Self {
            summary,
            detail: None,
        }
    }
}

impl Filter {
    /// Parses a filter expression, compiling globs immediately.
    pub fn parse(input: &str) -> Result<Self, FilterError> {
        let mut parser = Parser::new(input);
        let pred = parser.parse_expr()?;
        parser.skip_spaces();
        if let Some(ch) = parser.peek_char() {
            return Err(FilterError::new(
                parser.pos,
                format!("unexpected `{ch}`"),
                "check for an unbalanced closing parenthesis",
            ));
        }
        Ok(Filter(pred))
    }

    /// Evaluates against a summary (and detail when available).
    pub fn matches(&self, input: &FilterInput<'_>) -> bool {
        eval(&self.0, input)
    }

    /// Convenience for list-only evaluation.
    pub fn matches_summary(&self, summary: &FlowSummaryDto) -> bool {
        self.matches(&FilterInput::summary(summary))
    }

    /// Canonical reconstruction (AND joined by spaces, OR parenthesized).
    pub fn to_query_string(&self) -> String {
        pred_to_query(&self.0)
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn llm_of<'a>(input: &FilterInput<'a>) -> Option<&'a crate::tui::feed::LlmSummaryDto> {
    input.summary.llm.as_ref()
}

fn eval(pred: &Pred, input: &FilterInput<'_>) -> bool {
    match pred {
        Pred::Free(text) => {
            contains_ci(&input.summary.method, text)
                || contains_ci(&input.summary.path, text)
                || input
                    .summary
                    .host
                    .as_deref()
                    .map(|host| contains_ci(host, text))
                    .unwrap_or(false)
        }
        Pred::Field { key, op, value } => eval_field(*key, *op, value, input),
        Pred::All(children) => children.iter().all(|child| eval(child, input)),
        Pred::Any(children) => children.iter().any(|child| eval(child, input)),
    }
}

fn text_operand(value: &Operand) -> &str {
    match value {
        Operand::Text(text) => text,
        _ => "",
    }
}

fn eval_field(key: Key, op: Op, value: &Operand, input: &FilterInput<'_>) -> bool {
    match key {
        Key::Method => {
            let matched = contains_ci(&input.summary.method, text_operand(value));
            match op {
                Op::Eq => matched,
                Op::Ne => !matched,
                Op::Substr => matched,
                _ => false,
            }
        }
        Key::Host => {
            let Some(host) = input.summary.host.as_deref() else {
                return op == Op::Ne;
            };
            let matched = contains_ci(host, text_operand(value));
            match op {
                Op::Eq | Op::Substr => matched,
                Op::Ne => !matched,
                _ => false,
            }
        }
        Key::Path => {
            let matched = match value {
                Operand::Glob(glob) => glob.is_match(&input.summary.path),
                Operand::Text(text) => contains_ci(&input.summary.path, text),
                _ => false,
            };
            match op {
                Op::Eq | Op::Substr => matched,
                Op::Ne => !matched,
                _ => false,
            }
        }
        Key::Status => {
            let Some(status) = input.summary.status else {
                return false;
            };
            eval_status(op, value, status)
        }
        Key::Provider => {
            let Some(llm) = llm_of(input) else {
                return false;
            };
            let matched = contains_ci(&llm.provider, text_operand(value));
            match op {
                Op::Eq | Op::Substr => matched,
                Op::Ne => !matched,
                _ => false,
            }
        }
        Key::Model => {
            let Some(model) = llm_of(input).and_then(|llm| llm.model.as_deref()) else {
                return false;
            };
            let matched = contains_ci(model, &text_operand(value).to_lowercase());
            match op {
                Op::Eq | Op::Substr => matched,
                Op::Ne => !matched,
                _ => false,
            }
        }
        Key::Body => {
            // Body text exists only in resolved detail views.
            let Some(detail) = input.detail else {
                return false;
            };
            let needle = text_operand(value).to_lowercase();
            let hit = |view: &crate::tui::feed::BodyViewDto| {
                view.text
                    .as_deref()
                    .map(|text| contains_ci(text, &needle))
                    .unwrap_or(false)
            };
            let matched = hit(&detail.request_body) || hit(&detail.response_body);
            match op {
                Op::Eq | Op::Substr => matched,
                Op::Ne => !matched,
                _ => false,
            }
        }
    }
}

fn eval_status(op: Op, value: &Operand, status: u16) -> bool {
    match (op, value) {
        (Op::Eq, Operand::Code(code)) => status == *code,
        (Op::Eq, Operand::Class(low)) => status >= *low && status < low + 100,
        (Op::Ne, Operand::Code(code)) => status != *code,
        (Op::Ne, Operand::Class(low)) => !(status >= *low && status < low + 100),
        (_, Operand::Code(code)) => compare(op, status, *code),
        (_, Operand::Class(low)) => compare(op, status, *low),
        _ => false,
    }
}

fn compare(op: Op, left: u16, right: u16) -> bool {
    match op {
        Op::Ge => left >= right,
        Op::Gt => left > right,
        Op::Le => left <= right,
        Op::Lt => left < right,
        _ => left == right,
    }
}

fn pred_to_query(pred: &Pred) -> String {
    match pred {
        Pred::Free(text) => text.clone(),
        Pred::Field { key, op, value } => {
            let value = match value {
                Operand::Text(text) => text.clone(),
                Operand::Code(code) => code.to_string(),
                Operand::Class(low) => format!("{}xx", low / 100),
                // Globs cannot round-trip from the compiled form; the saved
                // query string keeps the raw text via SavedFilter.query.
                Operand::Glob(_) => String::new(),
            };
            format!("{}{}{}", key.name(), op.as_str(), value)
        }
        Pred::All(children) => children
            .iter()
            .map(pred_to_query)
            .collect::<Vec<_>>()
            .join(" "),
        Pred::Any(children) => format!(
            "({})",
            children
                .iter()
                .map(pred_to_query)
                .collect::<Vec<_>>()
                .join(" OR ")
        ),
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn peek_char(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek_char(), Some(' ') | Some('\t')) {
            self.pos += 1;
        }
    }

    fn parse_expr(&mut self) -> Result<Pred, FilterError> {
        let mut terms = vec![self.parse_and()?];
        loop {
            self.skip_spaces();
            if !self.consume_keyword("or") {
                break;
            }
            terms.push(self.parse_and()?);
        }
        Ok(if terms.len() == 1 {
            terms.pop().expect("non-empty")
        } else {
            Pred::Any(terms)
        })
    }

    fn parse_and(&mut self) -> Result<Pred, FilterError> {
        let mut terms = Vec::new();
        loop {
            self.skip_spaces();
            match self.peek_char() {
                Some('(') => {
                    self.pos += 1;
                    let inner = self.parse_expr()?;
                    self.skip_spaces();
                    if self.peek_char() != Some(')') {
                        return Err(FilterError::new(
                            self.pos,
                            "unbalanced parenthesis: expected `)`",
                            "every `(` needs a matching `)`",
                        ));
                    }
                    self.pos += 1;
                    terms.push(inner);
                }
                Some(')') | None => break,
                _ => {
                    if self.peek_or() {
                        if terms.is_empty() {
                            return Err(FilterError::new(
                                self.pos,
                                "`OR` without a preceding condition",
                                "write `a OR b`; every OR needs conditions on both sides",
                            ));
                        }
                        // Standalone OR ends the AND-group; parse_expr joins.
                        break;
                    }
                    terms.push(self.parse_term()?);
                }
            }
        }
        Ok(match terms.len() {
            0 => Pred::All(Vec::new()),
            1 => terms.pop().expect("non-empty"),
            _ => Pred::All(terms),
        })
    }

    /// True when the input at the cursor is a standalone `OR` keyword.
    fn peek_or(&self) -> bool {
        let rest = &self.src[self.pos..];
        let prefix = rest
            .get(..2)
            .map(|prefix| prefix.eq_ignore_ascii_case("or"))
            .unwrap_or(false);
        prefix
            && rest[2..]
                .chars()
                .next()
                .map(|ch| ch.is_whitespace() || ch == '(' || ch == ')')
                .unwrap_or(true)
    }
    /// Consumes `keyword` only when it stands alone (delimited by whitespace,
    /// parens, or end of input).
    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let rest = &self.src[self.pos..];
        // Case-insensitive prefix match, then require the keyword to stand
        // alone (delimited by whitespace, parens, or end of input).
        let prefix_matches = rest
            .get(..keyword.len())
            .map(|prefix| prefix.eq_ignore_ascii_case(keyword))
            .unwrap_or(false);
        if !prefix_matches {
            return false;
        }
        let delimited = rest[keyword.len()..]
            .chars()
            .next()
            .map(|ch| ch.is_whitespace() || ch == '(' || ch == ')')
            .unwrap_or(true);
        if delimited {
            self.pos += keyword.len();
            true
        } else {
            false
        }
    }

    fn parse_term(&mut self) -> Result<Pred, FilterError> {
        let term_start = self.pos;
        let ident = self.scan_ident();
        if ident.is_empty() {
            // Non-alphabetic barewords (e.g. `/v1/health`) are free text.
            let starts_token = self
                .peek_char()
                .map(|ch| !ch.is_whitespace() && ch != '(' && ch != ')' && ch != '"')
                .unwrap_or(false);
            if starts_token {
                return Ok(Pred::Free(self.scan_value()?));
            }
            let ch = self.peek_char().map(|c| c.to_string()).unwrap_or_default();
            return Err(FilterError::new(
                self.pos,
                format!("unexpected `{ch}`"),
                format!(
                    "expected a predicate like `method=GET`, `status>=500`, or free text; keys: {}",
                    Key::ALL.join(", ")
                ),
            ));
        }
        self.skip_spaces();
        let op_text = self.scan_op();
        match op_text {
            Some(op) => {
                let key_start = term_start;
                self.skip_spaces();
                let value_start = self.pos;
                let value = self.scan_value()?;
                if value.is_empty() {
                    return Err(FilterError::new(
                        self.pos,
                        format!(
                            "missing value after `{}`",
                            Key::from_name(&ident)
                                .map(Key::name)
                                .unwrap_or(ident.as_str())
                        ),
                        "provide a comparison value, quoted when it contains spaces",
                    ));
                }
                let key = match Key::from_name(&ident) {
                    Some(key) => key,
                    None => {
                        return Err(FilterError::new(
                            key_start,
                            format!("unknown filter key `{ident}`"),
                            format!("known keys: {}", Key::ALL.join(", ")),
                        ))
                    }
                };
                self.compile_term(key_start, key, op, value, value_start)
            }
            None => {
                // No operator: the whole remaining token is free text.
                let rest_start = term_start;
                self.pos = rest_start;
                let raw = self.scan_value()?;
                if raw.eq_ignore_ascii_case("or") {
                    return Err(FilterError::new(
                        rest_start,
                        "`OR` without a following condition",
                        "write `a OR b`; every OR needs conditions on both sides",
                    ));
                }
                Ok(Pred::Free(raw))
            }
        }
    }

    fn scan_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_alphabetic() || ch == '_' {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        self.src[start..self.pos].to_string()
    }

    fn scan_op(&mut self) -> Option<Op> {
        for candidate in ["!=", ">=", "<=", "=", "~", ">", "<"] {
            if self.src[self.pos..].starts_with(candidate) {
                self.pos += candidate.len();
                return Op::from_text(candidate);
            }
        }
        None
    }

    fn scan_value(&mut self) -> Result<String, FilterError> {
        match self.peek_char() {
            Some('"') => {
                self.pos += 1;
                let start = self.pos;
                while let Some(ch) = self.peek_char() {
                    if ch == '"' {
                        let value = self.src[start..self.pos].to_string();
                        self.pos += 1;
                        return Ok(value);
                    }
                    self.pos += ch.len_utf8();
                }
                Err(FilterError::new(
                    start.saturating_sub(1),
                    "unterminated quoted value",
                    "close the quote that opened here",
                ))
            }
            Some(_) => {
                let start = self.pos;
                while let Some(ch) = self.peek_char() {
                    if ch.is_whitespace() || ch == '(' || ch == ')' || ch == '"' {
                        break;
                    }
                    self.pos += ch.len_utf8();
                }
                Ok(self.src[start..self.pos].to_string())
            }
            None => Ok(String::new()),
        }
    }

    fn compile_term(
        &self,
        err_pos: usize,
        key: Key,
        op: Op,
        raw: String,
        value_pos: usize,
    ) -> Result<Pred, FilterError> {
        let supports_ordering = matches!(op, Op::Eq | Op::Ne | Op::Substr);
        let bad_op = |help: String| {
            Err(FilterError::new(
                err_pos,
                format!(
                    "operator `{}` not supported for key `{}`",
                    op.as_str(),
                    key.name()
                ),
                help,
            ))
        };
        match key {
            Key::Status => {
                let operand = parse_status_value(&raw).ok_or_else(|| {
                    FilterError::new(
                        value_pos,
                        format!("bad status value `{raw}`"),
                        "use a code (`404`), a class (`2xx`), or an ordering form (`status>=500`)",
                    )
                })?;
                if matches!(op, Op::Ge | Op::Gt | Op::Le | Op::Lt)
                    && !matches!(operand, Operand::Code(_))
                {
                    return bad_op(
                        "ordering comparisons (`>` `>=` `<` `<=`) need a numeric code, not a class"
                            .into(),
                    );
                }
                Ok(Pred::Field {
                    key,
                    op,
                    value: operand,
                })
            }
            Key::Path => {
                let value = match op {
                    Op::Substr => match compile_glob(&raw) {
                        Ok(glob) => Operand::Glob(glob),
                        Err(e) => {
                            return Err(FilterError::new(
                                value_pos,
                                format!("bad path glob `{raw}`: {e}"),
                                "`*` stays within one path segment; use `**` to cross segments",
                            ))
                        }
                    },
                    _ => Operand::Text(raw),
                };
                Ok(Pred::Field { key, op, value })
            }
            Key::Method | Key::Host | Key::Provider | Key::Model | Key::Body => {
                if !supports_ordering {
                    return bad_op(format!("only `=`, `!=`, `~` apply to `{}`", key.name()));
                }
                Ok(Pred::Field {
                    key,
                    op,
                    value: Operand::Text(raw),
                })
            }
        }
    }
}

fn parse_status_value(raw: &str) -> Option<Operand> {
    let trimmed = raw.trim();
    if let Some(prefix) = trimmed.strip_suffix("xx") {
        let hundreds: u16 = prefix.parse().ok()?;
        if !(1..=5).contains(&hundreds) {
            return None;
        }
        return Some(Operand::Class(hundreds * 100));
    }
    let code: u16 = trimmed.parse().ok()?;
    if !(100..=599).contains(&code) {
        return None;
    }
    Some(Operand::Code(code))
}

// ---------------------------------------------------------------------------
// Saved filters
// ---------------------------------------------------------------------------

/// A named, persisted filter expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedFilter {
    pub name: String,
    pub query: String,
}

/// Storage seam for named filters; the TUI palette and `GET/PUT
/// /__saved-filters` both go through this.
pub trait SavedFilterStore: Send + Sync {
    fn list(&self) -> Vec<SavedFilter>;
    /// Inserts or updates by name.
    fn save(&mut self, filter: SavedFilter);
    /// Removes by name; true when it existed.
    fn remove(&mut self, name: &str) -> bool;
}

/// User-facing filter grammar reference rendered inside the `?` help
/// overlay so every predicate is documented outside the source (T5).
pub const FILTER_HELP: &str = "\
FILTERS — grammar reference
  predicates
    method=GET            exact method (e.g. method=POST)
    status=2xx            response class (1xx–5xx); exact code: status=404
    status>=500           numeric comparison: > >= < <= = !=
    host=api.example.com  Host header value
    path~/v1/**           glob over the request path (** crosses segments)
    provider=anthropic    LLM metadata key (capture-session flows only)
    model~claude          substring match with ~
    body~\"rate limit\"   substring of resolved request/response bodies
  free text               a bare word matches method, path, or host
                          (case-insensitive substring)
  combining               adjacent terms AND together, OR alternates, and
                          parentheses group: (method=POST OR status=2xx) path~/v1/**
  quoting                 wrap values containing spaces or parentheses in
                          double quotes
  saved filters           :save NAME stores the active expression,
                          :load NAME re-applies it, :filters lists names;
                          saved filters persist to disk across runs";

/// In-memory saved-filter set with an optional JSON file backing store.
#[derive(Default)]
pub struct InMemorySavedFilterStore {
    filters: Vec<SavedFilter>,
    file_path: Option<PathBuf>,
}

impl InMemorySavedFilterStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(path: PathBuf) -> Self {
        let mut store = Self::load_from(&path);
        store.file_path = Some(path);
        store
    }

    fn load_from(path: &PathBuf) -> Self {
        let filters = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<SavedFilter>>(&bytes).ok())
            .unwrap_or_default();
        Self {
            filters,
            file_path: None,
        }
    }

    /// Writes the current set to the backing file when configured. Config-
    /// sized payloads only (<16 KiB expected); never fails the mutation.
    fn persist(&self) {
        let Some(path) = &self.file_path else {
            return;
        };
        if let Ok(json) = serde_json::to_vec_pretty(&self.filters) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

impl SavedFilterStore for InMemorySavedFilterStore {
    fn list(&self) -> Vec<SavedFilter> {
        self.filters.clone()
    }

    fn save(&mut self, filter: SavedFilter) {
        match self.filters.iter_mut().find(|f| f.name == filter.name) {
            Some(existing) => existing.query = filter.query,
            None => self.filters.push(filter),
        }
        self.filters.sort_by(|a, b| a.name.cmp(&b.name));
        self.persist();
    }

    fn remove(&mut self, name: &str) -> bool {
        let before = self.filters.len();
        self.filters.retain(|f| f.name != name);
        let removed = self.filters.len() != before;
        if removed {
            self.persist();
        }
        removed
    }
}

/// File-backed saved-filter store (T2): loads the JSON set on
/// construction, writes atomically (temp file + rename) with `0600`
/// permissions on every mutation, and creates missing parent directories.
/// The default location is `$XDG_CONFIG_HOME/arbiter/filters.json` or
/// `~/.config/arbiter/filters.json`; CLI wiring may override it with the
/// config `[tui]` section's path.
pub struct FileSavedFilterStore {
    filters: Vec<SavedFilter>,
    path: PathBuf,
}

impl FileSavedFilterStore {
    /// Loads the store from `path`. A missing or unreadable file yields an
    /// empty store (first run); a malformed file never blocks startup.
    pub fn new(path: PathBuf) -> Self {
        let filters = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<SavedFilter>>(&bytes).ok())
            .unwrap_or_default();
        Self { filters, path }
    }

    /// Default persistence path: `$XDG_CONFIG_HOME/arbiter/filters.json`,
    /// falling back to `~/.config/arbiter/filters.json`.
    pub fn default_path() -> PathBuf {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("arbiter").join("filters.json");
        }
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home)
                .join(".config")
                .join("arbiter")
                .join("filters.json"),
            None => PathBuf::from("filters.json"),
        }
    }

    /// Atomic write: create parent dirs, serialize to `<path>.tmp` with
    /// owner-only permissions, then rename over the destination so a crash
    /// can never leave a truncated filter file.
    fn persist(&self) -> std::io::Result<()> {
        use std::io::Write as _;
        let json = serde_json::to_vec_pretty(&self.filters)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&json)?;
        std::fs::rename(&tmp, &self.path)
    }
}

impl SavedFilterStore for FileSavedFilterStore {
    fn list(&self) -> Vec<SavedFilter> {
        self.filters.clone()
    }

    fn save(&mut self, filter: SavedFilter) {
        match self.filters.iter_mut().find(|f| f.name == filter.name) {
            Some(existing) => existing.query = filter.query,
            None => self.filters.push(filter),
        }
        self.filters.sort_by(|a, b| a.name.cmp(&b.name));
        let _ = self.persist();
    }

    fn remove(&mut self, name: &str) -> bool {
        let before = self.filters.len();
        self.filters.retain(|f| f.name != name);
        let removed = self.filters.len() != before;
        if removed {
            let _ = self.persist();
        }
        removed
    }
}

#[cfg(test)]
mod file_store_tests {
    use super::*;

    #[test]
    fn filter_help_documents_every_predicate() {
        assert!(!FILTER_HELP.trim().is_empty());
        for token in [
            "method=",
            "status=2xx",
            "status>=500",
            "status=404",
            "host=",
            "path~",
            "provider=",
            "model~",
            "body~",
            " OR ",
            "(",
            "\"",
            ":save",
            ":load",
            ":filters",
        ] {
            assert!(
                FILTER_HELP.contains(token),
                "help must document `{token}`:\n{FILTER_HELP}"
            );
        }
    }

    #[test]
    fn file_store_round_trips_over_tempdir_with_parent_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Nested path that does not exist yet: persist creates parents.
        let path = dir.path().join("nested").join("filters.json");
        let mut store = FileSavedFilterStore::new(path.clone());
        assert!(store.list().is_empty(), "missing file starts empty");

        store.save(SavedFilter {
            name: "errors".to_string(),
            query: "status>=500".to_string(),
        });
        store.save(SavedFilter {
            name: "llm".to_string(),
            query: "provider=anthropic".to_string(),
        });

        // On-disk representation is owner-only (unix).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("file written")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "filter file must be 0600");
        }

        // A fresh instance loads the persisted set.
        let reloaded = FileSavedFilterStore::new(path.clone());
        assert_eq!(reloaded.list(), store.list());
        assert_eq!(reloaded.list()[0].name, "errors");

        // Removal persists too.
        let mut writable = reloaded;
        assert!(writable.remove("errors"));
        let after = FileSavedFilterStore::new(path);
        assert_eq!(after.list().len(), 1);
        assert_eq!(after.list()[0].name, "llm");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::feed::{BodyViewDto, LlmSummaryDto};

    fn summary(seq: u64, method: &str, path: &str, status: u16) -> FlowSummaryDto {
        FlowSummaryDto {
            sequence: seq,
            started_at: "2026-08-22T01:02:03.400Z".to_string(),
            method: method.to_string(),
            path: path.to_string(),
            host: Some("Api.Example.com".to_string()),
            status: Some(status),
            duration_ms: Some(9.0),
            kind: "http".to_string(),
            llm: None,
        }
    }

    fn llm_summary(
        seq: u64,
        path: &str,
        provider: &str,
        model: Option<&str>,
        status: u16,
    ) -> FlowSummaryDto {
        let mut flow = summary(seq, "POST", path, status);
        flow.llm = Some(LlmSummaryDto {
            provider: provider.to_string(),
            model: model.map(str::to_string),
            input_tokens: Some(10),
            output_tokens: None,
            total_tokens: None,
        });
        flow
    }

    fn detail(body_text: &str) -> FlowDetailDto {
        FlowDetailDto {
            summary: summary(1, "GET", "/x", 200),
            request_headers: Default::default(),
            response_headers: Default::default(),
            request_body: BodyViewDto {
                available: true,
                encoding: Some("utf8".to_string()),
                text: Some(body_text.to_string()),
                total_size: body_text.len() as u64,
                truncated: false,
            },
            response_body: BodyViewDto::unavailable(),
        }
    }

    fn matches(expr: &str, flow: &FlowSummaryDto) -> bool {
        Filter::parse(expr)
            .expect("test expression parses")
            .matches_summary(flow)
    }

    #[test]
    fn equality_and_class_predicates() {
        let ok = summary(1, "GET", "/v1/models", 204);
        assert!(matches("method=GET", &ok));
        assert!(
            matches("method=get", &ok),
            "method compare is case-insensitive"
        );
        assert!(!matches("method=POST", &ok));
        assert!(matches("status=2xx", &ok));
        assert!(matches("status=204", &ok));
        assert!(!matches("status=404", &ok));
        assert!(matches("status!=404", &ok));
        assert!(matches("status>=200", &ok));
        assert!(!matches("status>=500", &ok));
        assert!(matches("status<300", &ok));
        // Host comparison is case-insensitive.
        assert!(matches("host=api.example.com", &ok));
        assert!(!matches("host=other.com", &ok));
    }

    #[test]
    fn ordering_forms_from_task_examples() {
        let err = summary(2, "GET", "/err", 502);
        let missing = summary(3, "GET", "/gone", 404);
        assert!(matches("status>=500", &err));
        assert!(!matches("status>=500", &missing));
        assert!(matches("status=5xx", &err));
        assert!(matches("status=4xx", &missing));
        // Invalid class digits are parse errors, not silent mismatches.
        assert!(Filter::parse("status=6xx").is_err());
        assert!(Filter::parse("status>=2xx").is_err());
    }

    #[test]
    fn glob_substring_and_provider_model_keys() {
        let deep = llm_summary(
            4,
            "/v1/messages/stream",
            "anthropic",
            Some("claude-sonnet-4"),
            200,
        );
        let plain = summary(5, "GET", "/healthz", 200);

        assert!(matches("path~/v1/**", &deep));
        assert!(matches("path~/v1/*/stream", &deep));
        assert!(!matches("path~/v1/**", &plain));

        assert!(matches("provider=anthropic", &deep));
        assert!(matches("model~claude", &deep));
        assert!(!matches("provider=openai", &deep));
        // Flows without an LLM block never match provider/model predicates.
        assert!(!matches("provider=anthropic", &plain));
        assert!(!matches("model~claude", &plain));
    }

    #[test]
    fn free_text_spans_method_path_host() {
        let flow = summary(6, "GET", "/v1/models", 200);
        assert!(matches("models", &flow));
        assert!(matches("example.com", &flow));
        assert!(!matches("nomatch", &flow));
    }

    #[test]
    fn body_predicate_needs_resolved_detail() {
        let flow = summary(7, "GET", "/x", 200);
        assert!(!matches("body~needle", &flow));
        let with_detail = detail("payload with needle inside");
        assert!(Filter::parse("body~needle")
            .expect("parses")
            .matches(&FilterInput {
                summary: &with_detail.summary,
                detail: Some(&with_detail),
            }));
    }

    #[test]
    fn implicit_and_or_keyword_and_parens() {
        let a = summary(1, "GET", "/a", 200);
        let b = summary(2, "POST", "/b", 500);

        assert!(matches("method=GET status=2xx", &a));
        assert!(!matches("method=GET status=2xx", &b));

        assert!(matches("method=GET OR status>=500", &a));
        assert!(matches("method=GET OR status>=500", &b));
        let c = summary(3, "POST", "/c", 200);
        assert!(!matches("method=GET OR status>=500", &c));

        // Parens group OR below AND.
        assert!(matches("(method=POST OR status>=500) path=/b", &b));
        assert!(!matches("(method=POST OR status>=500) path=/b", &c));
        // `or` keyword is case-insensitive; a bareword hits method/path/host.
        assert!(matches("/a", &a));
        assert!(matches("GET", &a));
    }

    #[test]
    fn quoted_values_allow_spaces() {
        let flow = summary(8, "GET", "/some path here", 200);
        assert!(matches("path~\"/some*\"", &flow));
        assert!(!matches("path~/nomatch*", &flow));
    }

    #[test]
    fn error_cases_carry_position_and_help() {
        // Unknown key points at the key's byte position.
        let err = Filter::parse("colour=red").unwrap_err();
        assert_eq!(err.position, 0);
        assert!(
            err.message.contains("unknown filter key"),
            "{}",
            err.message
        );
        assert!(err.help.contains("known keys"), "{}", err.render());

        // Unbalanced paren reports the end position.
        let err = Filter::parse("(status=200").unwrap_err();
        assert!(err.message.contains("unbalanced"), "{}", err.message);

        // Missing value after an operator fails loudly.
        let err = Filter::parse("path~").unwrap_err();
        assert!(err.message.contains("missing value"), "{}", err.message);
        assert!(Filter::parse("status=").is_err());
        assert!(Filter::parse("OR status=200").is_err());
        assert!(Filter::parse("status=200 )").is_err());

        // Ordering operators are rejected on non-numeric keys.
        assert!(Filter::parse("method>GET").is_err());
    }

    #[test]
    fn query_string_round_trip_stable_for_simple_terms() {
        let filter = Filter::parse("method=POST status>=500").expect("parses");
        assert_eq!(filter.to_query_string(), "method=POST status>=500");

        let or_filter = Filter::parse("method=POST OR status>=500").expect("parses");
        assert_eq!(or_filter.to_query_string(), "(method=POST OR status>=500)");
    }

    #[test]
    fn saved_filter_store_persists_to_file() {
        let dir = std::env::temp_dir().join(format!(
            "arbiter-filter-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("saved-filters.json");

        let mut store = InMemorySavedFilterStore::with_file(path.clone());
        store.save(SavedFilter {
            name: "errors".to_string(),
            query: "status>=500".to_string(),
        });
        // Reload from disk through a fresh instance (file hook round-trip).
        let reloaded = InMemorySavedFilterStore::load_from(&path);
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.list()[0].name, "errors");
        assert!(store.remove("errors"));
        assert!(!store.remove("errors"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
