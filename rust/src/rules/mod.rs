//! Traffic modification rules and hooks (W6).
//!
//! This module hosts the ordered header-rewrite engine applied to both
//! directions of the live proxy (and to mock responses). It is a pure,
//! deterministic function set over [`crate::types::HeaderMapValues`]: no I/O,
//! no clocks, no RNG, so identical input headers always produce identical
//! output regardless of environment.
//!
//! Pipeline position (AMEND-12): the proxy pipeline runs
//! `fault gate -> request hooks -> request header rules -> upstream ->
//! tee-pump -> response header rules -> response hooks -> client`.
//! Header rules apply AFTER hop-by-hop stripping
//! ([`crate::headers::forwardable_headers`]), so rewritten headers are always
//! end-to-end headers.
//!
//! The scripting-hook half of W6 lives in [`hooks`].
//!
//! # Determinism and semantics
//!
//! Ops apply strictly in declaration order, top to bottom. Header names are
//! matched case-insensitively (lowercased, matching the capture model):
//!
//! - [`HeaderOp::Set`] replaces ALL values of the target name with one value.
//! - [`HeaderOp::Append`] adds a value after any existing values.
//! - [`HeaderOp::Remove`] drops the header and every duplicate value.
//! - [`HeaderOp::Rename`] moves all values of `from` onto `to` (appended if
//!   `to` already exists) and deletes `from`.
//!
//! # Errors
//!
//! Malformed CLI specs fail at startup with a cause line plus a `  help:`
//! hint quoting the offending spec — never a per-request panic.

pub mod hooks;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::HeaderMapValues;

/// One ordered header rewrite operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", rename_all_fields = "camelCase")]
pub enum HeaderOp {
    /// Insert or overwrite: all existing values of `name` collapse to `value`.
    Set { name: String, value: String },
    /// Add `value` after any existing values of `name`.
    Append { name: String, value: String },
    /// Drop `name` and all of its duplicate values.
    Remove { name: String },
    /// Move all values of `from` onto `to`, deleting `from`. Values appended
    /// if `to` already exists; renaming a name onto itself is a no-op.
    Rename { from: String, to: String },
}

/// Which pipeline leg a [`HeaderRuleSet`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApplyPhase {
    /// Pre-upstream, before the request leaves for the target.
    Request,
    /// Pre-client, after the tee-pump snapshot, before delivery.
    Response,
}

/// An ordered set of header operations for one pipeline phase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderRuleSet {
    pub ops: Vec<HeaderOp>,
    pub apply_phase: ApplyPhase,
}

impl HeaderRuleSet {
    pub fn new(ops: Vec<HeaderOp>, apply_phase: ApplyPhase) -> Self {
        Self { ops, apply_phase }
    }

    /// Hot-path short circuit: an empty set skips the rewrite pass entirely.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Apply every op in declaration order. Pure: deterministic output for
    /// identical inputs; never panics on external input.
    pub fn apply(&self, headers: &mut HeaderMapValues) {
        for op in &self.ops {
            match op {
                HeaderOp::Set { name, value } => {
                    headers.insert(name.to_lowercase(), vec![value.clone()]);
                }
                HeaderOp::Append { name, value } => {
                    headers
                        .entry(name.to_lowercase())
                        .or_default()
                        .push(value.clone());
                }
                HeaderOp::Remove { name } => {
                    headers.remove(name.to_lowercase().as_str());
                }
                HeaderOp::Rename { from, to } => {
                    let from_lower = from.to_lowercase();
                    let to_lower = to.to_lowercase();
                    if let Some(values) = headers.remove(from_lower.as_str()) {
                        if from_lower == to_lower {
                            // Rename onto itself: keep original order intact.
                            headers.insert(to_lower, values);
                        } else {
                            headers.entry(to_lower).or_default().extend(values);
                        }
                    }
                }
            }
        }
    }

    /// Parse repeatable CLI specs into a request-phase rule set. Each entry
    /// takes one of the forms:
    ///
    /// ```text
    /// set:X-Foo=bar      append:X-Foo=bar      remove:X-Foo      rename:Old=New
    /// ```
    ///
    /// Values may contain `=`; names may not. Names are lowercased at parse
    /// time so lookup cost at request time is a plain map hit. Malformed
    /// entries return an error whose message carries the bad spec plus a
    /// `  help:` hint line (surfaced verbatim by the CLI layer).
    pub fn parse_rules(specs: &[String]) -> Result<Self> {
        Self::parse_rules_for(ApplyPhase::Request, specs)
    }

    /// Like [`parse_rules`](Self::parse_rules) with an explicit phase;
    /// used by response-direction flags.
    pub fn parse_rules_for(apply_phase: ApplyPhase, specs: &[String]) -> Result<Self> {
        let mut ops = Vec::with_capacity(specs.len());
        for spec in specs {
            ops.push(parse_one(spec)?);
        }
        Ok(Self { ops, apply_phase })
    }

    /// Build the typed pair cli-dx wires into the proxy: request specs become
    /// the pre-upstream set, response specs the pre-client set. Invalid
    /// entries abort startup with cause + help.
    pub fn from_cli(request_specs: &[String], response_specs: &[String]) -> Result<(Self, Self)> {
        Ok((
            Self::parse_rules_for(ApplyPhase::Request, request_specs)?,
            Self::parse_rules_for(ApplyPhase::Response, response_specs)?,
        ))
    }
}

/// Parse one `"kind:argument"` spec into a [`HeaderOp`].
fn parse_one(spec: &str) -> Result<HeaderOp> {
    const HELP: &str = "expected 'set:Name=Value', 'append:Name=Value', \
                        'remove:Name', or 'rename:Old=New' (e.g. --set-header 'x-debug=1')";
    let invalid = || Error::other(format!("invalid header rule '{spec}'\n  help: {HELP}"));
    let Some((kind, rest)) = spec.split_once(':') else {
        return Err(invalid());
    };
    match kind.trim().to_lowercase().as_str() {
        "set" | "append" => {
            let Some((name, value)) = rest.split_once('=') else {
                return Err(invalid());
            };
            let name = validate_name(name, spec)?;
            if kind.eq_ignore_ascii_case("set") {
                Ok(HeaderOp::Set {
                    name,
                    value: value.to_string(),
                })
            } else {
                Ok(HeaderOp::Append {
                    name,
                    value: value.to_string(),
                })
            }
        }
        "remove" => {
            if rest.contains('=') || rest.contains(':') {
                return Err(invalid());
            }
            Ok(HeaderOp::Remove {
                name: validate_name(rest, spec)?,
            })
        }
        "rename" | "map" => {
            let Some((from, to)) = rest.split_once('=') else {
                return Err(invalid());
            };
            Ok(HeaderOp::Rename {
                from: validate_name(from, spec)?,
                to: validate_name(to, spec)?,
            })
        }
        _ => Err(invalid()),
    }
}

/// Reject empty or whitespace-only header names early so startup fails loud
/// instead of silently matching nothing at request time.
fn validate_name(name: &str, spec: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::other(format!(
            "invalid header rule '{spec}': empty header name\n  help: \
             give the header a non-empty name, e.g. 'set:x-trace-id=1'"
        )));
    }
    Ok(trimmed.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn specs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_every_op_form_and_normalizes_names() {
        let set = HeaderRuleSet::parse_rules(&specs(&[
            "set:X-Foo=bar",
            "append:X-Foo=baz",
            "remove: X-Drop ",
            "rename:Old-Name=New-Name",
        ]))
        .expect("valid specs");
        assert_eq!(
            set.ops,
            vec![
                HeaderOp::Set {
                    name: "x-foo".into(),
                    value: "bar".into()
                },
                HeaderOp::Append {
                    name: "x-foo".into(),
                    value: "baz".into()
                },
                HeaderOp::Remove {
                    name: "x-drop".into()
                },
                HeaderOp::Rename {
                    from: "old-name".into(),
                    to: "new-name".into()
                },
            ]
        );
        assert_eq!(set.apply_phase, ApplyPhase::Request);
    }

    #[test]
    fn values_may_contain_equals() {
        let parsed =
            HeaderRuleSet::parse_rules(&specs(&["set:x-a=b=c=d"])).expect("value keeps '='");
        assert_eq!(
            parsed.ops[0],
            HeaderOp::Set {
                name: "x-a".into(),
                value: "b=c=d".into()
            }
        );
    }

    #[test]
    fn invalid_forms_carry_cause_and_help() {
        let cases = [
            "x-foo=bar",          // missing kind prefix
            "upsert:x-a=b",       // unknown kind
            "set:no-equals-sign", // set without '='
            "append:=bare-value", // empty name
            "remove:a=b",         // remove takes a bare name
            "rename:OnlyOne",     // rename needs Old=New
            "",                   // nothing at all
        ];
        for case in cases {
            let err = HeaderRuleSet::parse_rules(&specs(&[case])).expect_err(case);
            let msg = err.to_string();
            assert!(msg.contains(case), "{case}: message lost the spec: {msg}");
            assert!(
                msg.contains("\n  help: "),
                "{case}: missing help line: {msg}"
            );
        }
    }

    #[test]
    fn applies_in_declaration_order_set_remove_rename() {
        // Declaration order decides the outcome: the later Set wins over the
        // earlier Append, Remove erases everything earlier targeting x-drop,
        // and Rename relocates surviving values.
        let rules = HeaderRuleSet::parse_rules(&specs(&[
            "set:x-mode=first",
            "append:x-mode=second",
            "set:x-mode=final",
            "remove:x-drop",
            "rename:x-old=x-new",
        ]))
        .expect("valid");

        let mut headers: HeaderMapValues = BTreeMap::new();
        headers.insert("x-drop".into(), vec!["gone".into()]);
        headers.insert("x-old".into(), vec!["v1".into(), "v2".into()]);

        rules.apply(&mut headers);

        assert_eq!(headers.get("x-mode"), Some(&vec!["final".to_string()]));
        assert!(!headers.contains_key("x-drop"));
        assert!(!headers.contains_key("x-old"));
        assert_eq!(
            headers.get("x-new"),
            Some(&vec!["v1".to_string(), "v2".to_string()])
        );
    }

    #[test]
    fn rename_onto_existing_appends_and_self_rename_is_noop() {
        let rules = HeaderRuleSet::parse_rules(&specs(&["rename:x-src=x-dst"])).unwrap();

        let mut headers: HeaderMapValues = BTreeMap::new();
        headers.insert("x-src".into(), vec!["a".into()]);
        headers.insert("x-dst".into(), vec!["keep".into()]);
        rules.apply(&mut headers);
        assert!(!headers.contains_key("x-src"));
        assert_eq!(
            headers.get("x-dst"),
            Some(&vec!["keep".to_string(), "a".to_string()])
        );

        let self_rules = HeaderRuleSet::parse_rules(&specs(&["rename:x-same=x-same"])).unwrap();
        let mut same: HeaderMapValues = BTreeMap::new();
        same.insert("x-same".into(), vec!["1".into(), "2".into()]);
        self_rules.apply(&mut same);
        assert_eq!(
            same.get("x-same"),
            Some(&vec!["1".to_string(), "2".to_string()])
        );
    }

    #[test]
    fn append_creates_missing_header_and_remove_drops_duplicates() {
        let rules =
            HeaderRuleSet::parse_rules(&specs(&["append:x-add=lone", "remove:x-multi"])).unwrap();
        let mut headers: HeaderMapValues = BTreeMap::new();
        headers.insert("x-multi".into(), vec!["a".into(), "b".into()]);
        rules.apply(&mut headers);
        assert_eq!(headers.get("x-add"), Some(&vec!["lone".to_string()]));
        assert!(!headers.contains_key("x-multi"));
    }

    #[test]
    fn from_cli_splits_request_and_response_phases() {
        let (req, resp) = HeaderRuleSet::from_cli(
            &specs(&["set:x-req=1"]),
            &specs(&["remove:x-server", "set:x-resp=ok"]),
        )
        .expect("valid");
        assert_eq!(req.apply_phase, ApplyPhase::Request);
        assert_eq!(req.ops.len(), 1);
        assert_eq!(resp.apply_phase, ApplyPhase::Response);
        assert_eq!(resp.ops.len(), 2);
        assert!(!req.is_empty() && !resp.is_empty());
    }

    #[test]
    fn from_cli_propagates_invalid_spec_with_help() {
        let err = HeaderRuleSet::from_cli(&specs(&["set:broken"]), &[]).expect_err("bad");
        assert!(err.to_string().contains("help: "));
    }
}
