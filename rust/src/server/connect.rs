//! CONNECT handling: authority parsing, passthrough rules and the raw byte
//! pump for tunnels we do not intercept.
//!
//! Passthrough globs are compiled once at startup from `--tls-passthrough`
//! via the AMEND-1 glob library ([`crate::mock::matcher`], case-insensitive
//! host semantics). Matching compares the full `host:port` authority AND
//! the bare host, so `*.example.com` matches `api.example.com:443` while
//! `host:*` still works on the full form — the port is preserved, never
//! normalized away.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::mock::matcher::{compile_host_glob, GlobPattern};

/// Parsed CONNECT authority (`host:port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAuthority {
    pub host: String,
    pub port: u16,
}

/// Parse a CONNECT request-line authority. A missing port defaults to 443
/// (the overwhelmingly common HTTPS CONNECT); anything present must be a
/// valid port number.
pub fn parse_authority(authority: &str) -> Result<ConnectAuthority> {
    let s = authority.trim();
    if s.is_empty() {
        return Err(Error::other(
            "empty CONNECT authority\n  help: the CONNECT request line must carry 'host:port'",
        ));
    }

    // IPv6 literal: [::1]:8443
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| {
            Error::other(format!(
                "malformed IPv6 CONNECT authority '{s}'\n  help: bracket the host, e.g. '[::1]:443'"
            ))
        })?;
        let host = &rest[..close];
        if host.is_empty() {
            return Err(Error::other(format!(
                "empty IPv6 host in CONNECT authority '{s}'"
            )));
        }
        let port = parse_optional_port(&rest[close + 1..], s)?;
        return Ok(ConnectAuthority {
            host: host.to_string(),
            port,
        });
    }

    match s.rsplit_once(':') {
        None => Ok(ConnectAuthority { host: s.to_string(), port: 443 }),
        Some((host, "")) => Ok(ConnectAuthority { host: host.to_string(), port: 443 }),
        Some((host, digits)) if digits.bytes().all(|b| b.is_ascii_digit()) => {
            let port = digits.parse::<u16>().map_err(|_| {
                Error::other(format!(
                    "CONNECT port out of range in '{s}'\n  help: ports must be 0-65535"
                ))
            })?;
            if host.is_empty() {
                return Err(Error::other(format!(
                    "empty host in CONNECT authority '{s}'\n  help: the CONNECT line must carry 'host:port', e.g. 'api.example.com:443'"
                )));
            }
            Ok(ConnectAuthority { host: host.to_string(), port })
        }
        Some((_, junk)) => Err(Error::other(format!(
            "invalid CONNECT port '{junk}' in authority '{s}'\n  help: use numeric 'host:port', e.g. 'api.example.com:443'"
        ))),
    }
}

fn parse_optional_port(rest: &str, full: &str) -> Result<u16> {
    let digits = rest.strip_prefix(':').unwrap_or(rest);
    if digits.is_empty() {
        return Ok(443);
    }
    digits.parse::<u16>().map_err(|_| {
        Error::other(format!(
            "invalid CONNECT port '{digits}' in authority '{full}'\n  help: ports must be 0-65535"
        ))
    })
}

/// What to do with a CONNECT tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectAction {
    /// Terminate TLS locally and serve decrypted HTTP through the pipeline.
    Intercept,
    /// Reply 200 and pump raw bytes to the real upstream, untouched.
    Passthrough,
}

/// Compiled `--tls-passthrough` rules.
#[derive(Debug, Clone, Default)]
pub struct PassthroughRules {
    globs: Vec<GlobPattern>,
}

impl PassthroughRules {
    /// Compile patterns once at startup; a bad pattern fails fast with a
    /// `help:` line (DX bar).
    pub fn compile(patterns: &[String]) -> Result<Self> {
        let mut globs = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            if pattern.trim().is_empty() {
                return Err(Error::other(
                    "empty --tls-passthrough pattern\n  help: use host globs like '*.internal.example.com' or 'host:*'",
                ));
            }
            globs.push(compile_host_glob(pattern).map_err(|e| {
                Error::other(format!(
                    "invalid --tls-passthrough pattern '{pattern}': {e}\n  help: use host globs like '*.internal.example.com' or 'host:*'"
                ))
            })?);
        }
        Ok(PassthroughRules { globs })
    }

    /// True when no rules are configured (every CONNECT is intercepted).
    pub fn is_empty(&self) -> bool {
        self.globs.is_empty()
    }

    /// The underlying compiled globs (for diagnostics/wiring).
    pub fn globs(&self) -> &[GlobPattern] {
        &self.globs
    }

    /// Case-insensitive host match with the port preserved: the full
    /// `host:port` authority and the bare host are both offered to every
    /// pattern, so host globs and `host:*` port globs both behave as
    /// users expect.
    pub fn matches(&self, authority: &str) -> bool {
        if self.globs.is_empty() {
            return false;
        }
        let auth = authority.trim();
        if auth.is_empty() {
            return false;
        }
        if self.globs.iter().any(|g| g.is_match(auth)) {
            return true;
        }
        match bare_host(auth) {
            Some(bare) if bare != auth => self.globs.iter().any(|g| g.is_match(bare)),
            _ => false,
        }
    }
}

/// Strip a numeric `:port` suffix (IPv6-bracket aware) without failing on
/// odd input — used only for the secondary bare-host match attempt.
fn bare_host(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        return Some(&rest[..close + 1]);
    }
    match authority.rsplit_once(':') {
        Some((host, digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(host)
        }
        _ => None,
    }
}

/// Decide the action for a CONNECT authority against the compiled rules.
pub fn decide(rules: &PassthroughRules, authority: &str) -> ConnectAction {
    if rules.matches(authority) {
        ConnectAction::Passthrough
    } else {
        ConnectAction::Intercept
    }
}

/// Pump raw bytes both ways until either side closes. Returns
/// `(client_to_upstream, upstream_to_client)` byte counts.
pub async fn pump_passthrough<A, B>(client: &mut A, upstream: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .map_err(|e| Error::io("CONNECT passthrough tunnel pump", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(patterns: &[&str]) -> PassthroughRules {
        PassthroughRules::compile(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("valid patterns")
    }

    #[test]
    fn parses_authorities() {
        let a = parse_authority("api.example.com:8443").unwrap();
        assert_eq!(
            a,
            ConnectAuthority {
                host: "api.example.com".into(),
                port: 8443
            }
        );
        assert_eq!(parse_authority("api.example.com").unwrap().port, 443);
        assert_eq!(parse_authority("[::1]:9000").unwrap().host, "::1");
        assert_eq!(
            parse_authority("  localhost:1  ").unwrap().host,
            "localhost"
        );
    }

    #[test]
    fn rejects_bad_authorities_with_help() {
        for bad in ["", "   ", "host:port", "host:99999", "[::1", ":443"] {
            let err = parse_authority(bad).unwrap_err().to_string();
            assert!(
                err.contains("help:"),
                "'{bad}' error must carry help: {err}"
            );
        }
    }

    #[test]
    fn decision_matrix() {
        let r = rules(&["*.internal.example.com", "localhost:*", "exact.host"]);
        let d = |a: &str| decide(&r, a);

        // host globs match across ports, case-insensitively
        assert_eq!(
            d("api.internal.example.com:443"),
            ConnectAction::Passthrough
        );
        assert_eq!(d("API.INTERNAL.EXAMPLE.COM"), ConnectAction::Passthrough);
        assert_eq!(d("internal.example.com:443"), ConnectAction::Intercept);

        // port-preserved glob on the full authority
        assert_eq!(d("localhost:8443"), ConnectAction::Passthrough);
        assert_eq!(
            d("localhost"),
            ConnectAction::Intercept,
            "host:* needs a port"
        );

        // Hostile lookalikes must NOT match: mock::matcher anchors the last
        // chunk to the segment suffix (and single chunks are exact), so a
        // name that merely CONTAINS the glob suffix is intercepted.
        assert_eq!(
            d("evil.internal.example.com.attacker.test:443"),
            ConnectAction::Intercept
        );
        assert_eq!(
            d("exact.host.evil.com:443"),
            ConnectAction::Intercept,
            "single-chunk patterns are exact"
        );
        assert_eq!(d("exact.host:443"), ConnectAction::Passthrough);
        assert_eq!(d("exact.host"), ConnectAction::Passthrough);
        assert_eq!(d("notexact.host:443"), ConnectAction::Intercept);

        // empty rules intercept everything
        let empty = PassthroughRules::default();
        assert_eq!(decide(&empty, "anything.com:443"), ConnectAction::Intercept);
        assert!(empty.is_empty());
    }

    #[test]
    fn bad_pattern_fails_fast_with_help() {
        let err = PassthroughRules::compile(&["  ".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("help:"), "{err}");
    }
}
