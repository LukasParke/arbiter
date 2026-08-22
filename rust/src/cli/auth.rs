//! `arbiter auth` (port of src/commands/auth.ts).

use clap::Args;
use clap::Subcommand;

use super::fail;
use crate::auth::{AuthConfig, AuthManager, AuthType};

/// Manage authentication tokens for API requests
#[derive(Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Save an authentication token
    Set {
        /// the authentication token
        #[arg(long = "token")]
        token: String,

        /// auth type: plex-token, bearer, api-key
        #[arg(long = "type", default_value = "plex-token")]
        auth_type: String,

        /// header name for api-key auth
        #[arg(long = "header")]
        header: Option<String>,
    },
    /// Remove saved authentication token
    Clear,
    /// Show current authentication status
    Show,
}

pub fn run(args: &AuthArgs) -> i32 {
    match &args.command {
        AuthCommand::Set {
            token,
            auth_type,
            header,
        } => {
            let parsed_type = parse_auth_type(auth_type);
            let config = AuthConfig {
                auth_type: parsed_type,
                token: token.clone(),
                header_name: header.clone(),
                query_param_name: None,
            };
            let manager = AuthManager::from_config(config);
            manager.save_to_disk().ok();
            println!("Authentication token saved");
            println!("  Type: {auth_type}");
            println!("  Token: {}", manager.redacted_token());
        }
        AuthCommand::Clear => {
            let manager = AuthManager::from_config(AuthConfig {
                auth_type: AuthType::PlexToken,
                token: String::new(),
                header_name: None,
                query_param_name: None,
            });
            manager.save_to_disk().ok();
            println!("Authentication token cleared");
        }
        AuthCommand::Show => {
            let manager = AuthManager::new();
            if manager.is_authenticated() {
                println!("Authenticated");
                println!("  Token: {}", manager.redacted_token());
            } else {
                println!("No authentication token configured");
                println!("Run: arbiter auth set --token <your-token>");
            }
        }
    }
    0
}

fn parse_auth_type(raw: &str) -> AuthType {
    match raw {
        "plex-token" => AuthType::PlexToken,
        "bearer" => AuthType::Bearer,
        "api-key" => AuthType::ApiKey,
        other => fail(format!(
            "Invalid --type '{other}' (expected plex-token, bearer, or api-key)"
        )),
    }
}
