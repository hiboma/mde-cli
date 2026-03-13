use clap::Parser;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use crate::auth::StaticTokenAuth;
use crate::auth::oauth2::OAuth2Auth;
use crate::cli::{Cli, Commands};
use crate::client::MdeClient;
use crate::config::Config;
use crate::error::AppError;

/// Global mutex to serialize stdout capture across concurrent requests.
/// gag::BufferRedirect operates on process-level fd 1, so only one
/// capture can be active at a time.
static STDOUT_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn stdout_mutex() -> &'static Mutex<()> {
    STDOUT_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Dispatch a command from a CLI args vector (used by agent handler).
/// Captures stdout output and returns it as a string.
pub async fn dispatch_from_args(args: &[String]) -> Result<String, AppError> {
    let cli = Cli::try_parse_from(args).map_err(|e| AppError::InvalidInput(e.to_string()))?;

    let command = match cli.command {
        Some(command) => command,
        None => return Ok(String::new()),
    };

    let config = Config::load().unwrap_or_default();
    let access_token = std::env::var("MDE_ACCESS_TOKEN").ok();

    let build_mde_client = |base_url: &str, scope: &str| -> Result<MdeClient, AppError> {
        if let Some(ref token) = access_token {
            let auth = StaticTokenAuth(token.clone());
            return MdeClient::new(base_url.to_string(), Box::new(auth));
        }

        let tenant_id = cli
            .tenant_id
            .as_deref()
            .map(String::from)
            .or_else(|| std::env::var("MDE_TENANT_ID").ok())
            .or_else(|| config.auth.tenant_id.clone())
            .ok_or_else(|| {
                AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
            })?;

        let client_id = cli
            .client_id
            .as_deref()
            .map(String::from)
            .or_else(|| std::env::var("MDE_CLIENT_ID").ok())
            .or_else(|| config.auth.client_id.clone())
            .ok_or_else(|| {
                AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
            })?;

        let client_secret = std::env::var("MDE_CLIENT_SECRET")
            .ok()
            .or_else(|| config.auth.client_secret.clone())
            .ok_or_else(|| {
                AppError::Config(
                    "client_secret not set. Set MDE_CLIENT_SECRET env var or config.toml [auth].client_secret."
                        .to_string(),
                )
            })?;

        let auth = OAuth2Auth::new(tenant_id, client_id, client_secret, scope.to_string())?;
        MdeClient::new(base_url.to_string(), Box::new(auth))
    };

    dispatch_command(&command, cli.output, cli.raw, build_mde_client).await
}

/// Dispatch a command and capture its output as a string.
/// Uses a mutex to serialize stdout capture across concurrent requests.
async fn dispatch_command<F>(
    command: &Commands,
    output_format: crate::output::OutputFormat,
    raw: bool,
    build_mde_client: F,
) -> Result<String, AppError>
where
    F: Fn(&str, &str) -> Result<MdeClient, AppError>,
{
    // Acquire mutex to prevent concurrent stdout captures.
    let _guard = stdout_mutex().lock().await;

    // Redirect stdout to capture output.
    let buf = gag::BufferRedirect::stdout()
        .map_err(|e| AppError::Config(format!("failed to capture stdout: {}", e)))?;

    let result = match command {
        Commands::Alerts { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            crate::commands::alerts::handle(&client, cmd, output_format, raw).await
        }
        Commands::Incidents { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://graph.microsoft.com",
                "https://graph.microsoft.com/.default",
            )?;
            crate::commands::incidents::handle(&client, cmd, output_format, raw).await
        }
        Commands::Hunting { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            crate::commands::hunting::handle(&client, cmd, output_format).await
        }
        Commands::Machines { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            crate::commands::machines::handle(&client, cmd, output_format, raw).await
        }
        _ => Ok(()),
    };

    // Read captured output.
    let mut output = String::new();
    use std::io::Read;
    let mut reader = buf;
    reader
        .read_to_string(&mut output)
        .map_err(|e| AppError::Config(format!("failed to read captured output: {}", e)))?;

    // _guard is dropped here, releasing the mutex.
    result?;
    Ok(output)
}
