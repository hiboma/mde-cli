use clap::Parser;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use crate::auth::StaticTokenAuth;
use crate::auth::oauth2::OAuth2Auth;
use crate::cli::{Cli, Commands};
use crate::client::MdeClient;
use crate::config::MdeCredentials;
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
/// Credentials are provided via `MdeCredentials` instead of environment variables.
pub async fn dispatch_from_args(
    args: &[String],
    credentials: &MdeCredentials,
) -> Result<String, AppError> {
    let cli = Cli::try_parse_from(args).map_err(|e| AppError::InvalidInput(e.to_string()))?;

    let command = match cli.command {
        Some(command) => command,
        None => return Ok(String::new()),
    };

    let mde_base_url = credentials.mde_base_url.clone();
    let graph_base_url = credentials.graph_base_url.clone();

    let build_mde_client = |base_url: &str, scope: &str| -> Result<MdeClient, AppError> {
        if let Some(ref token) = credentials.access_token {
            let auth = StaticTokenAuth(token.clone());
            return MdeClient::new(base_url.to_string(), Box::new(auth));
        }

        let tenant_id = credentials.tenant_id.as_ref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;

        let client_id = credentials.client_id.as_ref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;

        let client_secret = credentials.client_secret.as_ref().ok_or_else(|| {
            AppError::Config(
                "client_secret not set. Set MDE_CLIENT_SECRET env var or credentials.toml."
                    .to_string(),
            )
        })?;

        let auth = OAuth2Auth::new(
            tenant_id.clone(),
            client_id.clone(),
            client_secret.clone(),
            scope.to_string(),
        )?;
        MdeClient::new(base_url.to_string(), Box::new(auth))
    };

    dispatch_command(
        &command,
        cli.output,
        cli.raw,
        &mde_base_url,
        &graph_base_url,
        build_mde_client,
    )
    .await
}

/// Dispatch a command and capture its output as a string.
/// Uses a mutex to serialize stdout capture across concurrent requests.
async fn dispatch_command<F>(
    command: &Commands,
    output_format: crate::output::OutputFormat,
    raw: bool,
    mde_base_url: &str,
    graph_base_url: &str,
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
                mde_base_url,
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            crate::commands::alerts::handle(&client, cmd, output_format, raw).await
        }
        Commands::Incidents { command: Some(cmd) } => {
            let client = build_mde_client(graph_base_url, "https://graph.microsoft.com/.default")?;
            crate::commands::incidents::handle(&client, cmd, output_format, raw).await
        }
        Commands::Hunting { command: Some(cmd) } => {
            let client = build_mde_client(graph_base_url, "https://graph.microsoft.com/.default")?;
            crate::commands::hunting::handle(&client, cmd, output_format).await
        }
        Commands::Machines { command: Some(cmd) } => {
            let client = build_mde_client(
                mde_base_url,
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            crate::commands::machines::handle(&client, cmd, output_format, raw).await
        }
        Commands::Indicators { command: Some(cmd) } => {
            let client = build_mde_client(
                mde_base_url,
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            crate::commands::indicators::handle(&client, cmd, output_format, raw).await
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
