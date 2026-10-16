use clap::Parser;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use crate::auth::resource::{GRAPH_SCOPE, MDE_SCOPE, build_mde_client};
use crate::cli::{Cli, Commands};
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

    dispatch_command(&command, cli.output, cli.raw, credentials).await
}

/// Dispatch a command and capture its output as a string.
/// Uses a mutex to serialize stdout capture across concurrent requests.
async fn dispatch_command(
    command: &Commands,
    output_format: crate::output::OutputFormat,
    raw: bool,
    credentials: &MdeCredentials,
) -> Result<String, AppError> {
    // Acquire mutex to prevent concurrent stdout captures.
    let _guard = stdout_mutex().lock().await;

    // Redirect stdout to capture output.
    let buf = gag::BufferRedirect::stdout()
        .map_err(|e| AppError::Config(format!("failed to capture stdout: {}", e)))?;

    let result = match command {
        Commands::Alerts { command: Some(cmd) } => {
            let client =
                build_mde_client(credentials, &credentials.mde_base_url, MDE_SCOPE).await?;
            crate::commands::alerts::handle(&client, cmd, output_format, raw).await
        }
        Commands::Incidents { command: Some(cmd) } => {
            let client =
                build_mde_client(credentials, &credentials.graph_base_url, GRAPH_SCOPE).await?;
            crate::commands::incidents::handle(&client, cmd, output_format, raw).await
        }
        Commands::Hunting { command: Some(cmd) } => {
            let client =
                build_mde_client(credentials, &credentials.graph_base_url, GRAPH_SCOPE).await?;
            crate::commands::hunting::handle(&client, cmd, output_format).await
        }
        Commands::Machines { command: Some(cmd) } => {
            let client =
                build_mde_client(credentials, &credentials.mde_base_url, MDE_SCOPE).await?;
            crate::commands::machines::handle(&client, cmd, output_format, raw).await
        }
        Commands::Indicators { command: Some(cmd) } => {
            let client =
                build_mde_client(credentials, &credentials.mde_base_url, MDE_SCOPE).await?;
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
