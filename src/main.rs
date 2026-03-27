use clap::{CommandFactory, Parser};
use std::path::PathBuf;
use std::process;

use mde::auth::StaticTokenAuth;
use mde::auth::oauth2::OAuth2Auth;
use mde::cli::agent::AgentCommand;
use mde::cli::{Cli, Commands};
use mde::client::MdeClient;
use mde::config::{Config, MdeCredentials};
use mde::error::AppError;

fn main() {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    // Load config and resolve credentials early (before fork).
    let config = Config::load().unwrap_or_default();
    let credentials = MdeCredentials::resolve(
        cli.tenant_id.as_deref(),
        cli.client_id.as_deref(),
        &config,
    );

    // Handle agent start (fork) before creating tokio runtime.
    // fork() is unsafe in multi-threaded processes, so we must do it here.
    if let Some(Commands::Agent {
        command:
            AgentCommand::Start {
                socket,
                config: agent_config,
                foreground,
            },
    }) = &cli.command
        && !foreground
    {
        let session_token = mde::agent::generate_token();
        let socket_path = socket.as_ref().map(PathBuf::from);
        let config_path = agent_config.as_ref().map(PathBuf::from);

        if let Err(e) = mde::agent::validate_credentials(&credentials) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }

        // Clear MDE credentials from environment before fork.
        // The child process will use the MdeCredentials struct instead.
        // SAFETY: Single-threaded context (before tokio runtime creation).
        unsafe {
            MdeCredentials::clear_env();
        }

        if let Err(e) = mde::agent::ensure_socket_dir() {
            eprintln!("Error: failed to create socket directory: {}", e);
            process::exit(1);
        }

        match mde::agent::server::fork_into_background(
            socket_path,
            config_path,
            session_token.clone(),
            credentials,
        ) {
            Ok((child_pid, _socket_path)) => {
                eprintln!("agent started, pid {}", child_pid);
                eprintln!(
                    "session file: {}",
                    mde::agent::session::session_file_path().display()
                );
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: failed to start agent: {}", e);
                process::exit(1);
            }
        }
    }

    // Create tokio runtime for all other operations.
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = run(cli, credentials).await {
            eprintln!("Error: {}", e);
            process::exit(e.exit_code());
        }
    });
}

async fn run(cli: Cli, credentials: MdeCredentials) -> Result<(), AppError> {
    let command = match cli.command {
        Some(command) => command,
        None => {
            Cli::command().print_help().ok();
            return Ok(());
        }
    };

    // Handle agent subcommands.
    if let Commands::Agent { command: agent_cmd } = &command {
        return handle_agent_command(agent_cmd, credentials).await;
    }

    // Check if we should route through the agent.
    // Commands without a subaction (e.g. `mde alerts` without `list`) display help locally.
    if !cli.no_agent
        && let Some(ref agent_token) = cli.token
        && requires_agent_routing(&command)
    {
        let socket_path = cli
            .socket
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(mde::agent::resolve_socket_path);

        return route_through_agent(&command, &socket_path, agent_token).await;
    }

    // If no explicit token but a session file exists, use it for auto-detection.
    if !cli.no_agent
        && cli.token.is_none()
        && requires_agent_routing(&command)
        && let Some(session) = mde::agent::session::read_session()
        && mde::agent::session::is_session_alive(&session)
    {
        return route_through_agent_from_session(&command, session).await;
    }

    // Auth commands only need tenant_id and client_id
    if let Commands::Auth {
        command: Some(ref auth_cmd),
    } = command
    {
        let tid = credentials.tenant_id.as_deref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;
        let cid = credentials.client_id.as_deref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;
        return mde::commands::auth::handle(auth_cmd, tid, cid, credentials.client_secret.as_deref())
            .await;
    }

    // For API commands, build client with appropriate auth
    let build_mde_client = |base_url: &str, scope: &str| -> Result<MdeClient, AppError> {
        if let Some(ref token) = credentials.access_token {
            let auth = StaticTokenAuth(token.clone());
            return MdeClient::new(base_url.to_string(), Box::new(auth));
        }

        let tid = credentials.tenant_id.as_ref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;
        let cid = credentials.client_id.as_ref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;
        let cs = credentials.client_secret.as_ref().ok_or_else(|| {
            AppError::Config(
                "client_secret not set. Set MDE_CLIENT_SECRET env var or config.toml [auth].client_secret."
                    .to_string(),
            )
        })?;

        let auth = OAuth2Auth::new(tid.clone(), cid.clone(), cs.clone(), scope.to_string())?;
        MdeClient::new(base_url.to_string(), Box::new(auth))
    };

    match &command {
        Commands::Alerts { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            mde::commands::alerts::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Incidents { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://graph.microsoft.com",
                "https://graph.microsoft.com/.default",
            )?;
            mde::commands::incidents::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Hunting { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://graph.microsoft.com",
                "https://graph.microsoft.com/.default",
            )?;
            mde::commands::hunting::handle(&client, cmd, cli.output).await
        }
        Commands::Machines { command: Some(cmd) } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            mde::commands::machines::handle(&client, cmd, cli.output, cli.raw).await
        }
        _ => {
            Cli::command()
                .find_subcommand(command.name())
                .expect("subcommand must exist")
                .clone()
                .print_help()
                .ok();
            Ok(())
        }
    }
}

/// Handle agent subcommands (start foreground, stop, status).
async fn handle_agent_command(
    cmd: &AgentCommand,
    credentials: MdeCredentials,
) -> Result<(), AppError> {
    match cmd {
        AgentCommand::Start {
            socket,
            config,
            foreground,
        } => {
            // Foreground mode (background is handled before tokio runtime).
            debug_assert!(*foreground, "background mode should be handled in main()");

            mde::agent::validate_credentials(&credentials).map_err(AppError::Config)?;

            // Clear MDE credentials from environment in foreground mode too.
            // SAFETY: Called before agent server starts processing requests.
            unsafe {
                MdeCredentials::clear_env();
            }

            let session_token = mde::agent::generate_token();
            let socket_path = socket.as_ref().map(PathBuf::from);
            let config_path = config.as_ref().map(PathBuf::from);

            mde::agent::ensure_socket_dir()
                .map_err(|e| AppError::Config(format!("failed to create socket dir: {}", e)))?;

            let pid = std::process::id();
            let actual_socket = socket_path.unwrap_or_else(|| mde::agent::pid_socket_path(pid));

            mde::agent::server::start(Some(actual_socket), config_path, &session_token, credentials)
                .await
                .map_err(|e| AppError::Config(format!("agent error: {}", e)))?;

            Ok(())
        }
        AgentCommand::Stop { socket, all } => {
            let msg = if *all {
                mde::agent::client::stop_all()?
            } else {
                let socket_path = socket
                    .as_ref()
                    .map(PathBuf::from)
                    .unwrap_or_else(mde::agent::resolve_socket_path);
                mde::agent::client::stop(&socket_path)?
            };
            println!("{}", msg);
            Ok(())
        }
        AgentCommand::Status => {
            let msg = mde::agent::client::status().await?;
            println!("{}", msg);
            Ok(())
        }
    }
}

/// Route a command through the agent via UDS.
async fn route_through_agent(
    command: &Commands,
    socket_path: &std::path::Path,
    agent_token: &str,
) -> Result<(), AppError> {
    let (cmd_name, action, args) = extract_command_args(command);

    let output =
        mde::agent::client::send_command(&cmd_name, &action, &args, socket_path, agent_token)
            .await?;

    print!("{}", output);
    Ok(())
}

/// Route a command through the agent using session file info.
async fn route_through_agent_from_session(
    command: &Commands,
    session: mde::agent::session::SessionInfo,
) -> Result<(), AppError> {
    let socket_path = PathBuf::from(&session.socket_path);
    let (cmd_name, action, args) = extract_command_args(command);

    let output =
        mde::agent::client::send_command(&cmd_name, &action, &args, &socket_path, &session.token)
            .await?;

    print!("{}", output);
    Ok(())
}

/// Check if a command has a subaction and should be routed through the agent.
/// Commands without a subaction (e.g. `mde alerts`) only display help,
/// which can be handled locally without agent involvement.
fn requires_agent_routing(command: &Commands) -> bool {
    match command {
        Commands::Alerts { command } => command.is_some(),
        Commands::Incidents { command } => command.is_some(),
        Commands::Hunting { command } => command.is_some(),
        Commands::Machines { command } => command.is_some(),
        Commands::Auth { command } => command.is_some(),
        Commands::Agent { .. } => false, // agent commands are handled separately
    }
}

/// Extract command name, action, and remaining args from a Commands variant.
/// Global flags like --output and --raw are preserved and passed to the agent.
/// Only agent-specific flags (--socket, --token) are stripped.
fn extract_command_args(command: &Commands) -> (String, String, Vec<String>) {
    let cmd_name = command.name().to_string();

    let all_args: Vec<String> = std::env::args().collect();
    let mut action = String::new();
    let mut extra_args = Vec::new();
    let mut found_command = false;

    // Only strip agent-specific flags that the server should not see.
    // Global flags like --output, --raw, --tenant-id are passed through
    // so the agent can honor the requested output format.
    let strip_flags_with_value = ["--socket", "--token"];
    let strip_flags_bool = ["--no-agent"];

    let mut skip_next = false;
    for arg in all_args.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Check if this flag should be stripped (exact match or --flag=value).
        let should_strip = strip_flags_with_value
            .iter()
            .any(|f| *arg == *f || arg.starts_with(&format!("{}=", f)))
            || strip_flags_bool.iter().any(|f| *arg == *f);

        if should_strip {
            // If it's a --flag value (not --flag=value), skip the next arg too.
            if strip_flags_with_value.iter().any(|f| *arg == *f) && !arg.contains('=') {
                skip_next = true;
            }
            continue;
        }

        if !found_command {
            if *arg == cmd_name || *arg == command.name() {
                found_command = true;
            }
            continue;
        }

        if action.is_empty() {
            action = arg.clone();
        } else {
            extra_args.push(arg.clone());
        }
    }

    (cmd_name, action, extra_args)
}
