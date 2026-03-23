use clap::{CommandFactory, Parser};
use std::path::PathBuf;
use std::process;

use mde::auth::StaticTokenAuth;
use mde::auth::oauth2::OAuth2Auth;
use mde::cli::agent::AgentCommand;
use mde::cli::{Cli, Commands, ProfileAction};
use mde::client::MdeClient;
use mde::config::Config;
use mde::error::AppError;
use mde::profile;

fn main() {
    dotenvy::dotenv().ok();

    // If top-level --help/-h is requested, show profile-aware help and exit.
    if should_show_profile_help() {
        show_profile_help();
        return;
    }

    let cli = Cli::parse();

    // Handle agent start (fork) before creating tokio runtime.
    // fork() is unsafe in multi-threaded processes, so we must do it here.
    if let Some(Commands::Agent {
        command:
            AgentCommand::Start {
                socket,
                config,
                foreground,
                shared,
            },
    }) = &cli.command
        && !foreground
    {
        let session_token = mde::agent::generate_token();
        let socket_path = socket.as_ref().map(PathBuf::from);
        let config_path = config.as_ref().map(PathBuf::from);
        let shared = *shared;

        if let Err(e) = mde::agent::ensure_socket_dir() {
            eprintln!("Error: failed to create socket directory: {}", e);
            process::exit(1);
        }

        match mde::agent::server::fork_into_background(
            socket_path,
            config_path,
            session_token.clone(),
            shared,
        ) {
            Ok((child_pid, socket_path)) => {
                if shared {
                    eprintln!("agent started in shared mode, pid {}", child_pid);
                    eprintln!(
                        "session file: {}",
                        mde::agent::session::session_file_path().display()
                    );
                } else {
                    mde::agent::server::print_shell_vars(&socket_path, &session_token, child_pid);
                }
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
        if let Err(e) = run(cli).await {
            eprintln!("Error: {}", e);
            process::exit(e.exit_code());
        }
    });
}

async fn run(cli: Cli) -> Result<(), AppError> {
    let command = match cli.command {
        Some(command) => command,
        None => {
            Cli::command().print_help().ok();
            return Ok(());
        }
    };

    // Handle profile subcommands.
    if let Commands::Profile { action } = &command {
        handle_profile_command(action, cli.profile.as_deref());
        return Ok(());
    }

    // Handle agent subcommands.
    if let Commands::Agent { command: agent_cmd } = &command {
        return handle_agent_command(agent_cmd).await;
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

    // Check profile restrictions before dispatching.
    if let Some(ref active_profile) = profile::resolve(cli.profile.as_deref()) {
        let cmd_name = command.name().to_string();
        if !active_profile.is_command_allowed(&cmd_name) {
            eprintln!(
                "Error: command '{}' is not allowed by profile '{}'",
                cmd_name, active_profile.name
            );
            eprintln!(
                "hint: use --profile to switch profiles, or run 'mde-cli profile list' to see available profiles"
            );
            process::exit(1);
        }
    }

    let config = Config::load().unwrap_or_default();

    let tenant_id = cli
        .tenant_id
        .as_deref()
        .map(String::from)
        .or_else(|| std::env::var("MDE_TENANT_ID").ok())
        .or_else(|| config.auth.tenant_id.clone());

    let client_id = cli
        .client_id
        .as_deref()
        .map(String::from)
        .or_else(|| std::env::var("MDE_CLIENT_ID").ok())
        .or_else(|| config.auth.client_id.clone());

    let client_secret = std::env::var("MDE_CLIENT_SECRET")
        .ok()
        .or_else(|| config.auth.client_secret.clone());

    let access_token = std::env::var("MDE_ACCESS_TOKEN").ok();

    // Auth commands only need tenant_id and client_id
    if let Commands::Auth {
        command: Some(ref auth_cmd),
    } = command
    {
        let tid = tenant_id.as_deref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;
        let cid = client_id.as_deref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;
        return mde::commands::auth::handle(auth_cmd, tid, cid, client_secret.as_deref()).await;
    }

    // For API commands, build client with appropriate auth
    let build_mde_client = |base_url: &str, scope: &str| -> Result<MdeClient, AppError> {
        // If access_token is provided via MDE_ACCESS_TOKEN env var, use it
        if let Some(ref token) = access_token {
            let auth = StaticTokenAuth(token.clone());
            return MdeClient::new(base_url.to_string(), Box::new(auth));
        }

        let tid = tenant_id.as_ref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;
        let cid = client_id.as_ref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;
        let cs = client_secret.as_ref().ok_or_else(|| {
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
async fn handle_agent_command(cmd: &AgentCommand) -> Result<(), AppError> {
    match cmd {
        AgentCommand::Start {
            socket,
            config,
            foreground,
            shared,
        } => {
            // Foreground mode (background is handled before tokio runtime).
            debug_assert!(*foreground, "background mode should be handled in main()");

            let session_token = mde::agent::generate_token();
            let socket_path = socket.as_ref().map(PathBuf::from);
            let config_path = config.as_ref().map(PathBuf::from);

            mde::agent::ensure_socket_dir()
                .map_err(|e| AppError::Config(format!("failed to create socket dir: {}", e)))?;

            let pid = std::process::id();
            let actual_socket = socket_path.unwrap_or_else(|| mde::agent::pid_socket_path(pid));

            if !*shared {
                mde::agent::server::print_shell_vars(&actual_socket, &session_token, pid);
            }

            mde::agent::server::start(Some(actual_socket), config_path, &session_token, *shared)
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
        AgentCommand::Status { socket, shared } => {
            let msg = if *shared {
                mde::agent::client::status_shared().await?
            } else {
                let socket_path = socket
                    .as_ref()
                    .map(PathBuf::from)
                    .unwrap_or_else(mde::agent::resolve_socket_path);
                mde::agent::client::status(&socket_path).await?
            };
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
        Commands::Profile { .. } => false, // profile commands are handled locally
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
    let strip_flags_with_value = ["--socket", "--token", "--profile"];
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

/// Check if top-level --help/-h is requested (not for a subcommand).
fn should_show_profile_help() -> bool {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-h" || arg == "--help" {
            return true;
        }
        // If we hit a non-flag argument, it's a subcommand — don't intercept.
        if !arg.starts_with('-') {
            return false;
        }
        // Skip flags with values.
        if matches!(
            arg.as_str(),
            "--tenant-id" | "--client-id" | "--output" | "--socket" | "--token" | "--profile"
        ) {
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Show profile-aware help text.
fn show_profile_help() {
    let args: Vec<String> = std::env::args().collect();
    let mut cli_profile = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--profile" {
            if i + 1 < args.len() {
                cli_profile = Some(args[i + 1].clone());
            }
            break;
        }
        if args[i].starts_with("--profile=") {
            cli_profile = Some(args[i].trim_start_matches("--profile=").to_string());
            break;
        }
        i += 1;
    }

    let active = profile::resolve(cli_profile.as_deref());

    match active {
        Some(ref ap) if !ap.commands.iter().any(|c| c == "*") => {
            print_filtered_help(ap);
        }
        _ => {
            // No profile or wildcard: show default help.
            let mut cmd = Cli::command();
            let help = cmd.render_help();
            print!("{}", help);
        }
    }
}

/// Print help text filtered by the active profile.
fn print_filtered_help(ap: &profile::ActiveProfile) {
    let version = env!("CARGO_PKG_VERSION");
    let total = total_command_count();
    let allowed = ap.commands.len();

    println!("mde-cli {}", version);
    println!("CLI tool for Microsoft Defender for Endpoint API");
    println!();
    println!("Usage: mde-cli [OPTIONS] [COMMAND]");
    println!();

    // Options section.
    let cmd = Cli::command();
    println!("Options:");
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        let long = arg
            .get_long()
            .map(|l| format!("--{}", l))
            .unwrap_or_default();
        let short = arg
            .get_short()
            .map(|s| format!("-{}, ", s))
            .unwrap_or_else(|| "    ".to_string());
        let is_takes_values = arg.get_action().takes_values();
        let value_name = if !is_takes_values {
            String::new()
        } else {
            arg.get_value_names()
                .map(|v| {
                    v.iter()
                        .map(|n| format!("<{}>", n))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };
        let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
        if long.is_empty() && value_name.is_empty() {
            continue;
        }
        let flag = if value_name.is_empty() {
            format!("  {}{}", short, long)
        } else {
            format!("  {}{} {}", short, long, value_name)
        };
        println!("{:<40} {}", flag, help);
    }
    println!();

    // Commands section — group by category, only showing allowed commands.
    let categories: &[(&str, &[&str])] = &[
        ("Resources", &["alerts", "incidents", "hunting", "machines"]),
        ("Authentication", &["auth"]),
    ];

    println!("Commands:");
    for (category, cmds) in categories {
        let filtered: Vec<&&str> = cmds.iter().filter(|c| ap.is_command_allowed(c)).collect();
        if filtered.is_empty() {
            continue;
        }
        println!();
        println!("{}:", category);
        let line = filtered
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {}", line);
    }

    // Always show agent, profile.
    println!();
    println!("Agent:");
    println!("  agent");
    println!();
    println!("Configuration:");
    println!("  profile");

    println!();
    println!(
        "Active profile: {} ({}/{} commands)",
        ap.name, allowed, total,
    );
    println!("Version: {}", version);
}

/// Handle `profile init` and `profile list` subcommands.
fn handle_profile_command(action: &ProfileAction, cli_profile: Option<&str>) {
    match action {
        ProfileAction::Init { global } => {
            let path = if *global {
                let home = std::env::var("HOME").unwrap_or_else(|_| {
                    eprintln!("Error: HOME is not set");
                    process::exit(1);
                });
                let dir = std::path::PathBuf::from(home).join(".config/mde-cli");
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    eprintln!("Error: failed to create {}: {}", dir.display(), e);
                    process::exit(1);
                }
                dir.join("config.toml")
            } else {
                std::path::PathBuf::from(".mde-cli.toml")
            };

            if path.exists() {
                eprintln!("Error: {} already exists", path.display());
                eprintln!("hint: remove or rename the file to re-initialize");
                process::exit(1);
            }

            if let Err(e) = std::fs::write(&path, profile::builtin_config_toml()) {
                eprintln!("Error: failed to write {}: {}", path.display(), e);
                process::exit(1);
            }
            println!("Created {}", path.display());
        }
        ProfileAction::List => {
            let config = profile::load_config();
            let active = profile::resolve(cli_profile);

            match config {
                Some(config) if !config.profiles.is_empty() => {
                    let active_name = active.as_ref().map(|a| a.name.as_str());
                    for (name, p) in &config.profiles {
                        let marker = if Some(name.as_str()) == active_name {
                            " (active)"
                        } else {
                            ""
                        };
                        let cmd_count = if p.commands.iter().any(|c| c == "*") {
                            "all".to_string()
                        } else {
                            format!("{} commands", p.commands.len())
                        };
                        println!("  {}{} - {} [{}]", name, marker, p.description, cmd_count);
                    }
                    if let Some(ref ap) = active {
                        let total = total_command_count();
                        let allowed = if ap.commands.iter().any(|c| c == "*") {
                            total
                        } else {
                            ap.commands.len()
                        };
                        println!(
                            "\nActive profile: {} - {} ({}/{} commands)",
                            ap.name, ap.description, allowed, total,
                        );
                    }
                }
                _ => {
                    println!("No profiles configured.");
                    println!("hint: run 'mde-cli profile init' to create a configuration file");
                }
            }
        }
    }
}

/// Get the total number of API commands (excluding agent, profile).
fn total_command_count() -> usize {
    let cmd = Cli::command();
    cmd.get_subcommands()
        .filter(|s| {
            let name = s.get_name();
            name != "agent" && name != "profile"
        })
        .count()
}
