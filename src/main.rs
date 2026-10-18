use clap::{CommandFactory, Parser};
use clap_complete::generate;
use std::io;
use std::process;

use mde::auth::resource::{GRAPH_SCOPE, MDE_SCOPE, build_mde_client};
use mde::cli::{Cli, Commands};
use mde::config::MdeCredentials;
use mde::error::AppError;

/// Load `.env` from cwd but refuse to inject `MDE_*` keys into the
/// environment.
///
/// Why: `MDE_CLIENT_SECRET` (and friends) are credentials that we want
/// to source from one of three trusted places — explicit env vars set by
/// the caller, the macOS Keychain, or `~/.config/mde/credentials.toml`.
/// `.env` is none of those: it lives in the current working directory,
/// which is typically a user's project tree. A malicious `.env` dropped
/// into a repo (or one carelessly checked into a tutorial) would
/// silently override the user's Keychain secret, redirecting all
/// subsequent OAuth flows to an attacker-controlled tenant.
///
/// We still honor `.env` for non-credential entries (proxy settings,
/// `RUST_LOG`, etc.) so existing workflows continue to work.
fn load_dotenv_excluding_mde_keys() {
    // Snapshot which MDE_* keys exist in the real environment *before*
    // dotenv runs. Anything that appears after dotenv but was not in
    // this snapshot came from `.env` and must be removed.
    use std::collections::HashSet;
    let pre: HashSet<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("MDE_"))
        .collect();

    if dotenvy::dotenv().is_err() {
        return;
    }

    // Anything starting with MDE_ that did not exist before dotenv ran
    // was injected from .env. Strip it.
    let injected: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("MDE_") && !pre.contains(k))
        .collect();
    for k in &injected {
        // SAFETY: single-threaded context; no other thread observes env
        // mutations at this point in startup.
        unsafe { std::env::remove_var(k) };
    }
    if !injected.is_empty() {
        eprintln!(
            "warning: ignored MDE_* keys from .env ({}). Set them \
             explicitly or use `mde-cli credentials set` instead.",
            injected.join(", ")
        );
    }
}

fn main() {
    load_dotenv_excluding_mde_keys();
    let cli = Cli::parse();

    // For subcommands that do not talk to the API via the normal client
    // path (`credentials`, `completion`, `doctor`), skip resolve() and the
    // env scrub. resolve() may consult the OS credential store, which can
    // prompt or fail with an ACL error; letting that noise leak into a
    // `credentials status` invocation confuses the user. `doctor` resolves
    // credentials itself (with provenance tracking) and reads MDE_* env
    // vars directly, so it must run before the env scrub.
    if matches!(
        cli.command,
        Some(Commands::Credentials { .. })
            | Some(Commands::Completion { .. })
            | Some(Commands::Doctor)
    ) {
        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        rt.block_on(async {
            if let Err(e) = run(cli, MdeCredentials::default()).await {
                eprintln!("Error: {}", e);
                process::exit(e.exit_code());
            }
        });
        return;
    }

    // Resolve credentials before creating the tokio runtime.
    let credentials = MdeCredentials::resolve(cli.tenant_id.as_deref(), cli.client_id.as_deref());

    // Scrub MDE_* from this process's environment immediately after
    // resolution to limit credential exposure. This runs while the process
    // is single-threaded, before tokio runtime creation.
    //
    // SAFETY: Single-threaded context (before tokio runtime creation).
    unsafe {
        MdeCredentials::clear_env();
    }

    // Create the tokio runtime after scrubbing credentials from the environment.
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = run(cli, credentials).await {
            eprintln!("Error: {}", e);
            process::exit(e.exit_code());
        }
    });
}

async fn run(cli: Cli, mut credentials: MdeCredentials) -> Result<(), AppError> {
    let command = match cli.command {
        Some(command) => command,
        None => {
            Cli::command().print_help().ok();
            return Ok(());
        }
    };

    // Handle completion generation (no credentials required).
    if let Commands::Completion { shell } = &command {
        let mut cmd = Cli::command();
        let bin_name = cmd.get_name().to_string();
        generate(*shell, &mut cmd, bin_name, &mut io::stdout());
        return Ok(());
    }

    // Handle doctor diagnostics. doctor resolves credentials itself (with
    // provenance), reports on local config/credentials/environment, and
    // probes connectivity.
    //
    // We deliberately do NOT forward cli.tenant_id / cli.client_id here.
    // clap folds the `--tenant-id` flag and the `MDE_TENANT_ID` env var into
    // the same field, so a forwarded value could not be attributed to its
    // real source. doctor reads the environment itself to report an accurate
    // provenance (env vs credentials.toml). The trade-off: a value supplied
    // *only* via the `--tenant-id` flag (no env, no toml) is not reflected —
    // an uncommon case for a diagnostic invocation.
    if let Commands::Doctor = &command {
        return mde::commands::doctor::handle().await;
    }

    // Handle credentials store management (does not require API credentials).
    if let Commands::Credentials { command: cred_cmd } = &command {
        return mde::commands::credentials::handle(cred_cmd);
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
        return mde::commands::auth::handle(auth_cmd, tid, cid).await;
    }

    // If the keychain access token is expired but a refresh token is available,
    // try to refresh before building the API client.
    if needs_mde_prerefresh(&command)
        && credentials.access_token.is_none()
        && let (Some(tid), Some(cid), Some(rt)) = (
            &credentials.tenant_id,
            &credentials.client_id,
            &credentials.refresh_token,
        )
    {
        match mde::auth::browser::refresh_access_token(tid, cid, rt, mde::commands::auth::MDE_SCOPE)
            .await
        {
            Ok(result) => {
                eprintln!(
                    "Access token refreshed. (expires in {}s)",
                    result.expires_in
                );
                match mde::commands::auth::save_tokens_to_keychain(
                    &result,
                    credentials.refresh_token.as_deref(),
                ) {
                    Ok(false) => {
                        eprintln!(
                            "warning: no credential store available. \
                             Refreshed token is valid for this session only."
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: failed to save refreshed tokens to keychain: {}",
                            e
                        );
                    }
                    Ok(true) => {}
                }
                credentials.refresh_token =
                    result.refresh_token.or(credentials.refresh_token.take());
                credentials.access_token = Some(result.access_token);
            }
            Err(e) => {
                eprintln!("warning: token refresh failed: {}", e);
                if credentials.client_secret.is_none() {
                    return Err(AppError::Auth(
                        "Authentication expired. Run `mde-cli auth login` to re-authenticate."
                            .to_string(),
                    ));
                }
            }
        }
    }

    match &command {
        Commands::Alerts { command: Some(cmd) } => {
            let client =
                build_mde_client(&credentials, &credentials.mde_base_url, MDE_SCOPE).await?;
            mde::commands::alerts::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Incidents { command: Some(cmd) } => {
            let client =
                build_mde_client(&credentials, &credentials.graph_base_url, GRAPH_SCOPE).await?;
            mde::commands::incidents::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Hunting { command: Some(cmd) } => {
            let client =
                build_mde_client(&credentials, &credentials.graph_base_url, GRAPH_SCOPE).await?;
            mde::commands::hunting::handle(&client, cmd, cli.output).await
        }
        Commands::Machines { command: Some(cmd) } => {
            let client =
                build_mde_client(&credentials, &credentials.mde_base_url, MDE_SCOPE).await?;
            mde::commands::machines::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Indicators { command: Some(cmd) } => {
            let client =
                build_mde_client(&credentials, &credentials.mde_base_url, MDE_SCOPE).await?;
            mde::commands::indicators::handle(&client, cmd, cli.output, cli.raw).await
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

/// Graph commands resolve their own resource token without refreshing the MDE bundle first.
fn needs_mde_prerefresh(command: &Commands) -> bool {
    !matches!(
        command,
        Commands::Hunting { .. } | Commands::Incidents { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_commands_skip_mde_prerefresh_with_or_without_subcommands() {
        assert!(!needs_mde_prerefresh(&Commands::Hunting { command: None }));
        assert!(!needs_mde_prerefresh(&Commands::Incidents {
            command: None
        }));
        for args in [
            vec![
                "mde-cli",
                "hunting",
                "run",
                "--query",
                "DeviceInfo | take 1",
            ],
            vec!["mde-cli", "incidents", "list"],
            vec!["mde-cli", "incidents", "get", "1"],
            vec![
                "mde-cli",
                "incidents",
                "update",
                "1",
                "--status",
                "resolved",
            ],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            assert!(!needs_mde_prerefresh(&cli.command.unwrap()), "{args:?}");
        }
    }

    #[test]
    fn non_graph_commands_keep_mde_prerefresh_eligibility() {
        for command in [
            Commands::Alerts { command: None },
            Commands::Machines { command: None },
            Commands::Indicators { command: None },
            Commands::Auth { command: None },
        ] {
            assert!(needs_mde_prerefresh(&command));
        }
        for args in [
            vec!["mde-cli", "alerts", "list"],
            vec!["mde-cli", "machines", "list"],
            vec!["mde-cli", "indicators", "list"],
            vec!["mde-cli", "credentials", "status"],
            vec!["mde-cli", "doctor"],
            vec!["mde-cli", "completion", "zsh"],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            assert!(needs_mde_prerefresh(&cli.command.unwrap()), "{args:?}");
        }
    }
}
