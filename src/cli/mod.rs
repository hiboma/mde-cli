pub mod agent;
pub mod alerts;
pub mod auth;
pub mod credentials;
pub mod hunting;
pub mod incidents;
pub mod machines;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

use crate::output::OutputFormat;

#[derive(Parser)]
#[command(
    name = "mde-cli",
    version,
    about = "CLI tool for Microsoft Defender for Endpoint API",
    subcommand_required = false,
    arg_required_else_help = true,
    help_template = "\
{before-help}{name} {version}
{about-with-newline}
{usage-heading} {name} [OPTIONS] [COMMAND]

Resources:
  alerts [alert]      Manage alerts
  incidents [incident] Manage incidents
  hunting [hunt]      Run advanced hunting queries
  machines [machine]  Manage machines (devices)

Authentication:
  auth               Authenticate and manage tokens
  agent              Manage the credential isolation agent
  credentials        Manage stored credentials (Keychain on macOS)

Other:
  completion         Generate shell completion script
  help               Print this message or the help of the given subcommand(s)

{all-args}{after-help}"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Azure AD tenant ID
    #[arg(long, env = "MDE_TENANT_ID", global = true, hide = true)]
    pub tenant_id: Option<String>,

    /// Azure AD client ID
    #[arg(long, env = "MDE_CLIENT_ID", global = true, hide = true)]
    pub client_id: Option<String>,

    /// Output format
    #[arg(
        long,
        env = "MDE_OUTPUT_FORMAT",
        global = true,
        default_value = "json",
        hide = true
    )]
    pub output: OutputFormat,

    /// Output raw API response without extracting data
    #[arg(long, global = true, hide = true)]
    pub raw: bool,

    /// Agent socket path (hidden, set by agent start)
    #[arg(long, env = "MDE_AGENT_SOCKET", global = true, hide = true)]
    pub socket: Option<String>,

    /// Agent session token (hidden, set by agent start)
    #[arg(long, env = "MDE_AGENT_TOKEN", global = true, hide = true)]
    pub token: Option<String>,

    /// Skip agent auto-detection and use direct API mode
    #[arg(long, global = true, hide = true)]
    pub no_agent: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authenticate and manage tokens
    #[command(
        subcommand_required = false,
        arg_required_else_help = true,
        hide = true
    )]
    Auth {
        #[command(subcommand)]
        command: Option<auth::AuthCommand>,
    },
    /// Manage alerts
    #[command(
        subcommand_required = false,
        arg_required_else_help = true,
        visible_alias = "alert",
        hide = true
    )]
    Alerts {
        #[command(subcommand)]
        command: Option<alerts::AlertsCommand>,
    },
    /// Manage incidents
    #[command(
        subcommand_required = false,
        arg_required_else_help = true,
        visible_alias = "incident",
        hide = true
    )]
    Incidents {
        #[command(subcommand)]
        command: Option<incidents::IncidentsCommand>,
    },
    /// Run advanced hunting queries
    #[command(
        subcommand_required = false,
        arg_required_else_help = true,
        visible_alias = "hunt",
        hide = true
    )]
    Hunting {
        #[command(subcommand)]
        command: Option<hunting::HuntingCommand>,
    },
    /// Manage machines (devices)
    #[command(
        subcommand_required = false,
        arg_required_else_help = true,
        visible_alias = "machine",
        hide = true
    )]
    Machines {
        #[command(subcommand)]
        command: Option<machines::MachinesCommand>,
    },
    /// Manage the credential isolation agent
    #[command(subcommand_required = true, arg_required_else_help = true, hide = true)]
    Agent {
        #[command(subcommand)]
        command: agent::AgentCommand,
    },
    /// Manage stored credentials (macOS Keychain)
    #[command(
        subcommand_required = true,
        arg_required_else_help = true,
        hide = true,
        long_about = "Manage stored credentials (macOS Keychain).\n\
                      \n\
                      Secrets are stored in the login keychain under \
                      service=\"dev.mde-cli\". Inspect or delete via \
                      Keychain Access.app or `security \
                      find-generic-password -s dev.mde-cli`. See README \
                      for the full credential resolution order and \
                      migration steps."
    )]
    Credentials {
        #[command(subcommand)]
        command: credentials::CredentialsCommand,
    },
    /// Generate shell completion script
    #[command(hide = true)]
    Completion {
        /// Shell to generate completion for
        shell: Shell,
    },
}

impl Commands {
    pub fn name(&self) -> &'static str {
        match self {
            Commands::Auth { .. } => "auth",
            Commands::Alerts { .. } => "alerts",
            Commands::Incidents { .. } => "incidents",
            Commands::Hunting { .. } => "hunting",
            Commands::Machines { .. } => "machines",
            Commands::Agent { .. } => "agent",
            Commands::Credentials { .. } => "credentials",
            Commands::Completion { .. } => "completion",
        }
    }
}
