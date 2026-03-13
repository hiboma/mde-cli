pub mod agent;
pub mod alerts;
pub mod auth;
pub mod hunting;
pub mod incidents;
pub mod machines;

use clap::{Parser, Subcommand};

use crate::output::OutputFormat;

#[derive(Parser)]
#[command(
    name = "mde",
    version,
    about = "CLI tool for Microsoft Defender for Endpoint API",
    subcommand_required = false,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Azure AD tenant ID
    #[arg(long, env = "MDE_TENANT_ID", global = true)]
    pub tenant_id: Option<String>,

    /// Azure AD client ID
    #[arg(long, env = "MDE_CLIENT_ID", global = true)]
    pub client_id: Option<String>,

    /// Output format
    #[arg(
        long,
        env = "MDE_OUTPUT_FORMAT",
        global = true,
        default_value = "json"
    )]
    pub output: OutputFormat,

    /// Output raw API response without extracting data
    #[arg(long, global = true)]
    pub raw: bool,

    /// Agent socket path (hidden, set by agent start)
    #[arg(long, env = "MDE_AGENT_SOCKET", global = true, hide = true)]
    pub socket: Option<String>,

    /// Agent session token (hidden, set by agent start)
    #[arg(long, env = "MDE_AGENT_TOKEN", global = true, hide = true)]
    pub token: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authenticate and manage tokens
    #[command(subcommand_required = false, arg_required_else_help = true)]
    Auth {
        #[command(subcommand)]
        command: Option<auth::AuthCommand>,
    },
    /// Manage alerts
    #[command(subcommand_required = false, arg_required_else_help = true)]
    Alerts {
        #[command(subcommand)]
        command: Option<alerts::AlertsCommand>,
    },
    /// Manage incidents
    #[command(subcommand_required = false, arg_required_else_help = true)]
    Incidents {
        #[command(subcommand)]
        command: Option<incidents::IncidentsCommand>,
    },
    /// Run advanced hunting queries
    #[command(subcommand_required = false, arg_required_else_help = true)]
    Hunting {
        #[command(subcommand)]
        command: Option<hunting::HuntingCommand>,
    },
    /// Manage machines (devices)
    #[command(subcommand_required = false, arg_required_else_help = true)]
    Machines {
        #[command(subcommand)]
        command: Option<machines::MachinesCommand>,
    },
    /// Manage the credential isolation agent
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Agent {
        #[command(subcommand)]
        command: agent::AgentCommand,
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
        }
    }
}
