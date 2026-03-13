use clap::Subcommand;

/// Agent subcommands for credential isolation.
#[derive(Subcommand, Debug)]
pub enum AgentCommand {
    /// Start the agent process
    Start {
        /// Custom socket path
        #[arg(long)]
        socket: Option<String>,

        /// Path to agent configuration file (agent.toml)
        #[arg(long)]
        config: Option<String>,

        /// Run in foreground (do not daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the agent process
    Stop {
        /// Custom socket path
        #[arg(long)]
        socket: Option<String>,

        /// Stop all running agents
        #[arg(long)]
        all: bool,
    },

    /// Show agent status
    Status {
        /// Custom socket path
        #[arg(long)]
        socket: Option<String>,
    },
}
