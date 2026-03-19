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

        /// Share the agent across terminals via session file (no eval needed)
        #[arg(long)]
        shared: bool,
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
        /// Show status from shared session file instead of socket
        #[arg(long)]
        shared: bool,
    },
}
