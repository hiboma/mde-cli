use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum MachinesCommand {
    /// List machines
    List(ListArgs),
    /// Get a single machine by ID
    Get(GetArgs),
    /// Get machine timeline events
    Timeline(TimelineArgs),
    /// Get logon users for a machine
    LogonUsers(LogonUsersArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Maximum number of results
    #[arg(long, default_value = "50")]
    pub top: u32,

    /// Raw OData $filter expression
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct GetArgs {
    /// Machine ID
    pub id: String,
}

#[derive(Args)]
pub struct TimelineArgs {
    /// Machine ID
    pub id: String,

    /// Maximum number of results
    #[arg(long, default_value = "50")]
    pub top: u32,
}

#[derive(Args)]
pub struct LogonUsersArgs {
    /// Machine ID
    pub id: String,
}
