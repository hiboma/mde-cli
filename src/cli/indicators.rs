use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum IndicatorsCommand {
    /// List indicators
    List(ListArgs),
    /// Create an indicator
    Create(CreateArgs),
    /// Delete an indicator by ID
    Delete(DeleteArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Maximum number of results
    #[arg(long, default_value = "50")]
    pub top: u32,

    /// Filter by indicatorType: FileSha256, FileSha1, FileMd5, CertificateThumbprint, IpAddress, DomainName, Url
    #[arg(long)]
    pub indicator_type: Option<String>,

    /// Filter by action: Allowed, Alert, AlertAndBlock, Block
    #[arg(long)]
    pub action: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    /// Indicator value (e.g. SHA256 hash, IP address, domain name)
    pub indicator_value: String,

    /// Indicator type: FileSha256, FileSha1, FileMd5, CertificateThumbprint, IpAddress, DomainName, Url
    #[arg(long)]
    pub indicator_type: String,

    /// Action: Allowed, Alert, AlertAndBlock, Block
    #[arg(long)]
    pub action: String,

    /// Title (short description)
    #[arg(long)]
    pub title: String,

    /// Description
    #[arg(long)]
    pub description: Option<String>,

    /// Severity: Informational, Low, Medium, High
    #[arg(long)]
    pub severity: Option<String>,

    /// Suppress alert generation for this indicator
    #[arg(long)]
    pub no_alert: bool,

    /// Expiration time in ISO 8601 format (e.g. 2026-12-31T00:00:00Z)
    #[arg(long)]
    pub expiration_time: Option<String>,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// Indicator ID
    pub id: u64,
}
