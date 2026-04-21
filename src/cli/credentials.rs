use clap::{Subcommand, ValueEnum};

#[derive(Subcommand)]
pub enum CredentialsCommand {
    /// Store a credential in the OS credential store (e.g. macOS Keychain).
    #[command(arg_required_else_help = true)]
    Set {
        #[arg(value_enum)]
        field: CredentialField,
        /// Read the value from stdin instead of prompting interactively.
        /// Useful for CI / automation. The value must be a single line.
        #[arg(long)]
        stdin: bool,
    },
    /// Delete a credential from the OS credential store.
    #[command(arg_required_else_help = true)]
    Delete {
        #[arg(value_enum)]
        field: CredentialField,
    },
    /// Show whether each credential is stored. Values are never printed.
    Status,
    /// Migrate `client_secret` from credentials.toml into the OS credential store.
    Migrate {
        /// Show what would be done without modifying anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CredentialField {
    /// OAuth2 client secret. Sensitive — stored only in the credential store.
    ClientSecret,
}

impl CredentialField {
    /// The logical key under which this field is stored in the credential
    /// store. Returns a static identifier (e.g. "client_secret") — never
    /// the credential value.
    pub fn key(self) -> &'static str {
        match self {
            CredentialField::ClientSecret => crate::config::credential_store::KEY_CLIENT_SECRET,
        }
    }
}
