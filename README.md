# mde-cli - Microsoft Defender for Endpoint CLI

A command-line tool for interacting with the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro).

## Features

- **Alerts** - List, get, and update security alerts
- **Incidents** - List, get, and update incidents (via Microsoft Graph API)
- **Advanced Hunting** - Run KQL queries against the advanced hunting API
- **Machines** - List, get machine details, view timelines and logon users
- **Indicators** - Create, list, and delete indicators (exclusions/blocks)
- **Agent Mode** - Credential isolation for use with LLM agents (ssh-agent pattern)
- **OAuth2 Authentication** - Browser login (Authorization Code Flow with PKCE) and client credentials

## Installation

### From source

```bash
cargo install --path .
```

### Build from source

```bash
git clone https://github.com/hiboma/mde-cli.git
cd mde-cli
cargo build --release
```

The binary will be at `target/release/mde-cli`.

## Configuration

### Environment Variables

| Variable | Description |
|---|---|
| `MDE_TENANT_ID` | Azure AD tenant ID |
| `MDE_CLIENT_ID` | Azure AD application (client) ID |
| `MDE_CLIENT_SECRET` | Azure AD client secret |
| `MDE_ACCESS_TOKEN` | Pre-obtained access token (skips OAuth2 flow) |
| `MDE_OUTPUT_FORMAT` | Output format: `json` (default), `json-minify`, or `table` |

### Config File

You can also set credentials in `~/.config/mde/credentials.toml`:

```toml
[credentials]
tenant_id = "your-tenant-id"
client_id = "your-client-id"
client_secret = "your-client-secret"
```

`client_secret` should preferably be stored in the OS credential store
instead — see [Credential storage](#credential-storage) below.

### Credential storage

`mde-cli` resolves the OAuth2 `client_secret` from the following sources,
highest priority first:

1. `MDE_CLIENT_SECRET` environment variable
2. **macOS Keychain** (login keychain, `service=dev.mde-cli`,
   `account=client_secret`)
3. `credentials.toml`, searched in this order:
   1. `./.mde-credentials.toml` (current working directory)
   2. `$XDG_CONFIG_HOME/mde/credentials.toml` (falls back to
      `~/.config/mde/credentials.toml`)

The cwd-relative `.mde-credentials.toml` is useful for project-local
overrides but note that it is picked up from whichever directory you
run `mde-cli` in.

`.env` files in the current directory are read for non-credential
variables (proxy settings, `RUST_LOG`, etc.), but `MDE_*` keys loaded
from `.env` are **ignored** and logged as a warning. Those would
otherwise let a malicious `.env` in a project tree override your
Keychain secret.

Storing the secret in the Keychain keeps it out of plaintext config
files (and out of dotfile backups, Time Machine snapshots, accidental
git commits, etc.).

#### Storing the secret

```bash
# Interactive prompt (recommended)
mde-cli credentials set client-secret

# Non-interactive (CI / scripts)
echo "$MDE_CLIENT_SECRET" | mde-cli credentials set client-secret --stdin

# Confirm presence (the value is never printed)
mde-cli credentials status
```

To migrate an existing plaintext `client_secret` from `credentials.toml`
into the Keychain in one step:

```bash
mde-cli credentials migrate
```

`migrate` writes the secret to the Keychain and then offers to dispose
of the plaintext copy:

- **Recommended (default)**: the `client_secret` line is removed from
  the toml via an atomic temp-file rename. No plaintext copy remains on
  disk.
- **Opt-in**: a 0o600 backup of the original toml is kept alongside
  the rewritten file. Choose this only if you need to roll back to the
  old setup.

> ⚠️ **The opt-in backup still contains the plaintext secret.** A
> backup under `$HOME` is typically included in Time Machine / iCloud /
> rsync snapshots and defeats the point of moving the secret into the
> Keychain. Delete it as soon as you have confirmed the new setup works
> with `mde-cli credentials status`.

If the rewrite fails partway through, migrate rolls back the Keychain
entry it just wrote so you are not left in a half-migrated state.

#### Recovering from an interrupted migrate

If you hit Ctrl-C (or your machine loses power) **between** the
Keychain write and the toml rewrite, both copies of the secret exist:
the new Keychain entry *and* the untouched `credentials.toml`. The
process is idempotent — re-running `mde-cli credentials migrate` on the
same file will detect that the secret is still present in the toml and
re-run the disposal step. Alternatively, if you want to bail out
entirely, `mde-cli credentials delete client-secret` removes the
Keychain entry and the toml stays as it was.

#### Inspecting the entry

The entry lives in your **login** keychain as a `generic password`:

| Attribute | Value |
|---|---|
| Kind | `application password` |
| Service (Name / Where) | `dev.mde-cli` |
| Account | `client_secret` |

GUI:

```
Keychain Access.app → login → Passwords → search "dev.mde-cli"
```

CLI (metadata only):

```bash
security find-generic-password -s dev.mde-cli -a client_secret
```

#### Removing the entry

```bash
mde-cli credentials delete client-secret
# or via macOS:
security delete-generic-password -s dev.mde-cli -a client_secret
```

#### Notes on Keychain prompts

macOS shows an access-prompt dialog the first time `mde-cli` reads the
Keychain entry. Choosing **Always Allow** suppresses subsequent
prompts.

The dialog reappears whenever the binary's code signature changes —
including after every `cargo install` rebuild. This is a macOS ACL
behavior, not an `mde-cli` bug.

If a non-`mde-cli` build of the binary keeps causing prompts, you can
inspect the entry's Access Control list in Keychain Access.app and
remove or replace the allowed-applications list.

### Azure AD App Registration

1. Register an application in [Azure AD](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Add the following API permissions:

| Permission | Type | Description |
|---|---|---|
| `Alert.Read.All` | Application | Read alerts |
| `Machine.Read.All` | Application | Read machine info |
| `ThreatHunting.Read.All` | Application | Run advanced hunting queries (Graph API) |
| `Incident.Read.All` | Delegated | Read incidents (Graph API) |
| `Ti.ReadWrite` | Application | Manage indicators (create/delete) |

3. Create a client secret under **Certificates & secrets**

## Usage

### Authentication

```bash
# Browser login (Authorization Code Flow with PKCE)
mde-cli auth login

# Show token for client_credentials flow (CI use)
mde-cli auth token

# Client credentials (non-interactive)
export MDE_TENANT_ID="your-tenant-id"
export MDE_CLIENT_ID="your-client-id"
export MDE_CLIENT_SECRET="your-secret"
```

### Alerts

```bash
mde-cli alerts list
mde-cli alerts get <alert-id>
mde-cli alerts update <alert-id> --status resolved
mde-cli alerts files <alert-id>
mde-cli alerts ips <alert-id>
mde-cli alerts domains <alert-id>
```

### Incidents

```bash
mde-cli incidents list
mde-cli incidents get <incident-id>
mde-cli incidents update <incident-id> --status resolved
```

### Advanced Hunting

```bash
mde-cli hunting run --query "DeviceProcessEvents | take 10"
```

### Machines

```bash
mde-cli machines list
mde-cli machines get <machine-id>
mde-cli machines timeline <machine-id>
mde-cli machines logon-users <machine-id>
```

### Indicators

```bash
# List indicators
mde-cli indicators list

# List indicators filtered by type
mde-cli indicators list --indicator-type FileSha256

# Create an exclusion (allow) indicator for a file hash
mde-cli indicators create <SHA256> \
  --indicator-type FileSha256 \
  --action Allowed \
  --title "FP exclusion" \
  --no-alert

# Delete an indicator by ID
mde-cli indicators delete <indicator-id>
```

### Agent Mode (Credential Isolation)

Agent mode isolates credentials from the process that invokes `mde-cli` commands. This is useful when running under LLM agents (e.g., Claude Code) where you want to prevent credential leakage via prompt injection.

```bash
# Start the agent (credentials stay in this process)
eval "$(op run --env-file .env.1password -- mde-cli agent start)"

# Now commands route through the agent automatically
mde-cli alerts list

# Check agent status
mde-cli agent status

# Stop the agent
mde-cli agent stop
```

See [ADR-0001](docs/adr/0001-agent-mode-for-credential-isolation.md) for the design rationale.

### Output Formats

```bash
# JSON output (default)
mde-cli alerts list --output json

# Minified JSON output
mde-cli alerts list --output json-minify

# Table output
mde-cli alerts list --output table

# Raw API response
mde-cli alerts list --raw
```

## Required API Permissions

| Subcommand | Base URL | Scope |
|---|---|---|
| `alerts`, `machines`, `indicators` | `https://api.security.microsoft.com` | `https://api.securitycenter.microsoft.com/.default` |
| `hunting`, `incidents` | `https://graph.microsoft.com` | `https://graph.microsoft.com/.default` |

## License

[MIT](LICENSE)
