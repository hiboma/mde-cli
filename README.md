# mde-cli - Microsoft Defender for Endpoint CLI

A command-line tool for interacting with the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro).

## Features

- **Alerts** - List, get, and update security alerts
- **Incidents** - List, get, and update incidents (via Microsoft Graph API)
- **Advanced Hunting** - Run KQL queries against the advanced hunting API
- **Machines** - List, get machine details, view timelines and logon users
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
| `MDE_OUTPUT_FORMAT` | Output format: `json` (default) or `table` |

### Config File

You can also set credentials in `~/.config/mde/credentials.toml`:

```toml
[credentials]
tenant_id = "your-tenant-id"
client_id = "your-client-id"
client_secret = "your-client-secret"
```

### Azure AD App Registration

1. Register an application in [Azure AD](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Add the following API permissions:

| Permission | Type | Description |
|---|---|---|
| `Alert.Read.All` | Application | Read alerts |
| `Machine.Read.All` | Application | Read machine info |
| `ThreatHunting.Read.All` | Application | Run advanced hunting queries (Graph API) |
| `Incident.Read.All` | Delegated | Read incidents (Graph API) |

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
mde-cli alerts get --id <alert-id>
mde-cli alerts update --id <alert-id> --status resolved
mde-cli alerts files --id <alert-id>
mde-cli alerts ips --id <alert-id>
mde-cli alerts domains --id <alert-id>
```

### Incidents

```bash
mde-cli incidents list
mde-cli incidents get --id <incident-id>
mde-cli incidents update --id <incident-id> --status resolved
```

### Advanced Hunting

```bash
mde-cli hunting run --query "DeviceProcessEvents | take 10"
```

### Machines

```bash
mde-cli machines list
mde-cli machines get --id <machine-id>
mde-cli machines timeline --id <machine-id>
mde-cli machines logon-users --id <machine-id>
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
| `alerts`, `machines` | `https://api.security.microsoft.com` | `https://api.securitycenter.microsoft.com/.default` |
| `hunting`, `incidents` | `https://graph.microsoft.com` | `https://graph.microsoft.com/.default` |

## License

[MIT](LICENSE)
