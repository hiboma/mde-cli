# CLAUDE.md

## Project Overview

`mde-cli` is a CLI tool for Microsoft Defender for Endpoint API, written in Rust.

## Build & Test

```bash
cargo build              # Build debug
cargo build --release    # Build release
cargo test               # Run tests
cargo clippy             # Lint
cargo fmt                # Format
```

## Architecture

- `src/main.rs` - Entry point, CLI routing
- `src/cli/` - Command-line interface definitions (clap)
- `src/commands/` - Command handlers (business logic)
- `src/client/` - HTTP client with retry logic
- `src/auth/` - OAuth2, device code flow, browser-based auth
- `src/models/` - API response models
- `src/output/` - Output formatters (JSON, table)
- `src/config/` - Configuration file handling
- `src/error.rs` - Error types

### Resource-specific authentication

- `src/auth/resource.rs` builds API clients for CLI commands.
- Browser login stores an MDE token. `hunting` and `incidents` exchange the
  refresh token for Graph scope on each invocation, without caching the
  Graph access token or replacing the MDE access token/expiry in Keychain.
- A rotated refresh token updates only the matching stored bundle's refresh token.
- Browser login requires Microsoft Graph delegated `ThreatHunting.Read.All`
  for hunting and `SecurityIncident.ReadWrite.All` for incident read/update,
  with administrator consent.
- For Graph commands, explicit `MDE_ACCESS_TOKEN` takes precedence. Otherwise,
  a stored refresh token takes precedence over a client secret and obtains a
  delegated token. Exchange failures do not fall back to client-secret auth.
  Without a refresh token, an available access token is used after audience
  inspection; client-secret authentication with application permissions is
  used only when neither token is available.
- JWT audience inspection is a diagnostic only; opaque tokens remain supported.
- Graph 401/403 errors include permission and consent guidance.

### Indicators

- `indicators` subcommand manages MDE Indicators API (`/api/indicators`)
- Supports `list`, `create`, `delete` operations
- `create` accepts indicatorType (FileSha256, FileSha1, FileMd5, CertificateThumbprint, IpAddress, DomainName, Url) and action (Allowed, Alert, AlertAndBlock, Block)
- Uses `securitycenter` scope, same as alerts/machines

### Doctor

- `doctor` subcommand prints a one-screen diagnostic: CONFIG (which
  credentials.toml is in effect), ACTIVE CREDENTIALS (each field's
  effective value and its source), ENVIRONMENT (MDE_* set/unset), and
  CONNECTIVITY (a `GET /api/machines?$top=1` probe with elapsed time)
- Never prints secret values: `client_secret`/`access_token`/`refresh_token`
  show presence + source only; `client_id` is masked to its first 4 chars;
  secret-bearing env vars show `(set, hidden)`
- Provenance comes from `MdeCredentials::resolve_with_provenance` in
  `config/mod.rs`, which mirrors `resolve` but records a `Source` per field.
  `resolve_with_store` delegates to it and drops the metadata
- Handled locally before the env scrub in `main.rs` (alongside
  `credentials`/`completion`). It does not
  forward `--tenant-id`/`--client-id` because clap merges those flags with
  their env vars, which would misattribute the source

## Code Style

- Follow Rust standard conventions
- Use `cargo fmt` and `cargo clippy` before committing
- Conventional Commits for commit messages
- End files with a newline (POSIX)

## CI

- GitHub Actions runs check, clippy, fmt, and test on push/PR
- Release workflow builds multi-platform binaries on tag push
