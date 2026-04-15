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
- `src/agent/` - Credential isolation agent (ssh-agent pattern)
- `src/models/` - API response models
- `src/output/` - Output formatters (JSON, table)
- `src/config/` - Configuration file handling
- `src/error.rs` - Error types

### Indicators

- `indicators` subcommand manages MDE Indicators API (`/api/indicators`)
- Supports `list`, `create`, `delete` operations
- `create` accepts indicatorType (FileSha256, FileSha1, FileMd5, CertificateThumbprint, IpAddress, DomainName, Url) and action (Allowed, Alert, AlertAndBlock, Block)
- Uses `securitycenter` scope, same as alerts/machines
- Registered in agent command whitelist (`agent/security.rs`)

### Shared Mode

- `mde-cli agent start --shared` writes session info to `~/.local/share/mde-cli/session.json`
- No `eval` needed; any terminal can auto-detect the agent via session file
- Session leader monitoring is disabled; no idle timeout
- Duplicate start is detected via socket connection check ("already started")
- `--no-agent` flag forces direct API mode, skipping agent auto-detection
- Priority: `--no-agent` > `MDE_AGENT_TOKEN` env > session.json > direct mode

## Code Style

- Follow Rust standard conventions
- Use `cargo fmt` and `cargo clippy` before committing
- Conventional Commits for commit messages
- End files with a newline (POSIX)

## CI

- GitHub Actions runs check, clippy, fmt, and test on push/PR
- Release workflow builds multi-platform binaries on tag push
