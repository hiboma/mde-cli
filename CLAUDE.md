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

## Code Style

- Follow Rust standard conventions
- Use `cargo fmt` and `cargo clippy` before committing
- Conventional Commits for commit messages
- End files with a newline (POSIX)

## CI

- GitHub Actions runs check, clippy, fmt, and test on push/PR
- Release workflow builds multi-platform binaries on tag push
