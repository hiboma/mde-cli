//! Integration tests for `mde-cli completion <SHELL>`.
//!
//! The completion subcommand must be runnable without any credentials or
//! agent context — installing completions is something users do before
//! authenticating. These tests guard the early-return path in `run()` so a
//! future refactor cannot accidentally require credentials to print a
//! completion script.

use assert_cmd::Command;
use predicates::prelude::*;

fn mde_cmd() -> Command {
    let mut cmd = Command::cargo_bin("mde-cli").unwrap();
    cmd.env_remove("MDE_TENANT_ID")
        .env_remove("MDE_CLIENT_ID")
        .env_remove("MDE_CLIENT_SECRET")
        .env_remove("MDE_ACCESS_TOKEN")
        .env_remove("MDE_AGENT_TOKEN")
        .env_remove("MDE_AGENT_SOCKET");
    cmd
}

#[test]
fn completion_zsh_emits_compdef_header() {
    mde_cmd()
        .args(["completion", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef mde-cli"));
}

#[test]
fn completion_bash_emits_function_definition() {
    mde_cmd()
        .args(["completion", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_mde-cli()"));
}

#[test]
fn completion_without_shell_argument_fails() {
    mde_cmd()
        .arg("completion")
        .assert()
        .failure()
        .stderr(predicate::str::contains("<SHELL>"));
}

#[test]
fn completion_rejects_unknown_shell() {
    mde_cmd().args(["completion", "tcsh"]).assert().failure();
}
