#![allow(deprecated)] // Command::cargo_bin is deprecated but cargo_bin_cmd! has different ergonomics

//! Integration tests for `mde-cli agent start/stop/status` lifecycle.
//!
//! Each test uses an isolated temporary directory for TMPDIR and XDG_DATA_HOME
//! so that sockets and session files do not interfere with each other or with
//! a real running agent.
//!
//! Dummy credentials (MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET) are
//! injected via environment variables so the agent passes credential validation
//! without hitting any real API.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

/// Build a `Command` for `mde-cli` with isolated env.
/// - TMPDIR → temp dir (socket directory lives under $TMPDIR/mde-agent/)
/// - XDG_DATA_HOME → temp dir (session.json lives under $XDG_DATA_HOME/mde-cli/)
/// - Dummy MDE credentials to pass validation
fn mde_cmd(tmpdir: &Path, xdg_data_home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("mde-cli").unwrap();
    cmd.env("TMPDIR", tmpdir)
        .env("XDG_DATA_HOME", xdg_data_home)
        .env("MDE_TENANT_ID", "test-tenant-id")
        .env("MDE_CLIENT_ID", "test-client-id")
        .env("MDE_CLIENT_SECRET", "test-client-secret")
        // Prevent loading the user's .env file
        .env("HOME", tmpdir);
    cmd
}

/// Wait for the session file to appear (agent needs a moment to fork and write it).
fn wait_for_session_file(xdg_data_home: &Path) -> std::path::PathBuf {
    let session_file = xdg_data_home.join("mde-cli").join("session.debug.json");
    for _ in 0..50 {
        if session_file.exists() {
            return session_file;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "session file did not appear within 5s: {}",
        session_file.display()
    );
}

/// Read the PID from the session file.
fn read_session_pid(session_file: &Path) -> u32 {
    let content = std::fs::read_to_string(session_file).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    v["pid"].as_u64().unwrap() as u32
}

/// Check if a process is alive.
fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[test]
fn test_agent_start_creates_session_file() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Start the agent (background mode).
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent started, pid"));

    // Session file should appear.
    let session_file = wait_for_session_file(xdg.path());
    assert!(session_file.exists());

    // Clean up: stop the agent.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .success();
}

#[test]
fn test_agent_start_twice_shows_already_started() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Start the agent.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success();

    wait_for_session_file(xdg.path());

    // Start again — should detect already running.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already started"));

    // Clean up.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .success();
}

#[test]
fn test_agent_status_when_running() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Start the agent.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success();

    wait_for_session_file(xdg.path());

    // Status should show running.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"running\": true"));

    // Clean up.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .success();
}

#[test]
fn test_agent_status_when_not_running() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Status without a running agent should show not running.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"running\": false"));
}

#[test]
fn test_agent_stop_kills_process_and_removes_session() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Start the agent.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success();

    let session_file = wait_for_session_file(xdg.path());
    let pid = read_session_pid(&session_file);
    assert!(is_process_alive(pid), "agent should be running");

    // Stop the agent.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stopped agent"));

    // Give the process a moment to exit.
    std::thread::sleep(Duration::from_millis(200));

    assert!(!is_process_alive(pid), "agent should have exited");
    assert!(!session_file.exists(), "session file should be removed");
}

#[test]
fn test_agent_stop_when_not_running() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Stop without a running agent should show an error.
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("agent is not running"));
}

#[test]
fn test_agent_start_without_credentials_fails() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // Start without credentials should fail.
    Command::cargo_bin("mde-cli")
        .unwrap()
        .env("TMPDIR", tmpdir.path())
        .env("XDG_DATA_HOME", xdg.path())
        .env("HOME", tmpdir.path())
        .env_remove("MDE_TENANT_ID")
        .env_remove("MDE_CLIENT_ID")
        .env_remove("MDE_CLIENT_SECRET")
        .env_remove("MDE_ACCESS_TOKEN")
        .args(["agent", "start"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing required credentials"));
}

#[test]
fn test_agent_full_lifecycle() {
    let tmpdir = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();

    // 1. Status: not running
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"running\": false"));

    // 2. Start
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success()
        .stderr(predicate::str::contains("agent started, pid"));

    wait_for_session_file(xdg.path());

    // 3. Status: running
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"running\": true"));

    // 4. Start again: already started
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "start"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already started"));

    // 5. Stop
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stopped agent"));

    // 6. Status: not running
    // Give the process a moment to fully exit.
    std::thread::sleep(Duration::from_millis(200));
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"running\": false"));

    // 7. Stop again: not running
    mde_cmd(tmpdir.path(), xdg.path())
        .args(["agent", "stop"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("agent is not running"));
}
