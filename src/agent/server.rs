use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use crate::agent::handler::handle_request;
use crate::agent::protocol::{AgentRequest, AgentResponse};
use crate::agent::security::{AgentConfig, AuditLog, CommandWhitelist, RateLimiter};
use crate::agent::{
    cleanup_files, ensure_socket_dir, list_agent_sockets, pid_file_path, pid_socket_path,
    read_pid_file, write_pid_file,
};

/// Maximum request size (1 MiB).
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Maximum concurrent connections.
const MAX_CONNECTIONS: usize = 64;

/// Check if an agent is already running.
/// For eval mode, scan all sockets via `list_agent_sockets()`.
/// For shared mode, read the socket path from `session.json`.
async fn check_already_running(shared: bool) -> Option<u32> {
    if shared {
        // Shared mode: check session.json for existing agent.
        if let Some(session) = crate::agent::session::read_session() {
            let socket_path = PathBuf::from(&session.socket_path);
            if tokio::net::UnixStream::connect(&socket_path).await.is_ok() {
                return Some(session.pid);
            }
        }
    } else {
        // Eval mode: scan all sockets in the socket directory.
        for socket in list_agent_sockets() {
            if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                let pid = read_pid_file(&pid_file_path(&socket)).unwrap_or(0);
                return Some(pid);
            }
        }
    }
    None
}

/// Start the agent in foreground mode.
pub async fn start(
    socket_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    session_token: &str,
    shared: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sanitize environment and harden process before starting.
    crate::agent::sanitize_env();
    crate::agent::harden_process();

    // Check if an agent is already running.
    if let Some(pid) = check_already_running(shared).await {
        eprintln!("agent: already started (pid {})", pid);
        return Ok(());
    }

    let config = AgentConfig::load(config_path.as_deref());

    // SAFETY: getsid(0) is always safe.
    let session_leader_pid = unsafe { libc::getsid(0) };

    ensure_socket_dir()?;
    let socket_path = socket_path.unwrap_or_else(|| pid_socket_path(std::process::id()));

    // Clean up stale socket if it exists.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Set restrictive umask before bind to prevent TOCTOU between bind and chmod.
    #[cfg(unix)]
    let _old_umask = unsafe { libc::umask(0o077) };

    let listener = UnixListener::bind(&socket_path)?;

    // Restore umask after bind.
    #[cfg(unix)]
    unsafe {
        libc::umask(_old_umask);
    }

    // Write PID file.
    let pid = std::process::id();
    write_pid_file(&pid_file_path(&socket_path), pid)?;

    eprintln!("agent: listening on {}", socket_path.display());
    if shared {
        eprintln!("agent: shared mode (session leader monitoring disabled)");
    } else {
        eprintln!("agent: session leader PID {}", session_leader_pid);
    }

    run_agent(
        listener,
        socket_path,
        session_token,
        session_leader_pid,
        config,
        shared,
    )
    .await
}

/// Fork into background and start the agent.
/// Returns the child PID on success (in the parent process).
pub fn fork_into_background(
    socket_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    session_token: String,
    shared: bool,
) -> Result<(u32, PathBuf), Box<dyn std::error::Error>> {
    let _socket_path = socket_path.unwrap_or_else(|| {
        // We don't know the child PID yet, use a temporary placeholder.
        // After fork, the child will re-resolve.
        pid_socket_path(0)
    });

    // Record the session leader PID before fork. Using getsid(0) instead of
    // getppid() so the watchdog monitors the terminal session leader (login
    // shell), not the immediate parent. This prevents premature shutdown when
    // launched indirectly (e.g. via Claude Code's temporary shell).
    // SAFETY: getsid(0) is always safe.
    let session_leader_pid = unsafe { libc::getsid(0) };

    // SAFETY: We are single-threaded at this point (tokio runtime not yet started).
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => Err(std::io::Error::last_os_error().into()),
        0 => {
            // Child process: create new session.
            // SAFETY: setsid() is always safe in forked child.
            unsafe { libc::setsid() };

            // Sanitize environment and harden process immediately after fork,
            // before tokio runtime creation. See ADR-0003.
            crate::agent::sanitize_env();
            crate::agent::harden_process();

            let child_pid = std::process::id();
            let actual_socket_path = pid_socket_path(child_pid);

            // Detach stdio so the parent's $() command substitution can complete.
            redirect_stdio(&actual_socket_path);

            let config = AgentConfig::load(config_path.as_deref());

            // Build and run the tokio runtime in the child.
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async {
                ensure_socket_dir().expect("failed to create socket dir");

                if actual_socket_path.exists() {
                    std::fs::remove_file(&actual_socket_path).ok();
                }

                // Set restrictive umask before bind to prevent TOCTOU.
                let old_umask = unsafe { libc::umask(0o077) };
                let listener =
                    UnixListener::bind(&actual_socket_path).expect("failed to bind socket");
                unsafe {
                    libc::umask(old_umask);
                }

                write_pid_file(&pid_file_path(&actual_socket_path), child_pid)
                    .expect("failed to write PID file");

                eprintln!("agent: listening on {}", actual_socket_path.display());
                if shared {
                    eprintln!("agent: shared mode (session leader monitoring disabled)");
                } else {
                    eprintln!("agent: session leader PID {}", session_leader_pid);
                }

                if let Err(e) = run_agent(
                    listener,
                    actual_socket_path,
                    &session_token,
                    session_leader_pid,
                    config,
                    shared,
                )
                .await
                {
                    eprintln!("agent: error: {}", e);
                }
            });

            std::process::exit(0);
        }
        child_pid => {
            // Parent process: return child PID and socket path.
            let child_pid = child_pid as u32;
            let actual_socket_path = pid_socket_path(child_pid);
            Ok((child_pid, actual_socket_path))
        }
    }
}

/// Output shell variables for eval.
pub fn print_shell_vars(socket_path: &std::path::Path, token: &str, pid: u32) {
    println!(
        "MDE_AGENT_SOCKET={}; export MDE_AGENT_SOCKET;",
        socket_path.display()
    );
    println!("MDE_AGENT_TOKEN={}; export MDE_AGENT_TOKEN;", token);
    println!("MDE_AGENT_PID={}; export MDE_AGENT_PID;", pid);
    eprintln!("agent: pid {}", pid);
}

/// Redirect stdin/stdout to /dev/null and stderr to a log file.
/// This ensures the parent's command substitution `$()` completes
/// because the child no longer holds the stdout pipe open.
fn redirect_stdio(socket_path: &Path) {
    // SAFETY: open, dup2, close are safe POSIX system calls.
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            if devnull > libc::STDERR_FILENO {
                libc::close(devnull);
            }
        }

        // Redirect stderr to a log file next to the socket.
        let log_path = socket_path
            .parent()
            .unwrap_or(Path::new("/tmp"))
            .join("mde-agent.log");
        if let Ok(log_cstr) = std::ffi::CString::new(log_path.to_string_lossy().as_bytes()) {
            let log_fd = libc::open(
                log_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                0o600,
            );
            if log_fd >= 0 {
                libc::dup2(log_fd, libc::STDERR_FILENO);
                if log_fd > libc::STDERR_FILENO {
                    libc::close(log_fd);
                }
            }
        }
    }
}

/// Run the agent server (accept loop + watchdog).
#[allow(clippy::too_many_arguments)]
async fn run_agent(
    listener: UnixListener,
    socket_path: PathBuf,
    session_token: &str,
    session_leader_pid: libc::pid_t,
    config: AgentConfig,
    shared: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_token = Arc::new(session_token.to_string());

    let whitelist = Arc::new(CommandWhitelist::new(
        config.whitelist.allowed_commands.into_iter().collect(),
    ));
    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.requests_per_minute));
    let audit_log = Arc::new(AuditLog::new());
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    // Shared mode: write session file for cross-terminal auto-detection.
    if shared {
        let session_info = crate::agent::session::SessionInfo {
            socket_path: socket_path.display().to_string(),
            token: session_token.as_str().to_string(),
            pid: std::process::id(),
            started_at: chrono::Utc::now(),
        };
        if let Err(e) = crate::agent::session::write_session(&session_info) {
            eprintln!("agent: failed to write session file: {}", e);
        } else {
            eprintln!(
                "agent: session file written to {}",
                crate::agent::session::session_file_path().display()
            );
        }
    }

    let socket_path_clone = socket_path.clone();

    let shutdown_reason = if shared {
        // Shared mode: no session leader monitoring, signal-only shutdown.
        tokio::select! {
            _ = accept_loop(
                listener,
                session_token,
                whitelist,
                rate_limiter,
                audit_log,
                semaphore,
            ) => "accept loop ended",
            _ = tokio::signal::ctrl_c() => "received SIGINT",
        }
    } else {
        tokio::select! {
            reason = watchdog(session_leader_pid, &config.watchdog) => reason,
            _ = accept_loop(
                listener,
                session_token,
                whitelist,
                rate_limiter,
                audit_log,
                semaphore,
            ) => "accept loop ended",
            _ = tokio::signal::ctrl_c() => "received SIGINT",
        }
    };

    eprintln!("agent: shutting down ({})", shutdown_reason);
    cleanup_files(&socket_path_clone);
    if shared {
        crate::agent::session::remove_session();
        eprintln!("agent: session file removed");
    }
    Ok(())
}

/// Accept loop: handle incoming connections.
async fn accept_loop(
    listener: UnixListener,
    session_token: Arc<String>,
    whitelist: Arc<CommandWhitelist>,
    rate_limiter: Arc<RateLimiter>,
    audit_log: Arc<AuditLog>,
    semaphore: Arc<Semaphore>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("agent: connection rejected (max connections reached)");
                continue;
            }
        };

        let session_token = session_token.clone();
        let whitelist = whitelist.clone();
        let rate_limiter = rate_limiter.clone();
        let audit_log = audit_log.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                &session_token,
                &whitelist,
                &rate_limiter,
                &audit_log,
            )
            .await
            {
                eprintln!("agent: connection error: {}", e);
            }
            drop(permit);
        });
    }
}

/// Handle a single connection: verify peer, read request, process, write response.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    session_token: &str,
    whitelist: &CommandWhitelist,
    rate_limiter: &RateLimiter,
    audit_log: &AuditLog,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Verify peer UID before processing.
    #[cfg(unix)]
    {
        use crate::agent::peer_verify::get_peer_uid;
        use crate::agent::security::verify_peer_uid;

        match get_peer_uid(&stream) {
            Ok(uid) => {
                if !verify_peer_uid(uid) {
                    eprintln!("agent: rejected connection from UID {}", uid);
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!("agent: failed to get peer UID: {}", e);
                return Ok(());
            }
        }
    }

    // Verify peer binary (code signing on macOS, path on Linux).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use crate::agent::peer_verify::verify_peer;

        match verify_peer(&stream) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("agent: rejected connection from unverified peer binary");
                return Ok(());
            }
            Err(e) => {
                eprintln!("agent: peer binary verification failed ({}), rejecting", e);
                return Ok(());
            }
        }
    }

    let (reader, mut writer) = stream.into_split();

    // Apply size limit BEFORE reading to prevent memory exhaustion.
    let limited_reader = reader.take(MAX_REQUEST_SIZE as u64);
    let mut buf_reader = BufReader::new(limited_reader);
    let mut line = String::new();

    let bytes_read = buf_reader.read_line(&mut line).await?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = match AgentRequest::from_json_line(&line) {
        Ok(req) => req,
        Err(_e) => {
            let resp = AgentResponse::error(String::new(), "invalid request".to_string());
            writer.write_all(resp.to_json_line()?.as_bytes()).await?;
            return Ok(());
        }
    };

    let response = handle_request(request, session_token, whitelist, rate_limiter, audit_log).await;

    writer
        .write_all(response.to_json_line()?.as_bytes())
        .await?;
    Ok(())
}

/// Watchdog task: checks session leader liveness.
/// Returns a reason string when the agent should shut down.
async fn watchdog(
    session_leader_pid: libc::pid_t,
    config: &crate::agent::security::WatchdogConfig,
) -> &'static str {
    let check_interval = tokio::time::Duration::from_secs(config.check_interval_secs);

    loop {
        tokio::time::sleep(check_interval).await;

        // Check if session leader is still alive.
        // SAFETY: kill(pid, 0) is safe—it only checks process existence.
        let session_alive = unsafe { libc::kill(session_leader_pid, 0) } == 0;
        if !session_alive {
            return "session leader exited";
        }
    }
}
