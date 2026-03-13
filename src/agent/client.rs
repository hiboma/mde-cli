use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::agent::list_agent_sockets;
use crate::agent::protocol::{AgentRequest, AgentResponse, ResponseStatus};
use crate::error::AppError;

/// Send a command to the agent and return the output.
pub async fn send_command(
    command: &str,
    action: &str,
    args: &[String],
    socket_path: &Path,
    token: &str,
) -> Result<String, AppError> {
    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        AppError::Config(format!(
            "Failed to connect to agent at {}: {}",
            socket_path.display(),
            e
        ))
    })?;

    let request = AgentRequest {
        token: token.to_string(),
        request_id: Uuid::new_v4().to_string(),
        command: command.to_string(),
        action: action.to_string(),
        args: args.to_vec(),
    };

    let (reader, mut writer) = stream.into_split();

    // Send request.
    let request_line = request
        .to_json_line()
        .map_err(|e| AppError::Config(format!("Failed to serialize request: {}", e)))?;
    writer.write_all(request_line.as_bytes()).await?;

    // Read response.
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;

    let response = AgentResponse::from_json_line(&line)
        .map_err(|e| AppError::Config(format!("Failed to parse agent response: {}", e)))?;

    match response.status {
        ResponseStatus::Success => Ok(response.output.unwrap_or_default()),
        ResponseStatus::Error => Err(AppError::Config(
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string()),
        )),
        ResponseStatus::Denied => Err(AppError::Config(format!(
            "agent denied request: {}",
            response
                .error
                .unwrap_or_else(|| "unknown reason".to_string())
        ))),
    }
}

/// Check agent status.
pub async fn status(socket_path: &Path) -> Result<String, AppError> {
    match UnixStream::connect(socket_path).await {
        Ok(_) => Ok(format!(
            "Agent is running (socket: {})",
            socket_path.display()
        )),
        Err(_) => Ok(format!(
            "Agent is not running (socket: {})",
            socket_path.display()
        )),
    }
}

/// Stop the agent by sending SIGTERM.
pub fn stop(socket_path: &Path) -> Result<String, AppError> {
    let pid_file = crate::agent::pid_file_path(socket_path);
    let Some(pid) = crate::agent::read_pid_file(&pid_file) else {
        return Err(AppError::Config(format!(
            "No PID file found for {}",
            socket_path.display()
        )));
    };

    // SAFETY: kill() with SIGTERM is safe when targeting a known PID.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret == 0 {
        Ok(format!("Stopped agent (PID {})", pid))
    } else {
        let err = std::io::Error::last_os_error();
        Err(AppError::Config(format!(
            "Failed to stop agent (PID {}): {}",
            pid, err
        )))
    }
}

/// Stop all running agents.
pub fn stop_all() -> Result<String, AppError> {
    let sockets = list_agent_sockets();
    if sockets.is_empty() {
        return Ok("No running agents found".to_string());
    }

    let mut results = Vec::new();
    for socket in &sockets {
        match stop(socket) {
            Ok(msg) => results.push(msg),
            Err(e) => results.push(format!("Error: {}", e)),
        }
    }

    Ok(results.join("\n"))
}
