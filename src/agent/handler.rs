use crate::agent::protocol::{AgentRequest, AgentResponse};
use crate::agent::security::{
    AuditLog, AuditResult, CommandWhitelist, RateLimiter, constant_time_eq, validate_command_name,
};
use crate::dispatch;

/// Handle an incoming agent request with security checks.
pub async fn handle_request(
    request: AgentRequest,
    session_token: &str,
    whitelist: &CommandWhitelist,
    rate_limiter: &RateLimiter,
    audit_log: &AuditLog,
) -> AgentResponse {
    let request_id = request.request_id.clone();

    // 1. Token verification (constant-time).
    if !constant_time_eq(&request.token, session_token) {
        audit_log.log(AuditLog::entry(
            request_id.clone(),
            request.command.clone(),
            request.action.clone(),
            None,
            AuditResult::Denied("invalid token".to_string()),
        ));
        return AgentResponse::denied(request_id, "authentication failed".to_string());
    }

    // 2. Command name validation.
    if !validate_command_name(&request.command) {
        audit_log.log(AuditLog::entry(
            request_id.clone(),
            request.command.clone(),
            request.action.clone(),
            None,
            AuditResult::Denied("invalid command name".to_string()),
        ));
        return AgentResponse::denied(request_id, "invalid command".to_string());
    }

    if !validate_command_name(&request.action) {
        audit_log.log(AuditLog::entry(
            request_id.clone(),
            request.command.clone(),
            request.action.clone(),
            None,
            AuditResult::Denied("invalid action name".to_string()),
        ));
        return AgentResponse::denied(request_id, "invalid command".to_string());
    }

    // 3. Whitelist check.
    if !whitelist.is_allowed(&request.command) {
        audit_log.log(AuditLog::entry(
            request_id.clone(),
            request.command.clone(),
            request.action.clone(),
            None,
            AuditResult::Denied("command not whitelisted".to_string()),
        ));
        return AgentResponse::denied(request_id, "command not allowed".to_string());
    }

    // 4. Rate limit check.
    if !rate_limiter.try_acquire() {
        audit_log.log(AuditLog::entry(
            request_id.clone(),
            request.command.clone(),
            request.action.clone(),
            None,
            AuditResult::Denied("rate limited".to_string()),
        ));
        return AgentResponse::denied(request_id, "rate limited".to_string());
    }

    // 5. Validate args: reject flags that could override global options.
    for arg in &request.args {
        if is_dangerous_flag(arg) {
            audit_log.log(AuditLog::entry(
                request_id.clone(),
                request.command.clone(),
                request.action.clone(),
                None,
                AuditResult::Denied(format!("dangerous flag rejected: {}", arg)),
            ));
            return AgentResponse::denied(request_id, "invalid argument".to_string());
        }
    }

    // 6. Build CLI args and dispatch.
    let cli_args = build_cli_args(&request);

    match dispatch::dispatch_from_args(&cli_args).await {
        Ok(output) => {
            audit_log.log(AuditLog::entry(
                request_id.clone(),
                request.command.clone(),
                request.action.clone(),
                None,
                AuditResult::Allowed,
            ));
            AgentResponse::success(request_id, output)
        }
        Err(e) => {
            audit_log.log(AuditLog::entry(
                request_id.clone(),
                request.command.clone(),
                request.action.clone(),
                None,
                AuditResult::Error(e.to_string()),
            ));
            // Do not leak detailed error messages to the client.
            AgentResponse::error(request_id, "command execution failed".to_string())
        }
    }
}

/// Flags that must not be injected via agent args.
/// These could override authentication parameters or agent routing.
const BLOCKED_FLAGS: &[&str] = &["--tenant-id", "--client-id", "--socket", "--token"];

/// Check if an argument is a dangerous flag that should be rejected.
fn is_dangerous_flag(arg: &str) -> bool {
    BLOCKED_FLAGS
        .iter()
        .any(|f| arg == *f || arg.starts_with(&format!("{}=", f)))
}

/// Build CLI argument vector from an AgentRequest.
/// Reconstructs: ["mde", <command>, <action>, ...args]
fn build_cli_args(request: &AgentRequest) -> Vec<String> {
    let mut args = vec![
        "mde".to_string(),
        request.command.clone(),
        request.action.clone(),
    ];
    args.extend(request.args.iter().cloned());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cli_args() {
        let req = AgentRequest {
            token: "token".to_string(),
            request_id: "req-1".to_string(),
            command: "alerts".to_string(),
            action: "list".to_string(),
            args: vec!["--severity".to_string(), "HIGH".to_string()],
        };
        let args = build_cli_args(&req);
        assert_eq!(args, vec!["mde", "alerts", "list", "--severity", "HIGH"]);
    }

    #[test]
    fn test_is_dangerous_flag() {
        assert!(is_dangerous_flag("--tenant-id"));
        assert!(is_dangerous_flag("--tenant-id=attacker"));
        assert!(is_dangerous_flag("--client-id"));
        assert!(is_dangerous_flag("--client-id=evil"));
        assert!(is_dangerous_flag("--socket"));
        assert!(is_dangerous_flag("--token"));
        assert!(is_dangerous_flag("--token=injected"));

        assert!(!is_dangerous_flag("--severity"));
        assert!(!is_dangerous_flag("--output"));
        assert!(!is_dangerous_flag("--raw"));
        assert!(!is_dangerous_flag("HIGH"));
    }

    #[tokio::test]
    async fn test_handle_request_invalid_token() {
        let whitelist = CommandWhitelist::new(["alerts"].iter().map(|s| s.to_string()).collect());
        let rate_limiter = RateLimiter::new(60);
        let audit_log = AuditLog::new();

        let req = AgentRequest {
            token: "wrong-token".to_string(),
            request_id: "req-1".to_string(),
            command: "alerts".to_string(),
            action: "list".to_string(),
            args: vec![],
        };

        let resp =
            handle_request(req, "correct-token", &whitelist, &rate_limiter, &audit_log).await;
        assert_eq!(resp.status, crate::agent::protocol::ResponseStatus::Denied);
        assert_eq!(resp.error.unwrap(), "authentication failed");
    }

    #[tokio::test]
    async fn test_handle_request_not_whitelisted() {
        let whitelist = CommandWhitelist::new(["alerts"].iter().map(|s| s.to_string()).collect());
        let rate_limiter = RateLimiter::new(60);
        let audit_log = AuditLog::new();

        let req = AgentRequest {
            token: "valid-token".to_string(),
            request_id: "req-2".to_string(),
            command: "auth".to_string(),
            action: "login".to_string(),
            args: vec![],
        };

        let resp = handle_request(req, "valid-token", &whitelist, &rate_limiter, &audit_log).await;
        assert_eq!(resp.status, crate::agent::protocol::ResponseStatus::Denied);
        assert_eq!(resp.error.unwrap(), "command not allowed");
    }

    #[tokio::test]
    async fn test_handle_request_dangerous_flag_rejected() {
        let whitelist = CommandWhitelist::new(["alerts"].iter().map(|s| s.to_string()).collect());
        let rate_limiter = RateLimiter::new(60);
        let audit_log = AuditLog::new();

        let req = AgentRequest {
            token: "valid-token".to_string(),
            request_id: "req-3".to_string(),
            command: "alerts".to_string(),
            action: "list".to_string(),
            args: vec!["--tenant-id".to_string(), "attacker-tenant".to_string()],
        };

        let resp = handle_request(req, "valid-token", &whitelist, &rate_limiter, &audit_log).await;
        assert_eq!(resp.status, crate::agent::protocol::ResponseStatus::Denied);
        assert_eq!(resp.error.unwrap(), "invalid argument");
    }

    #[tokio::test]
    async fn test_handle_request_invalid_command_name() {
        let whitelist = CommandWhitelist::new(["alerts"].iter().map(|s| s.to_string()).collect());
        let rate_limiter = RateLimiter::new(60);
        let audit_log = AuditLog::new();

        let req = AgentRequest {
            token: "valid-token".to_string(),
            request_id: "req-4".to_string(),
            command: "cmd;evil".to_string(),
            action: "list".to_string(),
            args: vec![],
        };

        let resp = handle_request(req, "valid-token", &whitelist, &rate_limiter, &audit_log).await;
        assert_eq!(resp.status, crate::agent::protocol::ResponseStatus::Denied);
        assert_eq!(resp.error.unwrap(), "invalid command");
    }

    #[tokio::test]
    async fn test_handle_request_rate_limited() {
        let whitelist = CommandWhitelist::new(["alerts"].iter().map(|s| s.to_string()).collect());
        let rate_limiter = RateLimiter::new(1); // 1 per minute
        let audit_log = AuditLog::new();

        // First request exhausts the token.
        let req1 = AgentRequest {
            token: "valid-token".to_string(),
            request_id: "req-5a".to_string(),
            command: "alerts".to_string(),
            action: "list".to_string(),
            args: vec![],
        };
        let _ = handle_request(req1, "valid-token", &whitelist, &rate_limiter, &audit_log).await;

        // Second request should be rate limited.
        let req2 = AgentRequest {
            token: "valid-token".to_string(),
            request_id: "req-5b".to_string(),
            command: "alerts".to_string(),
            action: "list".to_string(),
            args: vec![],
        };
        let resp = handle_request(req2, "valid-token", &whitelist, &rate_limiter, &audit_log).await;
        assert_eq!(resp.status, crate::agent::protocol::ResponseStatus::Denied);
        assert_eq!(resp.error.unwrap(), "rate limited");
    }
}
