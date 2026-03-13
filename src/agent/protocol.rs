use serde::{Deserialize, Serialize};

/// Request sent from client to agent over UDS.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentRequest {
    /// Session token for authentication.
    pub token: String,
    /// Unique request identifier (UUIDv4).
    pub request_id: String,
    /// Top-level command name (e.g. "alerts").
    pub command: String,
    /// Action name (e.g. "list").
    pub action: String,
    /// Additional arguments (e.g. ["--severity", "HIGH"]).
    #[serde(default)]
    pub args: Vec<String>,
}

/// Response sent from agent to client over UDS.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentResponse {
    /// Matching request identifier.
    pub request_id: String,
    /// Response status.
    pub status: ResponseStatus,
    /// Command output (stdout) on success.
    pub output: Option<String>,
    /// Error message on failure.
    pub error: Option<String>,
}

/// Status of an agent response.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    /// Command executed successfully.
    Success,
    /// Command execution failed.
    Error,
    /// Request was denied (auth, rate limit, whitelist).
    Denied,
}

impl AgentRequest {
    /// Serialize to a JSON line (with trailing newline).
    pub fn to_json_line(&self) -> serde_json::Result<String> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Deserialize from a JSON line.
    pub fn from_json_line(line: &str) -> serde_json::Result<Self> {
        serde_json::from_str(line.trim())
    }
}

impl AgentResponse {
    /// Serialize to a JSON line (with trailing newline).
    pub fn to_json_line(&self) -> serde_json::Result<String> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Deserialize from a JSON line.
    pub fn from_json_line(line: &str) -> serde_json::Result<Self> {
        serde_json::from_str(line.trim())
    }

    /// Create a success response.
    pub fn success(request_id: String, output: String) -> Self {
        Self {
            request_id,
            status: ResponseStatus::Success,
            output: Some(output),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(request_id: String, error: String) -> Self {
        Self {
            request_id,
            status: ResponseStatus::Error,
            output: None,
            error: Some(error),
        }
    }

    /// Create a denied response.
    pub fn denied(request_id: String, reason: String) -> Self {
        Self {
            request_id,
            status: ResponseStatus::Denied,
            output: None,
            error: Some(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let req = AgentRequest {
            token: "test-token".to_string(),
            request_id: "req-001".to_string(),
            command: "alerts".to_string(),
            action: "list".to_string(),
            args: vec!["--severity".to_string(), "HIGH".to_string()],
        };

        let line = req.to_json_line().unwrap();
        assert!(line.ends_with('\n'));

        let parsed = AgentRequest::from_json_line(&line).unwrap();
        assert_eq!(parsed.token, "test-token");
        assert_eq!(parsed.command, "alerts");
        assert_eq!(parsed.action, "list");
        assert_eq!(parsed.args, vec!["--severity", "HIGH"]);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = AgentResponse::success("req-001".to_string(), "output data".to_string());

        let line = resp.to_json_line().unwrap();
        let parsed = AgentResponse::from_json_line(&line).unwrap();

        assert_eq!(parsed.request_id, "req-001");
        assert_eq!(parsed.status, ResponseStatus::Success);
        assert_eq!(parsed.output.unwrap(), "output data");
        assert!(parsed.error.is_none());
    }

    #[test]
    fn test_response_denied() {
        let resp = AgentResponse::denied("req-002".to_string(), "rate limited".to_string());

        let line = resp.to_json_line().unwrap();
        let parsed = AgentResponse::from_json_line(&line).unwrap();

        assert_eq!(parsed.status, ResponseStatus::Denied);
        assert_eq!(parsed.error.unwrap(), "rate limited");
    }
}
