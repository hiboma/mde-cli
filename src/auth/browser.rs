use std::io::Write;
use std::sync::mpsc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::AppError;

const REDIRECT_PORT: u16 = 8400;
const REDIRECT_PATH: &str = "/callback";

struct PkceChallenge {
    verifier: String,
    challenge: String,
}

fn generate_pkce() -> PkceChallenge {
    let mut rng = rand::rng();
    let verifier_bytes: Vec<u8> = (0..32).map(|_| rng.random::<u8>()).collect();
    let verifier = URL_SAFE_NO_PAD.encode(&verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    PkceChallenge {
        verifier,
        challenge,
    }
}

fn generate_state() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn build_authorize_url(
    tenant_id: &str,
    client_id: &str,
    scope: &str,
    state: &str,
    pkce: &PkceChallenge,
) -> String {
    let redirect_uri = format!("http://localhost:{}{}", REDIRECT_PORT, REDIRECT_PATH);
    format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?\
         client_id={}&response_type=code&redirect_uri={}&scope={}\
         &state={}&code_challenge={}&code_challenge_method=S256",
        tenant_id,
        urlencoded(client_id),
        urlencoded(&redirect_uri),
        urlencoded(scope),
        urlencoded(state),
        urlencoded(&pkce.challenge),
    )
}

fn urlencoded(s: &str) -> String {
    s.replace(' ', "%20")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('?', "%3F")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
}

/// Parsed callback parameters from the redirect.
struct CallbackParams {
    code: String,
    #[allow(dead_code)]
    state: String,
}

fn parse_callback_query(query: &str) -> Option<CallbackParams> {
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next()?;
        let value = kv.next().unwrap_or("");
        match key {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            _ => {}
        }
    }
    Some(CallbackParams {
        code: code?,
        state: state.unwrap_or_default(),
    })
}

/// Start a local HTTP server, open the browser, and wait for the authorization code.
fn wait_for_auth_code(
    tenant_id: &str,
    client_id: &str,
    scope: &str,
) -> Result<(String, String), AppError> {
    let pkce = generate_pkce();
    let state = generate_state();
    let authorize_url = build_authorize_url(tenant_id, client_id, scope, &state, &pkce);

    let listener =
        std::net::TcpListener::bind(format!("127.0.0.1:{}", REDIRECT_PORT)).map_err(|e| {
            AppError::Network(format!("failed to bind localhost:{}: {}", REDIRECT_PORT, e))
        })?;

    eprintln!("Opening browser for authentication...");
    open::that(&authorize_url)
        .map_err(|e| AppError::Auth(format!("failed to open browser: {}", e)))?;

    eprintln!("Waiting for callback on localhost:{}...", REDIRECT_PORT);

    let (tx, rx) = mpsc::channel();
    let tx_clone = tx.clone();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);

            let result = if let Some(query_start) = request.find('?') {
                let query_end = request[query_start..]
                    .find(' ')
                    .unwrap_or(request.len() - query_start);
                let query = &request[query_start + 1..query_start + query_end];
                parse_callback_query(query)
            } else {
                None
            };

            let response_body = match &result {
                Some(_) => {
                    "<html><body><h1>Authentication successful</h1><p>You can close this window.</p></body></html>"
                }
                None => {
                    "<html><body><h1>Authentication failed</h1><p>No authorization code received.</p></body></html>"
                }
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body,
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = std::io::Write::flush(&mut stream);
            let _ = tx_clone.send(result);
        }
    });

    let params = rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|_| AppError::Auth("timed out waiting for browser callback".to_string()))?
        .ok_or_else(|| AppError::Auth("no authorization code received".to_string()))?;

    if params.state != state {
        return Err(AppError::Auth("state mismatch in callback".to_string()));
    }

    Ok((params.code, pkce.verifier))
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Exchange the authorization code for an access token.
async fn exchange_code(
    tenant_id: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
    scope: &str,
) -> Result<(String, u64), AppError> {
    let redirect_uri = format!("http://localhost:{}{}", REDIRECT_PORT, REDIRECT_PATH);
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );

    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("code_verifier", verifier),
        ("scope", scope),
    ];

    let http = reqwest::Client::new();
    let resp = http
        .post(&token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Auth(format!("token exchange failed: {}", e)))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Auth(format!(
            "token exchange returned {}: {}",
            status, body
        )));
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Auth(format!("failed to parse token response: {}", e)))?;

    Ok((token_resp.access_token, token_resp.expires_in))
}

/// Run the full browser-based OAuth2 authorization code flow with PKCE.
pub async fn browser_login(
    tenant_id: &str,
    client_id: &str,
    scope: &str,
) -> Result<(String, u64), AppError> {
    let (code, verifier) = tokio::task::spawn_blocking({
        let tenant_id = tenant_id.to_string();
        let client_id = client_id.to_string();
        let scope = scope.to_string();
        move || wait_for_auth_code(&tenant_id, &client_id, &scope)
    })
    .await
    .map_err(|e| AppError::Auth(format!("browser auth task failed: {}", e)))??;

    eprintln!("Authentication successful.");
    exchange_code(tenant_id, client_id, &code, &verifier, scope).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pkce() {
        let pkce = generate_pkce();
        assert!(!pkce.verifier.is_empty());
        assert!(!pkce.challenge.is_empty());
        assert_ne!(pkce.verifier, pkce.challenge);
    }

    #[test]
    fn test_generate_state() {
        let state = generate_state();
        assert!(!state.is_empty());
    }

    #[test]
    fn test_parse_callback_query() {
        let query = "code=abc123&state=xyz789";
        let params = parse_callback_query(query).unwrap();
        assert_eq!(params.code, "abc123");
        assert_eq!(params.state, "xyz789");
    }

    #[test]
    fn test_parse_callback_query_missing_code() {
        let query = "state=xyz789";
        assert!(parse_callback_query(query).is_none());
    }

    #[test]
    fn test_urlencoded() {
        assert_eq!(urlencoded("a b"), "a%20b");
        assert_eq!(
            urlencoded("https://example.com"),
            "https%3A%2F%2Fexample.com"
        );
    }
}
