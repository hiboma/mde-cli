use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mde::config::MdeCredentials;
use mde::dispatch::dispatch_from_args;

fn jwt(audience: &str) -> String {
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(serde_json::json!({"aud": audience}).to_string())
    )
}

// Run sequentially because dispatch captures the process-wide stdout descriptor.
#[tokio::test]
async fn dispatch_selects_graph_for_hunting_and_incidents_and_mde_for_alerts() {
    let mut server = mockito::Server::new_async().await;
    for (args, method, path, audience, body) in [
        (
            vec![
                "mde-cli",
                "hunting",
                "run",
                "--query",
                "DeviceInfo | take 1",
            ],
            "POST",
            "/v1.0/security/runHuntingQuery",
            "https://graph.microsoft.com",
            r#"{"results":[]}"#,
        ),
        (
            vec!["mde-cli", "incidents", "list"],
            "GET",
            "/v1.0/security/incidents",
            "https://graph.microsoft.com",
            r#"{"value":[]}"#,
        ),
        (
            vec!["mde-cli", "alerts", "list"],
            "GET",
            "/api/alerts",
            "https://api.securitycenter.microsoft.com",
            r#"{"value":[]}"#,
        ),
    ] {
        let token = jwt(audience);
        let request = server
            .mock(method, path)
            .match_query(mockito::Matcher::Any)
            .match_header("authorization", format!("Bearer {token}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;
        let mut credentials = MdeCredentials {
            access_token: Some(token),
            mde_base_url: server.url(),
            graph_base_url: server.url(),
            ..Default::default()
        };
        let args: Vec<String> = args.into_iter().map(String::from).collect();
        dispatch_from_args(&args, &credentials).await.unwrap();
        request.assert_async().await;

        credentials.access_token = Some(jwt(if audience == "https://graph.microsoft.com" {
            "https://api.securitycenter.microsoft.com"
        } else {
            "https://graph.microsoft.com"
        }));
        let error = dispatch_from_args(&args, &credentials).await.unwrap_err();
        assert!(error.to_string().contains("cannot be used"));
        request.assert_async().await;
    }
}
