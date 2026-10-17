use assert_cmd::cargo::cargo_bin_cmd;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use predicates::prelude::*;

fn jwt(audience: &str) -> String {
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(serde_json::json!({"aud": audience}).to_string())
    )
}

#[test]
fn cli_selects_graph_for_hunting_and_incidents_and_mde_for_alerts() {
    let mut graph = mockito::Server::new();
    let mut mde = mockito::Server::new();
    let config = tempfile::tempdir().unwrap();
    std::fs::write(
        config.path().join(".mde-credentials.toml"),
        format!(
            "[credentials]\nmde_base_url = {:?}\ngraph_base_url = {:?}\n",
            mde.url(),
            graph.url()
        ),
    )
    .unwrap();

    for (args, method, path, audience, body, is_graph) in [
        (
            vec!["hunting", "run", "--query", "DeviceInfo | take 1"],
            "POST",
            "/v1.0/security/runHuntingQuery",
            "https://graph.microsoft.com",
            r#"{"results":[]}"#,
            true,
        ),
        (
            vec!["incidents", "list"],
            "GET",
            "/v1.0/security/incidents",
            "https://graph.microsoft.com",
            r#"{"value":[]}"#,
            true,
        ),
        (
            vec!["alerts", "list"],
            "GET",
            "/api/alerts",
            "https://api.securitycenter.microsoft.com",
            r#"{"value":[]}"#,
            false,
        ),
    ] {
        let token = jwt(audience);
        let server = if is_graph { &mut graph } else { &mut mde };
        let request = server
            .mock(method, path)
            .match_query(mockito::Matcher::Any)
            .match_header("authorization", format!("Bearer {token}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create();
        let command = |token: String| {
            let mut cmd = cargo_bin_cmd!("mde-cli");
            cmd.timeout(std::time::Duration::from_secs(30))
                .current_dir(config.path())
                .env("XDG_CONFIG_HOME", config.path())
                .env("MDE_ACCESS_TOKEN", token)
                .env("MDE_CLIENT_SECRET", "test-secret")
                .env_remove("MDE_TENANT_ID")
                .env_remove("MDE_CLIENT_ID")
                .env("MDE_OUTPUT_FORMAT", "json")
                .args(&args);
            cmd
        };
        let output = command(token)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let expected = if args[0] == "hunting" {
            serde_json::json!({"results": []})
        } else {
            serde_json::json!([])
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            expected
        );
        request.assert();

        let wrong_token = jwt(if is_graph {
            "https://api.securitycenter.microsoft.com"
        } else {
            "https://graph.microsoft.com"
        });
        let rejected_request = server
            .mock(method, path)
            .match_query(mockito::Matcher::Any)
            .match_header("authorization", format!("Bearer {wrong_token}").as_str())
            .expect(0)
            .create();
        command(wrong_token)
            .assert()
            .failure()
            .stderr(predicate::str::contains("cannot be used"));
        rejected_request.assert();
        request.assert();
    }
}
