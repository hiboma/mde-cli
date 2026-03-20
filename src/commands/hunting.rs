use crate::cli::hunting::HuntingCommand;
use crate::client::MdeClient;
use crate::error::AppError;
use crate::output::OutputFormat;

pub async fn handle(
    client: &MdeClient,
    command: &HuntingCommand,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    match command {
        HuntingCommand::Run(args) => run(client, args, output_format).await,
    }
}

async fn run(
    client: &MdeClient,
    args: &crate::cli::hunting::RunArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let body = serde_json::json!({
        "query": args.query,
    });

    let resp: serde_json::Value = client
        .post("/v1.0/security/runHuntingQuery", &body)
        .await?
        .json()
        .await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_hunting_table(&resp);
            Ok(())
        }
    }
}

fn print_hunting_table(value: &serde_json::Value) {
    let schema = value.get("schema").and_then(|s| s.as_array());
    let results = value.get("results").and_then(|r| r.as_array());

    let columns: Vec<&str> = match schema {
        Some(s) => s
            .iter()
            .filter_map(|col| col.get("name").and_then(|n| n.as_str()))
            .collect(),
        None => {
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_default()
            );
            return;
        }
    };

    if columns.is_empty() {
        return;
    }

    // Print header
    let header: Vec<String> = columns.iter().map(|c| format!("{:<30}", c)).collect();
    println!("{}", header.join(" "));

    // Print rows
    if let Some(rows) = results {
        for row in rows {
            let line: Vec<String> = columns
                .iter()
                .map(|col| {
                    let val = row
                        .get(*col)
                        .map(|v| match v {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Null => "-".to_string(),
                            other => other.to_string(),
                        })
                        .unwrap_or_else(|| "-".to_string());
                    format!("{:<30}", val)
                })
                .collect();
            println!("{}", line.join(" "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_request_body_uses_query_field() {
        let query = "DeviceProcessEvents | take 10";
        let body = json!({
            "query": query,
        });
        assert_eq!(body["query"], query);
        assert!(body.get("Query").is_none());
        assert!(body.get("QueryString").is_none());
    }

    #[test]
    fn test_print_hunting_table_with_graph_api_response() {
        // Graph API の runHuntingQuery レスポンス形式（小文字キー）
        let resp = json!({
            "schema": [
                {"name": "DeviceName", "type": "String"},
                {"name": "ProcessId", "type": "Int64"}
            ],
            "results": [
                {"DeviceName": "host1", "ProcessId": 1234},
                {"DeviceName": "host2", "ProcessId": 5678}
            ]
        });
        print_hunting_table(&resp);
    }

    #[test]
    fn test_print_hunting_table_empty_results() {
        let resp = json!({
            "schema": [
                {"name": "DeviceName", "type": "String"}
            ],
            "results": []
        });
        print_hunting_table(&resp);
    }

    #[test]
    fn test_print_hunting_table_no_schema() {
        // schema がない場合は JSON をそのまま出力する
        let resp = json!({"error": "something went wrong"});
        print_hunting_table(&resp);
    }

    #[test]
    fn test_print_hunting_table_empty_schema() {
        let resp = json!({
            "schema": [],
            "results": [{"foo": "bar"}]
        });
        print_hunting_table(&resp);
    }

    #[test]
    fn test_print_hunting_table_null_value_in_row() {
        let resp = json!({
            "schema": [
                {"name": "DeviceName", "type": "String"},
                {"name": "Status", "type": "String"}
            ],
            "results": [
                {"DeviceName": "host1", "Status": null}
            ]
        });
        print_hunting_table(&resp);
    }

    #[test]
    fn test_print_hunting_table_missing_column_in_row() {
        let resp = json!({
            "schema": [
                {"name": "DeviceName", "type": "String"},
                {"name": "Missing", "type": "String"}
            ],
            "results": [
                {"DeviceName": "host1"}
            ]
        });
        print_hunting_table(&resp);
    }
}
