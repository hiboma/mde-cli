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
        "Query": args.query,
    });

    let resp: serde_json::Value = client
        .post("/api/advancedhunting/run", &body)
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
    let schema = value.get("Schema").and_then(|s| s.as_array());
    let results = value.get("Results").and_then(|r| r.as_array());

    let columns: Vec<&str> = match schema {
        Some(s) => s
            .iter()
            .filter_map(|col| col.get("Name").and_then(|n| n.as_str()))
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
