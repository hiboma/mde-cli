use crate::cli::indicators::IndicatorsCommand;
use crate::client::MdeClient;
use crate::error::AppError;
use crate::models::indicator::{IndicatorAction, IndicatorType};
use crate::output::OutputFormat;

pub async fn handle(
    client: &MdeClient,
    command: &IndicatorsCommand,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    match command {
        IndicatorsCommand::List(args) => list(client, args, output_format, raw).await,
        IndicatorsCommand::Create(args) => create(client, args, output_format).await,
        IndicatorsCommand::Delete(args) => delete(client, args).await,
    }
}

async fn list(
    client: &MdeClient,
    args: &crate::cli::indicators::ListArgs,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    let mut query: Vec<(String, String)> = Vec::new();
    query.push(("$top".to_string(), args.top.to_string()));

    let mut filters: Vec<String> = Vec::new();

    if let Some(ref indicator_type) = args.indicator_type {
        let t = IndicatorType::from_str_loose(indicator_type).ok_or_else(|| {
            AppError::InvalidInput(format!("unknown indicatorType: {}", indicator_type))
        })?;
        filters.push(format!("indicatorType eq '{}'", t.as_str()));
    }

    if let Some(ref action) = args.action {
        let a = IndicatorAction::from_str_loose(action)
            .ok_or_else(|| AppError::InvalidInput(format!("unknown action: {}", action)))?;
        filters.push(format!("action eq '{}'", a.as_str()));
    }

    if !filters.is_empty() {
        query.push(("$filter".to_string(), filters.join(" and ")));
    }

    let resp: serde_json::Value = client
        .get_with_query("/api/indicators", &query)
        .await?
        .json()
        .await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_data(&resp, raw, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_indicators_table(&resp);
            Ok(())
        }
    }
}

fn print_indicators_table(value: &serde_json::Value) {
    use crate::output::table::truncate;

    println!(
        "{:<10} {:<22} {:<14} {:<50} {:<20}",
        "ID", "TYPE", "ACTION", "VALUE", "TITLE"
    );

    if let Some(data) = value.get("value").and_then(|d| d.as_array()) {
        for item in data {
            let id = item
                .get("id")
                .and_then(|i| i.as_u64())
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".to_string());
            let indicator_type = item
                .get("indicatorType")
                .and_then(|t| t.as_str())
                .unwrap_or("-");
            let action = item.get("action").and_then(|a| a.as_str()).unwrap_or("-");
            let value_str = item
                .get("indicatorValue")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("-");

            println!(
                "{:<10} {:<22} {:<14} {:<50} {:<20}",
                truncate(&id, 10),
                truncate(indicator_type, 20),
                truncate(action, 12),
                truncate(value_str, 48),
                truncate(title, 18),
            );
        }
    }
}

async fn create(
    client: &MdeClient,
    args: &crate::cli::indicators::CreateArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let indicator_type = IndicatorType::from_str_loose(&args.indicator_type).ok_or_else(|| {
        AppError::InvalidInput(format!("unknown indicatorType: {}", args.indicator_type))
    })?;

    let action = IndicatorAction::from_str_loose(&args.action)
        .ok_or_else(|| AppError::InvalidInput(format!("unknown action: {}", args.action)))?;

    let mut body = serde_json::json!({
        "indicatorValue": args.indicator_value,
        "indicatorType": indicator_type.as_str(),
        "action": action.as_str(),
        "title": args.title,
        "generateAlert": !args.no_alert,
    });

    if let Some(ref description) = args.description {
        body["description"] = serde_json::json!(description);
    }

    if let Some(ref severity) = args.severity {
        body["severity"] = serde_json::json!(severity);
    }

    if let Some(ref expiration_time) = args.expiration_time {
        body["expirationTime"] = serde_json::json!(expiration_time);
    }

    let resp: serde_json::Value = client.post("/api/indicators", &body).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => crate::output::json::print_json_raw(&resp, false),
    }
}

async fn delete(
    client: &MdeClient,
    args: &crate::cli::indicators::DeleteArgs,
) -> Result<(), AppError> {
    let path = format!("/api/indicators/{}", args.id);
    client.delete(&path).await?;
    println!("Indicator {} deleted.", args.id);
    Ok(())
}
