use crate::cli::alerts::AlertsCommand;
use crate::client::MdeClient;
use crate::error::AppError;
use crate::models::alert::{AlertStatus, Classification, Determination, Severity};
use crate::output::OutputFormat;

pub async fn handle(
    client: &MdeClient,
    command: &AlertsCommand,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    match command {
        AlertsCommand::List(args) => list(client, args, output_format, raw).await,
        AlertsCommand::Get(args) => get(client, args, output_format).await,
        AlertsCommand::Update(args) => update(client, args, output_format).await,
        AlertsCommand::Files(args) => {
            related_entity(client, &args.id, "files", output_format).await
        }
        AlertsCommand::Ips(args) => related_entity(client, &args.id, "ips", output_format).await,
        AlertsCommand::Domains(args) => {
            related_entity(client, &args.id, "domains", output_format).await
        }
    }
}

async fn list(
    client: &MdeClient,
    args: &crate::cli::alerts::ListArgs,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    let mut query: Vec<(String, String)> = Vec::new();
    query.push(("$top".to_string(), args.top.to_string()));

    let mut filters: Vec<String> = Vec::new();

    if let Some(ref status) = args.status {
        let s = AlertStatus::from_str_loose(status)
            .ok_or_else(|| AppError::InvalidInput(format!("unknown status: {}", status)))?;
        filters.push(format!("status eq '{}'", s.as_str()));
    }

    if let Some(ref severity) = args.severity {
        let s = Severity::from_str_loose(severity)
            .ok_or_else(|| AppError::InvalidInput(format!("unknown severity: {}", severity)))?;
        filters.push(format!("severity eq '{}'", s.as_str()));
    }

    if let Some(ref filter) = args.filter {
        filters.push(filter.clone());
    }

    if !filters.is_empty() {
        query.push(("$filter".to_string(), filters.join(" and ")));
    }

    if args.expand_evidence {
        query.push(("$expand".to_string(), "evidence".to_string()));
    }

    let resp: serde_json::Value = client
        .get_with_query("/api/alerts", &query)
        .await?
        .json()
        .await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_data(&resp, raw, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_alerts_table(&resp);
            Ok(())
        }
    }
}

fn print_alerts_table(value: &serde_json::Value) {
    use crate::output::table::{format_timestamp, truncate};

    println!(
        "{:<40} {:<45} {:<14} {:<12} {:<24}",
        "ID", "TITLE", "SEVERITY", "STATUS", "CREATED"
    );

    if let Some(data) = value.get("value").and_then(|d| d.as_array()) {
        for item in data {
            let id = item.get("id").and_then(|i| i.as_str()).unwrap_or("-");
            let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("-");
            let severity = item.get("severity").and_then(|s| s.as_str()).unwrap_or("-");
            let status = item.get("status").and_then(|s| s.as_str()).unwrap_or("-");
            let created = format_timestamp(item.get("alertCreationTime").and_then(|t| t.as_str()));

            println!(
                "{:<40} {:<45} {:<14} {:<12} {:<24}",
                truncate(id, 38),
                truncate(title, 43),
                severity,
                status,
                created,
            );
        }
    }
}

async fn get(
    client: &MdeClient,
    args: &crate::cli::alerts::GetArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let path = format!("/api/alerts/{}", args.id);
    let resp: serde_json::Value = client.get(&path).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => crate::output::json::print_json_raw(&resp, false),
    }
}

async fn update(
    client: &MdeClient,
    args: &crate::cli::alerts::UpdateArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let mut body = serde_json::Map::new();

    if let Some(ref status) = args.status {
        let s = AlertStatus::from_str_loose(status)
            .ok_or_else(|| AppError::InvalidInput(format!("unknown status: {}", status)))?;
        body.insert("status".to_string(), serde_json::json!(s.as_str()));
    }

    if let Some(ref classification) = args.classification {
        let c = Classification::from_str_loose(classification).ok_or_else(|| {
            AppError::InvalidInput(format!("unknown classification: {}", classification))
        })?;
        body.insert("classification".to_string(), serde_json::json!(c.as_str()));
    }

    if let Some(ref determination) = args.determination {
        let d = Determination::from_str_loose(determination).ok_or_else(|| {
            AppError::InvalidInput(format!("unknown determination: {}", determination))
        })?;
        body.insert("determination".to_string(), serde_json::json!(d.as_str()));
    }

    if let Some(ref assigned_to) = args.assigned_to {
        body.insert("assignedTo".to_string(), serde_json::json!(assigned_to));
    }

    if let Some(ref comment) = args.comment {
        body.insert("comment".to_string(), serde_json::json!(comment));
    }

    if body.is_empty() {
        return Err(AppError::InvalidInput(
            "no fields to update. Use --status, --classification, --determination, --assigned-to, or --comment.".to_string(),
        ));
    }

    let path = format!("/api/alerts/{}", args.id);
    let resp: serde_json::Value = client
        .patch(&path, &serde_json::Value::Object(body))
        .await?
        .json()
        .await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => crate::output::json::print_json_raw(&resp, false),
    }
}

async fn related_entity(
    client: &MdeClient,
    alert_id: &str,
    entity: &str,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let path = format!("/api/alerts/{}/{}", alert_id, entity);
    let resp: serde_json::Value = client.get(&path).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => crate::output::json::print_json_raw(&resp, false),
    }
}
