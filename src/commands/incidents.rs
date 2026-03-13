use crate::cli::incidents::IncidentsCommand;
use crate::client::MdeClient;
use crate::error::AppError;
use crate::models::incident::IncidentStatus;
use crate::output::OutputFormat;

pub async fn handle(
    client: &MdeClient,
    command: &IncidentsCommand,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    match command {
        IncidentsCommand::List(args) => list(client, args, output_format, raw).await,
        IncidentsCommand::Get(args) => get(client, args, output_format).await,
        IncidentsCommand::Update(args) => update(client, args, output_format).await,
    }
}

async fn list(
    client: &MdeClient,
    args: &crate::cli::incidents::ListArgs,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    let mut query: Vec<(String, String)> = Vec::new();
    query.push(("$top".to_string(), args.top.to_string()));

    let mut filters: Vec<String> = Vec::new();

    if let Some(ref status) = args.status {
        let s = IncidentStatus::from_str_loose(status)
            .ok_or_else(|| AppError::InvalidInput(format!("unknown status: {}", status)))?;
        filters.push(format!("status eq '{}'", s.as_str()));
    }

    if let Some(ref severity) = args.severity {
        // Graph API uses lowercase severity values
        let valid = ["informational", "low", "medium", "high"];
        let lower = severity.to_lowercase();
        if !valid.contains(&lower.as_str()) {
            return Err(AppError::InvalidInput(format!(
                "unknown severity: {}",
                severity
            )));
        }
        filters.push(format!("severity eq '{}'", lower));
    }

    if let Some(ref filter) = args.filter {
        filters.push(filter.clone());
    }

    if !filters.is_empty() {
        query.push(("$filter".to_string(), filters.join(" and ")));
    }

    if args.expand_alerts {
        query.push(("$expand".to_string(), "alerts".to_string()));
    }

    let resp: serde_json::Value = client
        .get_with_query("/v1.0/security/incidents", &query)
        .await?
        .json()
        .await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_data(&resp, raw, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_incidents_table(&resp);
            Ok(())
        }
    }
}

fn print_incidents_table(value: &serde_json::Value) {
    use crate::output::table::{format_timestamp, truncate};

    println!(
        "{:<8} {:<55} {:<14} {:<10} {:<24}",
        "ID", "NAME", "SEVERITY", "STATUS", "CREATED"
    );

    if let Some(data) = value.get("value").and_then(|d| d.as_array()) {
        for item in data {
            let id = item.get("id").and_then(|i| i.as_str()).unwrap_or("-");
            let name = item
                .get("displayName")
                .and_then(|n| n.as_str())
                .unwrap_or("-");
            let severity = item.get("severity").and_then(|s| s.as_str()).unwrap_or("-");
            let status = item.get("status").and_then(|s| s.as_str()).unwrap_or("-");
            let created = format_timestamp(item.get("createdDateTime").and_then(|t| t.as_str()));

            println!(
                "{:<8} {:<55} {:<14} {:<10} {:<24}",
                id,
                truncate(name, 53),
                severity,
                status,
                created,
            );
        }
    }
}

async fn get(
    client: &MdeClient,
    args: &crate::cli::incidents::GetArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let mut path = format!("/v1.0/security/incidents/{}", args.id);
    if args.expand_alerts {
        path.push_str("?$expand=alerts");
    }

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
    args: &crate::cli::incidents::UpdateArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let mut body = serde_json::Map::new();

    if let Some(ref status) = args.status {
        let s = IncidentStatus::from_str_loose(status)
            .ok_or_else(|| AppError::InvalidInput(format!("unknown status: {}", status)))?;
        body.insert("status".to_string(), serde_json::json!(s.as_str()));
    }

    if let Some(ref classification) = args.classification {
        body.insert(
            "classification".to_string(),
            serde_json::json!(classification),
        );
    }

    if let Some(ref determination) = args.determination {
        body.insert(
            "determination".to_string(),
            serde_json::json!(determination),
        );
    }

    if let Some(ref assigned_to) = args.assigned_to {
        body.insert("assignedTo".to_string(), serde_json::json!(assigned_to));
    }

    if !args.tag.is_empty() {
        body.insert("customTags".to_string(), serde_json::json!(args.tag));
    }

    if let Some(ref comment) = args.comment {
        body.insert("resolvingComment".to_string(), serde_json::json!(comment));
    }

    if body.is_empty() {
        return Err(AppError::InvalidInput(
            "no fields to update. Use --status, --classification, --determination, --assigned-to, --tag, or --comment.".to_string(),
        ));
    }

    let path = format!("/v1.0/security/incidents/{}", args.id);
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
