use crate::cli::machines::MachinesCommand;
use crate::client::MdeClient;
use crate::error::AppError;
use crate::output::OutputFormat;

pub async fn handle(
    client: &MdeClient,
    command: &MachinesCommand,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    match command {
        MachinesCommand::List(args) => list(client, args, output_format, raw).await,
        MachinesCommand::Get(args) => get(client, args, output_format).await,
        MachinesCommand::Timeline(args) => timeline(client, args, output_format, raw).await,
        MachinesCommand::LogonUsers(args) => logon_users(client, args, output_format, raw).await,
        MachinesCommand::AddTag(args) => update_tag(client, args, "Add", output_format).await,
        MachinesCommand::RemoveTag(args) => update_tag(client, args, "Remove", output_format).await,
    }
}

async fn update_tag(
    client: &MdeClient,
    args: &crate::cli::machines::TagArgs,
    action: &str,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    if args.value.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "tag value must not be empty or whitespace-only".to_string(),
        ));
    }

    let path = format!("/api/machines/{}/tags", args.id);
    let body = serde_json::json!({
        "Value": args.value,
        "Action": action,
    });

    let resp: serde_json::Value = client.post(&path, &body).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => crate::output::json::print_json_raw(&resp, false),
    }
}

async fn list(
    client: &MdeClient,
    args: &crate::cli::machines::ListArgs,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    let mut query: Vec<(String, String)> = Vec::new();
    query.push(("$top".to_string(), args.top.to_string()));

    if let Some(ref filter) = args.filter {
        query.push(("$filter".to_string(), filter.clone()));
    }

    let resp: serde_json::Value = client
        .get_with_query("/api/machines", &query)
        .await?
        .json()
        .await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_data(&resp, raw, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_machines_table(&resp);
            Ok(())
        }
    }
}

fn print_machines_table(value: &serde_json::Value) {
    use crate::output::table::{format_timestamp, truncate};

    println!(
        "{:<42} {:<30} {:<20} {:<14} {:<24}",
        "ID", "NAME", "OS", "HEALTH", "LAST SEEN"
    );

    if let Some(data) = value.get("value").and_then(|d| d.as_array()) {
        for item in data {
            let id = item.get("id").and_then(|i| i.as_str()).unwrap_or("-");
            let name = item
                .get("computerDnsName")
                .and_then(|n| n.as_str())
                .unwrap_or("-");
            let os = item
                .get("osPlatform")
                .and_then(|o| o.as_str())
                .unwrap_or("-");
            let health = item
                .get("healthStatus")
                .and_then(|h| h.as_str())
                .unwrap_or("-");
            let last_seen = format_timestamp(item.get("lastSeen").and_then(|t| t.as_str()));

            println!(
                "{:<42} {:<30} {:<20} {:<14} {:<24}",
                truncate(id, 40),
                truncate(name, 28),
                truncate(os, 18),
                health,
                last_seen,
            );
        }
    }
}

async fn get(
    client: &MdeClient,
    args: &crate::cli::machines::GetArgs,
    output_format: OutputFormat,
) -> Result<(), AppError> {
    let path = format!("/api/machines/{}", args.id);
    let resp: serde_json::Value = client.get(&path).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_raw(&resp, output_format.is_minify())
        }
        OutputFormat::Table => crate::output::json::print_json_raw(&resp, false),
    }
}

async fn timeline(
    client: &MdeClient,
    args: &crate::cli::machines::TimelineArgs,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    let path = format!("/api/machines/{}/timeline", args.id);
    let query = vec![("$top".to_string(), args.top.to_string())];

    let resp: serde_json::Value = client.get_with_query(&path, &query).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_data(&resp, raw, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_timeline_table(&resp);
            Ok(())
        }
    }
}

fn print_timeline_table(value: &serde_json::Value) {
    use crate::output::table::{format_timestamp, truncate};

    println!("{:<24} {:<20} {:<50}", "TIME", "ACTION", "DETAILS");

    if let Some(data) = value.get("value").and_then(|d| d.as_array()) {
        for item in data {
            let time = format_timestamp(item.get("eventTime").and_then(|t| t.as_str()));
            let action = item
                .get("actionType")
                .and_then(|a| a.as_str())
                .unwrap_or("-");
            let details = item
                .get("fileName")
                .and_then(|f| f.as_str())
                .or_else(|| item.get("processCommandLine").and_then(|p| p.as_str()))
                .or_else(|| item.get("remoteUrl").and_then(|r| r.as_str()))
                .unwrap_or("-");

            println!(
                "{:<24} {:<20} {:<50}",
                time,
                truncate(action, 18),
                truncate(details, 48),
            );
        }
    }
}

async fn logon_users(
    client: &MdeClient,
    args: &crate::cli::machines::LogonUsersArgs,
    output_format: OutputFormat,
    raw: bool,
) -> Result<(), AppError> {
    let path = format!("/api/machines/{}/logonusers", args.id);
    let resp: serde_json::Value = client.get(&path).await?.json().await?;

    match output_format {
        OutputFormat::Json | OutputFormat::JsonMinify => {
            crate::output::json::print_json_data(&resp, raw, output_format.is_minify())
        }
        OutputFormat::Table => {
            print_logon_users_table(&resp);
            Ok(())
        }
    }
}

fn print_logon_users_table(value: &serde_json::Value) {
    use crate::output::table::{format_timestamp, truncate};

    println!(
        "{:<30} {:<30} {:<24} {:<12}",
        "ACCOUNT", "DOMAIN", "LAST SEEN", "TYPE"
    );

    if let Some(data) = value.get("value").and_then(|d| d.as_array()) {
        for item in data {
            let account = item
                .get("accountName")
                .and_then(|a| a.as_str())
                .unwrap_or("-");
            let domain = item
                .get("accountDomain")
                .and_then(|d| d.as_str())
                .unwrap_or("-");
            let last_seen = format_timestamp(item.get("lastSeenDateTime").and_then(|t| t.as_str()));
            let logon_type = item
                .get("logonTypes")
                .and_then(|l| l.as_str())
                .unwrap_or("-");

            println!(
                "{:<30} {:<30} {:<24} {:<12}",
                truncate(account, 28),
                truncate(domain, 28),
                last_seen,
                logon_type,
            );
        }
    }
}
