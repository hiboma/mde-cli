use reqwest::Response;

use crate::error::AppError;

/// Check the HTTP response status and convert errors.
pub async fn check_response(response: Response) -> Result<Response, AppError> {
    check_response_with_graph_hint(response, false).await
}

pub(crate) async fn check_response_with_graph_hint(
    response: Response,
    graph_permissions_hint: bool,
) -> Result<Response, AppError> {
    let status = response.status();

    if status.is_success() {
        return Ok(response);
    }

    let status_code = status.as_u16();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "failed to read response body".to_string());

    let graph_hint = "Microsoft Graph permissions or admin consent may be missing. For browser login, verify the delegated permissions ThreatHunting.Read.All (hunting) or SecurityIncident.ReadWrite.All (incidents) and admin consent. For client-secret authentication, verify the corresponding application permissions and admin consent.";

    match status_code {
        401 if graph_permissions_hint => Err(AppError::Auth(format!(
            "authentication failed. Verify your credentials. {graph_hint}"
        ))),
        403 if graph_permissions_hint => Err(AppError::Api {
            status: status_code,
            message: format!("{body}\n{graph_hint}"),
        }),
        401 => Err(AppError::Auth(
            "authentication failed. Verify your credentials.".to_string(),
        )),
        429 => Err(AppError::RateLimited),
        400..=499 => Err(AppError::Api {
            status: status_code,
            message: body,
        }),
        500..=599 => Err(AppError::Api {
            status: status_code,
            message: body,
        }),
        _ => Err(AppError::Api {
            status: status_code,
            message: body,
        }),
    }
}
