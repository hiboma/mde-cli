use std::io::{self, Write};

use crate::error::AppError;

fn writeln_stdout(s: &str) -> Result<(), AppError> {
    match writeln!(io::stdout(), "{}", s) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(AppError::Io(e)),
    }
}

pub fn print_json_raw(value: &serde_json::Value, minify: bool) -> Result<(), AppError> {
    let output = if minify {
        serde_json::to_string(value)?
    } else {
        serde_json::to_string_pretty(value)?
    };
    writeln_stdout(&output)
}

pub fn print_json_data(value: &serde_json::Value, raw: bool, minify: bool) -> Result<(), AppError> {
    if raw {
        print_json_raw(value, minify)
    } else {
        let data = value.get("value").unwrap_or(value);
        print_json_raw(data, minify)
    }
}
