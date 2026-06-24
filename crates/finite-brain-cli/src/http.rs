use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use nostr::Keys;

use crate::{
    CliEnvironment, CliError, HealthCheck, HttpResponse, SyncOnceReport, current_tree_root,
    find_agent_state, mutate_agent_state, option_value, read_agent_state, read_auth_required,
    read_working_tree_state, signed_http_auth_header, write_json_file,
};

pub(crate) fn check_http_health(url: &str) -> HealthCheck {
    let Some((host, port, path)) = parse_http_url(url) else {
        return HealthCheck::warn("server health skipped: only http URLs are supported");
    };
    let address = format!("{host}:{port}");
    let Some(socket_address) = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
    else {
        return HealthCheck::warn(format!("server address could not be resolved: {address}"));
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&socket_address, Duration::from_millis(500))
    else {
        return HealthCheck::warn(format!("server unavailable at {address}"));
    };
    let health_path = if path == "/" {
        "/health".to_owned()
    } else {
        format!("{path}/health")
    };
    let request =
        format!("GET {health_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return HealthCheck::warn("server health request failed");
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return HealthCheck::warn("server health response failed");
    }
    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
        HealthCheck::ok(format!("server healthy at {url}"))
    } else {
        HealthCheck::warn(format!("server health did not return 200 at {url}"))
    }
}

pub(crate) fn sync_once(
    env: &CliEnvironment,
    activity_kind: &str,
) -> Result<SyncOnceReport, CliError> {
    let root = current_tree_root(env)?;
    let state = read_agent_state(&root)?;
    let server_url = state
        .server_url
        .clone()
        .or_else(|| env::var("FINITE_BRAIN_PUBLIC_BASE_URL").ok())
        .ok_or(CliError::MissingServer)?;
    let mut tree_state = read_working_tree_state(&root)?;
    let path = if tree_state.sync.latest_sequence == 0 {
        format!("/_admin/vaults/{}/sync/bootstrap", state.vault_id)
    } else {
        format!(
            "/_admin/vaults/{}/sync/records?after={}&limit=100",
            state.vault_id, tree_state.sync.latest_sequence
        )
    };
    let response = signed_json_request_to_server(env, &server_url, "GET", &path, None)?;
    let latest_sequence = response
        .get("latestSequence")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(tree_state.sync.latest_sequence);
    let record_count = response
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            response
                .get("objectCount")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0) as usize;
    let sync_dir = root.join(".finitebrain/encrypted-sync");
    fs::create_dir_all(&sync_dir)?;
    let file_name = if tree_state.sync.latest_sequence == 0 {
        "bootstrap.json".to_owned()
    } else {
        format!("records-after-{}.json", tree_state.sync.latest_sequence)
    };
    write_json_file(&sync_dir.join(file_name), &response)?;
    tree_state.sync.latest_sequence = latest_sequence;
    write_json_file(
        &root.join(".finitebrain/working-tree-state.json"),
        &tree_state,
    )?;
    let status = if record_count == 0 {
        "caught-up".to_owned()
    } else {
        "applied-remote-records".to_owned()
    };
    let report = SyncOnceReport {
        status: status.clone(),
        latest_sequence,
        record_count,
        server_url,
    };
    mutate_agent_state(env, |state, now| {
        state.sync.status = status;
        state.add_activity(
            now,
            activity_kind,
            format!("Automatic sync observed latest sequence {latest_sequence}"),
        );
        Ok(())
    })?;
    Ok(report)
}

pub(crate) fn signed_json_request(
    env: &CliEnvironment,
    args: &[String],
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, CliError> {
    let server_url = server_url_for_command(env, args)?;
    signed_json_request_to_server(env, &server_url, method, path, body)
}

pub(crate) fn signed_json_request_to_server(
    env: &CliEnvironment,
    server_url: &str,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, CliError> {
    let body = body.map(|body| serde_json::to_vec(&body)).transpose()?;
    let url = absolute_server_url(server_url, path);
    let auth = read_auth_required(env)?;
    let keys = Keys::parse(&auth.secret_key)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let authorization = signed_http_auth_header(&keys, method, &url, body.as_deref())?;
    let response = http_request(method, &url, Some(&authorization), body.as_deref())?;
    if !(200..300).contains(&response.status) {
        return Err(CliError::Http(format!(
            "server returned {}: {}",
            response.status,
            response.body.trim()
        )));
    }
    if response.body.trim().is_empty() {
        return Ok(serde_json::json!({ "status": "ok" }));
    }
    serde_json::from_str(&response.body).map_err(CliError::from)
}

pub(crate) fn http_request(
    method: &str,
    url: &str,
    authorization: Option<&str>,
    body: Option<&[u8]>,
) -> Result<HttpResponse, CliError> {
    let Some((host, port, path)) = parse_http_url(url) else {
        return Err(CliError::Unsupported(
            "fbrain prototype HTTP client supports http:// URLs only".to_owned(),
        ));
    };
    let address = format!("{host}:{port}");
    let socket_address = address
        .to_socket_addrs()
        .map_err(|error| CliError::Http(error.to_string()))?
        .next()
        .ok_or_else(|| {
            CliError::Http(format!("server address could not be resolved: {address}"))
        })?;
    let mut stream = TcpStream::connect_timeout(&socket_address, Duration::from_secs(2))
        .map_err(|error| CliError::Http(error.to_string()))?;
    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(authorization) = authorization {
        request.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| CliError::Http("malformed HTTP response".to_owned()))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| CliError::Http("HTTP status did not parse".to_owned()))?;
    Ok(HttpResponse {
        status,
        body: body.to_owned(),
    })
}

pub(crate) fn server_url_for_command(
    env: &CliEnvironment,
    args: &[String],
) -> Result<String, CliError> {
    option_value(args, "--server")
        .or_else(|| {
            find_agent_state(&env.cwd)
                .ok()
                .flatten()
                .and_then(|root| read_agent_state(&root).ok())
                .and_then(|state| state.server_url)
        })
        .or_else(|| env::var("FINITE_BRAIN_PUBLIC_BASE_URL").ok())
        .ok_or(CliError::MissingServer)
}

pub(crate) fn absolute_server_url(server_url: &str, path: &str) -> String {
    format!(
        "{}{}",
        server_url.trim_end_matches('/'),
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    )
}

pub(crate) fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = host_port
        .split_once(':')
        .map(|(host, port)| (host.to_owned(), port.parse().ok()))
        .unwrap_or_else(|| (host_port.to_owned(), Some(80)));
    Some((host, port?, format!("/{}", path.trim_end_matches('/'))))
}
