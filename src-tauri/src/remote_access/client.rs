use super::*;

#[derive(Serialize, Deserialize)]
struct Connection {
    link: String,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}
fn entry(id: &str) -> Result<keyring::Entry, String> {
    if !id.starts_with("env-")
        || id.len() > 80
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid environment ID".into());
    }
    keyring::Entry::new("Yougori.RemoteAccess.v1", id)
        .map_err(|_| "OS credential storage unavailable".into())
}
pub(super) fn share_url(link: &str) -> Result<(String, String), String> {
    let url =
        url::Url::parse(link.trim()).map_err(|_| "Enter the HTTPS share link from its owner")?;
    let id = url
        .path()
        .strip_prefix("/share/")
        .filter(|s| {
            s.starts_with("share-")
                && s.len() == 38
                && s[6..].bytes().all(|b| b.is_ascii_hexdigit())
        })
        .ok_or("Use the complete link ending in /share/share-…")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
        || url.host_str().is_none()
    {
        return Err(
            "Use an HTTPS share link without credentials, query parameters or a custom port".into(),
        );
    }
    Ok((url.origin().ascii_serialization(), id.into()))
}
async fn call(link: &str, token: Option<&str>, body: Value) -> Result<Value, String> {
    let (base, _) = share_url(link)?;
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    let client = CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(12))
                .timeout(Duration::from_secs(95))
                .build()
                .map_err(|_| "Cannot create secure connection".to_owned())
        })
        .as_ref()
        .map_err(Clone::clone)?;
    let mut request = client
        .post(format!(
            "{base}/remote/{}",
            if token.is_some() { "rpc" } else { "login" }
        ))
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token)
    }
    let mut response = request.send().await.map_err(|_| {
        "Cannot reach the owner. Keep Yougori and its tunnel running on the sharing computer."
    })?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Remote connection interrupted")?
    {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err("Remote response exceeds the limit".into());
        }
        bytes.extend_from_slice(&chunk)
    }
    decode_response(status, &bytes)
}

fn decode_response(status: reqwest::StatusCode, bytes: &[u8]) -> Result<Value, String> {
    let result: Value = serde_json::from_slice(bytes).map_err(|_| {
        match status.as_u16() {
            530 => "The Cloudflare tunnel is unavailable. Quick links change when the tunnel restarts. Ask the owner for the current full share link and reconnect.",
            502 | 503 | 504 | 520..=524 => "The sharing gateway is temporarily unreachable. Keep Yougori and its tunnel running on the owner's computer, then retry.",
            301..=399 | 401 | 403 => "The link returned a login page or access restriction instead of Yougori. Check that the domain routes to the Yougori sharing gateway.",
            404 | 410 => "This sharing address is no longer available. Ask the owner for the current full share link and reconnect.",
            _ => "The link did not return a Yougori sharing response. Check the owner's current full share link and tunnel status.",
        }.to_owned()
    })?;
    if status.is_success() {
        Ok(result)
    } else {
        Err(result["error"]
            .as_str()
            .unwrap_or("Remote access was refused")
            .chars()
            .take(1000)
            .collect())
    }
}
pub(crate) async fn request_saved(
    env: &Environment,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let saved = entry(&env.id)?.get_password().map_err(|_| {
        "Remote session unavailable. Connect again with the owner's link and credentials."
    })?;
    let saved: Connection =
        serde_json::from_str(&saved).map_err(|_| "Invalid saved remote session")?;
    call(
        &saved.link,
        Some(&saved.token),
        json!({"method":method,"params":params}),
    )
    .await
}
pub(crate) fn bridge_credentials(env: &Environment) -> Result<(String, String), String> {
    if !env.runtime.starts_with("shared://tunnel/") {
        return Err("This sharing invitation cannot carry private connections".into());
    }
    let saved = entry(&env.id)?.get_password().map_err(|_| "Sign in to the shared environment again")?;
    let saved: Connection = serde_json::from_str(&saved).map_err(|_| "Invalid saved remote session")?;
    let (base, _) = share_url(&saved.link)?;
    if saved.token.len() != 64 || !saved.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Sign in to the shared environment again".into());
    }
    Ok((format!("{}/remote/bridge", base.replacen("https://", "wss://", 1)), saved.token))
}
pub(crate) fn forget(id: &str) -> Result<(), String> {
    match entry(id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Could not remove remote credentials".into()),
    }
}

pub(crate) async fn terminal_stream(env: &Environment, session: &str, offset: u64) -> Result<Option<yougori_cli::terminal_stream::Channel>, String> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    // Read the secure store once per connection, never per terminal byte.
    let saved = entry(&env.id)?.get_password().map_err(|_| "Sign in to the shared environment again")?;
    let saved: Connection = serde_json::from_str(&saved).map_err(|_| "Invalid saved remote session")?;
    let (base, _) = share_url(&saved.link)?;
    let summary = call(&saved.link, Some(&saved.token), json!({"method":"inspect","params":{}})).await?;
    if summary["terminalStreamVersion"] != 1 { return Ok(None); }
    let endpoint = format!("{}/remote/terminal", base.replacen("https://", "wss://", 1));
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(12), tokio_tungstenite::connect_async_with_config(endpoint, Some(crate::workspace::terminal_stream::websocket_config()), true)).await.map_err(|_| "Remote terminal connection timed out")?.map_err(|_| "Remote terminal streaming connection failed")?;
    socket.send(Message::Text(json!({"token":saved.token,"sessionId":session,"offset":offset}).to_string().into())).await.map_err(|_| "Remote terminal sign-in failed")?;
    crate::workspace::terminal_stream::stream_ready(&mut socket).await?;
    Ok(Some(crate::workspace::terminal_stream::from_websocket(socket)))
}

fn connection_target<'a>(
    environments: &'a [Environment],
    environment_id: Option<&str>,
    runtime: &str,
) -> Result<Option<&'a Environment>, String> {
    if let Some(id) = environment_id {
        return environments.iter()
            .find(|env| env.id == id && env.runtime.starts_with("shared://tunnel/"))
            .map(Some)
            .ok_or_else(|| "The shared node no longer exists. Add a new shared environment instead.".into());
    }
    Ok(environments.iter().find(|env| env.runtime == runtime))
}

#[tauri::command]
pub async fn connect_remote_share(
    link: String,
    username: String,
    password: String,
    environment_id: Option<String>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let (base, id) = share_url(&link)?;
    let remote_runtime = format!("shared://tunnel/{}/{}", hash(&base), id);
    connection_target(&store.snapshot()?.environments, environment_id.as_deref(), &remote_runtime)?;
    let link = format!("{base}/share/{id}");
    let login = call(
        &link,
        None,
        json!({"shareId":id,"username":username,"password":password}),
    )
    .await?;
    let token = login["token"]
        .as_str()
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("Invalid remote session")?
        .to_owned();
    let summary = call(&link, Some(&token), json!({"method":"inspect","params":{}})).await?;
    let mut env = if summary.get("environment").is_some() {
        serde_json::from_value::<Environment>(summary["environment"].clone())
            .map_err(|_| "Invalid shared environment")?
    } else {
        serde_json::from_value(json!({"id":"","name":"My PC","kind":"cloud","status":"running","runtime":"","description":"Shared PC folder","createdAt":chrono::Utc::now().to_rfc3339(),"cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":1,"preferred":1,"max":1,"current":0},"priority":"normal","dynamic":false}})).map_err(|_| "Cannot create remote PC entry")?
    };
    if env.name.len() > 160 || env.name.chars().any(char::is_control) {
        return Err("Invalid remote environment name".into());
    }
    let snapshot = store.snapshot()?;
    let existing = connection_target(&snapshot.environments, environment_id.as_deref(), &remote_runtime)?;
    env.id = existing
        .as_ref()
        .map(|e| e.id.clone())
        .unwrap_or_else(|| format!("env-{}", uuid::Uuid::new_v4()));
    if let Some(existing) = existing {
        env.created_at = existing.created_at.clone();
    }
    env.name = format!("{} (remote)", env.name);
    env.kind = EnvironmentKind::Cloud;
    env.provider = Some(RuntimeProviderKind::CloudSsh);
    env.runtime = remote_runtime;
    env.runtime_id = summary["fabricId"].as_str().filter(|id| super::bridge::valid_id(id)).map(str::to_owned);
    env.runtime_path = None;
    env.control_endpoint = None;
    env.console_endpoint = None;
    env.container_command = None;
    env.sandbox_policy = None;
    env.last_error = None;
    env.storage_drive = None;
    env.network_access = false;
    env.gpu_access = false;
    env.description = format!(
        "Remote share · {} · workloads stay with the owner",
        summary["permission"].as_str().unwrap_or("view")
    );
    let credentials = entry(&env.id)?;
    let previous = credentials.get_password().ok();
    credentials
        .set_password(
            &serde_json::to_string(&Connection {
                link,
                token,
                username: Some(username),
                password: Some(password),
            })
                .map_err(|_| "Cannot encode session")?,
        )
        .map_err(|_| "Cannot securely save the remote session")?;
    let result = store.mutate(|s| {
        connection_target(&s.environments, environment_id.as_deref(), &env.runtime)?;
        if let Some(current) = s.environments.iter_mut().find(|e| e.id == env.id) {
            *current = env;
        } else {
            s.environments.push(env)
        }
        Ok(())
    });
    if result.is_err() {
        if let Some(previous) = &previous {
            let _ = credentials.set_password(&previous);
        } else {
            let _ = credentials.delete_credential();
        }
    }
    if result.is_ok() {
        if let Some(previous) = previous {
            if let Ok(old) = serde_json::from_str::<Connection>(&previous) {
                let _ = tokio::time::timeout(
                    Duration::from_secs(3),
                    call(
                        &old.link,
                        Some(&old.token),
                        json!({"method":"logout","params":{}}),
                    ),
                )
                .await;
            }
        }
    }
    if let (Ok(state), Some(environment_id)) = (&result, environment_id.as_deref()) {
        let linked: Vec<_> = state.connections.iter().filter(|connection| connection.source_id == environment_id || connection.target_id == environment_id).map(|connection| connection.id.clone()).collect();
        for connection_id in linked {
            let _ = runtime.remove_environment_connection(&connection_id, "", "", false).await;
        }
        let _ = crate::commands::reconcile_connections(&store, &runtime).await;
        return store.snapshot();
    }
    result
}
#[tauri::command]
pub async fn reconnect_remote_share(
    environment_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    connection_target(&store.snapshot()?.environments, Some(&environment_id), "")?;
    let saved = entry(&environment_id)?
        .get_password()
        .map_err(|_| "No saved share credentials. Enter the owner's link and recipient credentials once to reconnect.".to_owned())?;
    let saved: Connection = serde_json::from_str(&saved)
        .map_err(|_| "Invalid saved remote session. Enter the share details again.".to_owned())?;
    let username = saved.username.filter(|value| !value.is_empty()).ok_or(
        "No saved recipient username. Enter the owner's link and recipient credentials once to reconnect.",
    )?;
    let password = saved.password.filter(|value| !value.is_empty()).ok_or(
        "No saved recipient password. Enter the owner's link and recipient credentials once to reconnect.",
    )?;
    connect_remote_share(saved.link, username, password, Some(environment_id), store, runtime).await
}
#[tauri::command]
pub async fn remote_share_request(
    environment_id: String,
    method: String,
    params: Value,
    store: State<'_, PlatformStore>,
) -> Result<Value, String> {
    let env = store
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == environment_id && e.runtime.starts_with("shared://tunnel/"))
        .ok_or("Remote environment not found")?;
    if !matches!(method.as_str(), "inspect" | "files" | "desktop" | "logout") {
        return Err("Use the environment's terminal, logs or power controls".into());
    }
    request_saved(&env, &method, params).await
}

/// Download a folder into a fresh local directory, in bounded chunks. The
/// remote host never selects a host path or overwrites an existing local file.
#[tauri::command]
pub async fn download_remote_folder(
    environment_id: String,
    path: String,
    destination: String,
    store: State<'_, PlatformStore>,
) -> Result<Value, String> {
    let env = store
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == environment_id && e.runtime.starts_with("shared://tunnel/"))
        .ok_or("Remote environment not found")?;
    let folder = format!("Yougori-download-{}", uuid::Uuid::new_v4().simple());
    crate::file_export::copy_out(crate::file_export::Source::Shared(&env), &path, &destination, &folder).await
}

#[cfg(test)]
mod download_tests {
    use super::*;
    #[test]
    fn saved_remote_login_remains_compatible_with_existing_sessions() {
        let old: Connection = serde_json::from_value(json!({
            "link": "https://example.com/share/share-00000000000000000000000000000000",
            "token": "session"
        })).unwrap();
        assert!(old.username.is_none());
        assert!(old.password.is_none());
        let new = Connection {
            link: old.link,
            token: old.token,
            username: Some("recipient".into()),
            password: Some(" private password ".into()),
        };
        let saved = serde_json::to_string(&new).unwrap();
        let restored: Connection = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.username.as_deref(), Some("recipient"));
        assert_eq!(restored.password.as_deref(), Some(" private password "));
    }
    #[test]
    fn reconnect_keeps_the_selected_node_when_endpoint_or_target_changes() {
        let mut env: Environment = serde_json::from_value(json!({
            "id":"env-original", "name":"Shared project", "kind":"cloud", "status":"error",
            "runtime":"", "description":"", "createdAt":"2026-09-21T00:00:00Z",
            "cpuUsage":0, "memoryUsageGb":0, "storageDeltaGb":0, "networkRxMbps":0,
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},
                "memoryGb":{"min":1,"preferred":1,"max":1,"current":0},"priority":"normal","dynamic":false}
        })).unwrap();
        env.id = "env-original".into();
        env.runtime = "shared://tunnel/old-domain/share-original".into();
        let mut other = env.clone();
        other.id = "env-other".into();
        other.runtime = "shared://tunnel/new-domain/share-different".into();
        let environments = vec![env, other];
        let runtime = &environments[1].runtime;
        let selected = connection_target(&environments, Some("env-original"), runtime).unwrap().unwrap();
        assert_eq!(selected.id, "env-original");
        assert_eq!(connection_target(&environments, None, runtime).unwrap().unwrap().id, "env-other");
        assert!(connection_target(&environments, None, "shared://tunnel/new/share-new").unwrap().is_none());
        assert!(connection_target(&environments, Some("env-deleted"), runtime).is_err());
        let mut local = environments[0].clone();
        local.runtime = "containerd".into();
        assert!(connection_target(&[local], Some("env-original"), runtime).is_err());
    }
    #[test]
    fn unavailable_tunnels_explain_reconnection_without_exposing_response_bodies() {
        let offline = decode_response(reqwest::StatusCode::from_u16(530).unwrap(), b"error code: 1033").unwrap_err();
        assert!(offline.contains("Quick links change"));
        assert!(offline.contains("current full share link"));
        let upstream = decode_response(reqwest::StatusCode::BAD_GATEWAY, b"<html>private proxy detail</html>").unwrap_err();
        assert!(upstream.contains("temporarily unreachable"));
        assert!(!upstream.contains("private proxy detail"));
        assert_eq!(decode_response(reqwest::StatusCode::FORBIDDEN, br#"{"error":"Session expired or revoked; connect again"}"#).unwrap_err(), "Session expired or revoked; connect again");
        assert_eq!(decode_response(reqwest::StatusCode::OK, br#"{"status":"running"}"#).unwrap()["status"], "running");
    }
    #[test]
    fn remote_names_never_choose_a_local_path_or_device() {
        for name in [
            "../escape",
            "C:secret",
            "/absolute",
            "a/b",
            "a\\b",
            "NUL",
            "con.txt",
            "COM1",
            ".. ",
            "a:stream",
            "trailing.",
        ] {
            assert!(!crate::file_export::valid_name(name), "{name}")
        }
        for name in ["project", "hello.txt", "résumé.txt"] {
            assert!(crate::file_export::valid_name(name))
        }
    }
}
