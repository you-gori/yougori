use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::Manager;
use crate::AppHandle;
use tokio::sync::Mutex;

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub created: bool,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub hostname: String,
}
#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    #[default]
    Local,
    Quick,
    Domain,
}
#[derive(Default)]
pub struct SetupState {
    pub operations: Mutex<()>,
    tunnel: Mutex<Option<crate::workspace::cloudflare::Started>>,
}
impl Configuration {
    fn for_connection(&self, mode: Mode, hostname: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            created: true,
            mode,
            // Keep the last saved domain even while public access is off or a
            // quick link is in use. Its token remains in Credential Manager.
            hostname: if mode == Mode::Domain {
                crate::workspace::cloudflare::hostname(hostname.unwrap_or(&self.hostname))?
            } else {
                self.hostname.clone()
            },
        })
    }

    fn reuse_active_tunnel(
        &self,
        mode: Mode,
        hostname: Option<&str>,
        token: Option<&str>,
        replace_quick_link: bool,
        active: bool,
    ) -> Result<bool, String> {
        if replace_quick_link && (mode != Mode::Quick || self.mode != Mode::Quick) {
            return Err("Only a quick link can be replaced. Connect a quick tunnel first.".into());
        }
        if !active || mode == Mode::Local || replace_quick_link {
            return Ok(false);
        }
        if mode != self.mode {
            return Err("Disconnect the current tunnel before changing its type.".into());
        }
        if mode == Mode::Domain {
            let requested =
                crate::workspace::cloudflare::hostname(hostname.unwrap_or(&self.hostname))?;
            if requested != self.hostname || token.is_some_and(|t| !t.is_empty()) {
                return Err(
                    "Disconnect the current tunnel before changing its domain or token.".into(),
                );
            }
        }
        Ok(true)
    }
}
fn path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("personal-vault-setup.json"))
}
pub fn configuration(app: &AppHandle) -> Result<Configuration, String> {
    let path = path(app)?;
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
            "Personal Vault settings could not be read; restore personal-vault-setup.json".into()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Configuration::default()),
        Err(_) => Err("Personal Vault settings are unavailable".into()),
    }
}
fn save(app: &AppHandle, config: &Configuration) -> Result<(), String> {
    use std::io::Write;
    let path = path(app)?;
    let parent = path.parent().ok_or("Invalid vault settings path")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(config).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
pub async fn status(app: &AppHandle) -> Result<Value, String> {
    let mut value = serde_json::to_value(configuration(app)?).map_err(|e| e.to_string())?;
    let state = app.state::<SetupState>();
    let mut tunnel = state.tunnel.lock().await;
    if let Some(active) = tunnel.as_mut() {
        if active
            .child
            .try_wait()
            .map_err(|_| "Cannot read tunnel status")?
            .is_some()
        {
            active.logs.abort();
            *tunnel = None;
        }
    }
    value["publicUrl"] = tunnel
        .as_ref()
        .map(|t| json!(format!("{}/mcp", t.url)))
        .unwrap_or(Value::Null);
    value["localUrl"] = json!(format!(
        "http://127.0.0.1:{}/mcp",
        crate::vault_gateway::HTTP_PORT
    ));
    Ok(value)
}
/// The broker reports `desktop: false` when it does not recognize this process
/// as Yougori Desktop (older brokers omit the field).
#[cfg(windows)]
pub(crate) fn unregistered(status: &Value) -> bool {
    status["desktop"] == false
}
#[cfg(windows)]
async fn ensure_broker(app: &AppHandle, allow_install: bool) -> Result<(), String> {
    use yougori_vault::{client, platform, protocol::Request};
    let bundled = crate::vault::bundled_broker(app)?;
    let update_required = platform::update_required(&bundled)?;
    if !allow_install && (update_required || !platform::installed_binary()?.exists()) {
        return Err("Vault component update required. Open Personal Vault MCP in Yougori and select Update vault.".into());
    }
    if !update_required {
        for _ in 0..5 {
            if let Ok(status) = client::call(&Request::Status {}).await {
                if !unregistered(&status) { return Ok(()); }
                // An unsigned development broker accepts Desktop requests only
                // from Desktop paths registered by an elevated install.
                if !allow_install {
                    return Err("Register this Yougori with Personal Vault: open Personal Vault MCP and select Update vault.".into());
                }
                tokio::task::spawn_blocking(platform::register_desktop)
                    .await
                    .map_err(|_| "Could not register Yougori with Personal Vault")??;
                for _ in 0..20 {
                    if client::call(&Request::Status {}).await.is_ok_and(|status| !unregistered(&status)) { return Ok(()); }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                return Err("Personal Vault did not recognize this Yougori after registration. Restart Yougori and retry.".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }
    let launch = bundled.clone();
    tokio::task::spawn_blocking(move || platform::launch(&launch, allow_install))
        .await
        .map_err(|_| "Could not start vault protection")??;
    for _ in 0..120 {
        if client::call(&Request::Status {}).await.is_ok()
            && !platform::update_required(&bundled)?
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err("Windows did not start the vault. Approve the one-time administrator prompt if shown; otherwise check the Yougori Protected Vault task in Windows Task Scheduler, then retry.".into())
}
#[cfg(windows)]
async fn start_container(app: &AppHandle) -> Result<(), String> {
    let result =
        yougori_vault::client::call(&yougori_vault::protocol::Request::HttpEndpoint {}).await?;
    let port = result["brokerPort"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| *p > 0)
        .ok_or("Invalid vault endpoint")?;
    let pin = result["fingerprint"]
        .as_str()
        .ok_or("Missing broker certificate pin")?
        .to_owned();
    crate::vault_gateway::start_http(app, port, pin).await?;
    // Readiness means an HTTP request traversed the running container and
    // reached the protected broker, not just that a local socket was bound.
    for _ in 0..20 {
        if crate::vault_gateway::http_ready().await {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    crate::vault_gateway::stop(app).await?;
    Err("The Personal Vault container did not respond. Retry to start it again.".into())
}
async fn stop_tunnel(app: &AppHandle) {
    #[cfg(windows)]
    let _ =
        yougori_vault::client::call(&yougori_vault::protocol::Request::HttpOrigin { origin: None })
            .await;
    if let Some(mut old) = app.state::<SetupState>().tunnel.lock().await.take() {
        let _ = old.child.kill().await;
        old.logs.abort();
    }
}
pub async fn shutdown(app: &AppHandle) {
    stop_tunnel(app).await;
    let _ = crate::vault_gateway::stop(app).await;
}
async fn start_tunnel(
    app: &AppHandle,
    config: &Configuration,
    account: Option<crate::workspace::cloudflare::Account>,
) -> Result<(), String> {
    if config.mode == Mode::Local {
        #[cfg(windows)]
        yougori_vault::client::call(&yougori_vault::protocol::Request::HttpOrigin { origin: None })
            .await?;
        return Ok(());
    }
    let state = app.state::<SetupState>();
    let mut active = state.tunnel.lock().await;
    if let Some(tunnel) = active.as_mut() {
        if tunnel
            .child
            .try_wait()
            .map_err(|_| "Cannot read tunnel status")?
            .is_none()
        {
            #[cfg(windows)]
            yougori_vault::client::call(&yougori_vault::protocol::Request::HttpOrigin {
                origin: Some(tunnel.url.trim_end_matches('/').to_owned()),
            })
            .await?;
            return Ok(());
        }
        tunnel.logs.abort();
        *active = None;
    }
    let root = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let executable = crate::workspace::cloudflared(&root).await?;
    let account = if config.mode == Mode::Domain {
        Some(match account {
            Some(account) => account,
            None => crate::workspace::cloudflare::Account::resolve(
                crate::vault_gateway::ID,
                crate::vault_gateway::HTTP_PORT,
                Some(crate::vault_gateway::HTTP_PORT),
                crate::workspace::cloudflare::AccountOptions {
                    hostname: config.hostname.clone(),
                    token: None,
                    preset_id: None,
                    preset_source_environment_id: None,
                    preset_port: None,
                    remember: true,
                    routes_reviewed: true,
                },
            )?,
        })
    } else {
        None
    };
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut started = crate::workspace::cloudflare::start(
        &executable,
        &root,
        crate::vault_gateway::HTTP_PORT,
        account.as_ref(),
    )
    .await?;
    #[cfg(windows)]
    if let Err(error) = yougori_vault::client::call(&yougori_vault::protocol::Request::HttpOrigin {
        origin: Some(started.url.trim_end_matches('/').to_owned()),
    })
    .await
    {
        let _ = started.child.kill().await;
        started.logs.abort();
        return Err(error);
    }
    if let Some(account) = account {
        if let Err(error) =
            account.remember(crate::vault_gateway::ID, crate::vault_gateway::HTTP_PORT)
        {
            let mut started = started;
            let _ = started.child.kill().await;
            started.logs.abort();
            #[cfg(windows)]
            let _ = yougori_vault::client::call(&yougori_vault::protocol::Request::HttpOrigin {
                origin: None,
            })
            .await;
            return Err(error);
        }
    }
    *active = Some(started);
    Ok(())
}
#[tauri::command]
pub async fn vault_bootstrap(app: AppHandle, window: crate::WebviewWindow, interactive: Option<bool>) -> Result<Value, String> {
    if window.label() != "main" { return Err("Open the main Yougori window to start Personal Vault".into()); }
    if interactive.unwrap_or(false) && !window.is_focused().map_err(|e| e.to_string())? { return Err("Focus Yougori to update Personal Vault".into()); }
    let state = app.state::<SetupState>();
    let _operation = state.operations.lock().await;
    let config = configuration(&app)?;
    if !config.created {
        return Ok(json!({"created":false}));
    }
    #[cfg(windows)]
    {
        if !interactive.unwrap_or(false) {
            let bundled = crate::vault::bundled_broker(&app)?;
            if yougori_vault::platform::update_required(&bundled)? || !yougori_vault::platform::installed_binary()?.exists()
                || yougori_vault::client::call(&yougori_vault::protocol::Request::Status {}).await.is_ok_and(|status| unregistered(&status))
            {
                return Ok(json!({"created":true,"ready":false,"updateRequired":true}));
            }
        }
        ensure_broker(&app, interactive.unwrap_or(false)).await?;
        start_container(&app).await?;
        // A failed Internet connection must not disable local vault access.
        let tunnel_error = start_tunnel(&app, &config, None).await.err();
        return Ok(json!({"created":true,"ready":true,"tunnelError":tunnel_error}));
    }
    #[cfg(not(windows))]
    Err("Personal Vault requires Windows in this release".into())
}
#[tauri::command]
pub async fn vault_create(app: AppHandle, window: crate::WebviewWindow) -> Result<Value, String> {
    if window.label() != "main" || !window.is_focused().map_err(|e| e.to_string())? { return Err("Focus Yougori to create Personal Vault".into()); }
    let state = app.state::<SetupState>();
    let _operation = state.operations.lock().await;
    #[cfg(windows)]
    {
        ensure_broker(&app, true).await?;
        yougori_vault::client::call(&yougori_vault::protocol::Request::HttpSetup {}).await?;
        start_container(&app).await?;
        let mut config = configuration(&app)?;
        config.created = true;
        save(&app, &config)?;
        return status(&app).await;
    }
    #[cfg(not(windows))]
    Err("Personal Vault requires Windows in this release".into())
}
#[tauri::command]
pub async fn vault_connection(
    app: AppHandle,
    window: crate::WebviewWindow,
    mode: Mode,
    hostname: Option<String>,
    token: Option<String>,
    routes_reviewed: bool,
    replace_quick_link: Option<bool>,
) -> Result<Value, String> {
    if window.label() != "main" || !window.is_focused().map_err(|e| e.to_string())? { return Err("Focus Yougori to change Personal Vault access".into()); }
    let state = app.state::<SetupState>();
    let _operation = state.operations.lock().await;
    let previous = configuration(&app)?;
    if !previous.created {
        return Err("Create your Personal Vault first".into());
    }
    let replace_quick_link = replace_quick_link.unwrap_or(false);
    // Repeated Connect requests must never rotate a live address. The explicit
    // quick-link action is the only exception; domain changes require disconnect.
    let current = status(&app).await?;
    if previous.reuse_active_tunnel(
        mode,
        hostname.as_deref(),
        token.as_deref(),
        replace_quick_link,
        current["publicUrl"].is_string(),
    )? {
        return Ok(current);
    }
    let config = previous.for_connection(mode, hostname.as_deref())?;
    let account = if mode == Mode::Domain {
        Some(crate::workspace::cloudflare::Account::resolve(
            crate::vault_gateway::ID,
            crate::vault_gateway::HTTP_PORT,
            Some(crate::vault_gateway::HTTP_PORT),
            crate::workspace::cloudflare::AccountOptions {
                hostname: config.hostname.clone(),
                token,
                preset_id: None,
                preset_source_environment_id: None,
                preset_port: None,
                remember: true,
                routes_reviewed,
            },
        )?)
    } else {
        None
    };
    stop_tunnel(&app).await;
    // Persist an explicit switch to localhost even if the network is offline.
    // Failed public setups remain local, never silently restore old exposure.
    save(
        &app,
        &Configuration {
            created: true,
            hostname: previous.hostname,
            ..Default::default()
        },
    )?;
    start_tunnel(&app, &config, account).await?;
    if let Err(error) = save(&app, &config) {
        stop_tunnel(&app).await;
        return Err(error);
    }
    status(&app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_domain_survives_disconnect_quick_links_and_settings_reload() {
        let domain = Configuration::default()
            .for_connection(Mode::Domain, Some("Vault.Example.com"))
            .unwrap();
        let local = domain.for_connection(Mode::Local, None).unwrap();
        let quick = local.for_connection(Mode::Quick, Some("")).unwrap();
        let reloaded: Configuration =
            serde_json::from_slice(&serde_json::to_vec(&quick).unwrap()).unwrap();
        let restored = reloaded.for_connection(Mode::Domain, None).unwrap();
        assert_eq!(restored.hostname, "vault.example.com");
        assert!(restored.created);
        assert!(restored.mode == Mode::Domain);
        assert!(restored
            .for_connection(Mode::Domain, Some("not a domain"))
            .is_err());
        let legacy: Configuration =
            serde_json::from_str(r#"{"created":true,"mode":"local"}"#).unwrap();
        assert!(legacy.hostname.is_empty());
    }

    #[test]
    fn repeated_connect_keeps_live_address_and_only_explicit_quick_rotation_replaces_it() {
        let quick = Configuration::default()
            .for_connection(Mode::Quick, None)
            .unwrap();
        assert!(quick
            .reuse_active_tunnel(Mode::Quick, None, None, false, true)
            .unwrap());
        assert!(!quick
            .reuse_active_tunnel(Mode::Quick, None, None, true, true)
            .unwrap());
        assert!(!quick
            .reuse_active_tunnel(Mode::Quick, None, None, false, false)
            .unwrap());
        assert!(!quick
            .reuse_active_tunnel(Mode::Local, None, None, false, true)
            .unwrap());
        assert!(quick
            .reuse_active_tunnel(Mode::Domain, Some("vault.example.com"), None, false, true)
            .is_err());
        let domain = quick
            .for_connection(Mode::Domain, Some("vault.example.com"))
            .unwrap();
        assert!(domain
            .reuse_active_tunnel(Mode::Domain, Some("Vault.Example.com"), None, false, true)
            .unwrap());
        assert!(domain
            .reuse_active_tunnel(Mode::Domain, Some("other.example.com"), None, false, true)
            .is_err());
        assert!(domain
            .reuse_active_tunnel(Mode::Domain, None, Some("replacement"), false, true)
            .is_err());
        assert!(domain
            .reuse_active_tunnel(Mode::Quick, None, None, true, true)
            .is_err());
    }
}
