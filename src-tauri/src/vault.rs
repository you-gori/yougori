//! Focused desktop facade for local vault management. The protected broker
//! still stores the items and enforces each agent permission.
use serde_json::{json, Value};
use crate::{AppHandle, WebviewWindow};
use std::{io::Write, path::Path};

fn focused_dashboard(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main" || !window.is_focused().map_err(|e| e.to_string())? {
        return Err("Open the main Yougori window to manage Personal Vault".into());
    }
    Ok(())
}

fn plugin_files(server_url: &str) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let parsed = url::Url::parse(server_url).map_err(|_| "Connect a public vault tunnel before downloading the plugin")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() || parsed.path() != "/mcp"
        || !parsed.username().is_empty() || parsed.password().is_some()
        || parsed.query().is_some() || parsed.fragment().is_some()
    {
        return Err("Connect a valid HTTPS vault tunnel before downloading the plugin".into());
    }
    let server_url = parsed.as_str();
    let description = "Request approved access to Yougori Personal Vault over MCP.";
    let manifest = json!({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "yougori-personal-vault",
        "version": "1.0.0",
        "description": description,
        "author": { "name": "Yougori" },
        "extensions": { "com.openai": { "interface": {
            "displayName": "Yougori Personal Vault",
            "shortDescription": "Approved vault access",
            "longDescription": "Connect to your Yougori Personal Vault. Every protected action requires your approval in Yougori Desktop.",
            "developerName": "Yougori",
            "category": "Productivity",
            "capabilities": ["Read", "Write"]
        } } }
    });
    let mcp = json!({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": { "yougori-personal-vault": {
            "type": "streamable-http", "url": server_url
        } }
    });
    let compatibility = json!({
        "name": "yougori-personal-vault",
        "version": "1.0.0",
        "description": description,
        "author": { "name": "Yougori" },
        "mcpServers": "./.mcp.json",
        "interface": {
            "displayName": "Yougori Personal Vault",
            "shortDescription": "Approved vault access",
            "longDescription": "Connect to your Yougori Personal Vault. Every protected action requires your approval in Yougori Desktop.",
            "developerName": "Yougori",
            "category": "Productivity",
            "capabilities": ["Read", "Write"]
        }
    });
    let compatibility_mcp = json!({ "mcpServers": {
        "yougori-personal-vault": { "type": "http", "url": server_url }
    } });
    let instructions = "Yougori Personal Vault plugin\n\nUpload this ZIP or select the extracted yougori-personal-vault folder in a plugin importer that accepts MCP plugins. The plugin points to the HTTPS vault address active when you downloaded it. Keep Yougori Desktop and its tunnel running, then complete OAuth sign-in and approve requests inside Yougori.\n\nIf the importer offers only skills-only ZIP uploads, choose its With MCP or server URL flow instead and enter the HTTPS /mcp address shown in Yougori. A quick tunnel link changes when restarted; download a new ZIP after the address changes. A saved domain is more stable.\n\nThis ZIP contains no vault items, passwords, OAuth tokens, or connection keys. It does not contain the vault server itself.\n";
    Ok(vec![
        ("yougori-personal-vault/plugin.json", serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?),
        ("yougori-personal-vault/mcp.json", serde_json::to_vec_pretty(&mcp).map_err(|e| e.to_string())?),
        ("yougori-personal-vault/.codex-plugin/plugin.json", serde_json::to_vec_pretty(&compatibility).map_err(|e| e.to_string())?),
        ("yougori-personal-vault/.mcp.json", serde_json::to_vec_pretty(&compatibility_mcp).map_err(|e| e.to_string())?),
        ("yougori-personal-vault/SETUP.txt", instructions.as_bytes().to_vec()),
    ])
}

fn write_plugin_archive(directory: &Path, server_url: &str) -> Result<std::path::PathBuf, String> {
    if !directory.is_dir() { return Err("Choose a folder for the plugin download".into()); }
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let target = directory.join(format!("yougori-personal-vault-{suffix}.zip"));
    let temporary = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipWriter::new(temporary);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, contents) in plugin_files(server_url)? {
        archive.start_file(name, options).map_err(|e| e.to_string())?;
        archive.write_all(&contents).map_err(|e| e.to_string())?;
    }
    let temporary = archive.finish().map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    temporary.persist_noclobber(&target).map_err(|e| format!("Plugin download already exists or cannot be saved: {e}"))?;
    Ok(target)
}

#[tauri::command]
pub async fn vault_export_plugin(app: AppHandle, window: WebviewWindow, directory: String) -> Result<String, String> {
    if window.label() != "main" { return Err("Open Yougori to download the plugin".into()); }
    let setup = crate::vault_setup::status(&app).await?;
    let server_url = setup["publicUrl"].as_str().ok_or("Connect a public vault tunnel before downloading the plugin")?.to_owned();
    let directory = std::path::PathBuf::from(directory);
    tokio::task::spawn_blocking(move || write_plugin_archive(&directory, &server_url))
        .await.map_err(|e| e.to_string())?
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod plugin_tests {
    use super::*;

    #[test]
    fn exported_plugin_is_uploadable_zip_with_remote_mcp_and_no_vault_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = write_plugin_archive(directory.path(), "https://vault.example.com/mcp").unwrap();
        assert_eq!(path.extension().unwrap(), "zip");
        let mut contents = std::collections::BTreeMap::new();
        let mut archive = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            let mut data = String::new();
            std::io::Read::read_to_string(&mut entry, &mut data).unwrap();
            contents.insert(entry.name().to_owned(), data);
        }
        assert!(contents.keys().all(|name| name.starts_with("yougori-personal-vault/")));
        let manifest: Value = serde_json::from_str(&contents["yougori-personal-vault/plugin.json"]).unwrap();
        assert_eq!(manifest["name"], "yougori-personal-vault");
        let mcp: Value = serde_json::from_str(&contents["yougori-personal-vault/mcp.json"]).unwrap();
        assert_eq!(mcp["mcpServers"]["yougori-personal-vault"]["url"], "https://vault.example.com/mcp");
        assert_eq!(mcp["mcpServers"]["yougori-personal-vault"]["type"], "streamable-http");
        assert!(contents.contains_key("yougori-personal-vault/.codex-plugin/plugin.json"));
        assert!(!contents.values().any(|value| value.contains("connectionKey") || value.contains("Bearer ")));
        assert!(plugin_files("http://vault.example.com/mcp").is_err());
        assert!(plugin_files("https://vault.example.com/mcp?token=secret").is_err());
        assert_ne!(write_plugin_archive(directory.path(), "https://vault.example.com/mcp").unwrap(), path);
    }
}

#[tauri::command]
pub async fn vault_add_items(window: WebviewWindow, items: Vec<yougori_vault::protocol::ItemInput>) -> Result<Value, String> {
    focused_dashboard(&window)?;
    #[cfg(windows)]
    { yougori_vault::client::call(&yougori_vault::protocol::Request::AddItems { items }).await }
    #[cfg(not(windows))]
    { let _ = items; Err("Personal Vault requires Windows in this release".into()) }
}

#[cfg(windows)]
pub(crate) fn bundled_broker(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let bundled = crate::resource_dir(app)?.join("vault").join("yougori-vault.exe");
    #[cfg(debug_assertions)]
    let bundled = if bundled.exists() {
        bundled
    } else {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources/vault/yougori-vault.exe")
    };
    Ok(bundled)
}

#[tauri::command]
pub async fn vault_status(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
    if window.label() != "main" { return Err("Personal Vault is available in the main Yougori window".into()); }
    #[cfg(not(windows))]
    let _ = app;
    #[cfg(windows)]
    {
        let update_required = yougori_vault::platform::update_required(&bundled_broker(&app)?)?
            || !yougori_vault::platform::installed_binary()?.exists();
        match yougori_vault::client::call(&yougori_vault::protocol::Request::Status {}).await {
            Ok(mut value) => {
                let unregistered = crate::vault_setup::unregistered(&value);
                value["updateRequired"] = json!(update_required || unregistered);
                if unregistered {
                    value["notice"] = json!("Personal Vault does not recognize this copy of Yougori yet. Select Update vault to register it.");
                }
                value["gateway"] = crate::vault_gateway::status(&app).await;
                value["setup"] = crate::vault_setup::status(&app).await?;
                Ok(value)
            }
            Err(error) => Ok(
                json!({"running":false,"locked":true,"supported":true,"updateRequired":update_required,"notice":error,"setup":crate::vault_setup::status(&app).await?,"items":[],"clients":[],"pending":[],"activity":[]}),
            ),
        }
    }
    #[cfg(not(windows))]
    Ok(
        json!({"running":false,"locked":true,"supported":false,"notice":"Personal Vault requires the protected Windows broker in this release.","items":[],"clients":[],"pending":[],"activity":[]}),
    )
}
#[tauri::command]
pub async fn vault_control(
    app: AppHandle,
    window: WebviewWindow,
    action: String,
    id: Option<String>,
) -> Result<Value, String> {
    focused_dashboard(&window)?;
    #[cfg(windows)]
    {
        use yougori_vault::{client, protocol::Request};
        let request = match action.as_str() {
            "start" => {
                let bundled = bundled_broker(&app)?;
                // Elevation waits for the administrator prompt and installer.
                tokio::task::spawn_blocking(move || yougori_vault::platform::launch(&bundled, true))
                    .await
                    .map_err(|_| "Could not start vault protection")??;
                return Ok(json!({"starting":true}));
            }
            "manage" => Request::Manage {},
            "approve" => {
                focused_dashboard(&window)?;
                Request::Approve { request: id.ok_or("Choose a pending request")? }
            }
            "browse" => Request::Browse {},
            "credentials" => Request::HttpCredentials {},
            "remote" => {
                let result = client::call(&Request::Remote {}).await?;
                let port = result["brokerPort"]
                    .as_u64()
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0)
                    .ok_or("Protected broker did not return a valid endpoint")?;
                let mut result = result;
                result["gateway"] = crate::vault_gateway::start(&app, port).await?;
                return Ok(result);
            }
            "remote_off" => {
                crate::vault_gateway::stop(&app).await?;
                return client::call(&Request::RemoteOff {}).await;
            }
            "lock" => Request::Lock {},
            "revoke" => Request::Revoke {
                client: id.ok_or("Choose a client")?,
            },
            "remove" => Request::Remove {
                item: id.ok_or("Choose an item")?,
            },
            "deny" => Request::Deny {
                request: id.ok_or("Choose a pending request")?,
            },
            _ => return Err("Unsupported vault management action".into()),
        };
        client::call(&request).await
    }
    #[cfg(not(windows))]
    {
        let _ = (app, action, id);
        Err("Personal Vault requires Windows in this release".into())
    }
}
