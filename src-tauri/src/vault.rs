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

/// A finished destroy's answer, with what this app could not clean up after it added to what
/// the broker named. The vault is gone either way, so none of it is an error, and the list is
/// never dropped: an answer that is not an object, which the protocol never sends, becomes
/// `{"destroyed":true}` (the broker answers a destroy without an error only once the vault is
/// gone, and this app has cleaned up on that basis).
#[cfg_attr(not(windows), allow(dead_code))]
fn with_left_behind(answer: Value, left: Vec<String>) -> Value {
    if left.is_empty() {
        return answer;
    }
    let mut answer = match answer {
        Value::Object(answer) => answer,
        _ => serde_json::Map::from_iter([("destroyed".to_owned(), Value::Bool(true))]),
    };
    let mut all = answer.get("leftBehind").and_then(Value::as_array).cloned().unwrap_or_default();
    all.extend(left.into_iter().map(Value::from));
    answer.insert("leftBehind".into(), Value::Array(all));
    Value::Object(answer)
}

/// What a destroy request's delivery means: done, nothing deleted, stopped part way, or unknown.
#[cfg(windows)]
#[derive(Debug, PartialEq)]
enum Delivered {
    /// Finished: the broker's answer.
    Done(Value),
    /// Nothing was deleted, said in full.
    Nothing(String),
    /// Deleting began and stopped, in the broker's words.
    Partial(String),
    /// Sent and not answered, or the broker's worker stopped mid-request: only the vault folder
    /// can say what happened.
    Unknown(String),
}

/// The answer an older broker gives to a request it does not know.
#[cfg(windows)]
const OLDER_BROKER: &str = "Invalid or unsupported vault request";

/// Reads a destroy's delivery. A request never sent deleted nothing; any refusal the broker
/// answered with came before a file was touched (an older broker's, which does not know the
/// request, included); only a request sent and left unanswered is unknown.
#[cfg(windows)]
fn delivered(asked: yougori_vault::client::Asked) -> Delivered {
    use yougori_vault::{client::Asked, protocol::{DESTROY_NOT_STARTED, DESTROY_UNFINISHED, SERVICE_STOPPED}};
    match asked {
        Asked::NotSent(error) => Delivered::Nothing(format!("{DESTROY_NOT_STARTED} {error}")),
        Asked::Answered(Ok(result)) => Delivered::Done(result),
        Asked::Answered(Err(error)) if error.starts_with(DESTROY_UNFINISHED) => Delivered::Partial(error),
        Asked::Answered(Err(error)) if error.starts_with(DESTROY_NOT_STARTED) => Delivered::Nothing(error),
        Asked::Answered(Err(error)) if error == SERVICE_STOPPED => Delivered::Unknown(error),
        Asked::Answered(Err(error)) if error == OLDER_BROKER => Delivered::Nothing(format!(
            "{DESTROY_NOT_STARTED} This Personal Vault is older than this Yougori and cannot delete itself. Choose Update vault, then choose Delete my vault again."
        )),
        Asked::Answered(Err(error)) => Delivered::Nothing(format!("{DESTROY_NOT_STARTED} {error}")),
        Asked::Unanswered(error) => Delivered::Unknown(error),
    }
}

/// What a destroy whose answer never came turned out to be, read from what the vault folder
/// holds (`on_disk`, from the broker's status; `None` when that could not be asked either).
#[derive(Debug, PartialEq)]
#[cfg_attr(not(windows), allow(dead_code))]
enum Settled {
    /// No secret can remain: it finished, and only its answer was lost.
    Finished,
    /// The vault is there and no destroy began.
    NothingDeleted(String),
    /// A destroy began and secrets may remain.
    Partial(String),
    /// Nothing could say.
    Unknown(String),
}

#[cfg_attr(not(windows), allow(dead_code))]
fn settled(error: &str, on_disk: Option<&str>) -> Settled {
    use yougori_vault::protocol::{DESTROY_NOT_STARTED, DESTROY_UNFINISHED};
    match on_disk {
        Some("none") => Settled::Finished,
        Some("vault") => Settled::NothingDeleted(format!("{DESTROY_NOT_STARTED} The vault is still there; its answer was lost ({error}). Run Delete my vault again when you're ready.")),
        Some("partial") => Settled::Partial(format!("{DESTROY_UNFINISHED} Its answer was lost ({error}), but the vault folder shows deleting began and did not finish. Run Delete my vault again to finish; it names every file left.")),
        _ => Settled::Unknown(format!("Yougori could not confirm whether Personal Vault was deleted: {error}.")),
    }
}

/// A destroy whose outcome nothing could confirm: what reaches the vault is stopped until
/// somebody looks, and they are told how. `left` names whatever could not be stopped.
#[cfg_attr(not(windows), allow(dead_code))]
fn unconfirmed(said: String, left: &[String]) -> String {
    let access = if left.is_empty() {
        "The vault's public link and gateway are stopped until you check.".to_owned()
    } else {
        left.join(" ")
    };
    format!("{said} {access} Open Personal Vault to see whether it is still there; if it is, run Delete my vault again.")
}

/// A destroy that stopped part way, and what became of the vault's public link and gateway:
/// `left` names whichever is still running.
#[cfg_attr(not(windows), allow(dead_code))]
fn unfinished(error: String, left: &[String]) -> String {
    if left.is_empty() {
        format!("{error} The vault's public link and gateway are stopped, so nothing can reach what is left.")
    } else {
        format!("{error} {}", left.join(" "))
    }
}

#[cfg(test)]
mod destroy_tests {
    use super::*;

    #[test]
    fn a_finished_destroy_names_what_is_left_and_never_reads_as_failed() {
        let broker = json!({"destroyed": true, "leftBehind": ["The activity record could not note this deletion (disk full); the deletion itself finished."]});
        let token = "The Cloudflare tunnel token for vault.example.com is still saved in Windows Credential Manager.".to_owned();
        let answer = with_left_behind(broker, vec![token.clone()]);
        assert_eq!(answer["destroyed"], true);
        assert_eq!(answer["leftBehind"].as_array().unwrap().len(), 2, "the broker's and the app's, both named");
        assert_eq!(answer["leftBehind"][1], json!(token));
        // Cleanup that only fails on the token still reports a finished destroy.
        let only_token = with_left_behind(json!({"destroyed": true}), vec![token.clone()]);
        assert_eq!(only_token, json!({"destroyed": true, "leftBehind": [token]}));
        assert_eq!(with_left_behind(json!({"destroyed": true}), Vec::new()), json!({"destroyed": true}));
        // An answer that is not an object never loses the list.
        assert_eq!(with_left_behind(json!(null), vec![token.clone()]), json!({"destroyed": true, "leftBehind": [token]}));
    }

    #[test]
    fn a_destroy_whose_answer_was_lost_is_settled_by_what_the_vault_folder_holds() {
        use yougori_vault::protocol::{DESTROY_NOT_STARTED, DESTROY_UNFINISHED};
        let lost = "Vault request timed out; inspect activity before retrying an action";
        assert_eq!(settled(lost, Some("none")), Settled::Finished);
        let Settled::NothingDeleted(said) = settled(lost, Some("vault")) else { panic!("the vault is there") };
        assert!(said.starts_with(DESTROY_NOT_STARTED) && said.contains(lost), "{said}");
        let Settled::Partial(said) = settled(lost, Some("partial")) else { panic!("a destroy began") };
        assert!(said.starts_with(DESTROY_UNFINISHED) && said.contains(lost), "{said}");
        // Nothing to ask, or an answer it cannot read: never claimed either way.
        for on_disk in [None, Some("unknown"), Some("something new")] {
            let Settled::Unknown(said) = settled(lost, on_disk) else { panic!("{on_disk:?}") };
            assert!(!said.starts_with(DESTROY_NOT_STARTED) && !said.starts_with(DESTROY_UNFINISHED) && said.contains("could not confirm"), "{said}");
            let told = unconfirmed(said, &[]);
            assert!(told.contains("stopped until you check") && told.contains("run Delete my vault again"), "{told}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn only_a_destroy_sent_and_left_unanswered_is_an_unknown_outcome() {
        use yougori_vault::{client::Asked, protocol::{DESTROY_NOT_STARTED, DESTROY_UNFINISHED, SERVICE_STOPPED}};
        // A vault that was not running was never asked: nothing deleted, nothing stopped for it.
        let offline = delivered(Asked::NotSent("Personal Vault is not running. Open it from Yougori Desktop.".into()));
        assert_eq!(offline, Delivered::Nothing(format!("{DESTROY_NOT_STARTED} Personal Vault is not running. Open it from Yougori Desktop.")));
        // An older broker answered that it does not know the request: nothing deleted.
        let Delivered::Nothing(older) = delivered(Asked::Answered(Err(OLDER_BROKER.into()))) else { panic!("an answer") };
        assert!(older.starts_with(DESTROY_NOT_STARTED) && older.contains("Update vault"), "{older}");
        // Any other answered refusal came before a file was touched.
        assert_eq!(delivered(Asked::Answered(Err("The approval queue is full".into()))), Delivered::Nothing(format!("{DESTROY_NOT_STARTED} The approval queue is full")));
        let said = format!("{DESTROY_NOT_STARTED} The deletion was declined or timed out.");
        assert_eq!(delivered(Asked::Answered(Err(said.clone()))), Delivered::Nothing(said));
        let partial = format!("{DESTROY_UNFINISHED} Its key is gone.");
        assert_eq!(delivered(Asked::Answered(Err(partial.clone()))), Delivered::Partial(partial));
        assert_eq!(delivered(Asked::Answered(Ok(json!({"destroyed": true})))), Delivered::Done(json!({"destroyed": true})));
        // Only these leave it unknown: no answer, or a worker that stopped mid-request.
        assert_eq!(delivered(Asked::Unanswered("Vault request timed out".into())), Delivered::Unknown("Vault request timed out".into()));
        assert_eq!(delivered(Asked::Answered(Err(SERVICE_STOPPED.into()))), Delivered::Unknown(SERVICE_STOPPED.into()));
    }

    #[test]
    fn a_destroy_that_stopped_part_way_says_the_public_link_is_stopped_or_names_it() {
        let error = format!("{} Its key is gone.", yougori_vault::protocol::DESTROY_UNFINISHED);
        assert!(unfinished(error.clone(), &[]).ends_with("nothing can reach what is left."));
        let link = "The vault's public link https://vault.example.com is still connected: cloudflared process 4242 could not be stopped.".to_owned();
        let named = unfinished(error.clone(), &[link.clone()]);
        assert!(named.starts_with(&error) && named.ends_with(&link), "{named}");
    }
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
        // Deliberately `exists()`: a broker that cannot be checked reads as needing an update,
        // which offers Update vault with the person's consent. Nothing is written on this answer.
        let update_required = yougori_vault::platform::update_required(&bundled_broker(&app)?)?
            || !yougori_vault::platform::installed_binary()?.exists();
        match yougori_vault::client::call(&yougori_vault::protocol::Request::Status {}).await {
            Ok(mut value) => {
                // The broker's answer, read from the vault folder, is the truth; the note follows it.
                if let Some(unfinished) = value["destroyIncomplete"].as_bool() {
                    let _ = crate::vault_setup::note_destroy_unfinished(&app, unfinished);
                }
                let unregistered = crate::vault_setup::unregistered(&value);
                value["updateRequired"] = json!(update_required || unregistered);
                if unregistered {
                    value["notice"] = json!("Personal Vault does not recognize this copy of Yougori yet. Select Update vault to register it.");
                }
                value["gateway"] = crate::vault_gateway::status(&app).await;
                value["setup"] = crate::vault_setup::status(&app).await?;
                Ok(value)
            }
            // The broker reads the vault folder; without it, the note this app keeps of a destroy
            // that stopped part way stands in, so the row still says so before anyone tries.
            Err(error) => Ok(
                json!({"running":false,"locked":true,"supported":true,"updateRequired":update_required,"notice":error,"destroyIncomplete":crate::vault_setup::destroy_unfinished_noted(&app),"setup":crate::vault_setup::status(&app).await?,"items":[],"clients":[],"pending":[],"activity":[]}),
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
            "lock" => Request::Lock {},
            "revoke" => Request::Revoke {
                client: id.ok_or("Choose a client")?,
            },
            "remove" => Request::Remove {
                item: id.ok_or("Choose an item")?,
            },
            // The broker deletes only after its own approval in this window. Then nothing on
            // this computer points at the vault: no setup, gateway or public link. Cleanup after
            // that cannot undo the deletion, so it never fails it: anything it could not remove
            // is named in `leftBehind`, and asking to delete again is never the answer.
            "destroy" => {
                let result = match delivered(client::ask(&Request::Destroy {}).await) {
                    Delivered::Done(result) => result,
                    // Never sent, or refused before a file was touched: nothing was deleted, and
                    // nothing that reaches the vault is stopped for it.
                    Delivered::Nothing(said) => return Err(said),
                    // Deleting began and stopped: nothing may reach what is left. The setup
                    // stays, so the vault row still offers Delete my vault.
                    Delivered::Partial(error) => {
                        let _ = crate::vault_setup::note_destroy_unfinished(&app, true);
                        return Err(unfinished(error, &crate::vault_setup::stop_access(&app).await));
                    }
                    // Sent and no answer came: the broker stopped, or did not answer in time.
                    // What the vault folder holds, as the broker reads it, settles it.
                    Delivered::Unknown(error) => {
                        let status = client::call(&Request::Status {}).await;
                        let on_disk = status.as_ref().ok().and_then(|status| status["onDisk"].as_str()).map(str::to_owned);
                        return match settled(&error, on_disk.as_deref()) {
                            Settled::Finished => Ok(with_left_behind(json!({"destroyed": true}), crate::vault_setup::forget(&app).await)),
                            Settled::NothingDeleted(said) => Err(said),
                            Settled::Partial(said) => {
                                let _ = crate::vault_setup::note_destroy_unfinished(&app, true);
                                Err(unfinished(said, &crate::vault_setup::stop_access(&app).await))
                            }
                            Settled::Unknown(said) => Err(unconfirmed(said, &crate::vault_setup::stop_access(&app).await)),
                        };
                    }
                };
                return Ok(with_left_behind(result, crate::vault_setup::forget(&app).await));
            }
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
