//! Append to WebView2's own menu without removing its standard commands.
use std::{cell::RefCell, collections::HashMap};
use webview2_com::{
    ContextMenuRequestedEventHandler, CustomItemSelectedEventHandler,
    ExecuteScriptCompletedHandler, Microsoft::Web::WebView2::Win32::*,
};
use windows::core::{w, Interface, HSTRING};

thread_local! {
    static HANDLERS: RefCell<HashMap<usize, i64>> = RefCell::new(HashMap::new());
}

/// Reads and clears both context flags in one pass. Clearing them here means neither can leak
/// into the next right-click, wherever that one lands.
const CONTEXT_SCRIPT: &str = "(() => { const d = document.documentElement.dataset; const node = d.yougoriNodeContext || ''; const vault = d.yougoriVaultContext || ''; delete d.yougoriNodeContext; delete d.yougoriVaultContext; return { node: node, vault: vault }; })()";

/// What was right-clicked. The vault row and an environment node are mutually exclusive: the
/// vault never offers the node commands, and a node never offers the vault's.
#[derive(Debug, PartialEq)]
enum Target {
    None,
    Node(String),
    Vault,
}

/// The vault flag is only a marker, so any short non-empty value means the vault row. A node
/// carries its id, bounded exactly as it always was.
fn target_from(json: &str) -> Target {
    let value = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let vault = value["vault"].as_str().unwrap_or_default();
    if !vault.is_empty() && vault.len() <= 20 {
        return Target::Vault;
    }
    let node = value["node"].as_str().unwrap_or_default();
    if node.is_empty() || node.len() > 200 {
        return Target::None;
    }
    Target::Node(node.to_owned())
}

pub fn install(webview: &tauri::Webview) {
    let window = webview.clone();
    let _ = webview.with_webview(move |native| unsafe {
        let result = (|| -> windows::core::Result<()> {
            let core = native.controller().CoreWebView2()?;
            let menu_core: ICoreWebView2_11 = core.cast()?;
            let identity = core.as_raw() as usize;
            if let Some(old) = HANDLERS.with(|handlers| handlers.borrow_mut().remove(&identity)) {
                let _ = menu_core.remove_ContextMenuRequested(old);
            }
            let environment: ICoreWebView2Environment9 = native.environment().cast()?;
            let handler = ContextMenuRequestedEventHandler::create(Box::new(move |sender, args| {
                let (Some(sender), Some(args)) = (sender, args) else { return Ok(()) };
                let deferral = args.GetDeferral()?;
                let completion = deferral.clone();
                let environment = environment.clone();
                let window = window.clone();
                let callback = ExecuteScriptCompletedHandler::create(Box::new(move |result, json| {
                    let append = (|| -> windows::core::Result<()> {
                        result?;
                        let id = match target_from(&json) {
                            Target::None => return Ok(()),
                            Target::Vault => {
                                let items = args.MenuItems()?;
                                let item = environment.CreateContextMenuItem(w!("Delete my vault"), None, COREWEBVIEW2_CONTEXT_MENU_ITEM_KIND_COMMAND)?;
                                let vault_window = window.clone();
                                let selected_vault = CustomItemSelectedEventHandler::create(Box::new(move |_, _| {
                                    // Only opens the existing UI confirmation; no deletion in native menu code.
                                    let _ = vault_window.eval("window.dispatchEvent(new CustomEvent('yougori-delete-vault'))");
                                    Ok(())
                                }));
                                let mut vault_token = 0;
                                item.add_CustomItemSelected(&selected_vault, &mut vault_token)?;
                                let mut vault_index = 0;
                                items.Count(&mut vault_index)?;
                                items.InsertValueAtIndex(vault_index, &item)?;
                                return Ok(());
                            }
                            Target::Node(id) => id,
                        };
                        let items = args.MenuItems()?;
                        let download = environment.CreateContextMenuItem(w!("Create a download link"), None, COREWEBVIEW2_CONTEXT_MENU_ITEM_KIND_COMMAND)?;
                        let download_window = window.clone();
                        let download_id = id.clone();
                        let selected_download = CustomItemSelectedEventHandler::create(Box::new(move |_, _| {
                            let detail = serde_json::to_string(&download_id).unwrap_or_default();
                            let _ = download_window.eval(&format!("window.dispatchEvent(new CustomEvent('yougori-download-node', {{detail:{detail}}}))"));
                            Ok(())
                        }));
                        let mut download_token = 0;
                        download.add_CustomItemSelected(&selected_download, &mut download_token)?;
                        let mut download_index = 0;
                        items.Count(&mut download_index)?;
                        items.InsertValueAtIndex(download_index, &download)?;
                        let item = environment.CreateContextMenuItem(w!("Delete node"), None, COREWEBVIEW2_CONTEXT_MENU_ITEM_KIND_COMMAND)?;
                        let delete_window = window.clone();
                        let selected = CustomItemSelectedEventHandler::create(Box::new(move |_, _| {
                            // Only opens the existing UI confirmation; no deletion in native menu code.
                            let detail = serde_json::to_string(&id).unwrap_or_default();
                            let _ = delete_window.eval(&format!("window.dispatchEvent(new CustomEvent('yougori-delete-node', {{detail:{detail}}}))"));
                            Ok(())
                        }));
                        let mut token = 0;
                        item.add_CustomItemSelected(&selected, &mut token)?;
                        let mut count = 0;
                        items.Count(&mut count)?;
                        items.InsertValueAtIndex(count, &item)?;
                        Ok(())
                    })();
                    // Always let the normal menu open, including unsupported targets/errors.
                    if let Err(error) = append { eprintln!("Node context menu: {error}"); }
                    completion.Complete()
                }));
                if let Err(error) = sender.ExecuteScript(&HSTRING::from(CONTEXT_SCRIPT), &callback) {
                    let _ = deferral.Complete();
                    return Err(error);
                }
                Ok(())
            }));
            let mut token = 0;
            menu_core.add_ContextMenuRequested(&handler, &mut token)?;
            HANDLERS.with(|handlers| { handlers.borrow_mut().insert(identity, token); });
            Ok(())
        })();
        if let Err(error) = result { eprintln!("Native node menu unavailable: {error}"); }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vault_and_a_node_never_share_a_menu() {
        assert_eq!(target_from(r#"{"node":"","vault":"1"}"#), Target::Vault, "the vault row offers its own item");
        assert_eq!(target_from(r#"{"node":"env-1","vault":"1"}"#), Target::Vault, "the vault wins, so the node commands never appear on it");
        assert_eq!(target_from(r#"{"node":"env-1","vault":""}"#), Target::Node("env-1".into()), "a node keeps its own commands");
        assert_eq!(target_from(r#"{"node":"","vault":""}"#), Target::None, "an ordinary surface keeps the standard menu");
    }

    #[test]
    fn oversized_or_unreadable_values_add_nothing() {
        assert_eq!(target_from(&format!(r#"{{"node":"{}","vault":""}}"#, "a".repeat(201))), Target::None);
        assert_eq!(target_from(&format!(r#"{{"node":"","vault":"{}"}}"#, "a".repeat(21))), Target::None);
        assert_eq!(target_from("not json"), Target::None);
        assert_eq!(target_from("null"), Target::None);
    }

    #[test]
    fn the_script_reads_and_clears_both_flags() {
        assert!(CONTEXT_SCRIPT.contains("yougoriNodeContext") && CONTEXT_SCRIPT.contains("yougoriVaultContext"));
        assert_eq!(CONTEXT_SCRIPT.matches("delete d.").count(), 2, "both flags are cleared, so neither leaks into the next menu");
    }
}
