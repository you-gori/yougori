use std::collections::HashSet;

use serde_json::Value;
use tauri::{Emitter, Manager, UserAttentionType};
use crate::AppHandle;
use tauri_plugin_notification::NotificationExt;

const EVENT: &str = "vault-approval-needed";

fn ready_ids(status: &Value) -> HashSet<String> {
    status["pending"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|request| request["ready"] == true)
        .filter_map(|request| request["id"].as_str().map(str::to_owned))
        .collect()
}
fn should_alert(ready: &HashSet<String>, alerted: &HashSet<String>, focused: bool, last_alert: Option<std::time::Instant>) -> bool {
    !focused
        && !ready.is_subset(alerted)
        && last_alert.is_none_or(|time| time.elapsed() >= std::time::Duration::from_secs(10))
}

pub fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut seen = HashSet::new();
        let mut alerted = HashSet::new();
        let mut last_alert: Option<std::time::Instant> = None;
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            timer.tick().await;
            let Ok(status) = crate::vault::broker(&yougori_vault::protocol::Request::Status {}).await else {
                // Keep IDs across a brief broker restart so a request is not
                // announced twice if the same request is still pending.
                continue;
            };
            let ready = ready_ids(&status);
            let new_count = ready.difference(&seen).count();
            seen = ready.clone();
            alerted.retain(|id| ready.contains(id));
            if new_count > 0 {
                // Only IDs and a count leave the broker here. Notification text
                // never contains item names, client identity, or secret values.
                let _ = app.emit_to("main", EVENT, new_count);
            }
            let window = app.get_webview_window("main");
            if !should_alert(&ready, &alerted, window.as_ref().is_some_and(|window| window.is_focused().unwrap_or(false)), last_alert) {
                continue;
            }
            if let Some(window) = window {
                let _ = window.request_user_attention(Some(UserAttentionType::Informational));
            }
            let body = if ready.len() == 1 {
                "A Personal Vault request is waiting. Open Yougori to review it."
            } else {
                "Personal Vault requests are waiting. Open Yougori to review them."
            };
            let _ = app.notification().builder().title("Yougori · approval needed").body(body).show();
            alerted.extend(ready);
            last_alert = Some(std::time::Instant::now());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_ready_requests_are_eligible_and_ids_deduplicate() {
        let status = json!({"pending":[
            {"id":"a","ready":true,"description":"secret item name"},
            {"id":"b","ready":false},
            {"id":"a","ready":true},
        ]});
        let ready = ready_ids(&status);
        assert_eq!(ready.len(), 1);
        assert!(ready.contains("a"));
        assert!(ready_ids(&json!({"pending":[]})).is_empty());
        assert!(should_alert(&ready, &HashSet::new(), false, None));
        assert!(!should_alert(&ready, &HashSet::new(), true, None));
        assert!(!should_alert(&ready, &ready, false, None));
        assert!(!should_alert(&ready, &HashSet::new(), false, Some(std::time::Instant::now())));
    }
}
