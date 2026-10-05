use crate::{
    models::{Environment, EnvironmentKind, EnvironmentStatus, RuntimeProviderKind},
    runtime::RuntimeManager,
    store::PlatformStore,
};
use serde_json::{json, Value};
use tauri::{State, WebviewUrl, WebviewWindowBuilder};
use crate::AppHandle;

pub(crate) fn supports_apps(environment: &Environment) -> bool {
    environment.kind == EnvironmentKind::Container
        && environment.provider != Some(RuntimeProviderKind::YougoriCuda)
        || environment.kind == EnvironmentKind::MicroVm && environment.runtime == "builtin:alpine"
}

fn app_environment(store: &PlatformStore, id: &str) -> Result<Environment, String> {
    let environment = store.environment(&id)?;
    // GPU containers run in the separate CUDA runtime, which has no app display.
    let supported = supports_apps(&environment);
    if !supported {
        return Err(
            "Graphical app support requires an OCI container or a built-in Alpine MicroVM".into(),
        );
    }
    if environment.status != EnvironmentStatus::Running {
        return Err("Start this environment before opening apps".into());
    }
    Ok(environment)
}
fn valid_session(id: &str) -> bool {
    id.starts_with("app-")
        && id.len() <= 80
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[tauri::command]
pub async fn micro_vm_apps(
    environment_id: String,
    action: String,
    session_id: Option<String>,
    name: Option<String>,
    command: Option<String>,
    package: Option<String>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    let candidate = store.environment(&environment_id)?;
    if candidate.runtime.starts_with("shared://tunnel/") {
        if !matches!(action.as_str(), "status" | "install" | "launch" | "stop") { return Err("Use the authenticated remote display viewer".into()); }
        return crate::remote_access::request_saved(&candidate, "apps", json!({"action":action,"sessionId":session_id,"name":name,"command":command,"package":package})).await;
    }
    let environment = app_environment(&store, &environment_id)?;
    if !matches!(
        action.as_str(),
        "status" | "install" | "launch" | "stop" | "view"
    ) {
        return Err("Unknown app action".into());
    }
    if matches!(action.as_str(), "launch" | "stop" | "view")
        && !session_id.as_deref().is_some_and(valid_session)
    {
        return Err("Invalid app identifier".into());
    }
    if matches!(action.as_str(), "launch" | "install")
        && environment.resource_policy.memory_gb.current < 0.5
    {
        return Err(if environment.kind == EnvironmentKind::Container {
            "Give this container at least 0.5 GB of memory before running graphical apps. For browsers, use 2 GB."
        } else {
            "Set MicroVM Preferred memory to at least 0.5 GB and restart before setting up graphical apps. For browsers, start with 2 GB."
        }
        .into());
    }
    let body = json!({"id":environment.runtime_id.as_deref().unwrap_or(&environment.id),"sessionId":session_id,"name":name,"command":command,"package":package});
    let mut value = runtime
        .workspace_request(&environment, &format!("/v1/apps/{action}"), body)
        .await?;
    if action == "view" {
        let key = value["key"]
            .as_str()
            .filter(|k| k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("Invalid app display credentials")?;
        let (base, _) = runtime.workspace_endpoint(&environment).await?;
        let mut url = url::Url::parse(&base).map_err(|e| e.to_string())?;
        if url.host_str() != Some("127.0.0.1") {
            return Err("App display must use a local guest endpoint".into());
        }
        url.set_scheme("ws").map_err(|_| "Invalid display URL")?;
        url.set_path("/v1/apps/display");
        url.query_pairs_mut()
            .append_pair("sessionId", session_id.as_deref().unwrap())
            .append_pair("key", key);
        value = json!({"websocketUrl":url.to_string()});
    }
    Ok(value)
}

#[tauri::command]
pub async fn open_micro_vm_app_window(
    environment_id: String,
    session_id: String,
    app: AppHandle,
    store: State<'_, PlatformStore>,
) -> Result<bool, String> {
    let candidate = store.environment(&environment_id)?;
    let environment = if candidate.runtime.starts_with("shared://tunnel/") { candidate } else { app_environment(&store, &environment_id)? };

    if !valid_session(&session_id)
        || !environment_id.starts_with("env-")
        || environment_id.len() > 80
        || !environment_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid app window identifier".into());
    }
    crate::require_windows("App windows")?;
    // Only a trusted local route is loaded. Guest HTML never receives Tauri IPC.
    let location = format!("index.html?environment={environment_id}&guestApp={session_id}");
    WebviewWindowBuilder::new(
        &app,
        format!(
            "environment-{environment_id}-{}",
            uuid::Uuid::new_v4().simple()
        ),
        WebviewUrl::App(location.into()),
    )
    .title(format!(
        "App · {} — Yougori",
        environment.name.replace(['\r', '\n'], " ")
    ))
    .inner_size(1280.0, 850.0)
    .min_inner_size(720.0, 480.0)
    .resizable(true)
    .focused(true)
    .center()
    .build()
    .map_err(|e| e.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn app_session_ids_cannot_change_the_window_route() {
        assert!(valid_session("app-123-abcd"));
        for id in ["", "app-x&guestApp=y", "../../x", "app-%23", "env-x"] {
            assert!(!valid_session(id));
        }
    }
}

#[cfg(test)]
#[path = "guest_apps_tests.rs"]
mod runtime_tests;
