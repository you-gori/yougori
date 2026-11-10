use serde_json::{json, Value};
use yougori_cli::release_notice::{self, ReleaseStatus};
use yougori_cli::update::{self, Offer, Plan};

#[tauri::command]
pub async fn check_release_update(force: bool) -> Result<Option<ReleaseStatus>, String> {
    if !force && !release_notice::automatic_allowed() {
        return Ok(None);
    }
    release_notice::check(env!("CARGO_PKG_VERSION"), false, force)
        .await
        .map(Some)
}

#[tauri::command]
pub async fn remind_release_update_later(version: String) -> Result<(), String> {
    let status = release_notice::check(env!("CARGO_PKG_VERSION"), false, false).await?;
    if status.latest == version {
        release_notice::remind_later(&status)?;
    }
    Ok(())
}

#[tauri::command]
pub fn open_release_downloads() -> Result<(), String> {
    release_notice::open_downloads(false)
}

/// The release `version` this app can install in place, as `yougori update` decides it for the
/// app: `Err` with what to tell the person when it cannot (they get the installer page instead).
async fn plan(version: &str) -> Result<Plan, String> {
    let app = std::env::current_exe().map_err(|e| e.to_string())?;
    match update::offer_for_app(app).await? {
        Offer::Ready(plan) if plan.latest == version => in_place(plan),
        Offer::Ready(plan) => Err(format!("Yougori {} is the newest release now. Check again.", plan.latest)),
        Offer::Current(_) => Err("Yougori is up to date.".into()),
        Offer::Elsewhere(answer) => Err(answer["next"].as_str().unwrap_or("Get the installer at https://yougori.com/#download.").to_owned()),
    }
}

#[cfg(windows)]
fn in_place(plan: Plan) -> Result<Plan, String> {
    Ok(plan)
}

#[cfg(target_os = "linux")]
fn in_place(plan: Plan) -> Result<Plan, String> {
    // The package installs through the desktop's own password dialog.
    let dialog = std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|folder| folder.join("pkexec").is_file()));
    if dialog { Ok(plan) } else { Err("This computer has no password dialog for installing packages (pkexec). Get the installer at https://yougori.com/#download, or run `yougori update` in a terminal.".into()) }
}

#[cfg(target_os = "macos")]
fn in_place(_: Plan) -> Result<Plan, String> {
    Err("Get the new version at https://yougori.com/#download.".into())
}

/// Before the person confirms: whether `version` installs in place, and whether it has a
/// publisher signature to check (unsigned updates are checked against their published SHA-256).
#[tauri::command]
pub async fn prepare_release_update(version: String) -> Result<Value, String> {
    Ok(match plan(&version).await {
        Ok(plan) => json!({"ready": true, "unsigned": plan.unsigned()}),
        Err(reason) => json!({"ready": false, "reason": reason}),
    })
}

/// Once the person confirms: downloads and checks `version`, then hands the installer over so it
/// runs as soon as the app has quit. The dashboard quits the app next, the way its Quit does, and
/// the installer opens it again.
#[tauri::command]
pub async fn install_release_update(version: String) -> Result<Value, String> {
    let prepared = update::prepare(plan(&version).await?).await?;
    #[cfg(windows)]
    update::install_after_exit(prepared, std::process::id())?;
    #[cfg(target_os = "linux")]
    {
        update::install_with_password_dialog(&prepared).await?;
        update::reopen_after_exit(std::process::id())?;
    }
    #[cfg(target_os = "macos")]
    drop(prepared);
    Ok(json!({"installing": version}))
}
