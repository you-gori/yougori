//! What a command says it is doing while it runs.
//!
//! Every command goes through [`command_progress`], not just the ones that used to be reachable
//! from the launcher menu: it is what puts a label and a spinner on the wait. It lived under
//! launcher/ because the menu was written first, which meant deleting the launcher would have
//! taken the progress line off every remaining command, templates included.

use crate::cli_ui as ui;


pub fn activity_label(args: &[String]) -> &'static str {
    let first = args.first().map(String::as_str).unwrap_or("");
    let second = args.get(1).map(String::as_str).unwrap_or("");
    match (first, second) {
        ("rm", _) | ("env", "delete") => "Deleting environment and cleaning up its data",
        ("start", _) | ("env", "start") => "Starting environment",
        ("stop", _) | ("env", "stop") => "Stopping environment",
        ("restart", _) | ("env", "restart") => "Restarting environment",
        ("env", "create") => "Creating environment",
        ("env", "open") => "Opening environment",
        ("env", "resources") => "Updating CPU and memory",
        ("rename", _) => "Renaming environment",
        ("cp", _) => "Copying files",
        ("logs", _) => "Loading environment logs",
        ("snapshot", "create") => "Creating snapshot",
        ("snapshot", "restore") => "Restoring snapshot",
        ("snapshot", "delete") => "Deleting snapshot",
        ("backup", "export") => "Exporting backup",
        ("backup", "import") => "Importing backup",
        ("backup", "restore") => "Restoring backup",
        ("storage", "prune") => "Reclaiming storage",
        ("storage", "location") => "Updating storage location",
        ("gpu", "setup") => "Installing GPU runtime",
        ("share", "add") => "Sharing folder",
        ("app", "quit") => "Stopping Yougori and its workloads",
        ("app", "show") => "Opening Yougori desktop",
        ("app", "autostart") => "Loading startup settings",
        ("app", "start") => "Starting Yougori engine",
        ("update", _) => "Checking for updates",
        ("doctor", _) => "Checking Yougori",
        ("status" | "ps" | "inspect", _) => "Loading environment details",
        ("model", _) => "Loading model information",
        ("neocloud", "install") => "Installing provider CLI",
        ("neocloud", "prices") => "Checking GPU stock and prices",
        ("neocloud", _) => "Loading Neocloud information",
        ("grids", "list") => "Looking for the grids on this computer",
        ("grids", "status") => "Asking the grid how it is",
        ("grids", "log") => "Reading what the grid recorded",
        ("grids", _) => "Asking the grid",
        _ => "Working",
    }
}

/// Runs `work`, showing what it is doing, named from `args`.
pub async fn command_progress<T>(args: &[String], work: impl std::future::Future<Output = T>) -> T {
    ui::command_activity(activity_label(args), work).await
}
