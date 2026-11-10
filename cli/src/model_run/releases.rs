use super::{busy, clean, left, stage, ui};
use std::{
    io::{self, IsTerminal},
    sync::atomic::{AtomicBool, Ordering},
};
use yougori_cli::release_notice;

static OFFERED: AtomicBool = AtomicBool::new(false);

/// Only interactive entry points call this. Scripted output stays unchanged.
pub(super) async fn offer(manual: bool) -> Result<(), String> {
    if !manual && (OFFERED.swap(true, Ordering::Relaxed) || !release_notice::automatic_allowed()) {
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !ui::can_prompt() {
        return Ok(());
    }
    let status = if manual {
        stage("Checking for updates", |_| "Release check complete".into(), release_notice::check_cli(true)).await?
    } else {
        match busy("Checking for updates", release_notice::check_cli(false)).await {
            Ok(status) => status,
            Err(error) if error == ui::CANCELLED => return Err(error),
            Err(_) => return Ok(()), // Offline must not prevent the user's work.
        }
    };
    if !status.update_available || (!manual && status.remind_later) {
        if manual {
            ui::info(&if status.download_available {
                format!("Yougori {} is up to date.", clean(&status.current))
            } else {
                format!(
                    "No newer downloadable release is available for {}.",
                    clean(&status.platform)
                )
            });
        }
        return Ok(());
    }
    let mut note = vec![format!(
        "Installed: {}. Updating stops Yougori's workloads, installs the release and starts Yougori again.",
        status.current
    )];
    if status.channel == "preview" {
        note.push("This preview has no publisher signature: Yougori checks it against the SHA-256 published on yougori.com.".into());
    }
    if !status.notes.is_empty() {
        note.push(clean(&status.notes));
    }
    let choice = ui::select(
        &format!("Yougori {} is available. Update now?", status.latest),
        &note,
        &[
            ui::Choice::new("Update now", "the same as yougori update"),
            ui::Choice::new("Later", "remind me tomorrow"),
        ],
        1,
    );
    match choice {
        Ok(0) => return update_now().await,
        Err(error) if !left(&error) => return Err(error),
        _ => {}
    }
    // Dismissing is not permission to install anything.
    let _ = release_notice::remind_later(&status);
    Ok(())
}

/// Update now, from a menu: what `yougori update` does once confirmed. The command the person
/// started then ends, since Yougori restarts under it.
async fn update_now() -> Result<(), String> {
    use yougori_cli::update::{self, Offer};
    let plan = match busy("Checking for updates", update::offer()).await? {
        Offer::Ready(plan) => plan,
        Offer::Current(answer) | Offer::Elsewhere(answer) => {
            ui::lines(update::summary(&answer));
            return Ok(());
        }
    };
    let (result, _) = crate::install_update(&["update".to_owned()], plan).await?;
    ui::lines(update::summary(&result));
    Err(yougori_cli::wire::cancelled("Run the command again once Yougori is back."))
}
