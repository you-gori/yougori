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
        "Installed: {}. Checking and opening the installer page keep your environments running.",
        status.current
    )];
    if status.channel == "preview" {
        note.push("This is a preview release. Unsigned installation requires your consent.".into());
    }
    if !status.notes.is_empty() {
        note.push(clean(&status.notes));
    }
    let choice = ui::select(
        &format!("Yougori {} is available. Get the update?", status.latest),
        &note,
        &[
            ui::Choice::new("Get update", "open the installer page"),
            ui::Choice::new("Later", "remind me tomorrow"),
        ],
        1,
    );
    match choice {
        Ok(0) => {
            let engine_only = status.platform.ends_with("-engine");
            if let Err(error) = release_notice::open_downloads(engine_only) {
                ui::warn(&clean(&error));
            }
            ui::info(&format!(
                "Get the latest installer at {}",
                release_notice::downloads_url(engine_only)
            ));
            ui::info("Finish your work before running the installer. The CLI and engine update together.");
        }
        Err(error) if !left(&error) => return Err(error),
        _ => {}
    }
    // Opening the page or dismissing is not permission to install anything.
    let _ = release_notice::remind_later(&status);
    Ok(())
}
