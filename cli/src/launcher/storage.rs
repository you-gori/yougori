use super::{busy, call, clean, ui};
use serde_json::{json, Value};
use std::{io::IsTerminal, sync::atomic::Ordering};
use yougori_cli::{client, public, storage};

pub struct Selection {
    pub drive: Option<String>,
    pub host: Value,
    pub label: String,
}

pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Existing disks stay in place and may reuse their already allocated capacity. The engine may
/// need a moment to measure the disk, so callers show a spinner (see [`super::busy`]).
pub async fn for_environment(host: &Value, env: &Value) -> Result<Value, String> {
    let id = env["id"].as_str().ok_or("Environment has no ID")?;
    let allocation = call("get_storage_allocation", json!({"environmentId":id})).await?;
    let maximum = allocation["maximumGb"]
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .ok_or("Cannot read this environment's storage capacity")?;
    let mut selected = host.clone();
    // The engine has already reserved its 2 GB; sliders subtract that reserve once.
    selected["totalStorageGb"] = json!(maximum + 2.0);
    selected["usedStorageGb"] = json!(0.0);
    Ok(selected)
}

/// Reads host disks only. Creation rechecks free space and filesystem support on the chosen drive.
/// With `explicit` nothing is asked. Otherwise a single question: as a [`ui::Wizard`] step, Back
/// returns [`ui::BACK`], while its Cancel choice still cancels.
pub fn choose(host: &Value, explicit: Option<&str>, minimum: u32) -> Result<Selection, String> {
    choose_supported(host, explicit, minimum, true, None)
}

/// [`choose`] asked again, with the drive chosen earlier (its path or label) preselected.
pub fn choose_with_previous(host: &Value, minimum: u32, previous: Option<&str>) -> Result<Selection, String> {
    choose_supported(host, None, minimum, true, previous)
}

/// [`choose`] for a model, on the engine's configured drive when it cannot place models on
/// another. `previous` is the drive chosen earlier, preselected when asked again.
pub fn choose_model(
    host: &Value,
    explicit: Option<&str>,
    minimum: u32,
    supports_selection: bool,
    previous: Option<&str>,
) -> Result<Selection, String> {
    public::model_storage_drive(supports_selection, host, explicit)?;
    let mut selected = choose_supported(host, explicit, minimum, supports_selection, previous)?;
    if !supports_selection {
        selected.drive = None;
        ui::info("Using the running engine's configured storage drive. Reopen the updated Yougori app to enable other drives.");
    }
    Ok(selected)
}

/// The drive to preselect: the one chosen earlier, else the configured storage drive, else the
/// first with room; only drives that `fit` count.
fn initial_drive(drives: &[Value], host: &Value, previous: Option<&str>, fits: impl Fn(&Value) -> bool) -> Option<usize> {
    let at = |path: Option<&str>| {
        let path = path?;
        drives.iter().position(|drive| {
            drive["path"].as_str().is_some_and(|candidate| storage::same_drive(candidate, path)) && fits(drive)
        })
    };
    at(previous)
        .or_else(|| at(host["storageDrive"].as_str()))
        .or_else(|| drives.iter().position(&fits))
}

fn choose_supported(
    host: &Value,
    explicit: Option<&str>,
    minimum: u32,
    supports_selection: bool,
    previous: Option<&str>,
) -> Result<Selection, String> {
    let drives = host["storageDrives"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    if drives.is_empty() {
        if explicit.is_some() {
            return Err("The selected storage drive is unavailable".into());
        }
        let picked = ui::select(
            "Where should this environment be stored?",
            &[],
            &[
                ui::Choice::new("Default storage", "use the configured environment storage"),
                ui::Choice::new("Cancel", "nothing is created"),
            ],
            0,
        )?;
        if picked == 1 {
            return Err(ui::CANCELLED.into());
        }
        return Ok(Selection {
            drive: None,
            host: host.clone(),
            label: "Default storage".into(),
        });
    }
    let allowed = |drive: &Value| {
        supports_selection
            || drive["path"]
                .as_str()
                .zip(host["storageDrive"].as_str())
                .is_some_and(|(a, b)| storage::same_drive(a, b))
    };
    let fits = |drive: &Value| {
        allowed(drive)
            && drive["readOnly"] != true
            && drive["freeGb"]
                .as_f64()
                .is_some_and(|free| free.is_finite() && free >= f64::from(minimum) + 2.0)
    };
    let picked = if let Some(path) = explicit {
        drives
            .iter()
            .position(|drive| {
                drive["path"]
                    .as_str()
                    .is_some_and(|candidate| storage::same_drive(candidate, path))
            })
            .ok_or("Choose an available storage drive")?
    } else {
        let mut choices = drives
            .iter()
            .map(|drive| {
                let path = clean(drive["path"].as_str().unwrap_or("Storage"));
                let free = drive["freeGb"].as_f64().unwrap_or(0.0);
                let hint = if !allowed(drive) {
                    "reopen the updated app to enable this drive".into()
                } else if drive["readOnly"] == true {
                    "read-only".into()
                } else if !fits(drive) {
                    format!(
                        "{free:.1} GB free; needs at least {} GB",
                        u64::from(minimum) + 2
                    )
                } else {
                    format!(
                        "{free:.1} GB free{}",
                        if drive["removable"] == true {
                            " · removable"
                        } else {
                            ""
                        }
                    )
                };
                let choice = ui::Choice::new(path, hint);
                if fits(drive) {
                    choice
                } else {
                    choice.disabled()
                }
            })
            .collect::<Vec<_>>();
        choices.push(ui::Choice::new("Cancel", "nothing is created"));
        let initial = initial_drive(drives, host, previous, &fits).unwrap_or(drives.len());
        let picked = ui::select(
            "Where should this environment be stored?",
            &["Storage is chosen for this new environment.".into()],
            &choices,
            initial,
        )?;
        if picked == drives.len() {
            return Err(ui::CANCELLED.into());
        }
        picked
    };
    if !fits(&drives[picked]) {
        return Err("The selected drive is read-only or does not have enough free space".into());
    }
    let path = drives[picked]["path"]
        .as_str()
        .ok_or("Storage drive has no path")?
        .to_owned();
    let selected = storage::host_on_drive(host, &drives[picked])?;
    Ok(Selection {
        drive: Some(path.clone()),
        host: selected,
        label: path,
    })
}

/// While alive, the engine's plain "still working" lines stay off the terminal: they would break
/// the spinners, which show the same progress. The command that follows prints them again.
struct Quiet(bool);

impl Quiet {
    fn on() -> Self {
        Self(client::QUIET.swap(true, Ordering::Relaxed))
    }
}

impl Drop for Quiet {
    fn drop(&mut self) {
        client::QUIET.store(self.0, Ordering::Relaxed);
    }
}

/// Direct CLI commands use the same picker as the menus. Piped scripts and dry runs never prompt.
pub async fn prepare_args(args: &mut Vec<String>) -> Result<(), String> {
    if !interactive()
        || args.iter().any(|a| {
            matches!(
                a.as_str(),
                "--help" | "-h" | "--dry-run" | "--dry-run=true" | "--file" | "--json"
            )
        })
    {
        return Ok(());
    }
    let first = args.first().map(String::as_str).unwrap_or("");
    let nested =
        matches!(first, "machine" | "vm" | "microvm") && args.get(1).is_some_and(|a| a == "run");
    let env = matches!(first, "env" | "environment") && args.get(1).is_some_and(|a| a == "create");
    let model = first == "model"
        && args.get(1).is_some_and(|a| a == "run")
        && !args.iter().any(|a| a == "--neocloud");
    let hf = first == "run"
        && args
            .get(1)
            .is_some_and(|a| a.starts_with("hf.co/") || a.starts_with("https://huggingface.co/"));
    if !env && !nested && !model && !hf && !matches!(first, "run" | "create") {
        return Ok(());
    }
    if args.len() < 2 || (first == "run" && args.len() == 1) {
        return Ok(());
    }
    let _quiet = Quiet::on();
    // Explicit drive flags belong to the host options, not a guest command after the image.
    let mut model_support = None;
    let (offset, minimum) = if model || hf {
        if args.iter().any(|a| a == "--storage-drive") {
            return Ok(());
        }
        busy("Starting Yougori engine", client::start(None)).await?;
        let target = args
            .get(if model { 2 } else { 1 })
            .ok_or("Supply a model")?;
        if busy("Looking for this model on this computer", public::find_model(target)).await?.is_some()
            && !args.iter().any(|a| a == "--quant")
        {
            return Ok(());
        }
        let quant = args
            .iter()
            .position(|a| a == "--quant")
            .and_then(|i| args.get(i + 1))
            .map(String::as_str);
        let requested = args
            .iter()
            .position(|a| a == "--storage")
            .and_then(|i| args.get(i + 1))
            .and_then(|raw| raw.trim_end_matches("GB").parse::<f64>().ok())
            .unwrap_or(20.0)
            .ceil()
            .max(1.0) as u32;
        let plan = super::model_storage(target, quant).await?;
        model_support = Some(plan.supports_selection);
        (if model { 3 } else { 2 }, plan.minimum.max(requested))
    } else if env {
        if args.iter().any(|a| a == "--storage-drive") {
            return Ok(());
        }
        let parsed = yougori_cli::parse::parse(args, |_| {
            Err("Use explicit storage in JSON requests".into())
        })?;
        let request = &parsed.request.params["request"];
        (
            2,
            request["storageGb"]
                .as_f64()
                .unwrap_or(match request["kind"].as_str() {
                    Some("microVm") => 6.0,
                    Some("fullVm") => 64.0,
                    _ => 20.0,
                })
                .ceil()
                .max(1.0) as u32,
        )
    } else {
        let offset = if nested { 2 } else { 1 };
        let parsed = public::parse_run(&args[offset..], matches!(first, "machine" | "vm"))?;
        if parsed.dry || parsed.request["storageDrive"].is_string() {
            return Ok(());
        }
        (
            offset,
            parsed.request["storageGb"]
                .as_f64()
                .unwrap_or(1.0)
                .ceil()
                .max(1.0) as u32,
        )
    };
    busy("Starting Yougori engine", client::start(None)).await?;
    let host = busy("Reading this computer's drives and memory", call("refresh_host_metrics", json!({}))).await?["host"].take();
    let selection = match model_support {
        Some(supported) => choose_model(&host, None, minimum, supported, None)?,
        None => choose(&host, None, minimum)?,
    };
    if let Some(drive) = selection.drive {
        args.splice(offset..offset, ["--storage-drive".into(), drive]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_storage_uses_an_available_drive_and_checks_its_capacity() {
        let host = json!({"totalCpu":8,"totalMemoryGb":16,"storageDrive":"C:\\","storageDrives":[
            {"path":"C:\\","totalGb":100,"freeGb":4,"readOnly":false},
            {"path":"D:\\","totalGb":1000,"freeGb":800,"readOnly":false},
            {"path":"E:\\","totalGb":1000,"freeGb":800,"readOnly":true}
        ]});
        let selected = choose(&host, Some("d:/"), 76).unwrap();
        assert_eq!(selected.drive.as_deref(), Some("D:\\"));
        assert_eq!(
            super::super::limits(&selected.host, true, 76).unwrap().0,
            [2, 4, 76]
        );
        assert!(choose(&host, Some("C:\\"), 76).is_err());
        assert!(choose(&host, Some("E:\\"), 76).is_err());
        assert!(choose(&host, Some("F:\\"), 76).is_err());
    }
    #[test]
    fn the_drive_chosen_earlier_is_preselected_when_it_still_fits() {
        let host = json!({"storageDrive":"C:\\","storageDrives":[
            {"path":"C:\\","freeGb":50},
            {"path":"D:\\","freeGb":800},
            {"path":"E:\\","freeGb":10}
        ]});
        let drives = host["storageDrives"].as_array().unwrap();
        let fits = |drive: &Value| drive["freeGb"].as_f64().is_some_and(|free| free >= 22.0);
        assert_eq!(initial_drive(drives, &host, Some("d:/"), fits), Some(1));
        assert_eq!(initial_drive(drives, &host, None, fits), Some(0), "the configured drive");
        assert_eq!(initial_drive(drives, &host, Some("E:\\"), fits), Some(0), "a drive without room is not preselected");
        assert_eq!(initial_drive(drives, &host, Some("Default storage"), fits), Some(0));
        let full = json!({"storageDrive":"E:\\"});
        assert_eq!(initial_drive(drives, &full, None, fits), Some(0), "the first drive with room");
        assert_eq!(initial_drive(drives, &host, None, |_: &Value| false), None);
    }
    #[test]
    fn older_model_engine_keeps_the_chosen_default_without_an_unsupported_resource_field() {
        let host = json!({"totalCpu":8,"totalMemoryGb":16,"storageDrive":"D:\\","storageDrives":[
            {"path":"C:\\","totalGb":100,"freeGb":80,"readOnly":false},
            {"path":"D:\\","totalGb":1000,"freeGb":800,"readOnly":false}
        ]});
        let selected = choose_model(&host, Some("D:/"), 20, false, None).unwrap();
        assert!(selected.drive.is_none());
        assert_eq!(selected.label, "D:\\");
        assert_eq!(selected.host["storageDrive"], "D:\\");
        assert!(choose_model(&host, Some("C:\\"), 20, false, None).is_err());
        assert_eq!(
            choose_model(&host, Some("C:\\"), 20, true, None)
                .unwrap()
                .drive
                .as_deref(),
            Some("C:\\")
        );
    }
    #[test]
    fn engine_progress_lines_return_once_the_picker_is_done() {
        let before = client::QUIET.load(Ordering::Relaxed);
        {
            let _quiet = Quiet::on();
            assert!(client::QUIET.load(Ordering::Relaxed), "spinners show the progress meanwhile");
        }
        assert_eq!(client::QUIET.load(Ordering::Relaxed), before);
    }
    #[tokio::test]
    async fn scripts_and_dry_runs_do_not_open_a_picker_or_contact_the_engine() {
        let original = vec![
            "model".into(),
            "run".into(),
            "hf.co/example/model".into(),
            "--dry-run".into(),
        ];
        let mut args = original.clone();
        prepare_args(&mut args).await.unwrap();
        assert_eq!(args, original);
        assert!(!interactive());
        let original = vec![
            "run".into(),
            "alpine".into(),
            "echo".into(),
            "--storage-drive".into(),
            "literal-guest-option".into(),
        ];
        let mut args = original.clone();
        prepare_args(&mut args).await.unwrap();
        assert_eq!(args, original);
    }
}
