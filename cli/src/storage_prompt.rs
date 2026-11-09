//! Choosing where a model or environment is stored, as a person is asked it.
//!
//! A library module in its own right: `prepare_args` runs before every command that can take a
//! drive. It once sat in the launcher, which is gone; the prompt outlived it.
use crate::cli_ui::{self as ui, busy};
use crate::{client, public, public::call, storage};
use serde_json::{json, Value};
use std::{io::IsTerminal, sync::atomic::Ordering};

pub use crate::storage::Selection;
#[cfg(test)]
use crate::storage::initial_drive;

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

fn choose_supported(
    host: &Value,
    explicit: Option<&str>,
    minimum: u32,
    supports_selection: bool,
    previous: Option<&str>,
) -> Result<Selection, String> {
    storage::choose_drive(host, explicit, minimum, supports_selection, previous,
        "Where should this environment be stored?", "Storage is chosen for this new environment.")
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
        // A model from a local folder is checked against that folder, not looked up on Hugging Face.
        let folder = args.iter().position(|a| a == "--folder").and_then(|i| args.get(i + 1)).map(|path| public::model_folder(path)).transpose()?;
        let plan = model_storage(target, quant, folder.as_ref()).await?;
        model_support = Some(plan.supports_selection);
        (if model { 3 } else { 2 }, plan.minimum.max(requested))
    } else if env {
        if args.iter().any(|a| a == "--storage-drive") {
            return Ok(());
        }
        let parsed = crate::parse::parse(args, |_| {
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
            limits(&selected.host, true, 76).unwrap().0,
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

/// What a model's preflight says it needs on disk, and whether it can go on another drive.
pub struct ModelStorage { pub minimum: u32, pub supports_selection: bool }
impl ModelStorage {
    /// What a model's preflight says about storage: what it recommends, at least 12 GB, and
    /// whether the engine can place the model on another drive.
    pub fn from_preflight(preflight: &Value) -> Self {
        Self {
            minimum: preflight["resources"]["storageGbRecommended"].as_f64().unwrap_or(20.0).ceil().max(12.0) as u32,
            supports_selection: preflight["storageDriveSelection"] == true,
        }
    }
}
pub async fn model_storage(model: &str, quant: Option<&str>, folder: Option<&Value>) -> Result<ModelStorage, String> {
    let preflight=busy(if folder.is_some() {"Checking the model folder"} else {"Checking the model on Hugging Face"}, call("model_preflight",json!({"model":model,"quant":quant,"folder":folder}))).await?;
    if preflight["supported"]!=true {return Err(preflight["reason"].as_str().unwrap_or("This model needs a dedicated runner").into());}
    Ok(ModelStorage::from_preflight(&preflight))
}
/// Defaults and slider limits for this host; `min_storage` is raised to an existing disk's size.
pub fn limits(host: &Value, model: bool, min_storage: u32) -> Result<([u32; 3], [(u32, u32); 3]), String> {
    let max_cpu = host["totalCpu"]
        .as_u64()
        .unwrap_or(2)
        .max(1)
        .min(u32::MAX as u64) as u32;
    let max_ram = host["totalMemoryGb"]
        .as_f64()
        .unwrap_or(4.0)
        .floor()
        .max(2.0) as u32;
    let max_storage = host["totalStorageGb"]
        .as_f64()
        .zip(host["usedStorageGb"].as_f64())
        .map(|(total, used)| ((total - used - 2.0).floor() as i64).clamp(0, 16380) as u32)
        .unwrap_or(16380);
    if max_storage < min_storage {
        return Err(format!("This drive needs at least {min_storage} GB free for this environment, plus 2 GB reserved for the computer."));
    }
    if model && (max_cpu < 2 || max_ram < 4) {
        return Err("Models require at least 2 CPU cores and 4 GB RAM".into());
    }
    // A model runs on the GPU, so it needs no more CPU or memory than a project.
    let defaults = [
        max_cpu.min(2),
        max_ram.min(4),
        max_storage.min(20).max(min_storage),
    ];
    let limits = [
        (if model { 2 } else { 1 }, max_cpu),
        (if model { 4 } else { 1 }, max_ram),
        (min_storage, max_storage),
    ];
    Ok((defaults, limits))
}
