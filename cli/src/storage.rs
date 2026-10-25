//! Storage placement shared by interactive and scripted CLI creation.
use serde_json::Value;

pub fn same_drive(a: &str, b: &str) -> bool {
    fn normalized(value: &str) -> String {
        let path = value.replace('\\', "/").trim_end_matches('/').to_owned();
        if path.as_bytes().get(1) == Some(&b':') {
            path.to_ascii_lowercase()
        } else {
            path
        }
    }
    normalized(a) == normalized(b)
}

pub fn existing_drive<'a>(env: &'a Value, host: &'a Value) -> Option<&'a str> {
    env["storageDrive"]
        .as_str()
        .filter(|path| !path.is_empty())
        .or_else(|| host["storageDrive"].as_str())
}

pub fn validate_reuse(env: &Value, host: &Value, requested: Option<&str>) -> Result<(), String> {
    if let Some(requested) = requested {
        if existing_drive(env, host).is_none_or(|current| !same_drive(current, requested)) {
            return Err("This model already has an environment on another drive. Reusing it keeps its disk location; use its current drive or omit --storage-drive. No data was moved.".into());
        }
    }
    Ok(())
}

/// A drive chosen for new storage: its path (none for the engine's default storage), the host
/// figures measured on that drive, and its label.
pub struct Selection {
    pub drive: Option<String>,
    pub host: Value,
    pub label: String,
}

fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// The drive to preselect: the one chosen earlier, else the configured storage drive, else the
/// first with room; only drives that `fit` count.
pub fn initial_drive(drives: &[Value], host: &Value, previous: Option<&str>, fits: impl Fn(&Value) -> bool) -> Option<usize> {
    let at = |path: Option<&str>| {
        let path = path?;
        drives.iter().position(|drive| {
            drive["path"].as_str().is_some_and(|candidate| same_drive(candidate, path)) && fits(drive)
        })
    };
    at(previous)
        .or_else(|| at(host["storageDrive"].as_str()))
        .or_else(|| drives.iter().position(&fits))
}

/// Where new storage goes: one question listing this computer's drives with their free space
/// (`title` and `note` say what is stored), the same wherever it is asked (`yougori launch`,
/// models, Hub templates). Drives without `minimum` GB free (plus the engine's 2 GB) or that are
/// read-only cannot be picked. With `explicit` nothing is asked. As a [`ui::Wizard`] step, Back
/// returns [`ui::BACK`], while its Cancel choice cancels.
pub fn choose_drive(
    host: &Value,
    explicit: Option<&str>,
    minimum: u32,
    supports_selection: bool,
    previous: Option<&str>,
    title: &str,
    note: &str,
) -> Result<Selection, String> {
    use crate::cli_ui as ui;
    let drives = host["storageDrives"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    if drives.is_empty() {
        if explicit.is_some() {
            return Err("The selected storage drive is unavailable".into());
        }
        let picked = ui::select(
            title,
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
                .is_some_and(|(a, b)| same_drive(a, b))
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
                    .is_some_and(|candidate| same_drive(candidate, path))
            })
            .ok_or_else(|| {
                let available = drives.iter().filter_map(|drive| drive["path"].as_str()).map(clean).collect::<Vec<_>>().join(", ");
                format!("Storage drive {path} is not available. Choose one of: {available}.")
            })?
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
        let picked = ui::select(title, &[note.into()], &choices, initial)?;
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
    let selected = host_on_drive(host, &drives[picked])?;
    Ok(Selection {
        drive: Some(path.clone()),
        host: selected,
        label: path,
    })
}

/// Resource limits must use the selected disk, rather than the default disk's free space.
pub fn host_on_drive(host: &Value, drive: &Value) -> Result<Value, String> {
    let total = drive["totalGb"]
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or("Invalid storage capacity")?;
    let free = drive["freeGb"]
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0 && *value <= total)
        .ok_or("Invalid free storage")?;
    if drive["readOnly"] == true {
        return Err("The selected drive is read-only".into());
    }
    let mut selected = host.clone();
    selected["totalStorageGb"] = total.into();
    selected["usedStorageGb"] = (total - free).into();
    selected["storageDrive"] = drive["path"].clone();
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn resource_budget_uses_selected_drive_and_read_only_disks_are_rejected() {
        let host = json!({"totalCpu":16,"totalMemoryGb":32,"totalStorageGb":100,"usedStorageGb":90,"storageDrive":"C:\\"});
        let drive = json!({"path":"D:\\","totalGb":1000,"freeGb":800,"readOnly":false});
        let selected = host_on_drive(&host, &drive).unwrap();
        assert_eq!(selected["totalCpu"], 16);
        assert_eq!(selected["totalStorageGb"], 1000.0);
        assert_eq!(selected["usedStorageGb"], 200.0);
        assert_eq!(host["storageDrive"], "C:\\");
        assert!(host_on_drive(&host, &json!({"totalGb":100,"freeGb":80,"readOnly":true})).is_err());
    }
    #[test]
    fn reusing_models_cannot_silently_change_their_disk_location() {
        let host = json!({"storageDrive":"C:\\"});
        let model = json!({"storageDrive":"D:\\"});
        assert!(validate_reuse(&model, &host, Some("d:/")).is_ok());
        assert!(validate_reuse(&model, &host, Some("C:\\")).is_err());
        assert!(validate_reuse(&model, &host, None).is_ok());
        assert!(validate_reuse(&json!({}), &host, Some("C:/")).is_ok());
    }
}
