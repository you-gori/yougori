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
