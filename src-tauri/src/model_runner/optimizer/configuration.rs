//! Durable uncertainty for a potentially delayed private configuration command.
use super::control::{self, Observation};
use serde_json::{json, Map, Value};

pub(super) const PENDING: &str = "YOUGORI_GPU_CONFIGURATION_PENDING";

pub(super) fn record(health: &Value) -> Result<String, String> {
    if !matches!(control::observation(health), Ok(Observation::V1 { .. })) {
        return Err("Restart this model with the updated engine before changing GPU settings. Model files are kept.".into());
    }
    // Keep only schema-validated counters/state, never model identity, content,
    // headers, errors, credentials, or unbounded extra health fields.
    let mut optimizer = Map::new();
    for key in [
        "controlProtocol",
        "instanceId",
        "sequence",
        "enabled",
        "pinned",
        "resident",
        "loading",
        "releaseUncertain",
        "active",
        "pending",
    ] {
        optimizer.insert(key.into(), health["optimizer"][key].clone());
    }
    Ok(json!({"status":health["status"],"optimizer":optimizer}).to_string())
}

fn observed(record: &str) -> Option<Observation> {
    if record.len() > 2048 {
        return None;
    }
    let health: Value = serde_json::from_str(record).ok()?;
    match control::observation(&health).ok()? {
        value @ Observation::V1 { .. } => Some(value),
        Observation::Legacy => None,
    }
}

/// A new CAS can supersede an older or equal pending CAS. An unparseable/legacy
/// marker has no such proof and is never silently overwritten.
pub(super) fn can_replace(record: &str, health: &Value) -> bool {
    match (observed(record), control::observation(health)) {
        (
            Some(Observation::V1 {
                instance_id: old,
                sequence: before,
            }),
            Ok(Observation::V1 {
                instance_id: current,
                sequence: after,
            }),
        ) => old != current || after >= before,
        _ => false,
    }
}

/// A later state-lock observation makes the old compare-and-set impossible.
/// Occupancy is still interpreted separately, including disabled resident models.
pub(super) fn invalidated(record: &str, health: &Value) -> bool {
    match (observed(record), control::observation(health)) {
        (
            Some(Observation::V1 {
                instance_id: old,
                sequence: before,
            }),
            Ok(Observation::V1 {
                instance_id: current,
                sequence: after,
            }),
        ) => old != current || after > before,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> Value {
        json!({"status":"idle","optimizer":{"controlProtocol":1,"instanceId":"a".repeat(32),"sequence":7,
            "enabled":true,"pinned":false,"resident":false,"loading":false,"releaseUncertain":false,"active":0,"pending":0}})
    }

    #[test]
    fn durable_record_uses_validated_state_and_survives_options_roundtrip() {
        let mut health = health();
        health["private"] = json!("fixture secret");
        health["optimizer"]["private"] = json!("fixture secret");
        let record = record(&health).unwrap();
        assert!(!record.contains("fixture secret"));
        assert!(record.len() <= 2048);
        let mut options = yougori_cli::workload::Options::default();
        options.environment.insert(PENDING.into(), record.clone());
        options.validate().unwrap();
        let saved = serde_json::to_vec(&options).unwrap();
        let loaded: yougori_cli::workload::Options = serde_json::from_slice(&saved).unwrap();
        assert!(!invalidated(&loaded.environment[PENDING], &health));
        health["optimizer"]["sequence"] = json!(8);
        assert!(invalidated(&loaded.environment[PENDING], &health));
    }

    #[test]
    fn unchanged_regressed_malformed_and_legacy_states_never_clear_pending_commands() {
        let initial = health();
        let pending = record(&initial).unwrap();
        assert!(!invalidated(&pending, &initial));
        let mut regression = initial.clone();
        regression["optimizer"]["sequence"] = json!(6);
        assert!(!invalidated(&pending, &regression));
        assert!(!can_replace(&pending, &regression));
        for malformed in [
            json!(null),
            json!({"optimizer":{}}),
            json!({"optimizer":{"controlProtocol":2}}),
        ] {
            assert!(!invalidated(&pending, &malformed));
            assert!(!can_replace(&pending, &malformed));
            assert!(record(&malformed).is_err());
        }
        for broken in ["", "PRIVATE", "{}", "{\"optimizer\":{}}"] {
            assert!(!invalidated(broken, &initial));
            assert!(!can_replace(broken, &initial));
        }
        assert!(!invalidated(&"x".repeat(2049), &initial));
    }

    #[test]
    fn later_revision_or_new_instance_invalidates_old_cas_without_claiming_free_memory() {
        let initial = health();
        let pending = record(&initial).unwrap();
        assert!(can_replace(&pending, &initial));
        let mut current = initial.clone();
        current["optimizer"]["enabled"] = json!(false);
        current["optimizer"]["loading"] = json!(true);
        current["optimizer"]["sequence"] = json!(8);
        assert!(invalidated(&pending, &current));
        current["optimizer"]["instanceId"] = json!("b".repeat(32));
        current["optimizer"]["sequence"] = json!(0);
        assert!(invalidated(&pending, &current));
        assert!(can_replace(&pending, &current));
        assert_eq!(current["optimizer"]["loading"], true);
    }
}
