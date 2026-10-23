use crate::models::ResourcePolicy;
use serde_json::{json, Value};

/// Resolve automatic RAM only after the exact quantization has been checked.
/// Explicit budgets remain the participant's choice.
pub(super) fn resolve_defaults(resources: &mut Value, preflight: &Value) {
    if resources["cpu"].is_null() { resources["cpu"] = json!(4); }
    if resources["memoryGb"].is_null() {
        resources["memoryGb"] = json!(yougori_cli::bounty::model_memory_recommendation(preflight));
    }
}

/// A model resized in Resources must not revert to an old worker budget when
/// its worker is restored and later recreates that model.
pub(super) fn adopt_model_allocation(resources: &mut Value, policy: &ResourcePolicy) {
    resources["cpu"] = json!(policy.cpu.preferred + 2.);
    resources["memoryGb"] = json!(policy.memory_gb.preferred + 4.);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_memory_fits_weights_and_sandboxes_but_preserves_explicit_limits() {
        let preflight = json!({"resources":{"weightsBytes":17_923_393_664u64}});
        let mut resources = json!({"storageGb":28,"storageDrive":"D:\\"});
        resolve_defaults(&mut resources, &preflight);
        assert_eq!(resources["memoryGb"], 28);
        assert_eq!(resources["cpu"], 4);
        assert_eq!(resources["storageGb"], 28);
        assert_eq!(resources["storageDrive"], "D:\\");
        for memory in [8, 36] {
            let mut explicit = json!({"cpu":6,"memoryGb":memory});
            resolve_defaults(&mut explicit, &preflight);
            assert_eq!(explicit, json!({"cpu":6,"memoryGb":memory}));
        }
    }

    #[test]
    fn restoring_a_resized_model_keeps_its_new_budget() {
        let policy = serde_json::from_value(json!({
            "cpu":{"min":2,"preferred":2,"max":2,"current":0},
            "memoryGb":{"min":28,"preferred":28,"max":28,"current":0},
            "dynamic":true,"priority":"normal"
        })).unwrap();
        let mut resources = json!({"cpu":4,"memoryGb":8,"storageGb":28});
        adopt_model_allocation(&mut resources, &policy);
        assert_eq!(resources, json!({"cpu":4.0,"memoryGb":32.0,"storageGb":28}));
        resolve_defaults(&mut resources, &json!({"resources":{"weightsBytes":17_923_393_664u64}}));
        assert_eq!(resources["memoryGb"], 32.0);
    }
}
