//! Migration of old setups: a decision is one of the offered options, a stored outcome
//! must be the rule's, and nothing changes before a verified backup. The rule over every
//! recorded choice, with V01's tiers and the setup crate's project files, is tested in
//! `product_views`.

use serde_json::json;

use super::*;
use crate::foundation::product::{
    BackupRef, CategoryShown, LegacyChoice, LegacySandboxType, MigrationItem, MigrationOption,
    MigrationOutcome, MigrationShown, MigrationStatus, Remedy,
};

fn sandbox(kind: LegacySandboxType, gpu: bool) -> LegacyChoice {
    LegacyChoice::SandboxType { kind, gpu }
}

fn labelled(category: ExecutionCategory) -> MigrationOption {
    MigrationOption::Labelled {
        category: CategoryShown::from(category),
    }
}

#[test]
fn a_decision_is_one_of_the_offered_options_and_a_stored_outcome_must_be_the_rules() {
    let gpu = MigrationItem::new("trainer", sandbox(LegacySandboxType::Gpu, true)).unwrap();
    assert!(gpu.needs_decision());
    let kept = gpu
        .decide(labelled(ExecutionCategory::SharedKernelGpuRuntime))
        .unwrap();
    assert_eq!(
        kept.outcome(),
        &MigrationOutcome::Decided {
            choice: labelled(ExecutionCategory::SharedKernelGpuRuntime)
        }
    );
    assert_eq!(round_trip(&kept), kept);
    assert!(gpu
        .decide(labelled(ExecutionCategory::ProviderContainerRuntime))
        .is_err());
    assert!(kept.decide(MigrationOption::VmSandbox).is_err());

    let vm = MigrationItem::new("web", sandbox(LegacySandboxType::Vm, false)).unwrap();
    let mut downgraded = serde_json::to_value(&vm).unwrap();
    downgraded["outcome"] = serde_json::to_value(MigrationOutcome::Preserved {
        category: CategoryShown::from(ExecutionCategory::SharedKernelGpuRuntime),
    })
    .unwrap();
    assert!(refused::<MigrationItem>(downgraded).contains("documented migration"));
    let mut chosen_for_them = serde_json::to_value(&vm).unwrap();
    chosen_for_them["outcome"] = serde_json::to_value(MigrationOutcome::Decided {
        choice: labelled(ExecutionCategory::SharedKernelGpuRuntime),
    })
    .unwrap();
    assert!(refused::<MigrationItem>(chosen_for_them).contains("documented migration"));
    let mut relabelled_pod = serde_json::to_value(
        MigrationItem::new("pod", sandbox(LegacySandboxType::Cloud, false)).unwrap(),
    )
    .unwrap();
    relabelled_pod["outcome"] = json!({
        "outcome": "decided",
        "choice": {"option": "labelled", "category": {
            "category": "provider_container_runtime", "label": "VM sandbox", "sandbox": true
        }}
    });
    assert!(refused::<MigrationItem>(relabelled_pod).contains("never with another label"));
}

#[test]
fn nothing_changes_before_a_verified_backup_or_while_a_decision_is_open() {
    let backup = BackupRef {
        manifest_sha256: digest("yougori/test/product/backup/v1", &[b"manifest"]),
        verified: true,
    };
    let open = vec![
        MigrationItem::new("web", sandbox(LegacySandboxType::Vm, false)).unwrap(),
        MigrationItem::new("trainer", sandbox(LegacySandboxType::Gpu, true)).unwrap(),
    ];
    let pending = MigrationShown::new(MigrationStatus::Pending, open.clone(), None).unwrap();
    assert_eq!(pending.refusals().len(), 1);
    assert!(MigrationShown::new(
        MigrationStatus::InProgress {
            completed: 0,
            total: 2
        },
        open.clone(),
        Some(backup)
    )
    .is_err());

    let decided = vec![
        open[0].clone(),
        open[1].decide(MigrationOption::VmSandbox).unwrap(),
    ];
    let running = MigrationStatus::InProgress {
        completed: 1,
        total: 2,
    };
    assert!(MigrationShown::new(running, decided.clone(), None).is_err());
    let unverified = BackupRef {
        verified: false,
        ..backup
    };
    assert!(MigrationShown::new(running, decided.clone(), Some(unverified)).is_err());
    assert!(MigrationShown::new(
        MigrationStatus::InProgress {
            completed: 3,
            total: 2
        },
        decided.clone(),
        Some(backup)
    )
    .is_err());
    let shown = MigrationShown::new(running, decided.clone(), Some(backup)).unwrap();
    assert!(shown.refusals().is_empty());
    assert_eq!(round_trip(&shown), shown);

    let interrupted = MigrationShown::new(
        MigrationStatus::Interrupted {
            completed: 1,
            total: 2,
        },
        decided,
        Some(backup),
    )
    .unwrap();
    let refusals = interrupted.refusals();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].code.as_str(), "migration_interrupted");
    assert_eq!(refusals[0].remedy(), &Remedy::ResumeMigration);
    assert!(refusals[0].remedy().is_retry());

    assert!(MigrationShown::new(MigrationStatus::NotNeeded, open, None).is_err());
    let mut json = serde_json::to_value(&interrupted).unwrap();
    json["backup"]["verified"] = json!(false);
    assert!(refused::<MigrationShown>(json).contains("verified backup"));
    let unit_extra = refused::<MigrationStatus>(json!({"status": "completed", "forced": true}));
    assert!(unit_extra.contains("unknown field"), "{unit_extra}");
}
