//! Migration of old setups: one documented rule over every recorded choice, V01's tiers
//! included, never downward, and old project files read with the setup crate's own spec.

use serde_json::json;

use super::*;
use crate::foundation::evidence::RuntimeRequirement;
use crate::foundation::product::{
    CategoryShown, IsolationTier, LegacyChoice, LegacySandboxType, MigrationItem, MigrationOption,
    MigrationOutcome, Remedy,
};
use crate::product_views::from_sandbox::{tier_item, tier_outcome};
use crate::product_views::from_setup::legacy_choice;
use crate::sandbox_contract::policy::LegacyTier;
use yougori_setup::resource::EnvironmentSpec;

fn sandbox(kind: LegacySandboxType, gpu: bool) -> LegacyChoice {
    LegacyChoice::SandboxType { kind, gpu }
}

fn labelled(category: ExecutionCategory) -> MigrationOption {
    MigrationOption::Labelled {
        category: CategoryShown::from(category),
    }
}

fn spec(json: serde_json::Value) -> EnvironmentSpec {
    serde_json::from_value(json).unwrap()
}

#[test]
fn every_recorded_choice_migrates_by_the_one_rule_and_never_downward() {
    let vm = RuntimeRequirement::VmSandbox;
    for kind in [LegacySandboxType::Vm, LegacySandboxType::MicroVm] {
        for gpu in [false, true] {
            assert_eq!(
                sandbox(kind, gpu).migrate().unwrap(),
                MigrationOutcome::Unchanged {
                    requirement: vm.clone()
                }
            );
        }
    }
    let MigrationOutcome::Strengthened { requirement, .. } =
        sandbox(LegacySandboxType::Container, false)
            .migrate()
            .unwrap()
    else {
        panic!("a CPU container is strengthened");
    };
    assert_eq!(requirement, vm);
    for (choice, kept) in [
        (
            sandbox(LegacySandboxType::Gpu, true),
            ExecutionCategory::SharedKernelGpuRuntime,
        ),
        (
            sandbox(LegacySandboxType::Container, true),
            ExecutionCategory::SharedKernelGpuRuntime,
        ),
        (
            sandbox(LegacySandboxType::Cloud, false),
            ExecutionCategory::ProviderContainerRuntime,
        ),
    ] {
        let MigrationOutcome::NeedsDecision { options, refusal } = choice.migrate().unwrap() else {
            panic!("{choice:?} is ambiguous");
        };
        assert_eq!(options, vec![MigrationOption::VmSandbox, labelled(kept)]);
        assert_eq!(refusal.code.as_str(), "migration_decision_required");
        assert_eq!(refusal.remedy(), &Remedy::ChooseMigrationOption);
    }
    assert_eq!(
        sandbox(LegacySandboxType::Shared, false).migrate().unwrap(),
        MigrationOutcome::FollowsOwner
    );

    for tier in [LegacyTier::T2, LegacyTier::T3] {
        let MigrationOutcome::Strengthened {
            requirement,
            reason,
        } = tier_outcome(IsolationTier::from(tier))
        else {
            panic!("{tier:?} has a requirement set");
        };
        assert!(tier_item("analysis", tier).is_ok());
        assert_eq!(requirement, vm);
        assert!(reason.as_str().contains("vm_sandbox"), "{reason}");
    }
    for tier in [LegacyTier::T1, LegacyTier::T4] {
        let MigrationOutcome::Refused { refusal } = tier_outcome(IsolationTier::from(tier)) else {
            panic!("{tier:?} is refused");
        };
        assert!(tier_item("scratch", tier).is_ok());
        assert_eq!(
            (LegacyChoice::IsolationTier {
                tier: IsolationTier::from(tier)
            })
            .migrate(),
            None
        );
        assert!(MigrationItem::with_outcome(
            "scratch",
            LegacyChoice::IsolationTier {
                tier: IsolationTier::from(tier)
            },
            MigrationOutcome::Preserved {
                category: CategoryShown::from(ExecutionCategory::SharedKernelGpuRuntime)
            }
        )
        .is_err());
        assert_eq!(refusal.code.as_str(), "legacy_tier_refused");
    }

    for category in ExecutionCategory::ALL {
        let outcome = (LegacyChoice::Category { category }).migrate().unwrap();
        if category.is_vm_sandbox() {
            assert_eq!(
                outcome,
                MigrationOutcome::Unchanged {
                    requirement: vm.clone()
                }
            );
        } else {
            assert_eq!(
                outcome,
                MigrationOutcome::Preserved {
                    category: CategoryShown::from(category)
                }
            );
        }
    }
}

#[test]
fn old_project_files_are_read_with_the_setup_crates_own_spec() {
    assert_eq!(
        legacy_choice(&spec(json!({}))).unwrap(),
        sandbox(LegacySandboxType::Container, false)
    );
    assert_eq!(
        legacy_choice(&spec(json!({"type": "gpu"}))).unwrap(),
        sandbox(LegacySandboxType::Gpu, true)
    );
    assert_eq!(
        legacy_choice(&spec(json!({"type": "container", "gpu": true}))).unwrap(),
        sandbox(LegacySandboxType::Container, true)
    );
    assert_eq!(
        legacy_choice(&spec(json!({"type": "microvm"}))).unwrap(),
        sandbox(LegacySandboxType::MicroVm, false)
    );
    let unknown = legacy_choice(&spec(json!({"type": "branch"}))).unwrap_err();
    assert_eq!(unknown.code.as_str(), "unknown_legacy_choice");
    assert!(unknown.reason.as_str().contains("kept as it is"));
}
