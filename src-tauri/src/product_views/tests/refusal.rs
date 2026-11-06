//! Refusals: stable codes unique across the product's and V08's, each source's own remedy,
//! and the setup crate's existing Diagnostic.

use std::collections::BTreeSet;

use super::*;
use crate::foundation::evidence::{
    CategoryRefusal, EvidenceRefusal, Remedy as EvidenceRemedy, SelectionRefusal, Staleness,
};
use crate::foundation::ids::GpuDeviceKey;
use crate::foundation::product::{
    CategoryCode, ContractCode, EvidenceCode, MigrationCode, ModelMemoryCode,
    PolicyCode as Carried, PolicyCodeError, Refusal, RefusalCode, Remedy,
};
use crate::model_memory::placement::ShapeRefusal;
use crate::model_memory::residency::vram::{VramBreakdown, VramOvercommit, VramPiece};
use crate::model_memory::residency::Interval;
use crate::product_views::from_sandbox::{policy_code, policy_refusal};
use crate::product_views::from_setup::diagnostic as to_diagnostic;
use crate::sandbox_contract::declarations::RefusalCode as PolicyCode;
use yougori_setup::dto::{Diagnostic, NextAction, Severity};

/// Every refusal code string, in [`RefusalCode::all`] order. A change here changes the
/// contract: bump `PRODUCT_CONTRACT_VERSION` and add fixtures for the new version.
const PINNED_CODES: &str = "evidence_missing evidence_source_too_weak \
    evidence_configuration_changed evidence_stale capability_unsupported capability_unknown \
    not_observed only_guest_asserted vm_sandbox_required runtime_not_allowed \
    no_runtime_offered no_admissible_runtime fallback_outside_authorized_runtime";

#[test]
fn codes_are_unique_across_domains_and_the_product_codes_are_pinned() {
    let own_codes = RefusalCode::all();
    assert_eq!(
        own_codes.len(),
        EvidenceCode::ALL.len()
            + CategoryCode::ALL.len()
            + ModelMemoryCode::ALL.len()
            + ContractCode::ALL.len()
            + MigrationCode::ALL.len()
    );
    let mut all = own_codes;
    for code in PolicyCode::ALL {
        let carried = policy_code(*code);
        assert_eq!(
            carried.as_str(),
            code.as_str(),
            "{code} is carried as it is"
        );
        all.push(RefusalCode::SandboxPolicy { code: carried });
    }
    let strings: Vec<&str> = all.iter().map(|code| code.as_str()).collect();
    let unique: BTreeSet<&str> = strings.iter().copied().collect();
    assert_eq!(unique.len(), strings.len(), "a code string repeats");
    assert_eq!(
        Carried::new("vm_sandbox_required"),
        Err(PolicyCodeError::ProductCode)
    );
    assert_eq!(
        Carried::new("Not Snake"),
        Err(PolicyCodeError::NotSnakeCase)
    );
    let own: Vec<&str> = EvidenceCode::ALL
        .iter()
        .map(|code| code.as_str())
        .chain(CategoryCode::ALL.iter().map(|code| code.as_str()))
        .collect();
    assert_eq!(own.join(" "), PINNED_CODES);
    let later: Vec<&str> = ModelMemoryCode::ALL
        .iter()
        .map(|code| code.as_str())
        .chain(ContractCode::ALL.iter().map(|code| code.as_str()))
        .chain(MigrationCode::ALL.iter().map(|code| code.as_str()))
        .collect();
    assert_eq!(
        later.join(" "),
        "context_too_long batch_too_large gpu_memory_short host_memory_short \
         newer_contract_version unsupported_contract_version contract_version_missing \
         invalid_product_document migration_decision_required migration_interrupted \
         unknown_legacy_choice"
    );
    for code in all {
        let json = serde_json::to_value(&code).unwrap();
        assert_eq!(json["code"], code.as_str());
        assert_eq!(serde_json::from_value::<RefusalCode>(json).unwrap(), code);
    }
}

#[test]
fn refusals_keep_their_sources_codes_and_remedies_without_repeating_the_remedy() {
    let stale = EvidenceRefusal::Stale {
        capability: Capability::HypervisorAvailable,
        staleness: Staleness::OtherClock,
    };
    let refusal = Refusal::from(&stale);
    assert_eq!(
        refusal.code,
        RefusalCode::Evidence {
            code: EvidenceCode::Stale
        }
    );
    assert_eq!(
        refusal.remedy(),
        &Remedy::Evidence {
            step: EvidenceRemedy::RunCheckAgain
        }
    );
    assert_eq!(
        refusal.reason.as_str(),
        "the hypervisor availability evidence was recorded on another clock, such as before a \
         restart"
    );
    assert!(stale.to_string().ends_with(&refusal.remedy().to_string()));

    let category = CategoryRefusal::NotExplicitlyAllowed {
        offered: ExecutionCategory::ProviderContainerRuntime,
        allowed: [ExecutionCategory::SharedKernelGpuRuntime].into(),
    };
    let refusal = Refusal::from(&category);
    assert_eq!(refusal.code.as_str(), "runtime_not_allowed");
    assert!(refusal.reason.as_str().contains("VM-D5"));
    assert!(!refusal
        .reason
        .as_str()
        .ends_with(&refusal.remedy().to_string()));
    let selection = SelectionRefusal {
        refusals: vec![category.clone(), category],
    };
    assert_eq!(Refusal::each_of(&selection).len(), 2);
    assert_eq!(
        Refusal::each_of(&SelectionRefusal { refusals: vec![] })[0]
            .code
            .as_str(),
        "no_runtime_offered"
    );

    let shape = ShapeRefusal::ContextTooLong {
        requested_tokens: 65_536,
        supported_tokens: 32_768,
    };
    let refusal = Refusal::from(&shape);
    assert_eq!(refusal.code.as_str(), "context_too_long");
    assert_eq!(refusal.remedy(), &Remedy::ShortenRequest);
    assert!(refusal.reason.as_str().contains("32768"));

    let piece = |total_bytes| VramPiece {
        during: Interval::new(MonotonicTime::from_nanos(0), MonotonicTime::from_nanos(10)).unwrap(),
        demand: VramBreakdown::default(),
        total_bytes,
    };
    let overcommit = VramOvercommit {
        device: GpuDeviceKey {
            machine: digest("yougori/test/product/machine/v1", &[b"m"]),
            device: digest("yougori/test/product/device/v1", &[b"d"]),
        },
        usable_vram_bytes: 20_000_000_000,
        first_over: piece(24_000_000_000),
        peak: piece(24_000_000_000),
    };
    let refusal = Refusal::from(&overcommit);
    assert_eq!(refusal.code.as_str(), "gpu_memory_short");
    assert_eq!(refusal.remedy(), &Remedy::FreeMemory);
    assert!(
        refusal
            .reason
            .as_str()
            .contains("needs 24 GB of GPU memory at its peak, and 20 GB is usable, 4 GB short"),
        "{refusal}"
    );
}

#[test]
fn a_refusal_is_the_setup_crates_diagnostic_with_typed_next_actions() {
    let category = CategoryRefusal::VmSandboxRequired {
        offered: ExecutionCategory::SharedKernelGpuRuntime,
    };
    let diagnostic = to_diagnostic(&Refusal::from(&category), Some("capabilities.run.runtime"));
    assert_eq!(diagnostic.code, "vm_sandbox_required");
    assert_eq!(diagnostic.severity, Severity::Error);
    assert!(!diagnostic.retryable);
    assert_eq!(
        diagnostic.field.as_deref(),
        Some("capabilities.run.runtime")
    );
    assert_eq!(
        diagnostic.next_actions,
        vec![NextAction::ChooseSupportedOption {
            field: "capabilities.run.runtime".to_owned()
        }]
    );
    assert!(diagnostic.message.contains("what you can do"));
    let wire = serde_json::to_value(&diagnostic).unwrap();
    assert_eq!(wire["nextActions"][0]["kind"], "choose_supported_option");
    assert_eq!(
        serde_json::from_value::<Diagnostic>(wire).unwrap(),
        diagnostic
    );

    let stale = to_diagnostic(
        &Refusal::from(&EvidenceRefusal::Missing {
            capability: Capability::IoUring,
        }),
        None,
    );
    assert!(stale.retryable);
    assert_eq!(stale.next_actions, vec![NextAction::Retry]);

    let policy = policy_refusal(PolicyCode::LegacyTierRefused, "tier T1 was a shared kernel");
    let diagnostic = to_diagnostic(&policy, None);
    assert_eq!(diagnostic.code, "legacy_tier_refused");
    assert!(diagnostic
        .message
        .contains(PolicyCode::LegacyTierRefused.help()));
    assert_eq!(diagnostic.next_actions, vec![NextAction::Review]);

    let update = to_diagnostic(
        &Refusal::new(
            RefusalCode::Contract {
                code: ContractCode::NewerContractVersion,
            },
            "a newer Yougori wrote this",
            Remedy::UpdateYougori,
        ),
        None,
    );
    assert!(update.next_actions.is_empty());
}
