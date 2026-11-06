//! Execution categories: labels never overclaim isolation, a VM-required request never
//! shows a labelled runtime as its backend, and requested capabilities carry their
//! evidence.

use std::sync::Arc;

use serde_json::{json, Value};

use super::*;
use crate::foundation::evidence::{EvidenceRefusal, RuntimeRequirement, UnknownReason};
use crate::foundation::product::{
    CapabilityCheck, CategoryCode, CategoryShown, Evidence, EvidenceCode, Execution, Observer,
    RefusalCode, RequestedExecution, VerifiedBy,
};

const LABELLED: [ExecutionCategory; 3] = [
    ExecutionCategory::SharedKernelGpuRuntime,
    ExecutionCategory::ProviderContainerRuntime,
    ExecutionCategory::HostProcessModelRuntime,
];

#[test]
fn every_category_is_shown_by_its_own_label_and_only_a_vm_is_a_sandbox() {
    for category in ExecutionCategory::ALL {
        let shown = CategoryShown::from(category);
        assert_eq!(shown.label(), category.label());
        assert_eq!(shown.decision(), category.decision());
        assert_eq!(shown.is_sandbox(), category.is_vm_sandbox());
        assert_eq!(round_trip(&shown), shown);
        if !category.is_vm_sandbox() {
            assert!(shown.label().ends_with("not a sandbox"));
        }
    }
    let as_vm = refused::<CategoryShown>(json!({
        "category": "shared_kernel_gpu_runtime", "label": "VM sandbox", "sandbox": true
    }));
    assert!(as_vm.contains("never with another label"), "{as_vm}");
    let flag_only = refused::<CategoryShown>(json!({
        "category": "provider_container_runtime",
        "label": "remote runtime (provider container), not a sandbox",
        "decision": "VM-D5",
        "sandbox": true
    }));
    assert!(
        flag_only.contains("never with another label"),
        "{flag_only}"
    );
    let no_decision = refused::<CategoryShown>(json!({
        "category": "host_process_model_runtime",
        "label": "model runtime (host process, sandbox profile), not a sandbox",
        "sandbox": false
    }));
    assert!(no_decision.contains("VM-D6"), "{no_decision}");
}

#[test]
fn a_vm_required_request_refuses_labelled_runtimes_with_codes_and_remedies() {
    let mut host = Probes::new(SourceClass::HostProbe);
    let offers: Vec<_> = LABELLED
        .into_iter()
        .map(|category| host.offer(category))
        .collect();
    let requirement = RuntimeRequirement::VmSandbox;

    let one = Execution::select(&requirement, &offers[..1], host.now());
    assert_eq!(one.actual().value(), None);
    let refusal = one.actual().evidence().refusal().unwrap();
    assert_eq!(
        refusal.code,
        RefusalCode::Category {
            code: CategoryCode::VmSandboxRequired
        }
    );
    assert!(refusal.reason.as_str().contains("VM-D4"), "{refusal}");
    assert_eq!(refusal.code.as_str(), "vm_sandbox_required");

    let all = Execution::select(&requirement, &offers, host.now());
    let refusal = all.actual().evidence().refusal().unwrap();
    assert_eq!(
        refusal.code,
        RefusalCode::Category {
            code: CategoryCode::NoAdmissibleRuntime
        }
    );
    for decision in ["VM-D4", "VM-D5", "VM-D6"] {
        assert!(refusal.reason.as_str().contains(decision), "{refusal}");
    }
    let none = Execution::select(&requirement, &[], host.now());
    assert_eq!(
        none.actual().evidence().refusal().unwrap().code,
        RefusalCode::Category {
            code: CategoryCode::NoRuntimeOffered
        }
    );

    let choices = all.requested().choices();
    assert_eq!(choices.len(), 4);
    for choice in choices {
        assert_eq!(choice.allowed, choice.category.is_sandbox());
        assert_eq!(choice.refusal.is_none(), choice.allowed);
    }

    let mut with_vm = offers.clone();
    with_vm.push(host.offer(ExecutionCategory::VmSandbox));
    let admitted = Execution::select(&requirement, &with_vm, host.now());
    let actual = admitted.actual().value().unwrap();
    assert!(actual.category.is_sandbox());
    assert!(matches!(
        admitted.actual().evidence(),
        Evidence::Verified {
            by: VerifiedBy::HostProbe { .. },
            ..
        }
    ));
    assert_eq!(round_trip(&admitted), admitted);
}

#[test]
fn an_explicit_labelled_choice_is_kept_and_a_provider_runtime_is_observed_not_verified() {
    let mut provider = Probes::new(SourceClass::ProviderApi);
    let requirement =
        RuntimeRequirement::explicit([ExecutionCategory::ProviderContainerRuntime]).unwrap();
    let pod = provider.offer(ExecutionCategory::ProviderContainerRuntime);
    let execution = Execution::select(&requirement, &[pod], provider.now());
    let actual = execution.actual().value().unwrap();
    assert_eq!(
        actual.category.category(),
        ExecutionCategory::ProviderContainerRuntime
    );
    assert!(!actual.category.is_sandbox());
    assert!(matches!(
        execution.actual().evidence(),
        Evidence::Observed {
            by: Observer::ProviderApi,
            ..
        }
    ));
    assert!(execution
        .requested()
        .allows(ExecutionCategory::ProviderContainerRuntime));
    assert!(!execution.requested().allows(ExecutionCategory::VmSandbox));
}

/// A document of an execution the test then tampers with.
fn admitted_json() -> Value {
    let mut host = Probes::new(SourceClass::HostProbe);
    let vm = host.offer(ExecutionCategory::VmSandbox);
    let execution = Execution::select(&RuntimeRequirement::VmSandbox, &[vm], host.now());
    serde_json::to_value(&execution).unwrap()
}

#[test]
fn a_document_showing_a_refused_category_as_the_backend_is_refused() {
    let mut json = admitted_json();
    assert!(serde_json::from_value::<Execution>(json.clone()).is_ok());
    json["actual"]["value"]["category"] = serde_json::to_value(CategoryShown::from(
        ExecutionCategory::SharedKernelGpuRuntime,
    ))
    .unwrap();
    let error = refused::<Execution>(json);
    assert!(error.contains("does not admit"), "{error}");

    let mut asserted = admitted_json();
    asserted["actual"]["evidence"] = json!({"state": "asserted", "by": "declaration"});
    let error = refused::<Execution>(asserted);
    assert!(error.contains("never on an assertion"), "{error}");

    let mut checked = admitted_json();
    checked["actual"]["evidence"]["by"] = json!({"kind": "controlled_check"});
    let error = refused::<Execution>(checked);
    assert!(
        error.contains("host-probe evidence of its runtime category"),
        "{error}"
    );
    let mut other_capability = admitted_json();
    other_capability["actual"]["evidence"]["by"] =
        json!({"kind": "host_probe", "capability": "io_uring"});
    assert!(refused::<Execution>(other_capability).contains("host-probe evidence"));

    let mut choices = admitted_json();
    choices["requested"]["choices"][1]["allowed"] = json!(true);
    let error = refused::<Execution>(choices);
    assert!(
        error.contains("choices are not what the requirement"),
        "{error}"
    );

    let mut relabelled = admitted_json();
    relabelled["requested"]["requirement"] =
        json!({"requires": "explicit", "allowed": ["shared_kernel_gpu_runtime"]});
    assert!(serde_json::from_value::<RequestedExecution>(relabelled["requested"].clone()).is_err());
}

#[test]
fn requested_capabilities_carry_their_evidence_and_weak_evidence_never_fills_a_strong_one() {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = Arc::new(FakeProbe::guest_report(Capability::IoUring));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let subject = Subject::Runtime(runtime(ExecutionCategory::VmSandbox));
    probe.respond(
        &subject,
        Observation::supported(config(), HOUR, SupportDetail::Plain),
    );
    registry.refresh(Capability::IoUring, &subject).unwrap();

    let host_only = Requirement::host_only(Capability::IoUring, subject.clone(), HOUR, config());
    let outcome = registry.evaluate(&host_only);
    let check = CapabilityCheck::evaluate(&host_only, &outcome, registry.now());
    assert_eq!(check.required(), SourceClass::HostProbe);
    assert_eq!(
        check.evidence().refusal().unwrap().code,
        RefusalCode::Evidence {
            code: EvidenceCode::SourceTooWeak
        }
    );

    let lenient = Requirement::new(
        Capability::IoUring,
        subject,
        SourceClass::GuestReport,
        HOUR,
        config(),
    );
    let check = CapabilityCheck::evaluate(&lenient, &registry.evaluate(&lenient), registry.now());
    assert!(check.evidence().is_asserted());
    assert_eq!(round_trip(&check), check);

    let mut forged = serde_json::to_value(&check).unwrap();
    forged["required"] = json!("host_probe");
    let error = refused::<CapabilityCheck>(forged);
    assert!(error.contains("never stands behind"), "{error}");

    let mut checked = serde_json::to_value(&check).unwrap();
    checked["evidence"] = json!({
        "state": "verified", "by": {"kind": "controlled_check"}, "observed_at": 1, "fresh_until": 2
    });
    assert!(refused::<CapabilityCheck>(checked).contains("evidence of itself"));

    let mut below_floor = serde_json::to_value(&check).unwrap();
    below_floor["capability"] = json!("hypervisor_available");
    below_floor["required"] = json!("guest_report");
    let error = refused::<CapabilityCheck>(below_floor);
    assert!(error.contains("floor"), "{error}");

    let unknown = CapabilityCheck::evaluate(
        &host_only,
        &Err(EvidenceRefusal::Unknown {
            capability: Capability::IoUring,
            reason: UnknownReason::NotTested,
        }),
        registry.now(),
    );
    assert_eq!(
        unknown.evidence().refusal().unwrap().code.as_str(),
        "capability_unknown"
    );
}
