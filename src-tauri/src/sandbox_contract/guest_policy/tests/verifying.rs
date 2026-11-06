//! The verification plan: coverage of every forbidden interface, V15's errnos and
//! verifiers, and running VM-CP-05's evaluator against a guest that behaves as the plan
//! says (M07A item 4; VM-CP-05; §8.1).

use std::collections::BTreeSet;

use super::*;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::confinement::{
    enforcement, evaluate, Check, Enforcement, Errno, GuestProbeDocument, GuestReport,
    HostCorroboration, InterfaceProbe, KernelBuildRecord, KernelOption, ManifestExpectation,
    ObservedCapabilities, OptionState, PathProbe, ProbeOutcome, Role, UidPolicy,
};

fn image(name: &str) -> Digest {
    digest("yougori/test/guest-policy/image/v1", &[name.as_bytes()])
}

/// The errno an honest guest's probe sees, read from the plan: seccomp answers first
/// where it is declared, otherwise the primary.
fn planned_errno(step: &VerificationStep) -> Errno {
    let answering = step
        .mechanisms
        .iter()
        .find(|planned| planned.mechanism == Mechanism::Seccomp)
        .unwrap_or(&step.mechanisms[0]);
    answering.failures[0]
}

/// What a guest that installed `policy` and probed as its plan says reports.
fn report_following(profile: &ConfinementProfile, policy: &GuestPolicy) -> GuestReport {
    let mut interfaces = Vec::new();
    let mut protected_paths = Vec::new();
    for step in &policy.body().verification {
        let outcome = ProbeOutcome::Failed {
            errno: planned_errno(step),
        };
        for verification in &step.verified_by {
            match verification {
                Verification::GuestProbe => interfaces.push(InterfaceProbe {
                    interface: step.interface,
                    outcome,
                }),
                Verification::GuestPathProbe { path } => protected_paths.push(PathProbe {
                    path: path.clone(),
                    outcome,
                }),
                Verification::HostKernelRecord { .. } => {}
            }
        }
    }
    let capabilities: Vec<LinuxCapability> = policy
        .body()
        .oci
        .process
        .capabilities
        .bounding
        .iter()
        .map(|capability| capability.capability())
        .collect();
    let uid = match policy.body().uid {
        UidPolicy::Fixed { uid, .. } => uid.get(),
        UidPolicy::AnyNonRoot => 1000,
    };
    GuestReport::receive(GuestProbeDocument {
        profile: profile.digest(),
        interfaces,
        protected_paths,
        capabilities: Some(ObservedCapabilities {
            bounding: capabilities.clone(),
            permitted: capabilities.clone(),
            effective: capabilities,
        }),
        uid: Some(uid),
        no_new_privs: Some(policy.body().oci.process.no_new_privileges),
        kernel_settings: Vec::new(),
        kernel_options: Vec::new(),
        root_image: None,
    })
    .unwrap()
}

/// A kernel built as the policy's kernel requirements say.
fn kernel(policy: &GuestPolicy) -> KernelBuildRecord {
    let mut options: Vec<(KernelOption, OptionState)> = policy
        .body()
        .kernel
        .absent_options
        .iter()
        .map(|option| (*option, OptionState::NotSet))
        .collect();
    options.push((KernelOption::Vsockets, OptionState::BuiltIn));
    KernelBuildRecord::new(image("kernel"), options).unwrap()
}

#[test]
fn the_verification_plan_covers_every_forbidden_interface_with_v15s_errnos_and_verifiers() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let steps = &policy.body().verification;
        let planned: Vec<Interface> = steps.iter().map(|step| step.interface).collect();
        let forbidden: Vec<Interface> = profile
            .forbidden()
            .iter()
            .map(|entry| entry.interface)
            .collect();
        assert_eq!(planned, forbidden);
        for (step, entry) in steps.iter().zip(profile.forbidden()) {
            let union: BTreeSet<Errno> = step
                .mechanisms
                .iter()
                .flat_map(|planned| planned.failures.iter().copied())
                .collect();
            assert_eq!(
                step.expected_failures,
                union.into_iter().collect::<Vec<_>>()
            );
            let typed = entry.expected_failures();
            assert!(step
                .expected_failures
                .iter()
                .all(|errno| typed.contains(errno)));
            assert_eq!(step.declared(), entry.mechanisms());
            assert_eq!(step.mechanisms[0].role, Role::Primary);
            for planned in &step.mechanisms {
                let Enforcement::Enforces(failures) =
                    enforcement(planned.mechanism, step.interface)
                else {
                    panic!("{} cannot enforce {}", planned.mechanism, step.interface)
                };
                let yama = planned.mechanism == Mechanism::Lsm
                    && matches!(
                        step.interface,
                        Interface::Ptrace | Interface::PtraceOtherUsers
                    );
                if yama {
                    assert_eq!(planned.failures, [Errno::EPERM]);
                } else {
                    assert_eq!(planned.failures, failures);
                }
                assert!(!planned.failures.is_empty());
            }
            let guest: Vec<&Verification> = step
                .verified_by
                .iter()
                .filter(|verification| verification.source() == SourceClass::GuestReport)
                .collect();
            if step.interface == Interface::ProtectedPathWrite {
                assert_eq!(guest.len(), profile.protected_paths().len());
            } else {
                assert_eq!(guest, [&Verification::GuestProbe]);
            }
            let host: BTreeSet<KernelOption> = step
                .verified_by
                .iter()
                .filter_map(|verification| match verification {
                    Verification::HostKernelRecord { option } => Some(*option),
                    _ => None,
                })
                .collect();
            let expected: BTreeSet<KernelOption> = if entry.uses(Mechanism::KernelOptionAbsent) {
                step.interface.kernel_options().iter().copied().collect()
            } else {
                BTreeSet::new()
            };
            assert_eq!(host, expected);
        }
        assert_eq!(
            policy.body().host_corroboration_required,
            profile.requires_host_corroboration()
        );
    }
    let strict = compiled(&builtin(WorkloadProfile::StrictTool));
    let io_uring = strict.step(Interface::IoUring).unwrap();
    assert_eq!(io_uring.expected_failures, [Errno::EPERM, Errno::ENOSYS]);
    assert_eq!(
        io_uring.verified_by,
        [
            Verification::GuestProbe,
            Verification::HostKernelRecord {
                option: KernelOption::IoUring
            }
        ]
    );
    assert_eq!(io_uring.verified_by[1].source(), SourceClass::HostProbe);
    let vsock = strict.step(Interface::VsockSocket).unwrap();
    assert_eq!(vsock.expected_failures, [Errno::EPERM]);
    let paths = strict.step(Interface::ProtectedPathWrite).unwrap();
    assert_eq!(paths.expected_failures, [Errno::EACCES, Errno::EROFS]);
    assert_eq!(paths.verified_by.len(), 5);
    let ptrace = strict.step(Interface::Ptrace).unwrap();
    assert_eq!(ptrace.expected_failures, [Errno::EPERM]);
    assert!(strict.body().host_corroboration_required);
}

#[test]
fn the_plan_expects_yamas_eperm_for_an_lsm_ptrace_rule_and_landlocks_eacces_for_a_path() {
    let gdb = compiled(&service_with_gdb());
    let other_users = gdb.step(Interface::PtraceOtherUsers).unwrap();
    assert_eq!(
        other_users.mechanisms,
        [PlannedMechanism {
            mechanism: Mechanism::Lsm,
            role: Role::Primary,
            failures: vec![Errno::EPERM],
        }]
    );
    assert_eq!(other_users.expected_failures, [Errno::EPERM]);
    assert_eq!(
        enforcement(Mechanism::Lsm, Interface::PtraceOtherUsers),
        Enforcement::Enforces(&[Errno::EPERM, Errno::EACCES])
    );
    assert!(!other_users.expected_failures.contains(&Errno::EACCES));
    let service = compiled(&builtin(WorkloadProfile::Service));
    let ptrace = service.step(Interface::Ptrace).unwrap();
    let lsm = &ptrace.mechanisms[1];
    assert_eq!((lsm.mechanism, lsm.role), (Mechanism::Lsm, Role::Backup));
    assert_eq!(lsm.failures, [Errno::EPERM]);
    let landlock = compiled(&device_with_lsm_path());
    let paths = landlock.step(Interface::ProtectedPathWrite).unwrap();
    assert_eq!(paths.mechanisms[0].failures, [Errno::EACCES]);
    assert_eq!(paths.expected_failures, [Errno::EACCES]);
}

#[test]
fn vm_cp_05_runs_against_a_guest_that_behaves_as_the_plan_says() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let guest = report_following(&profile, &policy);
        let host = HostCorroboration::host_observed(image("root"), kernel(&policy), []);
        let manifest = ManifestExpectation {
            root_image: image("root"),
            kernel: kernel(&policy),
        };
        let verdict = evaluate(&profile, Some(&guest), Some(&host), Some(&manifest));
        assert!(
            verdict.passed(),
            "{}: {:?}",
            profile.workload(),
            verdict.checks
        );
        let mut planned = BTreeSet::new();
        for step in &policy.body().verification {
            for (verification, check) in step.verified_by.iter().zip(step.checks()) {
                let found = verdict
                    .check(&check)
                    .unwrap_or_else(|| panic!("no {check:?}"));
                assert!(found.passed(), "{check:?}");
                assert_eq!(found.source, verification.source());
                planned.insert(format!("{check:?}"));
            }
        }
        for found in &verdict.checks {
            let per_interface = matches!(
                found.check,
                Check::ForbiddenInterface { .. }
                    | Check::ProtectedPathWrite { .. }
                    | Check::HostKernelOptionAbsent { .. }
            );
            if per_interface {
                assert!(
                    planned.contains(&format!("{:?}", found.check)),
                    "{:?} is not in the plan",
                    found.check
                );
            }
        }
    }
}

#[test]
fn an_errno_outside_the_plan_fails_its_vm_cp_05_check() {
    let profile = builtin(WorkloadProfile::StrictTool);
    let policy = compiled(&profile);
    let step = policy.step(Interface::VsockSocket).unwrap();
    assert!(!step.expected_failures.contains(&Errno::EAFNOSUPPORT));
    let mut document = GuestProbeDocument {
        profile: profile.digest(),
        interfaces: vec![InterfaceProbe {
            interface: Interface::VsockSocket,
            outcome: ProbeOutcome::Failed {
                errno: Errno::EAFNOSUPPORT,
            },
        }],
        protected_paths: Vec::new(),
        capabilities: None,
        uid: None,
        no_new_privs: None,
        kernel_settings: Vec::new(),
        kernel_options: Vec::new(),
        root_image: None,
    };
    let verdict = evaluate(
        &profile,
        Some(&GuestReport::receive(document.clone()).unwrap()),
        None,
        None,
    );
    let check = verdict.check(&step.checks()[0]).unwrap();
    assert!(!check.passed());
    document.interfaces[0].outcome = ProbeOutcome::Failed {
        errno: planned_errno(step),
    };
    let verdict = evaluate(
        &profile,
        Some(&GuestReport::receive(document).unwrap()),
        None,
        None,
    );
    assert!(verdict.check(&step.checks()[0]).unwrap().passed());
}
