//! The mechanism table, assignment refusals and the separated responsibility map
//! (VM-W07 "forbidden interfaces fail by intended mechanism; seccomp/LSM responsibilities
//! separated"; §3.4; VM-CP-05).

use std::collections::BTreeSet;

use super::*;

fn enforces(mechanism: Mechanism, interface: Interface) -> Vec<Errno> {
    match enforcement(mechanism, interface) {
        Enforcement::Enforces(failures) => failures.to_vec(),
        Enforcement::CannotEnforce(reason) => panic!("{mechanism} {interface}: {reason}"),
    }
}

fn cannot(mechanism: Mechanism, interface: Interface) -> Unenforceable {
    match enforcement(mechanism, interface) {
        Enforcement::CannotEnforce(reason) => reason,
        Enforcement::Enforces(_) => panic!("{mechanism} enforces {interface}"),
    }
}

/// Syscall-number rules: the interfaces seccomp can refuse by number or integer argument.
const SYSCALL_RULES: [Interface; 8] = [
    Interface::IoUring,
    Interface::Bpf,
    Interface::Userfaultfd,
    Interface::PerfEventOpen,
    Interface::Kexec,
    Interface::ModuleLoading,
    Interface::Ptrace,
    Interface::VsockSocket,
];

#[test]
fn the_vm_cp_05_failures_are_pinned() {
    use Interface as I;
    use Mechanism as M;
    assert_eq!(enforces(M::KernelOptionAbsent, I::IoUring), [Errno::ENOSYS]);
    assert_eq!(enforces(M::Seccomp, I::IoUring), [Errno::EPERM]);
    assert_eq!(enforces(M::Seccomp, I::VsockSocket), [Errno::EPERM]);
    assert_eq!(
        enforces(M::ReadOnlyMount, I::ProtectedPathWrite),
        [Errno::EROFS]
    );
    assert_eq!(enforces(M::Lsm, I::ProtectedPathWrite), [Errno::EACCES]);
    assert_eq!(
        enforces(M::NamespaceCredentials, I::ProtectedPathWrite),
        [Errno::EACCES]
    );
    assert_eq!(
        enforces(M::Lsm, I::Ptrace),
        [Errno::EPERM, Errno::EACCES],
        "Yama answers EPERM, AppArmor and SELinux EACCES"
    );
}

#[test]
fn seccomp_never_takes_a_path_rule_or_the_own_user_ptrace_rule() {
    assert_eq!(
        cannot(Mechanism::Seccomp, Interface::ProtectedPathWrite),
        Unenforceable::SeccompCannotDereferencePointers
    );
    assert_eq!(
        cannot(Mechanism::Seccomp, Interface::PtraceOtherUsers),
        Unenforceable::SeccompCannotInspectTarget
    );
    let mut document = strict().document().clone();
    for entry in &mut document.forbidden {
        if entry.interface == Interface::ProtectedPathWrite {
            entry.primary = Mechanism::Seccomp;
        }
    }
    assert_eq!(
        refused(document),
        ProfileRefusal::Responsibility(ResponsibilityRefusal::CannotEnforce {
            interface: Interface::ProtectedPathWrite,
            mechanism: Mechanism::Seccomp,
            reason: Unenforceable::SeccompCannotDereferencePointers,
        })
    );
    // Seccomp can deny ptrace outright: that rule needs only the syscall number.
    assert_eq!(
        enforces(Mechanism::Seccomp, Interface::Ptrace),
        [Errno::EPERM]
    );
}

#[test]
fn the_lsm_takes_no_syscall_number_rule_and_seccomp_always_answers_eperm() {
    for interface in SYSCALL_RULES {
        assert_eq!(enforces(Mechanism::Seccomp, interface), [Errno::EPERM]);
        if interface != Interface::Ptrace {
            assert_eq!(
                cannot(Mechanism::Lsm, interface),
                Unenforceable::NotAssigned,
                "{interface}"
            );
        }
    }
}

#[test]
fn capability_absence_refuses_only_capability_gated_interfaces() {
    use Interface as I;
    for interface in [I::Kexec, I::ModuleLoading, I::PtraceOtherUsers] {
        assert_eq!(
            enforces(Mechanism::CapabilityAbsence, interface),
            [Errno::EPERM]
        );
    }
    for (interface, reason) in [
        (I::Bpf, Unenforceable::UnprivilegedUseRemains),
        (I::Userfaultfd, Unenforceable::UnprivilegedUseRemains),
        (I::PerfEventOpen, Unenforceable::UnprivilegedUseRemains),
        (I::IoUring, Unenforceable::NoCapabilityGate),
        (I::VsockSocket, Unenforceable::NoCapabilityGate),
        (I::Ptrace, Unenforceable::SameUserNeedsNoCapability),
    ] {
        assert_eq!(
            cannot(Mechanism::CapabilityAbsence, interface),
            reason,
            "{interface}"
        );
    }
    assert_eq!(
        cannot(Mechanism::KernelOptionAbsent, I::VsockSocket),
        Unenforceable::KernelOptionNotPerProcess
    );
    assert_eq!(
        cannot(Mechanism::NamespaceCredentials, I::Ptrace),
        Unenforceable::SameUserNeedsNoCapability
    );
}

#[test]
fn the_table_is_pinned_and_every_refusal_has_a_failure() {
    let mut enforcing = 0;
    for mechanism in Mechanism::ALL {
        for interface in Interface::ALL {
            if let Enforcement::Enforces(failures) = enforcement(mechanism, interface) {
                enforcing += 1;
                assert!(!failures.is_empty(), "{mechanism} {interface}");
                if mechanism == Mechanism::KernelOptionAbsent {
                    assert!(!interface.kernel_options().is_empty(), "{interface}");
                }
            }
        }
    }
    // Kernel 6, seccomp 8, capability 3, LSM 3, read-only mount 1, credentials 2.
    assert_eq!(enforcing, 23);
}

#[test]
fn identity_changing_capabilities_defeat_credentials() {
    let developer_document = developer().document().clone();

    let mut ptrace = without(developer_document.clone(), Interface::PtraceOtherUsers);
    ptrace.forbidden.push(ForbiddenInterface::new(
        Interface::PtraceOtherUsers,
        Mechanism::NamespaceCredentials,
    ));
    assert_eq!(
        refused(ptrace),
        ProfileRefusal::Responsibility(ResponsibilityRefusal::DefeatedByCapability {
            interface: Interface::PtraceOtherUsers,
            mechanism: Mechanism::NamespaceCredentials,
            capability: LinuxCapability::Setuid,
        })
    );

    let mut by_capability = without(developer_document.clone(), Interface::PtraceOtherUsers);
    by_capability.forbidden.push(ForbiddenInterface::new(
        Interface::PtraceOtherUsers,
        Mechanism::CapabilityAbsence,
    ));
    assert!(matches!(
        refused(by_capability),
        ProfileRefusal::Responsibility(ResponsibilityRefusal::DefeatedByCapability {
            capability: LinuxCapability::Setuid,
            ..
        })
    ));

    let mut paths = developer_document;
    paths
        .protected_paths
        .push(ProtectedPath::parse("~/.bashrc").unwrap());
    paths.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::NamespaceCredentials,
    ));
    assert_eq!(
        refused(paths),
        ProfileRefusal::Responsibility(ResponsibilityRefusal::DefeatedByCapability {
            interface: Interface::ProtectedPathWrite,
            mechanism: Mechanism::NamespaceCredentials,
            capability: LinuxCapability::DacOverride,
        })
    );
}

#[test]
fn credentials_need_no_new_privs_and_a_backup_must_differ() {
    let mut document = builtin(WorkloadProfile::Service).document().clone();
    document.no_new_privs = false;
    document
        .protected_paths
        .push(ProtectedPath::parse("config/").unwrap());
    document.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::NamespaceCredentials,
    ));
    assert_eq!(
        refused(document),
        ProfileRefusal::Responsibility(ResponsibilityRefusal::CredentialsNeedNoNewPrivs {
            interface: Interface::ProtectedPathWrite
        })
    );

    let capabilities = BTreeSet::new();
    let context = AssignmentContext {
        capabilities: &capabilities,
        no_new_privs: true,
    };
    let twice =
        ForbiddenInterface::with_backup(Interface::Bpf, Mechanism::Seccomp, Mechanism::Seccomp);
    assert_eq!(
        check_assignment(&twice, &context),
        Err(ResponsibilityRefusal::SameMechanismTwice {
            interface: Interface::Bpf,
            mechanism: Mechanism::Seccomp,
        })
    );
    let backup_cannot = ForbiddenInterface::with_backup(
        Interface::VsockSocket,
        Mechanism::Seccomp,
        Mechanism::KernelOptionAbsent,
    );
    assert_eq!(
        check_assignment(&backup_cannot, &context),
        Err(ResponsibilityRefusal::CannotEnforce {
            interface: Interface::VsockSocket,
            mechanism: Mechanism::KernelOptionAbsent,
            reason: Unenforceable::KernelOptionNotPerProcess,
        })
    );
}

#[test]
fn failures_are_attributed_to_the_declared_mechanisms() {
    let profile = strict();
    let io_uring = profile.assignment(Interface::IoUring).unwrap();
    assert_eq!(io_uring.attribute(Errno::EPERM), [Mechanism::Seccomp]);
    assert_eq!(
        io_uring.attribute(Errno::ENOSYS),
        [Mechanism::KernelOptionAbsent]
    );
    assert!(io_uring.attribute(Errno::EINVAL).is_empty());
    assert_eq!(io_uring.expected_failures(), [Errno::EPERM, Errno::ENOSYS]);

    let kexec = profile.assignment(Interface::Kexec).unwrap();
    assert_eq!(
        kexec.attribute(Errno::EPERM),
        [Mechanism::Seccomp, Mechanism::CapabilityAbsence]
    );
    let paths = profile.assignment(Interface::ProtectedPathWrite).unwrap();
    assert_eq!(paths.attribute(Errno::EROFS), [Mechanism::ReadOnlyMount]);
    assert_eq!(
        paths.attribute(Errno::EACCES),
        [Mechanism::NamespaceCredentials]
    );
    assert_eq!(paths.expected_failures(), [Errno::EACCES, Errno::EROFS]);
}

#[test]
fn the_responsibility_map_separates_seccomp_from_path_and_target_rules() {
    for workload in WorkloadProfile::ALL {
        let profile = builtin(workload);
        let map = profile.responsibilities();
        for responsibility in map.responsibilities(Mechanism::Seccomp) {
            assert!(SYSCALL_RULES.contains(&responsibility.interface));
            assert_eq!(responsibility.failures, [Errno::EPERM]);
        }
        let lsm = map.interfaces_of(Mechanism::Lsm);
        assert!(lsm.iter().all(|interface| matches!(
            interface,
            Interface::Ptrace | Interface::PtraceOtherUsers | Interface::ProtectedPathWrite
        )));
        for entry in profile.forbidden() {
            let primary = map.responsibilities(entry.primary);
            assert!(primary
                .iter()
                .any(|r| r.interface == entry.interface && r.role == Role::Primary));
            if let Some(backup) = entry.backup {
                assert!(map
                    .responsibilities(backup)
                    .iter()
                    .any(|r| r.interface == entry.interface && r.role == Role::Backup));
            }
        }
        assert_eq!(map.mechanisms(), profile.mechanisms());
    }

    let map = strict().responsibilities();
    assert_eq!(
        map.interfaces_of(Mechanism::KernelOptionAbsent),
        BTreeSet::from([Interface::IoUring])
    );
    assert_eq!(
        map.interfaces_of(Mechanism::ReadOnlyMount),
        BTreeSet::from([Interface::ProtectedPathWrite])
    );
    assert_eq!(
        map.interfaces_of(Mechanism::NamespaceCredentials),
        BTreeSet::from([Interface::ProtectedPathWrite])
    );
    assert_eq!(
        developer().responsibilities().interfaces_of(Mechanism::Lsm),
        BTreeSet::from([Interface::PtraceOtherUsers])
    );
    let json = serde_json::to_value(&map).unwrap();
    assert!(json["entries"]["seccomp"].is_array());
    assert!(json["entries"]["read_only_mount"][0]["failures"] == serde_json::json!([30]));
}

#[test]
fn errnos_are_numbers_within_the_kernel_range() {
    assert_eq!(serde_json::to_string(&Errno::EROFS).unwrap(), "30");
    assert_eq!(serde_json::from_str::<Errno>("38").unwrap(), Errno::ENOSYS);
    assert!(serde_json::from_str::<Errno>("0").is_err());
    assert!(serde_json::from_str::<Errno>("4096").is_err());
    assert!(serde_json::from_str::<Errno>("\"EPERM\"").is_err());
    assert_eq!(Errno::new(0), Err(ErrnoRefusal { number: 0 }));
    assert_eq!(Errno::EACCES.to_string(), "EACCES (13)");
    assert_eq!(Errno::new(200).unwrap().to_string(), "errno 200");
}
