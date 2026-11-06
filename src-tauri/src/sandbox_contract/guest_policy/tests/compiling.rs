//! The compiler: determinism, the capability sets, where each forbidden interface lands,
//! the rules behind each interface, required tools, path rules, Landlock and Yama, the
//! integer-argument rules, exceptions and refusals (M07A items 1 to 5 and 7; VM-W07;
//! §3.4).

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use super::*;
use crate::sandbox_contract::confinement::{
    Errno, KernelOption, OwnerName, RecordedReason, UidPolicy, NEVER_GRANTED,
};

fn capability_set(set: &[OciCapability]) -> BTreeSet<LinuxCapability> {
    set.iter()
        .map(|capability| capability.capability())
        .collect()
}

fn id(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

/// The refusal of `interface` in `policy`'s seccomp section.
fn refusal(policy: &GuestPolicy, interface: Interface) -> &SeccompRefusal {
    policy
        .body()
        .seccomp
        .refusals
        .iter()
        .find(|refusal| refusal.interface == interface)
        .unwrap()
}

/// Every system call some rule of `policy`'s seccomp section names.
fn named_syscalls(policy: &GuestPolicy) -> BTreeSet<Syscall> {
    policy
        .body()
        .seccomp
        .refusals
        .iter()
        .flat_map(|refusal| refusal.rules.iter())
        .flat_map(|rule| rule.syscalls.iter().copied())
        .collect()
}

/// The mechanisms whose compiled configuration refuses `interface`, read from the
/// policy alone. Capability absence has nothing of its own: it is the capability sets.
fn placements(policy: &GuestPolicy, interface: Interface) -> BTreeSet<Mechanism> {
    let body = policy.body();
    let mut found = BTreeSet::new();
    if policy.seccomp_interfaces().contains(&interface) {
        found.insert(Mechanism::Seccomp);
    }
    if body.lsm.refuses(interface) {
        found.insert(Mechanism::Lsm);
    }
    if interface == Interface::ProtectedPathWrite {
        if !body.oci.linux.readonly_paths.is_empty() {
            found.insert(Mechanism::ReadOnlyMount);
        }
        if body
            .protected_paths
            .as_ref()
            .is_some_and(|protection| protection.ownership.is_some())
        {
            found.insert(Mechanism::NamespaceCredentials);
        }
    }
    let options = interface.kernel_options();
    if !options.is_empty()
        && options
            .iter()
            .all(|option| body.kernel.absent_options.contains(option))
    {
        found.insert(Mechanism::KernelOptionAbsent);
    }
    found
}

/// What V15 says refuses `interface` in `profile`, as `placements` can see it.
fn expected_placements(profile: &ConfinementProfile, interface: Interface) -> BTreeSet<Mechanism> {
    let mut expected: BTreeSet<Mechanism> = profile
        .assignment(interface)
        .map(|entry| entry.mechanisms())
        .unwrap_or_default()
        .into_iter()
        .filter(|mechanism| *mechanism != Mechanism::CapabilityAbsence)
        .collect();
    // Yama's admin-only scope, which carries an LSM rule for ptrace, refuses every attach,
    // other users' processes included, whether or not V15 lists that rule as well.
    if interface == Interface::PtraceOtherUsers
        && profile
            .assignment(Interface::Ptrace)
            .is_some_and(|entry| entry.uses(Mechanism::Lsm))
    {
        expected.insert(Mechanism::Lsm);
    }
    expected
}

#[test]
fn every_profile_compiles_deterministically_to_one_digest() {
    let mut digests = BTreeSet::new();
    for profile in profiles() {
        let first = compiled(&profile);
        let second = compiled(&profile);
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());
        let mut document = profile.document().clone();
        document.forbidden.reverse();
        document.required_tools.reverse();
        document.protected_paths.reverse();
        let reordered = ConfinementProfile::new(document).unwrap();
        assert_eq!(compiled(&reordered).digest(), first.digest());
        assert_eq!(first.body().profile, profile.digest());
        digests.insert(first.digest());
    }
    assert_eq!(digests.len(), profiles().len());
    let strict = builtin(WorkloadProfile::StrictTool);
    let elsewhere = GuestLayout::new(LayoutDocument {
        home: path("/home/tool"),
        workspace: path("/workspace"),
        writable_roots: vec![path("/workspace"), path("/tmp")],
        device_nodes: Vec::new(),
    })
    .unwrap();
    assert_ne!(
        compile(&strict, &elsewhere).unwrap().digest(),
        compiled(&strict).digest()
    );
}

#[test]
fn the_capability_sets_are_exactly_v15s_in_all_five_and_the_uid_is_v15s() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let process = &policy.body().oci.process;
        for set in process.capabilities.sets() {
            assert_eq!(capability_set(set), profile.capabilities());
            assert_eq!(set.len(), profile.capabilities().len());
            assert!(set.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(set
                .iter()
                .all(|capability| !NEVER_GRANTED.contains(&capability.capability())));
        }
        assert_eq!(process.no_new_privileges, profile.no_new_privs());
        assert_eq!(policy.body().uid, profile.uid());
        match profile.uid() {
            UidPolicy::Fixed { uid, gid } => assert_eq!(process.user, Some(OciUser { uid, gid })),
            UidPolicy::AnyNonRoot => assert_eq!(process.user, None),
        }
    }
    let strict = compiled(&builtin(WorkloadProfile::StrictTool));
    assert!(strict.body().oci.process.capabilities.bounding.is_empty());
    assert_eq!(
        strict.body().oci.process.user,
        Some(OciUser {
            uid: id(1000),
            gid: id(1000)
        })
    );
    let service = compiled(&builtin(WorkloadProfile::Service));
    assert_eq!(
        service.body().oci.process.capabilities.ambient,
        [OciCapability::new(LinuxCapability::NetBindService)]
    );
}

#[test]
fn each_forbidden_interface_lands_on_its_v15_mechanisms_and_nowhere_else() {
    for profile in profiles() {
        let policy = compiled(&profile);
        for interface in Interface::ALL {
            assert_eq!(
                placements(&policy, interface),
                expected_placements(&profile, interface),
                "{} {interface}",
                profile.workload()
            );
            match profile.assignment(interface) {
                Some(entry) => {
                    assert_eq!(
                        policy.step(interface).unwrap().declared(),
                        entry.mechanisms()
                    );
                    if entry.uses(Mechanism::CapabilityAbsence) {
                        let defeating =
                            Mechanism::CapabilityAbsence.defeating_capabilities(interface);
                        for set in policy.body().oci.process.capabilities.sets() {
                            assert!(capability_set(set)
                                .iter()
                                .all(|capability| !defeating.contains(capability)));
                        }
                    }
                }
                None => assert!(policy.step(interface).is_none()),
            }
        }
        let seccomp = profile
            .forbidden()
            .iter()
            .filter(|entry| entry.uses(Mechanism::Seccomp))
            .count();
        assert_eq!(policy.body().seccomp.refusals.len(), seccomp);
        assert_eq!(
            policy.body().kernel.absent_options,
            profile
                .required_absent_options()
                .into_iter()
                .collect::<Vec<_>>()
        );
    }
    let both = compiled(&service_with_both_ptrace_rules());
    assert_eq!(
        both.body().lsm.yama.unwrap().ptrace_scope,
        YamaPtraceScope::AdminOnly
    );
    for interface in [Interface::Ptrace, Interface::PtraceOtherUsers] {
        assert!(placements(&both, interface).contains(&Mechanism::Lsm));
    }
}

#[test]
fn every_seccomp_refusal_holds_every_rule_of_its_interface_and_v15s_errno() {
    for profile in profiles() {
        let policy = compiled(&profile);
        for refusal in &policy.body().seccomp.refusals {
            let rules: Vec<SeccompRule> = seccomp_matches(refusal.interface)
                .iter()
                .copied()
                .map(SeccompRule::of)
                .collect();
            assert!(!rules.is_empty());
            assert_eq!(refusal.rules, rules);
            assert_eq!(refusal.errno, Errno::EPERM);
            for rule in &refusal.rules {
                assert!(rule.syscalls.windows(2).all(|pair| pair[0] < pair[1]));
            }
        }
        assert_eq!(
            policy.body().seccomp.base_filter,
            BaseFilterRequirement::RuntimeDenyByDefault
        );
        assert_eq!(
            policy.body().seccomp.architectures,
            SeccompArchitecture::ALL
        );
    }
    let names: Vec<&str> = Syscall::ALL.iter().map(|syscall| syscall.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "declared in name order");
}

#[test]
fn ptrace_refuses_process_vm_access_and_pidfd_getfd_with_ptrace_itself() {
    // Seccomp alone is refused by V15 since M07B; the LSM behind it is always there.
    assert_eq!(
        ConfinementProfile::new(service_with_seccomp_only_ptrace()),
        Err(crate::sandbox_contract::confinement::ProfileRefusal::PtraceMemoryNeedsLsm)
    );
    let profile = builtin(WorkloadProfile::Service);
    let policy = compiled(&profile);
    assert_eq!(
        policy.body().lsm.yama.unwrap().ptrace_scope,
        YamaPtraceScope::AdminOnly
    );
    assert_eq!(
        refusal(&policy, Interface::Ptrace).rules,
        [SeccompRule {
            syscalls: vec![
                Syscall::PidfdGetfd,
                Syscall::ProcessVmReadv,
                Syscall::ProcessVmWritev,
                Syscall::Ptrace,
            ],
            argument: None,
        }]
    );
    let gdb = [tool_needing("gdb", &[Interface::Ptrace])];
    let quiet = LsmSection {
        yama: None,
        landlock: None,
    };
    assert_eq!(
        compile::check_tools(&gdb, &policy.body().seccomp, &quiet),
        Err(GuestPolicyRefusal::ToolSyscallRefused {
            tool: tool_name("gdb"),
            interface: Interface::Ptrace,
            syscall: Syscall::PidfdGetfd,
        })
    );
    for syscall in [
        Syscall::PidfdGetfd,
        Syscall::ProcessVmReadv,
        Syscall::ProcessVmWritev,
    ] {
        assert!(
            named_syscalls(&compiled(&builtin(WorkloadProfile::StrictTool))).contains(&syscall)
        );
        assert!(
            !named_syscalls(&compiled(&builtin(WorkloadProfile::Developer))).contains(&syscall)
        );
    }
}

#[test]
fn userfaultfd_also_refuses_the_dev_userfaultfd_ioctl() {
    assert_eq!(USERFAULTFD_IOC_NEW, 0xAA00);
    assert_eq!(IOCTL_REQUEST.index, 1);
    for profile in profiles() {
        let policy = compiled(&profile);
        assert_eq!(
            refusal(&policy, Interface::Userfaultfd).rules,
            [
                SeccompRule {
                    syscalls: vec![Syscall::Userfaultfd],
                    argument: None,
                },
                SeccompRule {
                    syscalls: vec![Syscall::Ioctl],
                    argument: Some(ArgumentMatch {
                        index: 1,
                        mask: 0xffff_ffff,
                        value: 0xAA00,
                    }),
                },
            ]
        );
    }
    // The ioctl rule refuses one request, never ioctl as a whole.
    let ioctl_rule = SeccompRule::of(seccomp_matches(Interface::Userfaultfd)[1]);
    let every_ioctl = SeccompRule {
        syscalls: vec![Syscall::Ioctl],
        argument: Some(ArgumentMatch {
            index: 1,
            mask: 0xffff_ffff,
            value: 0x5401,
        }),
    };
    assert_eq!(ioctl_rule.refuses_some_of(&every_ioctl), None);
}

#[test]
fn io_uring_compiles_to_its_three_calls_and_the_strict_profile_also_needs_it_built_out() {
    let strict = compiled(&builtin(WorkloadProfile::StrictTool));
    assert_eq!(
        refusal(&strict, Interface::IoUring).rules,
        [SeccompRule {
            syscalls: vec![
                Syscall::IoUringEnter,
                Syscall::IoUringRegister,
                Syscall::IoUringSetup,
            ],
            argument: None,
        }]
    );
    assert_eq!(strict.body().kernel.absent_options, [KernelOption::IoUring]);
    assert_eq!(
        strict.step(Interface::IoUring).unwrap().declared(),
        [Mechanism::KernelOptionAbsent, Mechanism::Seccomp]
    );
    for workload in [
        WorkloadProfile::Developer,
        WorkloadProfile::Service,
        WorkloadProfile::Device,
    ] {
        let policy = compiled(&builtin(workload));
        assert!(policy.seccomp_interfaces().contains(&Interface::IoUring));
        assert!(policy.body().kernel.absent_options.is_empty());
    }
}

#[test]
fn an_io_uring_exception_is_refused_because_io_uring_sockets_bypass_the_vsock_rule() {
    for workload in [
        WorkloadProfile::Developer,
        WorkloadProfile::Service,
        WorkloadProfile::Device,
    ] {
        let profile = io_uring_excepted(workload);
        assert_eq!(
            profile
                .assignment(Interface::VsockSocket)
                .unwrap()
                .mechanisms(),
            [Mechanism::Seccomp]
        );
        assert_eq!(
            compile(&profile, &layout()),
            Err(GuestPolicyRefusal::InterfaceReopensAnother {
                available: Interface::IoUring,
                operation: "IORING_OP_SOCKET",
                refused: Interface::VsockSocket,
            }),
            "{workload}"
        );
    }
    assert_eq!(
        SECCOMP_BYPASSES,
        [SeccompBypass {
            through: Interface::IoUring,
            operation: "IORING_OP_SOCKET",
            bypassed: Interface::VsockSocket,
        }]
    );
}

#[test]
fn required_tools_system_calls_stay_allowed() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let rules: Vec<&SeccompRule> = policy
            .body()
            .seccomp
            .refusals
            .iter()
            .flat_map(|refusal| refusal.rules.iter())
            .collect();
        for tool in profile.required_tools() {
            for interface in &tool.interfaces {
                for needed in seccomp_matches(*interface) {
                    let needed = SeccompRule::of(*needed);
                    assert!(rules
                        .iter()
                        .all(|rule| rule.refuses_some_of(&needed).is_none()));
                }
                assert!(!policy.body().lsm.refuses(*interface));
            }
        }
    }
    let developer = compiled(&builtin(WorkloadProfile::Developer));
    assert!(!named_syscalls(&developer).contains(&Syscall::Ptrace));
    let gdb = compiled(&service_with_gdb());
    assert!(!named_syscalls(&gdb).contains(&Syscall::Ptrace));
    assert!(!named_syscalls(&gdb).contains(&Syscall::ProcessVmReadv));
    assert_eq!(
        gdb.body().lsm.yama.unwrap().ptrace_scope,
        YamaPtraceScope::Relational
    );
    let perf = compiled(&strict_with_perf());
    assert!(!named_syscalls(&perf).contains(&Syscall::PerfEventOpen));
}

#[test]
fn the_tool_guard_refuses_a_seccomp_rule_a_yama_scope_or_a_landlock_ruleset_a_tool_needs() {
    let strict = compiled(&builtin(WorkloadProfile::StrictTool));
    let gdb = [tool_needing("gdb", &[Interface::Ptrace])];
    let body = strict.body();
    let quiet = LsmSection {
        yama: None,
        landlock: None,
    };
    assert_eq!(
        compile::check_tools(&gdb, &body.seccomp, &quiet),
        Err(GuestPolicyRefusal::ToolSyscallRefused {
            tool: tool_name("gdb"),
            interface: Interface::Ptrace,
            syscall: Syscall::PidfdGetfd,
        })
    );
    let empty = SeccompRestrictions {
        base_filter: BaseFilterRequirement::RuntimeDenyByDefault,
        architectures: SeccompArchitecture::ALL.to_vec(),
        refusals: Vec::new(),
    };
    assert_eq!(
        compile::check_tools(&gdb, &empty, &body.lsm),
        Err(GuestPolicyRefusal::ToolInterfaceRefusedByLsm {
            tool: tool_name("gdb"),
            interface: Interface::Ptrace,
        })
    );
    assert_eq!(compile::check_tools(&gdb, &empty, &quiet), Ok(()));
    let landlock = compiled(&device_with_lsm_path());
    let writer = [tool_needing("writer", &[Interface::ProtectedPathWrite])];
    assert_eq!(
        compile::check_tools(&writer, &empty, &landlock.body().lsm),
        Err(GuestPolicyRefusal::ToolInterfaceRefusedByLsm {
            tool: tool_name("writer"),
            interface: Interface::ProtectedPathWrite,
        })
    );
    assert_eq!(compile::check_tools(&writer, &empty, &quiet), Ok(()));
}

#[test]
fn path_rules_never_appear_in_seccomp() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let interfaces = policy.seccomp_interfaces();
        assert!(!interfaces.contains(&Interface::ProtectedPathWrite));
        assert!(!interfaces.contains(&Interface::PtraceOtherUsers));
        let seccomp = serde_json::to_string(&policy.body().seccomp).unwrap();
        assert!(!seccomp.contains('/'), "{seccomp}");
        for path in profile.protected_paths() {
            assert!(!seccomp.contains(&path.to_text()));
        }
    }
    let strict = compiled(&builtin(WorkloadProfile::StrictTool));
    let body = strict.body();
    assert_eq!(
        body.oci.linux.readonly_paths,
        [
            path("/home/agent/.bashrc"),
            path("/home/agent/.config/git"),
            path("/home/agent/.gitconfig"),
            path("/workspace/.git"),
            path("/workspace/.git/hooks")
        ]
    );
    let protection = body.protected_paths.as_ref().unwrap();
    assert_eq!(
        protection.ownership,
        Some(OwnershipRule::RootOwnedNoGroupOrOtherWrite)
    );
    let kinds: Vec<PathKind> = protection.paths.iter().map(|plan| plan.kind).collect();
    assert_eq!(
        kinds,
        [
            PathKind::File,
            PathKind::Directory,
            PathKind::File,
            PathKind::Directory,
            PathKind::Directory
        ]
    );
    assert!(body.lsm.landlock.is_none());
    for workload in [WorkloadProfile::Developer, WorkloadProfile::Service] {
        let policy = compiled(&builtin(workload));
        assert!(policy.body().oci.linux.readonly_paths.is_empty());
        assert!(policy.body().protected_paths.is_none());
    }
}

#[test]
fn an_lsm_path_rule_becomes_a_landlock_ruleset_and_nothing_in_seccomp() {
    let device = compiled(&builtin(WorkloadProfile::Device));
    let policy = compiled(&device_with_lsm_path());
    let body = policy.body();
    assert_eq!(
        body.seccomp,
        device.body().seccomp,
        "the path rule adds nothing to seccomp"
    );
    assert!(body.oci.linux.readonly_paths.is_empty());
    let landlock = body.lsm.landlock.as_ref().unwrap();
    assert_eq!(landlock.abi, LandlockAbi::CURRENT);
    assert_eq!(landlock.abi.get(), 3);
    assert_eq!(landlock.restriction, LandlockRestriction::NoNewPrivileges);
    assert_eq!(landlock.handled_access_fs, LandlockFsAccess::WRITE);
    assert!(landlock
        .handled_access_fs
        .iter()
        .all(|access| access.minimum_abi() <= LANDLOCK_ABI));
    assert!(landlock
        .handled_access_fs
        .contains(&LandlockFsAccess::Truncate));
    let roots: Vec<&AbsoluteGuestPath> = landlock
        .rules
        .iter()
        .filter(|rule| rule.grant == LandlockGrant::WritableRoot)
        .map(|rule| &rule.path)
        .collect();
    assert_eq!(roots, [&path("/tmp"), &path("/workspace")]);
    assert!(landlock
        .rules
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path));
    assert_eq!(landlock.refused_paths, [path("/home/agent/.profile")]);
    let step = policy.step(Interface::ProtectedPathWrite).unwrap();
    assert_eq!(step.expected_failures, [Errno::EACCES]);
}

#[test]
fn the_device_fixture_keeps_standard_devices_and_its_device_nodes_writable() {
    let policy = compile(&device_with_lsm_path(), &device_layout()).unwrap();
    let landlock = policy.body().lsm.landlock.as_ref().unwrap();
    let grant = |text: &str| {
        landlock
            .rules
            .iter()
            .find(|rule| rule.path == path(text))
            .map(|rule| (rule.grant, rule.allowed_access.clone()))
    };
    let file = LandlockFsAccess::FILE.to_vec();
    let write = LandlockFsAccess::WRITE.to_vec();
    for device in [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
        "/dev/pts",
    ] {
        assert_eq!(
            grant(device),
            Some((LandlockGrant::StandardDevice, file.clone())),
            "{device}"
        );
    }
    assert_eq!(
        grant("/dev/shm"),
        Some((LandlockGrant::StandardDevice, write.clone()))
    );
    for node in [
        "/dev/nvidia0",
        "/dev/nvidiactl",
        "/dev/nvidia-uvm",
        "/dev/dri",
    ] {
        assert_eq!(
            grant(node),
            Some((LandlockGrant::DeclaredDevice, file.clone())),
            "{node}"
        );
    }
    assert_eq!(
        grant("/workspace"),
        Some((LandlockGrant::WritableRoot, write))
    );
    assert_eq!(grant("/home/agent"), None);
    assert_eq!(
        LandlockFsAccess::FILE,
        [LandlockFsAccess::WriteFile, LandlockFsAccess::Truncate]
    );
    for name in STANDARD_DEVICES.iter().chain([&SHARED_MEMORY_DIRECTORY]) {
        assert_eq!(
            AbsoluteGuestPath::parse(&format!("/dev/{name}")).unwrap(),
            path(&format!("/dev/{name}"))
        );
    }
    // The same profile against the plain layout grants the standard devices only.
    let plain = compiled(&device_with_lsm_path());
    let plain = plain.body().lsm.landlock.as_ref().unwrap();
    assert!(plain
        .rules
        .iter()
        .all(|rule| rule.grant != LandlockGrant::DeclaredDevice));
    assert_eq!(plain.rules.len(), STANDARD_DEVICES.len() + 1 + 2);
}

#[test]
fn landlock_without_no_new_privs_records_that_the_runtime_needs_cap_sys_admin() {
    let policy = compiled(&device_with_lsm_path_without_no_new_privs());
    assert!(!policy.body().oci.process.no_new_privileges);
    assert_eq!(
        policy.body().lsm.landlock.as_ref().unwrap().restriction,
        LandlockRestriction::CapSysAdminBeforeCapabilityDrop
    );
    assert!(policy
        .body()
        .oci
        .process
        .capabilities
        .sets()
        .iter()
        .all(|set| !capability_set(set).contains(&LinuxCapability::SysAdmin)));
    let value = json(&policy);
    assert_eq!(
        value["body"]["lsm"]["landlock"]["restriction"],
        "cap_sys_admin_before_capability_drop"
    );
    assert_eq!(
        LandlockRestriction::for_no_new_privs(true),
        LandlockRestriction::NoNewPrivileges
    );
}

#[test]
fn landlock_cannot_carve_a_protected_path_out_of_a_grant() {
    assert_eq!(
        compile(&strict_with_lsm_backup(), &layout()),
        Err(GuestPolicyRefusal::LandlockCannotCarveOut {
            path: path("/workspace/.git"),
            granted: path("/workspace"),
        })
    );
    let device = device_with_lsm_path();
    assert_eq!(
        compile(&device, &layout_with(&["/home/agent", "/tmp"])),
        Err(GuestPolicyRefusal::LandlockCannotCarveOut {
            path: path("/home/agent/.profile"),
            granted: path("/home/agent"),
        })
    );
    assert_eq!(
        compile(&device, &layout_with(&["/home/agent/.profile/cache"])),
        Err(GuestPolicyRefusal::LandlockCannotCarveOut {
            path: path("/home/agent/.profile"),
            granted: path("/home/agent/.profile/cache"),
        })
    );
    let home_in_shm = GuestLayout::new(LayoutDocument {
        home: path("/dev/shm/agent"),
        workspace: path("/workspace"),
        writable_roots: Vec::new(),
        device_nodes: Vec::new(),
    })
    .unwrap();
    assert_eq!(
        compile(&device, &home_in_shm),
        Err(GuestPolicyRefusal::LandlockCannotCarveOut {
            path: path("/dev/shm/agent/.profile"),
            granted: path("/dev/shm"),
        })
    );
    // No writable root: every write but the devices is refused, the protected path too.
    let closed = compile(&device, &layout_with(&[])).unwrap();
    assert!(closed
        .body()
        .lsm
        .landlock
        .as_ref()
        .unwrap()
        .rules
        .iter()
        .all(|rule| rule.grant == LandlockGrant::StandardDevice));
}

#[test]
fn yamas_scope_follows_the_ptrace_rules_v15_hands_to_the_lsm() {
    let scope = |profile: &ConfinementProfile| {
        compiled(profile)
            .body()
            .lsm
            .yama
            .map(|policy| policy.ptrace_scope.value())
    };
    for workload in [
        WorkloadProfile::StrictTool,
        WorkloadProfile::Service,
        WorkloadProfile::Device,
    ] {
        assert_eq!(scope(&builtin(workload)), Some(2), "{workload}");
    }
    assert_eq!(scope(&builtin(WorkloadProfile::Developer)), Some(1));
    assert_eq!(scope(&service_with_gdb()), Some(1));
    assert_eq!(scope(&service_with_both_ptrace_rules()), Some(2));
    assert_eq!(scope(&service_with_lsm_only_ptrace()), Some(2));
    assert!(ConfinementProfile::new(service_with_seccomp_only_ptrace()).is_err());
    assert!(YamaPtraceScope::Relational.refuses(Interface::PtraceOtherUsers));
    assert!(!YamaPtraceScope::Relational.refuses(Interface::Ptrace));
    assert!(YamaPtraceScope::AdminOnly.refuses(Interface::Ptrace));
    assert!(YamaPtraceScope::AdminOnly.refuses(Interface::PtraceOtherUsers));
}

#[test]
fn only_the_vsock_and_userfaultfd_rules_filter_an_argument_and_both_mask_it_to_32_bits() {
    for profile in profiles() {
        let policy = compiled(&profile);
        for refusal in &policy.body().seccomp.refusals {
            for rule in &refusal.rules {
                if let Some(argument) = rule.argument {
                    assert_eq!(argument.mask, 0xffff_ffff);
                    let expected = match rule.syscalls.as_slice() {
                        [Syscall::Socket] => ArgumentMatch::int_equals(SOCKET_DOMAIN, AF_VSOCK),
                        [Syscall::Ioctl] => {
                            ArgumentMatch::int_equals(IOCTL_REQUEST, USERFAULTFD_IOC_NEW)
                        }
                        other => panic!("an argument filter on {other:?}"),
                    };
                    assert_eq!(argument, expected);
                }
            }
        }
        assert_eq!(
            refusal(&policy, Interface::VsockSocket).rules,
            [SeccompRule {
                syscalls: vec![Syscall::Socket],
                argument: Some(ArgumentMatch {
                    index: 0,
                    mask: 0xffff_ffff,
                    value: 40,
                }),
            }]
        );
    }
}

#[test]
fn an_exception_widens_exactly_its_one_interface() {
    let base = compiled(&builtin(WorkloadProfile::StrictTool));
    let perf = compiled(&strict_with_perf());
    let (base_body, perf_body) = (base.body(), perf.body());
    let mut expected = base.seccomp_interfaces();
    expected.remove(&Interface::PerfEventOpen);
    assert_eq!(perf.seccomp_interfaces(), expected);
    let mut refusals = base_body.seccomp.refusals.clone();
    refusals.retain(|refusal| refusal.interface != Interface::PerfEventOpen);
    assert_eq!(perf_body.seccomp.refusals, refusals);
    let mut steps = base_body.verification.clone();
    steps.retain(|step| step.interface != Interface::PerfEventOpen);
    assert_eq!(perf_body.verification, steps);
    assert_eq!(perf_body.oci, base_body.oci);
    assert_eq!(perf_body.lsm, base_body.lsm);
    assert_eq!(perf_body.kernel, base_body.kernel);
    assert_eq!(perf_body.protected_paths, base_body.protected_paths);
    assert!(base_body.exceptions.is_empty());
    assert_eq!(perf_body.exceptions.len(), 1);
    let record = &perf_body.exceptions[0];
    assert_eq!(
        record.exception.reason,
        RecordedReason::new("needed by the pinned toolchain").unwrap()
    );
    assert_eq!(
        record.exception.owner,
        OwnerName::new("platform-security").unwrap()
    );
    assert_eq!(record.exception.tool, tool_name("perf"));
    assert_eq!(
        record.effect,
        ExceptionEffect::InterfaceLeftAvailable {
            rules: vec![SeccompRule {
                syscalls: vec![Syscall::PerfEventOpen],
                argument: None,
            }]
        }
    );
    let gdb = compiled(&service_with_gdb());
    assert_eq!(
        gdb.body().exceptions[0].effect,
        ExceptionEffect::InterfaceLeftAvailable {
            rules: vec![SeccompRule::of(seccomp_matches(Interface::Ptrace)[0])]
        }
    );

    let base = compiled(&builtin(WorkloadProfile::Developer));
    let raw = compiled(&developer_with_net_raw());
    let (base_body, raw_body) = (base.body(), raw.body());
    for (with, without) in raw_body
        .oci
        .process
        .capabilities
        .sets()
        .into_iter()
        .zip(base_body.oci.process.capabilities.sets())
    {
        let added: Vec<LinuxCapability> = capability_set(with)
            .difference(&capability_set(without))
            .copied()
            .collect();
        assert_eq!(added, [LinuxCapability::NetRaw]);
        assert!(capability_set(without).is_subset(&capability_set(with)));
    }
    assert_eq!(raw_body.oci.linux, base_body.oci.linux);
    assert_eq!(raw_body.seccomp, base_body.seccomp);
    assert_eq!(raw_body.verification, base_body.verification);
    assert_eq!(raw_body.lsm, base_body.lsm);
    assert_eq!(
        raw_body.exceptions[0].effect,
        ExceptionEffect::CapabilityInEverySet {
            capability: LinuxCapability::NetRaw
        }
    );
}

#[test]
fn protected_paths_that_collide_or_do_not_resolve_are_refused() {
    let mut document = builtin(WorkloadProfile::Device).document().clone();
    document.protected_paths = vec![
        ProtectedPath::parse("~/.profile").unwrap(),
        ProtectedPath::parse(".profile").unwrap(),
    ];
    document.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::ReadOnlyMount,
    ));
    let profile = ConfinementProfile::new(document).unwrap();
    let shared = GuestLayout::new(LayoutDocument {
        home: path("/work"),
        workspace: path("/work"),
        writable_roots: Vec::new(),
        device_nodes: Vec::new(),
    })
    .unwrap();
    assert_eq!(
        compile(&profile, &shared),
        Err(GuestPolicyRefusal::ProtectedPathsCollide {
            guest_path: path("/work/.profile"),
        })
    );
    let deep: String = (0..MAX_GUEST_PATH_COMPONENTS)
        .map(|index| format!("/d{index}"))
        .collect();
    let deep_home = GuestLayout::new(LayoutDocument {
        home: path(&deep),
        workspace: path("/workspace"),
        writable_roots: Vec::new(),
        device_nodes: Vec::new(),
    })
    .unwrap();
    assert!(matches!(
        compile(&profile, &deep_home),
        Err(GuestPolicyRefusal::UnresolvablePath {
            refusal: GuestPathRefusal::TooManyComponents { .. },
            ..
        })
    ));
    let options = compile(&profile, &layout()).unwrap();
    assert_eq!(
        options.body().oci.linux.readonly_paths,
        [path("/home/agent/.profile"), path("/workspace/.profile")]
    );
}

#[test]
fn guest_paths_and_layouts_are_strict() {
    for (text, refusal) in [
        ("", GuestPathRefusal::Empty),
        ("relative/path", GuestPathRefusal::Relative),
        ("/", GuestPathRefusal::NoComponent),
        ("/a/", GuestPathRefusal::TrailingSlash),
        ("/a//b", GuestPathRefusal::EmptyComponent),
        ("/a/./b", GuestPathRefusal::DotComponent),
        ("/a/../b", GuestPathRefusal::DotComponent),
        ("/a\\b", GuestPathRefusal::Backslash),
        (
            "/a\u{202e}b",
            GuestPathRefusal::Hazardous {
                character: '\u{202e}',
            },
        ),
    ] {
        assert_eq!(AbsoluteGuestPath::parse(text), Err(refusal), "{text:?}");
    }
    let long = format!("/{}", "a".repeat(MAX_GUEST_PATH_BYTES));
    assert!(matches!(
        AbsoluteGuestPath::parse(&long),
        Err(GuestPathRefusal::TooLong { .. })
    ));
    assert_eq!(path("/home/agent").to_text(), "/home/agent");
    assert!(path("/home/agent/.bashrc").is_within(&path("/home/agent")));
    assert!(!path("/home/agentx").is_within(&path("/home/agent")));
    let with = |writable_roots: Vec<AbsoluteGuestPath>, device_nodes: Vec<AbsoluteGuestPath>| {
        GuestLayout::new(LayoutDocument {
            home: path("/home/agent"),
            workspace: path("/workspace"),
            writable_roots,
            device_nodes,
        })
    };
    assert_eq!(
        with(vec![path("/tmp"), path("/tmp")], Vec::new()),
        Err(LayoutRefusal::DuplicateWritableRoot { path: path("/tmp") })
    );
    let many: Vec<AbsoluteGuestPath> = (0..=MAX_WRITABLE_ROOTS)
        .map(|index| path(&format!("/w{index}")))
        .collect();
    assert!(matches!(
        with(many, Vec::new()),
        Err(LayoutRefusal::TooManyWritableRoots { .. })
    ));
    assert_eq!(
        with(Vec::new(), vec![path("/dev/nvidia0"), path("/dev/nvidia0")]),
        Err(LayoutRefusal::DuplicateDeviceNode {
            path: path("/dev/nvidia0")
        })
    );
    for outside in ["/dev", "/opt/dev/nvidia0", "/devices/nvidia0"] {
        assert_eq!(
            with(Vec::new(), vec![path(outside)]),
            Err(LayoutRefusal::DeviceNodeOutsideDev {
                path: path(outside)
            }),
            "{outside}"
        );
    }
    for standard in ["/dev/null", "/dev/shm", "/dev/pts/0"] {
        assert_eq!(
            with(Vec::new(), vec![path(standard)]),
            Err(LayoutRefusal::StandardDevice {
                path: path(standard)
            }),
            "{standard}"
        );
    }
    let devices: Vec<AbsoluteGuestPath> = (0..=MAX_DEVICE_NODES)
        .map(|index| path(&format!("/dev/gpu{index}")))
        .collect();
    assert!(matches!(
        with(Vec::new(), devices),
        Err(LayoutRefusal::TooManyDeviceNodes { .. })
    ));
    assert_eq!(
        device_layout().device_nodes(),
        [
            path("/dev/dri"),
            path("/dev/nvidia-uvm"),
            path("/dev/nvidia0"),
            path("/dev/nvidiactl")
        ]
    );
    let text = r#"{"home":"/home/agent","workspace":"/workspace","writable_roots":[],"device_nodes":[],"extra":1}"#;
    assert!(serde_json::from_str::<GuestLayout>(text).is_err());
    let missing = r#"{"home":"/home/agent","workspace":"/workspace","writable_roots":[]}"#;
    assert!(serde_json::from_str::<GuestLayout>(missing).is_err());
}
