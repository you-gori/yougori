//! Workload profiles: the built-ins, identity, strict reading, bounded text, exceptions,
//! capabilities, tools and protected paths (VM-W07; VM-R65, VM-R66; VM-CP-05; §3.4).

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use super::*;

/// The developer document with a `perf` tool and an exception for it (VM-R57 "explicit
/// supported exceptions").
fn developer_with_perf(reason: &str, owner: &str) -> ProfileDocument {
    let mut document = without(developer().document().clone(), Interface::PerfEventOpen);
    document
        .required_tools
        .push(tool_needing("perf", &[Interface::PerfEventOpen]));
    document.exceptions.push(ConfinementException {
        target: interface_target(Interface::PerfEventOpen),
        tool: tool_name("perf"),
        reason: RecordedReason::new(reason).unwrap(),
        owner: OwnerName::new(owner).unwrap(),
    });
    document
}

#[test]
fn every_builtin_profile_validates_and_round_trips_with_the_same_identity() {
    let mut digests = BTreeSet::new();
    for workload in WorkloadProfile::ALL {
        let profile = builtin(workload);
        assert_eq!(profile.workload(), workload);
        assert!(profile.no_new_privs());
        assert!(!profile.uid().admits(0));
        let text = serde_json::to_string(&profile).unwrap();
        let again: ConfinementProfile = serde_json::from_str(&text).unwrap();
        assert_eq!(again, profile);
        assert_eq!(again.digest(), profile.digest());
        digests.insert(profile.digest());
    }
    assert_eq!(digests.len(), WorkloadProfile::ALL.len());
}

#[test]
fn reading_normalizes_order_so_one_profile_has_one_identity() {
    let profile = strict();
    let mut document = profile.document().clone();
    document.forbidden.reverse();
    document.required_tools.reverse();
    document.protected_paths.reverse();
    let again = ConfinementProfile::new(document).unwrap();
    assert_eq!(again, profile);
    assert_eq!(again.digest(), profile.digest());
}

#[test]
fn the_strict_profile_is_vm_cp_05s_and_the_developer_profile_keeps_todays_capabilities() {
    let profile = strict();
    assert!(profile.capabilities().is_empty());
    let thousand = NonZeroU32::new(1000).unwrap();
    assert_eq!(
        profile.uid(),
        UidPolicy::Fixed {
            uid: thousand,
            gid: thousand
        }
    );
    let io_uring = profile.assignment(Interface::IoUring).unwrap();
    assert_eq!(io_uring.primary, Mechanism::KernelOptionAbsent);
    assert_eq!(io_uring.backup, Some(Mechanism::Seccomp));
    assert_eq!(
        profile.required_absent_options(),
        BTreeSet::from([KernelOption::IoUring])
    );
    let paths: Vec<String> = profile
        .protected_paths()
        .iter()
        .map(ProtectedPath::to_text)
        .collect();
    assert_eq!(
        paths,
        [
            "~/.bashrc",
            "~/.config/git/",
            "~/.gitconfig",
            ".git/",
            ".git/hooks/"
        ]
    );
    assert!(profile.requires_host_corroboration());
    assert!(profile.exceptions().is_empty());
    for interface in WorkloadProfile::StrictTool.baseline_forbidden() {
        assert!(profile.assignment(interface).is_some(), "{interface}");
    }

    // appliance/agent/container_security.go, containerCapabilities.
    let names: Vec<&str> = developer()
        .capabilities()
        .into_iter()
        .map(LinuxCapability::kernel_name)
        .collect();
    assert_eq!(
        names,
        [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_AUDIT_WRITE",
            "CAP_SETFCAP",
        ]
    );
    assert!(!developer().requires_host_corroboration());
}

#[test]
fn every_field_is_part_of_the_identity() {
    type Mutation = fn(&mut ProfileDocument);
    let developer_mutations: [Mutation; 9] = [
        |d| {
            let uid = NonZeroU32::new(1001).unwrap();
            d.uid = UidPolicy::Fixed { uid, gid: uid };
        },
        |d| d.capabilities.retain(|c| *c != LinuxCapability::AuditWrite),
        |d| d.no_new_privs = false,
        |d| {
            for entry in &mut d.forbidden {
                if entry.interface == Interface::Bpf {
                    entry.backup = Some(Mechanism::KernelOptionAbsent);
                }
            }
        },
        |d| d.required_tools.push(plain_tool("cargo")),
        |d| {
            for tool in &mut d.required_tools {
                tool.interfaces.clear();
            }
        },
        |d| {
            for tool in &mut d.required_tools {
                if tool.name.as_str() == "make" {
                    tool.capabilities.push(LinuxCapability::Kill);
                }
            }
        },
        |d| d.kernel_settings.push(KernelSetting::LockdownIntegrity),
        |d| {
            d.forbidden.push(ForbiddenInterface::with_backup(
                Interface::Ptrace,
                Mechanism::Seccomp,
                Mechanism::Lsm,
            ))
        },
    ];
    let base = developer();
    let mut seen = BTreeSet::from([base.digest()]);
    for mutate in developer_mutations {
        let mut document = base.document().clone();
        mutate(&mut document);
        if document
            .forbidden
            .iter()
            .any(|entry| entry.interface == Interface::Ptrace)
        {
            // gdb needs ptrace; the forbidding variant drops the tool.
            document
                .required_tools
                .retain(|tool| tool.name.as_str() != "gdb");
        }
        let profile = ConfinementProfile::new(document).unwrap();
        assert!(
            seen.insert(profile.digest()),
            "a mutation kept the identity"
        );
    }

    let mut paths = strict().document().clone();
    paths
        .protected_paths
        .push(ProtectedPath::parse("~/.profile").unwrap());
    assert_ne!(
        ConfinementProfile::new(paths).unwrap().digest(),
        strict().digest()
    );
}

#[test]
fn an_exception_is_a_new_identity_never_a_silent_re_enable() {
    // Dropping a baseline interface without a recorded exception is refused.
    let silent = without(developer().document().clone(), Interface::PerfEventOpen);
    assert_eq!(
        refused(silent),
        ProfileRefusal::BaselineInterfaceUnaccounted {
            workload: WorkloadProfile::Developer,
            interface: Interface::PerfEventOpen,
        }
    );
    // A tool that needs a forbidden interface does not work, so it is refused.
    let mut broken = developer().document().clone();
    broken
        .required_tools
        .push(tool_needing("perf", &[Interface::PerfEventOpen]));
    assert_eq!(
        refused(broken),
        ProfileRefusal::ToolNeedsForbiddenInterface {
            tool: tool_name("perf"),
            interface: Interface::PerfEventOpen,
        }
    );

    let excepted = ConfinementProfile::new(developer_with_perf("profiling", "team-a")).unwrap();
    assert_ne!(excepted.digest(), developer().digest());
    assert!(excepted.assignment(Interface::PerfEventOpen).is_none());
    let other_reason = ConfinementProfile::new(developer_with_perf("benchmarks", "team-a"));
    let other_owner = ConfinementProfile::new(developer_with_perf("profiling", "team-b"));
    assert_ne!(other_reason.unwrap().digest(), excepted.digest());
    assert_ne!(other_owner.unwrap().digest(), excepted.digest());

    // Forbidding and excepting the same interface is contradictory.
    let mut both = developer_with_perf("profiling", "team-a");
    both.forbidden.push(ForbiddenInterface::new(
        Interface::PerfEventOpen,
        Mechanism::Seccomp,
    ));
    assert_eq!(
        refused(both),
        ProfileRefusal::ForbiddenAndExcepted {
            interface: Interface::PerfEventOpen
        }
    );
}

#[test]
fn the_strict_profile_admits_no_exception_for_what_vm_cp_05_checks_or_the_brief_lists() {
    for interface in [
        Interface::IoUring,
        Interface::Bpf,
        Interface::Userfaultfd,
        Interface::Kexec,
        Interface::ModuleLoading,
        Interface::VsockSocket,
        Interface::ProtectedPathWrite,
    ] {
        let mut document = without(strict().document().clone(), interface);
        document
            .required_tools
            .push(tool_needing("t", &[interface]));
        document
            .exceptions
            .push(exception(interface_target(interface), "t"));
        assert_eq!(
            refused(document),
            ProfileRefusal::ExceptionNotAdmitted {
                workload: WorkloadProfile::StrictTool,
                target: interface_target(interface),
            },
            "{interface}"
        );
    }
    // No profile admits one for kernel code loading or the workload's AF_VSOCK.
    for workload in WorkloadProfile::ALL {
        for interface in [
            Interface::Kexec,
            Interface::ModuleLoading,
            Interface::VsockSocket,
            Interface::PtraceOtherUsers,
        ] {
            assert!(
                !workload.admits_exception(interface_target(interface)),
                "{workload} {interface}"
            );
        }
    }
    // Nor a capability in the strict profile.
    let mut capability = strict().document().clone();
    capability.capabilities.push(LinuxCapability::Kill);
    capability.required_tools.push(RequiredTool {
        name: tool_name("t"),
        interfaces: Vec::new(),
        capabilities: vec![LinuxCapability::Kill],
    });
    capability
        .exceptions
        .push(exception(capability_target(LinuxCapability::Kill), "t"));
    assert_eq!(
        refused(capability),
        ProfileRefusal::ExceptionNotAdmitted {
            workload: WorkloadProfile::StrictTool,
            target: capability_target(LinuxCapability::Kill),
        }
    );
}

#[test]
fn a_strict_ptrace_exception_still_needs_the_own_user_rule_outside_seccomp() {
    let mut document = without(strict().document().clone(), Interface::Ptrace);
    document
        .required_tools
        .push(tool_needing("debugger", &[Interface::Ptrace]));
    document
        .exceptions
        .push(exception(interface_target(Interface::Ptrace), "debugger"));
    assert_eq!(
        refused(document.clone()),
        ProfileRefusal::PtraceExceptionNeedsOwnUserRule
    );

    let mut by_seccomp = document.clone();
    by_seccomp.forbidden.push(ForbiddenInterface::new(
        Interface::PtraceOtherUsers,
        Mechanism::Seccomp,
    ));
    assert_eq!(
        refused(by_seccomp),
        ProfileRefusal::Responsibility(ResponsibilityRefusal::CannotEnforce {
            interface: Interface::PtraceOtherUsers,
            mechanism: Mechanism::Seccomp,
            reason: Unenforceable::SeccompCannotInspectTarget,
        })
    );

    for mechanism in [Mechanism::NamespaceCredentials, Mechanism::Lsm] {
        let mut accepted = document.clone();
        accepted.forbidden.push(ForbiddenInterface::new(
            Interface::PtraceOtherUsers,
            mechanism,
        ));
        let profile = ConfinementProfile::new(accepted).unwrap();
        assert_ne!(profile.digest(), strict().digest());
    }
}

#[test]
fn exceptions_name_a_required_tool_that_needs_them() {
    let mut unknown = developer_with_perf("profiling", "team-a");
    unknown.exceptions[0].tool = tool_name("ghost");
    assert_eq!(
        refused(unknown),
        ProfileRefusal::ExceptionForUnknownTool {
            tool: tool_name("ghost")
        }
    );

    let mut wrong_tool = developer_with_perf("profiling", "team-a");
    wrong_tool.exceptions[0].tool = tool_name("make");
    assert_eq!(
        refused(wrong_tool),
        ProfileRefusal::ExceptionToolDoesNotNeedTarget {
            tool: tool_name("make"),
            target: interface_target(Interface::PerfEventOpen),
        }
    );

    // A second tool cannot ride on the first tool's exception.
    let mut rider = developer_with_perf("profiling", "team-a");
    rider
        .required_tools
        .push(tool_needing("flamegraph", &[Interface::PerfEventOpen]));
    assert_eq!(
        refused(rider),
        ProfileRefusal::ToolLacksException {
            tool: tool_name("flamegraph"),
            target: interface_target(Interface::PerfEventOpen),
        }
    );

    // Ptrace is not in the developer baseline: an exception for it relaxes nothing.
    let mut needless = developer().document().clone();
    needless
        .exceptions
        .push(exception(interface_target(Interface::Ptrace), "gdb"));
    assert_eq!(
        refused(needless),
        ProfileRefusal::ExceptionNotNeeded {
            target: interface_target(Interface::Ptrace)
        }
    );
}

#[test]
fn capabilities_are_exact_bounded_by_a_ceiling_and_never_contradict_the_profile() {
    let ping = || RequiredTool {
        name: tool_name("ping"),
        interfaces: Vec::new(),
        capabilities: vec![LinuxCapability::NetRaw],
    };

    let mut above = developer().document().clone();
    above.capabilities.push(LinuxCapability::NetRaw);
    above.required_tools.push(ping());
    assert_eq!(
        refused(above.clone()),
        ProfileRefusal::CapabilityAboveCeiling {
            workload: WorkloadProfile::Developer,
            capability: LinuxCapability::NetRaw,
        }
    );
    above.exceptions.push(exception(
        capability_target(LinuxCapability::NetRaw),
        "ping",
    ));
    assert!(ConfinementProfile::new(above).is_ok());

    let mut never = developer().document().clone();
    never.capabilities.push(LinuxCapability::SysAdmin);
    assert_eq!(
        refused(never),
        ProfileRefusal::CapabilityNeverGranted {
            capability: LinuxCapability::SysAdmin
        }
    );

    let mut contradiction = builtin(WorkloadProfile::Service).document().clone();
    contradiction.capabilities.push(LinuxCapability::SysPtrace);
    contradiction.required_tools.push(RequiredTool {
        name: tool_name("tracer"),
        interfaces: Vec::new(),
        capabilities: vec![LinuxCapability::SysPtrace],
    });
    contradiction.exceptions.push(exception(
        capability_target(LinuxCapability::SysPtrace),
        "tracer",
    ));
    assert!(matches!(
        refused(contradiction),
        ProfileRefusal::CapabilityContradictsForbiddenInterface {
            capability: LinuxCapability::SysPtrace,
            ..
        }
    ));

    let mut not_held = developer().document().clone();
    not_held.required_tools.push(ping());
    assert_eq!(
        refused(not_held.clone()),
        ProfileRefusal::ToolNeedsMissingCapability {
            tool: tool_name("ping"),
            capability: LinuxCapability::NetRaw,
        }
    );
    not_held.exceptions.push(exception(
        capability_target(LinuxCapability::NetRaw),
        "ping",
    ));
    assert_eq!(
        refused(not_held),
        ProfileRefusal::ExceptionCapabilityNotHeld {
            capability: LinuxCapability::NetRaw
        }
    );

    assert!(LinuxCapability::ALL
        .iter()
        .enumerate()
        .all(|(index, capability)| usize::from(capability.number()) == index));
}

#[test]
fn the_strict_profile_requires_no_new_privs_and_settings_need_host_evidence() {
    let mut document = strict().document().clone();
    document.no_new_privs = false;
    assert_eq!(
        refused(document),
        ProfileRefusal::NoNewPrivsRequired {
            workload: WorkloadProfile::StrictTool
        }
    );

    let mut securebits = developer().document().clone();
    securebits
        .kernel_settings
        .push(KernelSetting::SecurebitsLocked);
    assert_eq!(
        refused(securebits),
        ProfileRefusal::SettingHasNoHostEvidence {
            setting: KernelSetting::SecurebitsLocked
        }
    );

    let mut lockdown = developer().document().clone();
    lockdown
        .kernel_settings
        .push(KernelSetting::LockdownIntegrity);
    let profile = ConfinementProfile::new(lockdown).unwrap();
    assert!(profile.requires_host_corroboration());
}

#[test]
fn protected_paths_parse_strictly_and_match_their_mechanism() {
    let bashrc = ProtectedPath::parse("~/.bashrc").unwrap();
    assert_eq!(bashrc.root(), PathRoot::Home);
    assert!(!bashrc.is_directory());
    let hooks = ProtectedPath::parse(".git/hooks/").unwrap();
    assert_eq!(hooks.root(), PathRoot::Workspace);
    assert!(hooks.is_directory());
    assert_eq!(hooks.to_text(), ".git/hooks/");

    let long = "a/".repeat(MAX_PATH_COMPONENTS + 1);
    for (text, expected) in [
        ("", PathRefusal::Empty),
        ("/etc/profile", PathRefusal::Absolute),
        ("~root/.bashrc", PathRefusal::TildeForm),
        ("~", PathRefusal::TildeForm),
        ("~/", PathRefusal::NoComponent),
        ("a//b", PathRefusal::EmptyComponent),
        ("./a", PathRefusal::DotComponent),
        (".git/../x", PathRefusal::DotComponent),
        ("a\\b", PathRefusal::Backslash),
        (
            "~/.bash\u{202E}rc",
            PathRefusal::Hazardous {
                character: '\u{202E}',
            },
        ),
        (
            long.as_str(),
            PathRefusal::TooManyComponents {
                count: MAX_PATH_COMPONENTS + 1,
                max: MAX_PATH_COMPONENTS,
            },
        ),
    ] {
        assert_eq!(ProtectedPath::parse(text), Err(expected), "{text:?}");
    }
    let too_long = "x".repeat(MAX_PROTECTED_PATH_BYTES + 1);
    assert!(matches!(
        ProtectedPath::parse(&too_long),
        Err(PathRefusal::TooLong { .. })
    ));

    let mut missing = strict().document().clone();
    missing
        .protected_paths
        .retain(|path| path.to_text() != ".git/hooks/");
    assert_eq!(
        refused(missing),
        ProfileRefusal::MissingProtectedPath { path: hooks }
    );

    let mut no_rule = developer().document().clone();
    no_rule.protected_paths.push(bashrc);
    assert_eq!(
        refused(no_rule.clone()),
        ProfileRefusal::ProtectedPathsWithoutMechanism
    );
    no_rule.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::ReadOnlyMount,
    ));
    assert!(ConfinementProfile::new(no_rule.clone()).is_ok());
    no_rule.protected_paths.clear();
    assert_eq!(
        refused(no_rule),
        ProfileRefusal::ProtectedPathMechanismWithoutPaths
    );
}

#[test]
fn profile_json_is_strict_and_bounded() {
    let base = serde_json::to_value(strict()).unwrap();
    let read = |value: serde_json::Value| serde_json::from_value::<ConfinementProfile>(value);

    let mut extra = base.clone();
    extra["score"] = serde_json::json!(1);
    assert!(read(extra).is_err());

    let mut entry = base.clone();
    entry["forbidden"][0]["note"] = serde_json::json!("x");
    assert!(read(entry).is_err());

    let mut unit_variant = base.clone();
    unit_variant["uid"] = serde_json::json!({"policy": "any_non_root", "uid": 0});
    assert!(read(unit_variant).is_err());

    let mut root = base.clone();
    root["uid"] = serde_json::json!({"policy": "fixed", "uid": 0, "gid": 0});
    assert!(read(root).is_err());

    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("exceptions");
    assert!(read(missing).is_err());

    let mut version = base.clone();
    version["version"] = serde_json::json!(2);
    assert!(read(version).is_err());

    let mut capability_name = base.clone();
    capability_name["capabilities"] = serde_json::json!(["CAP_SYS_ADMIN"]);
    assert!(read(capability_name).is_err());

    let mut document = developer().document().clone();
    document.capabilities.push(LinuxCapability::Kill);
    assert_eq!(
        refused(document),
        ProfileRefusal::Duplicate {
            list: ProfileList::Capabilities
        }
    );
    let mut document = developer().document().clone();
    document.forbidden.push(ForbiddenInterface::new(
        Interface::Bpf,
        Mechanism::KernelOptionAbsent,
    ));
    assert_eq!(
        refused(document),
        ProfileRefusal::Duplicate {
            list: ProfileList::Forbidden
        }
    );
    let mut document = developer_with_perf("profiling", "team-a");
    let mut twin = document.exceptions[0].clone();
    twin.reason = RecordedReason::new("another reason").unwrap();
    document.exceptions.push(twin);
    assert_eq!(
        refused(document),
        ProfileRefusal::Duplicate {
            list: ProfileList::Exceptions
        }
    );
    let mut document = developer().document().clone();
    document.required_tools = (0..=MAX_REQUIRED_TOOLS)
        .map(|index| plain_tool(&format!("tool-{index}")))
        .collect();
    assert_eq!(
        refused(document),
        ProfileRefusal::TooMany {
            list: ProfileList::RequiredTools,
            count: MAX_REQUIRED_TOOLS + 1,
            max: MAX_REQUIRED_TOOLS,
        }
    );
}

#[test]
fn recorded_text_is_bounded_and_refuses_hazardous_characters() {
    assert_eq!(RecordedReason::new("   "), Err(TextRefusal::Empty));
    assert_eq!(
        RecordedReason::new("ok\u{202E}evil"),
        Err(TextRefusal::Hazardous {
            character: '\u{202E}'
        })
    );
    assert_eq!(
        RecordedReason::new("line\nbreak"),
        Err(TextRefusal::Hazardous { character: '\n' })
    );
    assert_eq!(
        RecordedReason::new("x".repeat(MAX_REASON_BYTES + 1)),
        Err(TextRefusal::TooLong {
            bytes: MAX_REASON_BYTES + 1,
            max: MAX_REASON_BYTES,
        })
    );
    assert!(matches!(
        OwnerName::new("platform security"),
        Err(TextRefusal::Identifier { .. })
    ));
    assert!(ToolName::new("bin/sh").is_err());

    let mut value = serde_json::to_value(developer_with_perf("profiling", "team-a")).unwrap();
    value["exceptions"][0]["reason"] = serde_json::json!("hidden\u{200B}text");
    assert!(serde_json::from_value::<ProfileDocument>(value).is_err());
}
