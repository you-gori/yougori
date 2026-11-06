//! The M07B rules: a forbidden ptrace needs the LSM because seccomp cannot refuse opening
//! `/proc/<pid>/mem`, and protecting anything in the workspace repository needs the whole
//! repository protection (VM-W07; VM-CP-05; §3.4; §4.6).

use super::*;

/// `workload`'s built-in document with ptrace refused by `mechanisms` instead.
fn ptrace_by(
    workload: WorkloadProfile,
    primary: Mechanism,
    backup: Option<Mechanism>,
) -> ProfileDocument {
    let mut document = without(builtin(workload).document().clone(), Interface::Ptrace);
    document.forbidden.push(ForbiddenInterface {
        interface: Interface::Ptrace,
        primary,
        backup,
    });
    document
}

/// The service document with `paths` protected by a read-only mount.
fn service_protecting(paths: &[&str]) -> ProfileDocument {
    let mut document = builtin(WorkloadProfile::Service).document().clone();
    document.protected_paths = paths
        .iter()
        .map(|text| ProtectedPath::parse(text).unwrap())
        .collect();
    document.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::ReadOnlyMount,
    ));
    document
}

#[test]
fn ptrace_forbidden_by_seccomp_alone_is_refused_because_proc_pid_mem_stays_open() {
    for workload in [
        WorkloadProfile::StrictTool,
        WorkloadProfile::Service,
        WorkloadProfile::Device,
    ] {
        assert_eq!(
            refused(ptrace_by(workload, Mechanism::Seccomp, None)),
            ProfileRefusal::PtraceMemoryNeedsLsm,
            "{workload}"
        );
        // The LSM alone, or behind seccomp, covers the procfs open.
        for (primary, backup) in [
            (Mechanism::Lsm, None),
            (Mechanism::Seccomp, Some(Mechanism::Lsm)),
            (Mechanism::Lsm, Some(Mechanism::Seccomp)),
        ] {
            assert!(
                ConfinementProfile::new(ptrace_by(workload, primary, backup)).is_ok(),
                "{workload} {primary} {backup:?}"
            );
        }
        let profile = builtin(workload);
        assert!(profile
            .assignment(Interface::Ptrace)
            .unwrap()
            .uses(Mechanism::Lsm));
    }
    // An excepted ptrace has no entry to check; its own-user rule never rests on seccomp.
    let developer = developer();
    assert!(developer.assignment(Interface::Ptrace).is_none());
    assert_eq!(
        enforcement(Mechanism::Seccomp, Interface::PtraceOtherUsers),
        Enforcement::CannotEnforce(Unenforceable::SeccompCannotInspectTarget)
    );
    for mechanism in [
        Mechanism::CapabilityAbsence,
        Mechanism::Lsm,
        Mechanism::NamespaceCredentials,
    ] {
        assert!(matches!(
            enforcement(mechanism, Interface::PtraceOtherUsers),
            Enforcement::Enforces(_)
        ));
    }
    assert!(ProfileRefusal::PtraceMemoryNeedsLsm
        .to_string()
        .contains("/proc/<pid>/mem"));
}

#[test]
fn the_repository_protection_is_fixed_and_only_the_workspace_repository_triggers_it() {
    let paths: Vec<ProtectedPath> = REPOSITORY_PROTECTION
        .iter()
        .map(|text| ProtectedPath::parse(text).unwrap())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "listed in ProtectedPath order");
    let kinds: Vec<bool> = paths.iter().map(ProtectedPath::is_directory).collect();
    assert_eq!(kinds, [true, false, true]);
    for (text, inside) in [
        (".git/", true),
        (".git/hooks/", true),
        (".git", true),
        (".git/config", true),
        (".gitignore", false),
        (".github/workflows/", false),
        ("src/.git/", false),
        ("~/.git/", false),
        ("~/.gitconfig", false),
    ] {
        assert_eq!(
            ProtectedPath::parse(text).unwrap().in_repository(),
            inside,
            "{text}"
        );
    }
    let strict = strict();
    for path in &paths {
        assert!(strict.protected_paths().contains(path), "{path}");
    }
}

#[test]
fn protecting_part_of_the_repository_needs_all_of_the_repository_protection() {
    // The review's sidestep: `.git/hooks/` read-only, `.git` and its config writable.
    assert_eq!(
        refused(service_protecting(&[".git/hooks/"])),
        ProfileRefusal::RepositoryProtectionIncomplete {
            path: ProtectedPath::parse("~/.config/git/").unwrap()
        }
    );
    for missing in REPOSITORY_PROTECTION {
        let mut document = strict().document().clone();
        document
            .protected_paths
            .retain(|path| path.to_text() != missing);
        assert_eq!(
            refused(document),
            ProfileRefusal::RepositoryProtectionIncomplete {
                path: ProtectedPath::parse(missing).unwrap()
            },
            "{missing}"
        );
    }
    let complete = service_protecting(&[".git/", "~/.gitconfig", "~/.config/git/"]);
    assert!(ConfinementProfile::new(complete).is_ok());
    // Paths outside the repository need nothing more.
    assert!(ConfinementProfile::new(service_protecting(&["config/", "~/.profile"])).is_ok());
}

#[test]
fn a_capability_that_defeats_root_ownership_refuses_the_repository_protection() {
    let mut document = developer().document().clone();
    document.protected_paths = REPOSITORY_PROTECTION
        .iter()
        .map(|text| ProtectedPath::parse(text).unwrap())
        .collect();
    document.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::ReadOnlyMount,
    ));
    assert_eq!(
        refused(document.clone()),
        ProfileRefusal::RepositoryProtectionDefeatedByCapability {
            capability: LinuxCapability::DacOverride
        }
    );
    // The same paths outside the repository are a plain read-only mount V15 accepts.
    document
        .protected_paths
        .retain(|path| !path.in_repository());
    assert!(ConfinementProfile::new(document).is_ok());
    assert!(Mechanism::NamespaceCredentials
        .defeating_capabilities(Interface::ProtectedPathWrite)
        .contains(&LinuxCapability::Setuid));
}
