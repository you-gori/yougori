//! The M07B gaps: `/proc/<pid>/mem` whenever ptrace is refused (Yama and the boot checks),
//! the Landlock grant rule when compiling and when reading, and the repository protection
//! with its pins and git configuration (VM-W07; VM-CP-05; §3.4; §4.6).

use super::*;
use crate::sandbox_contract::confinement::{Errno, ProfileRefusal, REPOSITORY_PROTECTION};

/// What reading `policy`'s body, edited by `edit` and re-sealed, refuses for.
fn reread(
    policy: &GuestPolicy,
    edit: impl FnOnce(&mut GuestPolicyBody),
) -> Result<GuestPolicy, PolicyReadRefusal> {
    let mut body = policy.body().clone();
    edit(&mut body);
    GuestPolicy::from_json(&resealed(body))
}

fn broken(policy: &GuestPolicy, edit: impl FnOnce(&mut GuestPolicyBody)) -> PolicyInvariant {
    match reread(policy, edit) {
        Err(PolicyReadRefusal::Invariant(invariant)) => invariant,
        other => panic!("not an invariant: {other:?}"),
    }
}

fn strict_policy() -> GuestPolicy {
    compiled(&builtin(WorkloadProfile::StrictTool))
}

/// The service profile protecting the repository by `primary` and `backup`.
fn service_protecting(
    paths: &[&str],
    primary: Mechanism,
    backup: Option<Mechanism>,
) -> ConfinementProfile {
    let mut document = builtin(WorkloadProfile::Service).document().clone();
    document.protected_paths = paths
        .iter()
        .map(|text| ProtectedPath::parse(text).unwrap())
        .collect();
    document.forbidden.push(ForbiddenInterface {
        interface: Interface::ProtectedPathWrite,
        primary,
        backup,
    });
    ConfinementProfile::new(document).unwrap()
}

fn landlock_of(policy: &GuestPolicy) -> LandlockRuleset {
    policy.body().lsm.landlock.clone().unwrap()
}

fn yama_checks(scope: YamaPtraceScope) -> Vec<BootCheck> {
    let mut checks = vec![
        BootCheck::YamaActive,
        BootCheck::YamaScopeReadsBack { scope },
    ];
    if scope == YamaPtraceScope::AdminOnly {
        checks.push(BootCheck::ProcessMemoryRefused {
            target: ProcessMemoryTarget::ChildItStarted,
            errno: Errno::EACCES,
        });
    }
    checks.push(BootCheck::ProcessMemoryRefused {
        target: ProcessMemoryTarget::UnrelatedProcessOfItsUid,
        errno: Errno::EACCES,
    });
    checks
}

// ---------------------------------------------------------------- (a) /proc/<pid>/mem

#[test]
fn whenever_ptrace_is_refused_yama_closes_proc_pid_mem_and_the_guest_verifies_it_at_boot() {
    for profile in profiles() {
        let policy = compiled(&profile);
        let yama = policy.body().lsm.yama.map(|policy| policy.ptrace_scope);
        let expected = match (
            profile.assignment(Interface::Ptrace),
            profile.assignment(Interface::PtraceOtherUsers),
        ) {
            (Some(_), _) => Some(YamaPtraceScope::AdminOnly),
            (None, Some(entry)) if entry.uses(Mechanism::Lsm) => Some(YamaPtraceScope::Relational),
            (None, _) => None,
        };
        assert_eq!(yama, expected, "{}", profile.workload());
        let checks = &policy.body().boot_checks;
        match yama {
            Some(scope) => assert!(checks.starts_with(&yama_checks(scope))),
            None => assert!(!checks.contains(&BootCheck::YamaActive)),
        }
    }
    let strict = strict_policy();
    let mut expected = yama_checks(YamaPtraceScope::AdminOnly);
    expected.extend([
        BootCheck::ProtectedPathsMounted,
        BootCheck::RepositoryIsDirectory {
            path: path("/workspace/.git"),
        },
        BootCheck::GitConfigurationAsWritten,
    ]);
    assert_eq!(strict.body().boot_checks, expected);
    assert_eq!(
        compiled(&builtin(WorkloadProfile::Developer))
            .body()
            .boot_checks,
        yama_checks(YamaPtraceScope::Relational)
    );
    // The LSM alone refuses every entry point; nothing about ptrace is left in seccomp.
    let lsm_only = compiled(&service_with_lsm_only_ptrace());
    assert!(!lsm_only.seccomp_interfaces().contains(&Interface::Ptrace));
    assert_eq!(
        lsm_only.body().lsm.yama.unwrap().ptrace_scope,
        YamaPtraceScope::AdminOnly
    );
    assert_eq!(
        ConfinementProfile::new(service_with_seccomp_only_ptrace()),
        Err(ProfileRefusal::PtraceMemoryNeedsLsm)
    );
    let value = json(&strict);
    assert_eq!(
        value["body"]["boot_checks"][1],
        serde_json::json!({ "check": "yama_scope_reads_back", "scope": 2 })
    );
    assert_eq!(
        value["body"]["boot_checks"][2],
        serde_json::json!({
            "check": "process_memory_refused",
            "target": "child_it_started",
            "errno": 13
        })
    );
}

#[test]
fn a_policy_read_back_keeps_ptrace_on_the_lsm_and_yama_on_the_plan() {
    let strict = strict_policy();
    assert_eq!(
        broken(&strict, |body| body.lsm.yama = None),
        PolicyInvariant::YamaDisagreesWithPlan
    );
    assert_eq!(
        broken(&strict, |body| {
            body.lsm.yama = Some(YamaPolicy {
                ptrace_scope: YamaPtraceScope::Relational,
            });
        }),
        PolicyInvariant::YamaDisagreesWithPlan
    );
    assert_eq!(
        broken(&strict, |body| {
            for step in &mut body.verification {
                if step.interface == Interface::Ptrace {
                    step.mechanisms
                        .retain(|planned| planned.mechanism != Mechanism::Lsm);
                }
            }
            body.lsm.yama = None;
        }),
        PolicyInvariant::PtraceWithoutLsm
    );
    // Dropping ptrace from the plan, seccomp and Yama together still leaves the baseline.
    assert_eq!(
        broken(&strict, |body| {
            body.verification
                .retain(|step| step.interface != Interface::Ptrace);
            body.seccomp
                .refusals
                .retain(|refusal| refusal.interface != Interface::Ptrace);
            body.lsm.yama = None;
        }),
        PolicyInvariant::BaselineInterfaceUnaccounted {
            interface: Interface::Ptrace
        }
    );
    // The boot checks follow Yama.
    assert_eq!(
        broken(&strict, |body| {
            body.boot_checks
                .retain(|check| !matches!(check, BootCheck::ProcessMemoryRefused { .. }));
        }),
        PolicyInvariant::BootChecksNotCompiled
    );
}

// ---------------------------------------------------------------- (b) Landlock grants

#[test]
fn compiling_refuses_a_grant_that_exceeds_the_profile_with_a_typed_refusal() {
    let device = device_with_lsm_path();
    assert_eq!(
        compile(&device, &layout_with(&["/home", "/tmp"])),
        Err(GuestPolicyRefusal::LandlockCannotCarveOut {
            path: path("/home/agent/.profile"),
            granted: path("/home"),
        })
    );
    assert_eq!(
        GuestPolicyRefusal::from(LandlockGrantRefusal::CoversProtectedPath {
            path: path("/a/b"),
            granted: path("/a"),
        }),
        GuestPolicyRefusal::LandlockCannotCarveOut {
            path: path("/a/b"),
            granted: path("/a"),
        }
    );
    assert_eq!(
        GuestPolicyRefusal::from(LandlockGrantRefusal::RefusedPathsDiffer),
        GuestPolicyRefusal::LandlockGrantExceedsProfile {
            refusal: LandlockGrantRefusal::RefusedPathsDiffer
        }
    );
    // Every compiled ruleset passes the rule it was built through.
    for (profile, layout) in [
        (device_with_lsm_path(), layout()),
        (device_with_lsm_path(), device_layout()),
        (device_with_lsm_path_without_no_new_privs(), layout()),
    ] {
        let policy = compile(&profile, &layout).unwrap();
        let protected: Vec<AbsoluteGuestPath> = policy
            .body()
            .protected_paths
            .iter()
            .flat_map(|protection| protection.paths.iter())
            .map(|plan| plan.guest_path.clone())
            .collect();
        assert_eq!(
            landlock_of(&policy).check_grants(&protected, &layout),
            Ok(())
        );
        assert_eq!(landlock_of(&policy).rules, layout_grants(&layout));
    }
}

#[test]
fn the_grant_rule_types_every_way_a_ruleset_can_exceed_its_profile() {
    let policy = compiled(&device_with_lsm_path());
    let base = landlock_of(&policy);
    let protected = [path("/home/agent/.profile")];
    let check = |edit: &dyn Fn(&mut LandlockRuleset), layout: &GuestLayout| {
        let mut ruleset = base.clone();
        edit(&mut ruleset);
        ruleset.check_grants(&protected, layout)
    };
    let plain = layout();
    assert_eq!(
        check(
            &|ruleset| ruleset
                .handled_access_fs
                .retain(|access| *access != LandlockFsAccess::Truncate),
            &plain
        ),
        Err(LandlockGrantRefusal::UnhandledAccess {
            access: LandlockFsAccess::Truncate
        })
    );
    assert_eq!(
        check(
            &|ruleset| ruleset.handled_access_fs.push(LandlockFsAccess::WriteFile),
            &plain
        ),
        Err(LandlockGrantRefusal::HandledAccessNotCanonical)
    );
    assert_eq!(
        check(&|ruleset| ruleset.refused_paths.clear(), &plain),
        Err(LandlockGrantRefusal::RefusedPathsDiffer)
    );
    let home = |grant| LandlockRule {
        path: path("/home/agent"),
        grant,
        allowed_access: LandlockFsAccess::WRITE.to_vec(),
    };
    assert_eq!(
        check(
            &|ruleset| ruleset.rules.push(home(LandlockGrant::WritableRoot)),
            &plain
        ),
        Err(LandlockGrantRefusal::UnjustifiedGrant {
            path: path("/home/agent"),
            grant: LandlockGrant::WritableRoot,
        })
    );
    assert_eq!(
        check(
            &|ruleset| {
                for rule in &mut ruleset.rules {
                    if rule.path == path("/tmp") {
                        rule.grant = LandlockGrant::DeclaredDevice;
                    }
                }
            },
            &plain
        ),
        Err(LandlockGrantRefusal::UnjustifiedGrant {
            path: path("/tmp"),
            grant: LandlockGrant::DeclaredDevice,
        })
    );
    assert_eq!(
        check(
            &|ruleset| {
                for rule in &mut ruleset.rules {
                    if rule.path == path("/dev/null") {
                        rule.allowed_access = LandlockFsAccess::WRITE.to_vec();
                    }
                }
            },
            &plain
        ),
        Err(LandlockGrantRefusal::GrantAccessExceeds {
            path: path("/dev/null"),
            access: LandlockFsAccess::RemoveDir,
        })
    );
    // A layout whose grant covers the protected path: justified, and still refused.
    let widened = layout_with(&["/home/agent", "/tmp"]);
    assert_eq!(
        check(
            &|ruleset| ruleset.rules = layout_grants(&layout_with(&["/home/agent", "/tmp"])),
            &widened
        ),
        Err(LandlockGrantRefusal::CoversProtectedPath {
            path: path("/home/agent/.profile"),
            granted: path("/home/agent"),
        })
    );
    // Narrower or reordered lists allow nothing more, but are not the compiled form.
    let narrower: Vec<Box<dyn Fn(&mut LandlockRuleset)>> = vec![
        Box::new(|ruleset| {
            ruleset.rules.pop();
        }),
        Box::new(|ruleset| ruleset.rules.reverse()),
        Box::new(|ruleset| {
            for rule in &mut ruleset.rules {
                if rule.path == path("/tmp") {
                    rule.allowed_access = LandlockFsAccess::FILE.to_vec();
                }
            }
        }),
    ];
    for edit in &narrower {
        assert_eq!(
            check(edit.as_ref(), &plain),
            Err(LandlockGrantRefusal::GrantsNotCanonical)
        );
    }
    assert_eq!(check(&|_| {}, &plain), Ok(()));
}

#[test]
fn reading_applies_the_grant_rule_without_the_profile() {
    let profile = device_with_lsm_path();
    let policy = compiled(&profile);
    let grant = |body: &mut GuestPolicyBody, root: &str| {
        if let Some(ruleset) = body.lsm.landlock.as_mut() {
            ruleset.rules.push(LandlockRule {
                path: path(root),
                grant: LandlockGrant::WritableRoot,
                allowed_access: LandlockFsAccess::WRITE.to_vec(),
            });
            ruleset.rules.sort_by(|a, b| a.path.cmp(&b.path));
        }
    };
    assert_eq!(
        broken(&policy, |body| grant(body, "/home/agent")),
        PolicyInvariant::LandlockGrant(LandlockGrantRefusal::UnjustifiedGrant {
            path: path("/home/agent"),
            grant: LandlockGrant::WritableRoot,
        })
    );
    // Widening the layout as well makes the grant justified, and it still covers the path.
    assert_eq!(
        broken(&policy, |body| {
            body.layout = layout_with(&["/home/agent", "/tmp", "/workspace"]);
            grant(body, "/home/agent");
        }),
        PolicyInvariant::LandlockGrant(LandlockGrantRefusal::CoversProtectedPath {
            path: path("/home/agent/.profile"),
            granted: path("/home/agent"),
        })
    );
    assert_eq!(
        broken(&policy, |body| {
            if let Some(ruleset) = body.lsm.landlock.as_mut() {
                ruleset
                    .handled_access_fs
                    .retain(|access| *access != LandlockFsAccess::RemoveFile);
            }
        }),
        PolicyInvariant::LandlockGrant(LandlockGrantRefusal::UnhandledAccess {
            access: LandlockFsAccess::RemoveFile
        })
    );
    assert_eq!(
        broken(&policy, |body| {
            if let Some(ruleset) = body.lsm.landlock.as_mut() {
                ruleset.refused_paths.clear();
            }
        }),
        PolicyInvariant::LandlockGrant(LandlockGrantRefusal::RefusedPathsDiffer)
    );
    assert_eq!(
        broken(&policy, |body| body.lsm.landlock = None),
        PolicyInvariant::LandlockDisagreesWithPlan
    );
    let strict = strict_policy();
    assert_eq!(
        broken(&strict, |body| body.lsm.landlock =
            Some(landlock_of(&policy))),
        PolicyInvariant::LandlockDisagreesWithPlan
    );
    // The profile's own check refuses the same edit, untyped, as before.
    let mut body = policy.body().clone();
    body.lsm.landlock = None;
    let unchecked = GuestPolicy::seal(body).unwrap();
    assert_eq!(
        unchecked.check_against(&profile, &layout()),
        Err(PolicyReadRefusal::DiffersFromCompilation)
    );
}

// ---------------------------------------------------------------- (c) repository hooks

#[test]
fn the_strict_policy_protects_the_whole_repository_and_neutralizes_its_git_configuration() {
    let strict = strict_policy();
    let body = strict.body();
    let protection = body.protected_paths.as_ref().unwrap();
    assert_eq!(
        protection.pinned,
        [
            path("/home/agent"),
            path("/home/agent/.config"),
            path("/workspace")
        ]
    );
    assert!(body
        .oci
        .linux
        .readonly_paths
        .contains(&path("/workspace/.git")));
    let repository = body.repository.as_ref().unwrap();
    assert_eq!(
        *repository,
        RepositoryProtection {
            git_dir: path("/workspace/.git"),
            config: path("/workspace/.git/config"),
            kept_keys: KEPT_GIT_CONFIG_KEYS.to_vec(),
            repository_values: vec![
                GitConfigSetting::HooksDisabled,
                GitConfigSetting::FsmonitorOff,
                GitConfigSetting::SubmodulesIgnored,
            ],
            user_config: vec![
                path("/home/agent/.config/git"),
                path("/home/agent/.gitconfig")
            ],
            system_values: vec![
                GitConfigSetting::SafeDirectory {
                    path: path("/workspace")
                },
                GitConfigSetting::BareRepositoryExplicit,
            ],
        }
    );
    let written: Vec<(&str, String)> = repository
        .repository_values
        .iter()
        .chain(&repository.system_values)
        .map(|setting| (setting.key(), setting.value()))
        .collect();
    assert_eq!(
        written,
        [
            ("core.hooksPath", "/dev/null".to_owned()),
            ("core.fsmonitor", "false".to_owned()),
            ("diff.ignoreSubmodules", "all".to_owned()),
            ("safe.directory", "/workspace".to_owned()),
            ("safe.bareRepository", "explicit".to_owned()),
        ]
    );
    // No kept key runs anything, names another file or moves the hooks.
    for key in KEPT_GIT_CONFIG_KEYS {
        let name = key.name().to_ascii_lowercase();
        assert_eq!(serde_json::to_value(key).unwrap(), key.name());
        for hazard in [
            "hook",
            "fsmonitor",
            "include",
            "worktree",
            "editor",
            "pager",
            "command",
            "askpass",
            "helper",
            "filter",
            "attributes",
            "alias",
            "url",
        ] {
            assert!(!name.contains(hazard), "{name}");
        }
    }
    let value = json(&strict);
    assert_eq!(
        value["body"]["repository"]["repository_values"],
        serde_json::json!([
            { "setting": "hooks_disabled" },
            { "setting": "fsmonitor_off" },
            { "setting": "submodules_ignored" }
        ])
    );
    assert_eq!(
        value["body"]["repository"]["kept_keys"][0],
        "core.repositoryFormatVersion"
    );
    // VM-CP-05 probes a write to every path of the repository protection.
    let probed: Vec<String> = strict
        .step(Interface::ProtectedPathWrite)
        .unwrap()
        .verified_by
        .iter()
        .filter_map(|verification| match verification {
            Verification::GuestPathProbe { path } => Some(path.to_text()),
            _ => None,
        })
        .collect();
    for text in REPOSITORY_PROTECTION.iter().chain([&".git/hooks/"]) {
        assert!(probed.iter().any(|path| path == text), "{text}");
    }
}

#[test]
fn pins_and_the_repository_section_follow_v15s_mechanisms() {
    let all = ["~/.config/git/", "~/.gitconfig", ".git/"];
    let credentials = compiled(&service_protecting(
        &all,
        Mechanism::NamespaceCredentials,
        None,
    ));
    let body = credentials.body();
    assert!(body.oci.linux.readonly_paths.is_empty());
    assert_eq!(
        body.protected_paths.as_ref().unwrap().pinned,
        [
            path("/home/agent"),
            path("/home/agent/.config"),
            path("/home/agent/.config/git"),
            path("/home/agent/.gitconfig"),
            path("/workspace"),
            path("/workspace/.git"),
        ]
    );
    assert!(body.repository.as_ref().unwrap().system_values.contains(
        &GitConfigSetting::SafeDirectory {
            path: path("/workspace")
        }
    ));

    let read_only = compiled(&service_protecting(&all, Mechanism::ReadOnlyMount, None));
    let body = read_only.body();
    assert_eq!(
        body.protected_paths.as_ref().unwrap().pinned,
        [
            path("/home/agent"),
            path("/home/agent/.config"),
            path("/workspace")
        ]
    );
    // The workload keeps owning `.git`, so its git needs no safe.directory.
    assert_eq!(
        body.repository.as_ref().unwrap().system_values,
        [GitConfigSetting::BareRepositoryExplicit]
    );

    // The LSM alone refuses the rename itself: nothing pinned, no mount check.
    let landlock = compiled(&device_with_lsm_path());
    assert!(landlock
        .body()
        .protected_paths
        .as_ref()
        .unwrap()
        .pinned
        .is_empty());
    assert!(!landlock
        .body()
        .boot_checks
        .contains(&BootCheck::ProtectedPathsMounted));
    assert!(landlock.body().repository.is_none());

    // Outside the repository: pins, no repository section.
    let config = compiled(&service_protecting(
        &["config/settings/", "~/.profile"],
        Mechanism::ReadOnlyMount,
        None,
    ));
    assert_eq!(
        config.body().protected_paths.as_ref().unwrap().pinned,
        [
            path("/home/agent"),
            path("/workspace"),
            path("/workspace/config")
        ]
    );
    assert!(config.body().repository.is_none());
    for workload in [WorkloadProfile::Developer, WorkloadProfile::Service] {
        let policy = compiled(&builtin(workload));
        assert!(policy.body().protected_paths.is_none());
        assert!(policy.body().repository.is_none());
    }
    assert_eq!(
        pinned_paths(
            &[ProtectedPath::parse("a/b/c/").unwrap()],
            &layout(),
            &[Mechanism::Lsm]
        ),
        Ok(Vec::new())
    );
}

#[test]
fn a_policy_read_back_keeps_the_repository_section_pins_and_boot_checks_as_compiled() {
    let strict = strict_policy();
    assert_eq!(
        broken(&strict, |body| body.repository = None),
        PolicyInvariant::RepositoryNotCompiled
    );
    assert_eq!(
        broken(&strict, |body| {
            if let Some(repository) = body.repository.as_mut() {
                repository
                    .repository_values
                    .retain(|setting| *setting != GitConfigSetting::HooksDisabled);
            }
        }),
        PolicyInvariant::RepositoryNotCompiled
    );
    assert_eq!(
        broken(&strict, |body| {
            if let Some(repository) = body.repository.as_mut() {
                repository.user_config.clear();
            }
        }),
        PolicyInvariant::RepositoryNotCompiled
    );
    assert_eq!(
        broken(&strict, |body| {
            if let Some(protection) = body.protected_paths.as_mut() {
                protection.pinned.retain(|pin| *pin != path("/workspace"));
            }
        }),
        PolicyInvariant::PinsNotCompiled
    );
    assert_eq!(
        broken(&strict, |body| body.boot_checks.clear()),
        PolicyInvariant::BootChecksNotCompiled
    );
    assert_eq!(
        broken(&strict, |body| {
            if let Some(protection) = body.protected_paths.as_mut() {
                protection
                    .paths
                    .retain(|plan| plan.path.to_text() != "~/.gitconfig");
            }
        }),
        PolicyInvariant::RepositoryProtectionIncomplete {
            path: "~/.gitconfig"
        }
    );
    // Unknown fields and values outside the closed sets of the new sections.
    let malformed = |pointer: &str, replacement: Option<serde_json::Value>| {
        let mut value = json(&strict);
        let target = value.pointer_mut(pointer).unwrap();
        match replacement {
            Some(replacement) => *target = replacement,
            None => {
                target
                    .as_object_mut()
                    .unwrap()
                    .insert("extra".into(), 1.into());
            }
        }
        matches!(
            GuestPolicy::from_json(&serde_json::to_string(&value).unwrap()),
            Err(PolicyReadRefusal::Malformed { .. })
        )
    };
    for pointer in [
        "/body/repository",
        "/body/repository/repository_values/0",
        "/body/repository/system_values/0",
        "/body/boot_checks/0",
        "/body/boot_checks/1",
        "/body/protected_paths",
    ] {
        assert!(malformed(pointer, None), "{pointer}");
    }
    for (pointer, replacement) in [
        ("/body/repository/kept_keys/0", "core.hooksPath"),
        ("/body/repository/kept_keys/0", "include.path"),
        ("/body/repository/repository_values/0/setting", "hooks_path"),
        ("/body/boot_checks/0/check", "trust_me"),
        ("/body/boot_checks/2/target", "self"),
        ("/body/protected_paths/pinned/0", "relative"),
    ] {
        assert!(
            malformed(pointer, Some(replacement.into())),
            "{pointer} = {replacement}"
        );
    }
}

#[test]
fn every_policy_still_compiles_reads_back_and_checks_against_its_profile() {
    let mut variants = profiles();
    variants.push(service_protecting(
        &["~/.config/git/", "~/.gitconfig", ".git/"],
        Mechanism::ReadOnlyMount,
        Some(Mechanism::NamespaceCredentials),
    ));
    for profile in variants {
        let policy = compiled(&profile);
        let again = GuestPolicy::from_json(&policy.to_json().unwrap()).unwrap();
        assert_eq!(again, policy);
        assert_eq!(again.check_against(&profile, &layout()), Ok(()));
        assert_eq!(
            policy.body().boot_checks,
            BootCheck::for_policy(
                &policy.body().lsm,
                policy.body().protected_paths.as_ref(),
                policy.body().repository.as_ref()
            )
        );
    }
    assert_eq!(GUEST_POLICY_VERSION, 2);
    assert_eq!(GUEST_POLICY_DOMAIN, "yougori/sandbox/guest-policy/v2");
}
