//! The VM-CP-05 evaluator: honest and lying guests, host corroboration against the signed
//! manifest, the positive control, inconclusive results, boot arguments and strict guest
//! input (VM-CP-05; §8.1; §17; §3.4; VM-W09).

use crate::foundation::evidence::SourceClass;

use super::*;

fn outcome(verdict: &ConfinementVerdict, check: &Check) -> CheckOutcome {
    verdict
        .check(check)
        .unwrap_or_else(|| panic!("no {check:?}"))
        .outcome
        .clone()
}

fn failure(verdict: &ConfinementVerdict, check: &Check) -> FailureReason {
    match outcome(verdict, check) {
        CheckOutcome::Failed { reason } => reason,
        other => panic!("{check:?} did not fail: {other:?}"),
    }
}

fn host_checks(verdict: &ConfinementVerdict) -> Vec<&CheckVerdict> {
    verdict
        .checks
        .iter()
        .filter(|check| check.source == SourceClass::HostProbe)
        .collect()
}

fn lockdown_profile() -> ConfinementProfile {
    let mut document = developer().document().clone();
    document
        .kernel_settings
        .push(KernelSetting::LockdownIntegrity);
    ConfinementProfile::new(document).unwrap()
}

fn lockdown_kernel(host_state: Option<OptionState>) -> KernelBuildRecord {
    let mut options = vec![(KernelOption::Modules, OptionState::BuiltIn)];
    if let Some(state) = host_state {
        options.push((KernelOption::LockDownForceIntegrity, state));
    }
    KernelBuildRecord::new(image("kernel-strict"), options).unwrap()
}

#[test]
fn an_honest_guest_with_matching_host_corroboration_passes_the_strict_profile() {
    let profile = strict();
    let guest = report(honest_document(&profile));
    let verdict = evaluate(
        &profile,
        Some(&guest),
        Some(&matching_host()),
        Some(&manifest()),
    );
    assert!(
        verdict.passed(),
        "{:?}",
        verdict.failing().collect::<Vec<_>>()
    );
    assert!(verdict.host_corroborated());
    assert!(verdict.host_corroboration_required);
    assert_eq!(verdict.meaning, VerdictMeaning::InnerControlsDefenseInDepth);
    assert_eq!(verdict.profile, profile.digest());
    // Report, 8 interfaces, 5 paths, capabilities, uid, no_new_privs; 3 host checks and
    // the io_uring option.
    assert_eq!(verdict.checks.len(), 21);
    assert_eq!(host_checks(&verdict).len(), 4);
    assert!(verdict.checks.iter().all(|check| check.required));

    // Seccomp answers first, so the probe sees EPERM; the host record shows the option out.
    assert_eq!(
        outcome(
            &verdict,
            &Check::ForbiddenInterface {
                interface: Interface::IoUring
            }
        ),
        CheckOutcome::RefusedByDeclaredMechanism {
            errno: Errno::EPERM,
            mechanisms: vec![Mechanism::Seccomp],
        }
    );
    assert_eq!(
        outcome(
            &verdict,
            &Check::HostKernelOptionAbsent {
                option: KernelOption::IoUring
            }
        ),
        CheckOutcome::Passed
    );
    let hooks = ProtectedPath::parse(".git/hooks/").unwrap();
    assert_eq!(
        outcome(&verdict, &Check::ProtectedPathWrite { path: hooks }),
        CheckOutcome::RefusedByDeclaredMechanism {
            errno: Errno::EROFS,
            mechanisms: vec![Mechanism::ReadOnlyMount],
        }
    );
    for check in &verdict.checks {
        let host = matches!(
            check.check,
            Check::HostRootImage
                | Check::HostKernelImage
                | Check::HostKernelRecord
                | Check::HostKernelOptionAbsent { .. }
                | Check::KernelSetting { .. }
        );
        let expected = if host {
            SourceClass::HostProbe
        } else {
            SourceClass::GuestReport
        };
        assert_eq!(check.source, expected, "{:?}", check.check);
    }
    assert_eq!(guest.source(), SourceClass::GuestReport);
    assert_eq!(matching_host().source(), SourceClass::HostProbe);
}

#[test]
fn a_guest_report_alone_never_passes_the_strict_profile() {
    let profile = strict();
    let guest = report(honest_document(&profile));
    for (host, manifest, reason) in [
        (
            None,
            Some(manifest()),
            InconclusiveReason::NoHostCorroboration,
        ),
        (Some(matching_host()), None, InconclusiveReason::NoManifest),
    ] {
        let verdict = evaluate(&profile, Some(&guest), host.as_ref(), manifest.as_ref());
        assert!(!verdict.passed());
        assert!(!verdict.host_corroborated());
        let failing: Vec<&CheckVerdict> = verdict.failing().collect();
        assert_eq!(failing.len(), 4);
        for check in failing {
            assert_eq!(check.source, SourceClass::HostProbe);
            assert_eq!(check.outcome, CheckOutcome::Inconclusive { reason });
        }
    }
}

#[test]
fn positive_control_a_test_image_with_io_uring_enabled_fails_the_kernel_record_check() {
    let profile = strict();
    // The guest lies: it reports io_uring missing from its kernel.
    let lying = with_result(
        honest_document(&profile),
        Interface::IoUring,
        failed_with(Errno::ENOSYS),
    );
    let guest = report(lying);
    let test_image = HostCorroboration::host_observed(
        image("root-strict"),
        strict_kernel(image("kernel-with-io-uring"), OptionState::BuiltIn),
        [],
    );
    let verdict = evaluate(&profile, Some(&guest), Some(&test_image), Some(&manifest()));
    assert!(!verdict.passed());
    // The guest's own claim is consistent with a declared mechanism...
    assert!(verdict
        .check(&Check::ForbiddenInterface {
            interface: Interface::IoUring
        })
        .unwrap()
        .passed());
    // ...but the host's record of the booted kernel says otherwise.
    assert_eq!(
        failure(&verdict, &Check::HostKernelRecord),
        FailureReason::KernelRecordDiffers {
            option: KernelOption::IoUring,
            observed: Some(OptionState::BuiltIn),
            expected: OptionState::NotSet,
        }
    );
    assert_eq!(
        failure(
            &verdict,
            &Check::HostKernelOptionAbsent {
                option: KernelOption::IoUring
            }
        ),
        FailureReason::KernelOptionNotAbsent {
            option: KernelOption::IoUring,
            observed: Some(OptionState::BuiltIn),
        }
    );
    assert!(matches!(
        failure(&verdict, &Check::HostKernelImage),
        FailureReason::KernelImageMismatch { .. }
    ));
}

#[test]
fn a_lying_guest_that_reports_everything_passing_fails_on_a_mismatched_root_image() {
    let profile = strict();
    let guest = report(honest_document(&profile));
    let other_root = HostCorroboration::host_observed(
        image("root-tampered"),
        strict_kernel(image("kernel-strict"), OptionState::NotSet),
        [],
    );
    let verdict = evaluate(&profile, Some(&guest), Some(&other_root), Some(&manifest()));
    assert!(!verdict.passed());
    assert_eq!(
        failure(&verdict, &Check::HostRootImage),
        FailureReason::RootImageMismatch {
            observed: image("root-tampered"),
            expected: image("root-strict"),
        }
    );
    assert_eq!(verdict.failing().count(), 1);
}

#[test]
fn the_guests_claims_about_host_facts_are_kept_but_never_consulted() {
    let profile = strict();
    let mut document = honest_document(&profile);
    document.root_image = Some(image("root-strict"));
    document.kernel_options = vec![KernelOptionEntry {
        option: KernelOption::IoUring,
        state: OptionState::NotSet,
    }];
    let guest = report(document);
    assert_eq!(guest.claimed_root_image(), Some(image("root-strict")));
    assert_eq!(
        guest.claimed_kernel_option(KernelOption::IoUring),
        Some(OptionState::NotSet)
    );

    let alone = evaluate(&profile, Some(&guest), None, Some(&manifest()));
    assert!(!alone.passed());
    assert_eq!(
        outcome(&alone, &Check::HostRootImage),
        CheckOutcome::Inconclusive {
            reason: InconclusiveReason::NoHostCorroboration
        }
    );

    let other_root = HostCorroboration::host_observed(
        image("root-tampered"),
        strict_kernel(image("kernel-strict"), OptionState::NotSet),
        [],
    );
    let verdict = evaluate(&profile, Some(&guest), Some(&other_root), Some(&manifest()));
    assert!(matches!(
        failure(&verdict, &Check::HostRootImage),
        FailureReason::RootImageMismatch { observed, .. } if observed == image("root-tampered")
    ));
}

#[test]
fn a_forbidden_interface_passes_only_by_a_declared_mechanisms_errno() {
    let profile = strict();
    let host = matching_host();
    let manifest = manifest();
    let judge = |document: GuestProbeDocument, check: Check| {
        let verdict = evaluate(
            &profile,
            Some(&report(document)),
            Some(&host),
            Some(&manifest),
        );
        assert!(!verdict.passed() || matches!(check, Check::ProtectedPathWrite { .. }));
        outcome(&verdict, &check)
    };

    let einval = with_result(
        honest_document(&profile),
        Interface::IoUring,
        failed_with(Errno::EINVAL),
    );
    assert_eq!(
        judge(
            einval,
            Check::ForbiddenInterface {
                interface: Interface::IoUring
            }
        ),
        CheckOutcome::Failed {
            reason: FailureReason::UnexpectedErrno {
                errno: Errno::EINVAL,
                expected: vec![Errno::EPERM, Errno::ENOSYS],
            }
        }
    );

    // A kernel without AF_VSOCK answers EAFNOSUPPORT, which is not seccomp's EPERM.
    let no_family = with_result(
        honest_document(&profile),
        Interface::VsockSocket,
        failed_with(Errno::EAFNOSUPPORT),
    );
    assert!(matches!(
        judge(
            no_family,
            Check::ForbiddenInterface {
                interface: Interface::VsockSocket
            }
        ),
        CheckOutcome::Failed {
            reason: FailureReason::UnexpectedErrno { .. }
        }
    ));

    // A write to a protected path: EPERM is neither a read-only mount's EROFS nor
    // credential separation's EACCES.
    let bashrc = ProtectedPath::parse("~/.bashrc").unwrap();
    let hooks = ProtectedPath::parse(".git/hooks/").unwrap();
    let mut paths = honest_document(&profile);
    for probe in &mut paths.protected_paths {
        probe.outcome = if probe.path == bashrc {
            failed_with(Errno::EPERM)
        } else {
            failed_with(Errno::EACCES)
        };
    }
    let verdict = evaluate(&profile, Some(&report(paths)), Some(&host), Some(&manifest));
    assert_eq!(
        outcome(&verdict, &Check::ProtectedPathWrite { path: bashrc }),
        CheckOutcome::Failed {
            reason: FailureReason::UnexpectedErrno {
                errno: Errno::EPERM,
                expected: vec![Errno::EACCES, Errno::EROFS],
            }
        }
    );
    assert_eq!(
        outcome(&verdict, &Check::ProtectedPathWrite { path: hooks }),
        CheckOutcome::RefusedByDeclaredMechanism {
            errno: Errno::EACCES,
            mechanisms: vec![Mechanism::NamespaceCredentials],
        }
    );
}

#[test]
fn a_probe_that_succeeds_fails_its_check() {
    let profile = strict();
    let mut document = with_result(
        honest_document(&profile),
        Interface::IoUring,
        ProbeOutcome::Succeeded,
    );
    document.protected_paths[0].outcome = ProbeOutcome::Succeeded;
    let verdict = evaluate(
        &profile,
        Some(&report(document)),
        Some(&matching_host()),
        Some(&manifest()),
    );
    assert!(!verdict.passed());
    assert_eq!(
        failure(
            &verdict,
            &Check::ForbiddenInterface {
                interface: Interface::IoUring
            }
        ),
        FailureReason::InterfaceAvailable
    );
    assert_eq!(verdict.failing().count(), 2);
}

#[test]
fn a_missing_result_is_inconclusive_and_fails_a_required_check() {
    let profile = strict();
    let mut document = honest_document(&profile);
    document
        .interfaces
        .retain(|probe| probe.interface != Interface::VsockSocket);
    document.capabilities = None;
    let verdict = evaluate(
        &profile,
        Some(&report(document)),
        Some(&matching_host()),
        Some(&manifest()),
    );
    assert!(!verdict.passed());
    for check in [
        Check::ForbiddenInterface {
            interface: Interface::VsockSocket,
        },
        Check::CapabilitySet,
    ] {
        let verdict = verdict.check(&check).unwrap();
        assert!(verdict.required);
        assert_eq!(
            verdict.outcome,
            CheckOutcome::Inconclusive {
                reason: InconclusiveReason::NoResult
            }
        );
    }

    let nothing = evaluate(&profile, None, Some(&matching_host()), Some(&manifest()));
    assert!(!nothing.passed());
    for check in nothing
        .checks
        .iter()
        .filter(|check| check.source == SourceClass::GuestReport)
    {
        assert_eq!(
            check.outcome,
            CheckOutcome::Inconclusive {
                reason: InconclusiveReason::NoGuestReport
            }
        );
    }
}

#[test]
fn the_capability_sets_must_equal_the_profile_exactly() {
    let judge = |profile: &ConfinementProfile, sets: ObservedCapabilities| {
        let mut document = honest_document(profile);
        document.capabilities = Some(sets);
        let verdict = evaluate(profile, Some(&report(document)), None, None);
        outcome(&verdict, &Check::CapabilitySet)
    };
    let strict = strict();
    let extra = ObservedCapabilities {
        bounding: vec![LinuxCapability::Kill],
        permitted: Vec::new(),
        effective: Vec::new(),
    };
    assert_eq!(
        judge(&strict, extra),
        CheckOutcome::Failed {
            reason: FailureReason::CapabilitySetDiffers {
                missing: Vec::new(),
                extra: vec![LinuxCapability::Kill],
            }
        }
    );

    let developer = developer();
    let all: Vec<LinuxCapability> = developer.capabilities().into_iter().collect();
    let mut short = all.clone();
    short.retain(|capability| *capability != LinuxCapability::AuditWrite);
    assert_eq!(
        judge(
            &developer,
            ObservedCapabilities {
                bounding: short,
                permitted: Vec::new(),
                effective: Vec::new(),
            }
        ),
        CheckOutcome::Failed {
            reason: FailureReason::CapabilitySetDiffers {
                missing: vec![LinuxCapability::AuditWrite],
                extra: Vec::new(),
            }
        }
    );
    assert_eq!(
        judge(
            &developer,
            ObservedCapabilities {
                bounding: all.clone(),
                permitted: vec![LinuxCapability::NetRaw],
                effective: Vec::new(),
            }
        ),
        CheckOutcome::Failed {
            reason: FailureReason::PermittedOutsideProfile {
                extra: vec![LinuxCapability::NetRaw]
            }
        }
    );
    assert_eq!(
        judge(
            &developer,
            ObservedCapabilities {
                bounding: all.clone(),
                permitted: vec![LinuxCapability::Kill],
                effective: vec![LinuxCapability::Kill, LinuxCapability::Chown],
            }
        ),
        CheckOutcome::Failed {
            reason: FailureReason::EffectiveOutsidePermitted {
                extra: vec![LinuxCapability::Chown]
            }
        }
    );
    assert_eq!(
        judge(
            &developer,
            ObservedCapabilities {
                bounding: all,
                permitted: vec![LinuxCapability::Kill],
                effective: vec![LinuxCapability::Kill],
            }
        ),
        CheckOutcome::Passed
    );
}

#[test]
fn root_a_different_uid_or_missing_no_new_privs_fails() {
    let profile = strict();
    let judge = |document: GuestProbeDocument, check: Check| {
        let verdict = evaluate(&profile, Some(&report(document)), None, None);
        failure(&verdict, &check)
    };
    let mut root = honest_document(&profile);
    root.uid = Some(0);
    assert_eq!(judge(root, Check::NonRootUid), FailureReason::RootUid);
    let mut other = honest_document(&profile);
    other.uid = Some(1001);
    assert_eq!(
        judge(other, Check::NonRootUid),
        FailureReason::UidDiffers { observed: 1001 }
    );
    let mut privs = honest_document(&profile);
    privs.no_new_privs = Some(false);
    assert_eq!(
        judge(privs, Check::NoNewPrivs),
        FailureReason::NoNewPrivsOff
    );
    let mut wrong_profile = honest_document(&profile);
    wrong_profile.profile = developer().digest();
    assert_eq!(
        judge(wrong_profile, Check::ReportProfile),
        FailureReason::ProfileMismatch {
            reported: developer().digest()
        }
    );
}

#[test]
fn a_configured_boot_argument_or_a_guest_claim_never_counts_as_lockdown() {
    let profile = lockdown_profile();
    let setting = Check::KernelSetting {
        setting: KernelSetting::LockdownIntegrity,
    };
    let mut document = honest_document(&profile);
    document.kernel_settings = vec![KernelSetting::LockdownIntegrity];
    let guest = report(document);
    let manifest = |state: Option<OptionState>| ManifestExpectation {
        root_image: image("root-strict"),
        kernel: lockdown_kernel(state),
    };
    let host = |state: Option<OptionState>, boot: bool| {
        let boot_arguments = if boot {
            vec![KernelSetting::LockdownIntegrity]
        } else {
            Vec::new()
        };
        HostCorroboration::host_observed(
            image("root-strict"),
            lockdown_kernel(state),
            boot_arguments,
        )
    };

    let alone = evaluate(&profile, Some(&guest), None, None);
    assert_eq!(
        outcome(&alone, &setting),
        CheckOutcome::Inconclusive {
            reason: InconclusiveReason::NoHostCorroboration
        }
    );
    assert!(!alone.passed());

    let boot_argument = evaluate(
        &profile,
        Some(&guest),
        Some(&host(None, true)),
        Some(&manifest(None)),
    );
    assert_eq!(
        failure(&boot_argument, &setting),
        FailureReason::SettingNotForcedByBuild {
            setting: KernelSetting::LockdownIntegrity,
            boot_argument_configured: true,
            guest_claimed: true,
        }
    );
    assert!(!boot_argument.passed());

    // Forced in the host's record but not promised by the manifest: still refused.
    let unpromised = evaluate(
        &profile,
        Some(&guest),
        Some(&host(Some(OptionState::BuiltIn), false)),
        Some(&manifest(None)),
    );
    assert!(matches!(
        failure(&unpromised, &setting),
        FailureReason::SettingNotForcedByBuild { .. }
    ));

    let forced = evaluate(
        &profile,
        Some(&guest),
        Some(&host(Some(OptionState::BuiltIn), false)),
        Some(&manifest(Some(OptionState::BuiltIn))),
    );
    assert_eq!(outcome(&forced, &setting), CheckOutcome::Passed);
    assert!(
        forced.passed(),
        "{:?}",
        forced.failing().collect::<Vec<_>>()
    );
}

#[test]
fn without_host_corroboration_a_developer_verdict_is_guest_reported_only() {
    let profile = developer();
    let verdict = evaluate(
        &profile,
        Some(&report(honest_document(&profile))),
        None,
        None,
    );
    // Every required check passed, but a guest report is never sufficient alone.
    assert!(!verdict.passed());
    assert_eq!(verdict.outcome, VerdictOutcome::GuestReportedOnly);
    assert!(!verdict.host_corroboration_required);
    assert!(!verdict.host_corroborated());
    for check in &verdict.checks {
        if check.passed() {
            assert_eq!(check.source, SourceClass::GuestReport);
        } else {
            assert!(!check.required);
            assert_eq!(check.source, SourceClass::HostProbe);
        }
    }
    // ptrace of other users' processes is refused by the LSM (Yama: EPERM).
    assert_eq!(
        outcome(
            &verdict,
            &Check::ForbiddenInterface {
                interface: Interface::PtraceOtherUsers
            }
        ),
        CheckOutcome::RefusedByDeclaredMechanism {
            errno: Errno::EPERM,
            mechanisms: vec![Mechanism::Lsm],
        }
    );
}

#[test]
fn host_corroboration_given_for_any_profile_counts() {
    let profile = developer();
    let guest = report(honest_document(&profile));
    let other_root = HostCorroboration::host_observed(
        image("root-tampered"),
        strict_kernel(image("kernel-strict"), OptionState::NotSet),
        [],
    );
    let verdict = evaluate(&profile, Some(&guest), Some(&other_root), Some(&manifest()));
    assert!(!verdict.passed());
    assert!(verdict.check(&Check::HostRootImage).unwrap().required);

    let no_manifest = evaluate(&profile, Some(&guest), Some(&matching_host()), None);
    assert!(!no_manifest.passed());
    assert_eq!(
        outcome(&no_manifest, &Check::HostKernelRecord),
        CheckOutcome::Inconclusive {
            reason: InconclusiveReason::NoManifest
        }
    );

    let matching = evaluate(
        &profile,
        Some(&guest),
        Some(&matching_host()),
        Some(&manifest()),
    );
    assert!(matching.passed());
    assert!(matching.host_corroborated());
}

#[test]
fn guest_report_input_is_strict_bounded_and_never_echoed() {
    let profile = strict();
    let document = honest_document(&profile);
    let text = serde_json::to_string(&document).unwrap();
    assert_eq!(
        serde_json::from_str::<GuestProbeDocument>(&text).unwrap(),
        document
    );
    assert_eq!(
        GuestReport::from_json(&text).unwrap(),
        report(document.clone())
    );

    let mut value = serde_json::to_value(&document).unwrap();
    value["evil\u{202E}field"] = serde_json::json!(true);
    let refusal = GuestReport::from_json(&value.to_string()).unwrap_err();
    assert!(matches!(refusal, GuestReportRefusal::Malformed { .. }));
    assert!(!refusal.to_string().contains("evil"));

    let mut unit_extra = serde_json::to_value(&document).unwrap();
    unit_extra["interfaces"][0]["outcome"] =
        serde_json::json!({"outcome": "succeeded", "errno": 1});
    assert!(GuestReport::from_json(&unit_extra.to_string()).is_err());

    let mut zero = serde_json::to_value(&document).unwrap();
    zero["interfaces"][0]["outcome"] = serde_json::json!({"outcome": "failed", "errno": 0});
    assert!(GuestReport::from_json(&zero.to_string()).is_err());

    let mut twice = document.clone();
    let first = twice.interfaces[0];
    twice.interfaces.push(InterfaceProbe {
        outcome: ProbeOutcome::Succeeded,
        ..first
    });
    assert_eq!(
        GuestReport::receive(twice),
        Err(GuestReportRefusal::Duplicate {
            list: ReportList::Interfaces
        })
    );
    let mut repeated = document.clone();
    repeated.capabilities = Some(ObservedCapabilities {
        bounding: vec![LinuxCapability::Kill, LinuxCapability::Kill],
        permitted: Vec::new(),
        effective: Vec::new(),
    });
    assert_eq!(
        GuestReport::receive(repeated),
        Err(GuestReportRefusal::Duplicate {
            list: ReportList::BoundingCapabilities
        })
    );

    let huge = " ".repeat(MAX_GUEST_REPORT_BYTES + 1);
    assert_eq!(
        GuestReport::from_json(&huge),
        Err(GuestReportRefusal::TooLarge {
            bytes: MAX_GUEST_REPORT_BYTES + 1,
            max: MAX_GUEST_REPORT_BYTES,
        })
    );
}

#[test]
fn manifests_and_build_records_round_trip_and_refuse_duplicates() {
    let manifest = manifest();
    let value = serde_json::to_value(&manifest).unwrap();
    assert_eq!(
        value["kernel"]["options"][0],
        serde_json::json!({"option": "CONFIG_IO_URING", "state": "not_set"})
    );
    let again: ManifestExpectation = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(again, manifest);

    let mut duplicate = value.clone();
    duplicate["kernel"]["options"][1] =
        serde_json::json!({"option": "CONFIG_IO_URING", "state": "built_in"});
    assert!(serde_json::from_value::<ManifestExpectation>(duplicate).is_err());
    let mut unknown = value;
    unknown["kernel"]["signature"] = serde_json::json!("x");
    assert!(serde_json::from_value::<ManifestExpectation>(unknown).is_err());

    assert_eq!(
        KernelBuildRecord::new(
            image("k"),
            [
                (KernelOption::IoUring, OptionState::NotSet),
                (KernelOption::IoUring, OptionState::Module),
            ],
        ),
        Err(KernelRecordRefusal::DuplicateOption {
            option: KernelOption::IoUring
        })
    );
    let record = strict_kernel(image("k"), OptionState::NotSet);
    assert_eq!(record.state(KernelOption::Userfaultfd), None);
    assert!(record
        .state(KernelOption::IoUring)
        .is_some_and(OptionState::is_absent));
    for option in KernelOption::ALL {
        let name = serde_json::to_value(option).unwrap();
        assert_eq!(name, serde_json::json!(option.config_name()));
    }
}

#[test]
fn the_verdict_serializes_its_sources_and_meaning_with_no_score() {
    let profile = strict();
    let verdict = evaluate(
        &profile,
        Some(&report(honest_document(&profile))),
        Some(&matching_host()),
        Some(&manifest()),
    );
    let value = serde_json::to_value(&verdict).unwrap();
    assert_eq!(value["meaning"], "inner_controls_defense_in_depth");
    assert_eq!(value["outcome"], "passed");
    assert_eq!(value["checks"][0]["source"], "guest_report");
    assert_eq!(value["checks"][0]["check"], "report_profile");
    let sources: Vec<&str> = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| check["source"].as_str().unwrap())
        .collect();
    assert!(sources.contains(&"host_probe"));
    let mut found = Vec::new();
    keys(&value, &mut found);
    for key in found {
        for banned in ["score", "severity", "risk", "probability", "rating"] {
            assert!(!key.contains(banned), "{key}");
        }
    }
}
