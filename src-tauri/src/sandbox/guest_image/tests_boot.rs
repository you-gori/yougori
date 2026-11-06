//! Tests of the launch boundary, the booted-image check, the host corroboration and the
//! `sandbox::probes` observations, with a VM-CP-23 drill run through [`admit_launch`].

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::{
    ConfigurationFingerprint, ObservationResult, OsKind, ProbeAdapter, SandboxBootSubject,
    SourceClass, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, ContentKey, ExecutionId, SandboxBootGeneration, TenantId};
use crate::sandbox::backend::{
    DeviceExposure, DeviceProfile, LaunchRequest, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::probes::{
    BootedImageMatchesManifestProbe, CheckId, CorroboratingFact, ExpectationId, HostCheckRunner,
    Observed, Part, RunResult, RunnerInconclusive,
};
use crate::sandbox::trust::HexBytes;
use crate::sandbox_contract::confinement::{
    evaluate, Check, HostCorroboration, KernelBuildRecord, KernelOption, KernelSetting,
    ManifestExpectation, OptionState,
};

/// `bytes` with its first byte changed.
fn one_byte_changed(bytes: &[u8]) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    changed
}

#[test]
fn the_boot_set_must_be_exactly_the_signed_artifacts() {
    let release = release();
    let admitted = selected(&release).admit_boot(&boot_set()).unwrap();
    assert_eq!(admitted.artifacts(), boot_set().artifacts());
    assert_eq!(
        admitted.selected().manifest(),
        release.manifest.content_key()
    );
    let record = serde_json::to_value(&admitted).unwrap();
    assert!(record["artifacts"]["root_image"]["content_key"].is_string());

    let changed = one_byte_changed(ROOT_IMAGE);
    assert_eq!(
        selected(&release).admit_boot(
            &boot_set().with(ArtifactRole::RootImage, HostArtifact::of_bytes(&changed))
        ),
        Err(BootRefusal::Differs {
            role: ArtifactRole::RootImage,
            expected: ContentKey::of(ROOT_IMAGE),
            expected_bytes: ROOT_IMAGE.len() as u64,
            found: ContentKey::of(&changed),
            found_bytes: changed.len() as u64,
        })
    );
    // The right key with the wrong length is another artifact too.
    assert!(matches!(
        selected(&release).admit_boot(&boot_set().with(
            ArtifactRole::Kernel,
            HostArtifact::host_observed(ContentKey::of(KERNEL), KERNEL.len() as u64 + 1)
        )),
        Err(BootRefusal::Differs {
            role: ArtifactRole::Kernel,
            ..
        })
    ));
    let without_initrd = BootSet::new()
        .with(ArtifactRole::RootImage, HostArtifact::of_bytes(ROOT_IMAGE))
        .with(ArtifactRole::Kernel, HostArtifact::of_bytes(KERNEL));
    assert_eq!(
        selected(&release).admit_boot(&without_initrd),
        Err(BootRefusal::Missing {
            role: ArtifactRole::Initrd
        })
    );
    assert_eq!(
        selected(&release).admit_boot(
            &boot_set().with(ArtifactRole::Profile, HostArtifact::of_bytes(b"profile"))
        ),
        Err(BootRefusal::Unexpected {
            role: ArtifactRole::Profile
        })
    );
    for refusal in [
        BootRefusal::Missing {
            role: ArtifactRole::Kernel,
        },
        BootRefusal::Unexpected {
            role: ArtifactRole::Firmware,
        },
    ] {
        assert!(!refusal.to_string().is_empty());
    }
}

#[test]
fn the_host_reads_an_artifact_to_its_identity() {
    let large: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    let mut reader: &[u8] = &large;
    assert_eq!(
        HostArtifact::read(&mut reader, large.len() as u64).unwrap(),
        HostArtifact::of_bytes(&large)
    );
    let mut long: &[u8] = KERNEL;
    assert_eq!(
        HostArtifact::read(&mut long, 4),
        Err(ReadError::Length {
            declared: 4,
            seen: KERNEL.len() as u64
        })
    );
    let mut short: &[u8] = b"abc";
    assert_eq!(
        HostArtifact::read(&mut short, 5),
        Err(ReadError::Length {
            declared: 5,
            seen: 3
        })
    );
    struct Interrupted(bool, &'static [u8]);
    impl Read for Interrupted {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.1.read(buffer)
        }
    }
    let read = HostArtifact::read(&mut Interrupted(false, INITRD), INITRD.len() as u64).unwrap();
    assert_eq!(read.content_key(), ContentKey::of(INITRD));
    assert_eq!(read.length_bytes(), INITRD.len() as u64);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk gone"))
        }
    }
    assert_eq!(
        HostArtifact::read(&mut Broken, 1),
        Err(ReadError::Unreadable {
            detail: "disk gone".to_owned()
        })
    );
    assert!(!ReadError::Length {
        declared: 1,
        seen: 2
    }
    .to_string()
    .is_empty());
}

#[test]
fn the_booted_image_check_compares_every_role() {
    let release = release();
    let selected = selected(&release);
    let check = selected.check_boot(&boot_set());
    assert!(check.matches());
    assert_eq!(check.manifest, release.manifest.content_key());
    assert_eq!(check.roles.len(), 3);

    let changed = one_byte_changed(KERNEL);
    let booted = BootSet::new()
        .with(ArtifactRole::Kernel, HostArtifact::of_bytes(&changed))
        .with(ArtifactRole::Profile, HostArtifact::of_bytes(b"profile"))
        .with(ArtifactRole::Initrd, HostArtifact::of_bytes(INITRD));
    let check = selected.check_boot(&booted);
    assert!(!check.matches());
    assert_eq!(
        check.roles,
        BTreeMap::from([
            (
                ArtifactRole::RootImage,
                RoleCheck::NotObserved {
                    expected: ContentKey::of(ROOT_IMAGE)
                }
            ),
            (
                ArtifactRole::Kernel,
                RoleCheck::Differs {
                    expected: ContentKey::of(KERNEL),
                    observed: ContentKey::of(&changed)
                }
            ),
            (ArtifactRole::Initrd, RoleCheck::Matches),
            (
                ArtifactRole::Profile,
                RoleCheck::Unexpected {
                    observed: ContentKey::of(b"profile")
                }
            ),
        ])
    );
    assert_eq!(
        serde_json::to_value(&check.roles[&ArtifactRole::Initrd]).unwrap(),
        serde_json::json!({"result": "matches"})
    );
}

#[test]
fn the_host_corroboration_feeds_the_vm_cp_05_evaluator() {
    let release = release();
    let selected = selected(&release);
    let corroboration = selected
        .host_corroboration(&boot_set(), [KernelSetting::LockdownIntegrity])
        .unwrap();
    assert_eq!(
        corroboration.root_image(),
        *ContentKey::of(ROOT_IMAGE).digest()
    );
    assert_eq!(corroboration.kernel(), release.manifest.kernel());
    assert_eq!(corroboration.source(), SourceClass::HostProbe);

    let host_checks = |host: &HostCorroboration| {
        evaluate(&strict(), None, Some(host), Some(&selected.expectation()))
            .checks
            .into_iter()
            .filter(|check| check.source == SourceClass::HostProbe)
            .map(|check| (check.check.clone(), check.passed()))
            .collect::<Vec<_>>()
    };
    let checks = host_checks(&corroboration);
    assert!(checks.len() >= 4);
    assert!(checks.iter().all(|(_, passed)| *passed), "{checks:?}");

    // Another kernel booted: its options are unknown, so its record cannot match.
    let other_kernel = boot_set().with(
        ArtifactRole::Kernel,
        HostArtifact::of_bytes(b"other kernel"),
    );
    let other = selected
        .host_corroboration(&other_kernel, NO_SETTINGS)
        .unwrap();
    assert_eq!(other.kernel().options().count(), 0);
    let failed: Vec<Check> = host_checks(&other)
        .into_iter()
        .filter(|(_, passed)| !passed)
        .map(|(check, _)| check)
        .collect();
    assert!(failed.contains(&Check::HostKernelImage));
    assert!(failed.contains(&Check::HostKernelOptionAbsent {
        option: KernelOption::IoUring
    }));

    let changed = one_byte_changed(ROOT_IMAGE);
    let other_root = boot_set().with(ArtifactRole::RootImage, HostArtifact::of_bytes(&changed));
    let checks = host_checks(
        &selected
            .host_corroboration(&other_root, NO_SETTINGS)
            .unwrap(),
    );
    assert!(checks.contains(&(Check::HostRootImage, false)));

    let no_kernel =
        BootSet::new().with(ArtifactRole::RootImage, HostArtifact::of_bytes(ROOT_IMAGE));
    assert!(selected
        .host_corroboration(&no_kernel, NO_SETTINGS)
        .is_none());
    assert!(selected
        .host_corroboration(&BootSet::new(), NO_SETTINGS)
        .is_none());
}

fn launch_request(
    guest_image: crate::foundation::ids::Digest,
    configuration: ConfigurationFingerprint,
) -> LaunchRequest {
    LaunchRequest {
        execution: ExecutionId::new("exe-guest-image").unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        generations: SandboxGenerations::FIRST,
        machine: digest("yougori/test/machine/v1", &[b"m"]),
        configuration,
        contract: digest("yougori/test/contract/v1", &[b"c"]),
        pinned: PinnedArtifacts {
            guest_image,
            backend: digest("yougori/test/backend/v1", &[b"b"]),
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/profile/v1", &[b"minimal"]),
            devices: DeviceExposure::cpu_only(),
        },
        required: RequiredProperties::strictest(Duration::from_secs(60)),
        reservation: serde_json::from_value(serde_json::json!(4)).unwrap(),
    }
}

#[test]
fn a_launch_request_must_name_the_selected_image_and_row() {
    let selected = selected(&release());
    let request = launch_request(selected.root_image(), selected.fingerprint());
    assert_eq!(selected.check_request(&request), Ok(()));
    let declared = *ContentKey::of(b"a declared image").digest();
    assert_eq!(
        selected.check_request(&launch_request(declared, selected.fingerprint())),
        Err(RequestMismatch::GuestImage {
            requested: declared,
            selected: selected.root_image()
        })
    );
    let other = ConfigurationFingerprint::from_settings([("kvm", "1")]).unwrap();
    assert_eq!(
        selected.check_request(&launch_request(selected.root_image(), other)),
        Err(RequestMismatch::Configuration {
            requested: other,
            selected: selected.fingerprint()
        })
    );
    assert!(!RequestMismatch::Configuration {
        requested: other,
        selected: other
    }
    .to_string()
    .is_empty());
}

/// The fixture's launch inputs with `boot` and `floor`.
fn attempt(
    release: &Release,
    boot: &BootSet,
    floor: Option<&ReleaseFloor>,
    clock: &crate::sandbox::trust::TrustClock,
) -> Result<AdmittedBoot, LaunchRefusal> {
    let roots = roots();
    let row = row(&release.record);
    let profile = strict();
    admit_launch(
        &LaunchInputs {
            manifest: release.manifest.canonical_bytes(),
            record: release.record.canonical_bytes(),
            signature: &release.signature,
            roots: &roots,
            row: &row,
            profile: &profile,
            floor,
            boot,
        },
        clock,
    )
}

/// The VM-CP-23 drill on the fixtures: each case's attempt at the launch boundary.
fn drill() -> BTreeMap<BoundaryCase, Option<LaunchRefusal>> {
    let release = release();
    let (manual, clock) = clock();
    let mut outcomes = BTreeMap::new();
    let mut record = |case, result: Result<AdmittedBoot, LaunchRefusal>| {
        outcomes.insert(case, result.err());
    };
    record(
        BoundaryCase::SignedSet,
        attempt(&release, &boot_set(), None, &clock),
    );
    let changed = one_byte_changed(ROOT_IMAGE);
    record(
        BoundaryCase::RootImageByteChange,
        attempt(
            &release,
            &boot_set().with(ArtifactRole::RootImage, HostArtifact::of_bytes(&changed)),
            None,
            &clock,
        ),
    );
    let mut unsigned = release.clone();
    unsigned.signature.signature = HexBytes::new(Vec::new());
    record(
        BoundaryCase::UnsignedManifest,
        attempt(&unsigned, &boot_set(), None, &clock),
    );
    let newer = ReleaseFloor {
        image: image_name(),
        release: ReleaseNumber::new(4).unwrap(),
        manifest: ContentKey::of(b"release 4"),
    };
    record(
        BoundaryCase::RolledBackVersion,
        attempt(&release, &boot_set(), Some(&newer), &clock),
    );
    record(
        BoundaryCase::MixedVersionSet,
        attempt(
            &release,
            &boot_set().with(
                ArtifactRole::Initrd,
                HostArtifact::of_bytes(b"initramfs of release 2"),
            ),
            None,
            &clock,
        ),
    );
    manual.advance(Duration::from_secs(EXPIRES_AT - NOW));
    record(
        BoundaryCase::ExpiredMetadata,
        attempt(&release, &boot_set(), None, &clock),
    );
    outcomes
}

#[test]
fn the_launch_boundary_refuses_every_vm_cp_23_case() {
    let outcomes = drill();
    assert_eq!(outcomes.len(), BoundaryCase::ALL.len());
    assert_eq!(outcomes[&BoundaryCase::SignedSet], None);
    for case in BoundaryCase::ALL {
        if case == BoundaryCase::SignedSet {
            continue;
        }
        let refusal = outcomes[&case].as_ref().unwrap();
        assert!(case.refused_as_intended(refusal), "{case:?}: {refusal}");
        assert_eq!(
            case.observe(Some(refusal)),
            Some(Observed::Attempt { refused: true })
        );
        // No case's refusal stands in for another's.
        for other in BoundaryCase::ALL {
            if other != case {
                assert!(
                    !other.refused_as_intended(refusal),
                    "{other:?} for {case:?}"
                );
            }
        }
    }
    assert!(matches!(
        outcomes[&BoundaryCase::ExpiredMetadata],
        Some(LaunchRefusal::Select {
            refusal: SelectionRefusal::Expired { .. }
        })
    ));
    assert_eq!(
        BoundaryCase::SignedSet.observe(None),
        Some(Observed::Attempt { refused: false })
    );
    assert_eq!(
        BoundaryCase::SignedSet.observe(outcomes[&BoundaryCase::RolledBackVersion].as_ref()),
        Some(Observed::Attempt { refused: true })
    );
    // Admitted is a conclusive failure; refused for another reason tests nothing.
    assert_eq!(
        BoundaryCase::UnsignedManifest.observe(None),
        Some(Observed::Attempt { refused: false })
    );
    assert_eq!(
        BoundaryCase::UnsignedManifest.observe(outcomes[&BoundaryCase::RolledBackVersion].as_ref()),
        None
    );
    // A pin of another release in the row is a mixed set too.
    let pin_mismatch = LaunchRefusal::Select {
        refusal: SelectionRefusal::PinMismatch {
            component: crate::sandbox::trust::ComponentKind::GuestKernel,
            field: PinField::ContentKey,
        },
    };
    assert!(BoundaryCase::MixedVersionSet.refused_as_intended(&pin_mismatch));
    assert!(!BoundaryCase::RootImageByteChange.refused_as_intended(&pin_mismatch));
    assert!(!pin_mismatch.to_string().is_empty());
    for case in BoundaryCase::ALL {
        let id = ExpectationId::named(case.expectation()).unwrap();
        let entry = crate::sandbox::probes::expectation(id).unwrap();
        assert_eq!(entry.check.number(), 23);
        assert_eq!(entry.part, Part::Primary);
    }
}

/// The evidence of one good boot of the fixture release, owned.
struct Evidence {
    expectation: ManifestExpectation,
    booted: Option<HostCorroboration>,
    control: Option<KernelControl>,
    boundary: BTreeMap<BoundaryCase, Option<LaunchRefusal>>,
    fingerprint: ConfigurationFingerprint,
}

impl Evidence {
    fn good() -> Self {
        let selected = selected(&release());
        let io_uring_image = KernelBuildRecord::new(
            *ContentKey::of(b"io_uring test kernel").digest(),
            [(KernelOption::IoUring, OptionState::BuiltIn)],
        )
        .unwrap();
        Self {
            expectation: selected.expectation(),
            booted: selected.host_corroboration(&boot_set(), NO_SETTINGS),
            control: Some(KernelControl::run(
                &KernelRequirements::of_profile(&strict()),
                &io_uring_image,
            )),
            boundary: drill(),
            fingerprint: selected.fingerprint(),
        }
    }

    fn view(&self) -> BootEvidence<'_> {
        BootEvidence {
            expectation: &self.expectation,
            booted: self.booted.as_ref(),
            kernel_control: self.control,
            boundary: &self.boundary,
        }
    }
}

/// A host check runner answering from [`observations`], adding the persisted volume
/// inventory VM-CP-17 also needs, which is not this module's.
struct Runner(Evidence);

impl HostCheckRunner for Runner {
    fn configuration(&self) -> ConfigurationFingerprint {
        self.0.fingerprint
    }

    fn fresh_for(&self) -> Duration {
        Duration::from_secs(300)
    }

    fn os(&self) -> OsKind {
        OsKind::Linux
    }

    fn run(&self, check: CheckId, part: Part, _subject: &Subject) -> RunResult {
        match observations(check, part, &self.0.view()) {
            Some(mut observations) => {
                if check.number() == 17 {
                    observations.insert(
                        ExpectationId::named("cp17.persisted-writable-inventory").unwrap(),
                        Observed::Event { happened: true },
                    );
                }
                RunResult::Observed { observations }
            }
            None => RunResult::Inconclusive {
                reason: RunnerInconclusive::Unreachable,
            },
        }
    }
}

fn boot_subject() -> Subject {
    let part = |name: &[u8]| digest("yougori/test/guest-image/subject/v1", &[name]);
    Subject::SandboxBoot(SandboxBootSubject {
        machine: part(b"machine"),
        vm: part(b"vm"),
        boot: SandboxBootGeneration::new(1),
    })
}

fn observe(evidence: Evidence) -> ObservationResult {
    BootedImageMatchesManifestProbe::new(Runner(evidence))
        .observe(&boot_subject())
        .result
}

#[test]
fn the_observations_name_their_checks_parts_and_values() {
    let evidence = Evidence::good();
    let view = evidence.view();
    let check = |number| CheckId::new(number).unwrap();
    let root = Part::Corroboration {
        fact: CorroboratingFact::BootedRootImage,
    };
    let kernel = Part::Corroboration {
        fact: CorroboratingFact::KernelBuildRecord,
    };
    let named = |name: &str| ExpectationId::named(name).unwrap();
    let root_observations = observations(check(5), root, &view).unwrap();
    assert_eq!(
        root_observations[&named("cp05.booted-root-image")],
        Observed::Comparison {
            observed: *ContentKey::of(ROOT_IMAGE).digest(),
            reference: *ContentKey::of(ROOT_IMAGE).digest(),
        }
    );
    let kernel_observations = observations(check(5), kernel, &view).unwrap();
    let digest_of_record = kernel_record_digest(&evidence.expectation.kernel);
    assert_eq!(
        kernel_observations[&named("cp05.kernel-build-record")],
        Observed::Comparison {
            observed: digest_of_record,
            reference: digest_of_record,
        }
    );
    assert_eq!(
        kernel_observations[&named("cp05.io-uring-image-fails-kernel-check")],
        Observed::Event { happened: true }
    );
    let base = observations(check(17), Part::Primary, &view).unwrap();
    assert_eq!(base.len(), 1);
    assert!(base.contains_key(&named("cp17.next-generation-signed-base")));
    assert_eq!(
        observations(check(23), Part::Primary, &view).unwrap().len(),
        6
    );
    // Every observation belongs to the check and part it was produced for.
    for (number, part) in [
        (5, root),
        (5, kernel),
        (17, Part::Primary),
        (23, Part::Primary),
    ] {
        for id in observations(check(number), part, &view).unwrap().keys() {
            let entry = crate::sandbox::probes::expectation(*id).unwrap();
            assert_eq!((entry.check.number(), entry.part), (number, part));
        }
    }
    // Checks and parts this module does not feed.
    assert_eq!(observations(check(5), Part::Primary, &view), None);
    assert_eq!(observations(check(1), Part::Primary, &view), None);
    assert_eq!(
        observations(
            check(9),
            Part::Corroboration {
                fact: CorroboratingFact::NoGuestNetworkDevice
            },
            &view
        ),
        None
    );
    // Without host corroboration nothing is compared.
    let blind = BootEvidence {
        booted: None,
        kernel_control: None,
        ..view
    };
    assert!(observations(check(5), root, &blind).unwrap().is_empty());
    assert!(observations(check(5), kernel, &blind).unwrap().is_empty());
    assert!(observations(check(17), Part::Primary, &blind)
        .unwrap()
        .is_empty());
}

#[test]
fn the_fact_is_supported_only_when_every_part_holds() {
    assert_eq!(
        observe(Evidence::good()),
        ObservationResult::Supported {
            detail: SupportDetail::Plain
        }
    );

    // The host booted another root image.
    let mut other_root = Evidence::good();
    let changed = one_byte_changed(ROOT_IMAGE);
    other_root.booted = selected(&release()).host_corroboration(
        &boot_set().with(ArtifactRole::RootImage, HostArtifact::of_bytes(&changed)),
        NO_SETTINGS,
    );
    assert_eq!(
        observe(other_root),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::ImageNotAsSigned
        }
    );

    // The signed set was refused: the control failed, so nothing is decided.
    let mut control_failed = Evidence::good();
    control_failed.boundary.insert(
        BoundaryCase::SignedSet,
        Some(LaunchRefusal::Verify {
            refusal: VerifyRefusal::Unsigned,
        }),
    );
    assert!(matches!(
        observe(control_failed),
        ObservationResult::Unknown { .. }
    ));

    // A one-byte change was admitted: a conclusive failure.
    let mut admitted = Evidence::good();
    admitted
        .boundary
        .insert(BoundaryCase::RootImageByteChange, None);
    assert_eq!(
        observe(admitted),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::ImageNotAsSigned
        }
    );

    // The io_uring control did not run, or did not refuse.
    let mut no_control = Evidence::good();
    no_control.control = None;
    assert_eq!(
        observe(no_control),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );
    let mut quiet_control = Evidence::good();
    quiet_control.control = Some(KernelControl::run(
        &KernelRequirements::of_profile(&developer()),
        &quiet_control.expectation.kernel.clone(),
    ));
    assert!(matches!(
        observe(quiet_control),
        ObservationResult::Unknown { .. }
    ));

    // An expired-metadata attempt refused for another reason tests nothing.
    let mut wrong_reason = Evidence::good();
    wrong_reason.boundary.insert(
        BoundaryCase::ExpiredMetadata,
        Some(LaunchRefusal::Verify {
            refusal: VerifyRefusal::Unsigned,
        }),
    );
    assert_eq!(
        observe(wrong_reason),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );

    // No host corroboration at all.
    let mut blind = Evidence::good();
    blind.booted = None;
    assert!(matches!(observe(blind), ObservationResult::Unknown { .. }));
}
