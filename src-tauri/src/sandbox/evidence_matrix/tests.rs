//! Tests of the evidence matrix: rows from the doctor's examination, sealed launch records
//! of the fake backend's host script, a signed release and a stamped verdict; unavailable
//! and stale fields; refused disagreements; combination identities; the matrix and its
//! change report.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::fixtures::*;
use super::*;
use crate::foundation::evidence::{
    BackendVersion, HypervisorKind, OsKind, ProbeRegistry, Staleness,
};
use crate::foundation::ids::ManualClock;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox::backend::{
    Accelerator, BackendKind, ConfinementControl, DeviceExposure, FactName, FactSource,
    FakeBackend, LaunchRecord, NetworkAuthority, ObservationProblem, PerimeterRequirement,
    VmBackend,
};
use crate::sandbox::doctor::CheckInputs;
use crate::sandbox::doctor::{Doctor, Label};
use crate::sandbox::probes::{
    catalog, CheckId, CheckInput, CheckStatus, HostKind, ProbeOutcome, RecordResults, RunProfile,
    RunResult, Side, Vm05Evaluation,
};
use crate::sandbox::trust::{Architecture as ImageArchitecture, UnixSeconds};
use crate::sandbox_contract::confinement::{VerdictOutcome, WorkloadProfile};

const SECOND: Duration = Duration::from_secs(1);

fn identities(records: &[LaunchRecord]) -> Vec<Digest> {
    records.iter().map(LaunchRecord::identity).collect()
}

fn current(age: Duration) -> Freshness {
    Freshness::Current {
        age,
        limit: MAX_AGE,
    }
}

#[test]
fn complete_current_evidence_keeps_the_doctors_validated_label() {
    let world = World::new();
    world.clock.advance(20 * SECOND);
    let row = world.row();
    assert_eq!(row.label(), Label::Validated);
    assert_eq!(row.basis(), &LabelBasis::Doctor);
    assert!(row.unavailable_fields().is_empty());
    assert!(row.not_current_fields().is_empty());

    // The §7.1 elements, each from the evidence that states it.
    assert_eq!(row.host_build(), Some(&linux_host()));
    assert_eq!(row.host().observed.value(), Some(&linux_host()));
    assert_eq!(row.backend_kind(), Some(BackendKind::Qemu));
    assert_eq!(row.backend().build.value(), Some(&qemu()));
    let manifest = row.guest_image().manifest.value().unwrap();
    assert_eq!(manifest.root_image, root_image());
    assert_eq!(manifest.manifest, world.image.manifest().content_key());
    assert_eq!(manifest.release.get(), 3);
    assert_eq!(row.guest_image().pinned.value(), Some(&root_image()));
    assert_eq!(row.guest_image().booted.value(), Some(&root_image()));
    assert_eq!(
        row.accelerator().value(),
        Some(&Accelerator::Hardware {
            hypervisor: HypervisorKind::Kvm
        })
    );
    assert_eq!(
        row.confinement().hypervisor.value(),
        Some(&ConfinementControl::all())
    );
    let guest = row.confinement().guest.value().unwrap();
    assert_eq!(guest.workload, WorkloadProfile::StrictTool);
    assert_eq!(guest.profile, strict_profile());
    assert_eq!(row.devices().profile.value(), Some(&minimal_devices()));
    assert_eq!(
        row.devices()
            .measured
            .value()
            .map(|inventory| inventory.exposure()),
        Some(DeviceExposure::cpu_only())
    );
    assert_eq!(
        row.network().enforced.value(),
        Some(&NetworkAuthority::offline())
    );
    let perimeter = row.network().perimeter.value().unwrap();
    assert_eq!(perimeter.requirement, PerimeterRequirement::NotRequired);
    assert_eq!(perimeter.evidenced_rules, 0);
    assert_eq!(
        row.lifecycle().paths.value(),
        Some(&BTreeSet::from([LaunchPath::ColdBoot, LaunchPath::Restore]))
    );
    let lifecycle: Vec<u8> = row
        .lifecycle()
        .checks
        .value()
        .unwrap()
        .iter()
        .map(|result| result.check.number())
        .collect();
    assert_eq!(lifecycle, LIFECYCLE_CHECKS.to_vec());
    assert!(row
        .lifecycle()
        .checks
        .value()
        .unwrap()
        .iter()
        .all(|result| result.status.passed()));
    assert_eq!(
        row.result().value().map(|result| result.label),
        Some(Label::Validated)
    );

    // Every field names its source and freshness.
    let records = identities(&world.records);
    assert_eq!(
        row.accelerator().source(),
        Some(&Source::HostObserved {
            fact: FactName::Accelerator,
            how: FactSource::HostObserved,
            records: records.clone(),
        })
    );
    assert_eq!(row.accelerator().freshness(), Some(&current(20 * SECOND)));
    assert_eq!(
        row.backend().build.source(),
        Some(&Source::SealedRecords {
            records: records.clone()
        })
    );
    assert_eq!(row.backend().build.freshness(), Some(&current(20 * SECOND)));
    assert_eq!(
        row.lifecycle().paths.freshness(),
        Some(&current(20 * SECOND))
    );
    let report = world
        .doctor
        .candidates
        .iter()
        .find(|candidate| candidate.candidate.backend == BackendKind::Qemu)
        .unwrap()
        .report
        .identity();
    for doctor_field in [
        row.host().examined.source(),
        row.backend().candidate.source(),
        row.lifecycle().checks.source(),
        row.result().source(),
    ] {
        assert_eq!(doctor_field, Some(&Source::Doctor { report }));
    }
    assert_eq!(
        row.result().freshness(),
        Some(&Freshness::CurrentAgeNotExposed)
    );
    assert!(matches!(
        row.guest_image().manifest.source(),
        Some(Source::SignedManifest { manifest, key })
            if *manifest == world.image.manifest().content_key()
                && key.as_str() == "guest-release-test"
    ));
    assert_eq!(
        row.guest_image().manifest.freshness(),
        Some(&Freshness::WithinValidity {
            issued_at: UnixSeconds::new(ISSUED_AT),
            expires_at: UnixSeconds::new(EXPIRES_AT),
        })
    );
    assert_eq!(
        row.confinement().guest.source(),
        Some(&Source::ConfinementVerdict {
            profile: strict_profile()
        })
    );
    assert_eq!(
        row.confinement().guest.freshness(),
        Some(&Freshness::CurrentAgeNotExposed)
    );

    // The same evidence assembles the same row.
    assert_eq!(world.row(), row);
}

#[test]
fn a_row_serializes_every_field_with_its_source_and_freshness_and_no_score() {
    let world = World::new();
    let json = serde_json::to_value(world.row()).unwrap();
    assert_eq!(json["notice"], ROW_NOTICE);
    assert_eq!(json["label"], "validated");
    assert_eq!(json["basis"]["basis"], "doctor");
    assert_eq!(json["combination"], world.row().combination().to_hex());
    let fields = [
        &json["host"]["examined"],
        &json["host"]["observed"],
        &json["backend"]["candidate"],
        &json["backend"]["build"],
        &json["guest_image"]["manifest"],
        &json["guest_image"]["pinned"],
        &json["guest_image"]["booted"],
        &json["accelerator"],
        &json["confinement"]["hypervisor"],
        &json["confinement"]["guest"],
        &json["devices"]["profile"],
        &json["devices"]["measured"],
        &json["network"]["enforced"],
        &json["network"]["perimeter"],
        &json["lifecycle"]["paths"],
        &json["lifecycle"]["checks"],
        &json["result"],
    ];
    assert_eq!(fields.len(), RowField::ALL.len());
    for field in fields {
        assert_eq!(field["state"], "known", "{field}");
        assert!(field["source"]["source"].is_string(), "{field}");
        assert!(field["freshness"]["freshness"].is_string(), "{field}");
    }
    assert_eq!(json["accelerator"]["source"]["source"], "host_observed");
    assert_eq!(json["accelerator"]["source"]["how"], "host_observed");
    assert_eq!(json["accelerator"]["freshness"]["freshness"], "current");
    assert_eq!(json["result"]["value"]["label"], "validated");
    assert!(!json.to_string().contains("score"));
}

#[test]
fn a_field_nobody_observed_is_explicitly_unavailable() {
    let world = World::new();
    let untested = examine(&world.registry, linux_host(), BTreeMap::new());
    let sources = RowSources {
        doctor: &untested,
        backend: BackendKind::Qemu,
        records: &[],
        image: None,
        confinement: None,
    };
    let row = assemble(&sources, &world.reading()).unwrap();
    // The doctor's label, unchanged: nothing passed.
    assert_eq!(row.label(), Label::Unavailable);
    assert_eq!(row.basis(), &LabelBasis::Doctor);
    assert_eq!(
        row.unavailable_fields(),
        vec![
            RowField::HostObserved,
            RowField::BackendBuild,
            RowField::ImageManifest,
            RowField::ImagePinned,
            RowField::ImageBooted,
            RowField::Accelerator,
            RowField::HypervisorConfinement,
            RowField::GuestConfinement,
            RowField::DeviceProfile,
            RowField::DeviceInventory,
            RowField::NetworkEnforcement,
            RowField::Perimeter,
            RowField::LifecyclePaths,
        ]
    );
    assert_eq!(
        row.accelerator().unavailable_because(),
        Some(&Unavailable::NoLaunchRecord)
    );
    assert_eq!(
        row.guest_image().manifest.unavailable_because(),
        Some(&Unavailable::NoSignedManifest)
    );
    assert_eq!(
        row.confinement().guest.unavailable_because(),
        Some(&Unavailable::NoConfinementVerdict)
    );
    assert!(row
        .lifecycle()
        .checks
        .value()
        .unwrap()
        .iter()
        .all(|result| matches!(result.status, CheckStatus::NotTested { .. })));
    let json = serde_json::to_value(&row).unwrap();
    assert_eq!(json["accelerator"]["state"], "unavailable");
    assert_eq!(json["accelerator"]["reason"]["because"], "no_launch_record");
    assert!(json["accelerator"].get("value").is_none());
    assert!(Unavailable::NoLaunchRecord
        .to_string()
        .contains("no launch record"));
    assert!(Unavailable::NotObserved {
        fact: FactName::Devices,
        reason: crate::foundation::evidence::UnknownReason::Unreachable,
    }
    .to_string()
    .contains("device inventory"));

    // The doctor examined Firecracker too; its row is another combination.
    let firecracker = assemble(
        &RowSources {
            backend: BackendKind::Firecracker,
            ..sources
        },
        &world.reading(),
    )
    .unwrap();
    assert_eq!(firecracker.backend_kind(), Some(BackendKind::Firecracker));
    assert_ne!(firecracker.combination(), row.combination());
}

#[test]
fn a_validated_backend_stays_experimental_until_its_combination_is_established() {
    let world = World::new();
    // The doctor validated QEMU here, but no record names its build or accelerator.
    let bare = assemble(
        &RowSources {
            records: &[],
            image: None,
            confinement: None,
            ..world.sources()
        },
        &world.reading(),
    )
    .unwrap();
    assert_eq!(bare.label(), Label::Experimental);
    match bare.basis() {
        LabelBasis::CombinationNotEstablished {
            unavailable,
            not_current,
        } => {
            assert_eq!(unavailable, &bare.unavailable_fields());
            assert!(unavailable.contains(&RowField::Accelerator));
            assert!(not_current.is_empty());
        }
        other => panic!("{other:?}"),
    }

    // An expired manifest cannot be selected, so the combination is not established.
    let expired = Reading {
        calendar: UnixSeconds::new(EXPIRES_AT),
        ..world.reading()
    };
    let row = assemble(&world.sources(), &expired).unwrap();
    assert_eq!(row.label(), Label::Experimental);
    assert_eq!(
        row.basis(),
        &LabelBasis::CombinationNotEstablished {
            unavailable: Vec::new(),
            not_current: vec![RowField::ImageManifest],
        }
    );
    assert_eq!(
        row.guest_image().manifest.freshness(),
        Some(&Freshness::Expired {
            expires_at: UnixSeconds::new(EXPIRES_AT)
        })
    );
    let early = Reading {
        calendar: UnixSeconds::new(ISSUED_AT - 1),
        ..world.reading()
    };
    let row = assemble(&world.sources(), &early).unwrap();
    assert_eq!(
        row.guest_image().manifest.freshness(),
        Some(&Freshness::IssuedAfterNow {
            issued_at: UnixSeconds::new(ISSUED_AT)
        })
    );
    assert_eq!(row.label(), Label::Experimental);
    // The manifest's validity is no part of the combination.
    assert_eq!(row.combination(), world.row().combination());

    // A doctor label that is not validated is kept as it is.
    let failing = examine(
        &world.registry,
        linux_host(),
        BTreeMap::from([(
            BackendKind::Qemu,
            results(&world.registry, &world.evaluation, CheckId::new(4)),
        )]),
    );
    let row = assemble(
        &RowSources {
            doctor: &failing,
            ..world.sources()
        },
        &world.reading(),
    )
    .unwrap();
    // VM-CP-04's positive control fails with it, so the doctor reads it inconclusive.
    let doctor_label = failing
        .candidates
        .iter()
        .find(|candidate| candidate.candidate.backend == BackendKind::Qemu)
        .unwrap()
        .label;
    assert_eq!(doctor_label, Label::Experimental);
    assert_eq!(row.label(), doctor_label);
    assert_eq!(row.basis(), &LabelBasis::Doctor);
}

#[test]
fn stale_evidence_is_never_presented_as_current() {
    let world = World::new();
    let fresh = world.row();
    world.clock.advance(MAX_AGE + SECOND);
    let row = world.row();
    assert_eq!(row.label(), Label::Unavailable);
    let too_old = ObservationProblem::Stale {
        staleness: Staleness::TooOld {
            age: MAX_AGE + SECOND,
            limit: MAX_AGE,
        },
    };
    assert_eq!(
        row.basis(),
        &LabelBasis::ReportNotCurrent { problem: too_old }
    );
    // Values are kept, and say they are not current.
    assert!(row.accelerator().value().is_some());
    assert_eq!(
        row.accelerator().freshness(),
        Some(&Freshness::NotCurrent { problem: too_old })
    );
    assert_eq!(
        row.backend().build.freshness(),
        Some(&Freshness::NotCurrent { problem: too_old })
    );
    assert_eq!(
        row.result().freshness(),
        Some(&Freshness::NotCurrent { problem: too_old })
    );
    assert!(matches!(
        row.confinement().guest.freshness(),
        Some(Freshness::NotCurrent {
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld { .. }
            }
        })
    ));
    // The manifest's validity is calendar time, and the calendar reading did not move.
    assert!(row.guest_image().manifest.is_current());
    assert_eq!(
        row.not_current_fields(),
        RowField::ALL
            .into_iter()
            .filter(|field| *field != RowField::ImageManifest)
            .collect::<Vec<_>>()
    );
    // Time changes no part of the combination.
    assert_eq!(row.combination(), fresh.combination());

    // Under another configuration nothing applies.
    let world = World::new();
    let mut reading = world.reading();
    reading.context.configuration = configuration("host-b");
    let row = assemble(&world.sources(), &reading).unwrap();
    assert_eq!(row.label(), Label::Unavailable);
    assert!(matches!(
        row.basis(),
        LabelBasis::ReportNotCurrent {
            problem: ObservationProblem::OtherConfiguration { .. }
        }
    ));
    assert!(matches!(
        row.devices().profile.freshness(),
        Some(Freshness::NotCurrent {
            problem: ObservationProblem::OtherConfiguration { .. }
        })
    ));

    // On another clock session, such as after a restart, no age is known.
    let restarted = ProbeRegistry::new(Arc::clone(&world.clock));
    let reading = Reading {
        context: context(&restarted),
        ..world.reading()
    };
    let row = assemble(&world.sources(), &reading).unwrap();
    assert_eq!(row.label(), Label::Unavailable);
    assert_eq!(
        row.accelerator().freshness(),
        Some(&Freshness::NotCurrent {
            problem: ObservationProblem::Stale {
                staleness: Staleness::OtherClock
            }
        })
    );
}

#[test]
fn parts_that_disagree_are_refused() {
    let world = World::new();
    let reading = world.reading();
    let refused = |sources: RowSources<'_>| assemble(&sources, &reading).unwrap_err();
    let seal = |launches: Launches| launches.seal(&world.registry);

    let mut windows = reading;
    windows.context.os = OsKind::Windows;
    let error = assemble(&world.sources(), &windows).unwrap_err();
    assert_eq!(
        error,
        RowError::ReadingOfOtherHost {
            host: OsKind::Linux,
            reading: OsKind::Windows,
        }
    );
    assert!(error.to_string().contains("Windows host"));

    let error = refused(RowSources {
        backend: BackendKind::Hcs,
        records: &[],
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::NotExamined {
            backend: BackendKind::Hcs
        }
    );
    assert!(error.to_string().contains("did not examine"));

    let twice = [world.records[0].clone(), world.records[0].clone()];
    assert_eq!(
        refused(RowSources {
            records: &twice,
            ..world.sources()
        }),
        RowError::DuplicateRecord {
            record: world.records[0].identity()
        }
    );

    // Another host build.
    let other_host = seal(Launches {
        host: host("6.8.0-46"),
        restores: 0,
        ..Launches::qemu()
    });
    let mixed = [world.records[0].clone(), other_host[0].clone()];
    let error = refused(RowSources {
        records: &mixed,
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::OtherHost {
            record: other_host[0].identity()
        }
    );
    assert!(error.to_string().contains("host build"));
    // Another backend, and another build of the same backend.
    let firecracker = seal(Launches {
        backend: firecracker(),
        restores: 0,
        ..Launches::qemu()
    });
    let error = refused(RowSources {
        records: &firecracker,
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::OtherBackend {
            record: firecracker[0].identity(),
            examined: BackendKind::Qemu,
            found: BackendKind::Firecracker,
        }
    );
    assert!(error.to_string().contains("sealed by Firecracker"));
    let newer = seal(Launches {
        backend: qemu_build("9.2.1"),
        restores: 0,
        ..Launches::qemu()
    });
    let mixed = [world.records[0].clone(), newer[0].clone()];
    assert_eq!(
        refused(RowSources {
            records: &mixed,
            ..world.sources()
        }),
        RowError::OtherBackendBuild {
            record: newer[0].identity()
        }
    );

    // Another image: the manifest's root image is not the one the launches booted.
    let other = release_with(ImageArchitecture::X86_64, OTHER_ROOT_IMAGE, |_| {});
    let error = refused(RowSources {
        image: Some(&other),
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::OtherImage {
            record: world.records[0].identity(),
            expected: other_root_image(),
            found: root_image(),
        }
    );
    assert!(error.to_string().contains("root image"));
    // Without a manifest, records must boot one image among themselves.
    let other_boot = admitted(
        &world.registry,
        &launch_request(&qemu(), "exe-7", 1, other_root_image(), minimal_devices()),
        &qemu(),
        &script(linux_host(), other_root_image()),
        None,
    );
    let mixed = [world.records[0].clone(), other_boot.clone()];
    assert_eq!(
        refused(RowSources {
            records: &mixed,
            image: None,
            ..world.sources()
        }),
        RowError::OtherImage {
            record: other_boot.identity(),
            expected: root_image(),
            found: other_root_image(),
        }
    );
    // An image built for another architecture.
    let arm = release_with(ImageArchitecture::Aarch64, ROOT_IMAGE, |_| {});
    let error = refused(RowSources {
        image: Some(&arm),
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::ImageArchitecture {
            host: crate::sandbox::backend::Architecture::X86_64,
            image: ImageArchitecture::Aarch64,
        }
    );
    assert!(error.to_string().contains("aarch64"));

    // Records that disagree about a field of the combination.
    let display = seal(Launches {
        devices: device_profile(b"other-profile"),
        restores: 0,
        ..Launches::qemu()
    });
    let mixed = [world.records[0].clone(), display[0].clone()];
    let error = refused(RowSources {
        records: &mixed,
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::Disagree {
            field: RowField::DeviceProfile,
            record: display[0].identity(),
        }
    );
    assert!(error.to_string().contains("device profile"));

    // A verdict for a profile the image does not install.
    let developer = evaluation(
        &world.registry,
        WorkloadProfile::Developer,
        developer_profile(),
    );
    let error = refused(RowSources {
        confinement: Some(&developer),
        ..world.sources()
    });
    assert_eq!(
        error,
        RowError::ProfileNotInstalled {
            workload: WorkloadProfile::Developer,
            profile: developer_profile(),
        }
    );
    assert!(error.to_string().contains("does not install"));
    // A verdict the doctor judged otherwise is not the doctor's.
    let failed = evaluation_with(
        &world.registry,
        WorkloadProfile::StrictTool,
        strict_profile(),
        VerdictOutcome::Failed,
    );
    let error = refused(RowSources {
        confinement: Some(&failed),
        ..world.sources()
    });
    assert!(matches!(
        &error,
        RowError::VerdictDisagrees {
            doctor: CheckStatus::Passed,
            verdict: CheckStatus::Inconclusive { .. },
        }
    ));
    assert!(error.to_string().contains("judged VM-CP-05 passed"));
    // A doctor that judged no verdict leaves the one given as stated.
    let untested = examine(&world.registry, linux_host(), BTreeMap::new());
    let row = assemble(
        &RowSources {
            doctor: &untested,
            confinement: Some(&failed),
            ..world.sources()
        },
        &reading,
    )
    .unwrap();
    assert_eq!(
        row.confinement().guest.value().map(|guest| guest.outcome),
        Some(VerdictOutcome::Failed)
    );
    // Without the image the verdict cannot be checked against it, and is taken as stated.
    let row = assemble(
        &RowSources {
            confinement: Some(&developer),
            image: None,
            ..world.sources()
        },
        &reading,
    )
    .unwrap();
    assert_eq!(
        row.confinement().guest.value().map(|guest| guest.workload),
        Some(WorkloadProfile::Developer)
    );
}

#[test]
fn every_record_the_doctor_read_results_from_must_be_given() {
    let world = World::new();
    let mut from_records = RecordResults::new(linux_host(), qemu());
    for record in &world.records {
        from_records.record(record.clone()).unwrap();
    }
    let report = Doctor::new()
        .examine_with_records(
            &request(linux_host(), &[RunProfile::Strict]),
            &context(&world.registry),
            BTreeMap::new(),
            &[from_records],
        )
        .unwrap();
    let sources = RowSources {
        doctor: &report,
        ..world.sources()
    };
    let row = assemble(&sources, &world.reading()).unwrap();
    let read = &row.result().value().unwrap().from_launch_records;
    assert!(!read.is_empty());
    assert_eq!(row.label(), Label::Unavailable);

    let error = assemble(
        &RowSources {
            records: &world.records[..1],
            ..sources
        },
        &world.reading(),
    )
    .unwrap_err();
    match &error {
        RowError::DoctorRecordMissing { record } => {
            assert!(identities(&world.records[1..]).contains(record));
        }
        other => panic!("{other:?}"),
    }
    assert!(error.to_string().contains("was not given"));
}

#[test]
fn the_fake_backends_records_are_refused() {
    let world = World::new();
    let artifact = digest("yougori/test/evidence-matrix/backend/v1", &[b"fake"]);
    let mut fake = FakeBackend::new(
        HypervisorKind::Kvm,
        BackendVersion::new("0.1.0").unwrap(),
        artifact,
        script(linux_host(), root_image()),
    );
    let mut request = launch_request(&qemu(), "exe-6", 1, root_image(), minimal_devices());
    request.pinned.backend = artifact;
    let launched = fake.launch(&request, &world.registry).unwrap();
    assert_eq!(launched.record.backend().kind, BackendKind::Fake);
    let records = [launched.record];
    assert_eq!(
        assemble(
            &RowSources {
                records: &records,
                ..world.sources()
            },
            &world.reading()
        )
        .unwrap_err(),
        RowError::OtherBackend {
            record: records[0].identity(),
            examined: BackendKind::Qemu,
            found: BackendKind::Fake,
        }
    );
    // The doctor never examines the fake, so it has no row.
    assert_eq!(
        assemble(
            &RowSources {
                backend: BackendKind::Fake,
                records: &records,
                ..world.sources()
            },
            &world.reading()
        )
        .unwrap_err(),
        RowError::NotExamined {
            backend: BackendKind::Fake
        }
    );
}

#[test]
fn an_independent_perimeter_is_read_with_its_rule_evidence() {
    let rules = [block_rule(b"private-ranges"), block_rule(b"metadata")];
    let world = World::of(
        Launches {
            perimeter: independent(&rules),
            ..Launches::qemu()
        },
        &rules,
    );
    world.clock.advance(5 * SECOND);
    let row = world.row();
    let perimeter = row.network().perimeter.value().unwrap();
    assert_eq!(perimeter.requirement, independent(&rules));
    assert_eq!(perimeter.evidenced_rules, 2);
    assert!(matches!(
        row.network().perimeter.freshness(),
        Some(Freshness::Current { age, .. }) if *age == 5 * SECOND
    ));
    assert_eq!(row.label(), Label::Validated);
    assert_ne!(row.combination(), World::new().row().combination());

    world.clock.advance(MAX_AGE);
    assert!(!world.row().network().perimeter.is_current());
}

#[test]
fn every_part_of_the_combination_changes_its_identity_and_time_does_not() {
    let world = World::new();
    let base = world.row();
    let mut identities = BTreeSet::from([base.combination()]);
    let row = |sources: RowSources<'_>| assemble(&sources, &world.reading()).unwrap();
    let seal = |launches: Launches| launches.seal(&world.registry);

    let cold_boot_only = seal(Launches {
        restores: 0,
        ..Launches::qemu()
    });
    let newer_build = seal(Launches {
        backend: qemu_build("9.2.1"),
        ..Launches::qemu()
    });
    let other_devices = seal(Launches {
        devices: device_profile(b"other-profile"),
        ..Launches::qemu()
    });
    let later_release = release_with(ImageArchitecture::X86_64, ROOT_IMAGE, |document| {
        document.expires_at = UnixSeconds::new(EXPIRES_AT + 1);
    });
    let newer_doctor = examine(
        &world.registry,
        linux_host(),
        BTreeMap::from([(
            BackendKind::Qemu,
            results(&world.registry, &world.evaluation, None),
        )]),
    );
    let newer_doctor_row = row(RowSources {
        doctor: &newer_doctor,
        records: &newer_build,
        ..world.sources()
    });
    let gpu = Doctor::new()
        .examine(
            &request(linux_host(), &[RunProfile::Strict, RunProfile::GpuVm]),
            &context(&world.registry),
            BTreeMap::from([(
                BackendKind::Qemu,
                results(&world.registry, &world.evaluation, None),
            )]),
        )
        .unwrap();
    let other_host_launches = Launches {
        host: host("6.8.0-46"),
        ..Launches::qemu()
    };
    let other_host_records = seal(other_host_launches);
    let other_host_doctor = examine(
        &world.registry,
        host("6.8.0-46"),
        BTreeMap::from([(
            BackendKind::Qemu,
            results(&world.registry, &world.evaluation, None),
        )]),
    );

    let variants: Vec<(&str, MatrixRow)> = vec![
        (
            "lifecycle",
            row(RowSources {
                records: &cold_boot_only,
                ..world.sources()
            }),
        ),
        ("backend build", newer_doctor_row),
        (
            "device profile",
            row(RowSources {
                records: &other_devices,
                ..world.sources()
            }),
        ),
        (
            "manifest",
            row(RowSources {
                image: Some(&later_release),
                ..world.sources()
            }),
        ),
        (
            "no manifest",
            row(RowSources {
                image: None,
                ..world.sources()
            }),
        ),
        (
            "no verdict",
            row(RowSources {
                confinement: None,
                ..world.sources()
            }),
        ),
        (
            "run profiles",
            row(RowSources {
                doctor: &gpu,
                ..world.sources()
            }),
        ),
        (
            "host build",
            row(RowSources {
                doctor: &other_host_doctor,
                records: &other_host_records,
                ..world.sources()
            }),
        ),
        (
            "no records",
            row(RowSources {
                records: &[],
                ..world.sources()
            }),
        ),
    ];
    for (name, variant) in &variants {
        assert!(identities.insert(variant.combination()), "{name}");
    }

    // The same combination read later, or examined again, is the same combination.
    let again = row(RowSources {
        doctor: &newer_doctor,
        ..world.sources()
    });
    assert_eq!(again.combination(), base.combination());
    world.clock.advance(10 * SECOND);
    let later = world.row();
    assert_eq!(later.combination(), base.combination());
    assert_ne!(later, base);
    assert_eq!(
        COMBINATION_DOMAIN,
        "yougori/sandbox/evidence-matrix/combination/v1"
    );
}

#[test]
fn a_matrix_keeps_one_row_per_combination_and_says_what_changed() {
    let world = World::new();
    let complete = world.row();
    let bare_sources = RowSources {
        records: &[],
        image: None,
        confinement: None,
        ..world.sources()
    };
    let bare = assemble(&bare_sources, &world.reading()).unwrap();
    let mut earlier = EvidenceMatrix::new();
    assert!(earlier.is_empty());
    earlier.add(complete.clone()).unwrap();
    earlier.add(bare.clone()).unwrap();
    let duplicate = earlier.add(complete.clone()).unwrap_err();
    assert_eq!(
        duplicate,
        MatrixError::DuplicateCombination {
            combination: complete.combination()
        }
    );
    assert!(duplicate.to_string().contains("already has a row"));
    assert_eq!(earlier.len(), 2);
    assert_eq!(earlier.row(&complete.combination()), Some(&complete));
    assert_eq!(earlier.label_of(&complete.combination()), Label::Validated);
    assert_eq!(earlier.label_of(&bare.combination()), Label::Experimental);
    let nowhere = digest("yougori/test/evidence-matrix/combination/v1", &[b"none"]);
    assert_eq!(earlier.label_of(&nowhere), Label::Unavailable);
    let same = earlier.changes_since(&earlier);
    assert!(same.is_empty());
    assert_eq!(same.unchanged, 2);

    // A new examination with VM-CP-04 failing: the combination is the same, its label
    // and the doctor's checks changed.
    let failing = examine(
        &world.registry,
        linux_host(),
        BTreeMap::from([(
            BackendKind::Qemu,
            results(&world.registry, &world.evaluation, CheckId::new(4)),
        )]),
    );
    let reexamined = assemble(
        &RowSources {
            doctor: &failing,
            ..world.sources()
        },
        &world.reading(),
    )
    .unwrap();
    assert_eq!(reexamined.combination(), complete.combination());
    let firecracker = assemble(
        &RowSources {
            backend: BackendKind::Firecracker,
            ..bare_sources
        },
        &world.reading(),
    )
    .unwrap();
    let mut now = EvidenceMatrix::new();
    now.add(reexamined).unwrap();
    now.add(firecracker.clone()).unwrap();

    let changes = now.changes_since(&earlier);
    assert!(!changes.is_empty());
    assert_eq!(changes.unchanged, 0);
    assert_eq!(changes.added.len(), 1);
    assert_eq!(changes.added[0].combination, firecracker.combination());
    assert_eq!(changes.added[0].backend, Some(BackendKind::Firecracker));
    assert_eq!(changes.added[0].label, Label::Unavailable);
    assert_eq!(changes.removed.len(), 1);
    assert_eq!(changes.removed[0].combination, bare.combination());
    assert_eq!(changes.removed[0].label, Label::Experimental);
    assert_eq!(changes.changed.len(), 1);
    let change = &changes.changed[0];
    assert_eq!(change.summary.combination, complete.combination());
    assert_eq!(change.summary.host, Some(linux_host()));
    assert_eq!(change.label_before, Label::Validated);
    assert_eq!(change.summary.label, Label::Experimental);
    assert_eq!(
        change.fields,
        vec![
            RowField::HostExamined,
            RowField::BackendCandidate,
            RowField::LifecycleChecks,
            RowField::TestResult,
        ]
    );
    let report = change.report.as_ref().unwrap();
    assert!(report.launch_allowed_before);
    assert!(!report.launch_allowed_now);
    let checks: Vec<u8> = report
        .checks
        .iter()
        .map(|check| check.check.number())
        .collect();
    assert_eq!(checks, vec![4]);

    // The same rows read later: every field but the calendar-time manifest changed.
    world.clock.advance(MAX_AGE + SECOND);
    let mut stale = EvidenceMatrix::new();
    stale.add(world.row()).unwrap();
    let changes = stale.changes_since(&earlier);
    let change = &changes.changed[0];
    assert_eq!(change.summary.label, Label::Unavailable);
    assert!(change.report.is_none());
    assert_eq!(change.fields.len(), RowField::ALL.len() - 1);
    assert!(!change.fields.contains(&RowField::ImageManifest));

    let json = serde_json::to_value(&now).unwrap();
    assert_eq!(json["notice"], MATRIX_NOTICE);
    assert_eq!(json["rows"].as_array().unwrap().len(), 2);
    let json = serde_json::to_value(&now.changes_since(&earlier)).unwrap();
    assert_eq!(json["changed"][0]["label_before"], "validated");
    assert_eq!(json["changed"][0]["fields"][0], "host_examined");
    assert!(!json.to_string().contains("score"));
    assert_eq!(now.rows().count(), now.len());
}

#[test]
fn freshness_follows_the_core01_rules_in_order() {
    let world = World::new();
    let context = context(&world.registry);
    let at = context.now.at();
    let config = configuration(CONFIG);
    let session = context.now.session();
    assert_eq!(
        Freshness::of_stamp(config, session, at, FRESH, &context),
        current(Duration::ZERO)
    );
    let short = Freshness::of_stamp(config, session, at, 10 * SECOND, &context);
    assert_eq!(
        short,
        Freshness::Current {
            age: Duration::ZERO,
            limit: 10 * SECOND
        }
    );
    // Configuration first, even for a stamp from the future.
    assert!(matches!(
        Freshness::of_stamp(
            configuration("host-b"),
            session,
            at.saturating_add(SECOND),
            FRESH,
            &context
        ),
        Freshness::NotCurrent {
            problem: ObservationProblem::OtherConfiguration { .. }
        }
    ));
    assert_eq!(
        Freshness::of_stamp(config, session, at.saturating_add(SECOND), FRESH, &context),
        Freshness::NotCurrent {
            problem: ObservationProblem::Stale {
                staleness: Staleness::ObservedAfterNow
            }
        }
    );
    assert!(current(SECOND).preferred_over(&current(2 * SECOND)));
    assert!(!current(2 * SECOND).preferred_over(&current(SECOND)));
    let stale = Freshness::NotCurrent {
        problem: ObservationProblem::Stale {
            staleness: Staleness::OtherClock,
        },
    };
    assert!(current(MAX_AGE).preferred_over(&stale));
    assert!(!stale.preferred_over(&current(MAX_AGE)));
    assert!(stale.worse_than(&current(SECOND)));
    assert!(current(2 * SECOND).worse_than(&current(SECOND)));
    assert!(!stale.is_current());
    assert!(Freshness::CurrentAgeNotExposed.is_current());
    assert_eq!(
        Freshness::of_check(Err(ObservationProblem::Stale {
            staleness: Staleness::OtherClock
        })),
        stale
    );
    assert_eq!(RowField::ALL.len(), 17);
    for field in RowField::ALL {
        assert_eq!(
            serde_json::to_value(field).unwrap(),
            serde_json::Value::String(field.tag().to_owned())
        );
        assert!(!field.to_string().is_empty());
    }
    assert_eq!(LaunchPath::Restore.to_string(), "restore from a snapshot");
}

/// Inputs that pass every check on this Linux host, each observed now and standing for
/// `fresh_for`, with VM-CP-05 from `verdict`.
fn results_fresh_for(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    verdict: &Vm05Evaluation,
    fresh_for: Duration,
) -> CheckInputs {
    catalog()
        .iter()
        .map(|row| {
            let input = if row.id.number() == 5 {
                CheckInput::Vm05(verdict.clone())
            } else {
                let kind = match row.side {
                    Side::ControlledExternal => HostKind::ControlledExternal,
                    _ => HostKind::Host,
                };
                CheckInput::Outcomes(
                    row.parts()
                        .into_iter()
                        .map(|part| {
                            ProbeOutcome::host(
                                row.id,
                                part,
                                kind,
                                registry.now(),
                                fresh_for,
                                configuration(CONFIG),
                                RunResult::Observed {
                                    observations: observations(row, part, true),
                                },
                            )
                            .unwrap()
                        })
                        .collect(),
                )
            };
            (row.id, input)
        })
        .collect()
}

/// Review finding R3 at the matrix consumer: the doctor's inputs stand for thirty
/// seconds and its report is assembled just inside that, over launch records and a
/// verdict that stand far longer. Two seconds later the report is still two seconds old,
/// but the evidence it judged has expired, so the row no longer presents it as current,
/// while the records and the verdict still are.
#[test]
fn a_doctor_report_whose_evidence_expired_is_not_current_however_recent() {
    let (registry, clock) = kvm_host(CONFIG, &[]);
    let evaluation = evaluation(&registry, WorkloadProfile::StrictTool, strict_profile());
    let short = Duration::from_secs(30);
    let inputs = results_fresh_for(&registry, &evaluation, short);
    let launches = Launches::qemu();
    let records = launches.seal(&registry);
    clock.advance(short - SECOND);
    let doctor = examine(
        &registry,
        launches.host.clone(),
        BTreeMap::from([(launches.backend.kind, inputs)]),
    );
    let world = World {
        clock: Arc::clone(&clock),
        registry,
        records,
        image: release(),
        evaluation,
        doctor,
    };
    let row = world.row();
    assert_eq!(
        row.label(),
        Label::Validated,
        "positive control: at assembly everything is current ({:?})",
        row.basis()
    );
    world.clock.advance(2 * SECOND);
    let row = world.row();
    assert_eq!(row.label(), Label::Unavailable);
    assert_eq!(
        row.basis(),
        &LabelBasis::ReportNotCurrent {
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: short + SECOND,
                    limit: short,
                },
            }
        }
    );
    // The records and the verdict are still current: only the doctor's judged evidence
    // expired, two seconds after a report that would have passed as current before.
    assert!(row.backend().build.is_current());
    assert!(row.confinement().guest.is_current());
    assert!(matches!(
        row.result().freshness(),
        Some(Freshness::NotCurrent { .. })
    ));
}
