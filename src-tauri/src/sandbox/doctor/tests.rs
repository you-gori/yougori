//! Tests of the doctor: candidates per host, the §7.1 labels, change reporting, refusals,
//! results read from sealed launch records, the dry-run plan, the engine's own wording of
//! every check that did not pass, and the history kept across restarts.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::{SandboxGenerations, SnapshotId};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HypervisorKind, HypervisorSubject, Observation, OsKind,
    ProbeRegistry, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, Digest, ExecutionId, ManualClock, MonotonicTime, TenantId};
use crate::foundation::ledger::ReservationId;
use crate::sandbox::backend::{
    admit, precheck, vm_handle, Architecture, BackendFeatures, BackendIdentity, BackendKind,
    BuildId, DeviceProfile, HostBuild, HostScript, LaunchRecord, LaunchRequest, PinnedArtifacts,
    RequiredProperties,
};
use crate::sandbox::probes::{
    catalog, Applicability, CheckId, CheckInput, CheckRefusal, CheckStatus, ControlledCheck,
    ControlledFault, CorroboratingFact, Expect, Expectation, GpuPath, HostKind, JudgeContext,
    NegativeOutcome, Observations, Observed, Part, PositiveControl, ProbeOutcome, RecordAge,
    RecordResults, ReportError, Role, RunProfile, RunResult, Side, Vm05Evaluation,
};
use crate::sandbox_contract::confinement::{
    ConfinementVerdict, VerdictMeaning, VerdictOutcome, WorkloadProfile,
};

const FRESH: Duration = Duration::from_secs(600);
const MAX_AGE: Duration = Duration::from_secs(300);

fn registry() -> ProbeRegistry<Arc<ManualClock>> {
    ProbeRegistry::new(Arc::new(ManualClock::new(MonotonicTime::from_nanos(
        1_000_000,
    ))))
}

fn configuration(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

fn host(os: OsKind, build: &str) -> HostBuild {
    HostBuild {
        os,
        build: BuildId::new(build).unwrap(),
        architecture: Architecture::X86_64,
    }
}

fn strict() -> BTreeSet<RunProfile> {
    DEFAULT_PROFILES.into_iter().collect()
}

fn request(os: OsKind, build: &str, config: &str, profiles: BTreeSet<RunProfile>) -> DoctorRequest {
    DoctorRequest {
        host: host(os, build),
        configuration: configuration(config),
        profiles,
    }
}

fn context(registry: &ProbeRegistry<Arc<ManualClock>>, config: &str, os: OsKind) -> JudgeContext {
    JudgeContext {
        now: registry.now(),
        configuration: configuration(config),
        max_age: MAX_AGE,
        os,
    }
}

fn meeting(expect: Expect) -> Observed {
    let reference = digest("yougori/test/doctor/reference/v1", &[b"reference"]);
    match expect {
        Expect::Refused => Observed::Attempt { refused: true },
        Expect::Succeeds => Observed::Attempt { refused: false },
        Expect::Absent => Observed::Presence { present: false },
        Expect::Present => Observed::Presence { present: true },
        Expect::Happens => Observed::Event { happened: true },
        Expect::NeverHappens => Observed::Event { happened: false },
        Expect::OneOf(allowed) => Observed::Value {
            value: allowed[0].to_owned(),
        },
        Expect::WithinLimit => Observed::Bounded { value: 1, limit: 2 },
        Expect::Matches => Observed::Comparison {
            observed: reference,
            reference,
        },
        Expect::AllDistinct => Observed::Identities {
            values: vec![
                digest("yougori/test/doctor/identity/v1", &[b"a"]),
                digest("yougori/test/doctor/identity/v1", &[b"b"]),
            ],
        },
    }
}

fn violating(expect: Expect) -> Observed {
    match expect {
        Expect::Refused => Observed::Attempt { refused: false },
        Expect::Succeeds => Observed::Attempt { refused: true },
        Expect::Absent => Observed::Presence { present: true },
        Expect::Present => Observed::Presence { present: false },
        Expect::Happens => Observed::Event { happened: false },
        Expect::NeverHappens => Observed::Event { happened: true },
        Expect::OneOf(_) => Observed::Value {
            value: "tcg".to_owned(),
        },
        Expect::WithinLimit => Observed::Bounded { value: 3, limit: 2 },
        Expect::Matches => Observed::Comparison {
            observed: digest("yougori/test/doctor/observed/v1", &[b"other"]),
            reference: digest("yougori/test/doctor/reference/v1", &[b"reference"]),
        },
        Expect::AllDistinct => {
            let same = digest("yougori/test/doctor/identity/v1", &[b"same"]);
            Observed::Identities {
                values: vec![same, same],
            }
        }
    }
}

fn passing(row: &ControlledCheck, part: Part, os: OsKind) -> Observations {
    row.expectations()
        .filter(|entry| entry.part == part && entry.scope.applies(os))
        .map(|entry| (entry.id, meeting(entry.expect)))
        .collect()
}

fn outcomes(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    row: &ControlledCheck,
    config: &str,
    observations: impl Fn(Part) -> Observations,
) -> CheckInput {
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
                    FRESH,
                    configuration(config),
                    RunResult::Observed {
                        observations: observations(part),
                    },
                )
                .unwrap()
            })
            .collect(),
    )
}

/// Results that pass every check on `os`, with VM-CP-05 from a passing V15 verdict.
fn all_passing(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    os: OsKind,
    config: &str,
) -> CheckInputs {
    catalog()
        .iter()
        .map(|row| {
            let input = if row.id == vm_cp_05() {
                CheckInput::Vm05(Vm05Evaluation::evaluated(
                    ConfinementVerdict {
                        profile: digest("yougori/test/doctor/profile/v1", &[b"strict-tool"]),
                        workload: WorkloadProfile::StrictTool,
                        meaning: VerdictMeaning::InnerControlsDefenseInDepth,
                        host_corroboration_required: true,
                        checks: Vec::new(),
                        outcome: VerdictOutcome::Passed,
                    },
                    registry.now(),
                    FRESH,
                    configuration(config),
                ))
            } else {
                outcomes(registry, row, config, |part| passing(row, part, os))
            };
            (row.id, input)
        })
        .collect()
}

fn vm_cp_05() -> CheckId {
    CheckId::new(5).unwrap()
}

fn required_rows(profiles: &BTreeSet<RunProfile>) -> Vec<CheckId> {
    catalog()
        .iter()
        .filter(|row| row.required_for(profiles))
        .map(|row| row.id)
        .collect()
}

#[test]
fn each_host_examines_the_backends_the_plan_names() {
    let kinds = |os| {
        candidates(os)
            .iter()
            .map(|candidate| (candidate.backend, candidate.role))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        kinds(OsKind::Windows),
        vec![
            (BackendKind::Hcs, CandidateRole::Primary),
            (BackendKind::Qemu, CandidateRole::Fallback)
        ]
    );
    assert_eq!(
        kinds(OsKind::Linux),
        vec![
            (BackendKind::Firecracker, CandidateRole::Primary),
            (BackendKind::Qemu, CandidateRole::Alternative)
        ]
    );
    assert_eq!(
        kinds(OsKind::MacOs),
        vec![
            (BackendKind::VirtualizationFramework, CandidateRole::Primary),
            (BackendKind::Qemu, CandidateRole::Alternative)
        ]
    );
    assert!(candidates(OsKind::Wsl2).is_empty());
}

#[test]
fn without_results_every_backend_is_unavailable_and_nothing_passed() {
    let registry = registry();
    let mut doctor = Doctor::new();
    let report = doctor
        .examine(
            &request(OsKind::Windows, "26200", "host-a", strict()),
            &context(&registry, "host-a", OsKind::Windows),
            BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(report.notice, DOCTOR_NOTICE);
    assert_eq!(report.results, 0);
    assert!(
        report.changes.is_empty(),
        "a first examination has nothing to compare"
    );
    let required = required_rows(&strict());
    assert!(!required.is_empty());
    assert_eq!(report.candidates.len(), 2);
    for candidate in &report.candidates {
        assert_eq!(candidate.label, Label::Unavailable);
        assert_eq!(candidate.required.passed, 0);
        assert_eq!(candidate.required.not_tested, required.len());
        assert_eq!(candidate.required.total(), required.len());
        assert_eq!(candidate.all.total(), catalog().len());
        assert_eq!(candidate.blocking, required);
        assert!(!candidate.report.allows_launch());
        for entry in candidate.report.entries() {
            assert!(matches!(entry.status, CheckStatus::NotTested { .. }));
        }
    }
}

#[test]
fn a_backend_is_validated_only_when_every_required_check_passed_here() {
    let registry = registry();
    let os = OsKind::Linux;
    let examine = |results: CheckInputs| {
        Doctor::new()
            .examine(
                &request(os, "6.8.0-45", "host-a", strict()),
                &context(&registry, "host-a", os),
                BTreeMap::from([(BackendKind::Firecracker, results)]),
            )
            .unwrap()
    };
    let firecracker = |report: &DoctorReport| report.candidates[0].clone();

    let all = examine(all_passing(&registry, os, "host-a"));
    assert_eq!(firecracker(&all).label, Label::Validated);
    assert!(firecracker(&all).blocking.is_empty());
    assert!(firecracker(&all).report.allows_launch());
    // The other candidate got no results: still unavailable.
    assert_eq!(all.candidates[1].label, Label::Unavailable);

    // One required check without a result: experimental, and launch is refused.
    let required = required_rows(&strict());
    let mut partial = all_passing(&registry, os, "host-a");
    partial.remove(&required[0]);
    let report = examine(partial);
    assert_eq!(firecracker(&report).label, Label::Experimental);
    assert_eq!(firecracker(&report).blocking, vec![required[0]]);
    assert!(!firecracker(&report).report.allows_launch());

    // One required check failing: unavailable.
    let failing_row = catalog()
        .iter()
        .find(|row| {
            let control = row.control().map(|entry| entry.id);
            required.contains(&row.id)
                && row.id != vm_cp_05()
                && row.expectations().any(|entry| {
                    entry.part == Part::Primary
                        && entry.scope.applies(os)
                        && Some(entry.id) != control
                })
        })
        .unwrap();
    let mut failing = all_passing(&registry, os, "host-a");
    failing.insert(
        failing_row.id,
        outcomes(&registry, failing_row, "host-a", |part| {
            let mut observations = passing(failing_row, part, os);
            if part == Part::Primary {
                let control = failing_row.control().map(|entry| entry.id);
                let (id, entry) = failing_row
                    .expectations()
                    .filter(|entry| {
                        entry.part == Part::Primary
                            && entry.scope.applies(os)
                            && Some(entry.id) != control
                    })
                    .map(|entry| (entry.id, entry))
                    .next()
                    .unwrap();
                observations.insert(id, violating(entry.expect));
            }
            observations
        }),
    );
    let report = examine(failing);
    assert!(matches!(
        report.candidates[0]
            .report
            .entry(failing_row.id)
            .unwrap()
            .status,
        CheckStatus::Failed { .. }
    ));
    assert_eq!(firecracker(&report).label, Label::Unavailable);
}

#[test]
fn the_doctor_says_what_changed_since_it_last_looked() {
    let registry = registry();
    let os = OsKind::Linux;
    let mut doctor = Doctor::new();
    let first = doctor
        .examine(
            &request(os, "6.8.0-45", "host-a", strict()),
            &context(&registry, "host-a", os),
            BTreeMap::new(),
        )
        .unwrap();
    assert!(first.changes.is_empty());

    // Nothing changed: nothing reported.
    let same = doctor
        .examine(
            &request(os, "6.8.0-45", "host-a", strict()),
            &context(&registry, "host-a", os),
            BTreeMap::new(),
        )
        .unwrap();
    assert!(same.changes.is_empty());

    // Firecracker's checks now pass under a new configuration.
    let later = doctor
        .examine(
            &request(os, "6.8.0-45", "host-b", strict()),
            &context(&registry, "host-b", os),
            BTreeMap::from([(
                BackendKind::Firecracker,
                all_passing(&registry, os, "host-b"),
            )]),
        )
        .unwrap();
    let firecracker = later
        .changes
        .iter()
        .find_map(|change| match change {
            DoctorChange::Report { backend, changes } if *backend == BackendKind::Firecracker => {
                Some(changes)
            }
            _ => None,
        })
        .unwrap();
    assert!(firecracker.configuration_changed);
    assert!(!firecracker.launch_allowed_before && firecracker.launch_allowed_now);
    assert_eq!(firecracker.checks.len(), catalog().len());
    // QEMU's statuses stayed not tested, but its configuration changed too.
    assert!(later.changes.iter().any(|change| matches!(
        change,
        DoctorChange::Report { backend: BackendKind::Qemu, changes } if changes.configuration_changed && changes.checks.is_empty()
    )));

    // A new kernel build: earlier results say nothing about this host.
    let upgraded = doctor
        .examine(
            &request(os, "6.11.0-9", "host-b", strict()),
            &context(&registry, "host-b", os),
            BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(upgraded.changes.len(), 2);
    for change in &upgraded.changes {
        match change {
            DoctorChange::Host { before, after, .. } => {
                assert_eq!(before.build.as_str(), "6.8.0-45");
                assert_eq!(after.build.as_str(), "6.11.0-9");
            }
            other => panic!("expected a host change, got {other:?}"),
        }
    }
}

#[test]
fn the_doctor_refuses_what_it_cannot_examine() {
    let registry = registry();
    let mut doctor = Doctor::new();
    assert_eq!(
        doctor.examine(
            &request(OsKind::Linux, "6.8.0-45", "host-a", BTreeSet::new()),
            &context(&registry, "host-a", OsKind::Linux),
            BTreeMap::new(),
        ),
        Err(DoctorError::NoProfiles)
    );
    assert_eq!(
        doctor.examine(
            &request(OsKind::Linux, "6.8.0-45", "host-a", strict()),
            &context(&registry, "host-a", OsKind::Linux),
            BTreeMap::from([(BackendKind::Hcs, CheckInputs::new())]),
        ),
        Err(DoctorError::NotACandidate {
            backend: BackendKind::Hcs
        })
    );
    assert_eq!(
        doctor.examine(
            &request(OsKind::Linux, "6.8.0-45", "host-a", strict()),
            &context(&registry, "host-a", OsKind::Windows),
            BTreeMap::new(),
        ),
        Err(DoctorError::Report {
            backend: BackendKind::Firecracker,
            refusal: ReportError::OtherHost {
                profile: OsKind::Linux,
                context: OsKind::Windows
            }
        })
    );
    assert!(DoctorError::NoProfiles.to_string().contains("run profile"));
}

#[test]
fn inside_wsl2_the_doctor_explains_there_is_no_backend() {
    let registry = registry();
    let report = Doctor::new()
        .examine(
            &request(OsKind::Wsl2, "6.6.87.2", "host-a", strict()),
            &context(&registry, "host-a", OsKind::Wsl2),
            BTreeMap::new(),
        )
        .unwrap();
    assert!(report.candidates.is_empty());
    assert!(report.no_backend.unwrap().contains("VM-W20"));
}

#[test]
fn an_untested_gpu_path_is_explained_when_a_gpu_vm_is_asked_for() {
    let registry = registry();
    let profiles = BTreeSet::from([RunProfile::Strict, RunProfile::GpuVm]);
    let report = Doctor::new()
        .examine(
            &request(OsKind::Linux, "6.8.0-45", "host-a", profiles),
            &context(&registry, "host-a", OsKind::Linux),
            BTreeMap::new(),
        )
        .unwrap();
    match report.candidates[0].report.gpu() {
        GpuPath::Unavailable { status, why } => {
            assert!(matches!(status, CheckStatus::NotTested { .. }));
            assert!(!why.is_empty());
        }
        other => panic!("expected an unavailable GPU path, got {other:?}"),
    }
}

#[test]
fn the_plan_describes_every_check_and_runs_none() {
    for os in [OsKind::Windows, OsKind::Linux, OsKind::MacOs, OsKind::Wsl2] {
        let profiles = strict();
        let plan = plan(os, &profiles);
        assert_eq!(plan.notice, PLAN_NOTICE);
        assert_eq!(plan.checks.len(), catalog().len());
        for (planned, row) in plan.checks.iter().zip(catalog()) {
            assert_eq!(planned.check, row.id);
            assert_eq!(planned.required, row.required_for(&profiles));
            assert_eq!(planned.runs_here, row.runs_on(os));
            match row.positive_control {
                PositiveControl::Expectation { .. } => {
                    assert_eq!(planned.control, row.control().map(|entry| entry.says));
                    assert!(planned.control.is_some());
                }
                PositiveControl::NotListed { note } => {
                    assert_eq!(planned.control, None);
                    assert_eq!(planned.note, note);
                }
            }
            let applying = row
                .expectations()
                .filter(|entry| entry.scope.applies(os))
                .count();
            assert_eq!(planned.observes.len(), applying);
        }
        let json = serde_json::to_string(&plan).unwrap();
        assert!(!json.contains("score"));
    }
}

#[test]
fn profile_names_are_the_report_names() {
    for profile in RunProfile::ALL {
        let name = serde_json::to_value(profile).unwrap();
        assert_eq!(run_profile(name.as_str().unwrap()), Some(profile));
    }
    assert_eq!(run_profile("gpu_vm"), Some(RunProfile::GpuVm));
    assert_eq!(run_profile("Strict"), None);
    assert_eq!(run_profile("lenient"), None);
}

#[test]
fn a_report_serializes_with_its_notice_and_no_score() {
    let registry = registry();
    let report = Doctor::new()
        .examine(
            &request(OsKind::MacOs, "24.6.0", "host-a", strict()),
            &context(&registry, "host-a", OsKind::MacOs),
            BTreeMap::new(),
        )
        .unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["notice"], DOCTOR_NOTICE);
    assert_eq!(json["candidates"][0]["label"], "unavailable");
    assert_eq!(
        json["candidates"][0]["candidate"]["backend"],
        "virtualization_framework"
    );
    assert!(!json.to_string().contains("score"));
    assert_eq!(
        report.candidates[0]
            .report
            .entries()
            .iter()
            .filter(|entry| entry.applicability == Applicability::Required)
            .count(),
        required_rows(&strict()).len()
    );
}

// ---------------------------------------------------------------- results from launch records

const LINUX_BUILD: &str = "6.8.0-45";

fn machine() -> Digest {
    digest("yougori/test/doctor/machine/v1", &[b"m"])
}

fn root_image() -> Digest {
    digest("yougori/test/doctor/image/v1", &[b"root"])
}

/// The QEMU build the records are about.
fn qemu() -> BackendIdentity {
    BackendIdentity::new(
        BackendKind::Qemu,
        "9.2.0",
        digest("yougori/test/doctor/backend/v1", &[b"qemu"]),
        HypervisorKind::Kvm,
    )
    .unwrap()
}

/// A registry on a manual clock whose hypervisor probe found KVM available under `config`.
fn kvm_host(config: &str) -> (ProbeRegistry<Arc<ManualClock>>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000)));
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = FakeProbe::hypervisor_availability();
    let subject = Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: HypervisorKind::Kvm,
    });
    probe.respond(
        &subject,
        Observation::supported(
            configuration(config),
            FRESH,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Kvm,
            },
        ),
    );
    registry.register(Box::new(probe)).unwrap();
    registry
        .refresh(Capability::HypervisorAvailable, &subject)
        .unwrap();
    (registry, clock)
}

fn launch_request(execution: &str, boot: u64, config: &str) -> LaunchRequest {
    LaunchRequest {
        execution: ExecutionId::new(execution).unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        generations: SandboxGenerations {
            boot: crate::foundation::ids::SandboxBootGeneration::new(boot),
            ..SandboxGenerations::FIRST
        },
        machine: machine(),
        configuration: configuration(config),
        contract: digest("yougori/test/doctor/contract/v1", &[b"c1"]),
        pinned: PinnedArtifacts {
            guest_image: root_image(),
            backend: qemu().artifact,
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/doctor/profile/v1", &[b"minimal"]),
            devices: Default::default(),
        },
        required: RequiredProperties::strictest(Duration::from_secs(60)),
        reservation: serde_json::from_value::<ReservationId>(1.into()).unwrap(),
    }
}

/// A record the backend contract's own admission seals for the QEMU build, with the host
/// observing `host` and a clean hardware VM.
fn admitted(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    request: &LaunchRequest,
    host: HostBuild,
    restored_from: Option<SnapshotId>,
) -> LaunchRecord {
    let identity = qemu();
    let evidence = precheck(request, &identity, &BackendFeatures::none(), registry).unwrap();
    let facts = HostScript::hardware_vm(
        HypervisorKind::Kvm,
        host,
        root_image(),
        request.configuration,
    )
    .facts(registry.now());
    admit(
        request,
        &identity,
        registry,
        evidence,
        facts,
        vm_handle(
            BackendKind::Qemu,
            &request.execution,
            request.generations.boot,
        ),
        restored_from,
    )
    .unwrap()
}

/// QEMU's records on this Linux host: a normal launch, two clones of one snapshot and a
/// launch with the hypervisor forced unavailable that was not refused.
fn qemu_records(registry: &ProbeRegistry<Arc<ManualClock>>, config: &str) -> RecordResults {
    let linux = host(OsKind::Linux, LINUX_BUILD);
    let golden = SnapshotId::new(digest("yougori/test/doctor/snapshot/v1", &[b"golden"]));
    let mut records = RecordResults::new(linux.clone(), qemu());
    records
        .record(admitted(
            registry,
            &launch_request("exe-1", 1, config),
            linux.clone(),
            None,
        ))
        .unwrap();
    for boot in [2, 3] {
        records
            .record(admitted(
                registry,
                &launch_request("exe-1", boot, config),
                linux.clone(),
                Some(golden),
            ))
            .unwrap();
    }
    records
        .negative(
            ControlledFault::HypervisorUnavailable,
            NegativeOutcome::Launched {
                record: Box::new(admitted(
                    registry,
                    &launch_request("exe-2", 1, config),
                    linux,
                    None,
                )),
            },
        )
        .unwrap();
    records
}

fn qemu_report(report: &DoctorReport) -> &CandidateReport {
    report
        .candidates
        .iter()
        .find(|candidate| candidate.candidate.backend == BackendKind::Qemu)
        .unwrap()
}

#[test]
fn results_from_launch_records_are_judged_and_listed_with_their_age() {
    let (registry, clock) = kvm_host("host-a");
    let records = qemu_records(&registry, "host-a");
    clock.advance(Duration::from_secs(20));
    let report = Doctor::new()
        .examine_with_records(
            &request(OsKind::Linux, LINUX_BUILD, "host-a", strict()),
            &context(&registry, "host-a", OsKind::Linux),
            BTreeMap::new(),
            &[records],
        )
        .unwrap();
    assert_eq!(report.results, 3);
    assert_eq!(report.from_launch_records, 3);

    let qemu = qemu_report(&report);
    let listed: Vec<(u8, Part)> = qemu
        .from_launch_records
        .iter()
        .map(|result| (result.check.number(), result.part))
        .collect();
    assert_eq!(
        listed,
        vec![
            (1, Part::Primary),
            (
                21,
                Part::Corroboration {
                    fact: CorroboratingFact::CloneIdentities
                }
            ),
            (33, Part::Primary),
        ]
    );
    for result in &qemu.from_launch_records {
        assert_eq!(
            result.age,
            RecordAge::Observed {
                age: Duration::from_secs(20)
            }
        );
        assert!(!result.records.is_empty());
        assert_eq!(result.refusals, 0);
    }
    assert_eq!(qemu.from_launch_records[1].records.len(), 2);
    // The launch that should have been refused fails VM-CP-01 and VM-CP-33, which every VM
    // sandbox requires; the clone corroboration alone leaves VM-CP-21 not tested.
    let status = |number: u8| {
        qemu.report
            .entry(CheckId::new(number).unwrap())
            .unwrap()
            .status
            .clone()
    };
    assert!(matches!(status(1), CheckStatus::Failed { .. }));
    assert!(matches!(status(33), CheckStatus::Failed { .. }));
    assert!(matches!(status(21), CheckStatus::NotTested { .. }));
    assert_eq!(qemu.label, Label::Unavailable);
    assert!(qemu.blocking.contains(&CheckId::new(1).unwrap()));
    assert_eq!(qemu.required.failed, 2);
    // Firecracker got nothing from QEMU's records.
    let firecracker = &report.candidates[0];
    assert_eq!(firecracker.candidate.backend, BackendKind::Firecracker);
    assert!(firecracker.from_launch_records.is_empty());
    assert_eq!(firecracker.required.passed, 0);

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["from_launch_records"], 3);
    assert_eq!(
        json["candidates"][1]["from_launch_records"][0]["age"]["kind"],
        "observed"
    );
    assert!(!json.to_string().contains("score"));
}

#[test]
fn launch_record_results_go_stale_and_the_doctor_says_what_changed() {
    let (registry, clock) = kvm_host("host-a");
    let records = qemu_records(&registry, "host-a");
    let mut doctor = Doctor::new();
    let examine = |doctor: &mut Doctor| {
        doctor
            .examine_with_records(
                &request(OsKind::Linux, LINUX_BUILD, "host-a", strict()),
                &context(&registry, "host-a", OsKind::Linux),
                BTreeMap::new(),
                std::slice::from_ref(&records),
            )
            .unwrap()
    };
    let first = examine(&mut doctor);
    assert!(matches!(
        qemu_report(&first)
            .report
            .entry(CheckId::new(1).unwrap())
            .unwrap()
            .status,
        CheckStatus::Failed { .. }
    ));
    // Past the reader's maximum age, the records' facts are no longer current.
    clock.advance(MAX_AGE + Duration::from_secs(1));
    let later = examine(&mut doctor);
    let qemu = qemu_report(&later);
    assert!(matches!(
        qemu.report.entry(CheckId::new(1).unwrap()).unwrap().status,
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent { .. }
        }
    ));
    assert_eq!(
        qemu.from_launch_records[0].age,
        RecordAge::Observed {
            age: MAX_AGE + Duration::from_secs(1)
        }
    );
    let change = later
        .changes
        .iter()
        .find_map(|change| match change {
            DoctorChange::Report { backend, changes } if *backend == BackendKind::Qemu => {
                Some(changes)
            }
            _ => None,
        })
        .unwrap();
    assert!(!change.configuration_changed);
    let changed: Vec<u8> = change
        .checks
        .iter()
        .map(|check| check.check.number())
        .collect();
    // VM-CP-21 stays not tested: its guest-reported part is missing either way.
    assert_eq!(changed, vec![1, 33]);
}

#[test]
fn launch_records_add_to_given_results_and_what_does_not_belong_is_refused() {
    let (registry, _clock) = kvm_host("host-a");
    let records = qemu_records(&registry, "host-a");
    let linux_request = request(OsKind::Linux, LINUX_BUILD, "host-a", strict());
    let linux_context = context(&registry, "host-a", OsKind::Linux);

    // A host outcome given directly for VM-CP-21 joins the record's corroboration.
    let approval = ProbeOutcome::host(
        CheckId::new(21).unwrap(),
        Part::Corroboration {
            fact: CorroboratingFact::PreSnapshotApprovalRefused,
        },
        HostKind::Host,
        registry.now(),
        FRESH,
        configuration("host-a"),
        RunResult::Observed {
            observations: Observations::new(),
        },
    )
    .unwrap();
    let given = BTreeMap::from([(
        BackendKind::Qemu,
        CheckInputs::from([(
            CheckId::new(21).unwrap(),
            CheckInput::Outcomes(vec![approval]),
        )]),
    )]);
    let report = Doctor::new()
        .examine_with_records(
            &linux_request,
            &linux_context,
            given,
            std::slice::from_ref(&records),
        )
        .unwrap();
    assert_eq!(report.results, 3);
    assert_eq!(report.from_launch_records, 3);
    assert!(matches!(
        qemu_report(&report)
            .report
            .entry(CheckId::new(21).unwrap())
            .unwrap()
            .status,
        CheckStatus::NotTested { .. }
    ));

    // A confinement verdict and record outcomes for one check conflict.
    let verdict = CheckInput::Vm05(Vm05Evaluation::evaluated(
        ConfinementVerdict {
            profile: digest("yougori/test/doctor/profile/v1", &[b"strict-tool"]),
            workload: WorkloadProfile::StrictTool,
            meaning: VerdictMeaning::InnerControlsDefenseInDepth,
            host_corroboration_required: true,
            checks: Vec::new(),
            outcome: VerdictOutcome::Passed,
        },
        registry.now(),
        FRESH,
        configuration("host-a"),
    ));
    let conflicting = BTreeMap::from([(
        BackendKind::Qemu,
        CheckInputs::from([(CheckId::new(1).unwrap(), verdict)]),
    )]);
    let mut doctor = Doctor::new();
    assert_eq!(
        doctor.examine_with_records(
            &linux_request,
            &linux_context,
            conflicting,
            std::slice::from_ref(&records),
        ),
        Err(DoctorError::ConflictingResults {
            backend: BackendKind::Qemu,
            check: CheckId::new(1).unwrap()
        })
    );
    // Two sets for one backend, or records of another host build, are refused.
    assert_eq!(
        doctor.examine_with_records(
            &linux_request,
            &linux_context,
            BTreeMap::new(),
            &[records.clone(), records.clone()],
        ),
        Err(DoctorError::RecordsGivenTwice {
            backend: BackendKind::Qemu
        })
    );
    let upgraded = request(OsKind::Linux, "6.11.0-9", "host-a", strict());
    assert_eq!(
        doctor.examine_with_records(
            &upgraded,
            &linux_context,
            BTreeMap::new(),
            std::slice::from_ref(&records),
        ),
        Err(DoctorError::RecordsOfOtherHost {
            backend: BackendKind::Qemu
        })
    );
    // The same outcomes given directly are still bound to their backend and host.
    assert_eq!(
        doctor.examine(
            &linux_request,
            &linux_context,
            BTreeMap::from([(BackendKind::Firecracker, records.inputs())]),
        ),
        Err(DoctorError::RecordsOfOtherBackend {
            backend: BackendKind::Firecracker,
            records: BackendKind::Qemu
        })
    );
    assert_eq!(
        doctor.examine(
            &upgraded,
            &linux_context,
            BTreeMap::from([(BackendKind::Qemu, records.inputs())]),
        ),
        Err(DoctorError::RecordsOfOtherHost {
            backend: BackendKind::Qemu
        })
    );
    // The fake backend certifies nothing: its records are not a candidate's.
    let fake = BackendIdentity::new(
        BackendKind::Fake,
        "0.1.0",
        digest("yougori/test/doctor/backend/v1", &[b"fake"]),
        HypervisorKind::Kvm,
    )
    .unwrap();
    assert_eq!(
        doctor.examine_with_records(
            &linux_request,
            &linux_context,
            BTreeMap::new(),
            &[RecordResults::new(host(OsKind::Linux, LINUX_BUILD), fake)],
        ),
        Err(DoctorError::NotACandidate {
            backend: BackendKind::Fake
        })
    );
    for error in [
        DoctorError::ConflictingResults {
            backend: BackendKind::Qemu,
            check: CheckId::new(1).unwrap(),
        },
        DoctorError::RecordsGivenTwice {
            backend: BackendKind::Qemu,
        },
        DoctorError::RecordsOfOtherHost {
            backend: BackendKind::Qemu,
        },
        DoctorError::RecordsOfOtherBackend {
            backend: BackendKind::Firecracker,
            records: BackendKind::Qemu,
        },
    ] {
        assert!(error.to_string().contains("Qemu"));
        assert!(serde_json::to_value(&error).unwrap()["error"].is_string());
    }
}

// ---------------------------------------------------------------- the engine's own words

/// A required check other than VM-CP-05 with a primary observation (not its positive
/// control) on `os`, and results for `backend` passing every check but violating that one
/// observation, with the expectation violated.
fn one_failing(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    os: OsKind,
    config: &str,
) -> (CheckId, &'static Expectation, CheckInputs) {
    let required = required_rows(&strict());
    let (row, violated) = catalog()
        .iter()
        .filter(|row| required.contains(&row.id) && row.id != vm_cp_05())
        .find_map(|row| {
            let control = row.control().map(|entry| entry.id);
            row.expectations()
                .find(|entry| {
                    entry.part == Part::Primary
                        && entry.scope.applies(os)
                        && Some(entry.id) != control
                })
                .map(|entry| (row, entry))
        })
        .unwrap();
    let mut inputs = all_passing(registry, os, config);
    inputs.insert(
        row.id,
        outcomes(registry, row, config, |part| {
            let mut observations = passing(row, part, os);
            if part == Part::Primary {
                observations.insert(violated.id, violating(violated.expect));
            }
            observations
        }),
    );
    (row.id, violated, inputs)
}

#[test]
fn every_check_that_did_not_pass_carries_the_engines_reason_and_what_it_expects_here() {
    let registry = registry();
    for (os, build) in [
        (OsKind::Windows, "26200"),
        (OsKind::Linux, LINUX_BUILD),
        (OsKind::MacOs, "24.6.0"),
    ] {
        let profiles = BTreeSet::from([RunProfile::Strict, RunProfile::GpuVm]);
        let report = Doctor::new()
            .examine(
                &request(os, build, "host-a", profiles.clone()),
                &context(&registry, "host-a", os),
                BTreeMap::new(),
            )
            .unwrap();
        let planned = plan(os, &profiles);
        for candidate in &report.candidates {
            assert_eq!(candidate.not_passed.len(), catalog().len());
            for ((explained, entry), planned) in candidate
                .not_passed
                .iter()
                .zip(candidate.report.entries())
                .zip(&planned.checks)
            {
                assert_eq!(explained.check, entry.check);
                assert_eq!(
                    explained.required,
                    entry.applicability == Applicability::Required
                );
                assert_eq!(explained.status, StatusText::of(&entry.status));
                assert_eq!(explained.status.status, StatusKind::NotTested);
                assert!(explained.status.reason.starts_with("not tested: "));
                // What it expects here is what the dry run says it would observe here.
                assert_eq!(explained.check, planned.check);
                assert_eq!(explained.expects, planned.observes);
            }
            let required: Vec<CheckId> = candidate
                .not_passed
                .iter()
                .filter(|explained| explained.required)
                .map(|explained| explained.check)
                .collect();
            assert_eq!(candidate.blocking, required);
        }
        // Off Linux, VM-CP-31 says why it cannot run here, in the engine's words.
        let gpu = &report.candidates[0].not_passed[30];
        assert_eq!(gpu.check, CheckId::new(31).unwrap());
        let observes = gpu
            .expects
            .iter()
            .filter(|observation| observation.role == Role::Observation)
            .count();
        if os == OsKind::Linux {
            assert_eq!(gpu.status.reason, "not tested: it was not run");
            assert!(observes > 0);
        } else {
            assert!(gpu.status.reason.contains("no observation for a"));
            assert_eq!(observes, 0);
        }
    }

    // A failed check says what it expected, in the expectation table's words; a backend
    // whose checks all passed explains nothing.
    let os = OsKind::Linux;
    let (failed, violated, inputs) = one_failing(&registry, os, "host-a");
    let report = Doctor::new()
        .examine(
            &request(os, LINUX_BUILD, "host-a", strict()),
            &context(&registry, "host-a", os),
            BTreeMap::from([(BackendKind::Firecracker, inputs)]),
        )
        .unwrap();
    let firecracker = &report.candidates[0];
    assert_eq!(firecracker.not_passed.len(), 1);
    let explained = &firecracker.not_passed[0];
    assert_eq!(explained.check, failed);
    assert!(explained.required);
    assert_eq!(explained.status.status, StatusKind::Failed);
    assert_eq!(
        explained.status.reason,
        format!("failed: expected that {}", violated.says)
    );
    assert!(explained
        .expects
        .iter()
        .any(|observation| observation.id == violated.id && observation.says == violated.says));
    let passing = Doctor::new()
        .examine(
            &request(os, LINUX_BUILD, "host-a", strict()),
            &context(&registry, "host-a", os),
            BTreeMap::from([(
                BackendKind::Firecracker,
                all_passing(&registry, os, "host-a"),
            )]),
        )
        .unwrap();
    assert!(passing.candidates[0].not_passed.is_empty());

    // The written form: the status kind and the reason as text, beside the expectations.
    let json = serde_json::to_value(&report).unwrap();
    let written = &json["candidates"][0]["not_passed"][0];
    assert_eq!(written["check"], failed.to_string());
    assert_eq!(written["required"], true);
    assert_eq!(written["status"], "failed");
    assert_eq!(written["reason"], explained.status.reason.as_str());
    assert!(written["expects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|observation| observation["id"] == violated.id.as_str()
            && observation["says"] == violated.says));
    assert!(!json.to_string().contains("score"));
}

#[test]
fn changes_since_the_previous_report_are_worded_by_the_engine() {
    let registry = registry();
    let os = OsKind::Linux;
    let mut doctor = Doctor::new();
    doctor
        .examine(
            &request(os, LINUX_BUILD, "host-a", strict()),
            &context(&registry, "host-a", os),
            BTreeMap::new(),
        )
        .unwrap();
    let (failed, violated, inputs) = one_failing(&registry, os, "host-a");
    let report = doctor
        .examine(
            &request(os, LINUX_BUILD, "host-a", strict()),
            &context(&registry, "host-a", os),
            BTreeMap::from([(BackendKind::Firecracker, inputs)]),
        )
        .unwrap();
    assert_eq!(
        report.history.compared,
        vec![BackendKind::Firecracker, BackendKind::Qemu]
    );
    let [DoctorChange::Report { backend, changes }] = report.changes.as_slice() else {
        panic!("expected one report change, got {:?}", report.changes);
    };
    assert_eq!(*backend, BackendKind::Firecracker);
    assert!(!changes.configuration_changed);
    assert!(!changes.launch_allowed_before && !changes.launch_allowed_now);
    let not_run = StatusText {
        status: StatusKind::NotTested,
        reason: "not tested: it was not run".to_owned(),
    };
    let to_failed = changes
        .checks
        .iter()
        .find(|change| change.check == failed)
        .unwrap();
    assert_eq!(to_failed.before, not_run);
    assert_eq!(
        to_failed.after,
        StatusText {
            status: StatusKind::Failed,
            reason: format!("failed: expected that {}", violated.says),
        }
    );
    for change in changes
        .checks
        .iter()
        .filter(|change| change.check != failed)
    {
        assert_eq!(change.before, not_run);
        assert_eq!(change.after.status, StatusKind::Passed);
        assert_eq!(change.after.reason, "passed");
    }
    let json = serde_json::to_value(&report.changes).unwrap();
    assert_eq!(json[0]["change"], "report");
    assert_eq!(
        json[0]["changes"]["checks"][0]["before"],
        serde_json::json!({ "status": "not_tested", "reason": "not tested: it was not run" })
    );
}

// ---------------------------------------------------------------- the kept history

/// A store in memory that a test can look into, damage and make fail.
#[derive(Clone, Default)]
struct FakeStore {
    kept: Rc<RefCell<Option<Vec<u8>>>>,
    reads: Rc<RefCell<usize>>,
    read_fails: Option<&'static str>,
    replace_fails: Option<&'static str>,
}

impl FakeStore {
    fn holding(bytes: Vec<u8>) -> Self {
        let store = Self::default();
        store.kept.replace(Some(bytes));
        store
    }

    fn kept(&self) -> Vec<RememberedReport> {
        decode_history(self.kept.borrow().as_deref().unwrap()).unwrap()
    }
}

impl HistoryStore for FakeStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreFailure> {
        *self.reads.borrow_mut() += 1;
        match self.read_fails {
            Some(detail) => Err(StoreFailure {
                detail: detail.to_owned(),
            }),
            None => Ok(self.kept.borrow().clone()),
        }
    }

    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreFailure> {
        match self.replace_fails {
            Some(detail) => Err(StoreFailure {
                detail: detail.to_owned(),
            }),
            None => {
                self.kept.replace(Some(bytes.to_vec()));
                Ok(())
            }
        }
    }
}

/// One examination of a Linux host under `config`, with `results`.
fn linux_look<S: HistoryStore>(
    doctor: &mut Doctor<S>,
    registry: &ProbeRegistry<Arc<ManualClock>>,
    build: &str,
    config: &str,
    results: BTreeMap<BackendKind, CheckInputs>,
) -> DoctorReport {
    doctor
        .examine(
            &request(OsKind::Linux, build, config, strict()),
            &context(registry, config, OsKind::Linux),
            results,
        )
        .unwrap()
}

/// The history a doctor keeps after one Linux examination under `config`.
fn history_under(config: &str) -> Vec<u8> {
    let registry = registry();
    let store = FakeStore::default();
    linux_look(
        &mut Doctor::with_store(store.clone()),
        &registry,
        LINUX_BUILD,
        config,
        BTreeMap::new(),
    );
    let bytes = store.kept.borrow().clone().unwrap();
    bytes
}

#[test]
fn a_doctor_with_a_store_says_what_changed_since_the_report_kept_before_a_restart() {
    let registry = registry();
    let store = FakeStore::default();
    let first = linux_look(
        &mut Doctor::with_store(store.clone()),
        &registry,
        LINUX_BUILD,
        "host-a",
        BTreeMap::new(),
    );
    assert!(first.changes.is_empty());
    assert_eq!(first.history, History::default());
    let kept = store.kept();
    assert_eq!(
        kept,
        vec![
            RememberedReport::of(&first.candidates[0].report),
            RememberedReport::of(&first.candidates[1].report),
        ]
    );
    assert_eq!(kept[0].backend, BackendKind::Firecracker);
    assert_eq!(kept[0].checks.len(), catalog().len());

    // The engine restarts: a new doctor on the same store compares with what it kept.
    let mut restarted = Doctor::with_store(store.clone());
    let passing = BTreeMap::from([(
        BackendKind::Firecracker,
        all_passing(&registry, OsKind::Linux, "host-b"),
    )]);
    let later = linux_look(
        &mut restarted,
        &registry,
        LINUX_BUILD,
        "host-b",
        passing.clone(),
    );
    assert_eq!(
        later.history,
        History {
            compared: vec![BackendKind::Firecracker, BackendKind::Qemu],
            ignored: None,
            not_kept: None,
        }
    );
    assert_eq!(
        serde_json::to_value(&later).unwrap()["history"],
        serde_json::json!({ "compared": ["firecracker", "qemu"], "ignored": null, "not_kept": null })
    );
    let firecracker = later
        .changes
        .iter()
        .find_map(|change| match change {
            DoctorChange::Report { backend, changes } if *backend == BackendKind::Firecracker => {
                Some(changes)
            }
            _ => None,
        })
        .unwrap();
    assert!(firecracker.configuration_changed);
    assert!(!firecracker.launch_allowed_before && firecracker.launch_allowed_now);
    assert_eq!(firecracker.checks.len(), catalog().len());
    assert!(firecracker.checks.iter().all(|change| change.before.reason
        == "not tested: it was not run"
        && change.after.status == StatusKind::Passed));
    assert_eq!(
        store.kept()[0],
        RememberedReport::of(&later.candidates[0].report)
    );

    // The doctor reads its store once: what the store holds later is not read again, and
    // the next examination compares with the doctor's own previous report.
    store
        .kept
        .replace(Some(b"overwritten behind the doctor's back".to_vec()));
    let again = linux_look(&mut restarted, &registry, LINUX_BUILD, "host-b", passing);
    assert!(again.changes.is_empty());
    assert_eq!(again.history.ignored, None);
    assert_eq!(*store.reads.borrow(), 2);
    assert_eq!(store.kept().len(), 2);

    // A restart onto a new kernel build: the kept reports say nothing about this host.
    let upgraded = linux_look(
        &mut Doctor::with_store(store.clone()),
        &registry,
        "6.11.0-9",
        "host-b",
        BTreeMap::new(),
    );
    assert_eq!(upgraded.changes.len(), 2);
    assert!(upgraded.changes.iter().all(|change| matches!(
        change,
        DoctorChange::Host { before, after, .. }
            if before.build.as_str() == LINUX_BUILD && after.build.as_str() == "6.11.0-9"
    )));
}

#[test]
fn a_kept_history_says_what_the_same_doctor_would_have_said_in_memory() {
    let registry = registry();
    let os = OsKind::Linux;
    let (_, _, failing) = one_failing(&registry, os, "host-b");
    let looks: Vec<(&str, &str, BTreeMap<BackendKind, CheckInputs>)> = vec![
        (LINUX_BUILD, "host-a", BTreeMap::new()),
        (
            LINUX_BUILD,
            "host-b",
            BTreeMap::from([(BackendKind::Qemu, all_passing(&registry, os, "host-b"))]),
        ),
        (
            LINUX_BUILD,
            "host-b",
            BTreeMap::from([(BackendKind::Qemu, failing)]),
        ),
        ("6.11.0-9", "host-b", BTreeMap::new()),
        ("6.11.0-9", "host-b", BTreeMap::new()),
    ];
    let mut in_memory = Doctor::new();
    let store = FakeStore::default();
    for (build, config, results) in looks {
        let remembered = linux_look(&mut in_memory, &registry, build, config, results.clone());
        let restarted = linux_look(
            &mut Doctor::with_store(store.clone()),
            &registry,
            build,
            config,
            results,
        );
        assert_eq!(restarted.changes, remembered.changes);
        assert_eq!(restarted.history, remembered.history);
    }
}

#[test]
fn a_damaged_history_is_reported_and_ignored_and_then_replaced() {
    // Every damaged history below would, if trusted, say the configuration changed.
    let valid = history_under("host-z");
    let reports = decode_history(&valid).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    let edited = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut value = document.clone();
        edit(&mut value);
        serde_json::to_vec(&value).unwrap()
    };
    let mut shuffled = reports[0].clone();
    shuffled.checks.swap(0, 1);
    let mut short = reports[0].clone();
    short.checks.pop();

    let cases: Vec<(&str, Vec<u8>, fn(&HistoryError) -> bool)> = vec![
        ("empty", Vec::new(), |error| {
            matches!(error, HistoryError::Unparsable { .. })
        }),
        ("not JSON", b"not a history".to_vec(), |error| {
            matches!(error, HistoryError::Unparsable { .. })
        }),
        ("cut short", valid[..valid.len() / 2].to_vec(), |error| {
            matches!(error, HistoryError::Unparsable { .. })
        }),
        (
            "another format",
            edited(&|value| value["format"] = "yougori/sandbox/doctor/history/v2".into()),
            |error| matches!(error, HistoryError::OtherFormat { format } if format.ends_with("v2")),
        ),
        (
            "an edited reason",
            edited(&|value| value["reports"][0]["checks"][0]["reason"] = "passed".into()),
            |error| *error == HistoryError::DigestMismatch,
        ),
        (
            "an edited launch",
            edited(&|value| value["reports"][1]["launch_allowed"] = true.into()),
            |error| *error == HistoryError::DigestMismatch,
        ),
        (
            "an unknown field",
            edited(&|value| value["reports"][0]["score"] = 1.into()),
            |error| matches!(error, HistoryError::Unparsable { .. }),
        ),
        (
            "an unknown check",
            edited(&|value| value["reports"][0]["checks"][0]["check"] = "VM-CP-36".into()),
            |error| matches!(error, HistoryError::Unparsable { detail } if detail.contains("VM-CP-36")),
        ),
        (
            "a check named loosely",
            edited(&|value| value["reports"][0]["checks"][0]["check"] = "VM-CP-1".into()),
            |error| matches!(error, HistoryError::Unparsable { .. }),
        ),
        (
            "one backend twice",
            encode_history([&reports[0], &reports[0]]).unwrap(),
            |error| {
                *error
                    == HistoryError::BackendTwice {
                        backend: BackendKind::Firecracker,
                    }
            },
        ),
        (
            "checks out of table order",
            encode_history([&shuffled]).unwrap(),
            |error| {
                *error
                    == HistoryError::ChecksNotInTableOrder {
                        backend: BackendKind::Firecracker,
                    }
            },
        ),
        (
            "a check missing",
            encode_history([&short]).unwrap(),
            |error| matches!(error, HistoryError::ChecksNotInTableOrder { .. }),
        ),
        ("too large", vec![b' '; HISTORY_LIMIT + 1], |error| {
            *error
                == HistoryError::TooLarge {
                    bytes: HISTORY_LIMIT + 1,
                }
        }),
    ];
    let registry = registry();
    for (case, bytes, expected) in cases {
        let error = decode_history(&bytes).unwrap_err();
        assert!(expected(&error), "{case}: {error:?}");
        let store = FakeStore::holding(bytes);
        let report = linux_look(
            &mut Doctor::with_store(store.clone()),
            &registry,
            LINUX_BUILD,
            "host-a",
            BTreeMap::new(),
        );
        assert!(report.changes.is_empty(), "{case}: {:?}", report.changes);
        assert!(report.history.compared.is_empty(), "{case}");
        assert_eq!(
            report.history.ignored,
            Some(format!(
                "The previous reports were ignored, and nothing is compared with them: {error}."
            )),
            "{case}"
        );
        assert_eq!(report.history.not_kept, None, "{case}");
        // The damaged history is replaced by this examination.
        assert_eq!(
            store.kept(),
            vec![
                RememberedReport::of(&report.candidates[0].report),
                RememberedReport::of(&report.candidates[1].report),
            ],
            "{case}"
        );
    }
    // The untouched history is trusted, and says the configuration changed.
    let report = linux_look(
        &mut Doctor::with_store(FakeStore::holding(valid)),
        &registry,
        LINUX_BUILD,
        "host-a",
        BTreeMap::new(),
    );
    assert_eq!(report.changes.len(), 2);
    assert_eq!(report.history.ignored, None);
}

#[test]
fn a_store_that_cannot_be_read_or_written_is_reported_and_the_report_stands() {
    let registry = registry();
    let unreadable = FakeStore {
        read_fails: Some("access denied"),
        ..FakeStore::holding(history_under("host-z"))
    };
    let report = linux_look(
        &mut Doctor::with_store(unreadable.clone()),
        &registry,
        LINUX_BUILD,
        "host-a",
        BTreeMap::new(),
    );
    assert!(report.changes.is_empty());
    assert_eq!(
        report.history.ignored.as_deref(),
        Some("The previous reports were ignored, and nothing is compared with them: the store could not be read (access denied).")
    );
    assert_eq!(report.candidates.len(), 2);
    assert_eq!(unreadable.kept().len(), 2);

    let full = FakeStore {
        replace_fails: Some("no space left"),
        ..FakeStore::default()
    };
    let mut doctor = Doctor::with_store(full.clone());
    for look in 0..2 {
        let report = linux_look(
            &mut doctor,
            &registry,
            LINUX_BUILD,
            "host-a",
            BTreeMap::new(),
        );
        assert_eq!(
            report.history.not_kept.as_deref(),
            Some("This report could not be kept for the next examination: the store could not keep it (no space left).")
        );
        // The doctor still compares with its own previous report.
        assert_eq!(report.history.compared.len(), look * 2);
        assert!(report.changes.is_empty());
    }
    assert!(full.kept.borrow().is_none());
}

#[test]
fn the_kept_history_reads_strictly_and_writes_back_unchanged() {
    let sample = history_under("host-a");
    let reports = decode_history(&sample).unwrap();
    assert_eq!(encode_history(&reports).unwrap(), sample);
    let text = String::from_utf8(sample.clone()).unwrap();
    assert!(text.starts_with(&format!("{{\"format\":\"{HISTORY_FORMAT}\",\"digest\":\"")));

    // A string enum written as its variant index is refused, at every depth.
    let document: serde_json::Value = serde_json::from_slice(&sample).unwrap();
    let indexed: [(&[&str], u64); 4] = [
        (&["reports", "0", "backend"], 1),
        (&["reports", "0", "host", "os"], 1),
        (&["reports", "0", "host", "architecture"], 0),
        (&["reports", "0", "checks", "0", "status"], 3),
    ];
    for (path, index) in indexed {
        let mut value = document.clone();
        let mut at = &mut value;
        for key in path {
            at = match key.parse::<usize>() {
                Ok(position) => &mut at[position],
                Err(_) => &mut at[*key],
            };
        }
        assert!(at.is_string(), "{path:?}");
        *at = index.into();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            matches!(decode_history(&bytes), Err(HistoryError::Unparsable { .. })),
            "{path:?}"
        );
    }

    // A field repeated in one object is refused, at every depth.
    for (once, twice) in [
        (
            format!("\"format\":\"{HISTORY_FORMAT}\""),
            format!("\"format\":\"{HISTORY_FORMAT}\",\"format\":\"{HISTORY_FORMAT}\""),
        ),
        (
            "\"backend\":\"firecracker\"".to_owned(),
            "\"backend\":\"firecracker\",\"backend\":\"firecracker\"".to_owned(),
        ),
        (
            "\"os\":\"linux\"".to_owned(),
            "\"os\":\"linux\",\"os\":\"linux\"".to_owned(),
        ),
        (
            "\"status\":\"not_tested\"".to_owned(),
            "\"status\":\"not_tested\",\"status\":\"not_tested\"".to_owned(),
        ),
    ] {
        assert!(text.contains(&once), "{once}");
        let repeated = text.replacen(&once, &twice, 1);
        assert!(
            matches!(
                decode_history(repeated.as_bytes()),
                Err(HistoryError::Unparsable { detail }) if detail.contains("duplicate field")
            ),
            "{twice}"
        );
    }

    // Every refusal says what is wrong, without repeating control characters.
    let control = text.replacen("\"format\":\"", "\"format\":\"\\u0007", 1);
    let error = decode_history(control.as_bytes()).unwrap_err();
    assert!(matches!(&error, HistoryError::OtherFormat { format } if !format.contains('\u{7}')));
    assert!(!error.to_string().contains('\u{7}'));
    for error in [
        HistoryError::Unreadable {
            detail: "access denied".to_owned(),
        },
        HistoryError::NotKept {
            detail: "no space left".to_owned(),
        },
        HistoryError::DigestMismatch,
        HistoryError::BackendTwice {
            backend: BackendKind::Qemu,
        },
    ] {
        assert!(!error.to_string().is_empty());
        assert!(!error.to_string().contains("score"));
    }
}
